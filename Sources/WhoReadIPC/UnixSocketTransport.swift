import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// Development transport: length-prefixed JSON over a Unix domain socket.
///
/// Production uses XPC. This exists so the daemon and CLI can be exercised end to end on any
/// host (including Linux CI). It is only started when the daemon is given `--dev-socket`.
/// The socket file is chmod 0600 by default (owner only), and the peer's euid is passed to the
/// handler, so root-only operations stay root-only. A peer that hangs up early gets EPIPE, never
/// SIGPIPE, and the server bounds connections, request sizes and the time one frame may take.
public enum UnixSocket {
    /// Largest reply a client accepts.
    public static let maxFrame = 64 * 1024 * 1024
    /// Largest request the server accepts (a full catalog is well under 1 MiB).
    public static let maxRequestFrame = 4 * 1024 * 1024

    static func makeAddress(_ path: String) throws -> sockaddr_un {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard bytes.count < capacity else { throw IPCError(.invalid, "socket path too long: \(path)") }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        return addr
    }

    static var streamType: Int32 {
        #if canImport(Glibc)
        return Int32(SOCK_STREAM.rawValue)
        #else
        return SOCK_STREAM
        #endif
    }

    #if canImport(Glibc)
    static let sendFlags = Int32(MSG_NOSIGNAL)
    #else
    static let sendFlags: Int32 = 0  // SO_NOSIGPIPE is set on the socket instead.
    #endif

    /// No SIGPIPE on a closed peer (Darwin; Linux uses MSG_NOSIGNAL per send) and per-call I/O
    /// timeouts, so a silent peer cannot pin a thread forever.
    static func configure(_ fd: Int32, receiveTimeout: Int, sendTimeout: Int) {
        #if canImport(Darwin)
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        #endif
        var rcv = timeval(tv_sec: receiveTimeout, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcv, socklen_t(MemoryLayout<timeval>.size))
        var snd = timeval(tv_sec: sendTimeout, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &snd, socklen_t(MemoryLayout<timeval>.size))
    }

    /// Waits until `fd` is ready for `events` (POLLIN or POLLOUT), or `deadline` passes. The socket
    /// timeouts bound each read()/send() alone, so a peer moving one byte at a time never trips
    /// them; checking this before every call bounds the whole frame. Monotonic time, so setting
    /// the clock back cannot stretch a deadline.
    static func waitReady(_ fd: Int32, _ events: Int32, until deadline: DispatchTime) -> Bool {
        while true {
            let now = DispatchTime.now()
            guard now < deadline else { return false }
            let ms = (deadline.uptimeNanoseconds - now.uptimeNanoseconds) / 1_000_000 + 1
            var pfd = pollfd(fd: fd, events: Int16(events), revents: 0)
            let r = poll(&pfd, 1, Int32(min(ms, UInt64(Int32.max))))
            if r < 0 && errno == EINTR { continue }
            return r > 0
        }
    }

    static func writeAll(_ fd: Int32, _ data: Data, deadline: DispatchTime? = nil) -> Bool {
        var offset = 0
        return data.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return data.isEmpty }
            while offset < data.count {
                if let deadline, !waitReady(fd, POLLOUT, until: deadline) { return false }
                let n = send(fd, base + offset, data.count - offset, sendFlags)
                if n < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                offset += n
            }
            return true
        }
    }

    static func readExactly(_ fd: Int32, _ count: Int, deadline: DispatchTime? = nil) -> Result<Data, FrameFailure> {
        var buffer = Data(count: count)
        var offset = 0
        let failure = buffer.withUnsafeMutableBytes { raw -> FrameFailure? in
            guard let base = raw.baseAddress else { return count == 0 ? nil : .failed(EINVAL) }
            while offset < count {
                if let deadline, !waitReady(fd, POLLIN, until: deadline) { return .timedOut }
                let n = read(fd, base + offset, count - offset)
                if n < 0 {
                    let e = errno
                    if e == EINTR { continue }
                    // SO_RCVTIMEO passed.
                    return e == EAGAIN || e == EWOULDBLOCK ? .timedOut : .failed(e)
                }
                if n == 0 { return .closed }
                offset += n
            }
            return nil
        }
        return failure.map { .failure($0) } ?? .success(buffer)
    }

    static func sendFrame(_ fd: Int32, _ payload: Data, deadline: DispatchTime? = nil) -> Bool {
        var len = UInt32(payload.count).bigEndian
        let header = Data(bytes: &len, count: 4)
        return writeAll(fd, header + payload, deadline: deadline)
    }

    static func receiveFrame(_ fd: Int32, max: Int = maxFrame, deadline: DispatchTime? = nil) -> Data? {
        try? readFrame(fd, max: max, deadline: deadline).get()
    }

    /// Why no frame came.
    enum FrameFailure: Error, Equatable {
        /// The peer closed the connection.
        case closed
        /// The deadline, or the socket's receive timeout, passed.
        case timedOut
        /// The header announces this many bytes, more than the limit: none of them was read.
        case tooLarge(Int)
        /// read() failed with this errno.
        case failed(Int32)
    }

    /// One frame of at most `max` bytes, or why none came. A larger one is refused from its header: none
    /// of its payload is read (the server's request limit, the client's reply limit).
    static func readFrame(_ fd: Int32, max: Int = maxFrame, deadline: DispatchTime? = nil) -> Result<Data, FrameFailure> {
        readExactly(fd, 4, deadline: deadline).flatMap { header in
            let len = Int(header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.bigEndian)
            guard len <= max else { return .failure(.tooLarge(len)) }
            return readExactly(fd, len, deadline: deadline)
        }
    }

    /// (pid, euid) of the connected peer.
    static func peerCredentials(_ fd: Int32) -> (pid: Int32?, euid: UInt32?) {
        #if canImport(Glibc)
        // struct ucred is behind _GNU_SOURCE in glibc; same layout declared here.
        struct LinuxUcred { var pid: Int32 = 0; var uid: UInt32 = 0; var gid: UInt32 = 0 }
        var cred = LinuxUcred()
        var len = socklen_t(MemoryLayout<LinuxUcred>.size)
        if getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0 {
            return (cred.pid, cred.uid)
        }
        return (nil, nil)
        #else
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0 else { return (nil, nil) }
        var pid: pid_t = 0
        var len = socklen_t(MemoryLayout<pid_t>.size)
        // <sys/un.h>: LOCAL_PEERPID on SOL_LOCAL. (Pending compile check on macOS.)
        let ok = getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0
        return (ok ? pid : nil, uid)
        #endif
    }
}

public final class UnixSocketServer: @unchecked Sendable {
    /// Non-root connections served at once; more are closed right away (each one holds a thread).
    /// Root takes no slot, so other local users cannot lock it out.
    public static let maxConnections = 32
    /// Default seconds one request (from waiting for its first byte) or one reply may take.
    public static let ioTimeout = 10

    public let path: String
    private let handler: IPCHandler
    private let mode: mode_t
    private let timeout: Int
    private var listenFD: Int32 = -1
    private var thread: Thread?
    private let slots = DispatchSemaphore(value: UnixSocketServer.maxConnections)
    private var running = false

    public init(path: String, handler: IPCHandler, mode: mode_t = 0o600, ioTimeout: Int = UnixSocketServer.ioTimeout) {
        self.path = path
        self.handler = handler
        self.mode = mode
        self.timeout = ioTimeout
    }

    public func start() throws {
        unlink(path)
        let fd = socket(AF_UNIX, UnixSocket.streamType, 0)
        guard fd >= 0 else { throw IPCError(.unavailable, "socket(): \(String(cString: strerror(errno)))") }
        var addr = try UnixSocket.makeAddress(path)
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0 else {
            close(fd)
            throw IPCError(.unavailable, "bind(\(path)): \(String(cString: strerror(errno)))")
        }
        chmod(path, mode)
        // A backlog below the connection limit refuses connects (ECONNREFUSED on Darwin) whenever
        // clients arrive faster than the accept loop takes them, well before any slot is short.
        guard listen(fd, Int32(UnixSocketServer.maxConnections * 2)) == 0 else {
            close(fd)
            throw IPCError(.unavailable, "listen(): \(String(cString: strerror(errno)))")
        }
        listenFD = fd
        running = true
        let t = Thread { [weak self] in self?.acceptLoop() }
        t.name = "whoread.ipc.accept"
        thread = t
        t.start()
    }

    public func stop() {
        running = false
        if listenFD >= 0 {
            shutdown(listenFD, Int32(SHUT_RDWR))
            close(listenFD)
            listenFD = -1
        }
        unlink(path)
    }

    private func acceptLoop() {
        while running {
            let client = accept(listenFD, nil, nil)
            if client < 0 {
                if errno == EINTR { continue }
                if !running { return }
                usleep(10_000)
                continue
            }
            // Credentials before a slot: `sudo whoread enforcement off` must get through even while
            // other users hold every slot.
            let (pid, euid) = UnixSocket.peerCredentials(client)
            let takesSlot = euid != 0
            if takesSlot && slots.wait(timeout: .now()) != .success {
                close(client)
                continue
            }
            UnixSocket.configure(client, receiveTimeout: timeout, sendTimeout: timeout)
            // A thread of its own, not a shared GCD worker: blocked connections must not queue
            // root's behind them.
            let connection = Thread { [handler, slots, timeout] in
                defer { if takesSlot { slots.signal() } }
                let peer = IPCPeer(pid: pid, euid: euid, isTrustedCode: false)
                while let frame = UnixSocket.receiveFrame(client, max: UnixSocket.maxRequestFrame,
                                                          deadline: .now() + .seconds(timeout)) {
                    let reply = IPCCodec.serve(frame, handler: handler, peer: peer)
                    if !UnixSocket.sendFrame(client, reply, deadline: .now() + .seconds(timeout)) { break }
                }
                close(client)
            }
            connection.name = "whoread.ipc.connection"
            connection.start()
        }
    }
}

public final class UnixSocketClient: IPCClient, @unchecked Sendable {
    public let path: String
    /// Seconds to wait for a reply (a large query can take a while).
    public let replyTimeout: Int

    public init(path: String, replyTimeout: Int = 60) {
        self.path = path
        self.replyTimeout = replyTimeout
    }

    public func send(_ request: IPCRequest) throws -> IPCResponse {
        let payload = try IPCCodec.encode(request)
        // The server closes the connection on a larger frame without reading it (and without a reply),
        // which would read here as a daemon that did not answer.
        guard payload.count <= UnixSocket.maxRequestFrame else {
            throw IPCError(.invalid, "request too large: \(payload.count) bytes, the daemon's dev socket accepts at most "
                           + "\(UnixSocket.maxRequestFrame / (1024 * 1024)) MiB")
        }
        let fd = socket(AF_UNIX, UnixSocket.streamType, 0)
        guard fd >= 0 else {
            throw IPCError(.unavailable, "socket(): \(String(cString: strerror(errno)))", noAnswer: .noConnection)
        }
        defer { close(fd) }
        UnixSocket.configure(fd, receiveTimeout: replyTimeout, sendTimeout: UnixSocketServer.ioTimeout)
        var addr = try UnixSocket.makeAddress(path)
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0 else {
            let e = errno
            throw IPCError(.unavailable, "connect(\(path)): \(String(cString: strerror(e)))",
                           noAnswer: UnixSocketClient.noAnswer(connectErrno: e))
        }
        return try exchange(fd, payload)
    }

    /// What a failed connect() says about the daemon.
    static func noAnswer(connectErrno e: Int32) -> IPCError.NoAnswer {
        switch e {
        // No socket file.
        case ENOENT, ENOTDIR: return .notFound
        // The socket's mode (owner only by default: whoreadd --dev-socket-mode).
        case EACCES, EPERM: return .refused
        // ECONNREFUSED: a socket file nothing listens at any more (a daemon that stopped), or a full
        // listen backlog (Darwin refuses connects then, see UnixSocketServer.start).
        default: return .noConnection
        }
    }

    /// Sends one framed request on the connected `fd` and reads the reply (tests: one end of a socketpair).
    func exchange(_ fd: Int32, _ payload: Data) throws -> IPCResponse {
        guard UnixSocket.sendFrame(fd, payload) else {
            let e = errno
            // The send timeout passed (the daemon reads nothing), or the daemon closed the connection first.
            throw IPCError(.unavailable, "sending to \(path) failed: \(String(cString: strerror(e)))",
                           noAnswer: e == EAGAIN || e == EWOULDBLOCK ? .timedOut : .droppedBeforeAnswer)
        }
        switch UnixSocket.readFrame(fd) {
        case .success(let reply):
            return try IPCCodec.decodeResponse(reply)
        case .failure(.timedOut):
            throw IPCError(.unavailable, "no reply from \(path) within \(replyTimeout) s", noAnswer: .timedOut)
        case .failure(.tooLarge(let n)):
            throw IPCError(.unavailable, "the reply from \(path) is \(n) bytes, more than the "
                           + "\(UnixSocket.maxFrame / (1024 * 1024)) MiB this client takes", noAnswer: .replyTooLarge)
        case .failure(.closed):
            throw IPCError(.unavailable, "\(path) closed the connection without answering", noAnswer: .droppedBeforeAnswer)
        case .failure(.failed(let e)):
            throw IPCError(.unavailable, "no reply from \(path): \(String(cString: strerror(e)))", noAnswer: .noConnection)
        }
    }
}
