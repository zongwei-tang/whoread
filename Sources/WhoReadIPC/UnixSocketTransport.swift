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
/// SIGPIPE, and the server bounds connections, request sizes and idle time.
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

    static func writeAll(_ fd: Int32, _ data: Data) -> Bool {
        var offset = 0
        return data.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return data.isEmpty }
            while offset < data.count {
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

    static func readExactly(_ fd: Int32, _ count: Int) -> Data? {
        var buffer = Data(count: count)
        var offset = 0
        let ok = buffer.withUnsafeMutableBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return count == 0 }
            while offset < count {
                let n = read(fd, base + offset, count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                if n == 0 { return false }
                offset += n
            }
            return true
        }
        return ok ? buffer : nil
    }

    static func sendFrame(_ fd: Int32, _ payload: Data) -> Bool {
        var len = UInt32(payload.count).bigEndian
        let header = Data(bytes: &len, count: 4)
        return writeAll(fd, header + payload)
    }

    static func receiveFrame(_ fd: Int32, max: Int = maxFrame) -> Data? {
        guard let header = readExactly(fd, 4) else { return nil }
        let len = header.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }.bigEndian
        guard Int(len) <= max else { return nil }
        return readExactly(fd, Int(len))
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
    /// Connections served at once; more are closed right away (each one holds a GCD worker).
    public static let maxConnections = 32
    /// Seconds a connection may sit idle in a read or write.
    public static let ioTimeout = 10

    public let path: String
    private let handler: IPCHandler
    private let mode: mode_t
    private var listenFD: Int32 = -1
    private var thread: Thread?
    private let queue = DispatchQueue(label: "whoread.ipc.unix", attributes: .concurrent)
    private let slots = DispatchSemaphore(value: UnixSocketServer.maxConnections)
    private var running = false

    public init(path: String, handler: IPCHandler, mode: mode_t = 0o600) {
        self.path = path
        self.handler = handler
        self.mode = mode
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
        guard listen(fd, 16) == 0 else {
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
            guard slots.wait(timeout: .now()) == .success else {
                close(client)
                continue
            }
            UnixSocket.configure(client, receiveTimeout: UnixSocketServer.ioTimeout, sendTimeout: UnixSocketServer.ioTimeout)
            queue.async { [handler, slots] in
                defer { slots.signal() }
                let (pid, euid) = UnixSocket.peerCredentials(client)
                let peer = IPCPeer(pid: pid, euid: euid, isTrustedCode: false)
                while let frame = UnixSocket.receiveFrame(client, max: UnixSocket.maxRequestFrame) {
                    let reply = IPCCodec.serve(frame, handler: handler, peer: peer)
                    if !UnixSocket.sendFrame(client, reply) { break }
                }
                close(client)
            }
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
        let fd = socket(AF_UNIX, UnixSocket.streamType, 0)
        guard fd >= 0 else { throw IPCError(.unavailable, "socket(): \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        UnixSocket.configure(fd, receiveTimeout: replyTimeout, sendTimeout: UnixSocketServer.ioTimeout)
        var addr = try UnixSocket.makeAddress(path)
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0 else { throw IPCError(.unavailable, "connect(\(path)): \(String(cString: strerror(errno)))") }
        guard UnixSocket.sendFrame(fd, try IPCCodec.encode(request)) else { throw IPCError(.unavailable, "send failed") }
        guard let reply = UnixSocket.receiveFrame(fd) else {
            throw IPCError(.unavailable, "no reply from \(path) (timed out after \(replyTimeout) s, reply too large, or connection closed)")
        }
        return try IPCCodec.decodeResponse(reply)
    }
}
