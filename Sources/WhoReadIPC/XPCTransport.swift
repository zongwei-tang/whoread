#if os(macOS)
import Foundation

// XPC transport (macOS). One ObjC-visible method carries the JSON-encoded request and reply, so
// the whole protocol stays in Swift `Codable` types and can be tested without XPC.
//
// Compiled on macOS, not yet run against the real Mach service. UNVERIFIED on device: that
// setCodeSigningRequirement refuses each message whose sender does not meet the requirement (the
// header says so). Inside the file-system sandbox this was built in, an in-process anonymous
// connection was refused under every requirement, even `always`, so it could not be tested there.
// APIs used (NSXPCListener(machServiceName:),
// NSXPCConnection(machServiceName:options: .privileged), setCodeSigningRequirement (macOS 13+),
// synchronousRemoteObjectProxyWithErrorHandler) are documented in
// docs/research/eslogger-libproc-packaging.md §11.

@objc(WhoReadXPCProtocol)
public protocol WhoReadXPCProtocol {
    func handle(_ request: Data, withReply reply: @escaping (Data) -> Void)
}

private final class ExportedService: NSObject, WhoReadXPCProtocol {
    let handler: IPCHandler
    let peer: IPCPeer

    init(handler: IPCHandler, peer: IPCPeer) {
        self.handler = handler
        self.peer = peer
    }

    func handle(_ request: Data, withReply reply: @escaping (Data) -> Void) {
        reply(IPCCodec.serve(request, handler: handler, peer: peer))
    }
}

public final class XPCServer: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let listener: NSXPCListener
    private let handler: IPCHandler
    /// Requirements per connection (client, or client and app); see `XPCPeerPolicy`.
    private let policy: XPCPeerPolicy
    /// A look at a new peer's pid: does it seem to be the app? Only picks which requirement XPC then
    /// enforces on every message (XPCPeerPolicy); it never makes a peer the app by itself.
    private let appCandidate: @Sendable (Int32) -> Bool

    public init(machServiceName: String, handler: IPCHandler, policy: XPCPeerPolicy,
                appCandidate: @escaping @Sendable (Int32) -> Bool = { _ in false }) {
        self.listener = NSXPCListener(machServiceName: machServiceName)
        self.handler = handler
        self.policy = policy
        self.appCandidate = appCandidate
        super.init()
        listener.delegate = self
    }

    public func start() { listener.resume() }
    public func stop() { listener.invalidate() }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        let euid = connection.effectiveUserIdentifier
        let pid = connection.processIdentifier
        let looksLikeApp = euid != 0 && policy.recognisesApp && appCandidate(pid)
        guard case .accept(let requirement, let peer) = policy.decide(euid: euid, pid: pid, looksLikeApp: looksLikeApp) else {
            return false
        }
        // Before resume, and only once (a second call is an XPC error). The system checks every message
        // on the connection against it and invalidates the connection on the first one that fails.
        if let requirement { connection.setCodeSigningRequirement(requirement) }
        connection.exportedInterface = NSXPCInterface(with: WhoReadXPCProtocol.self)
        connection.exportedObject = ExportedService(handler: handler, peer: peer)
        connection.resume()
        return true
    }
}

public final class XPCClient: IPCClient, @unchecked Sendable {
    public let machServiceName: String
    private let timeout: TimeInterval
    private let lock = NSLock()
    private var connection: NSXPCConnection?

    public init(machServiceName: String, timeout: TimeInterval = 15) {
        self.machServiceName = machServiceName
        self.timeout = timeout
    }

    private func currentConnection() -> NSXPCConnection {
        lock.lock(); defer { lock.unlock() }
        if let c = connection { return c }
        let c = NSXPCConnection(machServiceName: machServiceName, options: .privileged)
        c.remoteObjectInterface = NSXPCInterface(with: WhoReadXPCProtocol.self)
        c.invalidationHandler = { [weak self] in
            self?.lock.lock()
            self?.connection = nil
            self?.lock.unlock()
        }
        c.resume()
        connection = c
        return c
    }

    public func send(_ request: IPCRequest) throws -> IPCResponse {
        let data = try IPCCodec.encode(request)
        let semaphore = DispatchSemaphore(value: 0)
        var replyData: Data?
        var failure: Error?
        let proxy = currentConnection().remoteObjectProxyWithErrorHandler { error in
            failure = error
            semaphore.signal()
        } as? WhoReadXPCProtocol
        guard let proxy else { throw IPCError(.unavailable, "no XPC proxy for \(machServiceName)") }
        proxy.handle(data) { reply in
            replyData = reply
            semaphore.signal()
        }
        if semaphore.wait(timeout: .now() + timeout) == .timedOut {
            throw IPCError(.unavailable, "daemon did not answer within \(Int(timeout)) s (\(machServiceName))")
        }
        if let failure { throw IPCError(.unavailable, "XPC: \(failure.localizedDescription)") }
        guard let replyData else { throw IPCError(.unavailable, "empty XPC reply") }
        return try IPCCodec.decodeResponse(replyData)
    }

    public func invalidate() {
        lock.lock(); defer { lock.unlock() }
        connection?.invalidate()
        connection = nil
    }
}
#endif
