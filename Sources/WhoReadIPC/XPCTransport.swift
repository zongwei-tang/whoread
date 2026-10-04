#if os(macOS)
import Foundation

// XPC transport (macOS). One ObjC-visible method carries the JSON-encoded request and reply, so
// the whole protocol stays in Swift `Codable` types and can be tested without XPC.
//
// NOT YET COMPILED: written on a Linux host. APIs used (NSXPCListener(machServiceName:),
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
    /// e.g. `anchor apple generic and certificate leaf[subject.OU] = "TEAMID"`. nil = accept any
    /// local client (development only); the handler still sees the peer euid.
    private let requirement: String?

    public init(machServiceName: String, handler: IPCHandler, codeSigningRequirement: String?) {
        self.listener = NSXPCListener(machServiceName: machServiceName)
        self.handler = handler
        self.requirement = codeSigningRequirement
        super.init()
        listener.delegate = self
    }

    public func start() { listener.resume() }
    public func stop() { listener.invalidate() }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        var trusted = false
        if let requirement {
            // The connection is invalidated by the system if the peer does not satisfy it.
            connection.setCodeSigningRequirement(requirement)
            trusted = true
        }
        let peer = IPCPeer(pid: connection.processIdentifier, euid: connection.effectiveUserIdentifier, isTrustedCode: trusted)
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
