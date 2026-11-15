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

    /// `serve` refuses a request over `IPCCodec.maxRequestSize` before decoding or authorizing it.
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

    public convenience init(machServiceName: String, handler: IPCHandler, policy: XPCPeerPolicy,
                            appCandidate: @escaping @Sendable (Int32) -> Bool = { _ in false }) {
        self.init(listener: NSXPCListener(machServiceName: machServiceName), handler: handler, policy: policy,
                  appCandidate: appCandidate)
    }

    /// Tests: an anonymous listener in this process (`NSXPCListener.anonymous()`), reached through
    /// `endpoint`; no Mach service is registered or looked up.
    init(listener: NSXPCListener, handler: IPCHandler, policy: XPCPeerPolicy,
         appCandidate: @escaping @Sendable (Int32) -> Bool = { _ in false }) {
        self.listener = listener
        self.handler = handler
        self.policy = policy
        self.appCandidate = appCandidate
        super.init()
        listener.delegate = self
    }

    /// The anonymous listener's endpoint (tests).
    var endpoint: NSXPCListenerEndpoint { listener.endpoint }

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
        // on the connection against it and invalidates the connection on the first one that fails (what
        // the client is told then, and for a refusal above: `XPCClient.noAnswerError`).
        if let requirement { connection.setCodeSigningRequirement(requirement) }
        connection.exportedInterface = NSXPCInterface(with: WhoReadXPCProtocol.self)
        connection.exportedObject = ExportedService(handler: handler, peer: peer)
        connection.resume()
        return true
    }
}

public final class XPCClient: IPCClient, @unchecked Sendable {
    /// What whoread waits for a read of the history (`IPCRequest.mayTakeLong`): as long as the dev
    /// socket's client waits for any reply (`UnixSocketClient.replyTimeout`).
    public static let queryTimeout: TimeInterval = 60

    public let machServiceName: String
    private let timeout: TimeInterval
    private let queryTimeout: TimeInterval?
    private let makeConnection: () -> NSXPCConnection
    private let lock = NSLock()
    private var connection: NSXPCConnection?
    /// `connection` has answered a request since it was made or last interrupted: the daemon was there
    /// and took this program.
    private var answered = false

    /// `timeout`: seconds to wait for an answer; `queryTimeout`: for a read of the history instead
    /// (nil: `timeout` too).
    public init(machServiceName: String, timeout: TimeInterval = 15, queryTimeout: TimeInterval? = nil) {
        self.machServiceName = machServiceName
        self.timeout = timeout
        self.queryTimeout = queryTimeout
        makeConnection = { NSXPCConnection(machServiceName: machServiceName, options: .privileged) }
    }

    /// Tests: a listener in this process (`XPCServer(listener: .anonymous(), …)`). `name` stands in
    /// for the service name in messages.
    init(endpoint: NSXPCListenerEndpoint, name: String = "an anonymous test listener", timeout: TimeInterval = 15,
         queryTimeout: TimeInterval? = nil) {
        machServiceName = name
        self.timeout = timeout
        self.queryTimeout = queryTimeout
        makeConnection = { NSXPCConnection(listenerEndpoint: endpoint) }
    }

    /// The error for a failure XPC reported, and what it says about the daemon (`IPCError.NoAnswer`).
    /// `answeredBefore`: the connection had answered a request since it was made or last interrupted.
    ///
    /// What the client is told, as seen in a process talking to an anonymous listener (on the Mach
    /// service: UNVERIFIED on device): a name nothing is registered under fails "at lookup"
    /// (NSXPCConnectionInvalid); a connection the daemon refuses, at `shouldAcceptNewConnection` or by
    /// the code-signing requirement it set on it, is interrupted (NSXPCConnectionInterrupted) before any
    /// answer, as one whose daemon stopped would be. NSXPCConnectionCodeSigningRequirementFailure is
    /// reported to the side that set the requirement, the daemon; it means a refusal when it does come.
    static func noAnswerError(_ failure: Error, answeredBefore: Bool) -> IPCError {
        let e = failure as NSError
        // "Couldn't communicate with a helper application." for all of them; the debug description
        // says what happened ("… failed at lookup with error 3 - No such process.").
        let debug = (e.userInfo[NSDebugDescriptionErrorKey] as? String) ?? ""
        let detail = debug.isEmpty ? e.localizedDescription : debug
        let kind: IPCError.NoAnswer
        switch e.domain == NSCocoaErrorDomain ? e.code : 0 {
        case NSXPCConnectionCodeSigningRequirementFailure:
            kind = .refused
        case NSXPCConnectionInterrupted:
            kind = answeredBefore ? .droppedAfterAnswer : .droppedBeforeAnswer
        case NSXPCConnectionInvalid where detail.contains("failed at lookup"):
            kind = .notFound
        case NSXPCConnectionInvalid:
            kind = answeredBefore ? .droppedAfterAnswer : .noConnection
        default:
            kind = .noConnection
        }
        return IPCError(.unavailable, "XPC: \(detail) (error \(e.code))", noAnswer: kind)
    }

    /// The connection, and whether it has answered (see `answered`).
    private func currentConnection() -> (NSXPCConnection, answered: Bool) {
        lock.lock(); defer { lock.unlock() }
        if let c = connection { return (c, answered) }
        let c = makeConnection()
        c.remoteObjectInterface = NSXPCInterface(with: WhoReadXPCProtocol.self)
        c.invalidationHandler = { [weak self] in
            self?.lock.lock()
            self?.connection = nil
            self?.answered = false
            self?.lock.unlock()
        }
        // The next message goes to the daemon as it is then (maybe a new instance, maybe one that no
        // longer takes this program).
        c.interruptionHandler = { [weak self] in
            self?.lock.lock()
            self?.answered = false
            self?.lock.unlock()
        }
        c.resume()
        connection = c
        answered = false
        return (c, false)
    }

    private func noteAnswer(on c: NSXPCConnection) {
        lock.lock(); defer { lock.unlock() }
        if connection === c { answered = true }
    }

    public func send(_ request: IPCRequest) throws -> IPCResponse {
        let data = try IPCCodec.encode(request)
        let wait = request.mayTakeLong ? max(timeout, queryTimeout ?? timeout) : timeout
        let (connection, answeredBefore) = currentConnection()
        let semaphore = DispatchSemaphore(value: 0)
        var replyData: Data?
        var failure: Error?
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            failure = error
            semaphore.signal()
        } as? WhoReadXPCProtocol
        guard let proxy else { throw IPCError(.unavailable, "no XPC proxy for \(machServiceName)", noAnswer: .noConnection) }
        proxy.handle(data) { reply in
            replyData = reply
            semaphore.signal()
        }
        if semaphore.wait(timeout: .now() + wait) == .timedOut {
            // XPC reports a connection it cannot make or keep: silence means the daemon has the request.
            throw IPCError(.unavailable, "daemon did not answer within \(Int(wait)) s (\(machServiceName))", noAnswer: .timedOut)
        }
        if let failure { throw XPCClient.noAnswerError(failure, answeredBefore: answeredBefore) }
        guard let replyData else { throw IPCError(.unavailable, "empty XPC reply", noAnswer: .noConnection) }
        noteAnswer(on: connection)
        return try IPCCodec.decodeResponse(replyData)
    }

    public func invalidate() {
        lock.lock(); defer { lock.unlock() }
        connection?.invalidate()
        connection = nil
        answered = false
    }
}
#endif
