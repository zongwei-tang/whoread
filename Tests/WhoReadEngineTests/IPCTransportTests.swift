import Foundation
import XCTest
import WhoReadCore
@testable import WhoReadIPC

// Regression tests for the IPC transports: the request size cap (ipc-4). XPC runs through an anonymous
// listener in this process (no Mach service is registered or looked up), the dev socket through a
// socketpair or a path nothing listens at, so none of these needs to bind a socket.

/// Counts what reaches it; answers `.ok`.
private final class RecordingHandler: IPCHandler, @unchecked Sendable {
    private let lock = NSLock()
    private var _requests = 0
    var requests: Int { lock.lock(); defer { lock.unlock() }; return _requests }

    func handle(_ request: IPCRequest, peer: IPCPeer) -> IPCResponse {
        lock.lock(); _requests += 1; lock.unlock()
        return .ok
    }
}

/// A local user who is not the console user (any process may connect to a daemon installed without a
/// client requirement).
private let otherUser = IPCPeer(pid: 4242, euid: 502, isTrustedCode: false)

/// `.deleteRule(id:)` with an id of `idBytes` bytes, as the JSON the client sends, written out directly.
private func deleteRule(idBytes: Int) -> Data {
    Data(#"{"deleteRule":{"id":""#.utf8) + Data(repeating: UInt8(ascii: "a"), count: idBytes) + Data(#""}}"#.utf8)
}

private let deleteRuleOverhead = deleteRule(idBytes: 0).count

private func errorOf(_ reply: Data) throws -> IPCError? {
    if case .error(let e) = try IPCCodec.decodeResponse(reply) { return e }
    return nil
}

final class RequestSizeCapTests: XCTestCase {
    /// ipc-4: the request was decoded in full, and only then authorized (and refused) by the handler.
    func testAnOversizedRequestIsRefusedBeforeItIsDecoded() throws {
        let handler = RecordingHandler()
        // The shape is right: a small one decodes and reaches the handler.
        XCTAssertNil(try errorOf(IPCCodec.serve(deleteRule(idBytes: 8), handler: handler, peer: otherUser)))
        XCTAssertEqual(handler.requests, 1)

        let big = deleteRule(idBytes: IPCCodec.maxRequestSize)
        XCTAssertNoThrow(try IPCCodec.decodeRequest(big), "a valid request, only too large")
        let e = try XCTUnwrap(try errorOf(IPCCodec.serve(big, handler: handler, peer: otherUser)), "served")
        XCTAssertEqual(handler.requests, 1, "an oversized request reached the handler (decoded, then authorized)")
        XCTAssertEqual(e.code, .invalid)
        XCTAssertTrue(e.message.contains("too large"), e.message)
        XCTAssertTrue(e.message.contains("64 MiB"), e.message)
    }

    /// The cap is inclusive: a request of exactly `maxRequestSize` bytes is still served.
    func testARequestOfExactlyTheCapIsServed() throws {
        let handler = RecordingHandler()
        let edge = deleteRule(idBytes: IPCCodec.maxRequestSize - deleteRuleOverhead)
        XCTAssertEqual(edge.count, IPCCodec.maxRequestSize)
        XCTAssertNil(try errorOf(IPCCodec.serve(edge, handler: handler, peer: otherUser)))
        XCTAssertEqual(handler.requests, 1)
    }

    #if os(macOS)
    /// ipc-4 on the XPC path: `ExportedService.handle` serves what XPC delivers.
    func testTheXPCListenerRefusesAnOversizedRequestUnread() throws {
        let handler = RecordingHandler()
        let server = XPCServer(listener: .anonymous(), handler: handler,
                               policy: XPCPeerPolicy(clientRequirement: nil, appRequirement: nil))
        server.start()
        defer { server.stop() }
        let client = XPCClient(endpoint: server.endpoint, timeout: 60)
        defer { client.invalidate() }
        guard case .ok = try client.send(.deleteRule(id: "small")) else { return XCTFail("the small request is served") }
        XCTAssertEqual(handler.requests, 1)

        let reply = try client.send(.deleteRule(id: String(repeating: "a", count: IPCCodec.maxRequestSize)))
        XCTAssertEqual(handler.requests, 1, "an oversized request reached the handler")
        guard case .error(let e) = reply else { return XCTFail("\(reply)") }
        XCTAssertEqual(e.code, .invalid)
        XCTAssertTrue(e.message.contains("too large"), e.message)
    }
    #endif

    /// The dev socket's server closes the connection on a frame over `UnixSocket.maxRequestFrame` without
    /// reading it, which its client could only report as a daemon that did not answer. The client says so
    /// before connecting.
    func testTheDevSocketClientSaysARequestIsTooLargeInsteadOfUnreachable() throws {
        let dir = TempDir()
        let client = UnixSocketClient(path: dir.path("nothing-listens.sock"))
        let big = IPCRequest.deleteRule(id: String(repeating: "a", count: UnixSocket.maxRequestFrame))
        XCTAssertThrowsError(try client.send(big)) { error in
            let e = error as? IPCError
            XCTAssertEqual(e?.code, .invalid, "\(error)")
            XCTAssertTrue(e?.message.contains("too large") == true, "\(error)")
            XCTAssertTrue(e?.message.contains("4 MiB") == true, "\(error)")
        }
        // A request that fits still goes out (and finds nothing listening).
        XCTAssertThrowsError(try client.send(.status)) { error in
            XCTAssertEqual((error as? IPCError)?.code, .unavailable, "\(error)")
        }
    }
}

// MARK: - ipc-5 / cli-13: why a request got no answer

/// The dev daemon's policy without requirements: any local client may connect.
private let anyClient = XPCPeerPolicy(clientRequirement: nil, appRequirement: nil)

/// Answers `.hello`; holds every other request until released (a daemon that took it and is busy).
private final class StallingHandler: IPCHandler, @unchecked Sendable {
    private let gate = DispatchSemaphore(value: 0)

    func handle(_ request: IPCRequest, peer: IPCPeer) -> IPCResponse {
        if case .hello = request { return .hello(serverVersion: whoReadIPCVersion) }
        _ = gate.wait(timeout: .now() + 30)
        return .ok
    }

    func releaseAll() { for _ in 0..<8 { gate.signal() } }
}

private func cocoa(_ code: Int, _ debugDescription: String? = nil, domain: String = NSCocoaErrorDomain) -> NSError {
    NSError(domain: domain, code: code, userInfo: debugDescription.map { [NSDebugDescriptionErrorKey: $0] } ?? [:])
}

private struct Answered: Error, CustomStringConvertible {
    let reply: Any
    var description: String { "expected no answer, got \(reply)" }
}

/// The `IPCError` `body` throws.
private func failure(_ body: () throws -> Any) throws -> IPCError {
    do {
        throw Answered(reply: try body())
    } catch let e as IPCError {
        return e
    }
}

private func withSocketPair(_ body: (_ mine: Int32, _ theirs: Int32) throws -> Void) throws {
    var fds: [Int32] = [0, 0]
    XCTAssertEqual(socketpair(AF_UNIX, UnixSocket.streamType, 0, &fds), 0)
    defer { close(fds[0]); close(fds[1]) }
    try body(fds[0], fds[1])
}

private func header(announcing length: Int) -> Data {
    var len = UInt32(length).bigEndian
    return Data(bytes: &len, count: 4)
}

final class NoAnswerTests: XCTestCase {
    /// The kind is for the client alone: what the daemon replies is encoded as before.
    func testTheFailureKindStaysOffTheWire() throws {
        let json = String(decoding: try IPCCodec.encode(IPCResponse.error(IPCError(.unavailable, "m", noAnswer: .timedOut))), as: UTF8.self)
        XCTAssertFalse(json.contains("noAnswer"), json)
        guard case .error(let back) = try IPCCodec.decodeResponse(Data(json.utf8)) else { return XCTFail(json) }
        XCTAssertEqual(back, IPCError(.unavailable, "m"))
        XCTAssertNil(back.noAnswer)
    }

    #if os(macOS)
    /// Before: every XPC failure was `.unavailable` "XPC: Couldn't communicate with a helper application.", and
    /// whoread asked whether the daemon was running, whether it had refused this program or was not there.
    func testXPCFailuresAreToldApart() {
        let lookup = cocoa(4099, "The connection to service named com.example.whoread was invalidated: Connection init failed at "
                           + "lookup with error 3 - No such process.")
        let fromThisProcess = "The connection to service named com.example.whoread was invalidated from this process."
        let cases: [(NSError, Bool, IPCError.NoAnswer)] = [
            (cocoa(4102, "The code signature requirement failed."), false, .refused),
            (cocoa(4097, "connection to service created from an endpoint"), false, .droppedBeforeAnswer),
            (cocoa(4097, "connection to service created from an endpoint"), true, .droppedAfterAnswer),
            (lookup, false, .notFound),
            (lookup, true, .notFound),
            (cocoa(4099, fromThisProcess), false, .noConnection),
            (cocoa(4099, fromThisProcess), true, .droppedAfterAnswer),
            (cocoa(4099), false, .noConnection),
            (cocoa(4101), false, .noConnection),
            (cocoa(1, domain: NSPOSIXErrorDomain), true, .noConnection),
        ]
        for (error, answeredBefore, expected) in cases {
            let e = XPCClient.noAnswerError(error, answeredBefore: answeredBefore)
            XCTAssertEqual(e.code, .unavailable, "\(error)")
            XCTAssertEqual(e.noAnswer, expected, "\(error), answered before: \(answeredBefore)")
        }
        // XPC's own account, not only "Couldn't communicate with a helper application."
        let e = XPCClient.noAnswerError(lookup, answeredBefore: false)
        XCTAssertTrue(e.message.contains("failed at lookup with error 3 - No such process"), e.message)
        XCTAssertTrue(e.message.contains("4099"), e.message)
    }

    func testAnXPCDaemonThatDoesNotAnswerHasTimedOut() throws {
        let handler = StallingHandler()
        let server = XPCServer(listener: .anonymous(), handler: handler, policy: anyClient)
        server.start()
        defer { handler.releaseAll(); server.stop() }
        let client = XPCClient(endpoint: server.endpoint, name: "com.example.whoread.test", timeout: 1)
        defer { client.invalidate() }
        guard case .hello = try client.send(.hello(clientVersion: whoReadIPCVersion)) else { return XCTFail("hello") }
        let e = try failure { try client.send(.status) }
        XCTAssertEqual(e.code, .unavailable)
        XCTAssertEqual(e.noAnswer, .timedOut, e.message)
        XCTAssertTrue(e.message.contains("did not answer within 1 s (com.example.whoread.test)"), e.message)
    }

    /// The finding: `events --limit 100000` or `daily` on a large store took longer than the 15 s XPC
    /// timeout, while the dev socket's client waits 60 s for the same query.
    func testReadsOfTheHistoryWaitLongerThanOtherRequests() throws {
        for r: IPCRequest in [.events(EventQuery()), .alerts(AlertQuery()), .summaries(since: nil), .dailyAggregates(since: nil), .baseline] {
            XCTAssertTrue(r.mayTakeLong, "\(r)")
        }
        for r: IPCRequest in [.hello(clientVersion: 1), .status, .live(afterID: nil, limit: 10, includeBenign: false), .rules, .catalog,
                              .settings, .asks, .agents] {
            XCTAssertFalse(r.mayTakeLong, "\(r)")
        }
        XCTAssertEqual(XPCClient.queryTimeout, TimeInterval(UnixSocketClient(path: "/x").replyTimeout))

        let handler = StallingHandler()
        let server = XPCServer(listener: .anonymous(), handler: handler, policy: anyClient)
        server.start()
        defer { handler.releaseAll(); server.stop() }
        let client = XPCClient(endpoint: server.endpoint, timeout: 1, queryTimeout: 2)
        defer { client.invalidate() }
        XCTAssertTrue(try failure { try client.send(.status) }.message.contains("within 1 s"))
        let start = Date()
        let e = try failure { try client.send(.events(EventQuery())) }
        XCTAssertTrue(e.message.contains("within 2 s"), e.message)
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(start), 1.9)
        // A caller that sets no query timeout keeps one timeout for everything (the app's clients).
        let plain = XPCClient(endpoint: server.endpoint, timeout: 1)
        defer { plain.invalidate() }
        XCTAssertTrue(try failure { try plain.send(.events(EventQuery())) }.message.contains("within 1 s"))
    }

    /// The finding: a program the daemon refuses (a rebuilt, re-signed or Debug build) was told the daemon
    /// was not running. A refused connection is closed by the daemon before any answer; XPC does not tell
    /// the client why, so both causes are named.
    func testAnXPCDaemonThatRefusesThisProgramIsNotReportedAsNotRunning() throws {
        try XCTSkipIf(geteuid() == 0, "root is accepted whatever the requirement")
        // A client requirement that does not parse: every non-root peer is refused at the connection.
        let refusing = XPCPeerPolicy(clientRequirement: "anchor (((", appRequirement: nil, parses: { _ in false })
        XCTAssertEqual(refusing.decide(euid: geteuid(), pid: getpid(), looksLikeApp: false), .reject)
        let handler = RecordingHandler()
        let server = XPCServer(listener: .anonymous(), handler: handler, policy: refusing)
        server.start()
        defer { server.stop() }
        let client = XPCClient(endpoint: server.endpoint, timeout: 10)
        defer { client.invalidate() }
        let e = try failure { try client.send(.hello(clientVersion: whoReadIPCVersion)) }
        XCTAssertEqual(handler.requests, 0)
        XCTAssertEqual(e.code, .unavailable)
        let kind = try XCTUnwrap(e.noAnswer, e.message)
        XCTAssertTrue([IPCError.NoAnswer.droppedBeforeAnswer, .noConnection].contains(kind), "\(kind): \(e.message)")
        let text = NoAnswerHelp.lines(for: e, target: .xpc(service: WhoReadPaths.machServiceName)).joined(separator: "\n")
        XCTAssertTrue(text.contains("refus"), text)
        XCTAssertTrue(text.contains("rebuilt or re-signed"), text)
        XCTAssertTrue(text.contains("scripts/install.sh"), text)
    }

    /// No service is registered under that name (never the real one).
    func testAnXPCServiceNothingAnswersAtIsNotFound() throws {
        let name = "com.whoread.test.missing.\(UUID().uuidString)"
        let client = XPCClient(machServiceName: name, timeout: 10)
        defer { client.invalidate() }
        let e = try failure { try client.send(.hello(clientVersion: whoReadIPCVersion)) }
        XCTAssertEqual(e.code, .unavailable)
        // XPC says the lookup failed ("Connection init failed at lookup with error 3 - No such process", or
        // error 159 inside a sandbox); without that the cause stays open.
        XCTAssertEqual(e.noAnswer, e.message.contains("failed at lookup") ? .notFound : .noConnection, e.message)
    }
    #endif

    /// Before: "no reply from PATH (timed out after 60 s, reply too large, or connection closed)" for all
    /// three, then "Is whoreadd running?".
    func testTheDevSocketClientTellsATimeoutAReplyTooLargeAndAClosedConnectionApart() throws {
        let client = UnixSocketClient(path: "/tmp/whoread-pair.sock", replyTimeout: 1)
        let request = try IPCCodec.encode(IPCRequest.status)
        try withSocketPair { mine, _ in
            UnixSocket.configure(mine, receiveTimeout: 1, sendTimeout: 1)
            let e = try failure { try client.exchange(mine, request) }
            XCTAssertEqual(e.noAnswer, .timedOut, e.message)
            XCTAssertTrue(e.message.contains("1 s"), e.message)
        }
        try withSocketPair { mine, theirs in
            UnixSocket.configure(mine, receiveTimeout: 5, sendTimeout: 1)
            XCTAssertTrue(UnixSocket.writeAll(theirs, header(announcing: UnixSocket.maxFrame + 1)))
            let start = Date()
            let e = try failure { try client.exchange(mine, request) }
            XCTAssertEqual(e.noAnswer, .replyTooLarge, e.message)
            XCTAssertTrue(e.message.contains("64 MiB"), e.message)
            XCTAssertLessThan(Date().timeIntervalSince(start), 2, "known from the header")
        }
        try withSocketPair { mine, theirs in
            UnixSocket.configure(mine, receiveTimeout: 5, sendTimeout: 1)
            DispatchQueue.global().async {
                _ = UnixSocket.receiveFrame(theirs, deadline: .now() + 5)
                shutdown(theirs, Int32(SHUT_RDWR))
            }
            let e = try failure { try client.exchange(mine, request) }
            XCTAssertEqual(e.noAnswer, .droppedBeforeAnswer, e.message)
        }
    }

    /// The dev socket's server refuses a frame over its limit from the header alone, before reading or
    /// decoding any of it (its cap, like the XPC one, comes first); the reader says that is why.
    func testAFrameOverTheLimitIsRefusedFromItsHeader() throws {
        try withSocketPair { a, b in
            XCTAssertTrue(UnixSocket.writeAll(a, header(announcing: UnixSocket.maxRequestFrame + 1)))
            let start = Date()
            XCTAssertEqual(UnixSocket.readFrame(b, max: UnixSocket.maxRequestFrame, deadline: .now() + 5),
                           .failure(.tooLarge(UnixSocket.maxRequestFrame + 1)))
            XCTAssertLessThan(Date().timeIntervalSince(start), 1, "without waiting for the payload")
        }
        try withSocketPair { a, b in
            XCTAssertTrue(UnixSocket.sendFrame(a, Data("hi".utf8)))
            XCTAssertEqual(UnixSocket.readFrame(b, deadline: .now() + 5), .success(Data("hi".utf8)))
            XCTAssertEqual(UnixSocket.readFrame(b, deadline: .now() + .milliseconds(200)), .failure(.timedOut))
            shutdown(a, Int32(SHUT_RDWR))
            XCTAssertEqual(UnixSocket.readFrame(b, deadline: .now() + 5), .failure(.closed))
        }
    }

    func testAFailedConnectToTheDevSocketSaysWhy() throws {
        XCTAssertEqual(UnixSocketClient.noAnswer(connectErrno: ENOENT), .notFound)
        XCTAssertEqual(UnixSocketClient.noAnswer(connectErrno: ENOTDIR), .notFound)
        XCTAssertEqual(UnixSocketClient.noAnswer(connectErrno: ECONNREFUSED), .notFound, "a socket file nothing listens at")
        XCTAssertEqual(UnixSocketClient.noAnswer(connectErrno: EACCES), .refused, "the socket's mode (0600 by default)")
        XCTAssertEqual(UnixSocketClient.noAnswer(connectErrno: EIO), .noConnection)
        let dir = TempDir()
        let e = try failure { try UnixSocketClient(path: dir.path("none.sock")).send(.status) }
        XCTAssertEqual(e.noAnswer, .notFound, e.message)
    }

    /// What whoread prints for each: before, "cannot reach the WhoRead daemon: …" and "Is whoreadd running?
    /// (sudo launchctl print system/com.whoread.daemon)" for every one, the system extension included.
    func testTheHintFitsWhatHappened() {
        let dev = NoAnswerHelp.Target.xpc(service: WhoReadPaths.machServiceName)
        let ext = NoAnswerHelp.Target.xpc(service: "ABCDE12345.com.example.whoread.extension.xpc")
        let socket = NoAnswerHelp.Target.socket(path: "/tmp/w.sock")
        func text(_ kind: IPCError.NoAnswer?, _ target: NoAnswerHelp.Target, _ message: String = "DETAIL") -> String {
            NoAnswerHelp.lines(for: IPCError(.unavailable, message, noAnswer: kind), target: target).joined(separator: "\n")
        }
        let devCheck = "sudo launchctl print system/com.whoread.daemon"
        let extCheck = "systemextensionsctl list"

        // Every message keeps what XPC or the socket reported.
        for kind: IPCError.NoAnswer? in [nil, .notFound, .refused, .droppedBeforeAnswer, .droppedAfterAnswer, .timedOut, .replyTooLarge,
                                         .noConnection] {
            for target in [dev, ext, socket] {
                XCTAssertTrue(text(kind, target).contains("DETAIL"), "\(String(describing: kind)) \(target)")
            }
        }
        // Timed out: the daemon took the request; it is running, busy or stuck.
        for target in [dev, ext, socket] {
            let s = text(.timedOut, target)
            XCTAssertTrue(s.contains("did not answer in time"), s)
            XCTAssertFalse(s.contains("Is whoreadd running"), s)
            XCTAssertFalse(s.contains("refus"), s)
            XCTAssertTrue(s.contains("--limit"), s)
        }
        // Refused, and XPC said so: which program to use instead.
        for target in [dev, ext] {
            let s = text(.refused, target)
            XCTAssertTrue(s.contains("refused this program"), s)
            XCTAssertTrue(s.contains("scripts/install.sh"), s)
            XCTAssertTrue(s.contains("sudo"), s)
            XCTAssertFalse(s.contains("running"), s)
        }
        // Closed before any answer, or no connection for a reason XPC does not give: a refusal is named,
        // with what fixes it, and so is the check whether it runs.
        for (kind, target, check) in [(IPCError.NoAnswer.droppedBeforeAnswer, dev, devCheck), (.droppedBeforeAnswer, ext, extCheck),
                                      (.noConnection, dev, devCheck), (.noConnection, ext, extCheck)] {
            let s = text(kind, target)
            XCTAssertTrue(s.contains("refus"), s)
            XCTAssertTrue(s.contains("rebuilt or re-signed"), s)
            XCTAssertTrue(s.contains("scripts/install.sh"), s)
            XCTAssertTrue(s.contains(check), s)
        }
        XCTAssertEqual(text(nil, dev), text(.noConnection, dev), "a transport that gives no kind: the same")
        // Nothing answers at that name: not installed, or not running. Nothing refused anything.
        XCTAssertTrue(text(.notFound, dev).contains(devCheck), text(.notFound, dev))
        XCTAssertTrue(text(.notFound, ext).contains(extCheck), text(.notFound, ext))
        XCTAssertTrue(text(.notFound, ext).contains("ABCDE12345.com.example.whoread.extension.xpc"), text(.notFound, ext))
        for target in [dev, ext] {
            XCTAssertFalse(text(.notFound, target).contains("refus"), text(.notFound, target))
            XCTAssertFalse(text(.notFound, target).contains(target == dev ? extCheck : devCheck), text(.notFound, target))
        }
        // The lookup was refused by a sandbox around this process (an AI agent's, say): not "not running".
        let sandboxed = text(.notFound, ext, "XPC: The connection to service named x was invalidated: Connection init failed at "
                             + "lookup with error 159 - Sandbox restriction. (error 4099)")
        XCTAssertTrue(sandboxed.contains("outside"), sandboxed)
        XCTAssertFalse(sandboxed.contains("installed and running"), sandboxed)
        XCTAssertTrue(sandboxed.contains(extCheck), sandboxed)
        // It answered before on this connection, then the connection broke: it stopped or restarted.
        XCTAssertTrue(text(.droppedAfterAnswer, dev).contains("stopped"), text(.droppedAfterAnswer, dev))
        XCTAssertFalse(text(.droppedAfterAnswer, dev).contains("refus"), text(.droppedAfterAnswer, dev))
        XCTAssertTrue(text(.droppedAfterAnswer, ext).contains(extCheck), text(.droppedAfterAnswer, ext))
        // The dev socket: its own hints, never the LaunchDaemon's or code signing.
        for kind: IPCError.NoAnswer in [.notFound, .refused, .droppedBeforeAnswer, .droppedAfterAnswer, .timedOut, .replyTooLarge, .noConnection] {
            let s = text(kind, socket)
            XCTAssertFalse(s.contains("launchctl"), s)
            XCTAssertFalse(s.contains("scripts/install.sh"), s)
        }
        XCTAssertTrue(text(.notFound, socket).contains("--dev-socket /tmp/w.sock"), text(.notFound, socket))
        XCTAssertTrue(text(.noConnection, socket).contains("--dev-socket /tmp/w.sock"), text(.noConnection, socket))
        XCTAssertTrue(text(.refused, socket).contains("sudo"), text(.refused, socket))
        let tooLarge = text(.replyTooLarge, socket)
        XCTAssertTrue(tooLarge.contains("whoread export"), tooLarge)
        XCTAssertTrue(tooLarge.contains("--limit"), tooLarge)
        XCTAssertFalse(tooLarge.contains("running"), tooLarge)
    }
}
