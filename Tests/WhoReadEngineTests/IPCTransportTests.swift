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
