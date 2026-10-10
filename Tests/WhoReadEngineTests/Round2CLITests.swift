import XCTest
import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
import WhoReadCore
@testable import WhoReadIPC

/// Round-2 review fixes in the dev socket transport. The CLI parts (export paging, error mapping,
/// catalog path checks, settings parsing) live in the `whoread` executable, which no test target
/// links; scripts/dev/e2e-dev-socket.sh drives those against a real daemon.
final class Round2CLITests: XCTestCase {
    private final class OKHandler: IPCHandler, @unchecked Sendable {
        func handle(_ request: IPCRequest, peer: IPCPeer) -> IPCResponse {
            if case .hello = request { return .hello(serverVersion: whoReadIPCVersion) }
            return .ok
        }
    }

    /// A raw connection that announced a `length`-byte request and has sent none of it yet.
    private func announce(_ path: String, length: UInt32) throws -> Int32 {
        let fd = socket(AF_UNIX, UnixSocket.streamType, 0)
        XCTAssertGreaterThanOrEqual(fd, 0)
        UnixSocket.configure(fd, receiveTimeout: 5, sendTimeout: 5)  // SO_NOSIGPIPE on Darwin
        var addr = try UnixSocket.makeAddress(path)
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        XCTAssertEqual(rc, 0)
        var len = length.bigEndian
        XCTAssertTrue(UnixSocket.writeAll(fd, Data(bytes: &len, count: 4)))
        return fd
    }

    /// The server closed its end (the request never gets a reply, so readable means EOF).
    private func closedByServer(_ fd: Int32, within seconds: Double) -> Bool {
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&pfd, 1, Int32(seconds * 1000)) > 0 else { return false }
        var byte: UInt8 = 0
        return read(fd, &byte, 1) <= 0
    }

    // store-ipc-cli-5: SO_RCVTIMEO bounds each read() alone, so one byte every 0.2 s kept a
    // connection (and its slot) forever. The whole frame now has to arrive within the timeout.
    func testTricklingRequestIsCutOffAtTheFrameDeadline() throws {
        try skipIfSocketBindDenied()
        let dir = TempDir()
        let server = UnixSocketServer(path: dir.path("t.sock"), handler: OKHandler(), ioTimeout: 1)
        try server.start()
        defer { server.stop() }
        let fd = try announce(dir.path("t.sock"), length: 100)
        defer { close(fd) }
        let start = Date()
        var closedAfter: TimeInterval?
        while Date().timeIntervalSince(start) < 5 {
            _ = UnixSocket.writeAll(fd, Data([0x20]))
            if closedByServer(fd, within: 0.2) {
                closedAfter = Date().timeIntervalSince(start)
                break
            }
        }
        let t = try XCTUnwrap(closedAfter, "a trickling peer kept its connection past the frame deadline")
        XCTAssertLessThan(t, 2.5)
    }

    // ...and so do the slots they hold (each connection has its own thread, so none waits for a
    // worker to start its clock).
    func testSlotsHeldByTricklingPeersFreeUpAtTheDeadline() throws {
        try skipIfSocketBindDenied()
        try XCTSkipIf(geteuid() == 0, "root takes no slot")
        let dir = TempDir()
        let path = dir.path("t.sock")
        let server = UnixSocketServer(path: path, handler: OKHandler(), ioTimeout: 1)
        try server.start()
        defer { server.stop() }
        let fds = try (0..<UnixSocketServer.maxConnections).map { _ in try announce(path, length: 1 << 20) }
        defer { fds.forEach { close($0) } }
        Thread.sleep(forTimeInterval: 0.2)
        let client = UnixSocketClient(path: path, replyTimeout: 3)
        XCTAssertThrowsError(try client.send(.status), "every slot is held")
        let start = Date()
        var servedAfter: TimeInterval?
        while Date().timeIntervalSince(start) < 5 {
            for fd in fds { _ = UnixSocket.writeAll(fd, Data([0x20])) }
            if case .ok? = try? client.send(.status) {
                servedAfter = Date().timeIntervalSince(start)
                break
            }
            Thread.sleep(forTimeInterval: 0.2)
        }
        let t = try XCTUnwrap(servedAfter, "trickling peers kept every slot")
        XCTAssertLessThan(t, 2.5)
    }

    // The frame deadline is monotonic: a far one must not overflow the poll timeout, and one that
    // has passed fails at once even with the bytes already waiting.
    func testFrameDeadlineEdges() throws {
        var fds: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, UnixSocket.streamType, 0, &fds), 0)
        defer { close(fds[0]); close(fds[1]) }
        XCTAssertTrue(UnixSocket.sendFrame(fds[0], Data("hi".utf8), deadline: .distantFuture))
        XCTAssertEqual(UnixSocket.receiveFrame(fds[1], deadline: .distantFuture), Data("hi".utf8))
        XCTAssertTrue(UnixSocket.sendFrame(fds[0], Data("hi".utf8)))
        XCTAssertNil(UnixSocket.receiveFrame(fds[1], deadline: .now() - .seconds(1)))
    }

    func testRequestsStillWorkUnderTheFrameDeadline() throws {
        try skipIfSocketBindDenied()
        let dir = TempDir()
        let server = UnixSocketServer(path: dir.path("t.sock"), handler: OKHandler(), ioTimeout: 1)
        try server.start()
        defer { server.stop() }
        let client = UnixSocketClient(path: dir.path("t.sock"))
        for _ in 0..<3 {
            guard case .hello(let v) = try client.send(.hello(clientVersion: whoReadIPCVersion)) else { return XCTFail() }
            XCTAssertEqual(v, whoReadIPCVersion)
        }
    }
}
