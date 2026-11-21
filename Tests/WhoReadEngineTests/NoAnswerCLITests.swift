import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC

/// cli-13 / ipc-5: what the built `whoread` says when a request gets no answer. Every run names a
/// service or socket nothing answers at: never the real Mach service (whoread without --service or
/// --socket would ask it).
final class NoAnswerCLITests: XCTestCase {
    /// The `whoread` executable next to the test bundle (as in AskCLITests).
    private static let binary: String? = {
        var dirs: [URL] = []
        #if os(macOS)
        dirs += Bundle.allBundles.filter { $0.bundlePath.hasSuffix(".xctest") }.map { $0.bundleURL.deletingLastPathComponent() }
        #else
        dirs.append(Bundle.main.bundleURL)
        #endif
        dirs.append(repoRoot.appendingPathComponent(".build/debug"))
        return dirs.map { $0.appendingPathComponent("whoread").path }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }()

    private struct Run {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    private func whoread(_ args: [String]) throws -> Run {
        guard let bin = NoAnswerCLITests.binary else { throw XCTSkip("the whoread executable is not built") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["--lang", "en"] + args
        // No WHOREAD_SOCKET or WHOREAD_MACH_SERVICE from the runner's environment.
        p.environment = ["PATH": "/usr/bin:/bin", "HOME": ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory()]
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        try p.run()
        let o = out.fileHandleForReading.readDataToEndOfFile()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Run(status: p.terminationStatus, stdout: String(decoding: o, as: UTF8.self), stderr: String(decoding: e, as: UTF8.self))
    }

    #if os(macOS)
    /// Before: "cannot reach the WhoRead daemon: XPC: Couldn't communicate with a helper application." and
    /// "Is whoreadd running? (sudo launchctl print system/com.whoread.daemon)", whatever service was asked
    /// and whatever XPC said.
    func testAnXPCServiceNothingAnswersAt() throws {
        let name = "com.whoread.test.missing.\(UUID().uuidString)"
        let r = try whoread(["--service", name, "status"])
        XCTAssertEqual(r.status, 69, r.stderr)
        XCTAssertTrue(r.stderr.contains("cannot reach the WhoRead daemon"), r.stderr)
        XCTAssertTrue(r.stderr.contains(name), "names the service it asked: \(r.stderr)")
        XCTAssertFalse(r.stderr.contains("launchctl print system/com.whoread.daemon"), "not the dev LaunchDaemon: \(r.stderr)")
        XCTAssertTrue(r.stderr.contains("systemextensionsctl list"), r.stderr)
        if r.stderr.contains("failed at lookup") {
            // Nothing is registered under that name, so nothing refused anything.
            XCTAssertFalse(r.stderr.contains("refus"), r.stderr)
        } else {
            XCTAssertTrue(r.stderr.contains("scripts/install.sh"), r.stderr)
        }
    }
    #endif

    /// Before: the dev LaunchDaemon's launchctl label, for a socket whoreadd serves only with --dev-socket.
    func testADevSocketNothingListensAt() throws {
        let dir = TempDir()
        let path = dir.path("missing/s.sock")
        let r = try whoread(["--socket", path, "status"])
        XCTAssertEqual(r.status, 69, r.stderr)
        XCTAssertTrue(r.stderr.contains("cannot reach the WhoRead daemon: connect(\(path))"), r.stderr)
        XCTAssertTrue(r.stderr.contains("--dev-socket \(path)"), r.stderr)
        XCTAssertFalse(r.stderr.contains("launchctl"), r.stderr)
        XCTAssertFalse(r.stderr.contains("scripts/install.sh"), r.stderr)
    }

    /// Answers the handshake, refuses the rest.
    private final class HelloOnly: IPCHandler, @unchecked Sendable {
        func handle(_ request: IPCRequest, peer: IPCPeer) -> IPCResponse {
            if case .hello = request { return .hello(serverVersion: whoReadIPCVersion) }
            return .error(IPCError(.invalid, "not served by this stub"))
        }
    }

    /// A request too large for the dev socket is refused by the client before sending it (ipc-4): said as
    /// such, not as a daemon that cannot be reached. Needs a listening socket for the handshake.
    func testARequestTooLargeForTheDevSocketIsNotReportedAsUnreachable() throws {
        try skipIfSocketBindDenied()
        let dir = TempDir()
        let path = dir.path("s.sock")
        let server = UnixSocketServer(path: path, handler: HelloOnly())
        try server.start()
        defer { server.stop() }
        let rule = Rule(id: String(repeating: "r", count: UnixSocket.maxRequestFrame), target: .category("ssh"),
                        subject: .anyNonOwner, action: .alert)
        let file = dir.path("big-rule.json")
        XCTAssertTrue(touch(file, try Exporter.encoder(pretty: false).encode(rule)))
        let r = try whoread(["--socket", path, "rules", "add", "--json-file", file])
        XCTAssertEqual(r.status, 1, r.stderr)
        XCTAssertTrue(r.stderr.contains("request too large"), r.stderr)
        XCTAssertFalse(r.stderr.contains("cannot reach"), r.stderr)
    }
}
