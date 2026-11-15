import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// cli-8: `whoread asks` says what allowing a question covers; for a question whose starter is unknown
/// that includes chains whose starter is unknown, as the saved rule does (`coversUnknownAncestry`).
/// Runs the built `whoread` against a stub daemon on a dev socket (skipped where binding a Unix
/// socket is not permitted, as in some sandboxes; it runs on CI).
final class R5AsksCoverageCLITests: XCTestCase {
    override func setUpWithError() throws { try skipIfSocketBindDenied() }

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

    /// Serves the requests `whoread asks` makes.
    private final class Stub: IPCHandler, @unchecked Sendable {
        let asks: [AskRequest]
        let data: DefaultData
        init(asks: [AskRequest]) throws {
            self.asks = asks
            data = try DefaultData.load(directory: repoRoot.appendingPathComponent("Data"))
        }
        func handle(_ request: IPCRequest, peer: IPCPeer) -> IPCResponse {
            switch request {
            case .hello: return .hello(serverVersion: whoReadIPCVersion)
            case .asks: return .asks(asks)
            case .settings: return .settings(Settings())
            case .catalog: return .catalog(CatalogInfo(catalog: data.catalog, detected: [:], prefixes: [], homeDirectories: ["/Users/alice"]))
            case .agents: return .agents(data.agents)
            default: return .error(IPCError(.invalid, "not served by this stub"))
            }
        }
    }

    private func whoread(_ args: [String], socket: String, lang: String) throws -> (status: Int32, stdout: String, stderr: String) {
        guard let bin = R5AsksCoverageCLITests.binary else { throw XCTSkip("the whoread executable is not built") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["--socket", socket, "--lang", lang] + args
        p.environment = ["PATH": "/usr/bin:/bin", "HOME": ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), "TZ": "UTC"]
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        try p.run()
        let o = out.fileHandleForReading.readDataToEndOfFile()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: o, as: UTF8.self), String(decoding: e, as: UTF8.self))
    }

    func testAnUnknownStarterQuestionsCoverageIncludesUnknownStarters() throws {
        let terminal = ResponsibleEntity(kind: .app, key: "app:/system/applications/utilities/terminal.app", displayName: "Terminal",
                                         path: "/System/Applications/Utilities/Terminal.app")
        let t = Date(timeIntervalSince1970: 1_760_000_000)
        let q = AskRequest(id: 5, key: AskKey(responsibleKey: terminal.key, categoryID: "test-vault", access: .read, chainAgents: [],
                                              ancestryKnown: false),
                           responsible: terminal, severity: .critical, path: "/Users/alice/WhoReadTestVault/ssh/id_ed25519",
                           process: proc(900, "/usr/bin/ssh", platform: true), chain: [], agentID: nil, appleProgram: false,
                           firstAt: t, lastAt: t)
        let dir = TempDir()
        let server = UnixSocketServer(path: dir.path("s.sock"), handler: try Stub(asks: [q]))
        try server.start()
        defer { server.stop() }

        let en = try whoread(["asks"], socket: dir.path("s.sock"), lang: "en")
        XCTAssertEqual(en.status, 0, en.stderr)
        let cover = try XCTUnwrap(en.stdout.split(separator: "\n").map(String.init).first { $0.hasPrefix("#5 ") }, en.stdout)
        XCTAssertEqual(cover, "#5 allow-once / allow cover: Terminal (any program run in it) reading WhoRead test vault, only when no AI "
                              + "agent is seen in the chain, including chains whose starter is unknown (an AI agent there would not be seen)")
        let zh = try whoread(["asks"], socket: dir.path("s.sock"), lang: "zh-Hans")
        XCTAssertEqual(zh.status, 0, zh.stderr)
        let zhCover = try XCTUnwrap(zh.stdout.split(separator: "\n").map(String.init).first { $0.hasPrefix("#5 ") }, zh.stdout)
        XCTAssertEqual(zhCover, "#5 允许（allow-once、allow）适用于：Terminal（及在其中运行的任何程序）读取 WhoRead 测试保险库，"
                                + "仅限调用链中没有看到 AI agent 时，包括不知道是谁启动的调用链（那里的 AI agent 看不到）")
    }
}
