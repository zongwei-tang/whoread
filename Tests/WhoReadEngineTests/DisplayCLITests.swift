import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// privacy-3: the CLI printed file, process and bundle names as they are, so a name with terminal
/// escape sequences could hide the rest of its row in `whoread asks` (CATEGORY, PATH, AGENT under
/// `ESC[8m`) or erase its own line in `tail` / `events` (`\r ESC[2K`). Runs the built `whoread`:
/// `replay` needs no daemon; `asks` / `alerts` use a stub daemon on a dev socket.
final class DisplayCLITests: XCTestCase {
    private static let binary: String? = {
        var dirs = Bundle.allBundles.filter { $0.bundlePath.hasSuffix(".xctest") }.map { $0.bundleURL.deletingLastPathComponent() }
        dirs.append(repoRoot.appendingPathComponent(".build/debug"))
        return dirs.map { $0.appendingPathComponent("whoread").path }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }()

    private struct Run {
        let status: Int32
        let stdout: Data
        let stderr: Data
        var text: String { String(decoding: stdout, as: UTF8.self) }
    }

    private func whoread(_ args: [String]) throws -> Run {
        guard let bin = DisplayCLITests.binary else { throw XCTSkip("the whoread executable is not built") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["--lang", "en"] + args
        p.environment = ["PATH": "/usr/bin:/bin", "HOME": ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), "TZ": "UTC"]
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        try p.run()
        let o = out.fileHandleForReading.readDataToEndOfFile()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Run(status: p.terminationStatus, stdout: o, stderr: e)
    }

    /// No byte a terminal acts on: ESC, CR, BEL, the C1 CSI (as UTF-8), and no bidi override.
    private func assertNoTerminalControls(_ data: Data, file: StaticString = #filePath, line: UInt = #line) {
        let text = String(decoding: data, as: UTF8.self)
        let bad = text.unicodeScalars.filter { $0 != "\n" && DisplayText.isHidden($0) }
        XCTAssertTrue(bad.isEmpty, "raw control characters \(bad.map(\.value)) in:\n\(text)", file: file, line: line)
    }

    /// A review probe: the msgv10 capture with node's executable moved into a bundle whose name
    /// fakes the columns of a harmless row, then conceals the rest; node's own name erases its line.
    /// (U+2215 looks like "/", which a file name cannot contain.)
    static let craftedNode = #"\/Users\/alice\/x\/Terminal  SSH keys∕medium  read\u001b[8m.app\/Contents\/MacOS\/node\r\u001b[2K"#

    private func craftedCapture(_ dir: TempDir) throws -> String {
        let original = try String(contentsOfFile: fixtureV10, encoding: .utf8)
        let node = #"\/opt\/homebrew\/Cellar\/node\/22.9.0\/bin\/node"#
        XCTAssertTrue(original.contains(node))
        let path = dir.path("crafted.jsonl")
        try original.replacingOccurrences(of: node, with: DisplayCLITests.craftedNode).write(toFile: path, atomically: false, encoding: .utf8)
        return path
    }

    func testReplayEscapesNamesInEventRowsAndAlertLines() throws {
        let dir = TempDir()
        let capture = try craftedCapture(dir)
        let data = repoRoot.appendingPathComponent("Data").path
        let r = try whoread(["replay", capture, "--home", "/Users/alice", "--defaults", data, "--all"])
        XCTAssertEqual(r.status, 0, String(decoding: r.stderr, as: UTF8.self))
        assertNoTerminalControls(r.stdout)
        assertNoTerminalControls(r.stderr)
        let text = r.text
        XCTAssertTrue(text.contains("read\\u{1b}[8m"), "the bundle name is shown, escaped:\n\(text)")
        XCTAssertTrue(text.contains("node\\u{d}\\u{1b}[2K"), "the process name is shown, escaped:\n\(text)")
        // The table still lines up: every row of the events table has the header's column starts.
        XCTAssertTrue(text.contains("TIME"), text)

        // JSON stays exact: the raw name round-trips (JSON escaping covers it).
        let json = try whoread(["replay", capture, "--home", "/Users/alice", "--defaults", data, "--all", "--json"])
        XCTAssertEqual(json.status, 0)
        XCTAssertFalse(json.text.contains("\u{1B}"), "JSON escapes ESC itself")
        XCTAssertTrue(json.text.contains("read\\u001b[8m.app"), "the exact name, JSON-escaped")
    }

    /// Review round: JSONEncoder escapes C0 only, so `--json` printed a C1 CSI (U+009B, a control
    /// sequence introducer to some terminals), bidi overrides and DEL raw. They are `\u` escapes now,
    /// and the document still decodes to the exact name.
    func testJSONOutputEscapesC1AndBidiCharactersLosslessly() throws {
        let dir = TempDir()
        let original = try String(contentsOfFile: fixtureV10, encoding: .utf8)
        let node = #"\/opt\/homebrew\/Cellar\/node\/22.9.0\/bin\/node"#
        // In the capture's own JSON escapes: U+009B, U+202E, DEL and a tag character (U+E0041).
        let crafted = #"\/Users\/alice\/x\/evil\u009b8m\u202ex\u007f\udb40\udc41.app\/Contents\/MacOS\/node"#
        let path = dir.path("c1.jsonl")
        try original.replacingOccurrences(of: node, with: crafted).write(toFile: path, atomically: false, encoding: .utf8)
        let data = repoRoot.appendingPathComponent("Data").path
        let r = try whoread(["replay", path, "--home", "/Users/alice", "--defaults", data, "--all", "--json"])
        XCTAssertEqual(r.status, 0, String(decoding: r.stderr, as: UTF8.self))
        assertNoTerminalControls(r.stdout)
        // Beyond the BMP: a surrogate pair.
        XCTAssertTrue(r.text.contains(#"evil\u009b8m\u202ex\u007f\udb40\udc41.app"#), r.text)
        // Still JSON, with the exact name in it.
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: r.stdout) as? [String: Any])
        let events = try XCTUnwrap(object["events"] as? [[String: Any]])
        let process = try XCTUnwrap(events.compactMap { $0["process"] as? [String: Any] }.first {
            ($0["executablePath"] as? String)?.contains("evil") == true
        })
        XCTAssertEqual(process["executablePath"] as? String,
                       "/Users/alice/x/evil\u{9B}8m\u{202E}x\u{7F}\u{E0041}.app/Contents/MacOS/node")
    }

    // MARK: - asks / alerts against a stub daemon

    private final class Stub: IPCHandler, @unchecked Sendable {
        let data: DefaultData
        var asks: [AskRequest] = []
        var alerts: [Alert] = []
        var events: [AnalyzedEvent] = []
        init() throws { data = try DefaultData.load(directory: repoRoot.appendingPathComponent("Data")) }
        func handle(_ request: IPCRequest, peer: IPCPeer) -> IPCResponse {
            switch request {
            case .hello: return .hello(serverVersion: whoReadIPCVersion)
            case .asks: return .asks(asks)
            case .alerts: return .alerts(alerts)
            case .events(let q): return .events(Array(events.filter { e in q.afterID.map { e.id > $0 } ?? true }.prefix(q.limit)))
            case .catalog: return .catalog(CatalogInfo(catalog: data.catalog, detected: [:], prefixes: [], homeDirectories: ["/Users/alice"]))
            case .agents: return .agents(data.agents)
            case .answerAsk: return .error(IPCError(.notPermitted, "no \u{1B}[2J rule\nforged line"))
            default: return .error(IPCError(.invalid, "not served by this stub"))
            }
        }
    }

    static let lure = "Terminal  SSH keys∕medium  read\u{1B}[8m"
    static let bundle = "/Users/alice/x/\(lure).app"

    private func crafted() -> (ResponsibleEntity, [ChainLink]) {
        let who = ResponsibleEntity(kind: .app, key: "app:" + PathNormalizer.fold(DisplayCLITests.bundle), displayName: DisplayCLITests.lure,
                                    path: DisplayCLITests.bundle)
        let chain = [ChainLink(pid: 1, name: "launchd", path: "/sbin/launchd", isPlatformBinary: true),
                     ChainLink(pid: 50, name: "claude", path: "/opt/homebrew/bin/claude", agentID: "claude-code"),
                     ChainLink(pid: 60, name: "r\r\u{1B}[2K", path: DisplayCLITests.bundle + "/Contents/MacOS/r")]
        return (who, chain)
    }

    func testAsksAndAlertsEscapeNamesAndShowTheRealProgram() throws {
        try skipIfSocketBindDenied()
        let dir = TempDir()
        let stub = try Stub()
        let (who, chain) = crafted()
        let t = Date(timeIntervalSince1970: 1_760_000_000)
        let key = "/Users/alice/WhoReadTestVault/ssh/id_ed25519"
        stub.asks = [AskRequest(id: 7, key: AskKey(responsibleKey: who.key, categoryID: "test-vault", access: .read, chainAgents: ["claude-code"]),
                                responsible: who, severity: .critical, path: key,
                                process: ProcessRecord(pid: 60, ppid: 50, executablePath: DisplayCLITests.bundle + "/Contents/MacOS/r"),
                                chain: chain, agentID: "claude-code", appleProgram: false, firstAt: t, lastAt: t, attempts: 1, holding: 1)]
        stub.alerts = [Alert(id: 5, kind: .ask, createdAt: t, updatedAt: t, windowEndsAt: t + 600, responsible: who, categoryID: "test-vault",
                             severity: .critical, count: 1, accesses: .read, firstPath: key, firstEventID: 1, lastEventID: 1,
                             paths: [key], chain: chain, agentID: "claude-code", ruleID: nil)]
        let server = UnixSocketServer(path: dir.path("s.sock"), handler: stub)
        try server.start()
        defer { server.stop() }

        let asks = try whoread(["--socket", dir.path("s.sock"), "asks"])
        XCTAssertEqual(asks.status, 0, String(decoding: asks.stderr, as: UTF8.self))
        assertNoTerminalControls(asks.stdout)
        let row = try XCTUnwrap(asks.text.split(separator: "\n").map(String.init).first { $0.hasPrefix("7 ") }, asks.text)
        // The concealed columns are there and visible: category, path and the AI agent.
        for cell in ["read\\u{1b}[8m", "~/WhoReadTestVault/ssh/id_ed25519", "Claude Code",
                     "~/x/Terminal  SSH keys∕medium  read\\u{1b}[8m.app (not signed by an identified developer)"] {
            XCTAssertTrue(row.contains(cell), "\(cell) in \(row)")
        }
        XCTAssertTrue(asks.text.contains("PROGRAM"), asks.text)

        let alerts = try whoread(["--socket", dir.path("s.sock"), "alerts"])
        XCTAssertEqual(alerts.status, 0, String(decoding: alerts.stderr, as: UTF8.self))
        assertNoTerminalControls(alerts.stdout)
        XCTAssertTrue(alerts.text.contains("    Program: ~/x/Terminal  SSH keys∕medium  read\\u{1b}[8m.app"), alerts.text)
        XCTAssertTrue(alerts.text.contains("r\\u{d}\\u{1b}[2K"), alerts.text)

        // A daemon's error text is escaped too (one line, no screen clear).
        let refused = try whoread(["--socket", dir.path("s.sock"), "ask", "7", "allow"])
        XCTAssertEqual(refused.status, 77)
        assertNoTerminalControls(refused.stderr)
        XCTAssertTrue(String(decoding: refused.stderr, as: UTF8.self).contains("no \\u{1b}[2J rule\\u{a}forged line"))

        let json = try whoread(["--socket", dir.path("s.sock"), "asks", "--json"])
        XCTAssertEqual(try Exporter.decoder().decode([AskRequest].self, from: json.stdout), stub.asks, "JSON stays exact")
    }

    /// Review round: `whoread export` (JSON and JSON lines, to stdout by default) wrote through its own
    /// encoder, with C1, DEL and bidi characters raw. Escaped as for --json, decoding to the same events.
    func testExportEscapesHiddenCharactersInJSONLosslessly() throws {
        try skipIfSocketBindDenied()
        let dir = TempDir()
        let stub = try Stub()
        let (who, chain) = crafted()
        let t = Date(timeIntervalSince1970: 1_760_000_000)
        stub.events = [AnalyzedEvent(id: 1, time: t, operation: .open, access: .read,
                                     path: "/Users/alice/WhoReadTestVault/x\u{9B}8m\u{202E}y\u{7F}", secondaryPath: nil,
                                     categoryID: "test-vault", severity: .critical,
                                     process: ProcessRecord(pid: 60, ppid: 50, executablePath: DisplayCLITests.bundle + "/Contents/MacOS/r"),
                                     chain: chain, responsible: who, agentID: "claude-code", isOwner: false, benignServiceID: nil,
                                     decision: .allowed, ruleID: nil)]
        let server = UnixSocketServer(path: dir.path("s.sock"), handler: stub)
        try server.start()
        defer { server.stop() }

        let json = try whoread(["--socket", dir.path("s.sock"), "export", "--format", "json"])
        XCTAssertEqual(json.status, 0, String(decoding: json.stderr, as: UTF8.self))
        assertNoTerminalControls(json.stdout)
        XCTAssertEqual(try Exporter.decoder().decode([AnalyzedEvent].self, from: json.stdout), stub.events)

        let lines = try whoread(["--socket", dir.path("s.sock"), "export", "--format", "jsonl"])
        XCTAssertEqual(lines.status, 0, String(decoding: lines.stderr, as: UTF8.self))
        assertNoTerminalControls(lines.stdout)
        let decoded = try lines.text.split(separator: "\n").map { try Exporter.decoder().decode(AnalyzedEvent.self, from: Data($0.utf8)) }
        XCTAssertEqual(decoded, stub.events)
    }

    func testLogLinesEscapeBidiAndZeroWidthCharactersToo() {
        // The log shares the display sanitizer: a right-to-left override cannot reorder a log line.
        XCTAssertEqual(Log.sanitize("rule \u{202E}kcolb\u{200B}"), "rule \\u{202e}kcolb\\u{200b}")
        XCTAssertEqual(Log.sanitize(String(repeating: "a", count: 5000)), String(repeating: "a", count: 4096) + "…")
    }
}
