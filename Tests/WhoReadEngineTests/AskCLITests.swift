import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// Ask mode, CLI: `whoread asks`, `whoread ask ID …`, `alert ID trust-apple`,
/// `settings set trust-apple`, the status lines and the help text. No test target links the
/// `whoread` executable, so these run the built binary against a daemon on a dev socket: a stub
/// handler that serves canned questions and records what the CLI sent, or the real strict handler.
final class AskCLITests: XCTestCase {
    override func setUpWithError() throws { try skipIfSocketBindDenied() }

    private static let t = Date(timeIntervalSince1970: 1_760_000_000)

    /// The `whoread` executable next to the test bundle (`swift build --build-tests` builds it).
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

    private func whoread(_ args: [String], socket: String?, lang: String = "en") throws -> Run {
        guard let bin = AskCLITests.binary else { throw XCTSkip("the whoread executable is not built") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = (socket.map { ["--socket", $0] } ?? []) + ["--lang", lang] + args
        // UTC, so the times the CLI prints are known.
        p.environment = ["PATH": "/usr/bin:/bin", "HOME": ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), "TZ": "UTC"]
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        try p.run()
        let o = out.fileHandleForReading.readDataToEndOfFile()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Run(status: p.terminationStatus, stdout: String(decoding: o, as: UTF8.self), stderr: String(decoding: e, as: UTF8.self))
    }

    /// Serves canned answers; records every request.
    private final class StubDaemon: IPCHandler, @unchecked Sendable {
        private let lock = NSLock()
        private var _requests: [IPCRequest] = []
        private var _settings = Settings()
        var asks: [AskRequest] = []
        var alerts: [Alert] = []
        var rules: [Rule] = []
        var status: DaemonStatus?
        /// Refuse allowing answers as ServiceHandler does for the console user without sudo.
        var refuseAllowing = false
        let data: DefaultData

        init() throws { data = try DefaultData.load(directory: repoRoot.appendingPathComponent("Data")) }

        var requests: [IPCRequest] { lock.lock(); defer { lock.unlock() }; return _requests }
        var settings: Settings { lock.lock(); defer { lock.unlock() }; return _settings }

        func handle(_ request: IPCRequest, peer: IPCPeer) -> IPCResponse {
            lock.lock(); defer { lock.unlock() }
            _requests.append(request)
            switch request {
            case .hello: return .hello(serverVersion: whoReadIPCVersion)
            case .asks: return .asks(asks)
            case .answerAsk(let id, let action):
                if refuseAllowing && [.allowOnce, .alwaysAllow, .trustApplePrograms].contains(action) {
                    return .error(IPCError(.notPermitted, "this change weakens protection: run it with sudo, or use the WhoRead app"))
                }
                return .asks(asks.filter { $0.id != id })
            case .alerts: return .alerts(alerts)
            case .alertAction: return .ok
            case .rules: return .rules(rules)
            case .settings: return .settings(_settings)
            case .updateSettings(let s):
                _settings = s
                return .settings(s)
            case .status: return status.map { .status($0) } ?? .error(IPCError(.internalError, "no status"))
            case .catalog: return .catalog(CatalogInfo(catalog: data.catalog, detected: [:], prefixes: [], homeDirectories: ["/Users/alice"]))
            case .agents: return .agents(data.agents)
            default: return .error(IPCError(.invalid, "not served by this stub"))
            }
        }
    }

    private func serve(_ handler: IPCHandler, _ dir: TempDir) throws -> (UnixSocketServer, String) {
        let path = dir.path("s.sock")
        let server = UnixSocketServer(path: path, handler: handler)
        try server.start()
        return (server, path)
    }

    private func question(id: Int64, agent: Bool) -> AskRequest {
        let t = AskCLITests.t
        if agent {
            let who = ResponsibleEntity(kind: .agent, key: "agent:claude-code", displayName: "Claude Code", agentID: "claude-code")
            return AskRequest(id: id, key: AskKey(responsibleKey: who.key, categoryID: "ssh", access: .read, chainAgents: ["claude-code"]),
                              responsible: who, severity: .critical, path: "/Users/alice/.ssh/id_ed25519",
                              process: proc(900, "/bin/cat", platform: true), chain: [], agentID: "claude-code",
                              appleProgram: false, firstAt: t, lastAt: t, attempts: 3, holding: 1, answerBy: t.addingTimeInterval(5))
        }
        let who = ResponsibleEntity(kind: .app, key: "app:/system/applications/preview.app", displayName: "Preview",
                                    path: "/System/Applications/Preview.app")
        return AskRequest(id: id, key: AskKey(responsibleKey: who.key, categoryID: "ssh", access: [.read, .write], chainAgents: []),
                          responsible: who, severity: .critical, path: "/Users/alice/.ssh/config",
                          process: proc(901, "/System/Applications/Preview.app/Contents/MacOS/Preview", platform: true),
                          chain: [], agentID: nil, appleProgram: true, firstAt: t, lastAt: t)
    }

    private func line(_ text: String, starting prefix: String) -> String? {
        text.split(separator: "\n").map(String.init).first { $0.hasPrefix(prefix) }
    }

    // MARK: - asks

    func testAsksTableShowsEachQuestion() throws {
        let dir = TempDir()
        let stub = try StubDaemon()
        stub.asks = [question(id: 7, agent: true), question(id: 8, agent: false)]
        let (server, socket) = try serve(stub, dir)
        defer { server.stop() }

        let en = try whoread(["asks"], socket: socket)
        XCTAssertEqual(en.status, 0, en.stderr)
        for column in ["ID", "APP", "CATEGORY", "ACCESS", "PATH", "AGENT", "WAITING/ATTEMPTS", "APPLE"] {
            XCTAssertTrue(en.stdout.contains(column), "header \(column): \(en.stdout)")
        }
        let claude = try XCTUnwrap(line(en.stdout, starting: "7 "), en.stdout)
        for cell in ["Claude Code", "SSH keys/critical", "read", "~/.ssh/id_ed25519", "1/3"] {
            XCTAssertTrue(claude.contains(cell), "\(cell) in \(claude)")
        }
        XCTAssertFalse(claude.hasSuffix("yes"), "an agent chain is never offered trust-apple")
        let preview = try XCTUnwrap(line(en.stdout, starting: "8 "), en.stdout)
        for cell in ["Preview", "read+write", "~/.ssh/config", "0/1"] { XCTAssertTrue(preview.contains(cell), "\(cell) in \(preview)") }
        XCTAssertTrue(preview.hasSuffix("yes"), preview)
        XCTAssertTrue(en.stdout.contains("whoread ask ID allow-once|allow|deny|block|trust-apple"), "how to answer")
        // task-2: an answer is per app, not per program; each question says what allowing covers.
        let previewCover = try XCTUnwrap(line(en.stdout, starting: "#8 "), en.stdout)
        XCTAssertEqual(previewCover, "#8 allow-once / allow cover: Preview (any program run in it) reading and modifying SSH keys, "
                                     + "only when the chain has no AI agent")
        let claudeCover = try XCTUnwrap(line(en.stdout, starting: "#7 "), en.stdout)
        XCTAssertTrue(claudeCover.hasPrefix("#7 allow-once / allow cover: Claude Code (any program it runs) reading SSH keys, "
                                            + "only when the chain has no AI agent other than "), claudeCover)

        let zh = try whoread(["asks"], socket: socket, lang: "zh-Hans")
        XCTAssertEqual(zh.status, 0, zh.stderr)
        XCTAssertTrue(zh.stdout.contains("等待/次数") && zh.stdout.contains("SSH 密钥"), zh.stdout)
        XCTAssertTrue(try XCTUnwrap(line(zh.stdout, starting: "8 ")).hasSuffix("是"))
        XCTAssertEqual(try XCTUnwrap(line(zh.stdout, starting: "#8 ")),
                       "#8 允许（allow-once、allow）适用于：Preview（及在其中运行的任何程序）读写 SSH 密钥，仅限调用链中没有 AI agent 时")

        let json = try whoread(["asks", "--json"], socket: socket)
        XCTAssertEqual(json.status, 0, json.stderr)
        let decoded = try Exporter.decoder().decode([AskRequest].self, from: Data(json.stdout.utf8))
        XCTAssertEqual(decoded, stub.asks)
    }

    func testEmptyAsks() throws {
        let dir = TempDir()
        let stub = try StubDaemon()
        let (server, socket) = try serve(stub, dir)
        defer { server.stop() }
        let r = try whoread(["asks"], socket: socket)
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertEqual(r.stdout, "No questions waiting.\n")
        XCTAssertEqual(try whoread(["asks", "--json"], socket: socket).stdout.filter { !$0.isWhitespace }, "[]")
    }

    // MARK: - ask ID ANSWER

    func testAnswerWordsMapToTheirActions() throws {
        let dir = TempDir()
        let stub = try StubDaemon()
        stub.asks = [question(id: 7, agent: true), question(id: 8, agent: false)]
        let (server, socket) = try serve(stub, dir)
        defer { server.stop() }
        let words: [(String, AlertAction)] = [
            ("allow-once", .allowOnce), ("allow", .alwaysAllow), ("deny", .keepBlocking), ("block", .blockFromNowOn),
            ("trust-apple", .trustApplePrograms), ("always-allow", .alwaysAllow), ("keep-blocking", .keepBlocking),
        ]
        for (word, action) in words {
            let r = try whoread(["ask", "8", word], socket: socket)
            XCTAssertEqual(r.status, 0, "\(word): \(r.stderr)")
            XCTAssertTrue(r.stdout.hasPrefix("question #8: "), r.stdout)
            XCTAssertTrue(r.stdout.contains("1 more waiting: whoread asks"), r.stdout)
            guard case .answerAsk(let id, let sent)? = stub.requests.last else { return XCTFail("\(word): no answerAsk sent") }
            XCTAssertEqual(id, 8)
            XCTAssertEqual(sent, action, word)
        }
    }

    func testBadAnswersAreUsageErrorsAndSendNothing() throws {
        let dir = TempDir()
        let stub = try StubDaemon()
        let (server, socket) = try serve(stub, dir)
        defer { server.stop() }
        for args in [["ask"], ["ask", "8"], ["ask", "x", "deny"], ["ask", "8", "maybe"], ["ask", "8", "deny", "now"], ["ask", "8", "ignore"]] {
            let r = try whoread(args, socket: socket)
            XCTAssertNotEqual(r.status, 0, "\(args) was accepted")
            XCTAssertTrue(r.stderr.contains("usage: whoread ask"), "\(args): \(r.stderr)")
        }
        XCTAssertFalse(stub.requests.contains { if case .answerAsk = $0 { return true }; return false })
    }

    func testRefusedAllowSaysAllowingNeedsSudo() throws {
        let dir = TempDir()
        let stub = try StubDaemon()
        stub.refuseAllowing = true
        let (server, socket) = try serve(stub, dir)
        defer { server.stop() }
        for word in ["allow-once", "allow", "trust-apple"] {
            let r = try whoread(["ask", "12", word], socket: socket)
            XCTAssertEqual(r.status, 77, r.stderr)
            XCTAssertTrue(r.stderr.contains("Allowing needs root or the WhoRead app"), r.stderr)
            XCTAssertTrue(r.stderr.contains("e.g. sudo whoread --socket \(socket) --lang en ask 12 \(word)"), r.stderr)
        }
        let zh = try whoread(["ask", "12", "allow"], socket: socket, lang: "zh-Hans")
        XCTAssertEqual(zh.status, 77)
        XCTAssertTrue(zh.stderr.contains("允许访问需要 root 或 WhoRead 应用"), zh.stderr)
        XCTAssertEqual(try whoread(["ask", "12", "deny"], socket: socket).status, 0, "denying needs no sudo")
    }

    /// Against the real strict handler, as the console user: allowing is refused with the sudo
    /// hint, denying gets past the permission check.
    func testStrictDaemonRefusesAllowingButNotDenying() throws {
        try XCTSkipIf(geteuid() == 0, "root may allow")
        let dir = TempDir()
        var config = baseConfig(dir)
        config.devSocketPath = dir.path("d.sock")
        let daemon = try Daemon(configuration: config)
        daemon.handler.consoleUID = { geteuid() }
        try daemon.start()
        defer { daemon.stop() }
        let socket = dir.path("d.sock")

        let allow = try whoread(["ask", "1", "allow"], socket: socket)
        XCTAssertEqual(allow.status, 77, allow.stderr)
        XCTAssertTrue(allow.stderr.contains("Allowing needs root"), allow.stderr)
        let deny = try whoread(["ask", "1", "deny"], socket: socket)
        XCTAssertNotEqual(deny.status, 77, "denying is open to the console user: \(deny.stderr)")
        XCTAssertFalse(deny.stderr.contains("not permitted"), deny.stderr)
        let trust = try whoread(["settings", "set", "trust-apple", "on"], socket: socket)
        XCTAssertEqual(trust.status, 77, trust.stderr)
        XCTAssertTrue(trust.stderr.contains("sudo whoread"), trust.stderr)
        XCTAssertFalse(daemon.core.currentSettings.trustApplePrograms)
    }

    // MARK: - alerts, settings

    func testAlertTrustAppleAndAskAlertHint() throws {
        let dir = TempDir()
        let stub = try StubDaemon()
        let t = AskCLITests.t
        let who = ResponsibleEntity(kind: .app, key: "app:/system/applications/preview.app", displayName: "Preview")
        stub.alerts = [Alert(id: 5, kind: .ask, createdAt: t, updatedAt: t, windowEndsAt: t.addingTimeInterval(600),
                             responsible: who, categoryID: "ssh", severity: .critical, count: 1, accesses: .read,
                             firstPath: "/Users/alice/.ssh/config", firstEventID: 1, lastEventID: 1, paths: [], chain: [],
                             agentID: nil, ruleID: nil, appleProgram: true)]
        let (server, socket) = try serve(stub, dir)
        defer { server.stop() }

        let list = try whoread(["alerts"], socket: socket)
        XCTAssertEqual(list.status, 0, list.stderr)
        XCTAssertTrue(list.stdout.contains("[Needs your decision]"), list.stdout)
        XCTAssertTrue(list.stdout.contains("answer: whoread alert 5 allow-once|always-allow|keep-blocking|block|trust-apple"), list.stdout)

        let r = try whoread(["alert", "5", "trust-apple"], socket: socket)
        XCTAssertEqual(r.status, 0, r.stderr)
        guard case .alertAction(let id, let action)? = stub.requests.last else { return XCTFail("no alertAction sent") }
        XCTAssertEqual(id, 5)
        XCTAssertEqual(action, .trustApplePrograms)
    }

    func testTrustAppleSettingRoundTrip() throws {
        let dir = TempDir()
        let stub = try StubDaemon()
        let (server, socket) = try serve(stub, dir)
        defer { server.stop() }
        XCTAssertEqual(try whoread(["settings", "set", "trust-apple", "on"], socket: socket).status, 0)
        XCTAssertTrue(stub.settings.trustApplePrograms)
        XCTAssertEqual(try whoread(["settings", "set", "trust-apple", "off"], socket: socket).status, 0)
        XCTAssertFalse(stub.settings.trustApplePrograms)
        XCTAssertNotEqual(try whoread(["settings", "set", "trust-apple", "maybe"], socket: socket).status, 0)
        XCTAssertFalse(stub.settings.trustApplePrograms)
    }

    /// Answers become rules: the list must tell an approval for Terminal from one for Claude Code in
    /// Terminal, and "allow once" from "always allow".
    func testRulesListShowsChainAgentScopeAndExpiry() throws {
        let dir = TempDir()
        let stub = try StubDaemon()
        let t = AskCLITests.t
        let terminal = RuleSubject.responsible(key: "app:/system/applications/utilities/terminal.app", teamID: nil)
        stub.rules = [
            Rule(id: "plain", target: .category("ssh"), subject: terminal, access: .read, action: .allow, template: "ask-answer",
                 chainAgents: []),
            Rule(id: "agent", target: .category("ssh"), subject: terminal, access: .read, action: .allow,
                 expiresAt: t.addingTimeInterval(600), template: "ask-answer", chainAgents: ["claude-code"]),
            Rule(id: "old", target: .category("ssh"), subject: terminal, access: .read, action: .allow),
            Rule(id: "unknown", target: .category("ssh"), subject: terminal, access: .read, action: .allow, template: "ask-answer",
                 chainAgents: [], coversUnknownAncestry: true),
        ]
        let (server, socket) = try serve(stub, dir)
        defer { server.stop() }
        let r = try whoread(["rules"], socket: socket)
        XCTAssertEqual(r.status, 0, r.stderr)
        let plain = try XCTUnwrap(line(r.stdout, starting: "plain "), r.stdout)
        XCTAssertTrue(plain.contains("terminal.app, no AI agent in chain"), plain)
        XCTAssertFalse(plain.contains("unknown starter"), plain)
        XCTAssertFalse(plain.contains("until"), plain)
        // An answer given for a program whose starter was unknown also covers such chains.
        let unknown = try XCTUnwrap(line(r.stdout, starting: "unknown "), r.stdout)
        XCTAssertTrue(unknown.contains("terminal.app, no AI agent in chain (also unknown starter)"), unknown)
        let agent = try XCTUnwrap(line(r.stdout, starting: "agent "), r.stdout)
        XCTAssertTrue(agent.contains("terminal.app, chain agents claude-code"), agent)
        XCTAssertTrue(agent.contains("on until 2025-10-09 09:03:20"), agent)
        let old = try XCTUnwrap(line(r.stdout, starting: "old "), r.stdout)
        XCTAssertFalse(old.contains("chain") || old.contains("until"), "a rule from before ask mode covers any chain: \(old)")
    }

    // MARK: - status, help

    private func status(learning: Bool, pendingAsks: Int?, uncleanStop: String?, misses: Int, p99: Double) -> DaemonStatus {
        let t = AskCLITests.t
        return DaemonStatus(
            version: "test", pid: 1, startedAt: t, mode: .enforcing, source: .native, sourceRunning: true, sourceError: nil,
            sourceHint: nil, sourceCanEnforce: true, learning: learning, learningEndsAt: t.addingTimeInterval(86400),
            monitoringPaused: false, enforcementEnabled: true, enforcementActive: true, enforcementInactiveReasons: [],
            latencyTripReason: nil, killSwitchFilePresent: false,
            latency: LatencyStats(samples: 100, p50Micros: 80, p99Micros: p99, maxMicros: p99, deadlineMisses: misses, totalResponses: 100),
            parser: nil, counts: StoreCounts(events: 0, aggregatedDays: 0, alerts: 0, unreadAlerts: 0), unreadAlerts: 0,
            lastEventAt: nil, eventsProcessed: 0, writerDropped: 0, monitoredPrefixes: 1, homeDirectories: ["/Users/alice"],
            pendingAsks: pendingAsks, uncleanStop: uncleanStop)
    }

    func testStatusShowsQuestionsUncleanStopAndLatencyWarningsButNoLearning() throws {
        let dir = TempDir()
        let stub = try StubDaemon()
        stub.status = status(learning: true, pendingAsks: 2, uncleanStop: "stopped while AUTH was subscribed at 2026-10-05 09:00",
                             misses: 3, p99: 120_000)
        let (server, socket) = try serve(stub, dir)
        defer { server.stop() }
        let r = try whoread(["status"], socket: socket)
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertTrue(r.stdout.contains("questions:    2 waiting for your answer (whoread asks)"), r.stdout)
        XCTAssertTrue(r.stdout.contains("unclean stop: stopped while AUTH was subscribed at 2026-10-05 09:00"), r.stdout)
        XCTAssertTrue(r.stdout.contains("WARNING: 3 AUTH deadline misses"), r.stdout)
        XCTAssertTrue(r.stdout.contains("WARNING: AUTH p99 latency 120.0 ms is over latency-p99-ms 50 ms"), r.stdout)
        XCTAssertFalse(r.stdout.lowercased().contains("learning"), r.stdout)
        XCTAssertFalse(r.stdout.lowercased().contains("trip"), r.stdout)

        stub.status = status(learning: false, pendingAsks: 0, uncleanStop: nil, misses: 0, p99: 900)
        let calm = try whoread(["status"], socket: socket)
        XCTAssertTrue(calm.stdout.contains("questions:    none waiting"), calm.stdout)
        XCTAssertFalse(calm.stdout.contains("WARNING"), calm.stdout)
        XCTAssertFalse(calm.stdout.contains("unclean stop"), calm.stdout)
    }

    func testHelpDocumentsAskModeAndDropsRestartLearning() throws {
        let r = try whoread(["help"], socket: nil)
        XCTAssertEqual(r.status, 0)
        for text in ["asks [--json]", "ask <id> deny|block", "ask <id> allow-once|allow", "trust-apple on|off", "Ask mode:",
                     "never switched off automatically"] {
            XCTAssertTrue(r.stdout.contains(text), text)
        }
        // No learning period any more: not restart-learning, the learning-days key or replay's option.
        XCTAssertFalse(r.stdout.lowercased().contains("learning"), r.stdout)
    }
}
