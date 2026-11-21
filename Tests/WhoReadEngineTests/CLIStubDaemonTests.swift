import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// Round-5 command line fixes that need a daemon reply: the built `whoread` against a stub daemon
/// on a dev socket, which records every request. They skip where binding a Unix socket is not
/// permitted (scripts/dev/sc-build.sh inside a sandbox) and run on CI.
final class CLIStubDaemonTests: XCTestCase {
    override func setUpWithError() throws { try skipIfSocketBindDenied() }

    private static let t = Date(timeIntervalSince1970: 1_760_000_000)

    private static let binary: String? = {
        var dirs = Bundle.allBundles.filter { $0.bundlePath.hasSuffix(".xctest") }.map { $0.bundleURL.deletingLastPathComponent() }
        dirs.append(repoRoot.appendingPathComponent(".build/debug"))
        return dirs.map { $0.appendingPathComponent("whoread").path }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }()

    private struct Run {
        let status: Int32
        let reason: Process.TerminationReason
        let stdout: String
        let stderr: String
    }

    /// Serves canned replies; records every request. `.events` answers like the SQLite store: the
    /// LIMIT is taken first, then the rows in `undecodable` are dropped.
    private final class Stub: IPCHandler, @unchecked Sendable {
        private let lock = NSLock()
        private var _requests: [IPCRequest] = []
        private var _settings = Settings()
        private var _events: [AnalyzedEvent] = []
        var undecodable: Set<Int64> = []
        var alerts: [Alert] = []
        var asks: [AskRequest] = []
        var daily: [DailyAggregate] = []
        var status: DaemonStatus?
        var catalog: Catalog
        let data: DefaultData

        init() throws {
            data = try DefaultData.load(directory: repoRoot.appendingPathComponent("Data"))
            catalog = data.catalog
        }

        var requests: [IPCRequest] { lock.lock(); defer { lock.unlock() }; return _requests }
        var settings: Settings {
            get { lock.lock(); defer { lock.unlock() }; return _settings }
            set { lock.lock(); defer { lock.unlock() }; _settings = newValue }
        }
        var events: [AnalyzedEvent] {
            get { lock.lock(); defer { lock.unlock() }; return _events }
            set { lock.lock(); defer { lock.unlock() }; _events = newValue }
        }
        var eventQueries: [EventQuery] { requests.compactMap { if case .events(let q) = $0 { return q }; return nil } }
        var settingsUpdates: [Settings] { requests.compactMap { if case .updateSettings(let s) = $0 { return s }; return nil } }

        func handle(_ request: IPCRequest, peer: IPCPeer) -> IPCResponse {
            lock.lock(); defer { lock.unlock() }
            _requests.append(request)
            switch request {
            case .hello: return .hello(serverVersion: whoReadIPCVersion)
            case .events(var q):
                q.limit = min(q.limit, 100_000)
                var rows = _events.filter { e in
                    var probe = q
                    probe.text = nil
                    probe.appName = nil
                    return probe.matches(e)
                }.sorted { $0.id < $1.id }
                if q.newestFirst { rows.reverse() }
                return .events(rows.prefix(q.limit).filter { !undecodable.contains($0.id) })
            case .alerts(let q): return .alerts(Array(alerts.prefix(q.limit)))
            case .asks: return .asks(asks)
            case .dailyAggregates: return .dailyAggregates(daily)
            case .alertAction: return .ok
            case .settings: return .settings(_settings)
            case .updateSettings(let s):
                _settings = s
                return .settings(s)
            case .status: return status.map { .status($0) } ?? .error(IPCError(.internalError, "no status"))
            case .catalog:
                return .catalog(CatalogInfo(catalog: catalog, detected: [:], prefixes: [], homeDirectories: ["/Users/alice"]))
            case .agents: return .agents(data.agents)
            default: return .error(IPCError(.invalid, "not served by this stub"))
            }
        }
    }

    private let dir = TempDir()
    private var socket: String { dir.path("s.sock") }

    private func serve(_ stub: Stub) throws -> UnixSocketServer {
        let server = UnixSocketServer(path: socket, handler: stub)
        try server.start()
        return server
    }

    /// `shell` wraps the call in `/bin/sh -c` (`"$0" "$@"` is the call); `closedStdout` gives it a
    /// pipe whose reading end is already closed.
    private func whoread(_ args: [String], lang: String = "en", cwd: String? = nil, shell: String? = nil,
                         closedStdout: Bool = false) throws -> Run {
        guard let bin = CLIStubDaemonTests.binary else { throw XCTSkip("the whoread executable is not built") }
        let p = Process()
        let argv = ["--socket", socket, "--lang", lang] + args
        if let shell {
            p.executableURL = URL(fileURLWithPath: "/bin/sh")
            p.arguments = ["-c", shell, bin] + argv
        } else {
            p.executableURL = URL(fileURLWithPath: bin)
            p.arguments = argv
        }
        if let cwd { p.currentDirectoryURL = URL(fileURLWithPath: cwd, isDirectory: true) }
        p.environment = ["PATH": "/usr/bin:/bin", "HOME": dir.url.path, "TZ": "UTC"]
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        if closedStdout { try out.fileHandleForReading.close() }
        try p.run()
        let o = closedStdout ? Data() : out.fileHandleForReading.readDataToEndOfFile()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Run(status: p.terminationStatus, reason: p.terminationReason,
                   stdout: String(decoding: o, as: UTF8.self), stderr: String(decoding: e, as: UTF8.self))
    }

    private func event(_ id: Int64, path: String = "/Users/alice/WhoReadTestVault/ssh/id_ed25519", app: String = "Terminal",
                       program: String = "cat") -> AnalyzedEvent {
        AnalyzedEvent(id: id, time: CLIStubDaemonTests.t.addingTimeInterval(Double(id)), operation: .open, access: .read, path: path,
                      secondaryPath: nil, categoryID: "test-vault", severity: .critical,
                      process: ProcessRecord(pid: Int32(id), ppid: 1, executablePath: "/bin/" + program), chain: [],
                      responsible: ResponsibleEntity(kind: .app, key: "app:/applications/\(app.lowercased()).app", displayName: app),
                      agentID: nil, isOwner: false, benignServiceID: nil, decision: .observed, ruleID: nil)
    }

    private func alert(_ id: Int64) -> Alert {
        let t = CLIStubDaemonTests.t
        return Alert(id: id, kind: .firstAccess, createdAt: t, updatedAt: t.addingTimeInterval(Double(-id)), windowEndsAt: t,
                     responsible: ResponsibleEntity(kind: .app, key: "app:/applications/terminal.app", displayName: "Terminal"),
                     categoryID: "test-vault", severity: .critical, count: 1, accesses: .read,
                     firstPath: "/Users/alice/WhoReadTestVault/ssh/id_ed25519", firstEventID: id, lastEventID: id, paths: [],
                     chain: [], agentID: nil, ruleID: nil)
    }

    private func question(_ id: Int64, path: String = "/Users/alice/WhoReadTestVault/ssh/config") -> AskRequest {
        let t = CLIStubDaemonTests.t
        let who = ResponsibleEntity(kind: .app, key: "app:/applications/preview.app", displayName: "Preview", path: "/Applications/Preview.app")
        return AskRequest(id: id, key: AskKey(responsibleKey: who.key, categoryID: "test-vault", access: .read, chainAgents: []),
                          responsible: who, severity: .critical, path: path,
                          process: ProcessRecord(pid: 900, ppid: 1, executablePath: "/Applications/Preview.app/Contents/MacOS/Preview"),
                          chain: [], agentID: nil, appleProgram: false, firstAt: t, lastAt: t)
    }

    private func status(events: Int) -> DaemonStatus {
        let t = CLIStubDaemonTests.t
        return DaemonStatus(
            version: "test", pid: 1, startedAt: t, mode: .monitoring, source: .eslogger, sourceRunning: true, sourceError: nil,
            sourceHint: nil, sourceCanEnforce: false, learning: false, learningEndsAt: t, monitoringPaused: false,
            enforcementEnabled: false, enforcementActive: false, enforcementInactiveReasons: [.disabledByUser],
            latencyTripReason: nil, killSwitchFilePresent: false,
            latency: LatencyStats(samples: 0, p50Micros: 0, p99Micros: 0, maxMicros: 0, deadlineMisses: 0, totalResponses: 0),
            parser: nil, counts: StoreCounts(events: events, aggregatedDays: 0, alerts: 2, unreadAlerts: 1), unreadAlerts: 1,
            lastEventAt: nil, eventsProcessed: 0, writerDropped: 0, monitoredPrefixes: 3, homeDirectories: ["/Users/alice"],
            pendingAsks: 0, uncleanStop: nil)
    }

    private func realpathOf(_ path: String) -> String {
        guard let r = realpath(path, nil) else { return path }
        defer { free(r) }
        return String(cString: r)
    }

    // MARK: - cli-1: project roots

    func testRelativeProjectRootsAreStoredAsAbsolutePaths() throws {
        let stub = try Stub()
        let server = try serve(stub)
        defer { server.stop() }
        let project = dir.path("code/app")
        try FileManager.default.createDirectory(atPath: project + "/src", withIntermediateDirectories: true)
        let here = realpathOf(project)

        var r = try whoread(["settings", "set", "project-root-add", "."], cwd: project)
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertEqual(stub.settings.projectRoots, [here])
        r = try whoread(["settings", "set", "project-root-add", "src"], cwd: project)
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertEqual(stub.settings.projectRoots, [here, here + "/src"])
        // The same folder again, spelled another way: nothing changes.
        let updates = stub.settingsUpdates.count
        r = try whoread(["settings", "set", "project-root-add", here + "/src/"])
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertTrue(r.stderr.contains("already a project root"), r.stderr)
        XCTAssertEqual(stub.settingsUpdates.count, updates)
        // A home is refused once the daemon has said which homes it monitors.
        r = try whoread(["settings", "set", "project-root-add", "/Users/alice"])
        XCTAssertEqual(r.status, 64, r.stderr)
        XCTAssertEqual(stub.settingsUpdates.count, updates)
    }

    func testProjectRootRemoveMatchesOtherSpellingsAndFailsWhenNothingMatches() throws {
        let stub = try Stub()
        let project = dir.path("app")
        XCTAssertEqual(mkdir(project, 0o755), 0)
        let here = realpathOf(project)
        stub.settings.projectRoots = [".", "~/code", "/Users/alice/Work", here]
        let server = try serve(stub)
        defer { server.stop() }

        var r = try whoread(["settings", "set", "project-root-remove", "~/code/"])
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertEqual(stub.settings.projectRoots, [".", "/Users/alice/Work", here])
        r = try whoread(["settings", "set", "project-root-remove", "/users/alice/work"])
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertEqual(stub.settings.projectRoots, [".", here])
        // An entry stored before these checks, which never worked, can still be removed as typed.
        r = try whoread(["settings", "set", "project-root-remove", "."], cwd: "/")
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertEqual(stub.settings.projectRoots, [here])
        r = try whoread(["settings", "set", "project-root-remove", "."], cwd: project)
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertEqual(stub.settings.projectRoots, [])

        let updates = stub.settingsUpdates.count
        r = try whoread(["settings", "set", "project-root-remove", "~/nothing"])
        XCTAssertEqual(r.status, 1, r.stderr)
        XCTAssertTrue(r.stderr.contains("no project root ~/nothing"), r.stderr)
        XCTAssertEqual(stub.settingsUpdates.count, updates, "nothing sent when nothing matches")
    }

    // MARK: - cli-3: listings say when more match

    func testEventsAlertsAndAsksSayWhenMoreMatchThanAreShown() throws {
        let stub = try Stub()
        stub.events = (1...5).map { event($0) }
        stub.alerts = (1...3).map { alert($0) }
        let server = try serve(stub)
        defer { server.stop() }

        var r = try whoread(["events", "--limit", "2"])
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertEqual(stub.eventQueries.last?.limit, 3, "one more than shown")
        XCTAssertEqual(r.stdout.split(separator: "\n").count, 2 + 2, "header, rule, two rows: \(r.stdout)")
        XCTAssertTrue(r.stderr.contains("only the newest 2 matching events are shown; use --limit N for more, or whoread export"), r.stderr)
        r = try whoread(["events", "--limit", "2", "--json"])
        XCTAssertEqual(try Exporter.decoder().decode([AnalyzedEvent].self, from: Data(r.stdout.utf8)).map(\.id), [5, 4])
        XCTAssertTrue(r.stderr.contains("only the newest 2"), r.stderr)
        r = try whoread(["events", "--limit", "2"], lang: "zh-Hans")
        XCTAssertTrue(r.stderr.contains("只显示了最新的 2 条匹配事件"), r.stderr)
        r = try whoread(["events", "--limit", "5"])
        XCTAssertFalse(r.stderr.contains("note:"), r.stderr)
        r = try whoread(["events"])
        XCTAssertEqual(stub.eventQueries.last?.limit, 501)
        XCTAssertFalse(r.stderr.contains("note:"), r.stderr)

        r = try whoread(["alerts", "--limit", "2"])
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertTrue(r.stderr.contains("only the 2 most recently updated alerts are shown"), r.stderr)
        XCTAssertFalse(try whoread(["alerts", "--limit", "3"]).stderr.contains("note:"))

        stub.asks = (1...200).map { question($0) }
        r = try whoread(["asks"])
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertTrue(r.stderr.contains("more may be waiting: answer the rest in whoread alerts"), r.stderr)
        stub.asks = (1...199).map { question($0) }
        XCTAssertFalse(try whoread(["asks", "--json"]).stderr.contains("note:"))
    }

    // MARK: - cli-5: limits

    func testBadLimitIsRefusedAndExportKeepsTheOldestRows() throws {
        let stub = try Stub()
        stub.events = (1...5).map { event($0) }
        let who = ResponsibleEntity(kind: .app, key: "app:/applications/terminal.app", displayName: "Terminal")
        stub.daily = ["2026-10-03", "2026-10-02", "2026-10-01"].map { day in
            DailyAggregate(day: day, summary: UsageSummary(responsible: who, categoryID: "test-vault", agentID: nil,
                                                          firstSeen: CLIStubDaemonTests.t, lastSeen: CLIStubDaemonTests.t,
                                                          count: 1, reads: 1, writes: 0, denied: 0, benign: false))
        }
        let server = try serve(stub)
        defer { server.stop() }

        for bad in ["all", "1e6", "10k"] {
            let r = try whoread(["export", "--format", "jsonl", "--limit", bad])
            XCTAssertEqual(r.status, 64, r.stderr)
        }
        XCTAssertTrue(stub.eventQueries.isEmpty, "nothing is exported with the default limit instead")

        var r = try whoread(["export", "--format", "jsonl", "--limit", "2"])
        XCTAssertEqual(r.stdout.split(separator: "\n").compactMap { try? Exporter.decoder().decode(AnalyzedEvent.self, from: Data($0.utf8)).id },
                       [1, 2], "export --limit: the oldest N")
        r = try whoread(["export", "--aggregates", "--format", "jsonl", "--limit", "1"])
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertEqual(try Exporter.decoder().decode(DailyAggregate.self, from: Data(r.stdout.utf8)).day, "2026-10-01",
                       "export --aggregates --limit: the oldest N too")
        r = try whoread(["daily", "--limit", "1", "--json"])
        XCTAssertEqual(try Exporter.decoder().decode([DailyAggregate].self, from: Data(r.stdout.utf8)).map(\.day), ["2026-10-03"],
                       "daily --limit: the newest N")
    }

    // MARK: - cli-7: --app and --search

    func testAppSendsTheNameOnlyFilterAndSearchTheFullOne() throws {
        let stub = try Stub()
        stub.events = [event(1, path: "/Users/alice/WhoReadTestVault/claude/a.txt", app: "Codex", program: "codex"),
                       event(2, app: "Claude Code", program: "node")]
        let server = try serve(stub)
        defer { server.stop() }
        _ = try whoread(["events", "--app", "claude"])
        XCTAssertEqual(stub.eventQueries.last?.appName, "claude")
        XCTAssertEqual(stub.eventQueries.last?.text, "claude", "an older daemon still narrows by its wider match")
        _ = try whoread(["events", "--search", "id_ed25519"])
        XCTAssertNil(stub.eventQueries.last?.appName)
        XCTAssertEqual(stub.eventQueries.last?.text, "id_ed25519")
    }

    // MARK: - cli-11: Chinese output

    func testStatusCatalogAndAnswersFollowTheLanguage() throws {
        let stub = try Stub()
        stub.status = status(events: 7)
        if let i = stub.catalog.categories.firstIndex(where: { $0.id == "test-vault" }) { stub.catalog.categories[i].enabled = false }
        stub.asks = [question(4, path: ServiceHandler.hiddenPath)]
        let server = try serve(stub)
        defer { server.stop() }

        let zh = try whoread(["status"], lang: "zh-Hans")
        XCTAssertEqual(zh.status, 0, zh.stderr)
        for text in ["  事件源：", "  拦截：", "未生效（设置：关）：已被关闭", "  kill switch： 文件不存在", "  告警：", "未读 1 条，共 2 条",
                     "已存储 7 条", "从未"] {
            XCTAssertTrue(zh.stdout.contains(text), "\(text) in:\n\(zh.stdout)")
        }
        for english in ["source:", "enforcement:", "stored", "unread", "never"] { XCTAssertFalse(zh.stdout.contains(english), english) }
        let en = try whoread(["status"])
        XCTAssertTrue(en.stdout.contains("  enforcement:  inactive (setting off) — disabledByUser"), en.stdout)
        XCTAssertTrue(en.stdout.contains("  kill switch:  file absent"), en.stdout)

        let catalog = try whoread(["catalog"], lang: "zh-Hans")
        XCTAssertTrue(catalog.stdout.contains("严重性") && catalog.stdout.contains("拥有者"), catalog.stdout)
        let vault = try XCTUnwrap(catalog.stdout.split(separator: "\n").first { $0.hasPrefix("test-vault ") })
        XCTAssertTrue(vault.contains("已停用"), String(vault))
        XCTAssertFalse(catalog.stdout.contains("disabled"), catalog.stdout)

        let block = try whoread(["alert", "5", "block"])
        XCTAssertTrue(block.stdout.hasPrefix("alert #5: Block from now on\n"), block.stdout)
        XCTAssertTrue(try whoread(["alert", "5", "ignore"], lang: "zh-Hans").stdout.hasPrefix("告警 #5：忽略\n"))

        let asksZH = try whoread(["asks"], lang: "zh-Hans")
        XCTAssertTrue(asksZH.stdout.contains("文件路径已隐藏"), asksZH.stdout)
        XCTAssertFalse(asksZH.stdout.contains("path hidden"), asksZH.stdout)
        XCTAssertTrue(try whoread(["asks"]).stdout.contains(ServiceHandler.hiddenPath))
    }

    // MARK: - cli-12: rows the daemon cannot decode

    func testExportDoesNotEndAtAnUndecodableNewestRow() throws {
        let stub = try Stub()
        // A whole page that cannot be decoded, ten good events, and an undecodable newest row.
        stub.events = (1...5011).map { event(Int64($0)) }
        stub.undecodable = Set((1...5000).map(Int64.init) + [5011])
        let server = try serve(stub)
        defer { server.stop() }
        let r = try whoread(["export", "--format", "jsonl"])
        XCTAssertEqual(r.status, 0, r.stderr)
        let ids = r.stdout.split(separator: "\n").compactMap { try? Exporter.decoder().decode(AnalyzedEvent.self, from: Data($0.utf8)).id }
        XCTAssertEqual(ids, Array(5001...5010))
        XCTAssertTrue(r.stderr.contains("could not decode"), r.stderr)
    }

    func testTailStartsAfterTheNewestDecodableEvent() throws {
        let stub = try Stub()
        stub.events = (1...5).map { event($0, path: "/Users/alice/WhoReadTestVault/notes/old-\($0).txt") }
            + (6...8).map { event($0) }
        stub.undecodable = [6, 7, 8]
        let server = try serve(stub)
        defer { server.stop() }
        guard let bin = CLIStubDaemonTests.binary else { throw XCTSkip("the whoread executable is not built") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["--socket", socket, "--lang", "en", "tail"]
        p.environment = ["PATH": "/usr/bin:/bin", "HOME": dir.url.path, "TZ": "UTC"]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        try p.run()
        defer { if p.isRunning { p.terminate() } }
        // In its loop after event 5 (the start probes are done), then past the new event 9.
        XCTAssertNotNil(waitFor(20) { stub.eventQueries.contains { $0.afterID == 5 } }, "tail never started after event 5")
        stub.events += [event(9, path: "/Users/alice/WhoReadTestVault/notes/new.txt")]
        XCTAssertNotNil(waitFor(20) { stub.eventQueries.contains { $0.afterID == 9 } }, "tail never got past event 9")
        p.terminate()
        p.waitUntilExit()
        let text = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        XCTAssertTrue(text.contains("new.txt"), text)
        XCTAssertFalse(text.contains("old-"), "the history was printed as new:\n\(text)")

        // Nothing decodable at all, but stored events: refused instead of starting from the beginning.
        stub.events = (1...3).map { event($0) }
        stub.undecodable = [1, 2, 3]
        stub.status = status(events: 3)
        let refused = try whoread(["tail"])
        XCTAssertEqual(refused.status, 1, refused.stderr)
        XCTAssertTrue(refused.stderr.contains("cannot find the newest stored event"), refused.stderr)
    }

    // MARK: - cli-14: catalog export on a terminal

    func testCatalogExportEscapesHiddenCharactersAndStillImports() throws {
        let stub = try Stub()
        let i = try XCTUnwrap(stub.catalog.categories.firstIndex { $0.id == "custom" })
        stub.catalog.categories[i].paths.append("~/Documents/\u{202E}gpj.exe\u{200B}")
        let server = try serve(stub)
        defer { server.stop() }
        let r = try whoread(["catalog", "export"])
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertFalse(r.stdout.unicodeScalars.contains { $0 != "\n" && DisplayText.isHidden($0) }, "raw hidden characters")
        XCTAssertTrue(r.stdout.contains("\\u202e"), r.stdout)
        XCTAssertEqual(try Catalog.load(from: Data(r.stdout.utf8)), stub.catalog)
    }

    /// The legacy `FileHandle.write(_:)` raises on EPIPE (with SIGPIPE ignored, as a caller may
    /// leave it), and the uncaught exception aborts.
    func testCatalogExportIntoAClosedPipeFailsWithoutAborting() throws {
        let stub = try Stub()
        let server = try serve(stub)
        defer { server.stop() }
        let r = try whoread(["catalog", "export"], shell: "trap '' PIPE; exec \"$0\" \"$@\"", closedStdout: true)
        XCTAssertEqual(r.reason, .exit, "aborted with signal \(r.status)")
        XCTAssertEqual(r.status, 1, r.stderr)
    }
}
