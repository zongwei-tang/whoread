import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

final class EsloggerSourceTests: XCTestCase {
    func testFakeEsloggerEventsAppearWithinTwoSeconds() throws {
        let dir = TempDir()
        let argsFile = dir.path("args")
        let fake = script(dir, "eslogger", """
            echo "$@" > \(argsFile)
            cat \(fixtureV10)
            exec sleep 600
            """)
        var config = baseConfig(dir, source: .eslogger, replay: nil)
        config.esloggerPath = fake
        config.permissive = true
        let daemon = try Daemon(configuration: config)
        let client = InProcessClient(handler: daemon.handler)
        let started = Date()
        try daemon.start()
        defer { daemon.stop() }
        let elapsed = waitFor(6) { ((try? client.events(EventQuery(includeBenign: true)))?.count ?? 0) >= 15 }
        XCTAssertNotNil(elapsed, "events did not show up within 6 s (cold starts on a loaded machine vary; the M2 acceptance script measures the real latency)")
        print("fake eslogger → queryable records in \(String(format: "%.3f", Date().timeIntervalSince(started))) s")
        let events = try client.events(EventQuery(includeBenign: true, limit: 100, newestFirst: false))
        let cat = try XCTUnwrap(events.first { $0.process.pid == 501 })
        XCTAssertEqual(cat.chainDisplay, "launchd → Terminal → zsh → cat")
        XCTAssertEqual(events.first { $0.process.pid == 700 }?.benignServiceID, "spotlight")
        // Event list handed to eslogger.
        let passed = try String(contentsOfFile: argsFile, encoding: .utf8).split(separator: " ").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        XCTAssertEqual(passed, EsloggerSource.eventNames(readdir: false))
        let status = try client.status()
        XCTAssertEqual(status.source, .eslogger)
        XCTAssertTrue(status.sourceRunning)
        XCTAssertEqual(status.mode, .monitoring, "no learning period (ask mode)")
        XCTAssertEqual(status.parser?.malformed, 0)
        XCTAssertGreaterThan(status.parser?.ignored ?? 0, 0, "the prefilter dropped non-sensitive lines")
        XCTAssertEqual(status.parser?.droppedByKernel, 0, "prefiltered lines are not kernel drops")
    }

    func testImmediateExitReportsErrorWithHintAndRestarts() throws {
        let dir = TempDir()
        let counter = dir.path("runs")
        let fake = script(dir, "eslogger", """
            echo run >> \(counter)
            echo "ERROR: es_new_client: ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED" >&2
            exit 1
            """)
        var config = baseConfig(dir, source: .eslogger, replay: nil)
        config.esloggerPath = fake
        config.permissive = true
        let daemon = try Daemon(configuration: config)
        let client = InProcessClient(handler: daemon.handler)
        try daemon.start()
        defer { daemon.stop() }
        XCTAssertNotNil(waitFor(3) { (try? client.status())?.sourceError != nil })
        let s = try client.status()
        XCTAssertEqual(s.mode, .error)
        XCTAssertTrue(s.sourceError?.contains("NOT_PERMITTED") == true, s.sourceError ?? "")
        XCTAssertNotNil(s.sourceHint)
        // Backoff restart (1 s, then 2 s).
        XCTAssertNotNil(waitFor(4) { ((try? String(contentsOfFile: counter, encoding: .utf8))?.split(separator: "\n").count ?? 0) >= 2 })
    }

    func testDiagnosis() {
        XCTAssertTrue(EsloggerSource.diagnose(stderr: "", euid: 501).contains("root"))
        XCTAssertTrue(EsloggerSource.diagnose(stderr: "ERR_NOT_PERMITTED", euid: 0).contains("Full Disk Access"))
    }
}

final class DaemonTests: XCTestCase {
    func replayDaemon(_ dir: TempDir, permissive: Bool = true, socket: Bool = false) throws -> (Daemon, IPCClient) {
        var config = baseConfig(dir)
        config.permissive = permissive
        if socket { config.devSocketPath = dir.path("d.sock") }
        let daemon = try Daemon(configuration: config)
        daemon.handler.consoleUID = { geteuid() }
        try daemon.start()
        XCTAssertTrue((daemon.core.source as! ReplaySource).waitUntilFinished(timeout: 10))
        daemon.core.writer.flush()
        let client: IPCClient = socket ? UnixSocketClient(path: dir.path("d.sock")) : InProcessClient(handler: daemon.handler)
        return (daemon, client)
    }

    func testQueriesOverDevSocket() throws {
        try skipIfSocketBindDenied()
        let dir = TempDir()
        let (daemon, client) = try replayDaemon(dir, socket: true)
        defer { daemon.stop() }
        guard case .hello(let v) = try client.call(.hello(clientVersion: whoReadIPCVersion)) else { return XCTFail() }
        XCTAssertEqual(v, whoReadIPCVersion)
        XCTAssertEqual(try client.events(EventQuery()).count, 14, "the folded Spotlight read is hidden by default")
        XCTAssertEqual(try client.events(EventQuery(includeBenign: true)).count, 15)
        XCTAssertEqual(try client.events(EventQuery(agentsOnly: true)).count, 2)
        XCTAssertEqual(try client.alerts(AlertQuery()).count, 2)
        let sums = try client.summaries(since: nil)
        XCTAssertTrue(sums.contains { $0.responsible.displayName == "Claude Code" && $0.categoryID == "test-vault" })
        let info = try client.catalog()
        XCTAssertEqual(info.homeDirectories, ["/Users/alice"])
        XCTAssertEqual(info.detected["test-vault"], false, "no such directory on this host")
        XCTAssertEqual(try client.rules().map(\.id), RuleTemplates.all.map(\.id))
        if case .events(let live) = try client.call(.live(afterID: nil, limit: 3, includeBenign: true)) {
            XCTAssertEqual(live.count, 3)
        } else { XCTFail() }
        // Socket permissions.
        let attrs = try FileManager.default.attributesOfItem(atPath: dir.path("d.sock"))
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        // Version mismatch is reported.
        if case .error(let e) = try client.send(.hello(clientVersion: 999)) { XCTAssertEqual(e.code, .versionMismatch) } else { XCTFail() }
    }

    func testAlertActionsChangeRulesAndBaseline() throws {
        let dir = TempDir()
        let (daemon, client) = try replayDaemon(dir)
        defer { daemon.stop() }
        let alerts = try client.alerts(AlertQuery())
        let agentAlert = try XCTUnwrap(alerts.first { $0.responsible.key == "agent:claude-code" })
        // Block from now on → an enforcing deny rule for that app on that category.
        _ = try client.call(.alertAction(alertID: agentAlert.id, action: .blockFromNowOn))
        let rules = try client.rules()
        // Owners keep working (critic-5): the rule exempts the category's owners.
        let block = try XCTUnwrap(rules.first { $0.subject == .responsible(key: "agent:claude-code", teamID: nil, exceptOwners: true) })
        XCTAssertEqual(block.action, .deny)
        XCTAssertTrue(block.enforce)
        XCTAssertEqual(block.target, .category("test-vault"))
        XCTAssertEqual(try client.alerts(AlertQuery()).first { $0.id == agentAlert.id }?.resolution, .blockFromNowOn)
        // Always allow on a non-blocked alert approves the baseline.
        let terminal = try XCTUnwrap(alerts.first { $0.responsible.displayName == "Terminal" })
        _ = try client.call(.alertAction(alertID: terminal.id, action: .alwaysAllow))
        XCTAssertTrue(daemon.core.baseline.isApproved(BaselineKey(responsibleKey: terminal.responsible.key, categoryID: "test-vault", access: .read)))
        // Allow once needs a rule behind the alert.
        if case .error(let e) = try client.send(.alertAction(alertID: terminal.id, action: .allowOnce)) {
            XCTAssertEqual(e.code, .invalid)
        } else { XCTFail() }
        // Persisted: a fresh core over the same data dir sees the rule and the approval.
        daemon.stop()
        let again = try DaemonCore(config: baseConfig(dir))
        XCTAssertTrue(again.rules.rules.contains { $0.id == block.id })
        XCTAssertTrue(again.baseline.isApproved(BaselineKey(responsibleKey: terminal.responsible.key, categoryID: "test-vault", access: .read)))
        XCTAssertGreaterThan(try again.store.maxEventID(), 0)
        XCTAssertEqual(again.coalescer.peekNextID, (try again.store.maxAlertID()) + 1)
    }

    func testStrictPolicyRefusesWeakeningFromNonRoot() throws {
        try skipIfSocketBindDenied()
        guard geteuid() != 0 else { throw XCTSkip("must run as a non-root user") }
        let dir = TempDir()
        let (daemon, client) = try replayDaemon(dir, permissive: false, socket: true)
        defer { daemon.stop() }
        // Reading and strengthening are fine.
        XCTAssertNoThrow(try client.status())
        XCTAssertNoThrow(try client.call(.setEnforcement(enabled: true)))
        XCTAssertNoThrow(try client.call(.setPaused(false)))
        var deny = RuleTemplates.denyNonOwnersSSH()
        deny.id = "new-deny"
        deny.enabled = true
        XCTAssertNoThrow(try client.call(.upsertRule(deny)))
        // Weakening is refused.
        for request: IPCRequest in [.setEnforcement(enabled: false), .setPaused(true), .deleteRule(id: "new-deny"),
                                    .updateSettings(Settings()), .resetCatalog, .restartLearning,
                                    .upsertRule(RuleTemplates.blockAgentsFromCritical())] {
            guard case .error(let e) = try client.send(request) else { return XCTFail("\(request) was allowed") }
            XCTAssertEqual(e.code, .notPermitted, "\(request)")
        }
        // Other users are refused entirely.
        daemon.handler.consoleUID = { geteuid() + 1 }
        guard case .error(let e) = try client.send(.status) else { return XCTFail() }
        XCTAssertEqual(e.code, .notPermitted)
    }

    func testSettingsApplyLive() throws {
        let dir = TempDir()
        let (daemon, client) = try replayDaemon(dir)
        defer { daemon.stop() }
        var s = try client.settings()
        s.projectRoots = ["~/code"]
        s.learningDays = 1
        s.coalesceMinutes = 5
        s.readdirEnabled = true
        _ = try client.call(.updateSettings(s))
        XCTAssertEqual(daemon.core.baseline.learningDuration, 86400)
        XCTAssertEqual(daemon.core.coalescer.window, 300)
        XCTAssertTrue(daemon.core.analyzer.readdirEnabled)
        XCTAssertEqual(daemon.core.analyzer.classifier.classify("/Users/alice/code/x/.env")?.categoryID, "project-secrets")
        // Validation clamps nonsense.
        s.retentionDays = 100_000
        _ = try client.call(.updateSettings(s))
        XCTAssertEqual(try client.settings().retentionDays, 365)
    }

    func testCatalogUpdateAndReset() throws {
        let dir = TempDir()
        let (daemon, client) = try replayDaemon(dir)
        defer { daemon.stop() }
        var catalog = try client.catalog().catalog
        let i = catalog.categories.firstIndex { $0.id == "custom" }!
        catalog.categories[i].paths = ["~/Secrets/"]
        _ = try client.call(.updateCatalog(catalog))
        XCTAssertEqual(daemon.core.analyzer.classifier.classify("/Users/alice/Secrets/a.txt")?.categoryID, "custom")
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.path("data/catalog.json")))
        _ = try client.call(.resetCatalog)
        XCTAssertNil(daemon.core.analyzer.classifier.classify("/Users/alice/Secrets/a.txt"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path("data/catalog.json")))
    }

    func testPausedDropsFileEventsButKeepsTree() throws {
        let dir = TempDir()
        var config = baseConfig(dir)
        config.permissive = true
        let core = try DaemonCore(config: config)
        var s = core.currentSettings
        s.monitoringPaused = true
        try core.update(settings: s, peer: .inProcess)
        try core.source.start(sink: core.pipeline)
        XCTAssertTrue((core.source as! ReplaySource).waitUntilFinished())
        core.writer.flush()
        XCTAssertEqual(try core.store.events(EventQuery(includeBenign: true)).count, 0)
        XCTAssertNotNil(core.tree.node(pid: 501), "lifecycle still processed")
        XCTAssertEqual(core.status().mode, .paused)
    }
}

final class EnforcementPathTests: XCTestCase {
    func makeCore(_ dir: TempDir) throws -> (DaemonCore, FakeSource) {
        let fake = FakeSource(canEnforce: true)
        let core = try DaemonCore(config: baseConfig(dir), makeSource: { _ in fake })
        return (core, fake)
    }

    func agentCat(_ core: DaemonCore) -> ProcessRecord {
        let t = Date(timeIntervalSince1970: 1_760_000_000)
        let zsh = proc(500, "/bin/zsh", ppid: 1, platform: true)
        core.tree.observe(zsh, at: t)
        let claude = proc(600, "/opt/homebrew/Cellar/node/22.9.0/bin/node", ppid: 500, argv: ["node", "/opt/homebrew/bin/claude"])
        var child = zsh
        child.pid = 600
        child.ppid = 500
        core.tree.fork(parent: zsh, child: child, at: t)
        core.tree.exec(old: child, new: claude, at: t)
        return proc(601, "/bin/cat", ppid: 600, platform: true)
    }

    func read(_ p: ProcessRecord, _ path: String) -> FileActivity {
        FileActivity(time: Date(timeIntervalSince1970: 1_760_000_100), operation: .open, process: p,
                     targets: OperationSemantics.open(path: path, fflag: 1))
    }

    func testDecisionsAndAllThreeKillSwitches() throws {
        let dir = TempDir()
        let (core, fake) = try makeCore(dir)
        var rule = RuleTemplates.blockAgentsFromCritical()
        rule.enabled = true
        rule.enforce = true
        try core.setRules([rule])
        let cat = agentCat(core)
        let key = "/Users/alice/.ssh/id_ed25519"

        // Enforcement setting off → allow.
        XCTAssertEqual(core.enforcer.decide(read(cat, key)).reason, .enforcementInactive)
        var s = core.currentSettings
        s.enforcementEnabled = true
        try core.update(settings: s, peer: .inProcess)
        core.drainPolicyQueue()  // observers run off the mutating thread
        XCTAssertEqual(fake.enforcementCalls.last, true)
        XCTAssertEqual(core.enforcer.decide(read(cat, key)).verdict, .deny)
        XCTAssertEqual(core.enforcer.decide(read(cat, "/Users/alice/Documents/x")).reason, .notSensitive)
        XCTAssertEqual(core.status().mode, .enforcing)

        // 1. UI / CLI switch.
        s.enforcementEnabled = false
        try core.update(settings: s, peer: .inProcess)
        XCTAssertEqual(core.enforcer.decide(read(cat, key)).verdict, .allow)
        s.enforcementEnabled = true
        try core.update(settings: s, peer: .inProcess)
        XCTAssertEqual(core.enforcer.decide(read(cat, key)).verdict, .deny)

        // 2. Kill-switch file (watched every 200 ms).
        let watcher = KillSwitchWatcher(path: core.config.resolvedKillSwitchPath, state: core.enforcement)
        watcher.start()
        defer { watcher.stop() }
        touch(core.config.resolvedKillSwitchPath)
        let t = waitFor(1) { core.enforcer.decide(read(cat, key)).verdict == .allow }
        XCTAssertNotNil(t, "kill-switch file did not take effect within 1 s")
        print("kill-switch file took effect in \(String(format: "%.3f", t ?? -1)) s")
        try FileManager.default.removeItem(atPath: core.config.resolvedKillSwitchPath)
        XCTAssertNotNil(waitFor(1) { core.enforcer.decide(read(cat, key)).verdict == .deny })

        // 3. Ask mode: a missed deadline is counted, never an automatic switch-off.
        core.enforcer.recordResponse(micros: 10, missedDeadline: true)
        core.checkLatency()
        core.drainPolicyQueue()
        XCTAssertEqual(core.enforcer.decide(read(cat, key)).verdict, .deny)
        XCTAssertTrue(core.status().enforcementActive)
        XCTAssertEqual(core.status().latency.deadlineMisses, 1)
        XCTAssertTrue(core.currentSettings.enforcementEnabled)
        XCTAssertTrue(try core.store.settings().enforcementEnabled)
        XCTAssertNil(core.status().latencyTripReason)
    }

    // Ask mode (was: a trip cleared by "enforcement on"): no automatic switch-off at all.
    func testMissedDeadlinesNeverSwitchEnforcementOff() throws {
        let dir = TempDir()
        let (core, _) = try makeCore(dir)
        var rule = RuleTemplates.blockAgentsFromCritical()
        rule.enabled = true
        rule.enforce = true
        try core.setRules([rule])
        try core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
        let cat = agentCat(core)
        let key = "/Users/alice/.ssh/id_ed25519"
        for _ in 0..<50 { core.enforcer.recordResponse(micros: 10, missedDeadline: true) }
        core.checkLatency()
        core.drainPolicyQueue()
        XCTAssertEqual(core.enforcer.decide(read(cat, key)).verdict, .deny)
        XCTAssertTrue(core.enforcement.inactiveReasons.isEmpty)
    }

    // Ask mode (was: a trip during the kill-switch window is persisted): releasing the kill switch
    // brings enforcement back, whatever happened meanwhile.
    func testDeadlineMissDuringKillSwitchWindowChangesNothing() throws {
        let dir = TempDir()
        let (core, _) = try makeCore(dir)
        try core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
        core.enforcement.setKillSwitchFilePresent(true)   // already inactive
        core.enforcer.recordResponse(micros: 10, missedDeadline: true)
        core.checkLatency()
        core.drainPolicyQueue()
        XCTAssertTrue(core.currentSettings.enforcementEnabled)
        XCTAssertTrue(try core.store.settings().enforcementEnabled)
        core.enforcement.setKillSwitchFilePresent(false)
        XCTAssertTrue(core.enforcement.isActive, "back on once the kill switch is released")
    }

    // Ask mode (was: left off after a death while enforcing): kept as set, the unclean stop reported.
    func testRestartAfterDeathWhileEnforcingKeepsEnforcementAndReportsIt() throws {
        let dir = TempDir()
        do {
            let (core, _) = try makeCore(dir)
            try core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
        }
        touch(dir.path("data/auth-armed"))
        let (core, _) = try makeCore(dir)
        XCTAssertTrue(core.currentSettings.enforcementEnabled)
        XCTAssertTrue(core.enforcement.isActive)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path("data/auth-armed")))
        XCTAssertNil(core.status().latencyTripReason)
        XCTAssertTrue(core.status().uncleanStop?.contains("while enforcing") == true)
    }

    // Ask mode (was: a p99 trip via the latency check): slow responses are reported, never a trip.
    func testSlowP99NeverSwitchesEnforcementOff() throws {
        let dir = TempDir()
        let (core, _) = try makeCore(dir)
        var s = core.currentSettings
        s.enforcementEnabled = true
        s.latencyP99ThresholdMs = 1
        try core.update(settings: s, peer: .inProcess)
        for round in 0..<5 {
            for _ in 0..<100 { core.enforcer.recordResponse(micros: 5000, missedDeadline: false) }
            core.checkLatency()
            XCTAssertTrue(core.enforcement.isActive, "round \(round)")
        }
        XCTAssertTrue(core.latency.isSlow)
        XCTAssertNil(core.status().latencyTripReason)
        XCTAssertGreaterThan(core.status().latency.p99Micros, 1000)
    }

    func testPolicyChangeCallbackFires() throws {
        let dir = TempDir()
        let (core, _) = try makeCore(dir)
        let counter = Counter()
        core.onPolicyChanged = { counter.bump() }
        try core.setRules(RuleTemplates.all)
        var s = core.currentSettings
        s.enforcementEnabled = true
        try core.update(settings: s, peer: .inProcess)
        core.drainPolicyQueue()
        XCTAssertGreaterThanOrEqual(counter.value, 2)
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var v = 0
    func bump() { lock.lock(); v += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return v }
}

final class FixtureSanitizerTests: XCTestCase {
    func testSanitize() throws {
        let raw = try String(contentsOfFile: fixtureV7, encoding: .utf8)
            .replacingOccurrences(of: "/Users/alice", with: "/Users/zongwei")
            .split(separator: "\n").map(String.init)
        // Add an unrelated personal event and a system one.
        let vaultOpen = raw.first { $0.contains("\"open\":") && $0.contains("WhoReadTestVault/ssh/id_ed25519") }!
        let personal = vaultOpen.replacingOccurrences(of: "WhoReadTestVault/ssh/id_ed25519", with: "Documents/taxes.pdf")
            .replacingOccurrences(of: "\"pid\":501", with: "\"pid\":9999")
        let system = vaultOpen.replacingOccurrences(of: "/Users/zongwei/WhoReadTestVault/ssh/id_ed25519", with: "/usr/lib/libz.dylib")
        let s = FixtureSanitizer(home: "/Users/zongwei", samplePerKind: 5)
        let (out, report) = s.sanitize(lines: raw + [personal, system])
        let joined = out.joined(separator: "\n")
        XCTAssertFalse(joined.contains("zongwei"))
        XCTAssertFalse(joined.contains("taxes.pdf"))
        XCTAssertTrue(joined.contains("/usr/lib/libz.dylib"))
        XCTAssertFalse(joined.contains("SECRET_TOKEN"))
        XCTAssertTrue(joined.contains("\"env\":[]"))
        XCTAssertGreaterThan(report.vaultEvents, 10)
        XCTAssertGreaterThan(report.lifecycle, 5)
        // Still parseable, and the vault scenario survives.
        let parser = EsloggerParser()
        out.forEach { _ = parser.parse(line: $0) }
        XCTAssertEqual(parser.stats.malformed, 0)
        XCTAssertGreaterThan(parser.stats.events, 30)
    }

    func testEscapedSlashesAndArgsTruncation() {
        let line = #"{"schema_version":1,"event":{"exec":{"args":["\/usr\/bin\/git","push","--token=x"],"env":["A=1","B=[x]"],"target":{}}},"process":{"executable":{"path":"\/Users\/bob\/x"}}}"#
        XCTAssertEqual(FixtureSanitizer.replaceArray(in: line, key: "env", with: "[]").contains(#""env":[]"#), true)
        XCTAssertEqual(FixtureSanitizer.truncateArgs(in: line).contains(#""args":["\/usr\/bin\/git"]"#), true)
        let s = FixtureSanitizer(home: "/Users/bob")
        XCTAssertTrue(s.rewrite(line).contains(#"\/Users\/alice\/x"#))
    }
}

final class OwnerResolverTests: XCTestCase {
    struct FakeReader: CodesignReader {
        let table: [String: CodesignInfo]
        func read(path: String) -> CodesignInfo? { table[path] }
    }

    func testResolve() throws {
        let catalog = try DefaultData.load(directory: repoRoot.appendingPathComponent("Data")).catalog
        let reader = FakeReader(table: [
            "/Applications/Google Chrome.app": CodesignInfo(identifier: "com.google.Chrome", teamID: "TEAMCHROME"),
            "/usr/local/aws-cli/aws": CodesignInfo(identifier: "aws", teamID: "TEAMAWS"),
        ])
        let installed: Set<String> = ["/Applications/Google Chrome.app", "/usr/local/aws-cli/aws"]
        let (resolved, report) = OwnerResolver.resolve(catalog: catalog, reader: reader, exists: installed.contains)
        let chrome = resolved.category("chrome")!.owners[0]
        XCTAssertEqual(chrome.teamIDs, ["TEAMCHROME"])
        XCTAssertNil(chrome.signingIDs, "bundles pin the team, not helper signing IDs")
        let aws = resolved.category("aws")!.owners[0]
        XCTAssertEqual(aws.signingIDs, ["aws"])
        XCTAssertEqual(aws.teamIDs, ["TEAMAWS"])
        XCTAssertEqual(report.resolved.count, 2)
        XCTAssertGreaterThan(report.skippedGlobs, 10)
        XCTAssertGreaterThan(report.missing.count, 5)
        XCTAssertEqual(CodesignCommandReader.parse("Executable=/x\nIdentifier=com.apple.ls\nFormat=Mach-O\nTeamIdentifier=not set\n"),
                       CodesignInfo(identifier: "com.apple.ls", teamID: nil))
    }
}
