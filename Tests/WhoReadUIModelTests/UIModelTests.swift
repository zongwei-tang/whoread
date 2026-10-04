import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine
@testable import WhoReadUIModel

let repoRoot: URL = {
    var url = URL(fileURLWithPath: #filePath)
    while url.path != "/" {
        url.deleteLastPathComponent()
        if FileManager.default.fileExists(atPath: url.appendingPathComponent("Package.swift").path) { return url }
    }
    fatalError()
}()

final class L10nTests: XCTestCase {
    func testEveryKeyHasBothLanguages() {
        for key in L.allCases {
            XCTAssertNotNil(L10n.table[key], "missing \(key)")
            let en = L10n.t(key, .en)
            let zh = L10n.t(key, .zhHans)
            XCTAssertFalse(en.isEmpty, "\(key) en")
            XCTAssertFalse(zh.isEmpty, "\(key) zh")
            // Format strings keep the same placeholders in both languages.
            XCTAssertEqual(en.components(separatedBy: "%").count, zh.components(separatedBy: "%").count, "\(key) placeholders")
        }
        XCTAssertEqual(L10n.f(.unreadAlertsFormat, 3, language: .zhHans), "3 条未读告警")
        XCTAssertEqual(L10n.mode(.enforcing, .zhHans), "拦截中")
        for op in FileOperation.allCases { XCTAssertNotEqual(L10n.operation(op, .zhHans), "") }
    }
}

final class AppModelTests: XCTestCase {
    var dir: URL!
    var core: DaemonCore!
    var client: IPCClient!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("whoread-ui-\(UUID().uuidString.prefix(6))")
        var c = DaemonConfiguration()
        c.dataDirectory = dir.path
        c.defaultsDirectory = repoRoot.appendingPathComponent("Data").path
        c.source = .replay
        c.replayPath = repoRoot.appendingPathComponent("Tests/Fixtures/eslogger/schema-v1-msgv10/scenario.jsonl").path
        c.homeDirectories = ["/Users/alice"]
        c.seedProcesses = false
        c.permissive = true
        core = try DaemonCore(config: c)
        try core.source.start(sink: core.pipeline)
        XCTAssertTrue((core.source as! ReplaySource).waitUntilFinished())
        core.writer.flush()
        client = InProcessClient(handler: Daemon.handlerForReplay(core))
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    func testApplySnapshotsAndDerivedTables() {
        let model = AppModel(language: .en)
        model.apply(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: true, full: true))
        XCTAssertTrue(model.connected)
        XCTAssertEqual(model.menuBar.symbol, "graduationcap")
        XCTAssertEqual(model.menuBar.title, "Learning")
        XCTAssertEqual(model.menuBar.badge, "2")
        XCTAssertEqual(model.liveRows.count, 14, "folded Spotlight read hidden")
        model.showSystemNoise = true
        XCTAssertEqual(model.liveRows.count, 15)
        model.showSystemNoise = false
        model.searchText = "aws"
        XCTAssertEqual(model.liveRows.count, 4)
        model.searchText = ""

        let apps = model.appRows
        XCTAssertEqual(apps.map(\.name).sorted(), ["Claude Code", "Terminal"])
        XCTAssertEqual(apps.first { $0.name == "Claude Code" }?.kind, .agent)
        XCTAssertEqual(apps.first { $0.name == "Terminal" }?.categories, ["WhoRead test vault"])
        let files = model.fileRows
        XCTAssertEqual(files.first?.id, "test-vault", "touched categories first")
        XCTAssertEqual(files.first?.apps, ["Claude Code", "Terminal"])
        XCTAssertTrue(files.contains { $0.id == "ssh" && $0.count == 0 })
        XCTAssertEqual(model.agentRows.map(\.name), ["Claude Code"])
        XCTAssertEqual(model.unreadCount, 2)
        XCTAssertEqual(model.abbreviate("/Users/alice/.ssh/x"), "~/.ssh/x")

        // Incremental live polling only appends new events.
        let before = model.live.events.count
        model.apply(SnapshotFetcher.fetch(client, liveAfter: model.liveCursor, includeBenign: true, full: false))
        XCTAssertEqual(model.live.events.count, before)
        XCTAssertEqual(model.live.events.first?.id, model.liveCursor)
    }

    func testUnreachableDaemon() {
        let model = AppModel(language: .zhHans)
        var s = Snapshot()
        s.error = IPCError(.unavailable, "no daemon")
        model.apply(s)
        XCTAssertFalse(model.connected)
        XCTAssertEqual(model.menuBar.symbol, "eye.slash")
        XCTAssertEqual(model.menuBar.title, "无法连接 WhoRead 守护进程")
    }

    func testNotificationPlanner() throws {
        let model = AppModel(language: .zhHans)
        model.apply(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: true))
        let planner = NotificationPlanner()
        let settings = NotificationSettings()
        // First poll seeds: nothing posted for alerts that existed before launch.
        XCTAssertEqual(planner.plan(model.alerts, settings: settings, formatter: model.formatter), [])
        // A new alert appears.
        var fresh = model.alerts[0]
        fresh.id = 99
        fresh.kind = .firstAccess
        fresh.status = .unread
        let planned = planner.plan(model.alerts + [fresh], settings: settings, formatter: model.formatter)
        XCTAssertEqual(planned.count, 1)
        XCTAssertEqual(planned[0].categoryIdentifier, NotificationPlanner.categoryAlert)
        XCTAssertEqual(planned[0].actions, [.alwaysAllow, .blockFromNowOn, .ignore])
        XCTAssertTrue(planned[0].body.contains("调用链："))
        // Repeats (merged count) do not re-notify; escalation to blocked does.
        fresh.count = 5
        XCTAssertEqual(planner.plan([fresh], settings: settings, formatter: model.formatter), [])
        fresh.kind = .blocked
        let blocked = planner.plan([fresh], settings: settings, formatter: model.formatter)
        XCTAssertEqual(blocked.first?.title, "WhoRead 拦截了一次访问")
        XCTAssertEqual(blocked.first?.actions, [.allowOnce, .alwaysAllow, .keepBlocking])
        // Severity floor and switches.
        var medium = fresh
        medium.id = 100
        medium.kind = .firstAccess
        medium.severity = .medium
        XCTAssertEqual(planner.plan([medium], settings: NotificationSettings(minimumSeverity: .high), formatter: model.formatter), [])
        var off = medium
        off.id = 101
        XCTAssertEqual(planner.plan([off], settings: NotificationSettings(enabled: false), formatter: model.formatter), [])
    }

    func testOnboardingStates() {
        let o = OnboardingModel()
        XCTAssertEqual(o.fullDiskAccessState(nil, connected: false), .waiting)
        var status = core.status()
        status.sourceRunning = false
        status.sourceError = "es_new_client: ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED"
        XCTAssertEqual(o.fullDiskAccessState(status, connected: true), .waiting)
        status.sourceError = "something else broke"
        status.sourceHint = nil
        XCTAssertEqual(o.fullDiskAccessState(status, connected: true), .failed("something else broke"))
        status.sourceRunning = true
        status.sourceError = nil
        XCTAssertEqual(o.fullDiskAccessState(status, connected: true), .done)
        XCTAssertTrue(o.isComplete(status, connected: true))
        XCTAssertTrue(OnboardingModel.fullDiskAccessURLs[0].contains("com.apple.settings.PrivacySecurity.extension"))
    }

    func testRuleDraftRoundTrip() {
        for rule in RuleTemplates.all + [
            Rule(target: .pathPrefix("~/x"), subject: .unsigned(path: "/opt/x", cdhash: "ab"), action: .alert),
            Rule(target: .category("aws"), subject: .responsible(key: "app:/applications/zoom.us.app", teamID: "T"), action: .deny),
            Rule(target: .category("ssh"), subject: .signed(signingID: "com.apple.cat", teamID: nil), action: .allow),
        ] {
            let draft = RuleDraft(rule: rule)
            XCTAssertNil(draft.validationError())
            let built = draft.build(now: rule.createdAt)
            XCTAssertEqual(built.id, rule.id)
            XCTAssertEqual(built.target, rule.target)
            XCTAssertEqual(built.subject, rule.subject)
            XCTAssertEqual(built.access, rule.access)
            XCTAssertEqual(built.action, rule.action)
            XCTAssertEqual(built.enforce, rule.enforce)
        }
        var d = RuleDraft()
        d.targetKind = .path
        d.pathPrefix = "relative"
        XCTAssertNotNil(d.validationError())
        d.pathPrefix = "~/.ssh/id_rsa"
        d.subjectKind = .signed
        XCTAssertNotNil(d.validationError())
        d.signingID = "us.zoom.xos"
        XCTAssertNil(d.validationError())
    }
}
