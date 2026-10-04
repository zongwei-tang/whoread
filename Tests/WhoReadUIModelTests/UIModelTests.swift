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
        XCTAssertEqual(L10n.f(.ruleBlockAppFormat, "Zoom", "SSH", language: .zhHans), "拦截 Zoom 访问 SSH")
    }

    func testHelpersAreLocalized() {
        let reasons: [EnforcementState.InactiveReason] = [.disabledByUser, .killSwitchFile, .latencyTripped, .rulesFailedToLoad, .sourceCannotEnforce]
        for r in reasons {
            XCTAssertNotEqual(L10n.inactiveReason(r, .zhHans), r.rawValue)
            XCTAssertNotEqual(L10n.inactiveReason(r, .en), L10n.inactiveReason(r, .zhHans))
        }
        XCTAssertEqual(L10n.access(.readWrite, .zhHans), "读写")
        XCTAssertEqual(L10n.access(.write, .en), "Write")
        for t in RuleTemplates.all { XCTAssertNotNil(L10n.templateName(t.template, .zhHans), t.id) }
        XCTAssertEqual(L10n.message(for: IPCError(.notPermitted, "x"), .en), L10n.t(.errNotPermitted, .en))
        XCTAssertEqual(L10n.message(for: IPCError(.invalid, "bad rule"), .en), "The daemon refused: bad rule")
        XCTAssertTrue(L10n.message(for: IPCError(.versionMismatch, "client 1, daemon 2"), .zhHans).contains("client 1, daemon 2"))
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
        XCTAssertEqual(model.menuBar.symbol, "exclamationmark.triangle", "brief §6 Error state")
        XCTAssertEqual(model.menuBar.title, "出错 — 无法连接 WhoRead 守护进程")
    }

    func testHandshake() {
        let model = AppModel(language: .en)
        let ok = SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: false, hello: true)
        XCTAssertEqual(ok.handshake, .ok)
        model.apply(ok)
        XCTAssertNil(model.versionProblem)
        XCTAssertNil(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: false).handshake)

        let old = FixedClient { request in
            if case .hello = request { return .error(IPCError(.versionMismatch, "client speaks protocol 1, daemon 2")) }
            return try self.client.send(request)
        }
        let mismatch = SnapshotFetcher.fetch(old, liveAfter: nil, includeBenign: false, full: false, hello: true)
        XCTAssertEqual(mismatch.handshake, .mismatch("client speaks protocol 1, daemon 2"))
        model.apply(mismatch)
        XCTAssertEqual(model.versionProblem, "client speaks protocol 1, daemon 2")
        model.apply(ok)
        XCTAssertNil(model.versionProblem)

        // Undecodable answers are a version problem, not "daemon unreachable".
        let garbled = FixedClient { request in
            if case .status = request { throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "new field")) }
            return try self.client.send(request)
        }
        let s = SnapshotFetcher.fetch(garbled, liveAfter: nil, includeBenign: false, full: false)
        XCTAssertEqual(s.error?.code, .versionMismatch)
        model.apply(s)
        XCTAssertTrue(model.connected)
        XCTAssertNotNil(model.versionProblem)
    }

    func testDaemonRestartResetsLiveFeed() throws {
        let model = AppModel(language: .en)
        model.apply(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: true, full: true))
        XCTAssertEqual(model.daemonRestarts, 0)
        let cursor = try XCTUnwrap(model.liveCursor)
        XCTAssertFalse(model.live.events.isEmpty)

        // Same daemon: nothing changes.
        model.apply(SnapshotFetcher.fetch(client, liveAfter: model.liveCursor, includeBenign: true, full: false))
        XCTAssertEqual(model.daemonRestarts, 0)
        XCTAssertEqual(model.liveCursor, cursor)

        // New instance (other pid): the feed starts over and the stale-cursor batch is dropped.
        var s = SnapshotFetcher.fetch(client, liveAfter: model.liveCursor, includeBenign: true, full: false)
        s.status?.pid += 1
        model.apply(s)
        XCTAssertEqual(model.daemonRestarts, 1)
        XCTAssertTrue(model.live.events.isEmpty)
        XCTAssertNil(model.liveCursor)
        // The next poll (cursor nil) refills it, including ids the old feed had already shown.
        var refill = SnapshotFetcher.fetch(client, liveAfter: model.liveCursor, includeBenign: true, full: false)
        refill.status?.pid += 1
        model.apply(refill)
        XCTAssertEqual(model.daemonRestarts, 1)
        XCTAssertEqual(model.liveCursor, cursor)

        // A batch fetched before a reset does not land in the new feed.
        var late = Snapshot()
        late.status = refill.status
        late.liveAfter = 3
        late.newLive = refill.newLive
        let before = model.live.events.count
        model.apply(late)
        XCTAssertEqual(model.live.events.count, before)
    }

    func testWriteResponsesApplyImmediately() throws {
        let model = AppModel(language: .en)
        model.apply(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: true))
        var catalog = try XCTUnwrap(model.catalog).catalog
        catalog = catalog.applying([.setEnabled(categoryID: "ssh", false)])
        model.apply(response: try client.call(.updateCatalog(catalog)))
        XCTAssertEqual(model.catalog?.catalog.category("ssh")?.enabled, false)

        var settings = try XCTUnwrap(model.settings)
        settings.language = .zhHans
        model.apply(response: try client.call(.updateSettings(settings)))
        XCTAssertEqual(model.language, .zhHans)
        // "System" (nil) goes back to the system language without a relaunch.
        settings.language = nil
        model.apply(response: try client.call(.updateSettings(settings)))
        XCTAssertEqual(model.language, .en)

        let rule = Rule(target: .category("aws"), subject: .anyNonOwner, action: .alert)
        model.apply(response: try client.call(.upsertRule(rule)))
        XCTAssertTrue(model.rules.contains { $0.id == rule.id })

        model.apply(response: try client.call(.setEnforcement(enabled: true)))
        XCTAssertEqual(model.status?.enforcementEnabled, true)
    }

    func testEnforcementPresentation() throws {
        let model = AppModel(language: .en)
        var s = SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: true)
        var status = try XCTUnwrap(s.status)
        status.enforcementEnabled = true
        status.enforcementActive = false
        status.enforcementInactiveReasons = [.latencyTripped]
        status.latencyTripReason = "deadline missed"
        status.sourceCanEnforce = true
        status.killSwitchFilePresent = false
        s.status = status
        model.apply(s)
        XCTAssertFalse(model.enforcementSwitchOn, "a tripped switch reads off")
        XCTAssertEqual(model.enforcementInactiveText, "Not active: turned off automatically: responses too slow (deadline missed)")
        XCTAssertEqual(model.enforcementCaveat, L10n.t(.rulesEnforcementOffNote, .en))

        status.latencyTripReason = nil
        status.enforcementInactiveReasons = [.killSwitchFile, .sourceCannotEnforce]
        status.killSwitchFilePresent = true
        status.sourceCanEnforce = false
        s.status = status
        model.apply(s)
        XCTAssertFalse(model.enforcementSwitchOn)
        XCTAssertEqual(model.enforcementCaveat, L10n.t(.sourceCannotEnforceNote, .en))
        XCTAssertFalse(model.enforcementInactiveText?.contains("killSwitchFile") ?? true)

        status.killSwitchFilePresent = false
        status.enforcementInactiveReasons = []
        status.enforcementActive = true
        status.sourceCanEnforce = true
        s.status = status
        model.apply(s)
        XCTAssertTrue(model.enforcementSwitchOn)
        XCTAssertNil(model.enforcementInactiveText)
        XCTAssertNil(model.enforcementCaveat)
    }

    func testSettingsDraftKeepsDaemonSwitches() throws {
        let model = AppModel(language: .en)
        var s = SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: true)
        var draft = try XCTUnwrap(s.settings)
        draft.retentionDays = 60
        // Meanwhile the user switched enforcement off and paused from the menu bar.
        s.status?.enforcementEnabled = false
        s.status?.monitoringPaused = true
        model.apply(s)
        draft.enforcementEnabled = true
        draft.monitoringPaused = false
        let saved = model.preparedForSave(draft)
        XCTAssertEqual(saved.retentionDays, 60)
        XCTAssertFalse(saved.enforcementEnabled)
        XCTAssertTrue(saved.monitoringPaused)
    }

    func testNotificationPlanner() throws {
        let model = AppModel(language: .zhHans)
        model.apply(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: true))
        let planner = NotificationPlanner(launchedAt: Date().addingTimeInterval(3600))
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

    func testPlannerIgnoresAlertStatus() throws {
        let model = AppModel(language: .en)
        model.apply(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: true))
        let planner = NotificationPlanner(launchedAt: Date().addingTimeInterval(3600))
        let settings = NotificationSettings()
        XCTAssertEqual(planner.plan(model.alerts, settings: settings, formatter: model.formatter), [])
        // An agent marked its alert read / ignored before the app polled: still notified.
        var read = model.alerts[0]
        read.id = 200
        read.kind = .criticalNonOwner
        read.status = .read
        var ignored = read
        ignored.id = 201
        ignored.status = .resolved
        ignored.resolution = .ignore
        XCTAssertEqual(planner.plan([read, ignored], settings: settings, formatter: model.formatter).map(\.alertID), [200, 201])
        // A reused id (different creation time) is a new alert.
        var reused = read
        reused.createdAt = read.createdAt.addingTimeInterval(40 * 86400)
        reused.updatedAt = reused.createdAt
        XCTAssertEqual(planner.plan([reused], settings: settings, formatter: model.formatter).map(\.alertID), [200])
        XCTAssertEqual(planner.plan([reused], settings: settings, formatter: model.formatter), [])
    }

    func testFirstPlanNotifiesAlertsSinceLaunch() throws {
        let model = AppModel(language: .en)
        model.apply(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: true))
        let launch = Date()
        let planner = NotificationPlanner(launchedAt: launch)
        var old = model.alerts[0]
        old.updatedAt = launch.addingTimeInterval(-60)
        var recent = model.alerts[0]
        recent.id = 300
        recent.updatedAt = launch.addingTimeInterval(5)
        // The daemon was unreachable at launch; its first answer has both.
        XCTAssertEqual(planner.plan([old, recent], settings: NotificationSettings(), formatter: model.formatter).map(\.alertID), [300])
    }

    func testLatencyTripNotice() throws {
        let planner = NotificationPlanner()
        var status = core.status()
        status.latencyTripReason = nil
        XCTAssertEqual(planner.plan(status: status, language: .en), [])
        status.latencyTripReason = "deadline missed"
        let notices = planner.plan(status: status, language: .zhHans)
        XCTAssertEqual(notices.count, 1)
        XCTAssertEqual(notices.first?.title, "WhoRead 已关闭拦截")
        XCTAssertTrue(notices.first?.body.contains("deadline missed") ?? false)
        XCTAssertEqual(planner.plan(status: status, language: .zhHans), [], "once per trip")
        status.latencyTripReason = nil
        XCTAssertEqual(planner.plan(status: status, language: .en), [])
        status.latencyTripReason = "p99 80 ms"
        XCTAssertEqual(planner.plan(status: status, language: .en).count, 1)
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

        // Step 1 is detected from the connection, not only from this session's request.
        status.source = .eslogger
        XCTAssertEqual(o.extensionStepState(status, connected: true, viaExtension: false), .pending)
        XCTAssertEqual(o.extensionStepState(status, connected: true, viaExtension: true), .done)
        XCTAssertEqual(o.extensionStepState(status, connected: false, viaExtension: true), .pending)
        status.source = .native
        XCTAssertEqual(o.extensionStepState(status, connected: true, viaExtension: false), .done)
        XCTAssertEqual(OnboardingModel(extensionState: .needsRestart).extensionStepState(nil, connected: false, viaExtension: false), .needsRestart)
    }

    func testRuleDraftRoundTrip() {
        let cd = String(repeating: "ab", count: 20)
        for rule in RuleTemplates.all + [
            Rule(target: .pathPrefix("~/x"), subject: .unsigned(path: "/opt/x", cdhash: cd), action: .alert),
            Rule(target: .category("aws"), subject: .responsible(key: "app:/applications/zoom.us.app", teamID: "T"), action: .deny),
            Rule(target: .category("aws"), subject: .responsible(key: "bin:/opt/x", teamID: nil, cdhash: cd, exceptOwners: true), action: .deny),
            Rule(target: .category("ssh"), subject: .signed(signingID: "com.apple.cat", teamID: nil), action: .allow),
            Rule(target: .category("ssh"), subject: .agentAncestor(agentIDs: ["codex"], exceptOwners: false), action: .deny),
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
            XCTAssertEqual(built.template, rule.template)
        }
        var d = RuleDraft()
        d.targetKind = .path
        d.pathPrefix = "relative"
        XCTAssertEqual(d.validationError(), .ruleErrPath)
        d.pathPrefix = "~/.ssh/id_rsa"
        d.subjectKind = .signed
        XCTAssertEqual(d.validationError(), .ruleErrSigningID)
        d.signingID = "us.zoom.xos"
        XCTAssertEqual(d.validationError(), .ruleErrTeamID, "an empty Team ID must be chosen explicitly")
        d.teamID = "BJ4HAAB9B3"
        XCTAssertNil(d.validationError())
        XCTAssertEqual(d.build().subject, .signed(signingID: "us.zoom.xos", teamID: "BJ4HAAB9B3"))
        d.signedWithoutTeam = true
        XCTAssertEqual(d.build().subject, .signed(signingID: "us.zoom.xos", teamID: nil))

        d.subjectKind = .unsigned
        d.unsignedPath = "/opt/x"
        d.cdhash = "zz"
        XCTAssertEqual(d.validationError(), .ruleErrCdhash)
        d.cdhash = " " + cd.uppercased() + " "
        XCTAssertNil(d.validationError())
        XCTAssertEqual(d.build().subject, .unsigned(path: "/opt/x", cdhash: cd))
    }

    func testRuleDraftKeepsHiddenFields() {
        let expires = Date(timeIntervalSince1970: 2_000_000_000)
        let created = Date(timeIntervalSince1970: 1_700_000_000)
        let rule = Rule(name: "temp", target: .category("ssh"), subject: .responsible(key: "app:/Applications/Zoom.app", teamID: "ZOOMTEAM"),
                        action: .allow, expiresAt: expires, remainingUses: 1, createdAt: created, template: "x")
        var d = RuleDraft(rule: rule)
        d.name = "renamed"
        let built = d.build()
        XCTAssertEqual(built.expiresAt, expires)
        XCTAssertEqual(built.remainingUses, 1)
        XCTAssertEqual(built.createdAt, created)
        XCTAssertEqual(built.template, "x")

        // Picking another app drops the old app's pins.
        d.selectApp("app:/Applications/Zoom.app")
        XCTAssertEqual(d.appTeamID, "ZOOMTEAM")
        d.selectApp("app:/Applications/Slack.app")
        XCTAssertEqual(d.build().subject, .responsible(key: "app:/Applications/Slack.app", teamID: nil))

        // From a template: new id, template provenance, fresh creation time.
        let t = RuleDraft(template: RuleTemplates.blockAgentsFromCritical())
        let now = Date()
        let fromTemplate = t.build(now: now)
        XCTAssertNotEqual(fromTemplate.id, RuleTemplates.blockAgentsFromCritical().id)
        XCTAssertEqual(fromTemplate.template, "block-agents-critical")
        XCTAssertEqual(fromTemplate.createdAt, now)
        XCTAssertNil(fromTemplate.name)

        var agents = RuleDraft()
        agents.setAgent("codex", selected: true)
        agents.setAgent("claude-code", selected: true)
        agents.setAgent("codex", selected: false)
        XCTAssertEqual(agents.build().subject, .agentAncestor(agentIDs: ["claude-code"], exceptOwners: true))
    }

    func testRuleNamesAndMonitoredPaths() {
        let model = AppModel(language: .zhHans)
        model.apply(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: true))
        XCTAssertEqual(model.ruleName(RuleTemplates.denyNonOwnersSSH()), "禁止非 owner 进程读取 SSH 密钥")
        let sshName = model.catalog?.catalog.category("ssh")?.name
        let block = Rule(name: "Block Zoom from \(sshName?.en ?? "")", target: .category("ssh"),
                         subject: .responsible(key: "app:/Applications/zoom.us.app", teamID: nil), action: .deny)
        XCTAssertEqual(model.ruleName(block), "拦截 Zoom 访问 \(sshName?.zhHans ?? "")")
        XCTAssertEqual(model.ruleName(Rule(name: "Mine", target: .category("ssh"), subject: .anyNonOwner, action: .deny)), "Mine")

        XCTAssertTrue(model.isMonitored(pathPrefix: "~/.ssh/"))
        XCTAssertTrue(model.isMonitored(pathPrefix: "~/.ssh/id_ed25519"))
        XCTAssertFalse(model.isMonitored(pathPrefix: "~/Documents/taxes/"))
        XCTAssertFalse(model.isMonitored(pathPrefix: "relative"))
    }

    func testCatalogEdits() throws {
        let model = AppModel(language: .en)
        model.apply(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: true))
        let base = try XCTUnwrap(model.catalog).catalog

        XCTAssertNil(CatalogEdit.validPath("relative"))
        XCTAssertNil(CatalogEdit.validPath("/"))
        XCTAssertNil(CatalogEdit.validPath("~/"))
        XCTAssertNil(CatalogEdit.validPath("~"))
        XCTAssertEqual(CatalogEdit.validPath("  ~/secrets/ "), "~/secrets/")

        var c = base.applying([.addPath(categoryID: "custom", "~/secrets/"), .addPath(categoryID: "custom", "~/secrets/"),
                               .addPath(categoryID: "custom", "nope"), .setSeverity(categoryID: "custom", .critical)])
        XCTAssertEqual(c.category("custom")?.paths, ["~/secrets/"])
        XCTAssertEqual(c.category("custom")?.severity, .critical)
        c = c.applying([.removePath(categoryID: "custom", "~/secrets/"), .addPath(categoryID: "project-secrets", "/x/y")])
        XCTAssertEqual(c.category("custom")?.paths, [])
        XCTAssertEqual(c.category("project-secrets")?.paths, [], "project roots come from settings")

        let id = CatalogEdit.newCategoryID()
        c = c.applying([.addCategory(id: id, name: " Taxes ", severity: .high, path: "~/Documents/taxes/"),
                        .addCategory(id: id, name: "Again", severity: .medium, path: nil),
                        .addCategory(id: "custom.empty", name: "  ", severity: .medium, path: nil)])
        XCTAssertEqual(c.category(id)?.name.en, "Taxes")
        XCTAssertEqual(c.category(id)?.paths, ["~/Documents/taxes/"])
        XCTAssertEqual(c.category(id)?.kind, .custom)
        XCTAssertNil(c.category("custom.empty"))
        XCTAssertTrue(CatalogEdit.isUserCategory(try XCTUnwrap(c.category(id))))
        XCTAssertFalse(CatalogEdit.isUserCategory(try XCTUnwrap(c.category("custom"))))

        c = c.applying([.deleteCategory(id: id), .deleteCategory(id: "ssh"), .deleteCategory(id: "custom")])
        XCTAssertNil(c.category(id))
        XCTAssertNotNil(c.category("ssh"))
        XCTAssertNotNil(c.category("custom"))

        // "Also monitor this path" from the rule editor; recreates and enables `custom` if needed.
        var noCustom = base
        noCustom.categories.removeAll { $0.id == "custom" }
        let monitored = noCustom.applying([.monitorPath("~/Documents/taxes/")])
        XCTAssertEqual(monitored.category("custom")?.paths, ["~/Documents/taxes/"])
        XCTAssertEqual(monitored.category("custom")?.enabled, true)

        // The daemon accepts the edited catalog and starts monitoring the path.
        model.apply(response: try client.call(.updateCatalog(base.applying([.monitorPath("~/Documents/taxes/")]))))
        XCTAssertTrue(model.isMonitored(pathPrefix: "~/Documents/taxes/x.pdf"))
    }
}

/// A client whose answers the test controls.
final class FixedClient: IPCClient, @unchecked Sendable {
    let answer: (IPCRequest) throws -> IPCResponse
    init(_ answer: @escaping (IPCRequest) throws -> IPCResponse) { self.answer = answer }
    func send(_ request: IPCRequest) throws -> IPCResponse { try answer(request) }
}
