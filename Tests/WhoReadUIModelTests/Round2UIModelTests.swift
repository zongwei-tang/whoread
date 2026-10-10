import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine
@testable import WhoReadUIModel

/// Round-2 review fixes in the app's view models.
final class Round2UIModelTests: XCTestCase {
    var dir: URL!
    var core: DaemonCore!
    var client: IPCClient!

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), isDirectory: true).appendingPathComponent("whoread-ui2-\(UUID().uuidString.prefix(6))")
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

    private func loadedModel(_ language: Language = .en) -> AppModel {
        let model = AppModel(language: language)
        model.apply(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: true))
        return model
    }

    private func event(_ id: Int64, _ time: Date, _ path: String, _ access: AccessSet, denied: Bool = false) -> AnalyzedEvent {
        AnalyzedEvent(id: id, time: time, operation: .open, access: access, path: path, secondaryPath: nil, categoryID: "ssh",
                      severity: .critical, process: ProcessRecord(pid: 7, ppid: 1, executablePath: "/Applications/zoom.us.app/Contents/MacOS/zoom.us"),
                      chain: [], responsible: ResponsibleEntity(kind: .app, key: "app:/applications/zoom.us.app", displayName: "zoom.us"),
                      agentID: nil, isOwner: false, benignServiceID: nil, decision: denied ? .denied : .observed, ruleID: denied ? "r" : nil)
    }

    // app-uimodel-1: a write after reads escalates at the same level and must notify again.
    func testSameLevelEscalationNotifies() throws {
        let model = loadedModel()
        let planner = NotificationPlanner(launchedAt: Date().addingTimeInterval(-3600))
        let settings = NotificationSettings()
        let c = AlertCoalescer(window: 600)
        let t = Date()
        let read = try XCTUnwrap(c.ingest(event(1, t, "/Users/alice/.ssh/id_rsa", .read), kind: .firstAccess))
        let first = planner.plan([read.alert], settings: settings, formatter: model.formatter)
        XCTAssertEqual(first.count, 1)
        // A repeat merges silently.
        let repeated = try XCTUnwrap(c.ingest(event(2, t + 10, "/Users/alice/.ssh/id_rsa", .read), kind: .firstAccess))
        XCTAssertEqual(repeated.change, .merged)
        XCTAssertEqual(planner.plan([repeated.alert], settings: settings, formatter: model.formatter), [])
        // The write: same kind, new access → escalated by the coalescer, and notified as its own banner.
        let write = try XCTUnwrap(c.ingest(event(3, t + 30, "/Users/alice/.ssh/authorized_keys", .write), kind: .firstAccess))
        XCTAssertEqual(write.change, .escalated)
        XCTAssertEqual(write.alert.kind, read.alert.kind)
        let second = planner.plan([write.alert], settings: settings, formatter: model.formatter)
        XCTAssertEqual(second.map(\.alertID), [read.alert.id])
        XCTAssertNotEqual(second.first?.identifier, first.first?.identifier, "a new request, not a silent replacement")
        XCTAssertEqual(planner.plan([write.alert], settings: settings, formatter: model.formatter), [], "once")

        // Blocked alerts escalate the same way (blocked read, then blocked write).
        let blockedRead = try XCTUnwrap(c.ingest(event(4, t + 40, "/Users/alice/.ssh/id_rsa", .read, denied: true), kind: .blocked))
        XCTAssertEqual(planner.plan([blockedRead.alert], settings: settings, formatter: model.formatter).count, 1)
        let blockedWrite = try XCTUnwrap(c.ingest(event(5, t + 50, "/Users/alice/.ssh/id_rsa", .write, denied: true), kind: .blocked))
        XCTAssertEqual(blockedWrite.change, .escalated)
        XCTAssertEqual(planner.plan([blockedWrite.alert], settings: settings, formatter: model.formatter).map(\.title),
                       [L10n.t(.notifBlockedTitle, .en)])
    }

    // app-uimodel-2 and app-uimodel-5 (latency trips explained and notified once) are gone with the
    // trips: enforcement is never switched off automatically (AskUIModelTests covers what replaced them).

    // app-uimodel-6: repeats merged since launch do not re-notify an alert from before launch.
    func testFirstPlanUsesCreationTime() throws {
        let model = loadedModel()
        let launch = Date()
        let planner = NotificationPlanner(launchedAt: launch)
        var old = model.alerts[0]
        old.kind = .criticalNonOwner
        old.createdAt = launch.addingTimeInterval(-300)
        old.updatedAt = launch.addingTimeInterval(2)
        old.count = 3
        var fresh = old
        fresh.id = 400
        fresh.createdAt = launch.addingTimeInterval(1)
        XCTAssertEqual(planner.plan([old, fresh], settings: NotificationSettings(), formatter: model.formatter).map(\.alertID), [400])
        old.count = 4
        XCTAssertEqual(planner.plan([old, fresh], settings: NotificationSettings(), formatter: model.formatter), [])
    }

    // app-uimodel-3: saving keeps what the daemon changed on its own since the app fetched the rule.
    func testRuleSaveKeepsDaemonState() throws {
        let subject = RuleSubject.responsible(key: "app:/applications/zoom.us.app", teamID: "ZOOMTEAM")
        let once = RuleException(subject: subject, categoryID: "ssh", access: .read,
                                 expiresAt: Date().addingTimeInterval(600), remainingUses: 1)
        var rule = Rule(target: .category("ssh"), subject: .anyNonOwner, action: .deny)
        rule.exceptions = [once]
        _ = try client.call(.upsertRule(rule))
        let model = loadedModel()
        let stale = try XCTUnwrap(model.rules.first { $0.id == rule.id })
        XCTAssertEqual(stale.exceptions.first?.remainingUses, 1)

        // Meanwhile the engine used the "allow once" and the user said "always allow" from a banner.
        var server = try XCTUnwrap(try client.rules().first { $0.id == rule.id })
        server.exceptions[0].remainingUses = 0
        server.exceptions.append(RuleException(subject: subject, categoryID: "ssh", access: .read))
        try core.setRules(core.rules.rules.map { $0.id == rule.id ? server : $0 })

        // The toggle / editor save as DaemonConnection does it: on the daemon's current copy.
        var edited = RuleDraft(rule: stale)
        edited.name = "renamed"
        edited.enabled = false
        let current = try client.rules().first { $0.id == rule.id }
        _ = try client.call(.upsertRule(edited.build().keepingDaemonState(of: current)))
        let saved = try XCTUnwrap(try client.rules().first { $0.id == rule.id })
        XCTAssertEqual(saved.name, "renamed")
        XCTAssertFalse(saved.enabled)
        XCTAssertEqual(saved.exceptions, current?.exceptions)
        XCTAssertFalse(saved.exceptions.contains { $0.remainingUses == 1 }, "a used allow once stays used")
        XCTAssertTrue(saved.exceptions.contains { $0.remainingUses == nil }, "the always allow is kept")

        // A new rule (none on the daemon) is saved as built.
        let fresh = Rule(target: .category("aws"), subject: .anyNonOwner, action: .alert)
        XCTAssertEqual(fresh.keepingDaemonState(of: nil), fresh)
    }

    // app-uimodel-4: a parent of monitored folders is covered (the daemon saves it without a catalog change).
    func testParentOfMonitoredFoldersIsCovered() throws {
        let model = loadedModel()
        XCTAssertTrue(model.isMonitored(pathPrefix: "~/.config/"))
        XCTAssertTrue(model.isMonitored(pathPrefix: "~/.config"))
        XCTAssertTrue(model.isMonitored(pathPrefix: "~/.ssh/"))
        XCTAssertFalse(model.isMonitored(pathPrefix: "~/Documents/taxes/"))
        XCTAssertFalse(model.isMonitored(pathPrefix: "/"))

        // Same verdict as the daemon: the rule saves without touching Custom.
        _ = try client.call(.upsertRule(Rule(target: .pathPrefix("~/.config/"), subject: .anyNonOwner, action: .deny)))
        XCTAssertEqual(try client.catalog().catalog.category("custom")?.paths, [])
        // An uncovered one is added to Custom on save, as the editor now says.
        _ = try client.call(.upsertRule(Rule(target: .pathPrefix("~/Documents/taxes/"), subject: .anyNonOwner, action: .deny)))
        XCTAssertEqual(try client.catalog().catalog.category("custom")?.paths, ["~/Documents/taxes/"])
        XCTAssertFalse(L10n.t(.rulePathNotMonitored, .en).contains("never"))
    }

    // app-uimodel-7: an incompatible daemon replacing the running one.
    func testIncompatibleDaemonIsNotShownAsLive() throws {
        let model = loadedModel()
        XCTAssertEqual(model.menuBar.symbol, "eye")
        var down = Snapshot()
        down.error = IPCError(.unavailable, "gone")
        model.apply(down)
        XCTAssertEqual(model.menuBar.symbol, "exclamationmark.triangle")

        let newer = FixedClient { request in
            if case .hello = request { return .error(IPCError(.versionMismatch, "client speaks protocol 2, daemon 3")) }
            if case .status = request {
                throw DecodingError.keyNotFound(DaemonStatusKey.x, .init(codingPath: [], debugDescription: "missing"))
            }
            return try self.client.send(request)
        }
        model.apply(SnapshotFetcher.fetch(newer, liveAfter: nil, includeBenign: false, full: false, hello: true))
        XCTAssertTrue(model.connected)
        XCTAssertEqual(model.versionProblem, "client speaks protocol 2, daemon 3", "the handshake's text, not a decoder dump")
        XCTAssertNil(model.liveStatus)
        XCTAssertNotNil(model.status, "kept for restart detection")
        XCTAssertEqual(model.menuBar.symbol, "exclamationmark.triangle")
        XCTAssertEqual(model.menuBar.title, "Error")
        XCTAssertEqual(model.menuBar.unread, 0)
        // Later polls have no handshake: the readable text stays.
        model.apply(SnapshotFetcher.fetch(newer, liveAfter: nil, includeBenign: false, full: false))
        XCTAssertEqual(model.versionProblem, "client speaks protocol 2, daemon 3")

        // A compatible daemon again.
        model.apply(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: false, hello: true))
        XCTAssertNil(model.versionProblem)
        XCTAssertNotNil(model.liveStatus)
        XCTAssertEqual(model.menuBar.symbol, "eye")
    }

    // app-uimodel-7 (second review): a daemon replaced between two polls answers before any handshake.
    // DaemonConnection then handshakes again; its mismatch text replaces the decoder dump.
    func testHandshakeAfterUnreadableAnswerGivesTheReason() throws {
        let model = loadedModel()
        let newer = FixedClient { request in
            if case .hello = request { return .error(IPCError(.versionMismatch, "client speaks protocol 2, daemon 3")) }
            if case .status = request {
                throw DecodingError.keyNotFound(DaemonStatusKey.x, .init(codingPath: [], debugDescription: "missing"))
            }
            return try self.client.send(request)
        }
        model.apply(SnapshotFetcher.fetch(newer, liveAfter: nil, includeBenign: false, full: false))
        XCTAssertNil(model.liveStatus)
        XCTAssertEqual(model.menuBar.title, "Error")
        model.apply(SnapshotFetcher.fetch(newer, liveAfter: nil, includeBenign: false, full: false, hello: true))
        XCTAssertEqual(model.versionProblem, "client speaks protocol 2, daemon 3")
    }

    // app-uimodel-4 (second review): the editor's warning agrees with what the daemon does on save.
    func testCoverageMatchesTheDaemon() throws {
        let model = loadedModel()
        let original = try XCTUnwrap(model.catalog).catalog
        for p in ["~/.config/", "~/", "/Users/", "~/.ssh/id_rsa", "~/.docker/config.json", "~/.docker/",
                  "~/Library/Application Support/", "~/.config/ghx/", "~/Documents/taxes/", "/Volumes/x/"] {
            let rule = Rule(target: .pathPrefix(p), subject: .anyNonOwner, action: .alert)
            _ = try client.call(.upsertRule(rule))
            let added = try client.catalog().catalog.category("custom")?.paths.contains(p) ?? false
            XCTAssertEqual(model.isMonitored(pathPrefix: p), !added, p)
            _ = try client.call(.deleteRule(id: rule.id))
            _ = try client.call(.updateCatalog(original))
        }
    }

    // app-uimodel-8: the App subject pins the chosen app's identity.
    func testAppSubjectPinsIdentity() throws {
        let model = AppModel(language: .en)
        let cd = String(repeating: "ab", count: 20)
        let older = String(repeating: "cd", count: 20)
        func summary(_ r: ResponsibleEntity, _ lastSeen: TimeInterval) -> UsageSummary {
            UsageSummary(responsible: r, categoryID: "ssh", agentID: nil, firstSeen: Date(timeIntervalSince1970: 0),
                         lastSeen: Date(timeIntervalSince1970: lastSeen), count: 1, reads: 1, writes: 0, denied: 0, benign: false)
        }
        let tool = ResponsibleEntity(kind: .binary, key: "bin:/users/alice/bin/tool", displayName: "tool",
                                     path: "/Users/alice/bin/tool", cdhash: cd)
        var oldTool = tool
        oldTool.cdhash = older
        let zoom = ResponsibleEntity(kind: .app, key: "app:/applications/zoom.us.app", displayName: "zoom.us", teamID: "ZOOMTEAM")
        var s = Snapshot()
        s.summaries = [summary(oldTool, 100), summary(tool, 200), summary(zoom, 150)]
        model.apply(s)
        let toolRow = try XCTUnwrap(model.appRows.first { $0.id == tool.key })
        XCTAssertEqual(toolRow.cdhash, cd, "the identity last seen")
        let zoomRow = try XCTUnwrap(model.appRows.first { $0.id == zoom.key })

        var d = RuleDraft()
        d.subjectKind = .app
        d.action = .allow
        d.selectApp(toolRow)
        XCTAssertEqual(d.build().subject, .responsible(key: tool.key, teamID: nil, cdhash: cd))
        d.selectApp(zoomRow)
        XCTAssertEqual(d.build().subject, .responsible(key: zoom.key, teamID: "ZOOMTEAM", cdhash: nil))

        // Re-picking the app a rule already names keeps that rule's pins.
        var editing = RuleDraft(rule: Rule(target: .category("ssh"), subject: .responsible(key: tool.key, teamID: nil, cdhash: older),
                                           action: .allow))
        editing.selectApp(toolRow)
        XCTAssertEqual(editing.appCdhash, older)
    }
}

/// A coding key for a decoding error the way a newer daemon's answer produces one.
private enum DaemonStatusKey: String, CodingKey { case x }
