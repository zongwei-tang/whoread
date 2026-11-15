import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine
@testable import WhoReadUIModel

// Round-5 fixes in the app's alert and question lists, its polling and its notifications (group appa):
// app-1 to app-8. Tests that need the daemon use the replay fixture and in-process clients (no socket).

/// Against the real daemon (replayed fixture), as the signed app and as an unrecognised build.
final class R5AppaDaemonTests: XCTestCase {
    var dir: URL!
    var core: DaemonCore!
    var handler: ServiceHandler!
    /// The signed app.
    var signed: IPCClient!

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("whoread-r5appa-\(UUID().uuidString.prefix(6))")
        var c = DaemonConfiguration()
        c.dataDirectory = dir.path
        c.defaultsDirectory = repoRoot.appendingPathComponent("Data").path
        c.source = .replay
        c.replayPath = repoRoot.appendingPathComponent("Tests/Fixtures/eslogger/schema-v1-msgv10/scenario.jsonl").path
        c.homeDirectories = ["/Users/alice"]
        c.seedProcesses = false
        core = try DaemonCore(config: c)
        try core.source.start(sink: core.pipeline)
        XCTAssertTrue((core.source as! ReplaySource).waitUntilFinished())
        core.writer.flush()
        handler = ServiceHandler(daemon: core, policy: .strict)
        handler.consoleUID = { geteuid() }
        signed = InProcessClient(handler: handler, peer: IPCPeer(pid: getpid(), euid: geteuid(), isTrustedCode: true, isApp: true))
    }

    override func tearDownWithError() throws {
        core.askBroker.denyAll()
        try? FileManager.default.removeItem(at: dir)
    }

    static let terminal = ResponsibleEntity(kind: .app, key: "app:/system/applications/utilities/terminal.app",
                                            displayName: "Terminal", path: "/System/Applications/Utilities/Terminal.app")

    /// A question holding an access, as the native source opens one (Terminal → zsh → cat reads a file).
    private func openQuestion(category: String = "test-vault", path: String = "/Users/alice/WhoReadTestVault/ssh/id_ed25519") throws -> Int64 {
        let q = AskRequest(id: 0, key: AskKey(responsibleKey: Self.terminal.key, categoryID: category, access: .read, chainAgents: []),
                           responsible: Self.terminal, severity: .critical, path: path,
                           process: ProcessRecord(pid: 42, ppid: 10, executablePath: "/bin/cat"), chain: [], agentID: nil,
                           appleProgram: false, firstAt: Date(), lastAt: Date())
        core.askBroker.noteAnsweringClient()
        guard case .held(let id) = core.askBroker.hold(q, budget: 60, respond: { _ in }) else {
            XCTFail("not held")
            return 0
        }
        return id
    }

    // MARK: - app-1: an answer edited into a block or an alert

    /// "Allow once" for Terminal, then edited in the Rules tab into an enforced block. The block must
    /// cover Terminal driven by an AI agent too, and must not end (and be deleted) with the 10 minutes.
    func testApp1AllowOnceEditedIntoABlockCoversEveryChainAndDoesNotExpire() throws {
        let id = try openQuestion()
        _ = try signed.call(.answerAsk(id: id, action: .allowOnce))
        let answer = try XCTUnwrap(try signed.rules().first { $0.template == RuleTemplates.askAnswer })
        XCTAssertNotNil(answer.expiresAt, "allow once is a 10-minute answer")
        XCTAssertEqual(answer.chainAgents, [], "scoped to chains without an AI agent")

        var draft = RuleDraft(rule: answer)
        draft.action = .deny
        draft.enforce = true
        guard case .rules(let list) = try RuleSave.save(draft.build(), with: signed) else { return XCTFail("the signed app gets the rules back") }
        let saved = try XCTUnwrap(list.first { $0.id == answer.id })
        XCTAssertEqual(saved.action, .deny)
        XCTAssertNil(saved.chainAgents, "a block made from an answer covers chains with an AI agent too")
        XCTAssertFalse(saved.coversUnknownAncestry)
        XCTAssertNil(saved.template, "no longer an answer")
        XCTAssertNil(saved.expiresAt, "a block does not end with the allow once it was made from")

        // The daemon's housekeeping (every 30 s) deletes expired answers: not this block.
        let later = Date().addingTimeInterval(11 * 60)
        core.saveConsumableRules(now: later)
        let kept = try XCTUnwrap(core.rules.rules.first { $0.id == answer.id }, "the block was deleted with the expired answer")
        XCTAssertTrue(kept.isLive(at: later))
    }

    func testApp1AlwaysAllowEditedIntoABlockIsNotScopedToChainsWithoutAnAgent() throws {
        let id = try openQuestion()
        _ = try signed.call(.answerAsk(id: id, action: .alwaysAllow))
        let answer = try XCTUnwrap(try signed.rules().first { $0.template == RuleTemplates.askAnswer })
        XCTAssertEqual(answer.chainAgents, [])
        var draft = RuleDraft(rule: answer)
        draft.action = .deny
        guard case .rules(let list) = try RuleSave.save(draft.build(), with: signed) else { return XCTFail() }
        let saved = try XCTUnwrap(list.first { $0.id == answer.id })
        XCTAssertNil(saved.chainAgents)
        XCTAssertNil(saved.template)
        // Renamed but still an allow: it stays scoped (never widened to the app driven by an AI agent).
        var renamed = RuleDraft(rule: answer)
        renamed.name = "Terminal may read the test vault"
        XCTAssertEqual(renamed.build().keepingDaemonState(of: answer).chainAgents, [])
    }
}

/// Editing rules, without the daemon.
final class R5AppaRuleEditTests: XCTestCase {
    static let t = Date(timeIntervalSince1970: 1_790_000_000)
    /// "Allow once" for Terminal as the daemon saves an answer (also for an unknown starter).
    let answer = Rule(name: "Allow Terminal to read SSH keys (10 minutes)", enabled: true, target: .category("ssh"),
                      subject: .responsible(key: "app:com.apple.Terminal", teamID: nil), access: .read, action: .allow,
                      expiresAt: R5AppaRuleEditTests.t.addingTimeInterval(600), createdAt: R5AppaRuleEditTests.t,
                      template: RuleTemplates.askAnswer, chainAgents: [], coversUnknownAncestry: true)

    func testApp1ABlockOrAlertMadeFromAnAnswerIsNeitherScopedNorTemporary() {
        for action in [RuleAction.deny, .alert] {
            var draft = RuleDraft(rule: answer)
            draft.action = action
            let built = draft.build()
            XCTAssertNil(built.chainAgents, "\(action)")
            XCTAssertFalse(built.coversUnknownAncestry, "\(action)")
            XCTAssertNil(built.template, "\(action)")
            XCTAssertNil(built.expiresAt, "\(action)")
            XCTAssertEqual(built.createdAt, answer.createdAt)
            // Saved over the daemon's copy, which still has the answer's expiry.
            let saved = built.keepingDaemonState(of: answer)
            XCTAssertNil(saved.expiresAt, "\(action)")
            XCTAssertNil(saved.chainAgents, "\(action)")
        }
        // A use count too (a rule-level one, as an imported "allow once" rule may carry).
        var counted = answer
        counted.remainingUses = 1
        var draft = RuleDraft(rule: counted)
        draft.action = .deny
        XCTAssertNil(draft.build().remainingUses)
        XCTAssertNil(draft.build().keepingDaemonState(of: counted).remainingUses)
    }

    func testApp1AnAnswerEditedAsAnAllowKeepsItsScopeAndExpiry() {
        var draft = RuleDraft(rule: answer)
        draft.name = "Terminal may read SSH keys"
        draft.access = .any
        let built = draft.build()
        XCTAssertEqual(built.chainAgents, [])
        XCTAssertTrue(built.coversUnknownAncestry)
        XCTAssertEqual(built.template, RuleTemplates.askAnswer)
        XCTAssertEqual(built.expiresAt, answer.expiresAt)
        // The daemon's copy decides expiry and uses while the action is the same.
        var daemon = answer
        daemon.remainingUses = 0
        XCTAssertEqual(built.keepingDaemonState(of: daemon).remainingUses, 0)
        // Switched to deny and back before saving: still the answer it was.
        draft.action = .deny
        draft.action = .allow
        XCTAssertEqual(draft.build().chainAgents, [])
        // A built-in template keeps its provenance whatever the action.
        var fromTemplate = RuleDraft(template: RuleTemplates.blockAgentsFromCritical())
        fromTemplate.action = .alert
        XCTAssertEqual(fromTemplate.build().template, "block-agents-critical")
    }
}

/// The questions and alerts as listed, and their banners, without the daemon.
final class R5AppaListTests: XCTestCase {
    static let base = Date(timeIntervalSince1970: 1_790_000_000)

    static func ask(_ id: Int64, firstAt: Date? = nil, answerBy: Date? = nil) -> AskRequest {
        let terminal = ResponsibleEntity(kind: .app, key: "app:/system/applications/utilities/terminal.app", displayName: "Terminal")
        let t = firstAt ?? base.addingTimeInterval(Double(id))
        return AskRequest(id: id, key: AskKey(responsibleKey: terminal.key, categoryID: "test-vault-\(id)", access: .read, chainAgents: []),
                          responsible: terminal, severity: .critical, path: "/Users/alice/WhoReadTestVault/ssh/id_ed25519",
                          process: ProcessRecord(pid: 42, ppid: 10, executablePath: "/bin/cat"), chain: [], agentID: nil,
                          appleProgram: false, firstAt: t, lastAt: t, holding: answerBy == nil ? 0 : 1, answerBy: answerBy)
    }

    static func status(pendingAsks: Int? = nil, alerts: Int = 0, unread: Int = 0, enforcementActive: Bool = true) -> DaemonStatus {
        DaemonStatus(version: "test", pid: 1, startedAt: base, mode: .enforcing, source: .native, sourceRunning: true,
                     sourceError: nil, sourceHint: nil, sourceCanEnforce: true, learning: false,
                     learningEndsAt: base, monitoringPaused: false, enforcementEnabled: true,
                     enforcementActive: enforcementActive, enforcementInactiveReasons: [], latencyTripReason: nil,
                     killSwitchFilePresent: false, latency: LatencyStats(), parser: nil,
                     counts: StoreCounts(events: 0, aggregatedDays: 0, alerts: alerts, unreadAlerts: unread),
                     unreadAlerts: unread, lastEventAt: nil, eventsProcessed: 0, writerDropped: 0, monitoredPrefixes: 1,
                     homeDirectories: ["/Users/alice"], pendingAsks: pendingAsks)
    }

    static func model(_ status: DaemonStatus) -> AppModel {
        let m = AppModel(language: .en)
        var s = Snapshot()
        s.status = status
        m.apply(s)
        return m
    }

    // MARK: - app-6: the reply to an answer withdraws the answered question's banner

    func testApp6TheReplyToAnAnswerWithdrawsItsBannerWhateverTheStatusSays() {
        // The status (read on the other connection) counted one open question.
        let m = Self.model(Self.status(pendingAsks: 1))
        m.apply(asks: .asks([Self.ask(1)]))
        let planner = NotificationPlanner()
        XCTAssertEqual(planner.plan(asks: m.asks, formatter: m.formatter, complete: m.asksListComplete).post.map(\.askID), [1])

        // Answered in the menu bar: the daemon's reply lists the questions still open, none. The status
        // still says 1 until the other connection reads it again (or for good, while that read fails).
        m.apply(response: .asks([]))
        XCTAssertEqual(m.status?.pendingAsks, 1)
        XCTAssertTrue(m.asksListComplete, "the daemon lists every open question below its cap")
        XCTAssertEqual(planner.plan(asks: m.asks, formatter: m.formatter, complete: m.asksListComplete).remove, ["ask-1"])

        // A capped list may leave open questions out: never complete.
        m.apply(asks: .asks((1...200).map { Self.ask(Int64($0)) }))
        XCTAssertFalse(m.asksListComplete)
        XCTAssertEqual(AppModel.maxListedAsks, DaemonCore.maxListedAsks, "the daemon's cap")
    }

    // MARK: - app-8: the alerts notified are not remembered for good

    static func alert(_ id: Int64, at t: Date, updated: Date? = nil, window: TimeInterval = 600, kind: AlertKind = .criticalNonOwner,
                      firstEventID: Int64? = nil, count: Int = 1) -> Alert {
        Alert(id: id, kind: kind, createdAt: t, updatedAt: updated ?? t, windowEndsAt: t.addingTimeInterval(window),
              responsible: ResponsibleEntity(kind: .agent, key: "agent:claude-code", displayName: "Claude Code"),
              categoryID: "test-vault", severity: .critical, count: count, accesses: .read,
              firstPath: "/Users/alice/WhoReadTestVault/ssh/id_ed25519", firstEventID: firstEventID ?? id * 10, lastEventID: id * 10,
              paths: ["/Users/alice/WhoReadTestVault/ssh/id_ed25519"], chain: [], agentID: "claude-code", ruleID: nil)
    }

    func testApp8AlertsWhoseWindowClosedAreForgottenOnceNoLongerListed() {
        let planner = NotificationPlanner(launchedAt: Self.base)
        let f = AlertFormatter(language: .en)
        // An agent that keeps reading a critical file: a new alert every 10-minute window, for a week.
        // The daemon lists the newest 300 by update.
        var all: [Alert] = []
        var notified = 0
        for i in 1...1000 {
            all.insert(Self.alert(Int64(i), at: Self.base.addingTimeInterval(Double(i) * 610)), at: 0)
            notified += planner.plan(Array(all.prefix(300)), settings: NotificationSettings(), formatter: f).count
        }
        XCTAssertEqual(notified, 1000, "each new alert once")
        XCTAssertLessThanOrEqual(planner.notifiedCount, 302, "only the listed alerts, and those whose window just closed")
    }

    func testApp8AnAlertThatLeftTheListWhileItsWindowIsOpenIsNotNotifiedAgain() {
        let planner = NotificationPlanner(launchedAt: Self.base)
        let f = AlertFormatter(language: .en)
        let first = Self.alert(1, at: Self.base.addingTimeInterval(10))
        XCTAssertEqual(planner.plan([first], settings: NotificationSettings(), formatter: f).map(\.alertID), [1])
        // A flood of newer alerts pushes it out of the newest 300 while its window is still open.
        let flood = (2...301).map { Self.alert(Int64($0), at: Self.base.addingTimeInterval(20 + Double($0))) }
        XCTAssertEqual(planner.plan(flood.reversed(), settings: NotificationSettings(), formatter: f).count, 300)
        // A repeat merges into it (same window, same first event): back in the list, and quiet.
        let repeated = Self.alert(1, at: Self.base.addingTimeInterval(10), updated: Self.base.addingTimeInterval(500), count: 2)
        XCTAssertEqual(planner.plan([repeated] + flood.reversed().prefix(299), settings: NotificationSettings(), formatter: f), [])
        // Escalated: notified again, as before.
        var escalated = repeated
        escalated.kind = .blocked
        escalated.updatedAt = Self.base.addingTimeInterval(550)
        XCTAssertEqual(planner.plan([escalated] + flood.reversed().prefix(299), settings: NotificationSettings(), formatter: f).map(\.alertID), [1])
    }
}
