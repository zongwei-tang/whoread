import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine
@testable import WhoReadUIModel

/// Ask mode in the app's view models (docs/ASK_MODE.md): fetching and polling questions, their
/// notifications, the menu bar without a learning state, the "slow responses" warning that replaced
/// latency trips, the unclean-stop notice, and the strings.
final class AskUIModelTests: XCTestCase {
    var dir: URL!
    var core: DaemonCore!
    var client: IPCClient!

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), isDirectory: true).appendingPathComponent("whoread-ask-ui-\(UUID().uuidString.prefix(6))")
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

    // MARK: - Fixtures

    private static let base = Date(timeIntervalSince1970: 1_790_000_000)

    private func link(_ name: String, _ path: String, agent: String? = nil) throws -> ChainLink {
        var json: [String: Any] = ["pid": 10, "name": name, "path": path, "isPlatformBinary": agent == nil]
        if let agent { json["agentID"] = agent }
        return try JSONDecoder().decode(ChainLink.self, from: JSONSerialization.data(withJSONObject: json))
    }

    private func ask(_ id: Int64, app: String = "Claude Code", category: String = "ssh", access: AccessSet = .read,
                     apple: Bool = false, firstAt: Date = AskUIModelTests.base, attempts: Int = 1,
                     answerBy: Date? = nil) throws -> AskRequest {
        let responsible = apple
            ? ResponsibleEntity(kind: .binary, key: "bin:/usr/bin/\(app)", displayName: app)
            : ResponsibleEntity(kind: .agent, key: "agent:claude-code", displayName: app)
        let chain = apple
            ? [try link("launchd", "/sbin/launchd"), try link(app, "/usr/bin/\(app)")]
            : [try link("launchd", "/sbin/launchd"), try link("claude", "/opt/claude", agent: "claude-code"), try link("cat", "/bin/cat")]
        return AskRequest(id: id, key: AskKey(responsibleKey: responsible.key, categoryID: category, access: access,
                                              chainAgents: apple ? [] : ["claude-code"]),
                          responsible: responsible, severity: .critical, path: "/Users/alice/.ssh/id_ed25519",
                          process: ProcessRecord(pid: 42, ppid: 10, executablePath: "/bin/cat"), chain: chain,
                          agentID: apple ? nil : "claude-code", appleProgram: apple, firstAt: firstAt, lastAt: firstAt,
                          attempts: attempts, holding: answerBy == nil ? 0 : 1, answerBy: answerBy)
    }

    private func status(mode: DaemonMode = .monitoring, unread: Int = 0, latency: LatencyStats = LatencyStats(),
                        uncleanStop: String? = nil) -> DaemonStatus {
        DaemonStatus(version: "test", pid: 1, startedAt: AskUIModelTests.base, mode: mode, source: .native, sourceRunning: true,
                     sourceError: nil, sourceHint: nil, sourceCanEnforce: true, learning: mode == .learning,
                     learningEndsAt: AskUIModelTests.base, monitoringPaused: false, enforcementEnabled: true,
                     enforcementActive: true, enforcementInactiveReasons: [], latencyTripReason: nil,
                     killSwitchFilePresent: false, latency: latency, parser: nil,
                     counts: StoreCounts(events: 0, aggregatedDays: 0, alerts: unread, unreadAlerts: unread),
                     unreadAlerts: unread, lastEventAt: nil, eventsProcessed: 0, writerDropped: 0, monitoredPrefixes: 1,
                     homeDirectories: ["/Users/alice"], uncleanStop: uncleanStop)
    }

    private func model(_ status: DaemonStatus, asks: [AskRequest] = [], settings: Settings? = nil,
                       language: Language = .en) -> AppModel {
        let m = AppModel(language: language)
        var s = Snapshot()
        s.status = status
        s.asks = asks
        s.settings = settings
        m.apply(s)
        return m
    }

    /// The real daemon, except for `.asks` (the daemon implements it) and a count of polls.
    private final class AskingClient: IPCClient, @unchecked Sendable {
        let inner: IPCClient
        var asks: [AskRequest]
        var asksCalls = 0
        init(_ inner: IPCClient, asks: [AskRequest]) { self.inner = inner; self.asks = asks }
        func send(_ request: IPCRequest) throws -> IPCResponse {
            if case .asks = request { asksCalls += 1; return .asks(asks) }
            return try inner.send(request)
        }
    }

    private struct FailingClient: IPCClient {
        func send(_ request: IPCRequest) throws -> IPCResponse { throw IPCError(.unavailable, "gone") }
    }

    // MARK: - Fetching and polling

    func testEveryPollFetchesQuestions() throws {
        // The daemon answers `.asks` (an empty list until questions open).
        XCTAssertNil(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: false).error)

        let open = [try ask(1), try ask(2, app: "security", category: "keychain", apple: true)]
        let asking = AskingClient(client, asks: open)
        let m = AppModel(language: .en)
        m.apply(SnapshotFetcher.fetch(asking, liveAfter: nil, includeBenign: false, full: true, hello: true))
        XCTAssertEqual(asking.asksCalls, 1)
        XCTAssertEqual(m.asks, open)
        m.apply(SnapshotFetcher.fetch(asking, liveAfter: m.liveCursor, includeBenign: false, full: false))
        XCTAssertEqual(asking.asksCalls, 2, "fast polls too: polling tells the daemon an answering app is present")
        XCTAssertEqual(m.pollInterval, 0.25)
        XCTAssertEqual(m.menuBar.openAsks, 2)

        // Answered: the daemon's answer to `.answerAsk` is the remaining list.
        m.apply(response: .asks([open[1]]))
        XCTAssertEqual(m.asks.map(\.id), [2])
        asking.asks = []
        m.apply(SnapshotFetcher.fetch(asking, liveAfter: m.liveCursor, includeBenign: false, full: false))
        XCTAssertEqual(m.asks, [])
        XCTAssertEqual(m.pollInterval, 1)

        // A daemon that cannot be reached cannot take answers: nothing is listed.
        asking.asks = open
        m.apply(SnapshotFetcher.fetch(asking, liveAfter: m.liveCursor, includeBenign: false, full: false))
        XCTAssertEqual(m.asks.count, 2)
        var down = Snapshot()
        down.error = IPCError(.unavailable, "gone")
        m.apply(down)
        XCTAssertEqual(m.asks, [])
        XCTAssertEqual(m.pollInterval, 1)
        XCTAssertNil(m.menuBar.badge)
    }

    func testPollCadence() {
        XCTAssertEqual(PollSchedule.interval(openAsks: 0), 1)
        XCTAssertEqual(PollSchedule.interval(openAsks: 1), 0.25)
        XCTAssertEqual(PollSchedule.interval(openAsks: 300), 0.25)

        var schedule = PollSchedule()
        let t = AskUIModelTests.base
        XCTAssertTrue(schedule.isFullDue(now: t), "the first poll is full")
        schedule.fullStarted(at: t)
        // At 250 ms, 39 polls later is still within the 10 s: full polls do not speed up with the cadence.
        XCTAssertFalse(schedule.isFullDue(now: t + 0.25 * 39))
        XCTAssertTrue(schedule.isFullDue(now: t + 10))
        schedule.fullStarted(at: t + 3)
        XCTAssertFalse(schedule.isFullDue(now: t + 10), "a full poll after a change restarts the 10 s")
        XCTAssertTrue(schedule.isFullDue(now: t + 13))
    }

    func testTicksBetweenFastPollsFetchOnlyQuestions() throws {
        var schedule = PollSchedule()
        let t = AskUIModelTests.base
        XCTAssertEqual(schedule.kind(now: t, openAsks: 2), .full)
        schedule.fullStarted(at: t)
        // 250 ms ticks: questions only, status / alerts / live tail once a second.
        XCTAssertEqual(schedule.kind(now: t + 0.25, openAsks: 2), .asks)
        XCTAssertEqual(schedule.kind(now: t + 0.5, openAsks: 2), .asks)
        XCTAssertEqual(schedule.kind(now: t + 0.75, openAsks: 2), .asks)
        XCTAssertEqual(schedule.kind(now: t + 0.999, openAsks: 2), .fast, "a timer firing a little early still polls")
        schedule.fastStarted(at: t + 1)
        XCTAssertEqual(schedule.kind(now: t + 1.25, openAsks: 2), .asks)
        XCTAssertEqual(schedule.kind(now: t + 2.1, openAsks: 2), .fast)
        // No question open: every tick (once a second) is a fast poll, even one right after a change.
        XCTAssertEqual(schedule.kind(now: t + 1.25, openAsks: 0), .fast)
        // Full polls keep their 10 s, and come first until settings are known.
        XCTAssertEqual(schedule.kind(now: t + 10, openAsks: 2), .full)
        XCTAssertEqual(schedule.kind(now: t + 1.25, openAsks: 2, needsFull: true), .full)

        // The questions alone, from the daemon (empty list) and from a daemon with questions open.
        XCTAssertEqual(SnapshotFetcher.fetchAsks(client), [])
        let open = [try ask(1)]
        let asking = AskingClient(client, asks: open)
        XCTAssertEqual(SnapshotFetcher.fetchAsks(asking), open)
        XCTAssertEqual(asking.asksCalls, 1, "polling them also tells the daemon an answering app is present")
        // Unreachable: nil, left to the next fast poll to report.
        XCTAssertNil(SnapshotFetcher.fetchAsks(FailingClient()))
        let m = AppModel(language: .en)
        m.apply(response: .asks(open))
        XCTAssertEqual(m.asks, open)
        XCTAssertEqual(m.pollInterval, 0.25)
    }

    // MARK: - Notifications

    func testOneNotificationPerQuestionAndRemovals() throws {
        let m = model(status())
        // Launched in the future: alerts would be seeded, questions are still notified.
        let planner = NotificationPlanner(launchedAt: Date().addingTimeInterval(3600))
        let agent = try ask(1, attempts: 3)
        let apple = try ask(2, app: "security", category: "keychain", apple: true, firstAt: AskUIModelTests.base + 5)

        let first = planner.plan(asks: [apple, agent], formatter: m.formatter)
        XCTAssertEqual(first.post.map(\.identifier), ["ask-1", "ask-2"], "oldest first")
        XCTAssertEqual(first.remove, [])
        XCTAssertEqual(first.post.map(\.askID), [1, 2])
        XCTAssertEqual(first.post[0].categoryIdentifier, NotificationPlanner.categoryAsk)
        XCTAssertEqual(first.post[0].actions, [.allowOnce, .alwaysAllow, .keepBlocking, .blockFromNowOn])
        XCTAssertEqual(first.post[1].categoryIdentifier, NotificationPlanner.categoryAskApple)
        XCTAssertEqual(first.post[1].actions, [.allowOnce, .alwaysAllow, .keepBlocking, .blockFromNowOn, .trustApplePrograms])
        XCTAssertEqual(first.post[0].title, "Allow this access?")
        XCTAssertEqual(first.post[0].body, // guard-4: the agent line comes first
                       "AI agent in the chain: claude-code\n"
                       + "Claude Code wants to read ~/.ssh/id_ed25519: not allowed until you decide (×3)\n"
                       + "Chain: launchd → claude → cat")
        XCTAssertEqual(first.post[1].body.components(separatedBy: "\n").count, 2, "no agent line without an agent")

        // Still open (more attempts, a new hold): no new banner.
        var again = agent
        again.attempts = 5
        again.answerBy = Date()
        XCTAssertEqual(planner.plan(asks: [again, apple], formatter: m.formatter), AskNotificationPlan())

        // Answered elsewhere (CLI, menu bar, another banner) or expired: withdrawn.
        let answered = planner.plan(asks: [apple], formatter: m.formatter)
        XCTAssertEqual(answered.post, [])
        XCTAssertEqual(answered.remove, ["ask-1"])
        XCTAssertEqual(planner.plan(asks: [apple], formatter: m.formatter), AskNotificationPlan(), "once")

        // A restarted daemon reuses id 2 for a new question: posted again (replacing the old banner).
        let reused = try ask(2, app: "ssh-add", apple: true, firstAt: AskUIModelTests.base + 600)
        let restarted = planner.plan(asks: [reused], formatter: m.formatter)
        XCTAssertEqual(restarted.post.map(\.identifier), ["ask-2"])
        XCTAssertTrue(restarted.post[0].body.hasPrefix("ssh-add wants to read"))
        XCTAssertEqual(planner.plan(asks: [], formatter: m.formatter).remove, ["ask-2"])

        // In Chinese.
        let zh = NotificationPlanner().plan(asks: [agent], formatter: model(status(), language: .zhHans).formatter)
        XCTAssertEqual(zh.post.first?.title, "允许这次访问吗？")
        XCTAssertEqual(zh.post.first?.body,
                       "调用链中有 AI agent：claude-code\nClaude Code 想要读取 ~/.ssh/id_ed25519，你决定之前不会放行（3 次）\n调用链：launchd → claude → cat")

        // The headline may name only the app (Terminal) the agent runs in: the agent is named too,
        // as the app knows it (an answer covers the app only as driven by that agent).
        var inTerminal = agent
        inTerminal.id = 3
        inTerminal.responsible = ResponsibleEntity(kind: .app, key: "app:com.apple.Terminal", displayName: "Terminal")
        let body = try XCTUnwrap(NotificationPlanner().plan(asks: [inTerminal], formatter: m.formatter,
                                                            agentName: { $0 == "claude-code" ? "Claude Code" : $0 }).post.first?.body)
        XCTAssertTrue(body.contains("\nTerminal wants to read"), body)
        XCTAssertTrue(body.hasPrefix("AI agent in the chain: Claude Code\n"), body)
        XCTAssertNil(apple.agentsLine(.en))

        XCTAssertTrue(NotificationPlanner.isAskIdentifier(NotificationPlanner.askIdentifier(9)))
        XCTAssertFalse(NotificationPlanner.isAskIdentifier("alert-9-0-blocked-1"))
    }

    func testAskAlertsAreNotNotifiedSeparately() throws {
        let m = AppModel(language: .en)
        m.apply(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: true))
        let planner = NotificationPlanner(launchedAt: Date().addingTimeInterval(-3600))
        var askAlert = try XCTUnwrap(m.alerts.first)
        askAlert.id = 500
        askAlert.kind = .ask
        askAlert.createdAt = Date()
        XCTAssertEqual(planner.plan([askAlert], settings: NotificationSettings(), formatter: m.formatter), [],
                       "the question has its own notification")
        // A first access escalated to a question is not re-notified either.
        var first = askAlert
        first.id = 501
        first.kind = .firstAccess
        XCTAssertEqual(planner.plan([first], settings: NotificationSettings(), formatter: m.formatter).count, 1)
        first.kind = .ask
        XCTAssertEqual(planner.plan([first], settings: NotificationSettings(), formatter: m.formatter), [])
        // Other kinds still notify.
        var blocked = askAlert
        blocked.id = 502
        blocked.kind = .blocked
        XCTAssertEqual(planner.plan([blocked], settings: NotificationSettings(), formatter: m.formatter).map(\.alertID), [502])
    }

    func testUncleanStopIsNotifiedOnce() {
        let planner = NotificationPlanner()
        XCTAssertEqual(planner.plan(status: status(), language: .en), [])
        let stopped = status(uncleanStop: "stopped at 2026-10-05 01:00 while AUTH was subscribed")
        let notices = planner.plan(status: stopped, language: .zhHans)
        XCTAssertEqual(notices.count, 1)
        XCTAssertEqual(notices.first?.identifier, "whoread.unclean-stop")
        XCTAssertEqual(notices.first?.title, "WhoRead 监控程序意外停止")
        XCTAssertTrue(notices.first?.body.contains("stopped at 2026-10-05 01:00") ?? false)
        XCTAssertTrue(notices.first?.body.contains("拦截保持你的设置") ?? false)
        XCTAssertEqual(planner.plan(status: stopped, language: .zhHans), [], "once")
        XCTAssertEqual(planner.notifiedUncleanStop, stopped.uncleanStop)
        // A relaunched app hands back what it kept.
        XCTAssertEqual(NotificationPlanner(notifiedUncleanStop: planner.notifiedUncleanStop).plan(status: stopped, language: .en), [])
        // Another unclean stop while the app was closed.
        XCTAssertEqual(NotificationPlanner(notifiedUncleanStop: "older").plan(status: stopped, language: .en).count, 1)
        // A clean start: nothing left to keep.
        XCTAssertEqual(planner.plan(status: status(), language: .en), [])
        XCTAssertNil(planner.notifiedUncleanStop)

        // Shown in Settings while the daemon reports it.
        XCTAssertNil(model(status()).uncleanStopText)
        XCTAssertEqual(model(stopped).uncleanStopText,
                       "The monitor stopped unexpectedly while it could block (stopped at 2026-10-05 01:00 while AUTH was subscribed). Enforcement stays as you set it.")
    }

    // MARK: - Menu bar and status

    func testMenuBarHasNoLearningState() {
        let learning = model(status(mode: .learning))
        XCTAssertEqual(learning.menuBar.symbol, "eye")
        XCTAssertEqual(learning.menuBar.title, "Monitoring")
        XCTAssertEqual(model(status(mode: .learning), language: .zhHans).menuBar.title, "监控中")
        XCTAssertEqual(L10n.mode(.learning, .en), L10n.mode(.monitoring, .en))
        XCTAssertEqual(model(status(mode: .enforcing)).menuBar.symbol, "lock.shield")

        // No learning UI left in the string table.
        XCTAssertTrue(L.allCases.filter { $0.rawValue.lowercased().contains("learn") }.isEmpty)
        for key in L.allCases {
            XCTAssertFalse(L10n.t(key, .en).lowercased().contains("learn"), "\(key)")
            XCTAssertFalse(L10n.t(key, .zhHans).contains("学习"), "\(key)")
            XCTAssertFalse(L10n.t(key, .en).lowercased().contains("automatically"), "\(key): no automatic switch-off")
        }
    }

    func testOpenQuestionsComeFirstInTheMenuBar() throws {
        let quiet = model(status(mode: .enforcing, unread: 3))
        XCTAssertEqual(quiet.menuBar.badge, "3")
        XCTAssertEqual(quiet.menuBar.labelSymbol, "lock.shield")
        XCTAssertEqual(quiet.menuBar.accessibilityLabel, "Enforcing")

        let asking = model(status(mode: .enforcing, unread: 3), asks: [try ask(1), try ask(2)])
        XCTAssertEqual(asking.menuBar.badge, "2", "open questions before unread alerts")
        XCTAssertEqual(asking.menuBar.labelSymbol, "questionmark.circle.fill")
        XCTAssertEqual(asking.menuBar.symbol, "lock.shield", "the mode stays in the popover header")
        XCTAssertEqual(asking.menuBar.title, "Enforcing")
        XCTAssertEqual(asking.menuBar.accessibilityLabel, "2 questions waiting — Enforcing")
        XCTAssertEqual(model(status(mode: .enforcing), asks: [try ask(1)], language: .zhHans).menuBar.accessibilityLabel,
                       "1 个访问等待你的决定 — 拦截中")

        let many = model(status(), asks: try (1...120).map { try ask(Int64($0)) })
        XCTAssertEqual(many.menuBar.badge, "99+")

        // Listed with the questions that hold an access first (denied soonest on top): old ones that
        // hold nothing must not push them out of the menu bar's first three rows.
        let now = Date()
        let listed = model(status(), asks: [try ask(1), try ask(2), try ask(3), try ask(4, answerBy: now + 20),
                                            try ask(5), try ask(6, answerBy: now + 5)])
        XCTAssertEqual(listed.asksByUrgency.map(\.id), [6, 4, 1, 2, 3, 5])
        XCTAssertEqual(listed.asks.map(\.id), [1, 2, 3, 4, 5, 6], "the daemon's order is kept for the rest")
    }

    func testSlowResponsesWarningReplacesTrips() {
        XCTAssertNil(model(status()).slowResponsesText)
        let fine = LatencyStats(samples: 500, p50Micros: 200, p99Micros: 9_000, maxMicros: 20_000, deadlineMisses: 0, totalResponses: 500)
        XCTAssertNil(model(status(latency: fine)).slowResponsesText)

        let missed = LatencyStats(samples: 500, p50Micros: 200, p99Micros: 9_000, maxMicros: 20_000, deadlineMisses: 2, totalResponses: 500)
        let m = model(status(latency: missed))
        XCTAssertEqual(m.slowResponsesText, "Slow responses: 2 missed kernel deadlines. Enforcement stays as you set it.")
        XCTAssertTrue(m.enforcementSwitchOn, "never switched off automatically")
        XCTAssertNil(m.enforcementInactiveText)

        let slow = LatencyStats(samples: 500, p50Micros: 200, p99Micros: 80_400, maxMicros: 90_000, deadlineMisses: 0, totalResponses: 500)
        XCTAssertEqual(model(status(latency: slow)).slowResponsesText,
                       "Slow responses: p99 80.4 ms (warning above 50 ms). Enforcement stays as you set it.")
        // The threshold comes from Settings.
        XCTAssertNil(model(status(latency: slow), settings: Settings(latencyP99ThresholdMs: 100)).slowResponsesText)
        // Too few responses to judge a p99.
        var few = slow
        few.samples = 10
        XCTAssertNil(model(status(latency: few)).slowResponsesText)

        var both = slow
        both.deadlineMisses = 1
        XCTAssertEqual(model(status(latency: both), language: .zhHans).slowResponsesText,
                       "响应变慢：错过内核期限 1 次，p99 80.4 毫秒（超过 50 毫秒提醒）。拦截保持你的设置。")
    }

    // MARK: - Answers and settings

    func testAnswersAndTheirWording() throws {
        let agent = try ask(1)
        let apple = try ask(2, app: "security", apple: true)
        XCTAssertEqual(AskAnswers.allowActions(for: agent), [.allowOnce, .alwaysAllow])
        XCTAssertEqual(AskAnswers.allowActions(for: apple), [.allowOnce, .alwaysAllow, .trustApplePrograms])
        XCTAssertEqual(AskAnswers.denyActions, [.keepBlocking, .blockFromNowOn])
        // Same answers as the question's `ask` alert.
        XCTAssertEqual(AskAnswers.actions(for: agent), agent.asAlert.availableActions)
        XCTAssertEqual(AskAnswers.actions(for: apple), apple.asAlert.availableActions)

        let en = AskAnswers.actions(for: apple).map { L10n.askActionTitle($0, .en) }
        XCTAssertEqual(en, ["Allow once (10 min)", "Always allow", "Deny", "Always deny", "Allow all Apple programs"])
        let zh = AskAnswers.actions(for: apple).map { L10n.askActionTitle($0, .zhHans) }
        XCTAssertEqual(zh, ["允许一次（10 分钟）", "始终允许", "拒绝", "始终拒绝", "允许所有苹果程序"])

        // `ask` alerts in the Alerts tab use the same wording; other alerts keep theirs.
        let m = model(status())
        XCTAssertEqual(m.actionTitle(.keepBlocking, for: .ask), "Deny")
        XCTAssertEqual(m.actionTitle(.keepBlocking, for: .blocked), "Keep blocking")
        XCTAssertEqual(m.actionTitle(.blockFromNowOn, for: .firstAccess), "Block from now on")

        // An unsigned build (not root) cannot allow: say how to do it instead.
        let refused = IPCError(.notPermitted, "allowing needs root or the signed app")
        XCTAssertEqual(L10n.answerError(refused, askID: 7, action: .allowOnce, .en),
                       "Not allowed: only the signed WhoRead app or an administrator can allow (this build is not signed). In Terminal: sudo whoread ask 7 allow-once")
        XCTAssertTrue(L10n.answerError(refused, askID: 7, action: .trustApplePrograms, .zhHans).hasSuffix("sudo whoread ask 7 trust-apple"))
        XCTAssertTrue(L10n.answerError(refused, askID: 7, action: .alwaysAllow, .en).hasSuffix("sudo whoread ask 7 allow"))
        XCTAssertEqual(L10n.answerError(refused, askID: 7, action: .keepBlocking, .en), L10n.t(.errNotPermitted, .en))
        XCTAssertEqual(L10n.answerError(IPCError(.notFound, "no question #7"), askID: 7, action: .keepBlocking, .zhHans),
                       "这个问题已经关闭（已在别处回答或已过期）。")
        XCTAssertEqual(L10n.answerError(IPCError(.invalid, "bad"), askID: 7, action: .alwaysAllow, .en), "The daemon refused: bad")
        XCTAssertEqual(AskAnswers.denyActions.map(AskAnswers.cliVerb), ["deny", "block"])
    }

    func testTrustAppleProgramsIsItsOwnSwitch() throws {
        XCTAssertEqual(L10n.t(.setTrustApple, .en), "Trust all Apple programs (not when started by an AI agent)")
        XCTAssertEqual(L10n.t(.setTrustApple, .zhHans), "信任所有苹果程序（由 AI agent 启动时除外）")
        XCTAssertFalse(Settings().trustApplePrograms, "off by default")

        let m = AppModel(language: .en)
        m.apply(SnapshotFetcher.fetch(client, liveAfter: nil, includeBenign: false, full: true))
        let stale = try XCTUnwrap(m.settings)
        // Switched on (the Settings toggle, or "allow all Apple programs" on a question): read-modify-write.
        var current = try client.settings()
        current.trustApplePrograms = true
        m.apply(response: try client.call(.updateSettings(current)))
        XCTAssertEqual(m.settings?.trustApplePrograms, true)
        // A Settings draft started before must not switch it back off.
        var draft = stale
        draft.retentionDays = 60
        let saved = m.preparedForSave(draft)
        XCTAssertTrue(saved.trustApplePrograms)
        XCTAssertEqual(saved.retentionDays, 60)
    }

    func testEditingAnAnswerKeepsItsChainScope() throws {
        // "Always allow" for Terminal without an AI agent (as the daemon saves an answer).
        let answer = Rule(name: "Allow Terminal", enabled: true, enforce: false, target: .category("ssh"),
                          subject: .responsible(key: "app:com.apple.Terminal", teamID: nil, cdhash: nil, exceptOwners: false),
                          access: .read, action: .allow, template: "ask-answer", chainAgents: [])
        var draft = RuleDraft(rule: answer)
        draft.name = "Terminal may read SSH keys"
        draft.access = .any
        let edited = draft.build().keepingDaemonState(of: answer)
        XCTAssertEqual(edited.chainAgents, [], "never widened to Terminal driven by an AI agent")
        XCTAssertEqual(edited.name, "Terminal may read SSH keys")
        XCTAssertEqual(edited.template, "ask-answer")
        XCTAssertEqual(RuleDraft(rule: answer).build(now: answer.createdAt), answer, "unchanged when nothing is edited")

        var forAgent = answer
        forAgent.chainAgents = ["claude-code"]
        XCTAssertEqual(RuleDraft(rule: forAgent).build().chainAgents, ["claude-code"])
        // Rules without a scope stay unscoped; a new rule has none.
        XCTAssertNil(RuleDraft(template: RuleTemplates.all[0]).build().chainAgents)
        XCTAssertNil(RuleDraft().build().chainAgents)

        // Shown in the Rules tab, so the two answers do not read the same.
        let m = model(status())
        XCTAssertNil(m.chainScope(RuleTemplates.all[0]))
        XCTAssertEqual(m.chainScope(answer), "only without an AI agent in the chain")
        XCTAssertEqual(m.chainScope(forAgent), "only with these AI agents in the chain: claude-code")
        XCTAssertEqual(model(status(), language: .zhHans).chainScope(answer), "仅限调用链中没有 AI agent")
    }

    func testAskStringsExistInBothLanguages() {
        let keys: [L] = [.asksTitle, .asksWaitingFormat, .asksMoreFormat, .askDeniedIn, .askNotHeld, .askAllowOnce,
                         .askAlwaysAllow, .askDeny, .askAlwaysDeny, .askTrustApple, .askAllowNotPermittedFormat, .askGone,
                         .setAsk, .setAskNote, .setTrustApple, .setTrustAppleNote, .slowResponsesFormat, .slowMissesFormat,
                         .slowP99Format, .uncleanStopFormat, .notifUncleanStopTitle, .notifAskTitle, .notifAskFailedTitle,
                         .ruleChainNoAgent, .ruleChainAgentsFormat, .askAgentsFormat]
        for key in keys {
            XCTAssertNotNil(L10n.table[key], "\(key)")
            XCTAssertNotEqual(L10n.t(key, .en), L10n.t(key, .zhHans), "\(key) is translated")
        }
        XCTAssertEqual(L10n.f(.asksWaitingFormat, 3, language: .en), "3 questions waiting")
        XCTAssertEqual(L10n.f(.asksMoreFormat, 4, language: .zhHans), "还有 4 个…")
        XCTAssertEqual(L10n.t(.setLatency, .en), "Warn when p99 response time exceeds (ms)")
    }
}

final class AskPlanCompletenessTests: XCTestCase {
    func request(_ id: Int64) -> AskRequest {
        AskRequest(id: id, key: AskKey(responsibleKey: "app:/x", categoryID: "ssh", access: .read, chainAgents: []),
                   responsible: ResponsibleEntity(kind: .app, key: "app:/x", displayName: "X"), severity: .critical,
                   path: "/Users/alice/.ssh/id_ed25519", process: ProcessRecord(pid: 1, ppid: 0, executablePath: "/bin/cat"),
                   chain: [], agentID: nil, appleProgram: false, firstAt: Date(timeIntervalSince1970: Double(id)),
                   lastAt: Date(timeIntervalSince1970: Double(id)))
    }

    /// A capped reply (more open questions than listed) never withdraws banners of questions it left out.
    func testACappedReplyDoesNotWithdrawBanners() {
        let planner = NotificationPlanner()
        let f = AlertFormatter(language: .en)
        XCTAssertEqual(planner.plan(asks: [request(1), request(2)], formatter: f).post.count, 2)
        let capped = planner.plan(asks: [request(2), request(3)], formatter: f, complete: false)
        XCTAssertEqual(capped.remove, [], "#1 may still be open")
        XCTAssertEqual(capped.post.map(\.askID), [3])
        XCTAssertEqual(planner.plan(asks: [request(1), request(2), request(3)], formatter: f, complete: false).post, [],
                       "#1 is back in the list: not re-posted")
        XCTAssertEqual(planner.plan(asks: [request(3)], formatter: f).remove, ["ask-1", "ask-2"])
    }
}
