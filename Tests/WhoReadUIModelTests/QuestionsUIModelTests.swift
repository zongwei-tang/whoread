import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine
@testable import WhoReadUIModel

/// The questions do not depend on any history read: an app the daemon does not serve as the signed
/// WhoRead app (a development or ad hoc build, or a wrong guess when its connection was accepted) still
/// lists and denies questions, gets what is open to the console user, and says plainly what it cannot
/// see. Each read the app polls is checked against the daemon's real permission table (ServiceHandler).
final class QuestionsUIModelTests: XCTestCase {
    var dir: URL!
    var core: DaemonCore!
    var handler: ServiceHandler!
    /// The app as the daemon sees an unrecognised build: the console user, not the app.
    var unrecognised: IPCClient!
    /// The signed app.
    var signed: IPCClient!

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("whoread-questions-ui-\(UUID().uuidString.prefix(6))")
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
        unrecognised = InProcessClient(handler: handler, peer: IPCPeer(pid: getpid(), euid: geteuid(), isTrustedCode: true, isApp: false))
        signed = InProcessClient(handler: handler, peer: IPCPeer(pid: getpid(), euid: geteuid(), isTrustedCode: true, isApp: true))
    }

    override func tearDownWithError() throws {
        core.askBroker.denyAll()
        try? FileManager.default.removeItem(at: dir)
    }

    private static let terminal = ResponsibleEntity(kind: .app, key: "app:/system/applications/utilities/terminal.app",
                                                    displayName: "Terminal", path: "/System/Applications/Utilities/Terminal.app")

    /// A question holding an access, as the native source opens one (Terminal → zsh → cat reads a key).
    @discardableResult
    private func openQuestion(category: String = "ssh") throws -> Int64 {
        let q = AskRequest(id: 0, key: AskKey(responsibleKey: Self.terminal.key, categoryID: category, access: .read, chainAgents: []),
                           responsible: Self.terminal, severity: .critical, path: "/Users/alice/.ssh/id_ed25519",
                           process: ProcessRecord(pid: 42, ppid: 10, executablePath: "/bin/cat"), chain: [], agentID: nil,
                           appleProgram: false, firstAt: Date(), lastAt: Date())
        core.askBroker.noteAnsweringClient()
        guard case .held(let id) = core.askBroker.hold(q, budget: 60, respond: { _ in }) else {
            XCTFail("not held")
            return 0
        }
        return id
    }

    /// What the app does every tick: the questions on their own connection, then status and history.
    private func poll(_ m: AppModel, _ client: IPCClient, full: Bool = false, hello: Bool = false) -> Snapshot {
        m.apply(asks: SnapshotFetcher.fetchAsks(client))
        let s = SnapshotFetcher.fetch(client, liveAfter: m.liveCursor, includeBenign: false, full: full, hello: hello)
        m.apply(s)
        return s
    }

    // MARK: - task-1: questions never depend on a history read

    func testTask1UnrecognisedAppKeepsQuestionsAndWhatIsOpenToIt() throws {
        let id = try openQuestion()
        let m = AppModel(language: .en)
        let s = poll(m, unrecognised, full: true, hello: true)

        // Only the recorded reads are refused, each on its own; nothing else is lost.
        XCTAssertNil(s.error)
        XCTAssertEqual(Set(s.failures.keys), [.alerts, .live, .summaries, .rules])
        XCTAssertTrue(s.failures.values.allSatisfy { $0.code == .notPermitted })
        XCTAssertTrue(s.refusedRecordedRead)
        XCTAssertNotNil(m.settings, "settings are open to the console user")
        XCTAssertNotNil(m.catalog)
        XCTAssertNotNil(m.agents)
        XCTAssertNotNil(m.status)

        // The question is listed, and stays listed poll after poll.
        XCTAssertEqual(m.asks.map(\.id), [id])
        _ = poll(m, unrecognised)
        _ = poll(m, unrecognised, full: true)
        XCTAssertEqual(m.asks.map(\.id), [id])
        XCTAssertEqual(m.pollInterval, PollSchedule.askingInterval)

        // Not shown as broken: connected, the mode as usual, the question in the menu bar.
        XCTAssertNil(m.lastError)
        XCTAssertTrue(m.connected)
        XCTAssertNil(m.connectionProblemText)
        XCTAssertNotEqual(m.menuBar.symbol, "exclamationmark.triangle")
        XCTAssertEqual(m.menuBar.openAsks, 1)
        XCTAssertEqual(m.menuBar.labelSymbol, "questionmark.circle.fill")

        // A limited view, saying what is missing and what is needed.
        XCTAssertEqual(m.refusedParts, [.alerts, .live, .summaries, .rules])
        XCTAssertTrue(m.asksPathsHidden)
        let limited = try XCTUnwrap(m.limitedViewText)
        for part in ["alerts", "the live feed", "the app, file and AI agent history", "the rules", "the file paths in questions",
                     "signed WhoRead app", "deny", "sudo whoread asks"] {
            XCTAssertTrue(limited.contains(part), part)
        }
        XCTAssertTrue(try XCTUnwrap(m.unavailableNote(.alerts)).contains("sudo whoread alerts"))
        XCTAssertTrue(try XCTUnwrap(m.unavailableNote(.summaries)).contains("sudo whoread apps"))
        XCTAssertNil(m.unavailableNote(.settings))
        let zh = AppModel(language: .zhHans)
        _ = poll(zh, unrecognised, full: true)
        XCTAssertTrue(try XCTUnwrap(zh.limitedViewText).hasPrefix("受限视图"))

        // The daemon hides the path from this connection: the question says so in the UI language,
        // and still names the app.
        let ask = try XCTUnwrap(m.asks.first)
        XCTAssertTrue(ask.pathHidden)
        XCTAssertFalse(ServiceHandler.hiddenPath.hasPrefix("/"), "pathHidden recognises the daemon's placeholder")
        XCTAssertEqual(m.formatter.headline(ask.displayAlert(.en)),
                       "Terminal wants to read (file path hidden: only the signed WhoRead app or sudo can see it): not allowed until you decide")
        let banner = try XCTUnwrap(NotificationPlanner().plan(asks: m.asks, formatter: m.formatter).post.first)
        XCTAssertTrue(banner.body.contains("file path hidden"), banner.body)

        // Answering: allowing is refused with the way to do it from Terminal; denying works.
        let refused = try XCTUnwrap({ () -> IPCError? in
            do { _ = try unrecognised.call(.answerAsk(id: id, action: .alwaysAllow)); return nil } catch let e as IPCError { return e }
        }())
        XCTAssertEqual(refused.code, .notPermitted)
        XCTAssertTrue(L10n.answerError(refused, askID: id, action: .alwaysAllow, .en).contains("sudo whoread ask \(id) allow"))
        XCTAssertEqual(m.asks.map(\.id), [id], "still open")
        m.apply(response: try unrecognised.call(.answerAsk(id: id, action: .keepBlocking)))
        XCTAssertEqual(m.asks, [])
        _ = poll(m, unrecognised)
        XCTAssertEqual(m.asks, [])
        XCTAssertFalse(m.asksPathsHidden)
    }

    func testTask1SignedAppSeesEverythingAndARefusalHeals() throws {
        try openQuestion()
        let m = AppModel(language: .en)
        _ = poll(m, signed, full: true, hello: true)
        XCTAssertEqual(m.failures, [:])
        XCTAssertNil(m.limitedViewText)
        XCTAssertFalse(m.asksPathsHidden)
        XCTAssertEqual(m.asks.first?.path, "/Users/alice/.ssh/id_ed25519")
        let alerts = m.alerts
        let summaries = m.summaries
        let rules = m.rules
        XCTAssertFalse(alerts.isEmpty)
        XCTAssertFalse(summaries.isEmpty)

        // The same app on a connection the daemon does not serve as the app (a wrong guess when it was
        // accepted): what was read is kept, and the view says it is limited.
        let s = poll(m, unrecognised, full: true)
        XCTAssertTrue(s.refusedRecordedRead)
        XCTAssertEqual(m.alerts, alerts, "a refused read keeps the last data")
        XCTAssertEqual(m.summaries.count, summaries.count)
        XCTAssertEqual(m.rules, rules)
        XCTAssertEqual(m.asks.count, 1)
        XCTAssertNotNil(m.limitedViewText)
        XCTAssertNotNil(m.unavailableNote(.alerts))

        // A new connection served as the app: everything current again, no note left.
        _ = poll(m, signed)
        XCTAssertNil(m.unavailableNote(.alerts))
        XCTAssertNil(m.unavailableNote(.live))
        XCTAssertNotNil(m.unavailableNote(.summaries), "not read by a fast poll: still the old data")
        _ = poll(m, signed, full: true)
        XCTAssertEqual(m.failures, [:])
        XCTAssertNil(m.limitedViewText)
    }

    // MARK: - task-1-variant: every read fails on its own, status and questions decide alone

    func testTask1VariantEachReadFailsOnItsOwn() throws {
        let inner = signed!
        var calls: [String] = []
        let flaky = FixedClient { request in
            switch request {
            case .summaries: calls.append("summaries"); throw IPCError(.internalError, "database is locked")
            case .live: calls.append("live"); throw IPCError(.unavailable, "daemon did not answer within 15 s")
            case .rules: calls.append("rules")
            case .alerts: calls.append("alerts")
            default: break
            }
            return try inner.send(request)
        }
        let s = SnapshotFetcher.fetch(flaky, liveAfter: nil, includeBenign: false, full: true)
        XCTAssertNil(s.error)
        XCTAssertNotNil(s.status)
        XCTAssertNotNil(s.settings)
        XCTAssertNotNil(s.catalog)
        XCTAssertNotNil(s.agents)
        XCTAssertNotNil(s.alerts)
        XCTAssertNil(s.newLive)
        XCTAssertEqual(s.failures[.live]?.code, .unavailable)
        // No answer at all: the reads after it would wait as long, so the poll ends there.
        XCTAssertEqual(calls, ["alerts", "live"])
        XCTAssertNil(s.summaries)
        XCTAssertNil(s.rules)
        XCTAssertFalse(s.refusedRecordedRead, "not a refusal")

        let m = AppModel(language: .en)
        m.apply(asks: .asks([]))
        m.apply(s)
        XCTAssertTrue(m.connected)
        XCTAssertNil(m.lastError)
        XCTAssertNil(m.limitedViewText, "not refused")
        XCTAssertEqual(m.unavailableNote(.live), "Could not read the live feed: No answer from the WhoRead daemon.")

        // A store error is that read's alone.
        calls = []
        let locked = FixedClient { request in
            if case .summaries = request { throw IPCError(.internalError, "database is locked") }
            return try inner.send(request)
        }
        let t = SnapshotFetcher.fetch(locked, liveAfter: nil, includeBenign: false, full: true)
        XCTAssertNotNil(t.rules)
        XCTAssertNotNil(t.newLive)
        m.apply(t)
        XCTAssertNil(m.unavailableNote(.live))
        XCTAssertEqual(m.unavailableNote(.summaries), "Could not read the app, file and AI agent history: The daemon refused: database is locked")
    }

    func testTask1VariantQuestionsSurviveAStatusTheAppCannotRead() throws {
        let id = try openQuestion()
        let m = AppModel(language: .en)
        _ = poll(m, signed, full: true, hello: true)
        XCTAssertEqual(m.asks.map(\.id), [id])

        // The status and history connection fails; the questions' connection still reads them.
        var down = Snapshot()
        down.error = IPCError(.unavailable, "daemon did not answer within 15 s")
        m.apply(down)
        XCTAssertEqual(m.asks.map(\.id), [id], "only the questions' own connection lists or clears them")
        XCTAssertEqual(m.menuBar.openAsks, 1)
        XCTAssertEqual(m.menuBar.labelSymbol, "questionmark.circle.fill", "the error state still shows the question")
        XCTAssertEqual(m.menuBar.badge, "1")
        var garbled = Snapshot()
        garbled.error = IPCError(.versionMismatch, "new field")
        m.apply(garbled)
        XCTAssertEqual(m.asks.map(\.id), [id])

        // When the questions themselves cannot be read, they cannot be answered either.
        m.apply(asks: .failed(IPCError(.unavailable, "gone")))
        XCTAssertEqual(m.asks, [])
        XCTAssertEqual(m.pollInterval, PollSchedule.idleInterval)
        XCTAssertNil(m.menuBar.badge)
        m.apply(asks: SnapshotFetcher.fetchAsks(signed))
        XCTAssertEqual(m.asks.map(\.id), [id])
        XCTAssertNil(m.asksError)
    }

    func testTask1VariantAnotherUserThanTheConsoleIsToldWhy() throws {
        try openQuestion()
        handler.consoleUID = { geteuid() &+ 1 }
        let m = AppModel(language: .en)
        let s = poll(m, unrecognised, full: true, hello: true)
        XCTAssertEqual(s.error?.code, .notPermitted)
        XCTAssertEqual(m.asksError?.code, .notPermitted)
        XCTAssertEqual(m.asks, [])
        XCTAssertEqual(m.connectionProblemText, L10n.t(.errNotConsoleUser, .en))
        XCTAssertEqual(m.asksProblemText, L10n.t(.errNotConsoleUser, .en))
        XCTAssertTrue(try XCTUnwrap(m.connectionProblemText).contains("another user"))
        XCTAssertNil(m.limitedViewText, "not a limited view: nothing is served")

        // A daemon that does not answer: the menu says so already, the questions note adds nothing.
        let gone = AppModel(language: .en)
        var down = Snapshot()
        down.error = IPCError(.unavailable, "gone")
        gone.apply(down)
        gone.apply(asks: .failed(IPCError(.unavailable, "gone")))
        XCTAssertNil(gone.asksProblemText)
        XCTAssertNil(gone.connectionProblemText)
        // Reachable, but the questions' reply could not be read.
        let odd = AppModel(language: .en)
        _ = poll(odd, signed)
        odd.apply(asks: .failed(IPCError(.versionMismatch, "new field")))
        XCTAssertTrue(try XCTUnwrap(odd.asksProblemText).hasPrefix("Open questions cannot be read:"))
    }

    func testTask1VariantFetchAsksReportsWhy() throws {
        XCTAssertEqual(SnapshotFetcher.fetchAsks(FixedClient { _ in throw IPCError(.unavailable, "gone") }),
                       .failed(IPCError(.unavailable, "gone")))
        guard case .failed(let e) = SnapshotFetcher.fetchAsks(FixedClient { _ in
            throw DecodingError.dataCorrupted(.init(codingPath: [], debugDescription: "new field"))
        }) else { return XCTFail() }
        XCTAssertEqual(e.code, .versionMismatch)
        XCTAssertEqual(SnapshotFetcher.fetchAsks(FixedClient { _ in .ok }), .failed(IPCError(.internalError, "unexpected response")))
    }

    // MARK: - task-1-variant: strengthening changes do not depend on a history read either

    func testTask1VariantUnrecognisedAppCanStillAddABlockRule() throws {
        // The editor used to read the current rules first: refused, so not even a block rule was saved.
        XCTAssertThrowsError(try unrecognised.rules()) { XCTAssertEqual(($0 as? IPCError)?.code, .notPermitted) }
        let rule = Rule(target: .category("ssh"), subject: .anyNonOwner, action: .deny)
        guard case .ok = try RuleSave.save(rule, with: unrecognised) else { return XCTFail("an unprivileged upsert replies .ok") }
        XCTAssertTrue(core.rules.rules.contains { $0.id == rule.id })
        // Changing it weakens protection: the daemon refuses that itself.
        var edited = rule
        edited.action = .allow
        XCTAssertThrowsError(try RuleSave.save(edited, with: unrecognised)) { XCTAssertEqual(($0 as? IPCError)?.code, .notPermitted) }
        XCTAssertEqual(core.rules.rules.first { $0.id == rule.id }?.action, .deny)

        // The signed app saves over the daemon's current copy (its exceptions kept).
        let exception = RuleException(subject: .anyNonOwner, categoryID: "ssh", access: .read, createdAt: Date())
        var withException = try XCTUnwrap(core.rules.rules.first { $0.id == rule.id })
        withException.exceptions = [exception]
        _ = try signed.call(.upsertRule(withException))
        var renamed = rule
        renamed.name = "Block SSH keys"
        guard case .rules(let saved) = try RuleSave.save(renamed, with: signed) else { return XCTFail() }
        XCTAssertEqual(saved.first { $0.id == rule.id }?.exceptions.count, 1)
        XCTAssertEqual(saved.first { $0.id == rule.id }?.name, "Block SSH keys")
    }

    // MARK: - task-1-variant: a connection the daemon did not take for the app is reopened

    func testTask1VariantReconnectBacksOff() {
        var r = ConnectionRecovery()
        let t = Date(timeIntervalSince1970: 1_790_000_000)
        XCTAssertFalse(r.shouldReconnect(now: t, refused: false))
        XCTAssertTrue(r.shouldReconnect(now: t, refused: true), "at once on the first refusal")
        XCTAssertFalse(r.shouldReconnect(now: t + 1, refused: true), "never every tick")
        XCTAssertFalse(r.shouldReconnect(now: t + 29, refused: true))
        XCTAssertTrue(r.shouldReconnect(now: t + 30, refused: true))
        XCTAssertFalse(r.shouldReconnect(now: t + 89, refused: true))
        XCTAssertTrue(r.shouldReconnect(now: t + 90, refused: true), "then 60 s")
        var later = t + 90
        for _ in 0..<10 {
            later += 3600
            XCTAssertTrue(r.shouldReconnect(now: later, refused: true))
        }
        XCTAssertEqual(r.wait, ConnectionRecovery.maxRetry, "capped: a development build is refused for good")
        // Served again: the next refusal reconnects at once.
        XCTAssertFalse(r.shouldReconnect(now: later + 1, refused: false))
        XCTAssertTrue(r.shouldReconnect(now: later + 2, refused: true))
    }

    // MARK: - task-1-variant: alerts first read late do not all notify at once

    func testTask1VariantAlertsReadAfterARefusalDoNotBurst() throws {
        let m = AppModel(language: .en)
        _ = poll(m, signed, full: true)
        let old = m.alerts
        XCTAssertFalse(old.isEmpty)
        // Launched after these alerts were raised; alerts refused on the first polls.
        let planner = NotificationPlanner(launchedAt: Date().addingTimeInterval(3600))
        let settings = try XCTUnwrap(m.settings).notifications
        XCTAssertEqual(planner.plan(nil, settings: settings, formatter: m.formatter), [], "nothing read: nothing planned")
        XCTAssertEqual(planner.plan(nil, settings: settings, formatter: m.formatter), [])
        // The first read seeds: alerts raised before launch do not notify.
        XCTAssertEqual(planner.plan(old, settings: settings, formatter: m.formatter), [])
        var new = try XCTUnwrap(old.first)
        new.id = 9999
        new.createdAt = Date().addingTimeInterval(7200)
        new.updatedAt = new.createdAt
        XCTAssertEqual(planner.plan(old + [new], settings: settings, formatter: m.formatter).map(\.alertID), [9999])
    }
}
