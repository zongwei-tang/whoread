import XCTest
import SQLite3
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
        // task-3-variant: the daemon runs (the status was read); the questions' read got no reply.
        odd.apply(asks: .failed(IPCError(.unavailable, "daemon did not answer within 15 s")))
        XCTAssertEqual(odd.asksProblemText, "Open questions cannot be read: No answer from the WhoRead daemon.")
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

    // MARK: - task-2: an answer is per app; the question and its buttons say so

    private static let claudeCLI = ResponsibleEntity(kind: .agent, key: "agent:claude-code", displayName: "Claude Code",
                                                     path: "/opt/homebrew/bin/claude", agentID: "claude-code")
    private static let cursor = ResponsibleEntity(kind: .agent, key: "agent:cursor", displayName: "Cursor",
                                                  path: "/Applications/Cursor.app", agentID: "cursor")
    private static let python = ResponsibleEntity(kind: .binary, key: "bin:/opt/homebrew/bin/python3", displayName: "python3",
                                                  path: "/opt/homebrew/bin/python3")

    private func formatter(_ language: Language) -> AlertFormatter {
        AlertFormatter(language: language, categoryName: { $0 == "ssh" ? LocalizedText(en: "SSH keys", zhHans: "SSH 密钥") : nil })
    }

    func testTask2AlwaysAllowNamesTheWholeApp() {
        let en = formatter(.en), zh = formatter(.zhHans)
        XCTAssertEqual(en.alwaysAllowTitle(Self.terminal, categoryID: "ssh", access: .read),
                       "Always allow Terminal (any program run in it) to read SSH keys")
        XCTAssertEqual(zh.alwaysAllowTitle(Self.terminal, categoryID: "ssh", access: .read),
                       "始终允许 Terminal（及在其中运行的任何程序）读取 SSH 密钥")
        // What is charged to an AI agent outside an app, an AI agent that is an app, a program.
        XCTAssertEqual(en.alwaysAllowTitle(Self.claudeCLI, categoryID: "ssh", access: .write),
                       "Always allow Claude Code (any program it runs) to write to SSH keys")
        XCTAssertEqual(en.answerSubject(Self.cursor), "Cursor (any program run in it)")
        XCTAssertEqual(en.alwaysAllowTitle(Self.python, categoryID: "ssh", access: .readWrite),
                       "Always allow python3 (and the Apple programs it starts) to read and modify SSH keys")
        XCTAssertEqual(zh.answerSubject(Self.python), "python3（及它启动的苹果程序）")
        // Always deny: the same app, every access, every chain.
        XCTAssertEqual(en.alwaysDenyTitle(Self.terminal, categoryID: "ssh", kind: .ask),
                       "Always deny Terminal (any program run in it) any access to SSH keys")
        XCTAssertEqual(zh.alwaysDenyTitle(Self.terminal, categoryID: "ssh", kind: .ask), "始终拒绝 Terminal（及在其中运行的任何程序）访问 SSH 密钥")
        XCTAssertEqual(en.alwaysDenyTitle(Self.terminal, categoryID: "ssh", kind: .firstAccess),
                       "Block Terminal (any program run in it) from SSH keys from now on")

        // The AI agents in the chain: an answer covers chains with no AI agent other than those (Rule.chainAgents).
        XCTAssertEqual(en.allowCoverage(Self.terminal, categoryID: "ssh", access: .read, chainAgents: []),
                       "Terminal (any program run in it) reading SSH keys, only when the chain has no AI agent")
        XCTAssertEqual(en.allowCoverage(Self.terminal, categoryID: "ssh", access: .read, chainAgents: ["codex", "claude-code"],
                                        agentName: { $0 == "claude-code" ? "Claude Code" : "Codex" }),
                       "Terminal (any program run in it) reading SSH keys, only when the chain has no AI agent other than Claude Code, Codex")
        XCTAssertEqual(zh.allowCoverage(Self.terminal, categoryID: "ssh", access: .read, chainAgents: ["claude-code"],
                                        agentName: { _ in "Claude Code" }),
                       "Terminal（及在其中运行的任何程序）读取 SSH 密钥，仅限调用链中除 Claude Code 外没有其他 AI agent 时")
        // Names are the program's own choice: escaped like everywhere else.
        let forged = ResponsibleEntity(kind: .app, key: "app:/x/t.app", displayName: "Terminal\nAlways allow everything", path: "/x/t.app")
        XCTAssertFalse(en.alwaysAllowTitle(forged, categoryID: "ssh", access: .read).contains("\n"))
    }

    func testTask2QuestionAndButtonsSayWhatAnAnswerCovers() throws {
        try openQuestion()
        for (language, cover, allow, deny) in [
            (Language.en, "Allow once (10 min) and Always allow cover: Terminal (any program run in it) reading SSH keys, only when the chain has no AI agent.",
             "Always allow Terminal (any program run in it) to read SSH keys", "Always deny Terminal (any program run in it) any access to SSH keys"),
            (.zhHans, "「允许一次（10 分钟）」和「始终允许」适用于：Terminal（及在其中运行的任何程序）读取 SSH 密钥，仅限调用链中没有 AI agent 时。",
             "始终允许 Terminal（及在其中运行的任何程序）读取 SSH 密钥", "始终拒绝 Terminal（及在其中运行的任何程序）访问 SSH 密钥"),
        ] {
            let m = AppModel(language: language)
            _ = poll(m, signed, full: true)
            let ask = try XCTUnwrap(m.asks.first)
            // Menu bar and Alerts tab (AskRow).
            XCTAssertEqual(ask.allowCoverageLine(m.formatter, agentName: m.agentName), cover)
            XCTAssertEqual(m.answerTitle(.alwaysAllow, for: ask), allow)
            XCTAssertEqual(m.answerTitle(.blockFromNowOn, for: ask), deny)
            XCTAssertEqual(m.answerTitle(.allowOnce, for: ask), L10n.askActionTitle(.allowOnce, language))
            XCTAssertEqual(m.answerTitle(.keepBlocking, for: ask), L10n.askActionTitle(.keepBlocking, language))
            // The banner: after where the program really is, before the chain.
            let banner = try XCTUnwrap(NotificationPlanner().plan(asks: m.asks, formatter: m.formatter, agentName: m.agentName).post.first)
            let lines = banner.body.components(separatedBy: "\n")
            XCTAssertEqual(lines.count, 4, banner.body)
            XCTAssertTrue(lines[1].hasPrefix(language == .en ? "Program: " : "程序："), lines[1])
            XCTAssertEqual(lines[2], cover)
            // Its buttons, registered once per kind, say it too.
            let category = try XCTUnwrap(NotificationPlanner.categories(language: language).first { $0.identifier == banner.categoryIdentifier })
            XCTAssertEqual(category.buttons.map(\.action), banner.actions)
            let always = try XCTUnwrap(category.buttons.first { $0.action == .alwaysAllow })
            XCTAssertEqual(always.title, language == .en ? "Always allow this app (any program run in it)" : "始终允许此应用（及在其中运行的任何程序）")
            XCTAssertTrue(always.needsUnlock)
        }
    }

    func testTask2VariantAlertAnswersSayTheSame() throws {
        let m = AppModel(language: .en)
        _ = poll(m, signed, full: true)
        // Monitor-only mode: a first-access alert stands in for the question; "always allow" saves the
        // same app × category answer.
        var alert = try XCTUnwrap(m.alerts.first)
        alert.kind = .firstAccess
        alert.status = .unread
        alert.responsible = Self.terminal
        alert.categoryID = "ssh"
        alert.accesses = .read
        alert.chain = []
        XCTAssertEqual(alert.allowCoverageLine(m.formatter),
                       "Always allow covers: Terminal (any program run in it) reading SSH keys, only when the chain has no AI agent.")
        XCTAssertEqual(m.answerTitle(.alwaysAllow, for: alert), "Always allow Terminal (any program run in it) to read SSH keys")
        XCTAssertEqual(m.answerTitle(.blockFromNowOn, for: alert), "Block Terminal (any program run in it) from SSH keys from now on")
        XCTAssertEqual(m.answerTitle(.ignore, for: alert), "Ignore")
        // An agent in the chain scopes it (as the daemon takes the agents from the alert's chain).
        alert.chain = [ChainLink(pid: 5, name: "claude", path: "/opt/homebrew/bin/claude", signingID: nil, teamID: nil,
                                 isPlatformBinary: false, agentID: "claude-code", argv: nil)]
        XCTAssertTrue(try XCTUnwrap(alert.allowCoverageLine(m.formatter, agentName: m.agentName)).hasSuffix("no AI agent other than Claude Code."))
        // A question's alert names allow once too; a handled alert offers nothing.
        alert.kind = .ask
        XCTAssertTrue(try XCTUnwrap(alert.allowCoverageLine(m.formatter)).hasPrefix("Allow once (10 min) and Always allow cover:"))
        alert.status = .resolved
        XCTAssertNil(alert.allowCoverageLine(m.formatter))

        // The alert banner, and its category's buttons.
        alert.kind = .criticalNonOwner
        alert.status = .unread
        alert.id = 4242
        alert.createdAt = Date()
        let planned = try XCTUnwrap(NotificationPlanner(launchedAt: .distantPast)
            .plan([alert], settings: NotificationSettings(), formatter: m.formatter, agentName: m.agentName).first)
        XCTAssertTrue(planned.body.contains("Always allow covers: Terminal (any program run in it) reading SSH keys"), planned.body)
        XCTAssertTrue(planned.categoryIdentifier.hasSuffix(".app"))
        let category = try XCTUnwrap(NotificationPlanner.categories(language: .en).first { $0.identifier == planned.categoryIdentifier })
        XCTAssertEqual(category.buttons.map(\.action), planned.actions)
        XCTAssertEqual(category.buttons.first { $0.action == .blockFromNowOn }?.title, "Block this app (any program run in it) from now on")
    }

    func testTask2VariantEveryCategoryIsRegisteredWithItsKind() {
        for language in [Language.en, .zhHans] {
            let categories = NotificationPlanner.categories(language: language)
            XCTAssertEqual(Set(categories.map(\.identifier)).count, categories.count, "unique")
            let titles = Dictionary(uniqueKeysWithValues: categories.map { ($0.identifier, $0.buttons) })
            for kind in [ResponsibleEntity.Kind.app, .agent, .binary] {
                let f = AlertFormatter(language: language)
                for apple in [false, true] {
                    let id = NotificationPlanner.askCategory(apple: apple, responsible: kind)
                    let buttons = titles[id] ?? []
                    XCTAssertEqual(buttons.map(\.action), AskAnswers.actions(apple: apple), id)
                    XCTAssertEqual(buttons.first { $0.action == .alwaysAllow }?.title, f.alwaysAllowTitle(kind: kind), id)
                    XCTAssertEqual(buttons.filter(\.needsUnlock).map(\.action), AskAnswers.actions(apple: apple).filter(AskAnswers.isAllow), id)
                }
                for alertKind in [AlertKind.blocked, .wouldBlock, .firstAccess, .criticalNonOwner, .ruleAlert] {
                    for apple in [false, true] {
                        let id = NotificationPlanner.category(for: alertKind, appleProgram: apple, responsible: kind)
                        XCTAssertNotNil(titles[id], id)
                    }
                }
            }
            XCTAssertEqual(AlertFormatter(language: .en).alwaysAllowTitle(kind: .agent), "Always allow this AI agent (any program it runs)")
            XCTAssertEqual(AlertFormatter(language: .en).alwaysAllowTitle(kind: .binary), "Always allow this program (and the Apple programs it starts)")
        }
    }

    // MARK: - task-3: what happened to an answer is reported as it happened

    private func failure(_ request: IPCRequest, _ client: IPCClient) -> IPCError? {
        do { _ = try client.call(request); return nil } catch let e as IPCError { return e } catch { return nil }
    }

    func testTask3RuleLimitLeavesTheQuestionOpenAndSaysWhy() throws {
        try core.setRules((0..<DaemonCore.maxRules).map { _ in Rule(target: .category("aws"), subject: .anyNonOwner, action: .alert) })
        let id = try openQuestion()
        for action in [AlertAction.alwaysAllow, .allowOnce, .blockFromNowOn] {
            let e = try XCTUnwrap(failure(.answerAsk(id: id, action: action), signed), "\(action)")
            XCTAssertEqual(e.code, .invalid)
            // Used to read "The daemon refused: too many rules", as if the answer itself was refused.
            for language in [Language.en, .zhHans] {
                XCTAssertEqual(L10n.answerError(e, askID: id, action: action, language), L10n.t(.answerRuleLimit, language))
            }
            XCTAssertTrue(L10n.answerError(e, askID: id, action: action, .en).contains("512"))
            guard case .asks(let open) = SnapshotFetcher.fetchAsks(signed) else { return XCTFail() }
            XCTAssertEqual(open.map(\.id), [id], "still open")
            XCTAssertEqual(open.first?.holding, 1, "still holding the access")
        }
        // Deny still works.
        guard case .asks(let left) = try signed.call(.answerAsk(id: id, action: .keepBlocking)) else { return XCTFail() }
        XCTAssertTrue(left.isEmpty)

        // The same on an alert: "always allow" saves the same answer rule.
        let m = AppModel(language: .en)
        _ = poll(m, signed, full: true)
        let alert = try XCTUnwrap(m.alerts.first { $0.status != .resolved && $0.availableActions.contains(.alwaysAllow) })
        let e = try XCTUnwrap(failure(.alertAction(alertID: alert.id, action: .alwaysAllow), signed))
        XCTAssertEqual(L10n.alertActionError(e, alertID: alert.id, action: .alwaysAllow, .en), L10n.t(.answerRuleLimit, .en))
    }

    func testTask3AnswerAppliedButNotSavedIsNotReportedAsRefused() throws {
        let id = try openQuestion()
        // The disk refuses the write (here: the rules table is gone under the daemon).
        var db: OpaquePointer?
        XCTAssertEqual(sqlite3_open(core.config.databasePath, &db), SQLITE_OK)
        defer { sqlite3_close(db) }
        XCTAssertEqual(sqlite3_exec(db, "ALTER TABLE rules RENAME TO rules_gone", nil, nil, nil), SQLITE_OK)

        let e = try XCTUnwrap(failure(.answerAsk(id: id, action: .alwaysAllow), signed))
        XCTAssertEqual(e.code, .internalError)
        let text = L10n.answerError(e, askID: id, action: .alwaysAllow, .en)
        XCTAssertTrue(text.hasPrefix("Your answer applies now, but WhoRead could not save it ("), text)
        XCTAssertFalse(text.contains("refused"), text)
        // It did apply: the rule decides in memory and the question was released.
        XCTAssertNil(core.askBroker.request(id: id))
        XCTAssertTrue(core.rules.rules.contains { $0.template == DaemonCore.askAnswerTemplate })
        XCTAssertTrue(L10n.answerError(e, askID: id, action: .alwaysAllow, .zhHans).hasPrefix("你的回答已经生效"))
    }

    func testTask3QuestionGoneOrNoReply() throws {
        // A banner left from before the daemon restarted (question ids never repeat across restarts).
        let gone = try XCTUnwrap(failure(.answerAsk(id: 4242, action: .alwaysAllow), signed))
        XCTAssertEqual(gone.code, .notFound)
        XCTAssertTrue(L10n.answerError(gone, askID: 4242, action: .alwaysAllow, .en).contains("the WhoRead monitor restarted"))
        XCTAssertTrue(L10n.answerError(gone, askID: 4242, action: .alwaysAllow, .en).contains("you will be asked again"))
        // No reply (timed out, connection lost): it may or may not have been taken; not "not running".
        let silent = IPCError(.unavailable, "daemon did not answer within 15 s (x)")
        XCTAssertEqual(L10n.answerError(silent, askID: 1, action: .alwaysAllow, .en), L10n.t(.answerNoReply, .en))
        XCTAssertEqual(L10n.alertActionError(silent, alertID: 1, action: .ignore, .zhHans), L10n.t(.answerNoReply, .zhHans))
        // Another user than the one at the console: even a deny is refused, and it says why.
        handler.consoleUID = { geteuid() &+ 1 }
        let id = try openQuestion()
        let other = try XCTUnwrap(failure(.answerAsk(id: id, action: .keepBlocking), unrecognised))
        XCTAssertEqual(L10n.answerError(other, askID: id, action: .keepBlocking, .en), L10n.t(.errNotConsoleUser, .en))
    }

    func testTask3VariantRefusalsSayTheAppIsNotRecognised() throws {
        let id = try openQuestion()
        let e = try XCTUnwrap(failure(.answerAsk(id: id, action: .allowOnce), unrecognised))
        let text = L10n.answerError(e, askID: id, action: .allowOnce, .en)
        XCTAssertFalse(text.contains("not signed"), "a signed app the daemon did not recognise is not unsigned: \(text)")
        XCTAssertTrue(text.contains("does not recognise this app as the signed WhoRead app"), text)
        XCTAssertTrue(text.contains("The question is still open"), text)
        XCTAssertTrue(text.hasSuffix("sudo whoread ask \(id) allow-once"), text)
        // On an alert: the `whoread alert` words.
        let refused = IPCError(.notPermitted, "this change weakens protection")
        XCTAssertTrue(L10n.alertActionError(refused, alertID: 5, action: .alwaysAllow, .en).hasSuffix("sudo whoread alert 5 always-allow"))
        XCTAssertTrue(L10n.alertActionError(refused, alertID: 5, action: .keepBlocking, .zhHans).hasSuffix("sudo whoread alert 5 keep-blocking"))
        // Other changes: not "need the WhoRead app" to the WhoRead app itself.
        XCTAssertTrue(L10n.message(for: refused, .en).contains("does not recognise this app as the signed WhoRead app"))
    }
}
