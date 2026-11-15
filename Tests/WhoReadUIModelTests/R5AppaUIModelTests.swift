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
