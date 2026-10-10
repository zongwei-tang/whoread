import XCTest
import WhoReadCore
@testable import WhoReadUIModel

/// A question about a chain whose ancestry is unknown says so in its notification.
final class UnknownAncestryQuestionTests: XCTestCase {
    func testTheNotificationSaysWhoStartedItIsUnknown() {
        let key = AskKey(responsibleKey: "bin:apple:com.apple.cat", categoryID: "ssh", access: .read, chainAgents: [], ancestryKnown: false)
        let t = Date(timeIntervalSince1970: 1_790_000_000)
        let ask = AskRequest(id: 1, key: key, responsible: ResponsibleEntity(kind: .binary, key: key.responsibleKey, displayName: "cat"),
                             severity: .critical, path: "/Users/alice/.ssh/id_ed25519",
                             process: ProcessRecord(pid: 42, ppid: 1, executablePath: "/bin/cat"),
                             chain: [ChainLink(pid: 42, name: "cat", path: "/bin/cat", isPlatformBinary: true)],
                             agentID: nil, appleProgram: false, firstAt: t, lastAt: t)
        XCTAssertEqual(ask.asAlert.ancestryKnown, false)
        let plan = NotificationPlanner().plan(asks: [ask], formatter: AlertFormatter(language: .en))
        XCTAssertEqual(plan.post.first?.body.components(separatedBy: "\n").first,
                       "cat wants to read /Users/alice/.ssh/id_ed25519: not allowed until you decide (started by an unknown process, possibly an AI agent)")
    }
}

/// An answer given for a program whose starter was unknown also covers such chains: editing it in the
/// Rules tab keeps that, and the tab says so.
final class UnknownAncestryAnswerRuleTests: XCTestCase {
    let answer = Rule(name: "Allow cat", enabled: true, target: .category("ssh"),
                      subject: .responsible(key: "bin:apple:com.apple.cat", teamID: nil), access: .read, action: .allow,
                      template: "ask-answer", chainAgents: [], coversUnknownAncestry: true)

    func testEditingKeepsTheUnknownStarterScope() {
        XCTAssertEqual(RuleDraft(rule: answer).build(now: answer.createdAt), answer, "unchanged when nothing is edited")
        var draft = RuleDraft(rule: answer)
        draft.name = "cat may read SSH keys"
        XCTAssertTrue(draft.build().keepingDaemonState(of: answer).coversUnknownAncestry)
        var known = answer
        known.coversUnknownAncestry = false
        XCTAssertFalse(RuleDraft(rule: known).build().coversUnknownAncestry)
        XCTAssertFalse(RuleDraft().build().coversUnknownAncestry)
    }

    func testTheRulesTabSaysTheAnswerAlsoCoversAnUnknownStarter() {
        let en = AppModel(language: .en), zh = AppModel(language: .zhHans)
        XCTAssertEqual(en.chainScope(answer), "only without an AI agent in the chain (also when who started the program is unknown)")
        XCTAssertEqual(zh.chainScope(answer), "仅限调用链中没有 AI agent（启动者未知时也适用）")
        var known = answer
        known.coversUnknownAncestry = false
        XCTAssertEqual(en.chainScope(known), "only without an AI agent in the chain")
        XCTAssertNotEqual(L10n.t(.ruleChainUnknownStarter, .en), L10n.t(.ruleChainUnknownStarter, .zhHans))
    }
}
