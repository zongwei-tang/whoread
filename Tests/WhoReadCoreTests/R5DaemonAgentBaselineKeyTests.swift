import XCTest
@testable import WhoReadCore

/// attribution-2 (core): what the baseline knows an AI agent by, and what keeps its critical accesses
/// quiet.
final class R5DaemonAgentBaselineKeyTests: XCTestCase {
    private let key = "/Users/alice/WhoReadTestVault/ssh/id_ed25519"

    func testAnAgentsBaselineKeyCarriesItsTeam() {
        let app = ResponsibleEntity(kind: .app, key: "app:/applications/zoom.us.app", displayName: "zoom.us", teamID: "ZOOMTEAM01")
        XCTAssertEqual(app.baselineKey, app.key, "an app is told apart by its bundle path")
        var agent = ResponsibleEntity(kind: .agent, key: "agent:claude-code", displayName: "Claude Code", teamID: "ANTHROPIC1",
                                      agentID: "claude-code")
        XCTAssertEqual(agent.baselineKey, "agent:claude-code@ANTHROPIC1")
        agent.teamID = nil
        XCTAssertEqual(agent.baselineKey, "agent:claude-code", "an npm install has no team to pin")
    }

    /// A baseline approval alone does not quiet an AI agent's critical access; its answer rule does.
    func testABaselineApprovalAloneDoesNotQuietAnAgentsCriticalAccess() throws {
        let h = try Harness(learningDays: 0)
        let shell = h.fork(P.launchd, P.zsh(500, parent: 1))
        let agent = h.spawn(shell, P.node(600, parent: 500, argv: ["node", "/opt/homebrew/bin/claude"]))
        let first = h.open(agent, key, 1)
        XCTAssertEqual(first.events.first?.ancestryKnown, true)
        XCTAssertEqual(first.alerts.first?.alert.kind, .criticalNonOwner)
        let r = try XCTUnwrap(first.events.first?.responsible)
        XCTAssertEqual(r.key, "agent:claude-code")
        h.baseline.approve(responsibleKey: r.baselineKey, categoryID: "test-vault", access: .read, at: at(1))
        XCTAssertEqual(h.open(agent, key, 1000).alerts.first?.alert.kind, .criticalNonOwner, "approved, but no answer rule")
        h.rules.replace(rules: [Rule(target: .category("test-vault"), subject: .responsible(key: r.key, teamID: r.teamID), access: .read,
                                     action: .allow, template: RuleTemplates.askAnswer, chainAgents: ["claude-code"])])
        XCTAssertTrue(h.open(agent, key, 2000).alerts.isEmpty, "the answer rule")
    }
}
