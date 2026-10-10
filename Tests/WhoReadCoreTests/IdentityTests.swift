import XCTest
@testable import WhoReadCore

// Process identity: an AI agent that execs keeps its identity, parents are linked by the exact parent
// execution the source reports, code identity is trusted only for the kernel's signing categories,
// and unknown ancestry is never taken for "no AI agent".

private let sshKey = "/Users/alice/.ssh/id_ed25519"
private let claudeNodeArgv = ["node", "/opt/homebrew/bin/claude"]
private let claudeTeam = "Q6L2SF6YDW"

private func enforcedRule(_ rule: Rule) -> Rule {
    var r = rule
    r.enabled = true
    r.enforce = true
    return r
}

// MARK: - agent-exec: an AI agent process that execs keeps the agent

final class AgentExecTests: AncestryTestCase {
    /// Terminal → zsh → Claude Code (node, 600), which then execs /bin/cat itself. The process is still
    /// Claude Code's: the chain must not turn into an all-Apple `Terminal → zsh → cat`.
    func testAnAgentThatExecsKeepsItsAgentIdentity() {
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let claude = h.spawn(zsh, P.node(600, parent: 500, argv: claudeNodeArgv), 1)
        var cat = P.cat(600, parent: 500)
        cat.startTime = claude.startTime
        cat.pidVersion = claude.pidVersion.map { $0 + 1 }
        h.exec(claude, cat, 2)

        let chain = h.tree.chain(for: cat, at: at(3))
        XCTAssertEqual(names(chain), ["cat", "zsh", "Terminal", "launchd"])
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertFalse(AskPolicy.isTrustableAppleProgram(cat, chain: chain))
        XCTAssertEqual(h.attributor.attribute(chain: chain).key, "agent:claude-code")
        XCTAssertEqual(decide(cat, 3).verdict, .deny, "the agent rule still applies")
        // What it starts after the exec is the agent's too.
        let child = h.spawn(cat, P.cat(601, parent: 600), 4)
        XCTAssertEqual(h.tree.chain(for: child, at: at(5)).nearestAgent, "claude-code")
    }

    /// agent-exec variant: the exec event was lost (a kernel drop) and the next event shows the new
    /// image of the same process instance. The adopted image must not shed the agent either.
    func testAnAgentWhoseExecWasMissedKeepsItsAgentIdentity() {
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let claude = h.spawn(zsh, P.node(600, parent: 500, argv: claudeNodeArgv), 1)
        var cat = P.cat(600, parent: 500)
        cat.startTime = claude.startTime
        cat.pidVersion = claude.pidVersion.map { $0 + 1 }
        let chain = h.tree.chain(for: cat, at: at(3))
        XCTAssertEqual(chain.first?.image.executablePath, "/bin/cat")
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertEqual(decide(cat, 3).verdict, .deny)
    }

    /// agent-exec variant: the agent's team stays with the process. A team-pinned "block from now on"
    /// rule for the agent (responsible key + team) must still match after it execs a program of
    /// another (or no) team.
    func testAnAgentThatExecsKeepsItsTeamForTeamPinnedRules() {
        let block = Rule(id: "block-claude", enabled: true, enforce: true, target: .category("ssh"),
                         subject: .responsible(key: "agent:claude-code", teamID: claudeTeam, exceptOwners: true),
                         access: .any, action: .deny)
        h.rules.replace(rules: [block])
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let claude = h.spawn(zsh, proc(600, "/Users/alice/.local/share/claude/versions/2.0.1", ppid: 500, start: 1,
                                       signingID: "com.anthropic.claude-code", teamID: claudeTeam, argv: ["claude"]), 1)
        XCTAssertEqual(decide(claude, 2).verdict, .deny)
        var cat = P.cat(600, parent: 500)
        cat.startTime = claude.startTime
        cat.pidVersion = claude.pidVersion.map { $0 + 1 }
        h.exec(claude, cat, 2)
        let chain = h.tree.chain(for: cat, at: at(3))
        let responsible = h.attributor.attribute(chain: chain)
        XCTAssertEqual(responsible.key, "agent:claude-code")
        XCTAssertEqual(responsible.teamID, claudeTeam)
        XCTAssertEqual(decide(cat, 3).verdict, .deny)
        XCTAssertEqual(decide(cat, 3).ruleID, "block-claude")
    }

    /// Guard: the agent forking a shell for a command. The fork-time copy is recognised as the agent
    /// (same executable); once it execs zsh it is a shell the agent started, not the agent: the agent
    /// stays its parent, and the displayed chain still shows the shell.
    func testAForkedCopyOfTheAgentThatExecsAShellIsNotTheAgentItself() {
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let claude = h.spawn(zsh, proc(600, "/Users/alice/.local/share/claude/versions/2.0.1", ppid: 500, start: 1,
                                       teamID: claudeTeam), 1)
        let copy = proc(601, claude.executablePath, ppid: 600, start: 2, teamID: claudeTeam)
        h.tree.fork(parent: claude, child: copy, at: at(2))
        XCTAssertEqual(h.tree.node(pid: 601)?.agentID, "claude-code", "a fork-time copy runs the agent's code")
        let shell = h.exec(copy, proc(601, "/bin/zsh", ppid: 600, start: 2, platform: true, signingID: "com.apple.zsh"), 2)
        XCTAssertNil(h.tree.node(pid: 601)?.agentID)
        let cat = h.spawn(shell, P.cat(602, parent: 601), 3)
        let chain = h.tree.chain(for: cat, at: at(4))
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        let responsible = h.attributor.attribute(chain: chain)
        XCTAssertEqual(h.attributor.displayChain(chain, responsible: responsible).map(\.image.name),
                       ["2.0.1", "zsh", "cat"])
    }

    /// Guard: an agent that execs another agent takes the new one (Claude Code starting Codex in place).
    func testAnAgentThatExecsAnotherAgentBecomesThatAgent() {
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let claude = h.spawn(zsh, P.node(600, parent: 500, argv: claudeNodeArgv), 1)
        var codex = P.node(600, parent: 500, argv: ["node", "/opt/homebrew/bin/codex"])
        codex.startTime = claude.startTime
        codex.pidVersion = claude.pidVersion.map { $0 + 1 }
        h.exec(claude, codex, 2)
        XCTAssertEqual(h.tree.chain(for: codex, at: at(3)).nearestAgent, "codex")
    }
}
