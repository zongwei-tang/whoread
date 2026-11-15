import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// attribution-2: an AI agent is recognised by signals any process can copy (argv0, an executable or
/// .app folder name). What the baseline knows of a team-signed agent, and what was approved for it,
/// must not carry over to a process that only looks like it; and for critical files an agent's
/// access is quiet only through its "always allow" answer rule (team and chain scoped), as in ask
/// mode. Monitor-only mode, as on the user's Mac. Accesses are 20 minutes apart: alerts of the same
/// key would otherwise merge into one coalescing window.
final class R5DaemonAgentIdentityTests: XCTestCase {
    /// zsh started by launchd.
    private func shell(_ core: DaemonCore, _ pid: Int32) -> ProcessRecord {
        var p = proc(pid, "/bin/zsh", ppid: 1, platform: true)
        p.signingID = "com.apple.zsh"
        return r5dObserve(core, p)
    }

    /// Claude Code's native install, signed by its developer team.
    private func claude(_ core: DaemonCore, _ pid: Int32, parent: Int32) -> ProcessRecord {
        var p = proc(pid, "/Users/alice/.local/share/claude/versions/2.0.1", ppid: parent, argv: ["claude"])
        p.signingID = "com.anthropic.claude-code"
        p.teamID = "ANTHROPIC1"
        return r5dObserve(core, p)
    }

    private func cat(_ core: DaemonCore, _ pid: Int32, parent: Int32, argv0: String = "cat") -> ProcessRecord {
        var p = proc(pid, "/bin/cat", ppid: parent, platform: true, argv: [argv0, r5dVaultKey])
        p.signingID = "com.apple.cat"
        return r5dObserve(core, p)
    }

    func testAnAgentsApprovalDoesNotCarryOverToAProcessNamedLikeIt() throws {
        let dir = TempDir()
        let core = try r5dCore(dir)
        _ = shell(core, 500)
        let agent = claude(core, 600, parent: 500)
        let t = Date()
        r5dReceive(core, r5dOpen(agent, r5dVaultKey, at: t))
        let first = try XCTUnwrap(try r5dAlerts(core).first)
        XCTAssertEqual(first.kind, .criticalNonOwner)
        XCTAssertEqual(first.responsible.key, "agent:claude-code")
        XCTAssertEqual(first.responsible.teamID, "ANTHROPIC1")
        XCTAssertEqual(first.ancestryKnown, true)
        try core.apply(action: .alwaysAllow, toAlert: first.id, peer: .inProcess)

        // The agent itself: quiet.
        r5dReceive(core, r5dOpen(agent, r5dVaultKey, at: t.addingTimeInterval(1200)))
        let quiet = try r5dAlerts(core)
        XCTAssertEqual(quiet.count, 1, r5dDescribe(quiet))

        // `exec -a claude /bin/cat <key>` from launchd: recognised as Claude Code by its argv0 alone.
        let forger = cat(core, 700, parent: 1, argv0: "claude")
        r5dReceive(core, r5dOpen(forger, r5dVaultKey, at: t.addingTimeInterval(2400)))
        let alerts = try r5dAlerts(core)
        XCTAssertEqual(alerts.count, 2, r5dDescribe(alerts))
        XCTAssertEqual(alerts.last?.kind, .criticalNonOwner)
        XCTAssertEqual(alerts.last?.responsible.key, "agent:claude-code")
        XCTAssertNil(alerts.last?.responsible.teamID)
    }

    /// Codex → Claude Code → cat: the answer for Claude Code does not cover it driven by Codex (the ask
    /// mode rule's chainAgents), and monitor-only mode says so too.
    func testAnAgentsApprovalDoesNotCoverItDrivenByAnotherAgent() throws {
        let dir = TempDir()
        let core = try r5dCore(dir)
        _ = shell(core, 500)
        _ = claude(core, 600, parent: 500)
        let t = Date()
        r5dReceive(core, r5dOpen(cat(core, 601, parent: 600), r5dVaultKey, at: t))
        let first = try XCTUnwrap(try r5dAlerts(core).first)
        XCTAssertEqual(first.kind, .criticalNonOwner)
        XCTAssertEqual(first.chainAgents, ["claude-code"])
        try core.apply(action: .alwaysAllow, toAlert: first.id, peer: .inProcess)
        r5dReceive(core, r5dOpen(cat(core, 602, parent: 600), r5dVaultKey, at: t.addingTimeInterval(1200)))
        let quiet = try r5dAlerts(core)
        XCTAssertEqual(quiet.count, 1, "Claude Code alone stays allowed: \(r5dDescribe(quiet))")

        _ = shell(core, 510)
        var codex = proc(610, "/opt/homebrew/bin/codex", ppid: 510, argv: ["codex"])
        codex.signingID = "codex"
        codex.teamID = "OPENAI0001"
        r5dObserve(core, codex)
        _ = claude(core, 620, parent: 610)
        r5dReceive(core, r5dOpen(cat(core, 621, parent: 620), r5dVaultKey, at: t.addingTimeInterval(2400)))
        let alerts = try r5dAlerts(core)
        XCTAssertEqual(alerts.count, 2, r5dDescribe(alerts))
        XCTAssertEqual(alerts.last?.kind, .criticalNonOwner)
        XCTAssertEqual(alerts.last?.responsible.key, "agent:claude-code")
        XCTAssertEqual(alerts.last?.chainAgents, ["claude-code", "codex"])
    }

    /// What was seen of the team-signed agent is not what was seen of a process named like it: its
    /// first access to the category still alerts.
    func testAFirstAccessIsNotSwallowedByAnAgentsName() throws {
        let dir = TempDir()
        let core = try r5dCore(dir)
        _ = shell(core, 500)
        let agent = claude(core, 600, parent: 500)
        let t = Date()
        r5dReceive(core, r5dOpen(agent, r5dVaultNote, at: t))
        XCTAssertEqual(try r5dAlerts(core).map(\.kind), [.firstAccess])
        r5dReceive(core, r5dOpen(agent, r5dVaultNote, at: t.addingTimeInterval(1200)))
        XCTAssertEqual(try r5dAlerts(core).count, 1, "known by now")

        var forger = proc(700, "/bin/cat", ppid: 1, platform: true, argv: ["claude", r5dVaultNote])
        forger.signingID = "com.apple.cat"
        r5dObserve(core, forger)
        r5dReceive(core, r5dOpen(forger, r5dVaultNote, at: t.addingTimeInterval(86400)))
        let alerts = try r5dAlerts(core)
        XCTAssertEqual(alerts.map(\.kind), [.firstAccess, .firstAccess], r5dDescribe(alerts))
        XCTAssertNil(alerts.last?.responsible.teamID)
    }
}
