import XCTest
@testable import WhoReadCore

// Process identity: an AI agent that execs keeps its identity, parents are linked by the exact parent
// execution the source reports, code identity is trusted only for the kernel's signing categories,
// and unknown ancestry is never taken for "no AI agent".

private let sshKey = "/Users/alice/.ssh/id_ed25519"
private let claudeNodeArgv = ["node", "/opt/homebrew/bin/claude"]
private let claudeTeam = "Q6L2SF6YDW"

/// Counts calls from @Sendable closures.
private final class Calls: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func increment() { lock.lock(); n += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return n }
}

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

// MARK: - sdk-D3: parents linked by the exact parent execution (parent_audit_token)

final class ParentTokenTests: AncestryTestCase {
    func token(_ pid: Int32, _ version: UInt32?) -> ProcessToken { ProcessToken(pid: pid, pidVersion: version ?? 0) }

    /// The user's zsh (pid 700, under Terminal) exited, but its exit has not been processed yet. Claude
    /// Code's shell got pid 700 next (its fork is not processed yet either) and starts cat, whose file
    /// event arrives first. Start times cannot tell the stale zsh from the parent; the pidversion the
    /// child's event names can: libproc then gives the process that holds pid 700 now.
    func testAStaleInstanceOfTheParentPidIsNotTakenForTheParentTheTokenNames() {
        let userShell = h.spawn(h.spawn(P.terminal, P.zsh(500, parent: 100)), proc(700, "/bin/zsh", ppid: 500, start: 0, platform: true,
                                                                                  signingID: "com.apple.zsh"), 0)
        let claude = h.spawn(h.spawn(P.terminal, P.zsh(510, parent: 100)), P.node(600, parent: 510, argv: claudeNodeArgv), 1)
        _ = claude
        let agentShell = ProcessRecord(pid: 700, ppid: 600, executablePath: "/bin/sh", isPlatformBinary: true, argv: ["sh", "-c", "cat"],
                                       startTime: at(5))
        h.tree.parentResolver = { $0 == 700 ? agentShell : nil }
        var cat = proc(701, "/bin/cat", ppid: 700, start: 6, platform: true, signingID: "com.apple.cat", argv: ["cat"])
        cat.parentToken = token(700, 7_777)
        XCTAssertNotEqual(userShell.pidVersion, 7_777)

        let chain = h.tree.chain(for: cat, at: at(7))
        XCTAssertEqual(names(chain), ["cat", "sh", "node", "zsh", "Terminal", "launchd"])
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertEqual(decide(cat, 7).verdict, .deny)
    }

    /// Guard: the parent's pidversion is known to the tree: linked to that very execution without asking
    /// libproc.
    func testTheExecutionTheTokenNamesIsLinkedWithoutLibproc() {
        let shell = h.spawn(h.spawn(P.terminal, P.zsh(500, parent: 100)), proc(700, "/bin/zsh", ppid: 500, start: 0, platform: true), 0)
        let asked = Calls()
        h.tree.parentResolver = { _ in asked.increment(); return nil }
        var cat = proc(701, "/bin/cat", ppid: 700, start: 6, platform: true, signingID: "com.apple.cat")
        cat.parentToken = token(700, shell.pidVersion)
        XCTAssertEqual(names(h.tree.chain(for: cat, at: at(7))), ["cat", "zsh", "zsh", "Terminal", "launchd"])
        XCTAssertEqual(asked.value, 0)
    }

    /// The parent exec'd Claude Code (a pidversion the tree has not seen: its exec is not processed yet).
    /// libproc says it is the same process: linked to it with its new image, so the agent is in the chain.
    func testAParentThatExecdSinceIsStillTheParent() {
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let wrapper = h.spawn(zsh, proc(600, "/bin/sh", ppid: 500, start: 1, platform: true, argv: ["sh", "/opt/homebrew/bin/claude"]), 1)
        let execd = ProcessRecord(pid: 600, ppid: 500, executablePath: P.node(600, parent: 500, argv: []).executablePath,
                                  argv: claudeNodeArgv, startTime: wrapper.startTime)
        h.tree.parentResolver = { $0 == 600 ? execd : nil }
        var cat = proc(601, "/bin/cat", ppid: 600, start: 2, platform: true, signingID: "com.apple.cat")
        cat.parentToken = token(600, 9_999)
        let chain = h.tree.chain(for: cat, at: at(3))
        XCTAssertEqual(names(chain), ["cat", "node", "zsh", "Terminal", "launchd"])
        XCTAssertEqual(chain.nearestAgent, "claude-code")
    }

    /// Guard: libproc cannot say (the parent is gone): the candidate stands, as without a token.
    func testAnUnsettledCandidateStillStands() {
        let shell = h.spawn(h.spawn(P.terminal, P.zsh(500, parent: 100)), proc(700, "/bin/zsh", ppid: 500, start: 0, platform: true), 0)
        _ = shell
        h.tree.parentResolver = { _ in nil }
        var cat = proc(701, "/bin/cat", ppid: 700, start: 6, platform: true, signingID: "com.apple.cat")
        cat.parentToken = token(700, 1)
        XCTAssertEqual(names(h.tree.chain(for: cat, at: at(7))), ["cat", "zsh", "zsh", "Terminal", "launchd"])
    }

    /// Guard (process-1): a reparented child's token names launchd, its adopter, not who forked it: the
    /// fork-time parent is unknown and stays unknown.
    func testAReparentedChildsTokenNamingLaunchdIsNotItsParent() {
        h.tree.parentResolver = { _ in nil }
        _ = agentShell()
        var cat = proc(701, "/bin/cat", ppid: 1, start: 3, platform: true, signingID: "com.apple.cat", originalPPID: 700)
        cat.parentToken = token(1, 1)
        XCTAssertEqual(names(h.tree.chain(for: cat, at: at(4))), ["cat"])
    }

    /// Guard (process-1 traced variant): a traced child's token names its debugger: it stays linked to
    /// its fork-time parent under the agent.
    func testATracedChildsTokenNamingTheDebuggerIsNotItsParent() {
        _ = agentShell()
        let debugger = h.spawn(h.spawn(P.terminal, P.zsh(530, parent: 100)), proc(950, "/usr/bin/lldb", ppid: 530, start: 2, platform: true), 2)
        var cat = proc(706, "/bin/cat", ppid: 950, start: 3, platform: true, signingID: "com.apple.cat", originalPPID: 601)
        cat.parentToken = token(950, debugger.pidVersion)
        let chain = h.tree.chain(for: cat, at: at(4))
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertFalse(names(chain).contains("lldb"))
    }
}

// MARK: - sdk-D3/D4: what the eslogger parser reads from a process

final class EsloggerIdentityFieldTests: XCTestCase {
    func process(version: Int, extra: String) -> ProcessRecord? {
        let line = #"{"schema_version":1,"version":\#(version),"time":"2025-10-09T08:53:20.000000000Z","process":{"audit_token":{"pid":501,"pidversion":5010},"ppid":500,"original_ppid":500,"executable":{"path":"/bin/cat"},"is_platform_binary":true,"codesigning_flags":570522385\#(extra)},"event":{"exit":{"stat":0}}}"#
        if case .event(.exit(let p, _)) = EsloggerParser().parse(line: line) { return p }
        return nil
    }

    let tokens = #","parent_audit_token":{"pid":500,"pidversion":5000},"responsible_audit_token":{"pid":501,"pidversion":5010},"cs_validation_category":1"#

    func testTokensSigningCategoryAndFlagsAreRead() throws {
        let p = try XCTUnwrap(process(version: 10, extra: tokens))
        XCTAssertEqual(p.parentToken, ProcessToken(pid: 500, pidVersion: 5_000))
        XCTAssertNil(p.responsiblePID, "the process itself: no responsible process")
        XCTAssertEqual(p.signingCategory, .platform)
        XCTAssertEqual(p.codeSigningFlags, 570_522_385)
        XCTAssertTrue(p.isVerifiedPlatformBinary)

        let other = try XCTUnwrap(process(version: 10, extra: #","responsible_audit_token":{"pid":400,"pidversion":4000}"#))
        XCTAssertEqual(other.responsiblePID, 400)
    }

    /// Fields a message version does not have are not taken from it.
    func testFieldsAreGatedByTheMessageVersion() throws {
        let v9 = try XCTUnwrap(process(version: 9, extra: tokens))
        XCTAssertNil(v9.signingCategory)
        XCTAssertNotNil(v9.parentToken)
        let v3 = try XCTUnwrap(process(version: 3, extra: tokens))
        XCTAssertNil(v3.parentToken)
        XCTAssertNil(v3.signingCategory)
        XCTAssertEqual(v3.codeSigningFlags, 570_522_385)
    }

    /// The msgv10 fixture: the platform cat is category PLATFORM; its parent is named by pid.
    func testTheFixtureCarriesTheFields() throws {
        let url = fixtureURL("eslogger/schema-v1-msgv10/scenario.jsonl")
        let parser = EsloggerParser()
        var cat: ProcessRecord?
        for line in try String(contentsOf: url, encoding: .utf8).split(separator: "\n") {
            if case .event(.exec(_, let target, _)) = parser.parse(line: String(line)), target.pid == 501 { cat = target }
        }
        let target = try XCTUnwrap(cat)
        XCTAssertEqual(target.signingCategory, .platform)
        XCTAssertEqual(target.parentToken?.pid, 500)
        XCTAssertNotNil(target.codeSigningFlags)
    }
}
