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

    /// The traced variant with a reused pid: the agent's shell (700) forked cat and exited; lldb, started
    /// from the user's Terminal, got pid 700 next and attached to cat. cat's ppid and token now name
    /// lldb, whose pid is cat's fork-time parent's. A process that started after cat did not fork it:
    /// cat stays below the shell that did, with the agent above it.
    func testATokenNamingALaterHolderOfTheParentPidIsNotTheParent() {
        let sh = h.spawn(agentShell(), proc(700, "/bin/sh", ppid: 601, start: 3, platform: true, signingID: "com.apple.sh"), 3)
        h.tree.exit(sh, at: at(5))
        var lldb = proc(700, "/usr/bin/lldb", ppid: 530, start: 6, platform: true, signingID: "com.apple.lldb")
        lldb.pidVersion = 7_100
        lldb = h.spawn(h.spawn(P.terminal, P.zsh(530, parent: 100)), lldb, 6)
        var cat = proc(701, "/bin/cat", ppid: 700, start: 4, platform: true, signingID: "com.apple.cat", originalPPID: 700)
        cat.parentToken = token(700, lldb.pidVersion)

        let chain = h.tree.chain(for: cat, at: at(7))
        XCTAssertEqual(names(chain), ["cat", "sh", "zsh", "node", "zsh", "Terminal", "launchd"])
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertEqual(decide(cat, 7).verdict, .deny)
    }

    /// Once the newest candidate for the parent pid is unconfirmed (the token names a pidversion it was
    /// not seen with: the agent's shell exec'd again, not processed yet), an older candidate is not taken
    /// instead. Here that is the user's zsh from the snapshot, which held pid 700 before and whose exit
    /// was lost. libproc cannot say: the newest candidate stands, as it would without a token.
    func testAnOlderCandidateIsNotTakenBeforeAnUnconfirmedNewerOne() {
        h.tree.parentResolver = { _ in nil }
        h.tree.seed([ProcessRecord(pid: 700, ppid: 500, executablePath: "/bin/zsh", isPlatformBinary: true, startTime: at(0))], at: at(0))
        let sh = h.spawn(agentShell(), proc(700, "/bin/sh", ppid: 601, start: 3, platform: true, signingID: "com.apple.sh"), 3)
        var cat = proc(701, "/bin/cat", ppid: 700, start: 4, platform: true, signingID: "com.apple.cat")
        cat.parentToken = token(700, sh.pidVersion.map { $0 + 1 })

        let chain = h.tree.chain(for: cat, at: at(5))
        XCTAssertEqual(names(chain), ["cat", "sh", "zsh", "node", "zsh", "Terminal", "launchd"])
        XCTAssertEqual(chain.nearestAgent, "claude-code")
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

// MARK: - sdk-D4 / macos-2: code identity is trusted only for the kernel's signing categories

final class SigningCategoryTrustTests: AncestryTestCase {
    private let kubeConfig = "/Users/alice/.kube/config"
    private let dockerTeam = "9BNSXJN65R"
    private let noTrust = AskPolicy(enabled: true, trustApplePrograms: false, benignChain: false)

    func signed(_ p: ProcessRecord, _ category: SigningCategory?, flags: UInt32? = nil) -> ProcessRecord {
        var p = p
        p.signingCategory = category
        p.codeSigningFlags = flags
        return p
    }

    /// The catalog with Docker Desktop's team resolved (what `resolve-owners` does on a Mac).
    func dockerOwnedClassifier() -> PathClassifier {
        var catalog = h.data.catalog
        let i = catalog.categories.firstIndex { $0.id == "kube" }!
        catalog.categories[i].owners = [IdentitySpec(label: "Docker Desktop", bundles: ["/Applications/Docker.app"], teamIDs: [dockerTeam])]
        return PathClassifier(catalog: catalog, normalizer: h.normalizer)
    }

    func docker(_ category: SigningCategory?, flags: UInt32? = nil) -> ProcessRecord {
        signed(proc(900, "/Applications/Docker.app/Contents/MacOS/com.docker.backend", ppid: 1, start: 0, signingID: "com.docker.docker",
                    teamID: dockerTeam, originalPPID: 1), category, flags: flags)
    }

    /// A team-pinned third-party owner counts only when the kernel validated it as Developer ID or App
    /// Store code that no other process controls. A development (Xcode debug) build of the same app has
    /// the same team ID; so has an ad-hoc re-signed copy under local signing.
    func testATeamPinnedOwnerNeedsADistributionSignature() {
        let c = dockerOwnedClassifier()
        XCTAssertTrue(c.isOwner(docker(nil), of: "kube"), "no category reported (older macOS): as before")
        XCTAssertTrue(c.isOwner(docker(.developerID), of: "kube"))
        XCTAssertTrue(c.isOwner(docker(.appStore), of: "kube"))
        for category in [SigningCategory.development, .localSigning, .noPolicy, .invalid, .testFlight, .enterprise, .rosetta,
                         SigningCategory(rawValue: 42)] {
            XCTAssertFalse(c.isOwner(docker(category), of: "kube"), "category \(category.rawValue)")
        }
        XCTAssertFalse(c.isOwner(docker(.developerID, flags: CodeSigningFlag.getTaskAllow), of: "kube"), "get-task-allow")
        XCTAssertFalse(c.isOwner(docker(.developerID, flags: CodeSigningFlag.debugged), of: "kube"), "debugged")
        XCTAssertTrue(c.isOwner(docker(.developerID, flags: 0x2201_3b11), of: "kube"), "ordinary flags")
    }

    /// A location-only owner (Homebrew's OpenSSH) is ad hoc signed like anything else written there, so
    /// the signing category says nothing about it. But a process that another one controls (attached by
    /// a debugger, or built with get-task-allow) is nobody's owner, whatever its location.
    func testALocationOnlyOwnerIsNotAnOwnerWhileAnotherProcessControlsIt() {
        func ssh(_ category: SigningCategory?, flags: UInt32?) -> ProcessRecord {
            signed(proc(920, "/opt/homebrew/Cellar/openssh/9.9p1/bin/ssh", ppid: 1, start: 0, originalPPID: 1), category, flags: flags)
        }
        XCTAssertTrue(h.classifier.isOwner(ssh(nil, flags: nil), of: "ssh"))
        XCTAssertTrue(h.classifier.isOwner(ssh(.localSigning, flags: 0x2_0002), of: "ssh"), "ad hoc, linker-signed: as before")
        XCTAssertFalse(h.classifier.isOwner(ssh(.localSigning, flags: 0x2_0002 | CodeSigningFlag.debugged), of: "ssh"))
        XCTAssertFalse(h.classifier.isOwner(ssh(nil, flags: CodeSigningFlag.getTaskAllow), of: "ssh"))
    }

    /// The same on the AUTH path: a development build reading the category is asked, not passed as owner.
    func testADevelopmentBuildOfAnOwnerIsAskedNotPassed() {
        let engine = RuleEngine(rules: [], classifier: dockerOwnedClassifier(), attributor: h.attributor)
        func decide(_ p: ProcessRecord) -> RuleDecision {
            let chain = h.tree.chain(for: p, at: at(1))
            let c = h.classifier.classify(kubeConfig)!
            return engine.evaluate(process: chain.first?.image ?? p, chain: chain,
                                   targets: [EvaluationTarget(path: kubeConfig, access: .read,
                                                             categories: [TargetCategory(id: c.categoryID, severity: c.severity)])],
                                   enforcementActive: true, now: at(1), ask: noTrust)
        }
        XCTAssertEqual(decide(docker(.developerID)).reason, .owner)
        var dev = docker(.development)
        dev.pid = 901
        XCTAssertEqual(decide(dev).verdict, .ask)
    }

    /// Apple trust ("trust Apple programs") and platform owners: the platform flag counts only when the
    /// kernel's category is PLATFORM (where reported) and no other process controls the program.
    func testApplePlatformTrustNeedsThePlatformCategory() {
        let shell = h.spawn(P.terminal, P.zsh(500, parent: 100))
        func cat(_ pid: Int32, _ category: SigningCategory?, flags: UInt32? = nil) -> ProcessRecord {
            h.spawn(shell, signed(P.cat(pid, parent: 500), category, flags: flags), 1)
        }
        XCTAssertEqual(decide(cat(601, nil), 2).reason, .trustedApple)
        XCTAssertEqual(decide(cat(602, .platform), 2).reason, .trustedApple)
        XCTAssertEqual(decide(cat(603, .rosetta), 2).verdict, .ask)
        XCTAssertEqual(decide(cat(604, .platform, flags: CodeSigningFlag.debugged), 2).verdict, .ask)

        func ssh(_ pid: Int32, _ category: SigningCategory?, flags: UInt32? = nil) -> ProcessRecord {
            signed(proc(pid, "/usr/bin/ssh", ppid: 500, start: 1, platform: true, signingID: "com.apple.openssh"), category, flags: flags)
        }
        XCTAssertTrue(h.classifier.isOwner(ssh(610, .platform), of: "ssh"))
        XCTAssertFalse(h.classifier.isOwner(ssh(611, .noPolicy), of: "ssh"))
        XCTAssertFalse(h.classifier.isOwner(ssh(612, .platform, flags: CodeSigningFlag.getTaskAllow), of: "ssh"))
        XCTAssertEqual(decide(h.spawn(shell, ssh(613, .platform), 1), 2, ask: noTrust).reason, .owner)
        XCTAssertEqual(decide(h.spawn(shell, ssh(614, .development), 1), 2, ask: noTrust).verdict, .ask)
    }

    /// The same gate for benign services, the never-block list and the platform exemption of
    /// "any non-owner" deny rules.
    func testBenignNeverBlockAndPlatformExemptionNeedThePlatformCategory() {
        let worker = "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared"
        let benign = BenignClassifier(catalog: h.data.benign)
        for (pid, category, expected) in [(705, nil, "spotlight"), (706, SigningCategory.platform, "spotlight"),
                                          (707, SigningCategory.noPolicy, nil)] as [(Int32, SigningCategory?, String?)] {
            let p = signed(proc(pid, worker, ppid: 1, start: 3, platform: true, originalPPID: 1), category)
            XCTAssertEqual(benign.classify(chain: h.tree.chain(for: p, at: at(4))), expected, "category \(String(describing: category))")
        }

        let tccd = proc(80, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", ppid: 1, platform: true)
        XCTAssertTrue(NeverBlockList().contains(signed(tccd, .platform)))
        XCTAssertTrue(NeverBlockList().contains(tccd))
        XCTAssertFalse(NeverBlockList().contains(signed(tccd, .development)))

        h.rules.replace(rules: [enforcedRule(RuleTemplates.denyNonOwnersSSH())])
        let shell = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let off = AskPolicy.off
        XCTAssertEqual(decide(h.spawn(shell, P.cat(620, parent: 500), 1), 2, ask: off).verdict, .allow,
                       "platform binaries are exempt unless the rule opts in")
        XCTAssertEqual(decide(h.spawn(shell, signed(P.cat(621, parent: 500), .platform, flags: CodeSigningFlag.debugged), 1), 2,
                              ask: off).verdict, .deny, "not while another process controls it")
    }
}

// MARK: - Unknown ancestry is not "no AI agent" in alerts (process-1 follow-up)

final class UnknownAncestryAlertTests: AncestryTestCase {
    override func setUpWithError() throws {
        try super.setUpWithError()
        h.tree.parentResolver = { _ in nil }
        h.coalescer.window = 0.5  // one alert per access, so each one shows its own kind
    }

    func ssh(_ pid: Int32, originalPPID: Int32, _ t: TimeInterval) -> ProcessRecord {
        proc(pid, "/usr/bin/ssh", ppid: 1, start: t, platform: true, signingID: "com.apple.openssh", originalPPID: originalPPID)
    }

    /// An owner (ssh reading a key) is quiet only with no AI agent in its chain. ssh whose fork-time
    /// parent was never seen (an agent's shell that exited) has an unknown chain, which may hide one:
    /// it alerts, in monitor-only mode and for NOTIFY events after an AUTH allow alike.
    func testAnOwnerWithUnknownAncestryIsNotSilenced() throws {
        _ = agentShell()
        let monitor = h.open(ssh(702, originalPPID: 700, 3), sshKey, 4)
        XCTAssertTrue(monitor.events[0].isOwner)
        XCTAssertEqual(monitor.events[0].ancestryKnown, false)
        XCTAssertEqual(monitor.alerts.first?.alert.kind, .criticalNonOwner)

        let afterAuth = h.open(ssh(703, originalPPID: 700, 5), sshKey, 6, context: .afterAuth)
        XCTAssertEqual(afterAuth.alerts.first?.alert.kind, .criticalNonOwner)

        // The user's own ssh under Terminal (a known chain) stays quiet.
        let own = h.spawn(h.spawn(P.terminal, P.zsh(520, parent: 100)),
                          proc(704, "/usr/bin/ssh", ppid: 520, start: 7, platform: true, signingID: "com.apple.openssh"), 7)
        let quiet = h.open(own, sshKey, 8)
        XCTAssertEqual(quiet.events[0].ancestryKnown, true)
        XCTAssertTrue(quiet.alerts.isEmpty)
    }

    /// With the ancestry lost, the chain stops at the leaf and the access is charged to the leaf itself.
    /// An approval of `cat` (given for a cat launchd started) does not cover a cat whose starter is
    /// unknown: a critical read still alerts, as one an AI agent drives does.
    func testAnApprovalDoesNotCoverUnknownAncestryForCriticalFiles() throws {
        func cat(_ pid: Int32, originalPPID: Int32, _ t: TimeInterval) -> ProcessRecord {
            proc(pid, "/bin/cat", ppid: 1, start: t, platform: true, signingID: "com.apple.cat", originalPPID: originalPPID)
        }
        let first = h.open(cat(710, originalPPID: 1, 1), sshKey, 2)
        let key = first.events[0].responsible.key
        h.baseline.approve(responsibleKey: key, categoryID: first.events[0].categoryID, at: at(2))
        XCTAssertTrue(h.open(cat(711, originalPPID: 1, 3), sshKey, 4).alerts.isEmpty, "approved")

        let orphan = h.open(cat(712, originalPPID: 700, 5), sshKey, 6)
        XCTAssertEqual(orphan.events[0].responsible.key, key)
        XCTAssertEqual(orphan.alerts.first?.alert.kind, .criticalNonOwner)
    }
}

// MARK: - Answers scoped by ancestry: "no AI agent" is not "ancestry unknown"

final class AncestryScopedAnswerTests: AncestryTestCase {
    private let catKey = "bin:apple:com.apple.cat"

    override func setUpWithError() throws {
        try super.setUpWithError()
        h.tree.parentResolver = { _ in nil }
    }

    func cat(_ pid: Int32, originalPPID: Int32) -> ProcessRecord {
        proc(pid, "/bin/cat", ppid: 1, start: 1, platform: true, signingID: "com.apple.cat", originalPPID: originalPPID)
    }

    func answer(covering unknown: Bool) -> Rule {
        Rule(id: "answer", enabled: true, target: .category("ssh"), subject: .responsible(key: catKey, teamID: nil), access: .read,
             action: .allow, template: RuleTemplates.askAnswer, chainAgents: [], coversUnknownAncestry: unknown)
    }

    /// cat started by launchd (a known chain) and cat whose starter is unknown (an AI agent's shell that
    /// is gone) are both charged to cat. An answer given for the known one does not answer for the other,
    /// and the question about it says its ancestry is unknown.
    func testAnAnswerForAKnownChainDoesNotCoverUnknownAncestry() {
        let noTrust = AskPolicy(enabled: true, trustApplePrograms: false, benignChain: false)
        let known = cat(701, originalPPID: 1), unknown = cat(702, originalPPID: 700)
        XCTAssertEqual(decide(known, 2, ask: noTrust).askKey?.ancestryKnown, true)
        let asked = decide(unknown, 2, ask: noTrust)
        XCTAssertEqual(asked.askKey?.responsibleKey, catKey)
        XCTAssertEqual(asked.askKey?.ancestryKnown, false)

        h.rules.replace(rules: [answer(covering: false)])
        XCTAssertEqual(decide(known, 3, ask: noTrust).reason, .explicitAllow)
        XCTAssertEqual(decide(unknown, 3, ask: noTrust).verdict, .ask)
        // Answered for the unknown chain, knowing it: it covers both.
        h.rules.replace(rules: [answer(covering: true)])
        XCTAssertEqual(decide(unknown, 4, ask: noTrust).reason, .explicitAllow)
        XCTAssertEqual(decide(known, 4, ask: noTrust).reason, .explicitAllow)
    }

    /// The same for "always allow" on a rule's block (an exception on the deny rule).
    func testAnExceptionForAKnownChainDoesNotCoverUnknownAncestry() {
        func rule(covering unknown: Bool) -> Rule {
            var r = enforcedRule(Rule(id: "deny-ssh", target: .category("ssh"), subject: .anyNonOwner, action: .deny,
                                      includePlatformBinaries: true))
            r.exceptions = [RuleException(subject: .responsible(key: catKey, teamID: nil), categoryID: "ssh", access: .read,
                                          chainAgents: [], coversUnknownAncestry: unknown)]
            return r
        }
        h.rules.replace(rules: [rule(covering: false)])
        XCTAssertEqual(decide(cat(711, originalPPID: 1), 2, ask: .off).verdict, .allow)
        XCTAssertEqual(decide(cat(712, originalPPID: 700), 2, ask: .off).verdict, .deny)
        h.rules.replace(rules: [rule(covering: true)])
        XCTAssertEqual(decide(cat(713, originalPPID: 700), 3, ask: .off).verdict, .allow)
    }

    /// The scope bit survives storage; rules and keys saved before it existed get the narrower scope.
    func testTheScopeIsStoredAndOldRecordsGetTheNarrowerScope() throws {
        var r = answer(covering: true)
        r.exceptions = [RuleException(subject: .anyNonOwner, chainAgents: [], coversUnknownAncestry: true)]
        let decoded = try JSONDecoder().decode(Rule.self, from: JSONEncoder().encode(r))
        XCTAssertTrue(decoded.coversUnknownAncestry)
        XCTAssertEqual(decoded.exceptions.first?.coversUnknownAncestry, true)
        XCTAssertEqual(decoded, r)

        let old = #"{"id":"a","target":{"category":"ssh"},"subject":{"type":"anyNonOwner"},"action":"allow","chainAgents":[],"exceptions":[{"id":"e","subject":{"type":"anyNonOwner"},"chainAgents":[],"createdAt":0}]}"#
        let oldRule = try JSONDecoder().decode(Rule.self, from: Data(old.utf8))
        XCTAssertFalse(oldRule.coversUnknownAncestry)
        XCTAssertEqual(oldRule.exceptions.first?.coversUnknownAncestry, false)
        let oldKey = try JSONDecoder().decode(AskKey.self, from: Data(#"{"responsibleKey":"k","categoryID":"ssh","access":"read","chainAgents":[]}"#.utf8))
        XCTAssertTrue(oldKey.ancestryKnown)
    }
}

// MARK: - A question about a chain of unknown ancestry says so

final class UnknownAncestryWordingTests: XCTestCase {
    func alert(known: Bool?) -> Alert {
        Alert(id: 1, kind: .ask, createdAt: t0, updatedAt: t0, windowEndsAt: t0, responsible: ResponsibleEntity(kind: .binary, key: "bin:apple:com.apple.cat",
              displayName: "cat"), categoryID: "ssh", severity: .critical, count: 1, accesses: .read, firstPath: sshKey,
              firstEventID: 1, lastEventID: 1, paths: [sshKey], chain: [], agentID: nil, ruleID: nil, ancestryKnown: known)
    }

    func testTheHeadlineSaysWhoStartedItIsUnknown() {
        let en = AlertFormatter(language: .en), zh = AlertFormatter(language: .zhHans)
        XCTAssertEqual(en.headline(alert(known: false)),
                       "cat wants to read /Users/alice/.ssh/id_ed25519: not allowed until you decide (started by an unknown process, possibly an AI agent)")
        XCTAssertEqual(zh.headline(alert(known: false)), "cat 想要读取 /Users/alice/.ssh/id_ed25519，你决定之前不会放行（不知道是谁启动的，可能是 AI agent）")
        XCTAssertEqual(en.headline(alert(known: true)), "cat wants to read /Users/alice/.ssh/id_ed25519: not allowed until you decide")
        XCTAssertEqual(en.headline(alert(known: nil)), en.headline(alert(known: true)), "older alerts read as before")
    }
}

// MARK: - The AI agents of running processes survive a daemon restart

/// What libproc lists when the daemon starts (the seed): the current ppid only (launchd for an orphan),
/// no fork-time parent, no code signing data.
private func libproc(_ pid: Int32, _ path: String, ppid: Int32, start: TimeInterval, platform: Bool = false,
                     argv: [String]? = nil) -> ProcessRecord {
    ProcessRecord(pid: pid, ppid: ppid, executablePath: path, isPlatformBinary: platform, argv: argv, startTime: at(start))
}

final class AgentAncestryRestartTests: AncestryTestCase {
    private let noTrust = AskPolicy(enabled: true, trustApplePrograms: false, benignChain: false)
    private let nodePath = P.node(0, parent: 0, argv: []).executablePath

    /// Terminal → zsh (500) → Claude Code (600) → zsh (601) → sh (700) → ssh (702), a long-running job.
    /// sh has exited, so ssh is an orphan now (ppid 1). Returns what the daemon saves.
    func agentJobBeforeRestart(siblings: Bool = false) -> [AgentAncestryRecord] {
        let sh = h.spawn(agentShell(), proc(700, "/bin/sh", ppid: 601, start: 3, platform: true, signingID: "com.apple.sh"), 3)
        let ssh = h.spawn(sh, proc(702, "/usr/bin/ssh", ppid: 700, start: 4, platform: true, signingID: "com.apple.openssh"), 4)
        if siblings { h.spawn(sh, proc(703, "/usr/bin/ssh", ppid: 700, start: 4, platform: true, signingID: "com.apple.openssh"), 4) }
        h.tree.exit(sh, at: at(5))
        XCTAssertEqual(h.tree.chain(for: ssh, at: at(6)).nearestAgent, "claude-code")
        return h.tree.agentAncestry()
    }

    /// What is still running when the daemon starts again.
    func runningAfterRestart() -> [ProcessRecord] {
        [libproc(1, "/sbin/launchd", ppid: 0, start: -1000, platform: true),
         libproc(100, P.terminal.executablePath, ppid: 1, start: 0, platform: true),
         libproc(500, "/bin/zsh", ppid: 100, start: 0, platform: true),
         libproc(600, nodePath, ppid: 500, start: 0, argv: claudeNodeArgv),
         libproc(601, "/bin/zsh", ppid: 600, start: 0, platform: true),
         libproc(702, "/usr/bin/ssh", ppid: 1, start: 4, platform: true)]
    }

    /// A new daemon: a fresh tree seeded from libproc, then given the saved records.
    func restart(seed: [ProcessRecord], records: [AgentAncestryRecord], at t: TimeInterval = 10) throws {
        h = try Harness(rules: [enforcedRule(RuleTemplates.blockAgentsFromCritical())], learningDays: 0)
        h.tree.seed(seed, at: at(t))
        h.tree.restoreAgentAncestry(records, at: at(t))
    }

    /// The job's first event after the restart: original_ppid names the shell that is gone.
    let ssh = proc(702, "/usr/bin/ssh", ppid: 1, start: 4, platform: true, signingID: "com.apple.openssh", originalPPID: 700)

    /// Without the saved records the restarted daemon cannot tell who started the orphan: its ancestry
    /// is unknown and Claude Code is gone from its chain. With them it keeps the agent (above the shell
    /// as last seen, linked to the agent that is still running), and still never counts as a chain that
    /// reaches launchd.
    func testAnAgentsJobWhoseShellExitedKeepsTheAgentAcrossARestart() throws {
        let records = agentJobBeforeRestart()
        try restart(seed: runningAfterRestart(), records: [])
        XCTAssertNil(h.tree.chain(for: ssh, at: at(11)).nearestAgent, "the loss this restores")

        try restart(seed: runningAfterRestart(), records: records)
        let chain = h.tree.chain(for: ssh, at: at(11))
        XCTAssertEqual(names(chain), ["ssh", "sh", "node", "zsh", "Terminal"])
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertNil(chain.first { $0.image.pid == 600 }?.exitedAt, "the agent still running is linked as itself")
        XCTAssertNotNil(chain.first { $0.image.pid == 700 }?.exitedAt, "the shell is a placeholder")
        XCTAssertFalse(chain.reachesLaunchd)
        XCTAssertFalse(AskPolicy.isTrustableAppleProgram(ssh, chain: chain))
        XCTAssertEqual(h.attributor.attribute(chain: chain).key, "agent:claude-code")
        XCTAssertEqual(decide(ssh, 11).verdict, .deny, "the agent rule applies")
        // ssh owns SSH keys, but not driven by an agent.
        h.rules.replace(rules: [])
        XCTAssertTrue(h.classifier.isOwner(ssh, of: "ssh"))
        let asked = decide(ssh, 12, ask: noTrust)
        XCTAssertEqual(asked.verdict, .ask)
        XCTAssertEqual(asked.askKey?.chainAgents, ["claude-code"])
        // Saved again from the restored tree, the records still carry the agent (a second restart).
        XCTAssertEqual(h.tree.agentAncestry().first { $0.pid == 702 }?.agentsAbove.map(\.agentID), ["claude-code"])
    }

    /// The jobs of one shell share its placeholder.
    func testSiblingsShareOnePlaceholder() throws {
        let records = agentJobBeforeRestart(siblings: true)
        try restart(seed: runningAfterRestart() + [libproc(703, "/usr/bin/ssh", ppid: 1, start: 4, platform: true)], records: records)
        let a = h.tree.chain(for: ssh, at: at(11)), b = h.tree.chain(for: proc(703, "/usr/bin/ssh", ppid: 1, start: 4, platform: true,
                                                                              signingID: "com.apple.openssh", originalPPID: 700), at: at(11))
        XCTAssertEqual(b.nearestAgent, "claude-code")
        XCTAssertEqual(a[1].id, b[1].id)
    }

    /// A placeholder is reachable only through what was restored below it. Here pid 700 (the shell that
    /// is gone) belongs to an unrelated program now, which started cat just before the restore (too late
    /// for the snapshot). cat's parent is that program, not the old shell with Claude Code above it.
    func testAPlaceholderIsNotTakenForTheProcessThatHoldsItsPidNow() throws {
        let records = agentJobBeforeRestart()
        try restart(seed: runningAfterRestart() + [libproc(700, "/usr/bin/python3", ppid: 1, start: 8, platform: true)],
                    records: records)
        XCTAssertEqual(h.tree.node(pid: 700)?.image.name, "python3")
        let cat = proc(710, "/bin/cat", ppid: 700, start: 9, platform: true, signingID: "com.apple.cat")
        let chain = h.tree.chain(for: cat, at: at(11))
        XCTAssertEqual(names(chain), ["cat", "python3"])
        XCTAssertNil(chain.nearestAgent)
        // The restored job still has its placeholder.
        XCTAssertEqual(names(h.tree.chain(for: ssh, at: at(11))), ["ssh", "sh", "node", "zsh", "Terminal"])
    }

    /// Records name a process instance by pid and start time: a pid held by another process now gets
    /// nothing from them.
    func testARecordForAnotherInstanceOfThePidIsIgnored() throws {
        let records = agentJobBeforeRestart()
        try restart(seed: [libproc(1, "/sbin/launchd", ppid: 0, start: -1000, platform: true),
                           libproc(100, P.terminal.executablePath, ppid: 1, start: 0, platform: true),
                           libproc(500, "/bin/zsh", ppid: 100, start: 0, platform: true),
                           libproc(600, "/usr/bin/vim", ppid: 500, start: 9),
                           libproc(702, "/usr/bin/python3", ppid: 1, start: 9)], records: records)
        XCTAssertNil(h.tree.node(pid: 600)?.agentID)
        let chain = h.tree.chain(for: libproc(702, "/usr/bin/python3", ppid: 1, start: 9), at: at(11))
        XCTAssertEqual(names(chain), ["python3"])
        XCTAssertNil(chain.nearestAgent)
    }

    /// Claude Code (native, its team pinned by a "block from now on" rule) exec'd /bin/cat, which runs a
    /// job. libproc shows only /bin/cat: nothing to recognise the agent by. The record gives the process
    /// its agent and team back, and what it started (linked by the snapshot) has the agent above it.
    func testAnAgentThatExecdAwayIsAnAgentAgainAfterARestart() throws {
        let block = Rule(id: "block-claude", enabled: true, enforce: true, target: .category("ssh"),
                         subject: .responsible(key: "agent:claude-code", teamID: claudeTeam), access: .any, action: .deny)
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let claude = h.spawn(zsh, proc(600, "/Users/alice/.local/share/claude/versions/2.0.1", ppid: 500, start: 1,
                                       signingID: "com.anthropic.claude-code", teamID: claudeTeam, argv: ["claude"]), 1)
        var cat = P.cat(600, parent: 500)
        cat.startTime = claude.startTime
        cat.pidVersion = claude.pidVersion.map { $0 + 1 }
        h.exec(claude, cat, 2)
        let job = h.spawn(cat, proc(610, "/usr/bin/python3", ppid: 600, start: 3), 3)
        let records = h.tree.agentAncestry()

        let running = [libproc(1, "/sbin/launchd", ppid: 0, start: -1000, platform: true),
                       libproc(100, P.terminal.executablePath, ppid: 1, start: 0, platform: true),
                       libproc(500, "/bin/zsh", ppid: 100, start: 0, platform: true),
                       libproc(600, "/bin/cat", ppid: 500, start: 1, platform: true),
                       libproc(610, "/usr/bin/python3", ppid: 600, start: 3)]
        try restart(seed: running, records: [])
        XCTAssertNil(h.tree.chain(for: job, at: at(11)).nearestAgent, "the loss this restores")

        try restart(seed: running, records: records)
        h.rules.replace(rules: [block])
        XCTAssertEqual(h.tree.node(pid: 600)?.agentID, "claude-code")
        let chain = h.tree.chain(for: job, at: at(11))
        XCTAssertEqual(names(chain), ["python3", "cat", "zsh", "Terminal"])
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        let responsible = h.attributor.attribute(chain: chain)
        XCTAssertEqual(responsible.key, "agent:claude-code")
        XCTAssertEqual(responsible.teamID, claudeTeam)
        XCTAssertEqual(decide(job, 11).ruleID, "block-claude")
    }

    /// Only running processes with an AI agent in their ancestry are saved, the oldest first when there
    /// are more than the limit.
    func testOnlyRunningProcessesWithAnAgentAreSavedOldestFirst() {
        _ = agentJobBeforeRestart()
        XCTAssertEqual(h.tree.agentAncestry().map(\.pid), [600, 601, 702], "Claude Code, its shell and the job, not sh (exited)")
        XCTAssertEqual(h.tree.agentAncestry(limit: 1).map(\.pid), [600])
    }
}
