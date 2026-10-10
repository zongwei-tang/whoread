import XCTest
@testable import WhoReadCore

// Ancestry that is unknown, unverified or cut short (process-1, process-2, process-3 = macos-6,
// process-5, dos-3): it never counts as "started by launchd", never as an all-Apple or benign chain,
// and a deep chain keeps the AI agent at its top while its cost stays bounded.

private let sshKey = "/Users/alice/.ssh/id_ed25519"
private let trusting = AskPolicy(enabled: true, trustApplePrograms: true, benignChain: false)
private let claudeArgv = ["node", "/opt/homebrew/bin/claude"]

private func enforced(_ rule: Rule) -> Rule {
    var r = rule
    r.enabled = true
    r.enforce = true
    return r
}

/// libproc snapshot record: no fork-time parent, no code signing data.
private func snapshot(_ pid: Int32, _ path: String, ppid: Int32, start: TimeInterval, platform: Bool = false,
                      argv: [String]? = nil) -> ProcessRecord {
    ProcessRecord(pid: pid, ppid: ppid, executablePath: path, isPlatformBinary: platform, argv: argv, startTime: at(start))
}

class AncestryTestCase: XCTestCase {
    var h: Harness!

    override func setUpWithError() throws {
        h = try Harness(rules: [enforced(RuleTemplates.blockAgentsFromCritical())], learningDays: 0)
    }

    func target(_ path: String) -> EvaluationTarget {
        let c = h.classifier.classify(path)!
        return EvaluationTarget(path: h.normalizer.normalize(path), access: .read,
                                categories: [TargetCategory(id: c.categoryID, severity: c.severity)])
    }

    /// What the AUTH path decides (Enforcer.decide), with "trust Apple programs" on.
    func decide(_ p: ProcessRecord, _ t: TimeInterval, ask: AskPolicy = trusting) -> RuleDecision {
        let chain = h.tree.chain(for: p, at: at(t))
        let policy = AskPolicy(enabled: ask.enabled, trustApplePrograms: ask.trustApplePrograms,
                               benignChain: h.analyzer.isBenignChain(chain))
        return h.rules.evaluate(process: chain.first?.image ?? p, chain: chain, targets: [target(sshKey)],
                                enforcementActive: true, now: at(t), ask: policy)
    }

    func names(_ chain: [ProcessNode]) -> [String] { chain.map(\.image.name) }

    /// Terminal → zsh (500) → Claude Code (600) → zsh (601).
    func agentShell() -> ProcessRecord {
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let claude = h.spawn(zsh, P.node(600, parent: 500, argv: claudeArgv), 1)
        return h.spawn(claude, P.zsh(601, parent: 600), 2)
    }

    /// `parent` forks `pid` and the child execs `image`, as the process client reports it.
    @discardableResult
    func forkExec(_ parent: ProcessRecord, _ image: ProcessRecord, _ t: TimeInterval) -> ProcessRecord {
        h.spawn(parent, image, t)
    }
}

// MARK: - process-1: a reparented process whose original parent is unknown

final class UnknownAncestryTests: AncestryTestCase {
    /// Claude Code → zsh (601) → sh (700) → cat (701). sh exited and cat was reparented (ppid 1,
    /// original_ppid 700) before the process client delivered either fork: the file client decides first.
    func testReparentedProcessWhoseParentWasNotSeenIsNotStartedByLaunchd() {
        h.tree.parentResolver = { _ in nil }  // sh is gone
        let shell = agentShell()
        let cat = proc(701, "/bin/cat", ppid: 1, start: 3, platform: true, signingID: "com.apple.cat", argv: ["cat"],
                       originalPPID: 700)
        let chain = h.tree.chain(for: cat, at: at(4))
        XCTAssertEqual(names(chain), ["cat"], "ancestry unknown, not launchd")
        XCTAssertNil(chain.nearestAgent)
        XCTAssertFalse(AskPolicy.isTrustableAppleProgram(cat, chain: chain))
        let d = decide(cat, 4)
        XCTAssertEqual(d.verdict, .ask, "never trusted as an all-Apple chain")
        XCTAssertNotEqual(d.reason, .trustedApple)

        // The forks arrive: the chain is relinked, the agent is back and its rule denies.
        let sh = forkExec(shell, proc(700, "/bin/sh", ppid: 601, start: 3, platform: true), 3)
        forkExec(sh, cat, 3)
        let relinked = h.tree.chain(for: cat, at: at(5))
        XCTAssertEqual(names(relinked), ["cat", "sh", "zsh", "node", "zsh", "Terminal", "launchd"])
        XCTAssertEqual(decide(cat, 5).verdict, .deny)
    }

    /// The same race with an owner (ssh reading a key): "an owner without an AI agent in its chain"
    /// must not be assumed when the chain is unknown.
    func testAnOwnerWithUnknownAncestryIsAskedNotAllowed() {
        h.tree.parentResolver = { _ in nil }
        _ = agentShell()
        let ssh = proc(702, "/usr/bin/ssh", ppid: 1, start: 3, platform: true, signingID: "com.apple.openssh", originalPPID: 700)
        XCTAssertTrue(h.classifier.isOwner(ssh, of: "ssh"))
        let d = decide(ssh, 4, ask: AskPolicy(enabled: true, trustApplePrograms: false, benignChain: false))
        XCTAssertEqual(d.verdict, .ask)
        XCTAssertNotEqual(d.reason, .owner)
        // With a known chain (the user's own ssh) the owner still passes.
        let own = h.spawn(h.spawn(P.terminal, P.zsh(520, parent: 100)), proc(703, "/usr/bin/ssh", ppid: 520, start: 3, platform: true,
                                                                              signingID: "com.apple.openssh"), 3)
        XCTAssertEqual(decide(own, 4, ask: AskPolicy(enabled: true, trustApplePrograms: false, benignChain: false)).reason, .owner)
    }

    /// A Spotlight worker whose original parent is unknown is not a service launchd started.
    func testABenignServiceWithUnknownAncestryIsNotBenign() {
        h.tree.parentResolver = { _ in nil }
        let worker = proc(704, "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared",
                          ppid: 1, start: 3, platform: true, originalPPID: 700)
        XCTAssertNil(h.benignClassifier.classify(chain: h.tree.chain(for: worker, at: at(4))))
        // Started by launchd (original_ppid 1): benign.
        let real = proc(705, worker.executablePath, ppid: 1, start: 3, platform: true, originalPPID: 1)
        XCTAssertEqual(h.benignClassifier.classify(chain: h.tree.chain(for: real, at: at(4))), "spotlight")
    }

    /// process-1 variant: a traced process reports its debugger as ppid; it was started by its fork-time
    /// parent (original_ppid), here under the agent.
    func testATracedProcessKeepsItsForkTimeParent() {
        let shell = agentShell()
        let userShell = h.spawn(P.terminal, P.zsh(530, parent: 100))
        _ = h.spawn(userShell, proc(950, "/usr/bin/lldb", ppid: 530, start: 2, platform: true), 2)
        let cat = proc(706, "/bin/cat", ppid: 950, start: 3, platform: true, signingID: "com.apple.cat", originalPPID: 601)
        _ = shell
        let chain = h.tree.chain(for: cat, at: at(4))
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertFalse(names(chain).contains("lldb"))
        XCTAssertEqual(decide(cat, 4).verdict, .deny)
    }
}

// MARK: - process-2: a chain that does not reach launchd

final class TruncatedChainTests: AncestryTestCase {
    func testAChainThatStopsShortOfLaunchdIsNotAllApple() {
        // Parent 777 unknown and no resolver: the chain is the leaf alone.
        let cat = proc(401, "/bin/cat", ppid: 777, start: 3, platform: true, signingID: "com.apple.cat")
        let chain = h.tree.chain(for: cat, at: at(4))
        XCTAssertEqual(names(chain), ["cat"])
        XCTAssertFalse(AskPolicy.isTrustableAppleProgram(cat, chain: chain))
        XCTAssertEqual(decide(cat, 4).verdict, .ask)
    }

    func testABenignChainMustReachLaunchd() {
        let support = "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/"
        let mds = proc(402, support + "mds", ppid: 778, start: 0, platform: true)  // 778 never seen
        h.tree.observe(mds, at: at(1))
        let worker = proc(403, support + "mdworker_shared", ppid: 402, start: 1, platform: true)
        let chain = h.tree.chain(for: worker, at: at(2))
        XCTAssertEqual(names(chain), ["mdworker_shared", "mds"])
        XCTAssertNil(h.benignClassifier.classify(chain: chain))
    }

    /// The node cap splices an exited ancestor out (its children move up to the grandparent). An
    /// exited app's helpers then sit right below launchd: the chain is incomplete, not all-Apple, and a
    /// Spotlight worker below an app is still not a launchd-started service.
    func testALinkSplicedOutByTheNodeCapIsNotAChainThatReachesLaunchd() {
        let tree = h.tree
        tree.observe(P.launchd, at: t0)
        let app = proc(300, "/Applications/Helper.app/Contents/MacOS/Helper", ppid: 1, start: 0, teamID: "TEAMAPP01")
        tree.observe(app, at: at(0))
        let cat = proc(301, "/bin/cat", ppid: 300, start: 1, platform: true, signingID: "com.apple.cat")
        tree.fork(parent: app, child: cat, at: at(1))
        let support = "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/"
        let worker = proc(302, support + "mdworker_shared", ppid: 300, start: 1, platform: true)
        tree.fork(parent: app, child: worker, at: at(1))
        tree.exit(app, at: at(2))
        XCTAssertEqual(decide(cat, 3).verdict, .ask, "Helper.app → cat is not all-Apple")
        // Enough short-lived processes that the cap reaches the exited app (childless ones go first).
        tree.maxNodes = 3
        for i in 0..<6 {
            let p = proc(Int32(400 + i), "/bin/sh", ppid: 1, start: 3, platform: true)
            tree.observe(p, at: at(3))
            tree.exit(p, at: at(10))
        }
        tree.prune(now: at(20))
        XCTAssertNil(tree.node(pid: 300), "the app was spliced out")
        let chain = tree.chain(for: cat, at: at(21))
        XCTAssertEqual(names(chain), ["cat", "launchd"])
        XCTAssertFalse(chain.reachesLaunchd)
        XCTAssertFalse(AskPolicy.isTrustableAppleProgram(cat, chain: chain))
        XCTAssertEqual(decide(cat, 21).verdict, .ask)
        XCTAssertNil(h.benignClassifier.classify(chain: tree.chain(for: worker, at: at(21))))
    }
}

// MARK: - process-3 / macos-6: the libproc parent resolver

final class ResolvedParentTests: AncestryTestCase {
    /// cat (started at 10, reparented, original parent 500) and a resolver that returns whoever holds
    /// pid 500 now: Terminal, started at 50. A reused pid is not the parent.
    func testAResolvedParentThatStartedAfterTheChildIsRejected() {
        let terminal = proc(500, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", ppid: 1, start: 50, platform: true)
        h.tree.parentResolver = { $0 == 500 ? terminal : nil }
        let cat = proc(402, "/bin/cat", ppid: 1, start: 10, platform: true, signingID: "com.apple.cat", originalPPID: 500)
        XCTAssertEqual(names(h.tree.chain(for: cat, at: at(60))), ["cat"])
        XCTAssertEqual(decide(cat, 60).verdict, .ask)
    }

    /// Worse: the later instance is already in the tree (rejected there by its start time), and the
    /// resolver returns the same process.
    func testAReusedPidRejectedInTheTreeIsNotAcceptedFromTheResolver() {
        let terminal = proc(500, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", ppid: 1, start: 50, platform: true)
        h.tree.observe(terminal, at: at(55))
        h.tree.parentResolver = { $0 == 500 ? terminal : nil }
        let cat = proc(403, "/bin/cat", ppid: 1, start: 10, platform: true, signingID: "com.apple.cat", originalPPID: 500)
        XCTAssertEqual(names(h.tree.chain(for: cat, at: at(60))), ["cat"])
    }

    /// A parent that started before the child is still linked from the resolver.
    func testAResolvedParentThatStartedBeforeTheChildIsLinked() {
        let zsh = snapshot(500, "/bin/zsh", ppid: 100, start: 5, platform: true)
        h.tree.observe(P.terminal, at: at(0))
        h.tree.parentResolver = { $0 == 500 ? zsh : nil }
        let cat = proc(404, "/bin/cat", ppid: 500, start: 10, platform: true, signingID: "com.apple.cat")
        XCTAssertEqual(names(h.tree.chain(for: cat, at: at(11))), ["cat", "zsh", "Terminal", "launchd"])
    }

    /// Once a process's fork-time parent pid resolves to nothing usable, libproc is not asked again on
    /// every decision for it: the parent is dead, so any later holder of the pid started after the child.
    func testAnUnresolvableParentIsNotLookedUpOnEveryDecision() {
        let calls = Counter()
        let holder = proc(500, "/Applications/Other.app/Contents/MacOS/Other", ppid: 1, start: 50)
        h.tree.parentResolver = { pid in
            calls.increment()
            return pid == 500 ? holder : nil
        }
        let cat = proc(407, "/bin/cat", ppid: 1, start: 10, platform: true, originalPPID: 500)
        for i in 0..<5 { XCTAssertEqual(names(h.tree.chain(for: cat, at: at(60 + Double(i)))), ["cat"]) }
        XCTAssertEqual(calls.value, 1)
    }

    /// macos-6: a resolved parent's platform flag is guessed from its path; until an event confirms
    /// it, the chain is not an all-Apple chain.
    func testAResolvedParentIsNotTrustedAsAppleUntilAnEventConfirmsIt() {
        let zsh = snapshot(500, "/bin/zsh", ppid: 100, start: 5, platform: true)
        h.tree.observe(P.terminal, at: at(0))
        h.tree.parentResolver = { $0 == 500 ? zsh : nil }
        let cat = proc(405, "/bin/cat", ppid: 500, start: 10, platform: true, signingID: "com.apple.cat")
        XCTAssertEqual(decide(cat, 11).verdict, .ask)
        // zsh's own event (it forks something else) carries the real flag.
        h.tree.observe(proc(500, "/bin/zsh", ppid: 100, start: 5, platform: true, signingID: "com.apple.zsh"), at: at(12))
        XCTAssertEqual(decide(cat, 13).reason, .trustedApple)
    }

    /// macos-6 variant: a guessed platform flag never outlives the real one an event reports.
    func testAGuessedPlatformFlagDoesNotOverrideTheEvent() {
        let tree = h.tree
        tree.seed([snapshot(406, "/Users/alice/bin/tool", ppid: 100, start: 0, platform: true)], at: at(0))
        let event = proc(406, "/Users/alice/bin/tool", ppid: 100, start: 0, platform: false)
        XCTAssertEqual(tree.chain(for: event, at: at(1)).first?.image.isPlatformBinary, false)
    }
}

// MARK: - process-5: seeded processes after a daemon restart

final class SeededAncestryTests: AncestryTestCase {
    /// Snapshot at start: Claude Code alive, and a cat it started earlier whose shell has exited
    /// (ppid 1 now; libproc cannot tell). The first event from cat says original_ppid 700.
    func testASeededOrphanIsNotStartedByLaunchd() {
        h.tree.seed([
            snapshot(1, "/sbin/launchd", ppid: 0, start: -1000, platform: true),
            snapshot(100, P.terminal.executablePath, ppid: 1, start: -900, platform: true),
            snapshot(500, "/bin/zsh", ppid: 100, start: -800, platform: true),
            snapshot(600, P.node(600, parent: 500, argv: []).executablePath, ppid: 500, start: -700, argv: claudeArgv),
            snapshot(701, "/bin/cat", ppid: 1, start: -600, platform: true, argv: ["cat"]),
        ], at: at(0))
        let cat = proc(701, "/bin/cat", ppid: 1, start: -600, platform: true, signingID: "com.apple.cat", originalPPID: 700)
        let chain = h.tree.chain(for: cat, at: at(1))
        XCTAssertEqual(names(chain), ["cat"])
        XCTAssertFalse(AskPolicy.isTrustableAppleProgram(cat, chain: chain))
        XCTAssertEqual(decide(cat, 1).verdict, .ask)
    }

    /// A seeded intermediate that never acts itself (zsh, reparented) above a seeded leaf (cat): until
    /// zsh's own event says who started it, the chain does not reach launchd.
    func testASeededAncestorReparentedToLaunchdIsUnknownUntilItsOwnEvent() {
        h.tree.seed([
            snapshot(1, "/sbin/launchd", ppid: 0, start: -1000, platform: true),
            snapshot(800, "/bin/zsh", ppid: 1, start: -900, platform: true),
            snapshot(801, "/bin/cat", ppid: 800, start: -800, platform: true, argv: ["cat"]),
        ], at: at(0))
        let cat = proc(801, "/bin/cat", ppid: 800, start: -800, platform: true, signingID: "com.apple.cat")
        XCTAssertEqual(names(h.tree.chain(for: cat, at: at(1))), ["cat", "zsh"])
        XCTAssertEqual(decide(cat, 1).verdict, .ask)
        // zsh's event: launchd started it.
        h.tree.observe(proc(800, "/bin/zsh", ppid: 1, start: -900, platform: true, signingID: "com.apple.zsh", originalPPID: 1), at: at(2))
        XCTAssertEqual(names(h.tree.chain(for: cat, at: at(3))), ["cat", "zsh", "launchd"])
        XCTAssertEqual(decide(cat, 3).reason, .trustedApple)
    }

    /// After a daemon restart: Terminal and zsh were already running (libproc: no fork-time parent) and
    /// the user runs ssh in that window. Until Terminal's own event says launchd started it, the chain
    /// does not reach launchd, so ssh is asked rather than passed as an owner (one answer covers it).
    func testAnOwnerUnderASeededTerminalIsAskedUntilTerminalIsConfirmed() {
        let noTrust = AskPolicy(enabled: true, trustApplePrograms: false, benignChain: false)
        h.tree.seed([
            snapshot(1, "/sbin/launchd", ppid: 0, start: -1000, platform: true),
            snapshot(100, P.terminal.executablePath, ppid: 1, start: -900, platform: true),
            snapshot(500, "/bin/zsh", ppid: 100, start: -800, platform: true),
        ], at: at(0))
        let zsh = proc(500, "/bin/zsh", ppid: 100, start: -800, platform: true, signingID: "com.apple.zsh")
        let ssh = forkExec(zsh, proc(510, "/usr/bin/ssh", ppid: 500, start: 1, platform: true, signingID: "com.apple.openssh"), 1)
        XCTAssertEqual(names(h.tree.chain(for: ssh, at: at(2))), ["ssh", "zsh", "Terminal"])
        XCTAssertEqual(decide(ssh, 2, ask: noTrust).verdict, .ask)
        h.tree.observe(proc(100, P.terminal.executablePath, ppid: 1, start: -900, platform: true, signingID: "com.apple.Terminal"),
                       at: at(3))
        XCTAssertEqual(names(h.tree.chain(for: ssh, at: at(4))), ["ssh", "zsh", "Terminal", "launchd"])
        XCTAssertEqual(decide(ssh, 4, ask: noTrust).reason, .owner)
    }

    /// A traced process seen in the snapshot: libproc reports its debugger as ppid, so the seed links it
    /// there. Its first event says Claude Code's shell forked it: it moves there, with what it started.
    func testASeededTracedProcessMovesToItsForkTimeParent() {
        h.tree.seed([
            snapshot(1, "/sbin/launchd", ppid: 0, start: -1000, platform: true),
            snapshot(100, P.terminal.executablePath, ppid: 1, start: -900, platform: true),
            snapshot(500, "/bin/zsh", ppid: 100, start: -800, platform: true),
            snapshot(600, P.node(600, parent: 500, argv: []).executablePath, ppid: 500, start: -700, argv: claudeArgv),
            snapshot(601, "/bin/zsh", ppid: 600, start: -650, platform: true),
            snapshot(530, "/bin/zsh", ppid: 100, start: -640, platform: true),
            snapshot(950, "/usr/bin/lldb", ppid: 530, start: -620, platform: true),
            snapshot(706, "/bin/sh", ppid: 950, start: -600, platform: true),
            snapshot(707, "/bin/cat", ppid: 706, start: -590, platform: true),
        ], at: at(0))
        let sh = proc(706, "/bin/sh", ppid: 950, start: -600, platform: true, signingID: "com.apple.sh", originalPPID: 601)
        XCTAssertEqual(h.tree.chain(for: sh, at: at(1)).nearestAgent, "claude-code")
        XCTAssertFalse(names(h.tree.chain(for: sh, at: at(1))).contains("lldb"))
        // cat (seeded below sh, no event of its own yet) follows sh: its ancestry is refreshed too.
        let cat = proc(707, "/bin/cat", ppid: 706, start: -590, platform: true, signingID: "com.apple.cat")
        let chain = h.tree.chain(for: cat, at: at(2))
        XCTAssertEqual(names(chain), ["cat", "sh", "zsh", "node", "zsh", "Terminal"])
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertEqual(decide(cat, 2).verdict, .deny)
    }

    /// The same move with a subtree deeper than the walked links below the traced process: what the deep
    /// leaf recorded about its ancestors is redone (the agent beyond the cut, not the debugger's app).
    func testASeededTracedProcessMovesWithItsDeepSubtree() {
        var records = [
            snapshot(1, "/sbin/launchd", ppid: 0, start: -1000, platform: true),
            snapshot(100, P.terminal.executablePath, ppid: 1, start: -900, platform: true),
            snapshot(500, "/bin/zsh", ppid: 100, start: -800, platform: true),
            snapshot(600, P.node(600, parent: 500, argv: []).executablePath, ppid: 500, start: -700, argv: claudeArgv),
            snapshot(601, "/bin/zsh", ppid: 600, start: -650, platform: true),
            snapshot(950, "/Applications/Debugger.app/Contents/MacOS/Debugger", ppid: 1, start: -620),
            snapshot(706, "/bin/sh", ppid: 950, start: -600, platform: true),
        ]
        for i in 0..<80 {
            records.append(snapshot(Int32(3000 + i), "/bin/sh", ppid: i == 0 ? 706 : Int32(3000 + i - 1), start: -590, platform: true))
        }
        h.tree.seed(records, at: at(0))
        let leaf = proc(3079, "/bin/sh", ppid: 3078, start: -590, platform: true, signingID: "com.apple.sh")
        XCTAssertEqual(h.attributor.attribute(chain: h.tree.chain(for: leaf, at: at(1))).key,
                       "app:/applications/debugger.app", "before: under the debugger")
        h.tree.observe(proc(706, "/bin/sh", ppid: 950, start: -600, platform: true, signingID: "com.apple.sh", originalPPID: 601),
                       at: at(2))
        let chain = h.tree.chain(for: leaf, at: at(3))
        XCTAssertGreaterThan(chain.count, 64)
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertFalse(names(chain).contains("Debugger"))
        XCTAssertEqual(h.attributor.attribute(chain: chain).key, "agent:claude-code")
        XCTAssertEqual(decide(leaf, 3).verdict, .deny)
    }

    /// When the fork-time parent the event names is gone, the traced process is left unlinked, and the
    /// deep leaf below it no longer records the debugger's app as an ancestor.
    func testASeededTracedProcessWhoseForkTimeParentIsGoneIsUnlinkedWithItsSubtree() {
        h.tree.parentResolver = { _ in nil }
        var records = [
            snapshot(1, "/sbin/launchd", ppid: 0, start: -1000, platform: true),
            snapshot(950, "/Applications/Debugger.app/Contents/MacOS/Debugger", ppid: 1, start: -620),
            snapshot(706, "/bin/sh", ppid: 950, start: -600, platform: true),
        ]
        for i in 0..<80 {
            records.append(snapshot(Int32(3000 + i), "/bin/sh", ppid: i == 0 ? 706 : Int32(3000 + i - 1), start: -590, platform: true))
        }
        h.tree.seed(records, at: at(0))
        h.tree.observe(proc(706, "/bin/sh", ppid: 950, start: -600, platform: true, signingID: "com.apple.sh", originalPPID: 777),
                       at: at(1))
        let leaf = proc(3079, "/bin/sh", ppid: 3078, start: -590, platform: true, signingID: "com.apple.sh")
        let chain = h.tree.chain(for: leaf, at: at(2))
        XCTAssertFalse(names(chain).contains("Debugger"))
        XCTAssertEqual(chain.last?.image.pid, 706, "the topmost known process")
        XCTAssertNotEqual(h.attributor.attribute(chain: chain).key, "app:/applications/debugger.app")
    }

    /// A seeded process launchd really started is linked at its first event.
    func testASeededLaunchdChildIsLinkedAtItsFirstEvent() {
        h.tree.seed([
            snapshot(1, "/sbin/launchd", ppid: 0, start: -1000, platform: true),
            snapshot(100, P.terminal.executablePath, ppid: 1, start: -900, platform: true),
        ], at: at(0))
        let terminal = proc(100, P.terminal.executablePath, ppid: 1, start: -900, platform: true, signingID: "com.apple.Terminal")
        XCTAssertEqual(names(h.tree.chain(for: terminal, at: at(1))), ["Terminal", "launchd"])
    }
}

// MARK: - dos-3: chain depth is attacker-controlled

final class DeepChainTests: AncestryTestCase {
    /// Fork-then-exit generations under Claude Code; the leaf stays alive.
    func build(_ tree: ProcessTree, depth: Int, top: ProcessRecord = P.node(600, parent: 1, argv: claudeArgv)) -> ProcessRecord {
        tree.observe(P.launchd, at: t0)
        var parent = top
        tree.observe(parent, at: t0)
        for i in 0..<depth {
            let child = proc(Int32(10_000 + i), "/bin/sh", ppid: parent.pid, start: Double(i) * 0.01, platform: true)
            tree.fork(parent: parent, child: child, at: at(Double(i) * 0.01))
            if i > 0 { tree.exit(parent, at: at(Double(i) * 0.01)) }
            parent = child
        }
        return parent
    }

    func testForkCostDoesNotGrowWithDepth() throws {
        let tree = ProcessTree(detector: AgentDetector(catalog: try defaultData().agents))
        let start = Date()
        _ = build(tree, depth: 20_000)
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertLessThan(elapsed, 10, "each fork linked in O(1), not by walking to the root (O(depth²) overall)")
        print("built a 20000-deep fork chain in \(String(format: "%.3f", elapsed)) s")
    }

    func testADeepChainIsBoundedAndKeepsTheAgent() throws {
        let leaf = build(h.tree, depth: 5000)
        let cat = proc(leaf.pid, "/bin/cat", ppid: leaf.ppid, start: leaf.startTime!.timeIntervalSince(t0), platform: true,
                       signingID: "com.apple.cat")
        h.tree.exec(old: leaf, new: cat, at: at(100))
        let chain = h.tree.chain(for: cat, at: at(100))
        XCTAssertLessThanOrEqual(chain.count, 64 + 4, "walked links are capped, whatever the depth")
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertEqual(h.attributor.attribute(chain: chain).key, "agent:claude-code")
        XCTAssertNotEqual(chain.last?.image.pid, 1, "cut short: not a chain that reaches launchd")
        XCTAssertEqual(decide(cat, 100).verdict, .deny, "the agent rule still applies")
    }

    /// Deep all-Apple chain under Terminal: never trusted (the cut-off part is not looked at), and
    /// the responsible app beyond the walked links is still the app.
    func testADeepChainIsNeverTrustedAndKeepsTheResponsibleApp() throws {
        let leaf = build(h.tree, depth: 200, top: P.terminal)
        let chain = h.tree.chain(for: leaf, at: at(10))
        XCTAssertLessThanOrEqual(chain.count, 64 + 4)
        XCTAssertFalse(AskPolicy.isTrustableAppleProgram(leaf, chain: chain))
        XCTAssertEqual(decide(leaf, 10).verdict, .ask)
        XCTAssertEqual(h.attributor.attribute(chain: chain).key, "app:/system/applications/utilities/terminal.app")
    }

    /// A subtree built while its root's parent was unknown learns the agent when the root is linked.
    func testRelinkingASubtreeRootGivesDeepDescendantsTheAgent() throws {
        let tree = ProcessTree(detector: AgentDetector(catalog: try defaultData().agents))
        tree.observe(P.launchd, at: t0)
        let claude = P.node(600, parent: 1, argv: claudeArgv)
        tree.observe(claude, at: t0)
        // 900's fork event is late: it is first seen as a reparented process whose parent 850 is unknown.
        let root = proc(900, "/bin/sh", ppid: 1, start: 1, platform: true, originalPPID: 850)
        tree.observe(root, at: at(1))
        var parent = root
        for i in 0..<150 {
            let child = proc(Int32(20_000 + i), "/bin/sh", ppid: parent.pid, start: 2, platform: true)
            tree.fork(parent: parent, child: child, at: at(2))
            parent = child
        }
        XCTAssertNil(tree.chain(for: parent, at: at(3)).nearestAgent)
        // The late forks: claude → 850 → 900.
        let mid = proc(850, "/bin/zsh", ppid: 600, start: 0.5, platform: true)
        tree.fork(parent: claude, child: mid, at: at(4))
        tree.fork(parent: mid, child: root, at: at(4))
        let chain = tree.chain(for: parent, at: at(5))
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertEqual(chain.last?.image.name, "node", "topmost known process below launchd")
    }

    /// An ancestor recognised as an agent only once its code identity arrives (a snapshot has none):
    /// deep descendants carry it.
    func testLateAgentRecognitionReachesDeepDescendants() throws {
        let catalog = AgentCatalog(agents: [AgentSpec(id: "pinned", name: LocalizedText("Pinned"), kind: .cli,
                                                      match: [AgentMatchClause(executableNames: ["pinned-agent"], teamIDs: ["TEAM1"])])])
        let tree = ProcessTree(detector: AgentDetector(catalog: catalog))
        // Linked at seed (its parent zsh is known), so its event below relinks nothing.
        var records = [snapshot(1, "/sbin/launchd", ppid: 0, start: -1000, platform: true),
                       snapshot(250, "/bin/zsh", ppid: 1, start: -950, platform: true),
                       snapshot(300, "/opt/pinned/pinned-agent", ppid: 250, start: -900)]
        for i in 0..<100 {
            records.append(snapshot(Int32(3000 + i), "/bin/sh", ppid: i == 0 ? 300 : Int32(3000 + i - 1), start: -800, platform: true))
        }
        tree.seed(records, at: at(0))
        let leaf = proc(3099, "/bin/sh", ppid: 3098, start: -800, platform: true)
        XCTAssertNil(tree.chain(for: leaf, at: at(1)).nearestAgent)
        tree.observe(proc(300, "/opt/pinned/pinned-agent", ppid: 250, start: -900, teamID: "TEAM1"), at: at(2))
        XCTAssertEqual(tree.chain(for: leaf, at: at(3)).nearestAgent, "pinned")
    }

    /// Relinking a node with descendants below one of them is refused.
    func testRelinkingBelowADescendantIsRefused() throws {
        let tree = ProcessTree(detector: AgentDetector(catalog: try defaultData().agents))
        tree.observe(P.launchd, at: t0)
        // a (parent unknown) → b; then a late event says a was forked by b.
        let a = proc(70, "/bin/a", ppid: 1, start: 1, originalPPID: 71)
        tree.observe(a, at: at(1))
        let b = proc(71, "/bin/b", ppid: 70, start: 2)
        tree.observe(b, at: at(1))
        tree.fork(parent: b, child: a, at: at(3))
        let chain = tree.chain(for: b, at: at(3))
        XCTAssertEqual(chain.map(\.image.name), ["b", "a"])
    }

    /// Only the nearest instance of an agent (and team) is recorded. A second process that looks like
    /// Claude Code (here node with its argv; any program run with argv[0] `claude` also matches) forks
    /// a deep chain and then execs /bin/sh: it must not take the real Claude Code at the top with it.
    func testASecondInstanceOfTheAgentCannotShedItByExec() {
        let shell = agentShell()
        let lookalike = h.spawn(shell, P.node(602, parent: 601, argv: claudeArgv), 3)
        var leaf = lookalike
        for i in 0..<80 {
            let child = proc(Int32(40_000 + i), "/bin/sh", ppid: leaf.pid, start: 4, platform: true, signingID: "com.apple.sh")
            h.tree.fork(parent: leaf, child: child, at: at(4))
            leaf = child
        }
        let shed = proc(602, "/bin/sh", ppid: 601, start: 3, platform: true, signingID: "com.apple.sh")
        h.tree.exec(old: lookalike, new: shed, at: at(5))
        let chain = h.tree.chain(for: leaf, at: at(6))
        XCTAssertGreaterThan(chain.count, 64)
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertEqual(h.attributor.attribute(chain: chain).key, "agent:claude-code")
        XCTAssertEqual(decide(leaf, 6).verdict, .deny)

        // It exits, and short-lived processes push the node cap past it: still never evicted, or the
        // mark that stands for Claude Code would point at nothing.
        h.tree.exit(shed, at: at(7))
        let before = h.tree.count
        for i in 0..<5 {
            let p = proc(Int32(800 + i), "/bin/sh", ppid: 1, start: 7, platform: true)
            h.tree.observe(p, at: at(7))
            h.tree.exit(p, at: at(8))
        }
        h.tree.maxNodes = before - 1
        h.tree.prune(now: at(9))
        XCTAssertNotNil(h.tree.node(pid: 602))
        let after = h.tree.chain(for: leaf, at: at(10))
        XCTAssertEqual(after.nearestAgent, "claude-code")
        XCTAssertEqual(decide(leaf, 10).verdict, .deny)
    }

    /// Claude Code starting up: zsh forked it and it exec'd node, but the process client has not
    /// delivered that exec when a file event from the child it forks arrives, so the child is linked
    /// below "zsh". The exec, the child's fork and its descendants' forks follow in order: the deep
    /// leaf must carry Claude Code, as a walk of the whole chain would.
    func testAnAgentExecSeenAfterItsChildWasLinkedReachesDeepDescendants() {
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        var forked = zsh
        forked.pid = 600; forked.pidVersion = 5999; forked.ppid = 500; forked.originalPPID = 500; forked.startTime = at(1)
        h.tree.fork(parent: zsh, child: forked, at: at(1))
        let child = proc(700, "/bin/sh", ppid: 600, start: 2, platform: true, signingID: "com.apple.sh")
        h.tree.observe(child, at: at(2))  // file client first
        var claude = P.node(600, parent: 500, argv: claudeArgv)
        claude.startTime = at(1)
        h.tree.exec(old: forked, new: claude, at: at(1))
        h.tree.fork(parent: claude, child: child, at: at(2))
        var leaf = child
        for i in 0..<80 {
            let next = proc(Int32(30_000 + i), "/bin/sh", ppid: leaf.pid, start: 3, platform: true, signingID: "com.apple.sh")
            h.tree.fork(parent: leaf, child: next, at: at(3))
            leaf = next
        }
        let chain = h.tree.chain(for: leaf, at: at(4))
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertEqual(decide(leaf, 4).verdict, .deny)
    }

    /// The same with a child the process client reports by its exec only (no fork event of its own).
    func testAnAgentExecSeenAfterItsChildWasLinkedReachesDescendantsOfTheChildsExec() {
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        var forked = zsh
        forked.pid = 600; forked.pidVersion = 5999; forked.ppid = 500; forked.originalPPID = 500; forked.startTime = at(1)
        h.tree.fork(parent: zsh, child: forked, at: at(1))
        let child = proc(700, "/bin/sh", ppid: 600, start: 2, platform: true, signingID: "com.apple.sh")
        h.tree.observe(child, at: at(2))
        var claude = P.node(600, parent: 500, argv: claudeArgv)
        claude.startTime = at(1)
        h.tree.exec(old: forked, new: claude, at: at(1))
        let execd = proc(700, "/bin/bash", ppid: 600, start: 2, platform: true, signingID: "com.apple.bash")
        h.tree.exec(old: child, new: execd, at: at(2))
        var leaf = execd
        for i in 0..<80 {
            let next = proc(Int32(31_000 + i), "/bin/sh", ppid: leaf.pid, start: 3, platform: true, signingID: "com.apple.sh")
            h.tree.fork(parent: leaf, child: next, at: at(3))
            leaf = next
        }
        XCTAssertEqual(h.tree.chain(for: leaf, at: at(4)).nearestAgent, "claude-code")
    }
}

private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    var value: Int { lock.lock(); defer { lock.unlock() }; return n }
    func increment() { lock.lock(); n += 1; lock.unlock() }
}

private extension Harness {
    var benignClassifier: BenignClassifier { BenignClassifier(catalog: data.benign) }
}
