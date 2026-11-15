import XCTest
@testable import WhoReadCore

// Round 5, process tree and AI-agent detection: attribution-1 (agent argv matching at the script
// position), attribution-3 (live nodes whose exit was missed), attribution-4 (argv kept per node) and
// native-2 (a file event analyzed after its process exec'd).

private let node = "/opt/homebrew/Cellar/node/22.9.0/bin/node"
private let bun = "/opt/homebrew/Cellar/bun/1.1.30/bin/bun"
private let deno = "/opt/homebrew/Cellar/deno/2.1.4/bin/deno"
private let python = "/usr/bin/python3"

// MARK: - attribution-1

final class AgentScriptPositionTests: XCTestCase {
    var detector: AgentDetector!

    override func setUpWithError() throws {
        detector = AgentDetector(catalog: try defaultData().agents)
    }

    func d(_ path: String, _ argv: [String]?, platform: Bool = false) -> String? {
        detector.detect(ProcessRecord(pid: 5, ppid: 1, executablePath: path, isPlatformBinary: platform, argv: argv))
    }

    /// An agent's package name or basename among the arguments is not the agent: npm installing it, a
    /// project folder or an output directory named after it, a test directory.
    func testAnAgentNamedByAnArgumentIsNotTheAgent() {
        XCTAssertNil(d(node, ["node", "/opt/homebrew/bin/npm", "install", "-g", "@anthropic-ai/claude-code"]))
        XCTAssertNil(d(node, ["node", "/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js", "install", "-g", "@anthropic-ai/claude-code"]))
        XCTAssertNil(d(node, ["node", "/opt/homebrew/bin/npm", "i", "-g", "@openai/codex"]))
        XCTAssertNil(d(node, ["node", "/opt/homebrew/bin/npm", "update", "-g", "@google/gemini-cli", "opencode-ai"]))
        XCTAssertNil(d(node, ["node", "/opt/homebrew/bin/npx", "tsc", "-p", "/Users/alice/code/codex"]))
        XCTAssertNil(d(node, ["node", "/Users/alice/code/app/node_modules/.bin/tsc", "-p", "/Users/alice/code/codex"]))
        XCTAssertNil(d(node, ["node", "build.js", "--out", "dist/claude"]))
        XCTAssertNil(d(node, ["node", "--no-warnings", "scripts/release.js", "/Users/alice/code/gemini"]))
        XCTAssertNil(d(python, ["python3", "-m", "pytest", "tests/aider"], platform: true))
        XCTAssertNil(d(python, ["python3", "/Users/alice/code/tools/lint.py", "aider.main"], platform: true))
        XCTAssertNil(d(bun, ["bun", "install", "-g", "@anthropic-ai/claude-code"]))
        XCTAssertNil(d(bun, ["bun", "add", "-g", "opencode-ai"]))
        XCTAssertNil(d(bun, ["bun", "run", "build", "--outdir", "dist/claude"]))
        XCTAssertNil(d(deno, ["deno", "install", "-g", "npm:@anthropic-ai/claude-code"]))
    }

    /// The script or module an interpreter runs still makes it the agent, also after options the parser
    /// knows, and for bun and deno after a `run` or `x` subcommand.
    func testTheScriptAnInterpreterRunsIsTheAgent() {
        XCTAssertEqual(d(node, ["node", "/opt/homebrew/bin/claude"]), "claude-code")
        XCTAssertEqual(d(node, ["node", "/opt/homebrew/bin/claude", "--print", "hi"]), "claude-code")
        XCTAssertEqual(d(node, ["node", "--no-warnings", "--enable-source-maps", "/opt/homebrew/bin/claude"]), "claude-code")
        XCTAssertEqual(d(node, ["node", "/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js", "-p", "x"]), "claude-code")
        XCTAssertEqual(d(node, ["node", "/Users/alice/.npm/_npx/6b2a/node_modules/.bin/claude"]), "claude-code")
        XCTAssertEqual(d(node, ["node", "/opt/homebrew/bin/codex", "exec", "ls"]), "codex")
        XCTAssertEqual(d(node, ["node", "/opt/homebrew/lib/node_modules/@google/gemini-cli/dist/index.js"]), "gemini-cli")
        XCTAssertEqual(d(node, ["node", "/opt/homebrew/bin/opencode"]), "opencode")
        XCTAssertEqual(d(python, ["python3", "-m", "aider"], platform: true), "aider")
        XCTAssertEqual(d(python, ["python3", "-m", "aider.main", "--model", "x"], platform: true), "aider")
        XCTAssertEqual(d(python, ["python3", "-I", "/Users/alice/.local/bin/aider", "--model", "x"], platform: true), "aider")
        XCTAssertEqual(d(bun, ["bun", "run", "/Users/alice/.bun/bin/claude"]), "claude-code")
        XCTAssertEqual(d(bun, ["bun", "x", "@anthropic-ai/claude-code"]), "claude-code")
        XCTAssertEqual(d(bun, ["bunx", "@anthropic-ai/claude-code"]), "claude-code")
        XCTAssertEqual(d(bun, ["bun", "/Users/alice/.bun/bin/codex"]), "codex")
        XCTAssertEqual(d(deno, ["deno", "x", "npm:@google/gemini-cli"]), "gemini-cli")
    }

    /// Where the script position cannot be told (an option the parser does not know, a subcommand after
    /// runtime options), every argument counts, as before: missing an agent is the fail-open direction.
    func testAnUnknownScriptPositionFallsBackToEveryArgument() {
        XCTAssertEqual(d(deno, ["deno", "run", "-A", "npm:@anthropic-ai/claude-code"]), "claude-code")
        XCTAssertEqual(d(deno, ["deno", "run", "--allow-all", "npm:@google/gemini-cli"]), "gemini-cli")
        XCTAssertEqual(d(node, ["node", "--experimental-sqlite", "/opt/homebrew/bin/claude"]), "claude-code")
        XCTAssertEqual(d(bun, ["bun", "--smol", "run", "/Users/alice/.bun/bin/claude"]), "claude-code")
        // Code on the command line has no script either.
        XCTAssertNil(d(node, ["node", "-e", "console.log(1)"]))
    }

    /// The chain of an npm install of an agent from Terminal carries no agent, nor do the scripts it runs.
    func testInstallingAnAgentWithNpmIsChargedToTheApp() throws {
        let h = try Harness()
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let npm = h.spawn(zsh, P.node(600, parent: 500, argv: ["node", "/opt/homebrew/bin/npm", "install", "-g", "@anthropic-ai/claude-code"]), 1)
        let postinstall = h.spawn(npm, proc(601, "/bin/sh", ppid: 600, start: 2, platform: true, argv: ["sh", "-c", "node scripts/postinstall.js"]), 2)
        let chain = h.tree.chain(for: postinstall, at: at(3))
        XCTAssertNil(chain.nearestAgent)
        XCTAssertEqual(h.attributor.attribute(chain: chain).key, "app:/system/applications/utilities/terminal.app")
        let vault = h.open(npm, "/Users/alice/WhoReadTestVault/aws/credentials", 3)
        XCTAssertEqual(vault.events.first?.responsible.key, "app:/system/applications/utilities/terminal.app")
        XCTAssertNil(vault.events.first?.agentID)
        // The agent it installed is one when it runs.
        let claude = h.spawn(zsh, P.node(700, parent: 500, argv: ["node", "/opt/homebrew/bin/claude"]), 4)
        XCTAssertEqual(h.tree.chain(for: claude, at: at(5)).nearestAgent, "claude-code")
    }
}

// MARK: - native-2

private let vaultKey = "/Users/alice/WhoReadTestVault/ssh/id_ed25519"

final class StaleImageTests: XCTestCase {
    var h: Harness!

    override func setUpWithError() throws {
        h = try Harness(learningDays: 0)
    }

    func names(_ chain: [ProcessNode]) -> [String] { chain.map(\.image.name) }

    /// What the AUTH path decides (Enforcer.decide) for a read of the vault key, "trust Apple programs" on.
    func decide(_ p: ProcessRecord, _ t: TimeInterval) -> RuleDecision {
        let chain = h.tree.chain(for: p, at: at(t))
        let c = h.classifier.classify(vaultKey)!
        let target = EvaluationTarget(path: h.normalizer.normalize(vaultKey), access: .read,
                                      categories: [TargetCategory(id: c.categoryID, severity: c.severity)])
        return h.rules.evaluate(process: chain.first?.image ?? p, chain: chain, targets: [target], enforcementActive: true,
                                now: at(t), ask: AskPolicy(enabled: true, trustApplePrograms: true,
                                                           benignChain: h.analyzer.isBenignChain(chain)))
    }

    /// Native source: zsh (500) reads the key and that file event waits in the analysis queue while the
    /// process client sees zsh exec evil and evil fork 501. The late analysis of zsh's record must not
    /// turn node 500 back into zsh: 501's cat would get an all-Apple chain (Terminal → zsh → cat) and
    /// "trust Apple programs" would let it read the key without asking.
    func testAFileEventAnalyzedAfterAnExecDoesNotRollTheProcessBack() {
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        var evil = proc(500, "/Users/alice/bin/evil", ppid: 100, start: 0, argv: ["evil"])
        evil.pidVersion = 5001
        h.exec(zsh, evil, 1)
        var child = evil
        child.pid = 501
        child.pidVersion = 5010
        child.ppid = 500
        child.originalPPID = 500
        child.startTime = at(2)
        h.fork(evil, child, 2)

        // zsh's read, analyzed now: it still shows zsh, which did read the key.
        let late = h.open(zsh, vaultKey, 3)
        XCTAssertEqual(late.events.first?.process.executablePath, "/bin/zsh")
        XCTAssertEqual(late.events.first?.chain.map(\.name), ["launchd", "Terminal", "zsh"])
        XCTAssertEqual(h.tree.node(pid: 500)?.image.executablePath, "/Users/alice/bin/evil")
        XCTAssertEqual(h.tree.node(pid: 500)?.pidVersions, [4999, 5000, 5001], "no rollback, no reordering")

        var cat = P.cat(501, parent: 500)
        cat.pidVersion = 5011
        cat.startTime = at(2)
        h.exec(child, cat, 4)
        let chain = h.tree.chain(for: cat, at: at(5))
        XCTAssertEqual(names(chain), ["cat", "evil", "Terminal", "launchd"])
        XCTAssertFalse(AskPolicy.isTrustableAppleProgram(cat, chain: chain))
        let decision = decide(cat, 5)
        XCTAssertEqual(decision.verdict, .ask)
        XCTAssertNotEqual(decision.reason, .trustedApple)
    }

    /// The identity a process got from its current image came after an older image: an event from
    /// before zsh exec'd Claude Code is charged to Terminal. One it holds from an earlier image (Claude
    /// Code exec'd cat) covers the older events too.
    func testAStaleImageCarriesOnlyTheAgentItWasThen() {
        let terminal = "app:/system/applications/utilities/terminal.app"
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        var claude = P.node(500, parent: 100, argv: ["node", "/opt/homebrew/bin/claude"])
        claude.pidVersion = 5001
        h.exec(zsh, claude, 1)
        let before = h.open(zsh, vaultKey, 2)
        XCTAssertEqual(before.events.first?.responsible.key, terminal)
        XCTAssertNil(before.events.first?.agentID)
        XCTAssertEqual(h.tree.node(pid: 500)?.agentID, "claude-code")
        XCTAssertEqual(h.open(claude, vaultKey, 3).events.first?.agentID, "claude-code")

        var cat = P.cat(500, parent: 100)
        cat.pidVersion = 5002
        h.exec(claude, cat, 4)
        let held = h.open(claude, vaultKey, 5)
        XCTAssertEqual(held.events.first?.agentID, "claude-code")
        XCTAssertEqual(held.events.first?.process.executablePath, claude.executablePath)
        XCTAssertEqual(h.tree.node(pid: 500)?.image.executablePath, "/bin/cat")
    }

    /// eslogger delivers in order, so a record with a pidversion the node has not seen is an exec that
    /// was missed (dropped, or lost while eslogger restarted): it is still adopted.
    func testAMissedExecInEsloggerOrderIsStillAdopted() {
        _ = h.spawn(P.terminal, P.zsh(500, parent: 100))
        var cat = P.cat(500, parent: 100)
        cat.pidVersion = 5001
        let out = h.open(cat, vaultKey, 1)
        XCTAssertEqual(out.events.first?.process.executablePath, "/bin/cat")
        XCTAssertEqual(h.tree.node(pid: 500)?.image.executablePath, "/bin/cat")
        XCTAssertEqual(h.tree.node(pid: 500)?.pidVersions, [4999, 5000, 5001])
        // What it forks next is below cat.
        let child = h.spawn(cat, P.zsh(502, parent: 500), 2)
        XCTAssertEqual(names(h.tree.chain(for: child, at: at(3))), ["zsh", "cat", "Terminal", "launchd"])
        // Another record of the image it has now changes nothing.
        _ = h.open(cat, vaultKey, 4)
        XCTAssertEqual(h.tree.node(pid: 500)?.pidVersions, [4999, 5000, 5001])
        XCTAssertEqual(h.tree.node(pid: 500)?.image.executablePath, "/bin/cat")
    }
}

// MARK: - attribution-4

final class BoundedArgvTests: XCTestCase {
    var tree: ProcessTree!
    var detector: AgentDetector!

    override func setUpWithError() throws {
        detector = AgentDetector(catalog: try defaultData().agents)
        tree = ProcessTree(detector: detector)
    }

    static func bytes(_ argv: [String]?) -> Int { (argv ?? []).reduce(0) { $0 + $1.utf8.count } }

    /// What the tree may keep of one argv: the budget, plus one marker element.
    static let bound = ProcessTree.maxArgvBytes + 32

    /// A process running as the user can give every child up to ARG_MAX (1 MiB) of argv; each node kept
    /// all of it, tombstones too, for the whole TTL, in a daemon that runs as root.
    func testANodeKeepsABoundedArgv() {
        let huge = String(repeating: "x", count: 300 * 1024)
        tree.observe(proc(600, "/bin/sh", platform: true, argv: ["sh", "-c", huge, huge, huge]), at: at(0))
        let few = tree.node(pid: 600)?.image.argv ?? []
        XCTAssertEqual(few.count, 5)
        XCTAssertLessThanOrEqual(Self.bytes(few), 5 * 1100)
        XCTAssertEqual(few[2], String(repeating: "x", count: 1024) + "…", "cut, and says so")

        let paths = (0..<20_000).map { "/Users/alice/code/project/Sources/File\($0).swift" }
        tree.observe(proc(601, "/usr/bin/grep", platform: true, argv: ["grep", "-l", "x"] + paths), at: at(0))
        let many = tree.node(pid: 601)?.image.argv ?? []
        XCTAssertLessThanOrEqual(Self.bytes(many), Self.bound)
        XCTAssertGreaterThan(many.count, 8)
        XCTAssertEqual(Array(many.dropLast()), Array((["grep", "-l", "x"] + paths).prefix(many.count - 1)))
        XCTAssertEqual(many.last, "…(+\(20_003 - (many.count - 1)))", "how many elements were not kept")
    }

    /// Seed, exec, the parent resolver and observe all go through one entry point, and a tombstone
    /// keeps what its node kept.
    func testEveryWayIntoTheTreeIsBounded() {
        let huge = Array(repeating: String(repeating: "y", count: 64 * 1024), count: 16)
        tree.seed([ProcessRecord(pid: 700, ppid: 1, executablePath: "/bin/sh", isPlatformBinary: true, argv: ["sh"] + huge,
                                 startTime: at(-5))], at: at(0))
        let zsh = proc(701, "/bin/zsh", ppid: 1, start: 0, platform: true)
        tree.observe(zsh, at: at(0))
        var sh = proc(701, "/bin/sh", ppid: 1, start: 0, platform: true, argv: ["sh"] + huge)
        sh.pidVersion = 7011
        tree.exec(old: zsh, new: sh, at: at(1))
        tree.parentResolver = { pid in
            pid == 702 ? ProcessRecord(pid: 702, ppid: 1, executablePath: "/bin/bash", isPlatformBinary: true,
                                       argv: ["bash"] + huge, startTime: at(-10)) : nil
        }
        // (libproc has no fork-time parent: bash stays unlinked.)
        XCTAssertEqual(tree.chain(for: proc(703, "/bin/cat", ppid: 702, start: 2, platform: true), at: at(2)).map(\.image.name),
                       ["cat", "bash"])
        tree.exit(sh, at: at(3))
        for pid: Int32 in [700, 701, 702] {
            let argv = tree.node(pid: pid)?.image.argv
            XCTAssertLessThanOrEqual(Self.bytes(argv), Self.bound, "pid \(pid)")
            XCTAssertEqual(argv?.last, "…(+1)", "pid \(pid)")
        }
        XCTAssertNotNil(tree.node(pid: 701)?.exitedAt)
    }

    /// Display (ArgvRedactor, ChainLink) and agent and owner detection see what they saw before: the
    /// redactor reads the first 8 elements and the first 1024 characters of each, the detectors argv[0]
    /// and the script position. An element cut here ends in "…", so the redactor still sees it is cut.
    func testDisplayAndDetectionAreUnchangedForOrdinaryCommandLines() throws {
        let heredoc = "cat > Sources/App/Main.swift <<'EOF'\n"
            + String(repeating: "let value = compute(42) // token=abc123\n", count: 600) + "EOF"
        let lines: [[String]] = [
            ["/bin/zsh", "-c", heredoc],
            ["/bin/zsh", "-c", "curl -s -H 'Authorization: Bearer " + String(repeating: "Q", count: 3000) + "' https://example.com/api"],
            ["node", "/opt/homebrew/bin/claude", "--print", String(repeating: "文", count: 2000)],
            ["git", "commit", "-m", String(repeating: "word ", count: 500)],
            ["clang"] + (0..<40).map { "-I/Users/alice/code/include/\($0)" },
            ["node", "--require=" + String(repeating: "r", count: 5000), "/opt/homebrew/bin/claude"],
            ["cat", "/Users/alice/WhoReadTestVault/aws/credentials"],
            ["/usr/bin/python3", "-m", "aider", "--message", String(repeating: "fix it ", count: 400)],
        ]
        for argv in lines {
            let kept = ProcessTree.boundedArgv(argv)
            let label = "\(argv.prefix(2))"
            XCTAssertEqual(kept.prefix(8).map(ArgvRedactor.bounded), argv.prefix(8).map(ArgvRedactor.bounded), label)
            XCTAssertEqual(kept.count, argv.count, label)
            XCTAssertEqual(ArgvRedactor.redact(kept), ArgvRedactor.redact(argv), label)
            XCTAssertEqual(ArgvRedactor.redact(kept, maxArgs: 6, maxLength: 200), ArgvRedactor.redact(argv, maxArgs: 6, maxLength: 200), label)
            let path = argv[0].contains("python") ? "/usr/bin/python3" : node
            XCTAssertEqual(detector.detect(proc(600, path, argv: kept)), detector.detect(proc(600, path, argv: argv)), label)
            XCTAssertEqual(IdentitySpec.scriptArgument(kept), IdentitySpec.scriptArgument(argv), label)
        }
        // A node: its chain link and the event's process as before.
        let claude = ["node", "/opt/homebrew/bin/claude", "--append-system-prompt", String(repeating: "be brief ", count: 1000)]
        tree.observe(proc(610, node, argv: claude), at: at(0))
        let n = try XCTUnwrap(tree.node(pid: 610))
        XCTAssertEqual(n.agentID, "claude-code")
        var full = n
        full.image.argv = claude
        XCTAssertEqual(ChainLink(node: n), ChainLink(node: full))
        XCTAssertEqual(ArgvRedactor.redact(n.image), ArgvRedactor.redact(full.image))
        let h = try Harness()
        XCTAssertTrue(h.classifier.isOwner(n.image, of: "claude-sessions"))
    }

    /// Past the budget, elements are dropped from the end, never from the first 8, and bounding again
    /// changes nothing (libproc records are bounded where they are read, then again by the tree).
    func testOnlyTheTailOfALongCommandLineIsDropped() {
        let objects = ["ld", "-o", "app"] + (0..<5000).map { "/Users/alice/build/obj/file\($0).o" }
        let kept = ProcessTree.boundedArgv(objects)
        XCTAssertEqual(Array(kept.prefix(8)), Array(objects.prefix(8)))
        XCTAssertLessThanOrEqual(Self.bytes(kept), Self.bound)
        XCTAssertEqual(kept.last, "…(+\(objects.count - kept.count + 1))")
        XCTAssertEqual(ProcessTree.boundedArgv(kept), kept)
        let cut = ProcessTree.boundedArgv(["sh", "-c", String(repeating: "z", count: 100_000)])
        XCTAssertEqual(ProcessTree.boundedArgv(cut), cut)
        // Characters of many scalars each: bytes decide, at a scalar boundary.
        let zalgo = "e" + String(repeating: "\u{301}", count: 50_000)
        let odd = ProcessTree.boundedArgv(["echo", zalgo])
        XCTAssertLessThanOrEqual(odd[1].utf8.count, 4 * 1024 + 3)
        XCTAssertTrue(odd[1].hasSuffix("…"))
        XCTAssertEqual(ProcessTree.boundedArgv(odd), odd)
        // Short command lines are kept as they are.
        XCTAssertEqual(ProcessTree.boundedArgv(["cat", "a", "b"]), ["cat", "a", "b"])
        XCTAssertEqual(ProcessTree.boundedArgv([]), [])
    }
}

// MARK: - attribution-3

/// A liveness probe for tests: which process instances run, and what was asked.
private final class FakeLiveness: @unchecked Sendable {
    private let lock = NSLock()
    private var running: [Int32: Date] = [:]
    private var unknown: Set<Int32> = []
    private(set) var asked: [Int32] = []

    func run(_ p: ProcessRecord) { lock.lock(); running[p.pid] = p.startTime; lock.unlock() }
    func cannotTell(_ pid: Int32) { lock.lock(); unknown.insert(pid); lock.unlock() }
    func takeAsked() -> [Int32] { lock.lock(); defer { asked = []; lock.unlock() }; return asked }

    var probe: ProcessTree.LivenessProbe {
        { [self] pid, start in
            lock.lock(); defer { lock.unlock() }
            asked.append(pid)
            if unknown.contains(pid) { return nil }
            guard let s = running[pid] else { return false }
            return abs(s.timeIntervalSince(start)) <= ProcessTree.startTimeTolerance
        }
    }
}

final class MissedExitTests: XCTestCase {
    var detector: AgentDetector!

    override func setUpWithError() throws {
        detector = AgentDetector(catalog: try defaultData().agents)
    }

    func names(_ chain: [ProcessNode]) -> [String] { chain.map(\.image.name) }

    /// A pid has one live instance at a time: a later instance means the earlier one exited, though its
    /// exit event was lost. An agent that goes so changes what is saved across restarts.
    func testANewInstanceOfAPidRetiresTheEarlierOne() {
        let tree = ProcessTree(detector: detector)
        let claude = proc(700, node, ppid: 1, start: 0, argv: ["node", "/opt/homebrew/bin/claude"])
        tree.observe(claude, at: at(0))
        XCTAssertEqual(tree.liveCount, 2, "Claude Code and launchd")
        XCTAssertEqual(tree.agentAncestry().map(\.pid), [700])
        let generation = tree.agentAncestryGeneration
        // Its exit was dropped; the pid is reused.
        tree.observe(proc(700, "/bin/sh", ppid: 1, start: 50, platform: true), at: at(50))
        XCTAssertEqual(tree.count, 3)
        XCTAssertEqual(tree.liveCount, 2, "the new sh and launchd")
        XCTAssertEqual(tree.agentAncestry(), [])
        XCTAssertNotEqual(tree.agentAncestryGeneration, generation, "what is saved across restarts changed")
        // A late event from a child the old instance forked still finds it (a tombstone now).
        let child = proc(701, "/bin/cat", ppid: 700, start: 10, platform: true)
        let chain = tree.chain(for: child, at: at(51))
        XCTAssertEqual(names(chain), ["cat", "node", "launchd"])
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        // A record within the start time tolerance is the same instance, not a new one.
        var same = proc(700, "/bin/sh", ppid: 1, start: 50.001, platform: true)
        same.pidVersion = 7000
        tree.observe(same, at: at(52))
        XCTAssertEqual(tree.liveCount, 3, "sh, cat and launchd")
    }

    /// Maintenance (prune) checks live nodes not seen for a while against libproc, injected here: one
    /// whose process is gone, or whose pid another process holds now, missed its exit and becomes a
    /// tombstone. At most `livenessChecksPerPass` per pass; a node it confirms is not asked again soon.
    func testMaintenanceRetiresLiveNodesWhoseProcessIsGone() {
        let tree = ProcessTree(detector: detector, tombstoneTTL: 600)
        let live = FakeLiveness()
        tree.livenessProbe = live.probe
        tree.livenessChecksPerPass = 100
        let zsh = proc(500, "/bin/zsh", ppid: 1, start: 0, platform: true)
        tree.observe(zsh, at: at(0))
        live.run(zsh)
        for i in 0..<1000 {
            let p = proc(Int32(1000 + i), "/usr/bin/true", ppid: 500, start: 1 + Double(i) * 0.001, platform: true)
            tree.fork(parent: zsh, child: p, at: at(1 + Double(i) * 0.001))
        }
        // pid 1999 now belongs to another process; pid 1998 libproc cannot tell.
        live.run(proc(1999, "/bin/sh", ppid: 1, start: 400))
        live.cannotTell(1998)
        // Seen recently (and zsh, which forked it): not asked.
        let recent = proc(3000, "/usr/bin/true", ppid: 500, start: 290, platform: true)
        tree.fork(parent: zsh, child: recent, at: at(290))
        live.run(recent)
        XCTAssertEqual(tree.liveCount, 1003)

        tree.prune(now: at(500))
        let firstPass = live.takeAsked()
        XCTAssertEqual(firstPass.count, 100, "bounded")
        XCTAssertEqual(firstPass.first, 1000, "least recently seen first")
        XCTAssertEqual(tree.liveCount, 1003 - 100)
        for pass in 1...20 { tree.prune(now: at(500 + Double(pass))) }
        let later = live.takeAsked()
        XCTAssertEqual(later.filter { $0 == 1998 }.count, 1, "not asked again in the next minutes")
        XCTAssertFalse(later.contains(3000))
        XCTAssertFalse(later.contains(500))
        XCTAssertEqual(tree.liveCount, 4, "zsh, the process libproc cannot tell about, the recent one, launchd")
        XCTAssertNil(tree.node(pid: 500)?.exitedAt)
        XCTAssertNil(tree.node(pid: 1998)?.exitedAt)
        XCTAssertNotNil(tree.node(pid: 1999)?.exitedAt)
        // Tombstones go after their TTL like any other.
        tree.prune(now: at(2000))
        XCTAssertEqual(tree.count, 4)
        // Without a probe (tests, replay) nothing is asked.
        tree.livenessProbe = nil
        XCTAssertEqual(tree.reconcileLiveness(now: at(5000)), 0)
    }

    /// The consequence for restarts: ghosts below an agent whose shell exited rank first in the saved
    /// agent ancestry (their parent is gone, they are the oldest) and crowded out a real orphaned job.
    func testGhostsDoNotCrowdOutTheAgentAncestryThatIsSaved() {
        let tree = ProcessTree(detector: detector)
        let live = FakeLiveness()
        let claude = proc(600, node, ppid: 1, start: 0, argv: ["node", "/opt/homebrew/bin/claude"])
        tree.observe(claude, at: at(0))
        live.run(claude)
        let bash = proc(601, "/bin/bash", ppid: 600, start: 1, platform: true)
        tree.fork(parent: claude, child: bash, at: at(1))
        for i in 0..<300 {
            tree.fork(parent: bash, child: proc(Int32(2000 + i), "/usr/bin/cc", ppid: 601, start: 2, platform: true), at: at(2))
        }
        let job = proc(3000, "/usr/bin/caffeinate", ppid: 601, start: 10, platform: true)
        tree.fork(parent: bash, child: job, at: at(10))
        live.run(job)
        tree.exit(bash, at: at(11))
        XCTAssertFalse(tree.agentAncestry(limit: 100).contains { $0.pid == 3000 }, "crowded out")
        tree.livenessProbe = live.probe
        for pass in 0..<4 { tree.prune(now: at(400 + Double(pass))) }
        XCTAssertEqual(Set(tree.agentAncestry(limit: 100).map(\.pid)), [600, 3000])
    }

    /// When no tombstone is left to evict, the node cap evicts the least recently seen live leaves
    /// (processes that were never an agent first): the tree stays bounded even if every exit is lost.
    /// A process evicted while it still runs comes back from its next event, below its parent.
    func testTheNodeCapEvictsLiveLeavesWhenNoTombstoneIsLeft() {
        let tree = ProcessTree(detector: detector, maxNodes: 100)
        let zsh = proc(500, "/bin/zsh", ppid: 1, start: 0, platform: true)
        tree.observe(zsh, at: at(0))
        let claude = proc(600, node, ppid: 500, start: 0.5, argv: ["node", "/opt/homebrew/bin/claude"])
        tree.fork(parent: zsh, child: claude, at: at(0.5))
        for i in 0..<5000 {
            let p = proc(Int32(1000 + i), "/usr/bin/true", ppid: 500, start: 1 + Double(i) * 0.001, platform: true)
            tree.fork(parent: zsh, child: p, at: at(1 + Double(i) * 0.001))
        }
        XCTAssertEqual(tree.count, 5003)
        tree.prune(now: at(10_000))
        XCTAssertLessThanOrEqual(tree.count, 100)
        XCTAssertNotNil(tree.node(pid: 600), "the agent goes last")
        XCTAssertNotNil(tree.node(pid: 5999), "the most recently seen stay")
        XCTAssertNil(tree.node(pid: 1000))
        let back = proc(1000, "/usr/bin/true", ppid: 500, start: 1, platform: true)
        XCTAssertEqual(names(tree.chain(for: back, at: at(10_001))), ["true", "zsh", "launchd"])

        // A chain of live processes (each forked the next, every exit lost): leaves go first, then the
        // processes that became leaves, within one pass.
        let deep = ProcessTree(detector: detector, maxNodes: 50)
        var parent = proc(2, "/bin/sh", ppid: 1, start: 0, platform: true)
        deep.observe(parent, at: at(0))
        for i in 0..<200 {
            let child = proc(Int32(10 + i), "/bin/sh", ppid: parent.pid, start: 1 + Double(i) * 0.01, platform: true)
            deep.fork(parent: parent, child: child, at: at(1 + Double(i) * 0.01))
            parent = child
        }
        deep.prune(now: at(10_000))
        XCTAssertEqual(deep.count, 50)
        XCTAssertEqual(deep.chain(nodeID: deep.node(pid: 10 + 47)!.id).count, 50, "the top of the chain is what stays")
    }
}
