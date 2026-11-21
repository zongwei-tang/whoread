import XCTest
@testable import WhoReadCore

// Repairs of the round-5 process tree fixes, after their verification: attribution-1 (where the
// script is for deno, bun and node options the shared parser does not know, and code given on the
// command line), native-2 (a late record after many execs, and the agent of an image two execs back),
// and the argv bounds (time under the tree lock, the count of dropped elements, the script position).

private let node = "/opt/homebrew/Cellar/node/22.9.0/bin/node"
private let bun = "/opt/homebrew/Cellar/bun/1.1.30/bin/bun"
private let deno = "/opt/homebrew/Cellar/deno/2.1.4/bin/deno"
private let python = "/usr/bin/python3"
private let vaultKey = "/Users/alice/WhoReadTestVault/ssh/id_ed25519"

final class R5VAgentScriptPositionTests: XCTestCase {
    var detector: AgentDetector!

    override func setUpWithError() throws {
        detector = AgentDetector(catalog: try defaultData().agents)
    }

    func d(_ path: String, _ argv: [String]?, platform: Bool = false) -> String? {
        detector.detect(ProcessRecord(pid: 5, ppid: 1, executablePath: path, isPlatformBinary: platform, argv: argv))
    }

    /// Honest commands with an agent's name among their arguments, after options of deno and bun, node
    /// options the shared parser does not list, or code given on the command line: not the agent.
    func testAnAgentNamedAfterRuntimeOptionsIsNotTheAgent() {
        XCTAssertNil(d(deno, ["deno", "run", "-A", "scripts/build.ts", "--out", "dist/claude"]))
        XCTAssertNil(d(deno, ["deno", "run", "--allow-read", "--allow-write", "scripts/gen.ts", "/Users/alice/code/codex"]))
        XCTAssertNil(d(deno, ["deno", "run", "-A", "npm:vite", "build", "--outDir", "dist/gemini"]))
        XCTAssertNil(d(deno, ["deno", "run", "-c", "deno.json", "--allow-net=api.example.com", "main.ts", "claude"]))
        XCTAssertNil(d(deno, ["deno", "task", "claude"]))
        XCTAssertNil(d(node, ["node", "--openssl-legacy-provider", "node_modules/.bin/webpack", "--output-path", "dist/claude"]))
        XCTAssertNil(d(node, ["node", "--test", "--test-reporter=spec", "test/", "--", "claude"]))
        XCTAssertNil(d(node, ["node", "--unhandled-rejections=strict", "dist/index.js", "/Users/alice/code/claude"]))
        XCTAssertNil(d(node, ["node", "--max-http-header-size=16384", "server.js", "codex"]))
        XCTAssertNil(d(node, ["node", "--inspect-port", "9229", "server.js", "codex"]))
        XCTAssertNil(d(node, ["node", "-c", "scripts/check.js", "claude"]))
        XCTAssertNil(d(bun, ["bun", "--watch", "run", "index.ts", "codex"]))
        XCTAssertNil(d(bun, ["bun", "-e", "console.log(1)", "claude"]))
        XCTAssertNil(d(python, ["python3", "-c", "import sys; print(sys.argv)", "aider"], platform: true))
    }

    /// Real launches still are the agent, with those options before the script.
    func testTheAgentAfterRuntimeOptionsIsStillTheAgent() {
        XCTAssertEqual(d(deno, ["deno", "run", "-A", "npm:@anthropic-ai/claude-code"]), "claude-code")
        XCTAssertEqual(d(deno, ["deno", "run", "--allow-all", "--no-config", "npm:@anthropic-ai/claude-code", "-p", "hi"]), "claude-code")
        XCTAssertEqual(d(deno, ["deno", "run", "-c", "deno.json", "-A", "npm:@google/gemini-cli"]), "gemini-cli")
        XCTAssertEqual(d(deno, ["deno", "-q", "run", "--allow-env", "npm:@openai/codex"]), "codex")
        XCTAssertEqual(d(deno, ["deno", "/Users/alice/.deno/bin/claude"]), "claude-code")
        XCTAssertEqual(d(node, ["node", "--inspect=9229", "/opt/homebrew/bin/claude"]), "claude-code")
        XCTAssertEqual(d(node, ["node", "--openssl-legacy-provider", "/opt/homebrew/bin/claude"]), "claude-code")
        XCTAssertEqual(d(node, ["node", "--inspect-port", "9229", "/opt/homebrew/bin/codex"]), "codex")
        XCTAssertEqual(d(bun, ["bunx", "--bun", "@anthropic-ai/claude-code"]), "claude-code")
        XCTAssertEqual(d(bun, ["bun", "--watch", "run", "/Users/alice/.bun/bin/claude"]), "claude-code")
        XCTAssertEqual(d(bun, ["bun", "--preload", "./setup.ts", "/Users/alice/.bun/bin/opencode"]), "opencode")
        XCTAssertEqual(d(python, ["python3", "-m", "aider", "--model", "x"], platform: true), "aider")
    }
}

final class R5VStaleImageTests: XCTestCase {
    var h: Harness!

    override func setUpWithError() throws {
        h = try Harness(learningDays: 0)
    }

    func names(_ chain: [ProcessNode]) -> [String] { chain.map(\.image.name) }

    func decide(_ p: ProcessRecord, _ t: TimeInterval) -> RuleDecision {
        let chain = h.tree.chain(for: p, at: at(t))
        let c = h.classifier.classify(vaultKey)!
        let target = EvaluationTarget(path: h.normalizer.normalize(vaultKey), access: .read,
                                      categories: [TargetCategory(id: c.categoryID, severity: c.severity)])
        return h.rules.evaluate(process: chain.first?.image ?? p, chain: chain, targets: [target], enforcementActive: true,
                                now: at(t), ask: AskPolicy(enabled: true, trustApplePrograms: true,
                                                           benignChain: h.analyzer.isBenignChain(chain)))
    }

    /// zsh's read waits in the native source's analysis queue while zsh execs evil and evil execs itself
    /// seven times: zsh's pidversion has left the kept history by then. Its late record must not be taken
    /// for an exec that was missed: node 500 would turn back into zsh, and stay so (evil's own records
    /// would then look older than the image it had last), giving everything evil starts an all-Apple chain.
    func testALateRecordAfterManyExecsDoesNotRollTheProcessBack() {
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        var current = zsh
        for k in 1...8 {
            var evil = proc(500, "/Users/alice/bin/evil", ppid: 100, start: 0, argv: ["evil"])
            evil.pidVersion = UInt32(5000 + k)
            h.exec(current, evil, Double(k) / 10)
            current = evil
        }
        let late = h.open(zsh, vaultKey, 2)
        XCTAssertEqual(late.events.first?.process.executablePath, "/bin/zsh", "the event shows the image that read it")
        XCTAssertEqual(h.tree.node(pid: 500)?.image.executablePath, "/Users/alice/bin/evil")
        // evil's own records keep it evil.
        _ = h.open(current, vaultKey, 3)
        XCTAssertEqual(h.tree.node(pid: 500)?.image.executablePath, "/Users/alice/bin/evil")

        var child = current
        child.pid = 501
        child.pidVersion = 6000
        child.ppid = 500
        child.originalPPID = 500
        child.startTime = at(4)
        h.fork(current, child, 4)
        var cat = P.cat(501, parent: 500)
        cat.pidVersion = 6001
        cat.startTime = at(4)
        h.exec(child, cat, 5)
        let chain = h.tree.chain(for: cat, at: at(6))
        XCTAssertEqual(names(chain), ["cat", "evil", "Terminal", "launchd"])
        XCTAssertFalse(AskPolicy.isTrustableAppleProgram(cat, chain: chain))
        XCTAssertNotEqual(decide(cat, 6).reason, .trustedApple)
    }

    /// zsh execs Claude Code, Claude Code execs cat: a late record of zsh is charged to Terminal, not to
    /// the agent the process became two execs later; Claude Code's own late record is the agent's.
    func testAnImageTwoExecsBackCarriesTheAgentItWasThen() {
        let terminal = "app:/system/applications/utilities/terminal.app"
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        var claude = P.node(500, parent: 100, argv: ["node", "/opt/homebrew/bin/claude"])
        claude.pidVersion = 5001
        h.exec(zsh, claude, 1)
        var cat = P.cat(500, parent: 100)
        cat.pidVersion = 5002
        h.exec(claude, cat, 2)

        let before = h.open(zsh, vaultKey, 3)
        XCTAssertNil(before.events.first?.agentID)
        XCTAssertEqual(before.events.first?.responsible.key, terminal)
        XCTAssertEqual(h.open(claude, vaultKey, 4).events.first?.agentID, "claude-code")
        XCTAssertEqual(h.open(cat, vaultKey, 5).events.first?.agentID, "claude-code", "cat still runs as the agent")
    }
}

final class R5VBoundedArgvTests: XCTestCase {
    var tree: ProcessTree!
    var detector: AgentDetector!

    override func setUpWithError() throws {
        detector = AgentDetector(catalog: try defaultData().agents)
        tree = ProcessTree(detector: detector)
    }

    /// One megabyte of argv made of long grapheme clusters ("e" and 1000 combining accents, repeated):
    /// bounding it walks a few kilobytes, not the whole element, and the tree lock is not held for it.
    func testBoundingAnArgvOfLongGraphemesTakesLittleTime() {
        let cluster = "e" + String(repeating: "\u{301}", count: 1000)
        let element = String(repeating: cluster, count: 500)
        XCTAssertGreaterThan(element.utf8.count, 1_000_000)
        let start = Date()
        let kept = ProcessTree.boundedArgv(["echo", element])
        let took = Date().timeIntervalSince(start)
        XCTAssertLessThan(took, 0.005, "\(took) s")
        XCTAssertLessThanOrEqual(kept[1].utf8.count, ProcessTree.maxArgvElementBytes + 3)
        XCTAssertTrue(kept[1].hasSuffix("…"))

        // Same results as before for ordinary elements.
        let ascii = String(repeating: "x", count: 5000)
        XCTAssertEqual(ProcessTree.boundedArgvElement(ascii), String(repeating: "x", count: 1024) + "…")
        let wide = String(repeating: "😀", count: 1500)
        XCTAssertEqual(ProcessTree.boundedArgvElement(wide), String(repeating: "😀", count: 1024) + "…")
        let short = String(repeating: "é", count: 900)
        XCTAssertEqual(ProcessTree.boundedArgvElement(short), short)
        let exactly = String(repeating: "a", count: 1024)
        XCTAssertEqual(ProcessTree.boundedArgvElement(exactly), exactly)

        let exec = Date()
        tree.exec(old: proc(700, "/bin/zsh", platform: true), new: proc(700, "/bin/echo", platform: true, argv: ["echo", element, element]),
                  at: at(1))
        XCTAssertLessThan(Date().timeIntervalSince(exec), 0.01)
    }

    /// The display says how many elements a long command line had, not how many the tree kept.
    func testTheDisplayCountsTheElementsTheTreeDropped() {
        let paths = (0..<20_000).map { "/Users/alice/code/project/Sources/File\($0).swift" }
        let argv = ["grep", "-l", "x"] + paths
        tree.observe(proc(601, "/usr/bin/grep", platform: true, argv: argv), at: at(0))
        let node = tree.node(pid: 601)!
        XCTAssertLessThan(node.image.argv!.count, argv.count)
        XCTAssertEqual(ArgvRedactor.redact(node.image.argv)?.last, "…(+\(argv.count - 8))")
        XCTAssertEqual(ArgvRedactor.redact(argv)?.last, "…(+\(argv.count - 8))")
        XCTAssertEqual(ChainLink(node: node).argv?.last, "…(+\(argv.count - 6))")
    }

    /// Long options before the script used up the budget: the script element is kept all the same, so
    /// the node is still the agent it runs.
    func testTheScriptIsKeptPastTheBudget() {
        // Options of 1024 four-byte characters: the first eight elements already use twice the budget.
        let options = (0..<16).map { "--require=/Users/alice/x/" + String(repeating: "😀", count: 1500) + "\($0)" }
        let argv = ["node"] + options + ["/opt/homebrew/bin/claude", "-p", "hi"]
        XCTAssertEqual(detector.detect(proc(800, node, argv: argv)), "claude-code")
        tree.observe(proc(800, node, argv: argv), at: at(0))
        let n = tree.node(pid: 800)!
        XCTAssertEqual(n.agentID, "claude-code")
        XCTAssertTrue(n.image.argv!.contains("/opt/homebrew/bin/claude"))
        XCTAssertLessThanOrEqual(BoundedArgvTests.bytes(n.image.argv), 8 * (ProcessTree.maxArgvElementBytes + 3) + 64)
        XCTAssertEqual(n.image.argv?.last, "…(+\(argv.count - n.image.argv!.count + 1))")

        let module = ["python3"] + (0..<12).map { "-X" + String(repeating: "😀", count: 1100) + "\($0)" } + ["-m", "aider", "--model", "x"]
        XCTAssertEqual(detector.detect(proc(801, python, platform: true, argv: module)), "aider")
        tree.observe(proc(801, python, platform: true, argv: module), at: at(0))
        XCTAssertEqual(tree.node(pid: 801)?.agentID, "aider")
    }
}
