import XCTest
@testable import WhoReadCore

// Round 6, process tree: a missed exec once the pidversion history is trimmed, in eslogger's order
// (exec-rollback); more runtime options told apart from the script (runtime-options, already so); the
// script kept past the argv budget behind an option whose value is the next element (script pushed out);
// the count of dropped elements when an argv is bounded twice, as libproc records are (count display).

private let node = "/opt/homebrew/Cellar/node/22.9.0/bin/node"
private let deno = "/opt/homebrew/Cellar/deno/2.1.4/bin/deno"
private let python = "/usr/bin/python3"
private let vaultKey = "/Users/alice/WhoReadTestVault/ssh/id_ed25519"

final class R6TrimmedHistoryTests: XCTestCase {
    var h: Harness!

    override func setUpWithError() throws {
        h = try Harness(learningDays: 0)
    }

    func names(_ chain: [ProcessNode]) -> [String] { chain.map(\.image.name) }

    /// `parent` (pid 500) forks 501, which execs cat: cat, and its chain.
    func catBelow(_ parent: ProcessRecord, _ t: TimeInterval) -> (ProcessRecord, [ProcessNode]) {
        var child = parent
        child.pid = 501
        child.pidVersion = 9000
        child.ppid = 500
        child.originalPPID = 500
        child.startTime = at(t)
        h.fork(parent, child, t)
        var cat = P.cat(501, parent: 500)
        cat.pidVersion = 9001
        cat.startTime = at(t)
        h.exec(child, cat, t + 1)
        return (cat, h.tree.chain(for: cat, at: at(t + 2)))
    }

    /// eslogger: zsh execs itself 70 times, past the pidversion history a node keeps, and its exec into evil
    /// is lost (dropped under load, or while eslogger restarted). eslogger delivers in order, so evil's
    /// records, which come next, are that missed exec: adopted, and what evil starts is below evil, not
    /// below zsh (an all-Apple chain).
    func testAMissedExecIsAdoptedAfterATrimmedHistoryInEsloggerOrder() {
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        var current = zsh
        for k in 1...70 {
            var again = P.zsh(500, parent: 100)
            again.pidVersion = UInt32(5000 + k)
            h.exec(current, again, Double(k) / 100)
            current = again
        }
        XCTAssertEqual(h.tree.node(pid: 500)?.pidVersionsTrimmed, true)
        var evil = proc(500, "/Users/alice/bin/evil", ppid: 100, start: 0, argv: ["evil"])
        evil.pidVersion = 6000
        XCTAssertEqual(h.open(evil, vaultKey, 2).events.first?.process.executablePath, "/Users/alice/bin/evil")
        XCTAssertEqual(h.tree.node(pid: 500)?.image.executablePath, "/Users/alice/bin/evil")
        XCTAssertEqual(h.tree.node(pid: 500)?.pidVersions.last, 6000)

        let (cat, chain) = catBelow(evil, 4)
        XCTAssertEqual(names(chain), ["cat", "evil", "Terminal", "launchd"])
        XCTAssertFalse(AskPolicy.isTrustableAppleProgram(cat, chain: chain))
    }

    /// Native source: zsh's read waits in the analysis queue while zsh execs evil and evil execs itself 70
    /// times, past the history a node keeps. That late record is still not taken for a missed exec there.
    func testALateRecordAfterATrimmedHistoryIsNotAdoptedWhereRecordsArriveLate() {
        h.tree.recordsMayArriveLate = true
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        var current = zsh
        for k in 1...70 {
            var evil = proc(500, "/Users/alice/bin/evil", ppid: 100, start: 0, argv: ["evil"])
            evil.pidVersion = UInt32(5000 + k)
            h.exec(current, evil, Double(k) / 100)
            current = evil
        }
        XCTAssertEqual(h.tree.node(pid: 500)?.pidVersionsTrimmed, true)
        XCTAssertEqual(h.open(zsh, vaultKey, 2).events.first?.process.executablePath, "/bin/zsh", "the event shows the image that read it")
        XCTAssertEqual(h.tree.node(pid: 500)?.image.executablePath, "/Users/alice/bin/evil")
        _ = h.open(current, vaultKey, 3)
        XCTAssertEqual(h.tree.node(pid: 500)?.image.executablePath, "/Users/alice/bin/evil")
        XCTAssertEqual(h.tree.node(pid: 500)?.pidVersions.last, 5070)

        let (cat, chain) = catBelow(current, 4)
        XCTAssertEqual(names(chain), ["cat", "evil", "Terminal", "launchd"])
        XCTAssertFalse(AskPolicy.isTrustableAppleProgram(cat, chain: chain))
    }
}

/// runtime-options: honest node, deno, bun and python commands that name an agent among their arguments
/// are not that agent (beyond the commands R5VAgentScriptPositionTests lists), and launches still are.
final class R6AgentScriptPositionTests: XCTestCase {
    func testMoreRuntimeOptionsAreToldApart() throws {
        let detector = AgentDetector(catalog: try defaultData().agents)
        let bun = "/opt/homebrew/Cellar/bun/1.1.30/bin/bun"
        func d(_ path: String, _ argv: [String]) -> String? {
            detector.detect(ProcessRecord(pid: 5, ppid: 1, executablePath: path, isPlatformBinary: path == python, argv: argv))
        }
        let honest: [(String, [String])] = [
            (node, ["node", "-r", "ts-node/register", "script.ts", "claude"]),
            (node, ["node", "-C", "development", "app.js", "claude"]),
            (node, ["node", "--loader", "ts-node/esm", "app.ts", "gemini"]),
            (node, ["node", "--env-file", ".env", "app.js", "codex"]),
            (node, ["node", "--inspect-brk=0.0.0.0:9229", "--watch", "app.js", "claude"]),
            (node, ["node", "-pe", "1", "claude"]),
            (node, ["node", "--run", "build", "claude"]),
            (deno, ["deno", "run", "--import-map", "map.json", "main.ts", "claude"]),
            (deno, ["deno", "run", "--location", "https://example.com", "--unstable-kv", "main.ts", "claude"]),
            (deno, ["deno", "-A", "main.ts", "codex"]),
            (deno, ["deno", "eval", "console.log(1)", "claude"]),
            (deno, ["deno", "compile", "-o", "dist/claude", "main.ts"]),
            (bun, ["bun", "--hot", "index.ts", "claude"]),
            (bun, ["bun", "run", "--filter", "pkg", "dev", "claude"]),
            (bun, ["bun", "-r", "./setup.ts", "index.ts", "claude"]),
            (bun, ["bun", "--cwd", "packages/claude", "run", "dev"]),
            (bun, ["bun", "build", "--compile", "./src/claude.ts", "--outfile", "dist/claude"]),
            (bun, ["bunx", "tsc", "-p", "/Users/alice/code/codex"]),
            (python, ["python3", "-W", "ignore", "script.py", "aider"]),
            (python, ["python3", "-X", "dev", "-u", "-B", "script.py", "aider"]),
        ]
        for (path, argv) in honest { XCTAssertNil(d(path, argv), "\(argv)") }
        XCTAssertEqual(d(node, ["node", "-r", "ts-node/register", "/opt/homebrew/bin/claude"]), "claude-code")
        XCTAssertEqual(d(node, ["node", "--max-old-space-size=8192", "/opt/homebrew/bin/codex"]), "codex")
        XCTAssertEqual(d(deno, ["deno", "run", "--allow-all", "--import-map", "map.json", "npm:@google/gemini-cli"]), "gemini-cli")
        XCTAssertEqual(d(bun, ["bun", "run", "--hot", "/Users/alice/.bun/bin/claude"]), "claude-code")
    }
}

final class R6BoundedArgvTests: XCTestCase {
    var detector: AgentDetector!
    var tree: ProcessTree!

    override func setUpWithError() throws {
        detector = AgentDetector(catalog: try defaultData().agents)
        tree = ProcessTree(detector: detector)
    }

    /// An element that keeps 1024 characters, most of them four bytes long.
    func long(_ prefix: String, _ k: Int) -> String { prefix + String(repeating: "😀", count: 1500) + "\(k)" }

    /// Options whose value is the next element (`--require X`, `-X v`, `--config X`) used up the budget: the
    /// script is kept past it, and so is the value of the last option kept. Without that value the option
    /// would take the script for its value, the marker after it would pose as the script, and the agent
    /// would not be recognised.
    func testTheScriptIsKeptWithTheValueOfTheOptionBeforeIt() throws {
        let cases: [(path: String, argv: [String], agent: String, script: String)] = [
            (node, ["node"] + (0..<16).flatMap { ["--require", long("/Users/alice/x/", $0)] } + ["/opt/homebrew/bin/claude", "-p", "hi"],
             "claude-code", "/opt/homebrew/bin/claude"),
            (python, ["python3"] + (0..<8).flatMap { ["-X", long("importtime", $0)] } + ["/Users/alice/.local/bin/aider", "--model", "x"],
             "aider", "/Users/alice/.local/bin/aider"),
            (deno, ["deno", "run"] + (0..<8).flatMap { ["--config", long("/Users/alice/x/", $0)] } + ["npm:@anthropic-ai/claude-code"],
             "claude-code", "npm:@anthropic-ai/claude-code"),
        ]
        for (k, c) in cases.enumerated() {
            let label = c.argv[0]
            let record = proc(Int32(800 + k), c.path, platform: c.path == python, argv: c.argv)
            XCTAssertEqual(detector.detect(record), c.agent, label)
            tree.observe(record, at: at(0))
            let n = try XCTUnwrap(tree.node(pid: record.pid))
            let kept = try XCTUnwrap(n.image.argv)
            XCTAssertLessThan(kept.count, c.argv.count, label)
            XCTAssertEqual(n.agentID, c.agent, label)
            XCTAssertTrue(AgentMatchClause.scriptPosition(executableName: record.name, argv: kept) == .script(c.script, at: kept.count - 2),
                          "the script, then the marker: \(label)")
            XCTAssertLessThanOrEqual(BoundedArgvTests.bytes(kept), 10 * (ProcessTree.maxArgvElementBytes + 3) + 64, label)
            XCTAssertEqual(ArgvRedactor.redact(kept)?.last, "…(+\(c.argv.count - 8))", label)
        }
        // An owner's `argvGlobs` read the same script.
        XCTAssertEqual(IdentitySpec.scriptArgument(tree.node(pid: 801)?.image.argv), "/Users/alice/.local/bin/aider")
    }

    /// libproc records (the seed, the parent resolver) are bounded where they are read, then again by the tree:
    /// bounding twice changes nothing, so the script stays and the display still says how many elements the
    /// command line had.
    func testBoundingTwiceKeepsTheScriptAndTheCount() throws {
        let joined = (0..<16).map { "--require=" + long("/Users/alice/x/", $0) }
        let pairs = (0..<16).flatMap { ["--require", long("/Users/alice/x/", $0)] }
        for (k, options) in [joined, pairs].enumerated() {
            let argv = ["node"] + options + ["/opt/homebrew/bin/claude", "-p", "hi"]
            let once = ProcessTree.boundedArgv(argv, executableName: "node")
            XCTAssertLessThan(once.count, argv.count)
            // (Not XCTAssertEqual: a failure would print megabytes.)
            XCTAssertTrue(ProcessTree.boundedArgv(once, executableName: "node") == once, "case \(k)")
            let pid = Int32(900 + k)
            tree.seed([ProcessRecord(pid: pid, ppid: 1, executablePath: node, argv: once, startTime: at(-5))], at: at(0))
            let n = try XCTUnwrap(tree.node(pid: pid))
            XCTAssertTrue(n.image.argv == once, "case \(k)")
            XCTAssertEqual(n.agentID, "claude-code", "case \(k)")
            XCTAssertEqual(ArgvRedactor.redact(n.image.argv)?.last, "…(+\(argv.count - 8))", "case \(k)")
            XCTAssertEqual(ChainLink(node: n).argv?.last, "…(+\(argv.count - 6))", "case \(k)")
        }
    }
}
