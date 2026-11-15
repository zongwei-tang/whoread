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
