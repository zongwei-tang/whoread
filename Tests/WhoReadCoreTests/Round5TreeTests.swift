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
