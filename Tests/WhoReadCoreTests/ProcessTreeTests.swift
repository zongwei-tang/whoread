import XCTest
@testable import WhoReadCore

final class ProcessTreeTests: XCTestCase {
    var tree: ProcessTree!

    override func setUpWithError() throws {
        tree = ProcessTree(detector: AgentDetector(catalog: try defaultData().agents), tombstoneTTL: 60)
    }

    func names(_ chain: [ProcessNode]) -> [String] { chain.map { $0.image.name } }

    func testForkExecChain() {
        let zsh = proc(500, "/bin/zsh", ppid: 400, start: 0, platform: true)
        tree.seed([proc(400, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", ppid: 1, start: -100, platform: true), zsh], at: at(0))
        var child = zsh
        child.pid = 501
        child.ppid = 500
        child.startTime = at(1)
        tree.fork(parent: zsh, child: child, at: at(1))
        let cat = proc(501, "/bin/cat", ppid: 500, start: 1, platform: true, argv: ["cat", "x"])
        tree.exec(old: child, new: cat, at: at(1))
        XCTAssertEqual(names(tree.chain(for: cat, at: at(2))), ["cat", "zsh", "Terminal", "launchd"])
        XCTAssertEqual(tree.node(pid: 501)?.image.argv, ["cat", "x"])
    }

    func testReparentedProcessKeepsOriginalParent() {
        let zsh = proc(500, "/bin/zsh", ppid: 1, start: 0, platform: true)
        let bg = proc(600, "/bin/sleep", ppid: 500, start: 1, platform: true)
        tree.observe(zsh, at: at(0))
        tree.fork(parent: zsh, child: bg, at: at(1))
        tree.exit(zsh, at: at(2))
        // Now launchd adopted it; the event says ppid 1 but original_ppid 500.
        var orphan = bg
        orphan.ppid = 1
        orphan.originalPPID = 500
        XCTAssertEqual(names(tree.chain(for: orphan, at: at(3))), ["sleep", "zsh", "launchd"])
    }

    func testOrphanSeenFirstTimeUsesOriginalPPID() {
        let zsh = proc(500, "/bin/zsh", ppid: 1, start: 0, platform: true)
        tree.observe(zsh, at: at(0))
        let orphan = proc(601, "/bin/cat", ppid: 1, start: 1, platform: true, originalPPID: 500)
        XCTAssertEqual(names(tree.chain(for: orphan, at: at(2))), ["cat", "zsh", "launchd"])
    }

    func testPidReuseDoesNotInheritOldAncestry() {
        let a = proc(700, "/Applications/Evil.app/Contents/MacOS/Evil", ppid: 1, start: 0)
        tree.observe(a, at: at(0))
        tree.exit(a, at: at(1))
        // pid 700 is reused by a different process with a later start time.
        let b = proc(700, "/usr/bin/true", ppid: 1, start: 5, platform: true)
        let chain = tree.chain(for: b, at: at(6))
        XCTAssertEqual(names(chain), ["true", "launchd"])
        // A child of the *new* 700 must not be linked to the dead Evil.app instance.
        let child = proc(701, "/bin/cat", ppid: 700, start: 7, platform: true)
        XCTAssertEqual(names(tree.chain(for: child, at: at(8))), ["cat", "true", "launchd"])
    }

    func testParentStartedAfterChildIsRejected() {
        let child = proc(801, "/bin/cat", ppid: 800, start: 1, platform: true)
        let impostor = proc(800, "/bin/zsh", ppid: 1, start: 5, platform: true)
        tree.observe(impostor, at: at(5))
        XCTAssertEqual(names(tree.chain(for: child, at: at(6))), ["cat"])
    }

    func testExitedParentTombstoneResolvesLateEvents() {
        let zsh = proc(500, "/bin/zsh", ppid: 1, start: 0, platform: true)
        let cat = proc(501, "/bin/cat", ppid: 500, start: 1, platform: true)
        tree.fork(parent: zsh, child: cat, at: at(1))
        tree.exit(cat, at: at(2))
        tree.exit(zsh, at: at(2))
        // Native ES: the process client delivered exit before the file client delivered the open.
        XCTAssertEqual(names(tree.chain(for: cat, at: at(3))), ["cat", "zsh", "launchd"])
    }

    func testPruneKeepsTombstonesWithLiveChildren() {
        let zsh = proc(500, "/bin/zsh", ppid: 1, start: 0, platform: true)
        let daemon = proc(501, "/usr/bin/nohup", ppid: 500, start: 1, platform: true)
        tree.fork(parent: zsh, child: daemon, at: at(1))
        tree.exit(zsh, at: at(2))
        tree.prune(now: at(1000))
        XCTAssertNotNil(tree.chain(nodeID: tree.node(pid: 501)!.id).first { $0.image.name == "zsh" })
        tree.exit(daemon, at: at(1001))
        tree.prune(now: at(5000))
        XCTAssertNil(tree.node(pid: 501))
        XCTAssertNil(tree.node(pid: 500))
    }

    func testParentResolverFillsUnknownAncestors() {
        let known: [Int32: ProcessRecord] = [
            900: proc(900, "/Applications/Zoom.app/Contents/MacOS/zoom.us", ppid: 1, start: -10),
        ]
        tree.parentResolver = { known[$0] }
        let helper = proc(901, "/bin/sh", ppid: 900, start: 0, platform: true)
        XCTAssertEqual(names(tree.chain(for: helper, at: at(1))), ["sh", "zoom.us", "launchd"])
    }

    func testCyclesAreImpossible() {
        let a = proc(10, "/bin/a", ppid: 11, start: nil)
        let b = proc(11, "/bin/b", ppid: 10, start: nil)
        tree.observe(a, at: at(0))
        tree.observe(b, at: at(0))
        let chain = tree.chain(for: a, at: at(1))
        XCTAssertLessThanOrEqual(chain.count, 2)
    }

    func testMissedExecAdoptsNewImage() {
        let zsh = proc(500, "/bin/zsh", ppid: 1, start: 0, platform: true)
        tree.observe(zsh, at: at(0))
        var cat = proc(500, "/bin/cat", ppid: 1, start: 0, platform: true)
        cat.pidVersion = 9999
        let chain = tree.chain(for: cat, at: at(1))
        XCTAssertEqual(chain.first?.image.name, "cat")
        XCTAssertEqual(tree.count, 2, "same instance (pid + start time), new image; plus synthesized launchd")
    }

    func testAgentDetectedAtExecAndInherited() throws {
        let zsh = proc(500, "/bin/zsh", ppid: 1, start: 0, platform: true)
        tree.observe(zsh, at: at(0))
        var child = zsh
        child.pid = 600
        child.ppid = 500
        child.startTime = at(1)
        tree.fork(parent: zsh, child: child, at: at(1))
        let claude = proc(600, "/opt/homebrew/Cellar/node/22.9.0/bin/node", ppid: 500, start: 1,
                          argv: ["node", "/opt/homebrew/bin/claude"])
        tree.exec(old: child, new: claude, at: at(1))
        let cat = proc(601, "/bin/cat", ppid: 600, start: 2, platform: true)
        let chain = tree.chain(for: cat, at: at(3))
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertNil(chain[0].agentID)
        XCTAssertEqual(chain[1].agentID, "claude-code")
    }
}

final class AgentDetectionTests: XCTestCase {
    var detector: AgentDetector!

    override func setUpWithError() throws {
        detector = AgentDetector(catalog: try defaultData().agents)
    }

    func d(_ path: String, _ argv: [String]? = nil, platform: Bool = false) -> String? {
        detector.detect(ProcessRecord(pid: 5, ppid: 1, executablePath: path, isPlatformBinary: platform, argv: argv))
    }

    func testCLIAgents() {
        XCTAssertEqual(d("/opt/homebrew/Cellar/node/22.9.0/bin/node", ["node", "/opt/homebrew/bin/claude"]), "claude-code")
        XCTAssertEqual(d("/usr/local/bin/node", ["node", "/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js"]), "claude-code")
        XCTAssertEqual(d("/Users/alice/.local/share/claude/versions/2.0.14", ["claude"]), "claude-code")
        XCTAssertEqual(d("/opt/homebrew/lib/node_modules/@openai/codex/vendor/aarch64-apple-darwin/codex/codex", ["codex"]), "codex")
        XCTAssertEqual(d("/opt/homebrew/bin/node", ["node", "/opt/homebrew/lib/node_modules/@google/gemini-cli/dist/index.js"]), "gemini-cli")
        XCTAssertEqual(d("/Users/alice/.opencode/bin/opencode", ["opencode"]), "opencode")
        XCTAssertEqual(d("/opt/homebrew/Cellar/python@3.12/3.12.5/Frameworks/Python.framework/Versions/3.12/Resources/Python.app/Contents/MacOS/Python",
                         ["/opt/homebrew/opt/python@3.12/bin/python3.12", "/Users/alice/.local/bin/aider"]), "aider")
        XCTAssertEqual(d("/usr/bin/python3", ["python3", "-m", "aider"], platform: true), "aider")
    }

    func testAppAgents() {
        XCTAssertEqual(d("/Applications/Cursor.app/Contents/Frameworks/Cursor Helper (Plugin).app/Contents/MacOS/Cursor Helper (Plugin)"), "cursor")
        XCTAssertEqual(d("/Applications/Claude.app/Contents/MacOS/Claude"), "claude-desktop")
        XCTAssertEqual(d("/Applications/ChatGPT.app/Contents/MacOS/ChatGPT"), "chatgpt-desktop")
    }

    func testNoFalsePositives() {
        XCTAssertNil(d("/bin/cat", ["cat", "claude-notes.txt"], platform: true))
        XCTAssertNil(d("/opt/homebrew/bin/node", ["node", "server.js"]))
        XCTAssertNil(d("/usr/bin/python3", ["python3", "aider_notes.py"], platform: true))
        XCTAssertNil(d("/Applications/Claude Notes.app/Contents/MacOS/Claude Notes"))
    }
}

final class AttributionTests: XCTestCase {
    func testScenarios() throws {
        let h = try Harness()
        // Terminal → zsh → cat: charged to Terminal (outermost .app).
        let zsh = h.spawn(P.terminal, P.zsh(500, parent: 100))
        let cat = h.spawn(zsh, P.cat(501, parent: 500), 1)
        var chain = h.tree.chain(for: cat, at: at(2))
        var r = h.attributor.attribute(chain: chain)
        XCTAssertEqual(r.kind, .app)
        XCTAssertEqual(r.displayName, "Terminal")

        // Terminal → zsh → claude (node) → zsh → cat: charged to Claude Code.
        let claude = h.spawn(zsh, P.node(600, parent: 500, argv: ["node", "/opt/homebrew/bin/claude"]), 3)
        let sh = h.spawn(claude, P.zsh(601, parent: 600), 4)
        let cat2 = h.spawn(sh, P.cat(602, parent: 601), 5)
        chain = h.tree.chain(for: cat2, at: at(6))
        r = h.attributor.attribute(chain: chain)
        XCTAssertEqual(r.kind, .agent)
        XCTAssertEqual(r.agentID, "claude-code")
        XCTAssertEqual(r.key, "agent:claude-code")
        let links = Array(chain.reversed()).map { ChainLink(node: $0) }
        XCTAssertEqual(links.displayString(responsible: r), "Claude Code → zsh → cat")

        // Zoom helper inside the bundle: charged to zoom.us (outermost .app).
        let zoomHelper = proc(700, "/Applications/zoom.us.app/Contents/Frameworks/ZoomHelper.app/Contents/MacOS/ZoomHelper",
                              ppid: 1, start: 7, teamID: "TEAM12345")
        chain = h.tree.chain(for: zoomHelper, at: at(8))
        r = h.attributor.attribute(chain: chain)
        XCTAssertEqual(r.displayName, "zoom.us")
        XCTAssertEqual(r.key, "app:/applications/zoom.us.app")
        XCTAssertEqual(r.teamID, "TEAM12345")

        // cron → sh → python (homebrew) → cat: nearest non-platform ancestor is python.
        let cron = proc(800, "/usr/sbin/cron", ppid: 1, start: 9, platform: true)
        let sh2 = h.spawn(cron, proc(801, "/bin/sh", start: 9, platform: true), 9)
        let py = h.spawn(sh2, proc(802, "/opt/homebrew/Cellar/python@3.12/3.12.5/bin/python3.12", start: 9), 9)
        let cat3 = h.spawn(py, P.cat(803, parent: 802), 10)
        r = h.attributor.attribute(chain: h.tree.chain(for: cat3, at: at(11)))
        XCTAssertEqual(r.kind, .binary)
        XCTAssertEqual(r.displayName, "python3.12")

        // launchd → sshd-session → zsh → cat: all platform binaries → top-most below launchd.
        let sshd = proc(900, "/usr/libexec/sshd-session", ppid: 1, start: 12, platform: true)
        let rz = h.spawn(sshd, P.zsh(901, parent: 900), 12)
        let cat4 = h.spawn(rz, P.cat(902, parent: 901), 13)
        r = h.attributor.attribute(chain: h.tree.chain(for: cat4, at: at(14)))
        XCTAssertEqual(r.displayName, "sshd-session")
    }
}
