import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

// Process identity, Engine side: what the native source reads from es_process_t (parent and responsible
// tokens, the kernel's signing category, code signing flags), and answers scoped by the whole chain's
// AI agents and by whether its ancestry was known.

private let idT = Date(timeIntervalSince1970: 1_760_000_000)
private let idKeyPath = "/Users/alice/.ssh/id_ed25519"
private let catKey = "bin:apple:com.apple.cat"

private func identityCore(_ dir: TempDir) throws -> DaemonCore {
    var config = baseConfig(dir)
    config.resolveOwners = false
    return try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
}

/// /bin/cat, started by `originalPPID` (1: launchd; another pid that is not in the tree: unknown).
private func cat(_ pid: Int32, originalPPID: Int32) -> ProcessRecord {
    var p = proc(pid, "/bin/cat", ppid: 1, platform: true)
    p.originalPPID = originalPPID
    p.signingID = "com.apple.cat"
    return p
}

private func openKey(_ p: ProcessRecord) -> FileActivity {
    FileActivity(time: idT.addingTimeInterval(100), operation: .open, process: p,
                 targets: OperationSemantics.open(path: idKeyPath, fflag: 1))
}

/// Answers delivered to held accesses.
private final class HeldAnswers: @unchecked Sendable {
    private let lock = NSLock()
    private var byAccess: [Int: [AskBroker.Answer]] = [:]
    func respond(_ access: Int) -> @Sendable (AskBroker.Answer) -> Void {
        { answer in self.lock.lock(); self.byAccess[access, default: []].append(answer); self.lock.unlock() }
    }
    func of(_ access: Int) -> [AskBroker.Answer] { lock.lock(); defer { lock.unlock() }; return byAccess[access] ?? [] }
}

final class AncestryScopedAnswerEngineTests: XCTestCase {
    /// What the native source does on an `.ask` decision: build the question and hold the access.
    fileprivate func hold(_ core: DaemonCore, _ a: FileActivity, _ answers: HeldAnswers, _ n: Int) throws -> AskRequest {
        let d = core.enforcer.decide(a)
        XCTAssertEqual(d.verdict, .ask)
        let q = try XCTUnwrap(core.enforcer.askRequest(for: a, decision: d))
        core.askBroker.noteAnsweringClient()
        guard case .held(let id) = core.askBroker.hold(q, budget: 60, respond: answers.respond(n)) else {
            throw XCTSkip("not held")
        }
        return try XCTUnwrap(core.askBroker.pending().first { $0.id == id })
    }

    func answerRules(_ core: DaemonCore) -> [Rule] { core.rules.rules.filter { $0.template == DaemonCore.askAnswerTemplate } }

    /// Two open questions about cat reading an SSH key: one launchd started (a known chain), one whose
    /// starter is unknown (an AI agent's shell that is gone). "Always allow" on the known one releases
    /// only that one, and later unknown chains are still asked; given on the unknown one, it covers both.
    func testAnAnswerForAKnownChainLeavesTheUnknownOneAsked() throws {
        let dir = TempDir()
        let core = try identityCore(dir)
        try core.setRules([])
        try core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
        core.drainPolicyQueue()
        let answers = HeldAnswers()
        let known = try hold(core, openKey(cat(701, originalPPID: 1)), answers, 1)
        let unknown = try hold(core, openKey(cat(702, originalPPID: 700)), answers, 2)
        XCTAssertEqual(known.key.responsibleKey, catKey)
        XCTAssertEqual(unknown.key.responsibleKey, catKey)
        XCTAssertTrue(known.key.ancestryKnown)
        XCTAssertFalse(unknown.key.ancestryKnown)
        XCTAssertNotEqual(known.id, unknown.id, "separate questions")

        try core.answerAsk(id: known.id, action: .alwaysAllow, peer: .inProcess, privileged: true)
        core.askBroker.drain()
        XCTAssertEqual(answers.of(1), [.allow])
        XCTAssertEqual(answers.of(2), [], "still held")
        XCTAssertEqual(answerRules(core).map(\.coversUnknownAncestry), [false])
        XCTAssertEqual(core.enforcer.decide(openKey(cat(703, originalPPID: 1))).verdict, .allow)
        XCTAssertEqual(core.enforcer.decide(openKey(cat(704, originalPPID: 700))).verdict, .ask)

        try core.answerAsk(id: unknown.id, action: .alwaysAllow, peer: .inProcess, privileged: true)
        core.askBroker.drain()
        XCTAssertEqual(answers.of(2), [.allow])
        XCTAssertEqual(Set(answerRules(core).map(\.coversUnknownAncestry)), [false, true])
        XCTAssertEqual(core.enforcer.decide(openKey(cat(705, originalPPID: 700))).verdict, .allow)
        core.askBroker.denyAll()
    }

    /// An answer on an alert is scoped by the AI agents of the whole chain (the stored chain keeps only
    /// the nearest 64 links, so an agent at the top of a deeper one is not in it) and by whether the
    /// chain's ancestry was known; so is "always allow" on a rule's block.
    func testAnAlertAnswerUsesTheWholeChainsAgentsAndItsAncestry() throws {
        let dir = TempDir()
        let core = try identityCore(dir)
        let deny = Rule(id: "deny-ssh", enabled: true, enforce: true, target: .category("ssh"), subject: .anyNonOwner,
                        action: .deny, includePlatformBinaries: true)
        try core.setRules([deny])
        func alert(_ id: Int64, kind: AlertKind, category: String, agents: [String]?, known: Bool?, ruleID: String? = nil) -> Alert {
            let shallow = [ChainLink(pid: 900, name: "sh", path: "/bin/sh", isPlatformBinary: true),
                           ChainLink(pid: 901, name: "cat", path: "/bin/cat", isPlatformBinary: true)]
            return Alert(id: id, kind: kind, createdAt: idT, updatedAt: idT, windowEndsAt: idT.addingTimeInterval(600),
                         responsible: ResponsibleEntity(kind: .binary, key: catKey, displayName: "cat"), categoryID: category,
                         severity: .critical, count: 1, accesses: .read, firstPath: idKeyPath, firstEventID: 1, lastEventID: 1,
                         paths: [idKeyPath], chain: shallow, agentID: agents?.first, ruleID: ruleID, chainAgents: agents,
                         ancestryKnown: known)
        }
        try core.store.upsert([alert(1, kind: .ask, category: "aws", agents: ["claude-code"], known: true),
                               alert(2, kind: .ask, category: "gcloud", agents: [], known: false),
                               alert(3, kind: .ask, category: "kube", agents: nil, known: nil),
                               alert(4, kind: .blocked, category: "ssh", agents: [], known: false, ruleID: "deny-ssh")])
        for id in Int64(1)...4 { try core.apply(action: .alwaysAllow, toAlert: id, peer: .inProcess) }
        let byCategory = Dictionary(uniqueKeysWithValues: answerRules(core).map { (rule: Rule) -> (String, Rule) in
            guard case .category(let c) = rule.target else { return ("", rule) }
            return (c, rule)
        })
        XCTAssertEqual(byCategory["aws"]?.chainAgents, ["claude-code"], "the whole chain's agents")
        XCTAssertEqual(byCategory["aws"]?.coversUnknownAncestry, false)
        XCTAssertEqual(byCategory["gcloud"]?.chainAgents, [])
        XCTAssertEqual(byCategory["gcloud"]?.coversUnknownAncestry, true)
        XCTAssertEqual(byCategory["kube"]?.chainAgents, [], "an older alert: its stored chain")
        XCTAssertEqual(byCategory["kube"]?.coversUnknownAncestry, false)
        let exception = try XCTUnwrap(core.rules.rules.first { $0.id == "deny-ssh" }?.exceptions.first)
        XCTAssertEqual(exception.chainAgents, [])
        XCTAssertTrue(exception.coversUnknownAncestry)
    }
}

/// The daemon saves the AI agent ancestry of running processes in its store and gives it back to the
/// processes still running after a restart (libproc has no fork-time parent to find it again by).
final class AgentAncestryPersistenceTests: XCTestCase {
    private let start = Date().addingTimeInterval(-600)
    private let claudeArgv = ["node", "/opt/homebrew/bin/claude"]

    private func p(_ pid: Int32, _ path: String, ppid: Int32, _ offset: TimeInterval, platform: Bool = true,
                   argv: [String]? = nil) -> ProcessRecord {
        proc(pid, path, ppid: ppid, platform: platform, argv: argv, start: start.addingTimeInterval(offset))
    }

    /// libproc's view: current ppid only.
    private func snapshot(_ r: ProcessRecord, ppid: Int32? = nil) -> ProcessRecord {
        ProcessRecord(pid: r.pid, ppid: ppid ?? r.ppid, executablePath: r.executablePath, isPlatformBinary: r.isPlatformBinary,
                      argv: r.argv, startTime: r.startTime)
    }

    /// Terminal → zsh → Claude Code (node) → sh → python3 (a job); sh has exited, python3 is an orphan.
    private lazy var terminal = p(100, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", ppid: 1, 0)
    private lazy var zsh = p(500, "/bin/zsh", ppid: 100, 1)
    private lazy var claude = p(600, "/opt/homebrew/Cellar/node/22.9.0/bin/node", ppid: 500, 2, platform: false, argv: claudeArgv)
    private lazy var sh = p(700, "/bin/sh", ppid: 600, 3)
    private lazy var job = p(701, "/usr/bin/python3", ppid: 700, 4)

    /// `parent` forks a copy of itself, which execs `child`.
    private func spawn(_ tree: ProcessTree, _ parent: ProcessRecord, _ child: ProcessRecord) {
        let now = start.addingTimeInterval(5)
        var copy = parent
        copy.pid = child.pid
        copy.ppid = parent.pid
        copy.originalPPID = parent.pid
        copy.startTime = child.startTime
        tree.fork(parent: parent, child: copy, at: now)
        tree.exec(old: copy, new: child, at: now)
    }

    private func runAgentJob(_ tree: ProcessTree) {
        for (parent, child) in [(terminal, zsh), (zsh, claude), (claude, sh), (sh, job)] { spawn(tree, parent, child) }
        tree.exit(sh, at: start.addingTimeInterval(5))
    }

    private func seedAfterRestart(_ core: DaemonCore) {
        core.tree.seed([snapshot(terminal), snapshot(zsh), snapshot(claude), snapshot(job, ppid: 1)], at: Date())
    }

    func testTheAgentOfAnOrphanedJobIsRestoredFromTheStore() throws {
        let dir = TempDir()
        do {
            let core = try identityCore(dir)
            runAgentJob(core.tree)
            XCTAssertEqual(core.tree.chain(for: job, at: Date()).nearestAgent, "claude-code")
            core.persistAgentAncestry()
        }
        let again = try identityCore(dir)
        seedAfterRestart(again)
        XCTAssertNil(again.tree.chain(nodeID: try XCTUnwrap(again.tree.node(pid: 701)?.id)).nearestAgent, "seeded alone: unknown")
        again.restoreAgentAncestry()
        let chain = again.tree.chain(nodeID: try XCTUnwrap(again.tree.node(pid: 701)?.id))
        XCTAssertEqual(chain.map(\.image.name), ["python3", "sh", "node", "zsh", "Terminal"])
        XCTAssertEqual(chain.nearestAgent, "claude-code")
        XCTAssertFalse(chain.reachesLaunchd)
    }

    /// Saved before the last boot: none of those processes exist any more (pids and start times can
    /// repeat after a reboot), so nothing is restored.
    func testRecordsFromAnotherBootAreIgnored() throws {
        let dir = TempDir()
        let boot = Date().addingTimeInterval(-86_400)
        do {
            let core = try identityCore(dir)
            runAgentJob(core.tree)
            core.persistAgentAncestry(bootTime: boot.addingTimeInterval(-3_600))
        }
        let fresh = try identityCore(dir)
        seedAfterRestart(fresh)
        fresh.restoreAgentAncestry(bootTime: boot)
        XCTAssertNil(fresh.tree.chain(nodeID: try XCTUnwrap(fresh.tree.node(pid: 701)?.id)).nearestAgent)
        // Saved during this boot: restored.
        do {
            let core = try identityCore(dir)
            runAgentJob(core.tree)
            core.persistAgentAncestry(bootTime: boot)
        }
        let again = try identityCore(dir)
        seedAfterRestart(again)
        again.restoreAgentAncestry(bootTime: boot)
        XCTAssertEqual(again.tree.chain(nodeID: try XCTUnwrap(again.tree.node(pid: 701)?.id)).nearestAgent, "claude-code")
    }

    /// Saved only when the agent ancestry changed, and never more than the byte budget (the oldest kept).
    func testSavedWhenChangedAndBounded() throws {
        let dir = TempDir()
        let core = try identityCore(dir)
        runAgentJob(core.tree)
        core.persistAgentAncestry()
        try core.store.setValue(nil, forKey: DaemonCore.agentAncestryKey)
        core.persistAgentAncestry()
        XCTAssertNil(try core.store.value(forKey: DaemonCore.agentAncestryKey), "unchanged: not written again")

        // Many jobs, each below a program with a long path, all under the agent.
        let deep = "/Users/alice/" + String(repeating: "d", count: 3000) + "/tool"
        for i in Int32(0)..<250 {
            let tool = p(1000 + 2 * i, deep, ppid: 600, 10 + TimeInterval(i), platform: false)
            spawn(core.tree, claude, tool)
            spawn(core.tree, tool, p(1001 + 2 * i, "/bin/sleep", ppid: tool.pid, 10 + TimeInterval(i)))
        }
        XCTAssertGreaterThan(try JSONEncoder().encode(core.tree.agentAncestry()).count, DaemonCore.maxAgentAncestryBytes)
        core.persistAgentAncestry()
        let data = try XCTUnwrap(try core.store.value(forKey: DaemonCore.agentAncestryKey))
        XCTAssertLessThanOrEqual(data.count, DaemonCore.maxAgentAncestryBytes)
        let stored = try JSONDecoder().decode(DaemonCore.StoredAgentAncestry.self, from: data)
        XCTAssertFalse(stored.records.isEmpty)
        XCTAssertEqual(stored.records.first?.pid, 600, "the oldest first")
    }
}

#if canImport(EndpointSecurity)
import EndpointSecurity

/// An es_process_t built by hand in zeroed memory, laid out by the real SDK headers.
private final class FakeESProcess {
    private var blocks: [UnsafeMutableRawPointer] = []
    let process: UnsafeMutablePointer<es_process_t>

    init(pid: Int32, pidVersion: Int32, path: String) {
        func zeroed(_ size: Int, _ alignment: Int) -> UnsafeMutableRawPointer {
            let raw = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: max(alignment, 16))
            raw.initializeMemory(as: UInt8.self, repeating: 0, count: size)
            return raw
        }
        let p = zeroed(MemoryLayout<es_process_t>.stride, MemoryLayout<es_process_t>.alignment)
        let bytes = Array(path.utf8)
        let chars = zeroed(bytes.count + 1, 1)
        bytes.withUnsafeBytes { chars.copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        let f = zeroed(MemoryLayout<es_file_t>.stride, MemoryLayout<es_file_t>.alignment).bindMemory(to: es_file_t.self, capacity: 1)
        f.initialize(to: es_file_t(path: es_string_token_t(length: bytes.count, data: chars.assumingMemoryBound(to: CChar.self)),
                                   path_truncated: false, stat: stat()))
        blocks = [p, chars, UnsafeMutableRawPointer(f)]
        process = p.bindMemory(to: es_process_t.self, capacity: 1)
        set(\.executable, f)
        set(\.audit_token, FakeESProcess.token(pid: pid, version: pidVersion))
    }

    deinit { blocks.forEach { $0.deallocate() } }

    static func token(pid: Int32, version: Int32) -> audit_token_t {
        // audit_token_to_pid reads val[5], audit_token_to_pidversion val[7] (libbsm).
        audit_token_t(val: (0, 501, 20, 501, 20, UInt32(bitPattern: pid), 100_017, UInt32(bitPattern: version)))
    }

    func set<T>(_ field: PartialKeyPath<es_process_t>, _ value: T) {
        let offset = MemoryLayout<es_process_t>.offset(of: field)!
        (UnsafeMutableRawPointer(process) + offset).storeBytes(of: value, as: T.self)
    }
}

final class NativeProcessRecordTests: XCTestCase {
    /// sdk-D3/D4: the parent token, the responsible token (the process itself = none), the signing
    /// category and the code signing flags, each read only from the message version that has it.
    func testTheRecordCarriesTokensSigningCategoryAndFlags() {
        let fake = FakeESProcess(pid: 501, pidVersion: 5_010, path: "/Applications/Tool.app/Contents/MacOS/Tool")
        fake.set(\.ppid, Int32(500))
        fake.set(\.original_ppid, Int32(500))
        fake.set(\.parent_audit_token, FakeESProcess.token(pid: 500, version: 5_000))
        fake.set(\.responsible_audit_token, FakeESProcess.token(pid: 501, version: 5_010))
        #if compiler(>=6.2)
        fake.set(\.cs_validation_category, ES_CS_VALIDATION_CATEGORY_DEVELOPMENT)
        #endif
        fake.set(\.codesigning_flags, UInt32(0x2201_3b15))

        let r = NativeESSource.record(fake.process, version: 10)
        XCTAssertEqual(r.pid, 501)
        XCTAssertEqual(r.pidVersion, 5_010)
        XCTAssertEqual(r.parentToken, ProcessToken(pid: 500, pidVersion: 5_000))
        XCTAssertNil(r.responsiblePID, "the process itself: no responsible process")
        #if compiler(>=6.2)
        XCTAssertEqual(r.signingCategory, .development)
        #else
        XCTAssertNil(r.signingCategory, "an SDK older than macOS 26 cannot read the field")
        #endif
        XCTAssertEqual(r.codeSigningFlags, 0x2201_3b15)
        XCTAssertTrue(r.isControllable, "CS_GET_TASK_ALLOW")
        XCTAssertFalse(r.hasDistributionSignature)

        // Another responsible process is kept.
        fake.set(\.responsible_audit_token, FakeESProcess.token(pid: 400, version: 4_000))
        XCTAssertEqual(NativeESSource.record(fake.process, version: 10).responsiblePID, 400)

        // Fields newer than the message are not read.
        let v9 = NativeESSource.record(fake.process, version: 9)
        XCTAssertNil(v9.signingCategory)
        XCTAssertNotNil(v9.parentToken)
        let v3 = NativeESSource.record(fake.process, version: 3)
        XCTAssertNil(v3.parentToken)
        XCTAssertNil(v3.responsiblePID)
        XCTAssertEqual(v3.codeSigningFlags, 0x2201_3b15, "codesigning_flags exists in every version")
    }
}
#endif
