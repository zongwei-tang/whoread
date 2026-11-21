import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadStore
@testable import WhoReadEngine

// Ask mode, daemon half (docs/ASK_MODE.md): AskBroker, the Enforcer's ask path, answers, no automatic
// switch-off, unclean stops.

private let askT = Date(timeIntervalSince1970: 1_760_000_000)
private let askKeyPath = "/Users/alice/.ssh/id_ed25519"
private let terminalKey = "app:/system/applications/utilities/terminal.app"
private let rootPeer = IPCPeer(pid: 1, euid: 0, isTrustedCode: false)
private let agentPeer = IPCPeer(pid: 4242, euid: 501, isTrustedCode: false)

/// Answers delivered to held accesses, per access.
private final class Answers: @unchecked Sendable {
    private let lock = NSLock()
    private var byAccess: [Int: [AskBroker.Answer]] = [:]
    private var threads: [Thread] = []

    func respond(_ access: Int) -> @Sendable (AskBroker.Answer) -> Void {
        { answer in
            self.lock.lock()
            self.byAccess[access, default: []].append(answer)
            self.threads.append(Thread.current)
            self.lock.unlock()
        }
    }

    func of(_ access: Int) -> [AskBroker.Answer] {
        lock.lock(); defer { lock.unlock() }
        return byAccess[access] ?? []
    }

    var all: [Int: [AskBroker.Answer]] {
        lock.lock(); defer { lock.unlock() }
        return byAccess
    }

    var respondingThreads: [Thread] {
        lock.lock(); defer { lock.unlock() }
        return threads
    }
}

private final class MutableClock: @unchecked Sendable {
    private let lock = NSLock()
    private var t: Date
    init(_ t: Date) { self.t = t }
    var now: Date {
        lock.lock(); defer { lock.unlock() }
        return t
    }
    func advance(_ s: TimeInterval) { lock.lock(); t = t.addingTimeInterval(s); lock.unlock() }
}

private func request(_ key: String = terminalKey, category: String = "ssh", access: AccessSet = .read,
                     agents: [String] = [], apple: Bool = false) -> AskRequest {
    AskRequest(id: 0, key: AskKey(responsibleKey: key, categoryID: category, access: access, chainAgents: agents),
               responsible: ResponsibleEntity(kind: .app, key: key, displayName: "Terminal"), severity: .critical,
               path: askKeyPath, process: proc(501, "/bin/cat", platform: true), chain: [], agentID: agents.first,
               appleProgram: apple, firstAt: askT, lastAt: askT)
}

private func heldID(_ d: AskBroker.Disposition, file: StaticString = #filePath, line: UInt = #line) -> Int64? {
    if case .held(let id) = d { return id }
    XCTFail("not held: \(d)", file: file, line: line)
    return nil
}

/// A broker that holds with short budgets (an answering app is present).
private func presentBroker(maxHeld: Int = 256) -> AskBroker {
    // A long presence window: on a loaded machine a test can take longer than the default 5 s, and
    // these tests are not about an app that stopped polling.
    let b = AskBroker(presenceWindow: 600, maxHeld: maxHeld, minimumBudget: 0.01)
    b.noteAnsweringClient()
    return b
}

// MARK: - AskBroker

final class AskBrokerTests: XCTestCase {
    func testAnUnansweredAccessIsDeniedOnceWhenItsBudgetRunsOutAndTheQuestionStays() throws {
        let b = presentBroker()
        let answers = Answers()
        let id = try XCTUnwrap(heldID(b.hold(request(), budget: 0.1, respond: answers.respond(1))))
        let open = try XCTUnwrap(b.request(id: id))
        XCTAssertEqual(open.holding, 1)
        XCTAssertEqual(open.attempts, 1)
        XCTAssertNotNil(open.answerBy)
        XCTAssertEqual(answers.of(1), [], "not answered inside hold")
        XCTAssertNotNil(waitFor(2) { answers.of(1) == [.deny] })
        Thread.sleep(forTimeInterval: 0.1)
        b.drain()
        XCTAssertEqual(answers.of(1), [.deny], "exactly once")
        let after = try XCTUnwrap(b.request(id: id), "the question stays open for a later answer")
        XCTAssertEqual(after.holding, 0)
        XCTAssertNil(after.answerBy)
        XCTAssertEqual(b.heldAccesses, 0)
        // A later answer finds nothing held: nobody is answered twice.
        XCTAssertNotNil(b.resolve(id: id, answer: .allow))
        b.drain()
        XCTAssertEqual(answers.of(1), [.deny])
        XCTAssertTrue(b.pending().isEmpty)
    }

    func testRespondRunsOnTheBrokerQueueNeverOnTheCallingThread() throws {
        let b = AskBroker(minimumBudget: 0)
        b.noteAnsweringClient()
        let answers = Answers()
        for i in 0..<20 { _ = b.hold(request(category: "c\(i)"), budget: 0, respond: answers.respond(i)) }
        XCTAssertNotNil(waitFor(2) { answers.all.count == 20 })
        XCTAssertFalse(answers.respondingThreads.contains { $0 === Thread.current })
    }

    func testWithoutAnAnsweringAppAccessesAreDeniedAtOnceButListed() throws {
        let clock = MutableClock(askT)
        let b = AskBroker(minimumBudget: 0.01, now: { clock.now })
        let answers = Answers()
        guard case .denyNow(let id?) = b.hold(request(), budget: 5, respond: answers.respond(1)) else { return XCTFail() }
        XCTAssertEqual(b.request(id: id)?.attempts, 1)
        XCTAssertEqual(b.request(id: id)?.holding, 0)
        XCTAssertFalse(b.answeringClientPresent)
        b.noteAnsweringClient()
        XCTAssertTrue(b.answeringClientPresent)
        XCTAssertEqual(b.hold(request(), budget: 5, respond: answers.respond(2)), .held(requestID: id), "same question")
        XCTAssertEqual(b.request(id: id)?.attempts, 2)
        // The app stopped polling: after the presence window, deny at once again.
        clock.advance(5.5)
        XCTAssertFalse(b.answeringClientPresent)
        XCTAssertEqual(b.hold(request(), budget: 5, respond: answers.respond(3)), .denyNow(requestID: id))
        b.denyAll()
        XCTAssertEqual(answers.of(1), [], "denyNow: respond is never called")
        XCTAssertEqual(answers.of(2), [.deny])
        XCTAssertEqual(answers.of(3), [])
    }

    func testTooLittleBudgetOrTooManyHeldDeniesAtOnce() throws {
        let b = AskBroker(maxHeld: 2)  // minimumBudget 0.5 s
        b.noteAnsweringClient()
        let answers = Answers()
        guard case .denyNow(let id?) = b.hold(request(), budget: 0.4, respond: answers.respond(0)) else { return XCTFail() }
        XCTAssertEqual(b.hold(request(), budget: 30, respond: answers.respond(1)), .held(requestID: id))
        XCTAssertNotNil(heldID(b.hold(request(category: "aws"), budget: 30, respond: answers.respond(2))))
        guard case .denyNow(let third?) = b.hold(request(category: "gcp"), budget: 30, respond: answers.respond(3)) else {
            return XCTFail("a third access is not held")
        }
        XCTAssertNotNil(b.request(id: third), "still listed")
        XCTAssertEqual(b.heldAccesses, 2)
        b.denyAll()
        XCTAssertEqual(answers.all, [1: [.deny], 2: [.deny]])
    }

    func testSameKeySharesOneQuestionAndIdsAreMonotonic() throws {
        let b = presentBroker()
        let answers = Answers()
        let a = try XCTUnwrap(heldID(b.hold(request(), budget: 30, respond: answers.respond(1))))
        XCTAssertEqual(b.hold(request(), budget: 30, respond: answers.respond(2)), .held(requestID: a))
        let other = try XCTUnwrap(heldID(b.hold(request(access: .write), budget: 30, respond: answers.respond(3))))
        XCTAssertGreaterThan(other, a)
        XCTAssertEqual(b.request(id: a)?.attempts, 2)
        XCTAssertEqual(b.request(id: a)?.holding, 2)
        XCTAssertEqual(b.pending().map(\.id), [a, other], "oldest first")
        let resolved = try XCTUnwrap(b.resolve(id: a, answer: .allow))
        XCTAssertEqual(resolved.holding, 2)
        b.drain()
        XCTAssertEqual(answers.of(1), [.allow])
        XCTAssertEqual(answers.of(2), [.allow])
        XCTAssertEqual(answers.of(3), [], "another key is another question")
        XCTAssertNil(b.request(id: a))
        // The same key asks again later: a new question with a new id.
        let again = try XCTUnwrap(heldID(b.hold(request(), budget: 30, respond: answers.respond(4))))
        XCTAssertGreaterThan(again, other)
        b.denyAll()
    }

    func testEveryHeldAccessIsAnsweredExactlyOnceUnderRaces() throws {
        let b = presentBroker()
        let answers = Answers()
        let n = 200
        DispatchQueue.concurrentPerform(iterations: n) { i in
            let r = request(category: "c\(i % 7)", access: i % 2 == 0 ? .read : .write)
            _ = b.hold(r, budget: Double(i % 5) * 0.01 + 0.01, respond: answers.respond(i))
            switch i % 4 {
            case 0: _ = b.pending().first.map { b.resolve(id: $0.id, answer: .allow) }
            case 1: b.resolveMatching(.deny) { $0.key.access == .write }
            case 2: if i % 40 == 2 { b.denyAll() }
            default: break
            }
        }
        b.denyAll()
        XCTAssertNotNil(waitFor(2) { answers.all.count == n })
        Thread.sleep(forTimeInterval: 0.1)
        b.drain()
        let all = answers.all
        XCTAssertEqual(all.count, n)
        XCTAssertTrue(all.values.allSatisfy { $0.count == 1 }, "\(all.filter { $0.value.count != 1 })")
        XCTAssertEqual(b.heldAccesses, 0)
    }

    func testDenyAllReturnsOnlyAfterEveryHeldAccessWasAnswered() throws {
        let b = presentBroker()
        let answers = Answers()
        let first = try XCTUnwrap(heldID(b.hold(request(category: "aws"), budget: 60, respond: answers.respond(0))))
        for i in 1...50 { _ = b.hold(request(category: "c\(i % 5)"), budget: 60, respond: answers.respond(i)) }
        // Queued before denyAll: delivered before it returns, with its own answer.
        b.resolve(id: first, answer: .allow)
        b.denyAll()
        let all = answers.all
        XCTAssertEqual(all.count, 51, "no drain needed")
        XCTAssertEqual(all[0], [.allow])
        XCTAssertTrue((1...50).allSatisfy { all[$0] == [.deny] })
        XCTAssertEqual(b.pending().count, 5, "the questions stay listed")
        XCTAssertTrue(b.pending().allSatisfy { $0.holding == 0 && $0.answerBy == nil })
        // The broker keeps working after denyAll (the native source reconnects after a setup failure).
        XCTAssertNotNil(heldID(b.hold(request(), budget: 60, respond: answers.respond(99))))
        b.denyAll()
        XCTAssertEqual(answers.of(99), [.deny])
    }

    func testUnansweredQuestionsExpire() throws {
        let clock = MutableClock(askT)
        let b = AskBroker(requestLifetime: 10, minimumBudget: 0.01, now: { clock.now })
        let answers = Answers()
        _ = b.hold(request(), budget: 60, respond: answers.respond(1))   // denied at once: no app
        b.noteAnsweringClient()
        let held = try XCTUnwrap(heldID(b.hold(request(category: "aws"), budget: 60, respond: answers.respond(2))))
        clock.advance(11)
        b.expire()
        XCTAssertEqual(b.pending().map(\.id), [held], "a question with a held access is kept")
        b.denyAll()
        clock.advance(11)
        b.expire()
        XCTAssertTrue(b.pending().isEmpty)
    }

    func testResolveMatchingAnswersOnlyTheMatchingQuestions() throws {
        let b = presentBroker()
        let answers = Answers()
        let apple = try XCTUnwrap(heldID(b.hold(request(apple: true), budget: 60, respond: answers.respond(1))))
        _ = b.hold(request(apple: true), budget: 60, respond: answers.respond(2))
        _ = b.hold(request("agent:claude-code", agents: ["claude-code"]), budget: 60, respond: answers.respond(3))
        let released = b.resolveMatching(.allow) { $0.appleProgram }
        XCTAssertEqual(released.map(\.id), [apple])
        b.drain()
        XCTAssertEqual(answers.of(1), [.allow])
        XCTAssertEqual(answers.of(2), [.allow])
        XCTAssertEqual(answers.of(3), [])
        XCTAssertEqual(b.pending().count, 1)
        b.denyAll()
    }

    func testTheRequestTableIsBounded() throws {
        let b = AskBroker()   // no app: nothing held, everything listed
        let answers = Answers()
        for i in 0..<(AskBroker.maxRequests + 10) {
            _ = b.hold(request("bin:/tmp/copy\(i)"), budget: 60, respond: answers.respond(i))
        }
        XCTAssertEqual(b.pending().count, AskBroker.maxRequests)
        XCTAssertEqual(b.pending().last?.key.responsibleKey, "bin:/tmp/copy\(AskBroker.maxRequests + 9)", "the oldest go first")
    }
}

// MARK: - Daemon

private func askCore(_ dir: TempDir, _ configure: (inout DaemonConfiguration) -> Void = { _ in }) throws -> DaemonCore {
    var config = baseConfig(dir)
    config.resolveOwners = false
    configure(&config)
    return try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
}

private func enable(_ core: DaemonCore) throws {
    try core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
    core.drainPolicyQueue()
}

/// Terminal → zsh → leaf.
private func terminalChild(_ core: DaemonCore, _ leaf: ProcessRecord) -> ProcessRecord {
    core.tree.observe(proc(100, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", ppid: 1, platform: true), at: askT)
    core.tree.observe(proc(500, "/bin/zsh", ppid: 100, platform: true), at: askT)
    var l = leaf
    l.ppid = 500
    l.originalPPID = 500
    core.tree.observe(l, at: askT)
    return l
}

/// zsh → node running Claude Code → leaf.
private func agentChild(_ core: DaemonCore, _ leaf: ProcessRecord) -> ProcessRecord {
    core.tree.observe(proc(510, "/bin/zsh", ppid: 1, platform: true), at: askT)
    core.tree.observe(proc(600, "/opt/homebrew/Cellar/node/22.9.0/bin/node", ppid: 510, argv: ["node", "/opt/homebrew/bin/claude"]), at: askT)
    var l = leaf
    l.ppid = 600
    l.originalPPID = 600
    core.tree.observe(l, at: askT)
    return l
}

private func open(_ p: ProcessRecord, _ path: String = askKeyPath, write: Bool = false) -> FileActivity {
    FileActivity(time: askT.addingTimeInterval(100), operation: .open, process: p,
                 targets: OperationSemantics.open(path: path, fflag: write ? 2 : 1))
}

/// What the rule engine's ask decision carries (built here, so these tests do not depend on the
/// rule-engine half of ask mode).
private func askDecision(_ core: DaemonCore, _ a: FileActivity, category: String = "ssh") -> RuleDecision {
    let chain = core.tree.chain(for: a.process, at: a.time)
    let access = a.targets.reduce(AccessSet()) { $0.union($1.access) }
    let key = AskKey(responsibleKey: core.attributor.attribute(chain: chain).key, categoryID: category, access: access,
                     chainAgents: chain.compactMap(\.agentID))
    return RuleDecision(verdict: .ask, reason: .askUser, askKey: key)
}

/// What the native source does with an `.ask` decision: build the question and hold the access.
@discardableResult
private func holdAccess(_ core: DaemonCore, _ a: FileActivity, _ answers: Answers, _ n: Int, category: String = "ssh",
                        budget: TimeInterval = 60) throws -> Int64 {
    let q = try XCTUnwrap(core.enforcer.askRequest(for: a, decision: askDecision(core, a, category: category)))
    core.askBroker.noteAnsweringClient()
    return try XCTUnwrap(heldID(core.askBroker.hold(q, budget: budget, respond: answers.respond(n))))
}

private func strictHandler(_ core: DaemonCore) -> ServiceHandler {
    let h = ServiceHandler(daemon: core, policy: .strict)
    h.consoleUID = { 501 }
    return h
}

private func errorCode(_ r: IPCResponse) -> IPCError.Code? {
    if case .error(let e) = r { return e.code }
    return nil
}

private func askAlert(id: Int64, kind: AlertKind = .ask, key: String = terminalKey, category: String = "ssh",
                      access: AccessSet = .read, apple: Bool = false, chain: [ChainLink] = []) -> Alert {
    Alert(id: id, kind: kind, createdAt: Date(), updatedAt: Date(), windowEndsAt: Date().addingTimeInterval(600),
          responsible: ResponsibleEntity(kind: .app, key: key, displayName: "Terminal"), categoryID: category, severity: .critical,
          count: 1, accesses: access, firstPath: askKeyPath, firstEventID: 1, lastEventID: 1, paths: [askKeyPath], chain: chain,
          agentID: nil, ruleID: nil, appleProgram: apple)
}

private func answerRules(_ core: DaemonCore) -> [Rule] {
    core.rules.rules.filter { $0.template == DaemonCore.askAnswerTemplate }
}

final class AskEnforcerTests: XCTestCase {
    func testThePolicyFollowsTrustAndTheBenignChain() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try enable(core)
        let cat = terminalChild(core, proc(501, "/bin/cat", platform: true))
        let chain = core.tree.chain(for: cat, at: askT)
        XCTAssertEqual(core.enforcer.askPolicy(chain: chain), AskPolicy(enabled: true, trustApplePrograms: false, benignChain: false))
        let mds = proc(300, "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Support/mds_stores",
                       ppid: 1, platform: true)
        core.tree.observe(mds, at: askT)
        XCTAssertTrue(core.enforcer.askPolicy(chain: core.tree.chain(for: mds, at: askT)).benignChain)
        try core.mutateSettings(peer: .inProcess) { $0.trustApplePrograms = true }
        XCTAssertTrue(core.enforcer.askPolicy(chain: chain).trustApplePrograms)
        try core.mutateSettings(peer: .inProcess) { $0.trustApplePrograms = false }
        XCTAssertFalse(core.enforcer.trustApplePrograms)
        // Nowhere to hold an access: nothing is asked.
        let bare = Enforcer(analyzer: core.analyzer, state: core.enforcement, latency: core.latency)
        XCTAssertEqual(bare.askPolicy(chain: chain), .off)
        XCTAssertNil(bare.askBroker)
        XCTAssertTrue(core.enforcer.askBroker === core.askBroker)
    }

    func testTheQuestionCarriesKeyDisplayDataAndAppleEligibility() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        var cat = proc(501, "/bin/cat", platform: true, argv: ["cat", "--password=hunter2", askKeyPath])
        cat = terminalChild(core, cat)
        let a = open(cat)
        let d = askDecision(core, a)
        let q = try XCTUnwrap(core.enforcer.askRequest(for: a, decision: d))
        XCTAssertEqual(q.key, d.askKey)
        XCTAssertEqual(q.key.responsibleKey, terminalKey)
        XCTAssertEqual(q.responsible.displayName, "Terminal")
        XCTAssertEqual(q.path, askKeyPath)
        XCTAssertEqual(q.severity, .critical)
        XCTAssertEqual(Array(q.chain.map(\.name).suffix(3)), ["Terminal", "zsh", "cat"], "root first")
        // Raw here (the ES callback); the broker redacts it off the callback and shows none until then.
        let b = presentBroker()
        let id = try XCTUnwrap(heldID(b.hold(q, budget: 60, respond: Answers().respond(1))))
        b.drainRedaction()
        let shownArgv = try XCTUnwrap(b.request(id: id)?.process.argv).joined(separator: " ")
        XCTAssertFalse(shownArgv.contains("hunter2"), "argv redacted")
        XCTAssertTrue(shownArgv.contains(askKeyPath))
        b.denyAll()
        XCTAssertNil(q.agentID)
        XCTAssertTrue(q.appleProgram, "/bin/cat is an Apple program in a system location, no agent")

        // Under an AI agent: never eligible for "trust Apple programs".
        let agentCat = agentChild(core, proc(601, "/bin/cat", platform: true))
        let qa = try XCTUnwrap(core.enforcer.askRequest(for: open(agentCat), decision: askDecision(core, open(agentCat))))
        XCTAssertEqual(qa.agentID, "claude-code")
        XCTAssertEqual(qa.key.chainAgents, ["claude-code"])
        XCTAssertFalse(qa.appleProgram)
        // A copy of an Apple binary outside the system locations is not an Apple program.
        let copy = terminalChild(core, proc(502, "/Users/alice/bin/cat", platform: true))
        XCTAssertFalse(try XCTUnwrap(core.enforcer.askRequest(for: open(copy), decision: askDecision(core, open(copy)))).appleProgram)

        // Not an ask, no key, or a category the access does not touch: no question (deny at once).
        XCTAssertNil(core.enforcer.askRequest(for: a, decision: RuleDecision(verdict: .allow, reason: .defaultAllow)))
        XCTAssertNil(core.enforcer.askRequest(for: a, decision: RuleDecision(verdict: .ask, reason: .askUser)))
        XCTAssertNil(core.enforcer.askRequest(for: a, decision: askDecision(core, a, category: "aws")))
    }

    /// Needs the rule-engine half of ask mode (RuleEngine honours AskPolicy): skipped until it is merged.
    func testAnUndecidedAccessIsAskedAndTheAnswerDecidesTheNextOne() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try core.setRules([])
        try enable(core)
        let cat = terminalChild(core, proc(501, "/bin/cat", platform: true))
        let d = core.enforcer.decide(open(cat))
        try XCTSkipUnless(d.verdict == .ask, "needs the rule-engine half of ask mode (verdict \(d.verdict))")
        XCTAssertEqual(d.reason, .askUser)
        let q = try XCTUnwrap(core.enforcer.askRequest(for: open(cat), decision: d))
        core.askBroker.noteAnsweringClient()
        let answers = Answers()
        let id = try XCTUnwrap(heldID(core.askBroker.hold(q, budget: 60, respond: answers.respond(1))))
        try core.answerAsk(id: id, action: .alwaysAllow, peer: .inProcess, privileged: true)
        core.askBroker.drain()
        XCTAssertEqual(answers.of(1), [.allow])
        XCTAssertEqual(core.enforcer.decide(open(cat)).verdict, .allow)
        XCTAssertNotEqual(core.enforcer.decide(open(cat, write: true)).verdict, .allow, "a read answer is not a write answer")
    }

    func testResponsesAreStatisticsOnly() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try enable(core)
        for _ in 0..<500 { core.enforcer.recordResponse(micros: 900_000, missedDeadline: true) }
        for _ in 0..<5 { core.checkLatency() }
        core.drainPolicyQueue()
        XCTAssertTrue(core.enforcement.isActive)
        XCTAssertTrue(core.currentSettings.enforcementEnabled)
        let s = core.status()
        XCTAssertNil(s.latencyTripReason)
        XCTAssertEqual(s.latency.deadlineMisses, 500)
        XCTAssertFalse(s.enforcementInactiveReasons.contains(.latencyTripped))
        XCTAssertEqual(s.mode, .enforcing, "ask mode enforces without a deny rule")
    }
}

final class AskAnswerTests: XCTestCase {
    func testAllowOnceAndAlwaysAllowSaveScopedAllowRulesAndReleaseTheQuestion() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try core.setRules([])
        try enable(core)
        let answers = Answers()
        let cat = terminalChild(core, proc(501, "/bin/cat", platform: true))
        let id = try holdAccess(core, open(cat), answers, 1)
        try holdAccess(core, open(cat), answers, 2)   // same key: same question
        let before = Date()
        try core.answerAsk(id: id, action: .allowOnce, peer: .inProcess, privileged: true)
        core.askBroker.drain()
        XCTAssertEqual(answers.of(1), [.allow])
        XCTAssertEqual(answers.of(2), [.allow])
        XCTAssertTrue(core.askBroker.pending().isEmpty)
        let once = try XCTUnwrap(answerRules(core).first)
        XCTAssertEqual(once.action, .allow)
        XCTAssertEqual(once.target, .category("ssh"))
        XCTAssertEqual(once.subject, .responsible(key: terminalKey, teamID: nil, cdhash: nil))
        XCTAssertEqual(once.access, .read)
        XCTAssertEqual(once.chainAgents, [])
        let expires = try XCTUnwrap(once.expiresAt)
        XCTAssertEqual(expires.timeIntervalSince(before), 600, accuracy: 5)
        XCTAssertTrue(try core.store.loadRules()?.contains { $0.id == once.id } == true, "saved")
        // Another "allow once" for the same scope replaces it instead of piling up.
        let again = try holdAccess(core, open(cat), answers, 3)
        try core.answerAsk(id: again, action: .allowOnce, peer: .inProcess, privileged: true)
        XCTAssertEqual(answerRules(core).count, 1)

        // An agent's chain: the answer is scoped to exactly the agents seen.
        let agentCat = agentChild(core, proc(601, "/bin/cat", platform: true))
        let agentQ = try holdAccess(core, open(agentCat, write: true), answers, 4)
        try core.answerAsk(id: agentQ, action: .alwaysAllow, peer: .inProcess, privileged: true)
        core.askBroker.drain()
        XCTAssertEqual(answers.of(4), [.allow])
        let always = try XCTUnwrap(answerRules(core).first { $0.expiresAt == nil })
        XCTAssertEqual(always.subject, .responsible(key: "agent:claude-code", teamID: nil, cdhash: nil))
        XCTAssertEqual(always.access, .write)
        XCTAssertEqual(always.chainAgents, ["claude-code"])
        // The same permanent answer twice: one rule.
        let dup = try holdAccess(core, open(agentCat, write: true), answers, 5)
        try core.answerAsk(id: dup, action: .alwaysAllow, peer: .inProcess, privileged: true)
        XCTAssertEqual(answerRules(core).filter { $0.expiresAt == nil }.count, 1)
        XCTAssertThrowsError(try core.answerAsk(id: dup, action: .alwaysAllow, peer: .inProcess, privileged: true)) { e in
            XCTAssertEqual((e as? IPCError)?.code, .notFound, "answered")
        }
    }

    func testAnAllowAnswerReleasesOnlyTheQuestionsItsRuleCovers() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try enable(core)
        let answers = Answers()
        let cat = terminalChild(core, proc(501, "/bin/cat", platform: true))
        let read = try holdAccess(core, open(cat), answers, 1)
        try holdAccess(core, open(cat, write: true), answers, 2)                       // write: not covered by a read answer
        let agentCat = agentChild(core, proc(601, "/bin/cat", platform: true))
        try holdAccess(core, open(agentCat), answers, 3)                               // another subject
        try holdAccess(core, open(cat, "/Users/alice/.aws/credentials"), answers, 4, category: "aws")
        try core.answerAsk(id: read, action: .alwaysAllow, peer: .inProcess, privileged: true)
        core.askBroker.drain()
        XCTAssertEqual(answers.all, [1: [.allow]])
        XCTAssertEqual(core.askBroker.pending().count, 3)
        core.askBroker.denyAll()
    }

    func testAllowingNeedsPrivilegeDenyingDoesNot() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try core.setRules([])
        try enable(core)
        let answers = Answers()
        let cat = terminalChild(core, proc(501, "/bin/cat", platform: true))
        let id = try holdAccess(core, open(cat), answers, 1)
        for action in [AlertAction.allowOnce, .alwaysAllow, .trustApplePrograms] {
            XCTAssertThrowsError(try core.answerAsk(id: id, action: action, peer: agentPeer, privileged: false), "\(action)") { e in
                XCTAssertEqual((e as? IPCError)?.code, .notPermitted)
            }
        }
        let handler = strictHandler(core)
        XCTAssertEqual(handler.privilege(of: .answerAsk(id: id, action: .allowOnce)), .weaken)
        XCTAssertEqual(errorCode(handler.handle(.answerAsk(id: id, action: .alwaysAllow), peer: agentPeer)), .notPermitted)
        XCTAssertTrue(core.rules.rules.isEmpty)
        XCTAssertEqual(core.askBroker.request(id: id)?.holding, 1, "still waiting")
        // The console user (possibly an agent) lists and denies.
        guard case .asks(let listed) = handler.handle(.asks, peer: agentPeer) else { return XCTFail() }
        XCTAssertEqual(listed.map(\.id), [id])
        guard case .asks(let left) = handler.handle(.answerAsk(id: id, action: .keepBlocking), peer: agentPeer) else { return XCTFail() }
        XCTAssertTrue(left.isEmpty)
        core.askBroker.drain()
        XCTAssertEqual(answers.of(1), [.deny])
        XCTAssertTrue(core.rules.rules.isEmpty, "deny saves nothing")
        XCTAssertEqual(errorCode(handler.handle(.answerAsk(id: id, action: .keepBlocking), peer: agentPeer)), .notFound)
        // "ignore" is not an answer.
        let other = try holdAccess(core, open(cat), answers, 2)
        XCTAssertThrowsError(try core.answerAsk(id: other, action: .ignore, peer: .inProcess, privileged: true))
        core.askBroker.denyAll()
    }

    func testBlockFromNowOnSavesAnEnforcedDenyRuleAndDeniesWhatItCovers() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try core.setRules([])
        try enable(core)
        let answers = Answers()
        let agentCat = agentChild(core, proc(601, "/bin/cat", platform: true))
        let id = try holdAccess(core, open(agentCat), answers, 1)
        try holdAccess(core, open(agentCat, write: true), answers, 2)
        try holdAccess(core, open(agentCat, "/Users/alice/.aws/credentials"), answers, 3, category: "aws")
        try core.answerAsk(id: id, action: .blockFromNowOn, peer: agentPeer, privileged: false)
        core.askBroker.drain()
        XCTAssertEqual(answers.all, [1: [.deny], 2: [.deny]])
        let rule = try XCTUnwrap(core.rules.rules.first)
        XCTAssertEqual(rule.action, .deny)
        XCTAssertTrue(rule.enforce)
        XCTAssertEqual(rule.template, DaemonCore.blockFromNowOnTemplate)
        XCTAssertEqual(rule.subject, .responsible(key: "agent:claude-code", teamID: nil, cdhash: nil, exceptOwners: true))
        XCTAssertEqual(core.enforcer.decide(open(agentCat)).verdict, .deny)
        XCTAssertEqual(core.askBroker.pending().count, 1)
        core.askBroker.denyAll()
    }

    func testAnswersForAnUnsignedBinaryPinItsCdhash() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try core.setRules([])
        try enable(core)
        var tool = proc(800, "/Users/alice/bin/tool", ppid: 1)
        tool.cdhash = "abcd"
        core.tree.observe(tool, at: askT)
        let answers = Answers()
        let id = try holdAccess(core, open(tool), answers, 1)
        try core.answerAsk(id: id, action: .alwaysAllow, peer: .inProcess, privileged: true)
        XCTAssertEqual(answerRules(core).first?.subject, .responsible(key: "bin:/users/alice/bin/tool", teamID: nil, cdhash: "abcd"))
    }

    func testTrustAppleProgramsTurnsTheSettingOnAndReleasesAppleQuestionsOnly() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try enable(core)
        let answers = Answers()
        let cat = terminalChild(core, proc(501, "/bin/cat", platform: true))
        let apple = try holdAccess(core, open(cat), answers, 1)
        let agentCat = agentChild(core, proc(601, "/bin/cat", platform: true))
        let agentQ = try holdAccess(core, open(agentCat), answers, 2)
        XCTAssertThrowsError(try core.answerAsk(id: agentQ, action: .trustApplePrograms, peer: .inProcess, privileged: true)) { e in
            XCTAssertEqual((e as? IPCError)?.code, .invalid, "never offered under an AI agent")
        }
        try core.answerAsk(id: apple, action: .trustApplePrograms, peer: .inProcess, privileged: true)
        core.askBroker.drain()
        XCTAssertTrue(core.currentSettings.trustApplePrograms)
        XCTAssertTrue(try core.store.settings().trustApplePrograms)
        XCTAssertTrue(core.enforcer.trustApplePrograms)
        XCTAssertEqual(answers.all, [1: [.allow]])
        XCTAssertEqual(core.askBroker.pending().map(\.id), [agentQ])
        core.askBroker.denyAll()
    }

    func testTurningTrustOnInSettingsReleasesHeldAppleQuestions() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try enable(core)
        let answers = Answers()
        try holdAccess(core, open(terminalChild(core, proc(501, "/bin/cat", platform: true))), answers, 1)
        try holdAccess(core, open(agentChild(core, proc(601, "/bin/cat", platform: true))), answers, 2)
        try core.mutateSettings(peer: .inProcess) { $0.trustApplePrograms = true }
        core.askBroker.drain()
        XCTAssertEqual(answers.all, [1: [.allow]])
        core.askBroker.denyAll()
    }

    func testAnswersResolveTheMatchingAskAlertsWhenPrivileged() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try core.setRules([])
        try enable(core)
        try core.store.upsert([askAlert(id: 1), askAlert(id: 2, category: "aws"), askAlert(id: 3, kind: .firstAccess),
                               askAlert(id: 4, access: .write)])
        let answers = Answers()
        let cat = terminalChild(core, proc(501, "/bin/cat", platform: true))
        // An unprivileged "block from now on" leaves the alerts open.
        let first = try holdAccess(core, open(cat), answers, 1)
        try core.answerAsk(id: first, action: .blockFromNowOn, peer: agentPeer, privileged: false)
        XCTAssertTrue(try core.store.alerts(AlertQuery()).allSatisfy { $0.status == .unread })
        try core.setRules([])
        let second = try holdAccess(core, open(cat), answers, 2)
        try core.answerAsk(id: second, action: .alwaysAllow, peer: .inProcess, privileged: true)
        core.writer.flush()
        let byID = Dictionary(uniqueKeysWithValues: try core.store.alerts(AlertQuery()).map { ($0.id, $0) })
        XCTAssertEqual(byID[1]?.status, .resolved)
        XCTAssertEqual(byID[1]?.resolution, .alwaysAllow)
        XCTAssertEqual(byID[2]?.status, .unread, "another category")
        XCTAssertEqual(byID[3]?.status, .unread, "not a question")
        XCTAssertEqual(byID[4]?.status, .unread, "a write is not covered by a read answer")
    }

    func testAnsweringAnAskAlertAnswersItsQuestion() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try core.setRules([])
        try enable(core)
        let answers = Answers()
        let cat = terminalChild(core, proc(501, "/bin/cat", platform: true))
        try holdAccess(core, open(cat), answers, 1)
        try core.store.upsert([askAlert(id: 7), askAlert(id: 8)])
        try core.apply(action: .alwaysAllow, toAlert: 7, peer: .inProcess)
        core.askBroker.drain()
        core.writer.flush()
        XCTAssertEqual(answers.of(1), [.allow])
        XCTAssertEqual(answerRules(core).count, 1)
        XCTAssertTrue(core.baseline.isApproved(BaselineKey(responsibleKey: terminalKey, categoryID: "ssh", access: .read)))
        let alerts = try core.store.alerts(AlertQuery())
        XCTAssertTrue(alerts.allSatisfy { $0.status == .resolved && $0.resolution == .alwaysAllow }, "the duplicate too")

        // "Keep blocking" (deny) on an ask alert denies the held accesses it covers.
        try holdAccess(core, open(cat, write: true), answers, 2)
        try core.store.upsert([askAlert(id: 9, access: .write)])
        try core.apply(action: .keepBlocking, toAlert: 9, peer: .inProcess)
        core.askBroker.drain()
        XCTAssertEqual(answers.of(2), [.deny])
        XCTAssertEqual(answerRules(core).count, 1, "deny saves nothing")
        // "Allow once" on a question needs no rule behind the alert.
        try core.store.upsert([askAlert(id: 10, category: "aws")])
        try core.apply(action: .allowOnce, toAlert: 10, peer: .inProcess)
        XCTAssertNotNil(answerRules(core).first { $0.target == .category("aws") && $0.expiresAt != nil })
    }

    func testMonitorOnlyAlertsGetTheSameAllowRuleAndTrust() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try core.setRules([])
        try core.store.upsert([askAlert(id: 1, kind: .criticalNonOwner), askAlert(id: 2, kind: .firstAccess, apple: true),
                               askAlert(id: 3, kind: .firstAccess)])
        try core.apply(action: .alwaysAllow, toAlert: 1, peer: .inProcess)
        let rule = try XCTUnwrap(answerRules(core).first)
        XCTAssertNil(rule.expiresAt)
        XCTAssertEqual(rule.access, .read)
        XCTAssertTrue(core.baseline.isApproved(BaselineKey(responsibleKey: terminalKey, categoryID: "ssh", access: .read)),
                      "the baseline approval is kept")
        XCTAssertThrowsError(try core.apply(action: .trustApplePrograms, toAlert: 3, peer: .inProcess)) { e in
            XCTAssertEqual((e as? IPCError)?.code, .invalid)
        }
        XCTAssertThrowsError(try core.apply(action: .trustApplePrograms, toAlert: 2, peer: agentPeer, privileged: false))
        XCTAssertFalse(core.currentSettings.trustApplePrograms)
        try core.apply(action: .trustApplePrograms, toAlert: 2, peer: .inProcess)
        XCTAssertTrue(core.currentSettings.trustApplePrograms)
        XCTAssertEqual(try core.store.alert(id: 2)?.resolution, .trustApplePrograms)
    }

    func testAllowAnswersRespectTheRuleLoadFailureWriteRules() throws {
        let dir = TempDir()
        do {
            let core = try askCore(dir)
            try core.setRules([Rule(id: "a", enabled: true, target: .category("ssh"), subject: .anyNonOwner, action: .alert)])
            // Rule a as a newer WhoRead would have written it.
            let future = #"{"id":"a","target":{"category":"ssh"},"subject":{"type":"teamOnly"},"action":"alert"}"#
            try SQLiteDatabase(path: core.config.databasePath).exec("UPDATE rules SET body = CAST('\(future)' AS BLOB) WHERE id = 'a';")
        }
        let core = try askCore(dir)
        XCTAssertNotNil(core.status().rulesLoadError)
        core.askBroker.noteAnsweringClient()
        let answers = Answers()
        let id = try XCTUnwrap(heldID(core.askBroker.hold(request(), budget: 60, respond: answers.respond(1))))
        XCTAssertThrowsError(try core.answerAsk(id: id, action: .alwaysAllow, peer: rootPeer, privileged: true)) { e in
            XCTAssertEqual((e as? IPCError)?.code, .invalid)
            XCTAssertTrue((e as? IPCError)?.message.contains("rules replace") == true)
        }
        XCTAssertEqual(core.askBroker.request(id: id)?.holding, 1, "nothing released")
        try core.answerAsk(id: id, action: .keepBlocking, peer: rootPeer, privileged: true)
        core.askBroker.drain()
        XCTAssertEqual(answers.of(1), [.deny])
    }

    func testRuleChainAgentsAreBounded() throws {
        var r = Rule(id: "x", target: .category("ssh"), subject: .anyNonOwner, action: .allow,
                     chainAgents: (0..<33).map { "a\($0)" })
        XCTAssertThrowsError(try DaemonCore.validate(r))
        r.chainAgents = [String(repeating: "a", count: 65)]
        XCTAssertThrowsError(try DaemonCore.validate(r))
        r.chainAgents = ["claude-code"]
        XCTAssertNoThrow(try DaemonCore.validate(r))
    }
}

final class AskLifecycleTests: XCTestCase {
    func testEnforcementOffLetsHeldAccessesThrough() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try enable(core)
        let answers = Answers()
        try holdAccess(core, open(terminalChild(core, proc(501, "/bin/cat", platform: true))), answers, 1)
        XCTAssertEqual(core.status().pendingAsks, 1)
        try core.mutateSettings(peer: .inProcess) { $0.enforcementEnabled = false }
        core.drainPolicyQueue()
        core.askBroker.drain()
        XCTAssertEqual(answers.of(1), [.allow])
        XCTAssertEqual(core.status().pendingAsks, 0)
    }

    func testAsksMarksAnAnsweringClientAndStatusCountsQuestions() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        XCTAssertFalse(core.askBroker.answeringClientPresent)
        XCTAssertEqual(core.asks(peer: agentPeer), [])
        XCTAssertTrue(core.askBroker.answeringClientPresent)
        _ = core.askBroker.hold(request(), budget: 60, respond: { _ in })
        XCTAssertEqual(core.status().pendingAsks, 1)
        XCTAssertEqual(core.asks(peer: agentPeer).count, 1)
        core.askBroker.denyAll()
    }

    func testMaintenanceExpiresQuestionsAndDropsExpiredAllowOnceAnswers() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        let stale = Rule(id: "old-once", enabled: true, target: .category("ssh"), subject: .anyNonOwner, action: .allow,
                         expiresAt: Date().addingTimeInterval(-1), template: DaemonCore.askAnswerTemplate)
        let kept = Rule(id: "user-allow", enabled: true, target: .category("ssh"), subject: .anyNonOwner, action: .allow,
                        expiresAt: Date().addingTimeInterval(-1))
        try core.setRules([stale, kept])
        _ = core.askBroker.hold(request(), budget: 60, respond: { _ in })   // listed, not held (no app)
        core.askBroker.requestLifetime = 0
        Thread.sleep(forTimeInterval: 0.01)
        core.maintenance()
        XCTAssertTrue(core.askBroker.pending().isEmpty)
        XCTAssertEqual(core.rules.rules.map(\.id), ["user-allow"], "only answers are dropped")
        XCTAssertEqual(try core.store.loadRules()?.map(\.id), ["user-allow"])
    }

    func testAnUncleanStopIsReportedUntilTheNextCleanStop() throws {
        let dir = TempDir()
        var config = baseConfig(dir)
        config.resolveOwners = false
        do {
            let core = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
            try enable(core)
        }
        XCTAssertTrue(touch(dir.path("data/auth-armed")))
        do {
            let core = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
            XCTAssertTrue(core.enforcement.isActive, "enforcement as the user set it")
            XCTAssertTrue(core.status().uncleanStop?.contains("while enforcing") == true)
        }
        // Gone again without a clean stop (and without AUTH armed): still reported.
        let daemon = try Daemon(configuration: config, makeSource: { _ in FakeSource(canEnforce: true) })
        XCTAssertNotNil(daemon.core.status().uncleanStop)
        try daemon.start()
        daemon.stop()
        XCTAssertNil(daemon.core.status().uncleanStop)
        let after = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        XCTAssertNil(after.status().uncleanStop, "cleared by the clean stop")
        XCTAssertTrue(after.enforcement.isActive)
    }

    func testALegacyTripReasonIsDroppedAtStart() throws {
        let dir = TempDir()
        do {
            let core = try askCore(dir)
            try core.store.setValue(Data("deadline missed".utf8), forKey: DaemonCore.legacyTripKey)
        }
        let core = try askCore(dir)
        XCTAssertNil(try core.store.value(forKey: DaemonCore.legacyTripKey))
        XCTAssertNil(core.status().latencyTripReason)
    }
}

// MARK: - Second review

final class AskDaemonFollowUpTests: XCTestCase {
    /// askRequest runs on the ES callback thread. Redacting argv there (regular expressions over up to
    /// 8 KB per process, 64 processes) took over a second for a crafted chain; the broker redacts it
    /// instead, before anything can be read.
    func testTheQuestionIsBuiltCheaplyAndRedactedOffTheCallback() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        func noisy(_ seed: Int, _ j: Int) -> String {
            String(String(repeating: "?a\(seed)key\(j)x&b=kkkkk \"token\": \"v\(seed)\" ", count: 40).prefix(1020))
        }
        var ppid: Int32 = 1
        var leaf = proc(1, "/sbin/launchd", platform: true)
        for k in 0..<70 {
            let pid = Int32(2000 + k)
            leaf = proc(pid, "/bin/sh", ppid: ppid, platform: true, argv: ["sh", "--token=secret\(k)"] + (0..<7).map { noisy(k, $0) })
            core.tree.observe(leaf, at: askT)
            ppid = pid
        }
        let a = open(leaf)
        let start = Date()
        let q = try XCTUnwrap(core.enforcer.askRequest(for: a, decision: askDecision(core, a)))
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.25, "no argv redaction on the callback")
        XCTAssertEqual(q.chain.count, 64)

        func leaks(_ r: AskRequest?) -> Bool {
            guard let r else { return true }
            return ([r.process.argv ?? []] + r.chain.map { $0.argv ?? [] }).joined().contains { $0.contains("secret") }
        }
        let b = presentBroker()
        let answers = Answers()
        let id = try XCTUnwrap(heldID(b.hold(q, budget: 60, respond: answers.respond(1))))
        // Before the redact queue got to it (or after): never the raw argv.
        XCTAssertFalse(leaks(b.request(id: id)))
        XCTAssertFalse(leaks(b.pending().first))
        b.drainRedaction()
        let shown = try XCTUnwrap(b.request(id: id))
        XCTAssertFalse(leaks(shown))
        XCTAssertEqual(shown.chain.count, 64)
        XCTAssertEqual(shown.process.argv?.first, "sh", "redacted, not dropped")
        XCTAssertEqual(shown.chain.last?.argv?.count, 7, "as stored chains: 6 arguments and the count of the rest")
        // A second access with the same key keeps the (redacted) first question.
        XCTAssertEqual(b.hold(q, budget: 60, respond: answers.respond(2)), .held(requestID: id))
        XCTAssertFalse(leaks(b.request(id: id)))
        XCTAssertFalse(leaks(b.resolve(id: id, answer: .deny)))
        b.drain()
        XCTAssertEqual(answers.all, [1: [.deny], 2: [.deny]])
        // Raw requests answered before anyone read them come back redacted too.
        _ = b.hold(q, budget: 60, respond: answers.respond(3))
        XCTAssertFalse(leaks(b.resolveMatching(.deny) { _ in true }.first))
    }

    /// The "off" observer runs on a queue: when it runs after the next "on", it must not let through
    /// what was held under that "on".
    func testAnOffQueuedBeforeAnOnDoesNotReleaseWhatIsHeld() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try enable(core)
        let answers = Answers()
        core.policyQueue.suspend()
        try core.mutateSettings(peer: .inProcess) { $0.enforcementEnabled = false }
        try core.mutateSettings(peer: .inProcess) { $0.enforcementEnabled = true }
        try holdAccess(core, open(terminalChild(core, proc(501, "/bin/cat", platform: true))), answers, 1)
        core.policyQueue.resume()
        core.drainPolicyQueue()
        core.askBroker.drain()
        XCTAssertEqual(answers.of(1), [], "still waiting for the answer")
        XCTAssertEqual(core.askBroker.heldAccesses, 1)
        // A real "off" still lets it through.
        try core.mutateSettings(peer: .inProcess) { $0.enforcementEnabled = false }
        core.drainPolicyQueue()
        core.askBroker.drain()
        XCTAssertEqual(answers.of(1), [.allow])
    }

    /// An alert about metadata-only opens has no access to allow: "always allow" must not turn into an
    /// `.any` (read and write) allow rule.
    func testAlwaysAllowOnAMetadataOnlyAlertSavesNoAllowRule() throws {
        let dir = TempDir()
        let core = try askCore(dir)
        try core.setRules([])
        try core.store.upsert([askAlert(id: 1, kind: .criticalNonOwner, access: [])])
        try core.apply(action: .alwaysAllow, toAlert: 1, peer: .inProcess)
        XCTAssertEqual(answerRules(core), [])
        XCTAssertEqual(try core.store.alert(id: 1)?.status, .resolved)
    }
}
