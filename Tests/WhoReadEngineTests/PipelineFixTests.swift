import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// In-memory store whose inserts / upserts can be made to fail (disk full, SQLITE_BUSY).
final class FlakyStore: EventStore, @unchecked Sendable {
    private let base = InMemoryEventStore()
    private let lock = NSLock()
    private var _failInsert = false
    private var _failUpsert = false
    struct Failure: Error {}

    var failInsert: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _failInsert }
        set { lock.lock(); _failInsert = newValue; lock.unlock() }
    }
    var failUpsert: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _failUpsert }
        set { lock.lock(); _failUpsert = newValue; lock.unlock() }
    }

    func insert(_ events: [AnalyzedEvent]) throws {
        if failInsert { throw Failure() }
        try base.insert(events)
    }
    func upsert(_ alerts: [Alert]) throws {
        if failUpsert { throw Failure() }
        try base.upsert(alerts)
    }
    func events(_ query: EventQuery) throws -> [AnalyzedEvent] { try base.events(query) }
    func event(id: Int64) throws -> AnalyzedEvent? { try base.event(id: id) }
    func alerts(_ query: AlertQuery) throws -> [Alert] { try base.alerts(query) }
    func alert(id: Int64) throws -> Alert? { try base.alert(id: id) }
    func summaries(since: Date?) throws -> [UsageSummary] { try base.summaries(since: since) }
    func dailyAggregates(since: Date?) throws -> [DailyAggregate] { try base.dailyAggregates(since: since) }
    func maxEventID() throws -> Int64 { try base.maxEventID() }
    func maxAlertID() throws -> Int64 { try base.maxAlertID() }
    func loadBaseline() throws -> [BaselineEntry] { try base.loadBaseline() }
    func saveBaseline(_ changes: [(BaselineKey, BaselineEntry?)]) throws { try base.saveBaseline(changes) }
    func loadRules() throws -> [Rule]? { try base.loadRules() }
    func saveRules(_ rules: [Rule]) throws { try base.saveRules(rules) }
    func value(forKey key: String) throws -> Data? { try base.value(forKey: key) }
    func setValue(_ value: Data?, forKey key: String) throws { try base.setValue(value, forKey: key) }
    func applyRetention(detailCutoff: Date, retentionCutoff: Date) throws -> Int {
        try base.applyRetention(detailCutoff: detailCutoff, retentionCutoff: retentionCutoff)
    }
    func counts() throws -> StoreCounts { try base.counts() }
}

final class PipelineFixTests: XCTestCase {
    let key = "/Users/alice/.ssh/id_ed25519"
    let deny = RuleDecision(verdict: .deny, reason: .explicitDeny, ruleID: "test-deny")

    func makeCore(_ dir: TempDir) throws -> (DaemonCore, FakeSource) {
        let fake = FakeSource(canEnforce: true)
        let core = try DaemonCore(config: baseConfig(dir), makeSource: { _ in fake })
        return (core, fake)
    }

    /// `cat` under Claude Code (node … claude) under zsh.
    func agentCat(_ core: DaemonCore) -> ProcessRecord {
        let t = Date(timeIntervalSince1970: 1_760_000_000)
        let zsh = proc(500, "/bin/zsh", ppid: 1, platform: true)
        core.tree.observe(zsh, at: t)
        let claude = proc(600, "/opt/homebrew/Cellar/node/22.9.0/bin/node", ppid: 500, argv: ["node", "/opt/homebrew/bin/claude"])
        var child = zsh
        child.pid = 600
        child.ppid = 500
        core.tree.fork(parent: zsh, child: child, at: t)
        core.tree.exec(old: child, new: claude, at: t)
        return proc(601, "/bin/cat", ppid: 600, platform: true)
    }

    func activity(_ p: ProcessRecord, _ op: FileOperation, _ targets: [FileTarget]) -> FileActivity {
        FileActivity(time: Date(timeIntervalSince1970: 1_760_000_100), operation: op, process: p, targets: targets)
    }

    func read(_ p: ProcessRecord, _ path: String) -> FileActivity {
        activity(p, .open, OperationSemantics.open(path: path, fflag: OperationSemantics.fread))
    }

    /// Enforced deny of any access to the ssh category for processes with an agent in their chain.
    func enforceDenySSH(_ core: DaemonCore) throws {
        var rule = RuleTemplates.blockAgentsFromCritical()
        rule.id = "deny-agents-ssh"
        rule.target = .category("ssh")
        rule.access = .any
        rule.enabled = true
        rule.enforce = true
        try core.setRules([rule])
        var s = core.currentSettings
        s.enforcementEnabled = true
        try core.update(settings: s, peer: .inProcess)
        XCTAssertTrue(core.enforcement.isActive)
    }

    // MARK: - Pause (native-es-7)

    func testPausedPipelineStillRecordsDenials() throws {
        let dir = TempDir()
        let (core, _) = try makeCore(dir)
        var s = core.currentSettings
        s.monitoringPaused = true
        try core.update(settings: s, peer: .inProcess)
        let cat = agentCat(core)

        core.pipeline.receive(.file(read(cat, key)), context: .monitorOnly)
        core.pipeline.receive(.file(read(cat, key)), context: .decided(RuleDecision(verdict: .allow, reason: .defaultAllow)))
        core.pipeline.receive(.file(read(cat, key)), context: .decided(deny))
        core.writer.flush()

        let events = try core.store.events(EventQuery(includeBenign: true))
        XCTAssertEqual(events.map(\.decision), [.denied], "only the block is recorded while paused")
        let alerts = try core.store.alerts(AlertQuery())
        XCTAssertEqual(alerts.map(\.kind), [.blocked])
        XCTAssertEqual(core.live.after(nil, limit: 10, includeBenign: true).count, 1)
    }

    // MARK: - Enforcer: listings and creates

    func testEnforcerNeverBlocksListingsOrDirectoryOpens() throws {
        let dir = TempDir()
        let (core, _) = try makeCore(dir)
        try enforceDenySSH(core)
        let cat = agentCat(core)
        let sub = "/Users/alice/.ssh/keys"

        XCTAssertEqual(core.enforcer.decide(read(cat, sub)).verdict, .deny, "the rule covers this path")

        let listing = core.enforcer.decide(activity(cat, .readdir, OperationSemantics.readdir(path: sub)))
        XCTAssertEqual(listing.verdict, .allow)
        XCTAssertTrue(listing.cacheable)
        XCTAssertTrue(listing.policyDenied.isEmpty)

        // AUTH_OPEN of a directory (stat says directory): reported as readdir, so allowed.
        let (op, targets) = OperationSemantics.open(ReportedPath(sub, isDirectory: true), fflag: OperationSemantics.fread)
        XCTAssertEqual(op, .readdir)
        let dirOpen = core.enforcer.decide(activity(cat, op, targets))
        XCTAssertEqual(dirOpen.verdict, .allow)
        XCTAssertTrue(dirOpen.cacheable)
    }

    func testEnforcerDeniesCreatingANewFile() throws {
        let dir = TempDir()
        let (core, _) = try makeCore(dir)
        try enforceDenySSH(core)
        let cat = agentCat(core)
        // AUTH_CREATE with a NEW_PATH destination: ~/.ssh + authorized_keys.
        let dst = ReportedPath(OperationSemantics.join(dir: "/Users/alice/.ssh", name: "authorized_keys"))
        let d = core.enforcer.decide(activity(cat, .create, OperationSemantics.create(dst)))
        XCTAssertEqual(d.verdict, .deny)

        // The denial reaches the store as a blocked create.
        core.pipeline.receive(.file(activity(cat, .create, OperationSemantics.create(dst))), context: .decided(d))
        core.writer.flush()
        let events = try core.store.events(EventQuery(includeBenign: true))
        XCTAssertEqual(events.map(\.operation), [.create])
        XCTAssertEqual(events.map(\.decision), [.denied])
    }

    // MARK: - Writer (storage-ipc-3)

    /// One denied event and its blocked alert, analyzed by a real core.
    func deniedOutput(_ core: DaemonCore) -> AnalysisOutput {
        let out = core.analyzer.handle(.file(read(agentCat(core), key)), context: .decided(deny))
        XCTAssertEqual(out.events.count, 1)
        XCTAssertEqual(out.alerts.count, 1)
        return out
    }

    func testWriterRequeuesFailedWritesAndRateLimitsErrors() throws {
        let dir = TempDir()
        let (core, _) = try makeCore(dir)
        let out = deniedOutput(core)
        let store = FlakyStore()
        let writer = EventWriter(store: store, errorReportInterval: 3600)
        let errors = Counter()
        writer.onError = { _ in errors.bump() }

        // Insert fails, upsert succeeds: the alert is stored, the events wait, nothing is "dropped".
        store.failInsert = true
        writer.enqueue(events: out.events)
        writer.enqueue(alerts: out.alerts.map(\.alert))
        writer.flush()
        XCTAssertEqual(try store.events(EventQuery(includeBenign: true)).count, 0)
        XCTAssertEqual(try store.alerts(AlertQuery()).count, 1)
        XCTAssertEqual(writer.droppedCount, 0)
        writer.flush()
        XCTAssertEqual(errors.value, 1, "a persistent error is reported once per interval")

        store.failInsert = false
        writer.flush()
        XCTAssertEqual(try store.events(EventQuery(includeBenign: true)).map(\.id), out.events.map(\.id))
        XCTAssertEqual(writer.droppedCount, 0)

        // Upsert fails: the alert is re-queued, but a newer snapshot queued meanwhile wins.
        store.failUpsert = true
        var stale = out.alerts[0].alert
        stale.count = 2
        writer.enqueue(alerts: [stale])
        writer.flush()
        var newer = stale
        newer.count = 3
        writer.enqueue(alerts: [newer])
        store.failUpsert = false
        writer.flush()
        XCTAssertEqual(try store.alert(id: newer.id)?.count, 3)
        XCTAssertEqual(writer.droppedCount, 0)
    }

    func testWriterRequeueKeepsTheCap() throws {
        let dir = TempDir()
        let (core, _) = try makeCore(dir)
        let e = deniedOutput(core).events[0]
        let events = (0..<3).map { i -> AnalyzedEvent in
            var x = e
            x.id = e.id + Int64(i)
            return x
        }
        let store = FlakyStore()
        let writer = EventWriter(store: store, maxPending: 2)
        store.failInsert = true
        writer.enqueue(events: events)
        XCTAssertEqual(writer.droppedCount, 1)
        writer.flush()
        XCTAssertEqual(writer.droppedCount, 1, "a failed flush puts its batch back without losing it")
        var later = e
        later.id = e.id + 10
        writer.enqueue(events: [later])
        XCTAssertEqual(writer.droppedCount, 2, "the oldest re-queued event goes first when over the cap")
        store.failInsert = false
        writer.flush()
        XCTAssertEqual(try store.events(EventQuery(includeBenign: true)).map(\.id).sorted(), [e.id + 2, e.id + 10])
    }

    // MARK: - Ordering (storage-ipc-8)

    func testLiveBufferAndWriterGetEventsInIDOrderFromTwoQueues() throws {
        let dir = TempDir()
        let (core, _) = try makeCore(dir)
        let cat = agentCat(core)
        let n = 300
        let group = DispatchGroup()
        for context in [RuleContext.monitorOnly, .decided(deny)] {
            DispatchQueue.global().async(group: group) {
                for _ in 0..<n { core.pipeline.receive(.file(self.read(cat, self.key)), context: context) }
            }
        }
        XCTAssertEqual(group.wait(timeout: .now() + 30), .success)
        let ids = core.live.after(nil, limit: 10 * n, includeBenign: true).map(\.id)
        XCTAssertEqual(ids.count, 2 * n)
        let inversion = zip(ids, ids.dropFirst()).first { $0.0 >= $0.1 }
        XCTAssertNil(inversion.map { "\($0.0) before \($0.1)" }, "live buffer must never see id N after N+1")
    }

    // MARK: - Mute plan (native-es-9) and source stats (native-es-6)

    func testMutePlanKeepsEverySpellingByteForByte() {
        let nfc = "/Users/alice/Caf\u{E9}"
        let nfd = "/Users/alice/Cafe\u{301}"
        let resolved = ["/Users/alice/documents/Secrets": "/Users/alice/Documents/Secrets", "/Users/alice": "/Users/alice"]
        let plan = NativeMutePlan.plan(prefixes: [nfc, "/Users/alice/documents/Secrets"], ancestors: ["/Users/alice"],
                                       resolve: { resolved[$0] })
        let prefixes = Set(plan.prefixes.map { Array($0.path.utf8) })
        XCTAssertEqual(prefixes, Set([nfc, nfd, "/Users/alice/documents/Secrets", "/Users/alice/Documents/Secrets"].map { Array($0.utf8) }),
                       "NFC and NFD are distinct to ES even though Swift strings compare equal")
        XCTAssertEqual(plan.literals.map(\.path), ["/Users/alice"], "an identical resolved spelling is not duplicated")
        XCTAssertEqual(NativeMutePlan.variants("/Users/alice/.ssh/", resolve: { _ in nil }), ["/Users/alice/.ssh/"])
    }

    func testMutePlanNeverSelectsTheRoot() {
        // A custom path that is a link to "/" must not become an inverted "/" prefix (every file event).
        let plan = NativeMutePlan.plan(prefixes: ["/Users/alice/notes"], ancestors: ["/Users/alice"], resolve: { _ in "/" })
        XCTAssertEqual(plan.prefixes.map(\.path), ["/Users/alice/notes"])
        XCTAssertEqual(plan.literals.map(\.path), ["/Users/alice"])
    }

    func testSourcesReportNoDroppedEventsByDefault() {
        XCTAssertEqual(FakeSource(canEnforce: false).droppedEvents, 0)
    }
}
