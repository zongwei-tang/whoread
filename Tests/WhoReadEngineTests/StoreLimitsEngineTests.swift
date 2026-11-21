import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

private let limitsT = Date(timeIntervalSince1970: 1_760_000_000)

/// An access to the test vault by the program in a minted bundle /tmp/mN.app: every N is an app of its own.
private func minted(_ id: Int64, app: Int, at time: Date, access: AccessSet = .read) -> AnalyzedEvent {
    let bundle = "/tmp/m\(app).app"
    return AnalyzedEvent(
        id: id, time: time, operation: .open, access: access, path: "/Users/alice/WhoReadTestVault/notes/secret.txt",
        secondaryPath: nil, categoryID: "test-vault", severity: .critical,
        process: ProcessRecord(pid: 900, ppid: 1, executablePath: bundle + "/cat", isPlatformBinary: false, argv: ["cat"]),
        chain: [ChainLink(pid: 1, name: "launchd", path: "/sbin/launchd")],
        responsible: ResponsibleEntity(kind: .app, key: "app:" + bundle, displayName: "m\(app)", path: bundle),
        agentID: nil, isOwner: false, benignServiceID: nil, decision: .observed, ruleID: nil)
}

private func limitsCore(_ dir: TempDir, inMemory: Bool) throws -> DaemonCore {
    var config = baseConfig(dir)
    config.inMemoryStore = inMemory
    config.resolveOwners = false
    return try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: false) })
}

/// The daemon side of the summary and daily replies (daemon-6, ipc-1, cli-6), through the codec as a
/// client sees them. Each test runs against the SQLite store and the in-memory one.
final class SummaryReplyTests: XCTestCase {
    private func client(_ core: DaemonCore) -> InProcessClient {
        InProcessClient(handler: ServiceHandler(daemon: core, policy: .permissive))
    }

    /// The app polls `.summaries(since: nil)` every 10 s with no limit: the daemon sends the most
    /// recently active rows only, however many minted apps the table holds.
    func testSummariesReplyIsCappedWhenTheClientNamesNoLimit() throws {
        for inMemory in [false, true] {
            let dir = TempDir()
            let core = try limitsCore(dir, inMemory: inMemory)
            let n = UsageSummary.replyLimit + 5
            try core.store.insert((0..<n).map { minted(Int64($0 + 1), app: $0, at: limitsT.addingTimeInterval(Double($0))) })
            let c = client(core)
            let rows = try c.summaries(since: nil)
            XCTAssertEqual(rows.count, UsageSummary.replyLimit, "inMemory \(inMemory)")
            XCTAssertEqual(rows.first?.responsible.displayName, "m\(n - 1)", "inMemory \(inMemory): the most recently active first")
            XCTAssertEqual(rows.last?.responsible.displayName, "m5", "inMemory \(inMemory)")
            XCTAssertEqual(try c.summaries(since: nil, limit: 5).map(\.responsible.displayName), (n - 5..<n).reversed().map { "m\($0)" })
            XCTAssertEqual(try c.summaries(since: nil, limit: 10 * UsageSummary.replyLimit).count, UsageSummary.replyLimit,
                           "inMemory \(inMemory): a client cannot ask for more than the cap")
        }
    }

    /// `whoread daily` and `export --aggregates`: the reply is capped too, and the cursor pages through
    /// every row once, newest day first.
    func testDailyAggregatesReplyIsCappedAndPagesWithTheCursor() throws {
        for inMemory in [false, true] {
            let dir = TempDir()
            let core = try limitsCore(dir, inMemory: inMemory)
            let n = DailyAggregate.replyLimit + 5
            let old = limitsT.addingTimeInterval(-10 * 86_400)
            try core.store.insert((0..<n).map { minted(Int64($0 + 1), app: $0, at: old.addingTimeInterval(Double($0))) })
            try core.store.applyRetention(detailCutoff: limitsT.addingTimeInterval(-86_400), retentionCutoff: limitsT.addingTimeInterval(-30 * 86_400))
            let c = client(core)
            XCTAssertEqual(try c.dailyAggregates(since: nil).count, DailyAggregate.replyLimit, "inMemory \(inMemory)")

            var all: [DailyAggregate] = []
            var after: DailyAggregate.Key?
            var pages = 0
            while pages < 10 {
                let page = try c.dailyAggregates(since: nil, limit: 3_000, after: after)
                pages += 1
                all += page
                guard page.count == 3_000, let last = page.last else { break }
                after = last.key
            }
            XCTAssertEqual(pages, 4, "inMemory \(inMemory)")
            XCTAssertEqual(all.count, n, "inMemory \(inMemory)")
            XCTAssertEqual(Set(all.map(\.key)).count, n, "inMemory \(inMemory): each row once")
            XCTAssertEqual(all.map(\.key), all.map(\.key).sorted(by: >), "inMemory \(inMemory)")
        }
    }

    /// `whoread apps --since 1h` asks `.summaries(since:)`: FIRST and COUNT are those of the window,
    /// not all-time totals (cli-6). Without `since` the totals stay all-time.
    func testSummariesSinceCountOnlyTheWindow() throws {
        for inMemory in [false, true] {
            let dir = TempDir()
            let core = try limitsCore(dir, inMemory: inMemory)
            let now = limitsT
            // m1: five reads two hours ago and one ten minutes ago. m2: one read three hours ago.
            try core.store.insert((0..<5).map { minted(Int64($0 + 1), app: 1, at: now.addingTimeInterval(-7200 + Double($0))) })
            try core.store.insert([minted(6, app: 2, at: now.addingTimeInterval(-3 * 3600))])
            try core.store.insert([minted(7, app: 1, at: now.addingTimeInterval(-600), access: .write)])
            let c = client(core)
            let window = try c.summaries(since: now.addingTimeInterval(-3600))
            XCTAssertEqual(window.map(\.responsible.displayName), ["m1"], "inMemory \(inMemory)")
            XCTAssertEqual(window.first?.count, 1, "inMemory \(inMemory)")
            XCTAssertEqual(window.first?.firstSeen, now.addingTimeInterval(-600), "inMemory \(inMemory)")
            XCTAssertEqual(window.first?.writes, 1, "inMemory \(inMemory)")
            XCTAssertEqual(window.first?.reads, 0, "inMemory \(inMemory)")

            let allTime = try c.summaries(since: nil)
            XCTAssertEqual(allTime.first { $0.responsible.displayName == "m1" }?.count, 6, "inMemory \(inMemory)")
            XCTAssertEqual(allTime.first { $0.responsible.displayName == "m1" }?.firstSeen, now.addingTimeInterval(-7200),
                           "inMemory \(inMemory)")
        }
    }
}

/// Requests keep their wire form within protocol 4: the app and CLI already installed keep working
/// with this daemon, and a newer client with an older daemon.
final class SummaryProtocolCompatibilityTests: XCTestCase {
    /// The request cases as protocol 4 had them before limits and the daily cursor.
    private enum OlderRequest: Codable, Equatable {
        case summaries(since: Date?)
        case dailyAggregates(since: Date?)
    }

    func testRequestsOfOlderClientsStillDecode() throws {
        let enc = Exporter.encoder(pretty: false)
        for since in [nil, limitsT] {
            let summaries = try IPCCodec.decodeRequest(try enc.encode(OlderRequest.summaries(since: since)))
            guard case .summaries(let s, let limit) = summaries else { return XCTFail("\(summaries)") }
            XCTAssertEqual(s, since)
            XCTAssertNil(limit, "no limit: the daemon applies its default cap")
            let daily = try IPCCodec.decodeRequest(try enc.encode(OlderRequest.dailyAggregates(since: since)))
            guard case .dailyAggregates(let d, let l, let after) = daily else { return XCTFail("\(daily)") }
            XCTAssertEqual(d, since)
            XCTAssertNil(l)
            XCTAssertNil(after)
        }
        // Hand-written forms too: an explicit null.
        guard case .summaries(nil, nil) = try IPCCodec.decodeRequest(Data(#"{"summaries":{"since":null}}"#.utf8)) else {
            return XCTFail("null since")
        }
        guard case .summaries(nil, nil) = try IPCCodec.decodeRequest(Data(#"{"summaries":{}}"#.utf8)) else {
            return XCTFail("empty")
        }
    }

    func testRequestsOfNewerClientsDecodeInOlderDaemons() throws {
        let dec = Exporter.decoder()
        let key = DailyAggregate.Key(day: "2026-10-01", responsibleKey: "app:/tmp/m1.app", categoryID: "test-vault", agentID: "")
        XCTAssertEqual(try dec.decode(OlderRequest.self, from: IPCCodec.encode(.summaries(since: limitsT, limit: 5))),
                       .summaries(since: limitsT))
        XCTAssertEqual(try dec.decode(OlderRequest.self, from: IPCCodec.encode(.summaries(since: nil))), .summaries(since: nil))
        XCTAssertEqual(try dec.decode(OlderRequest.self, from: IPCCodec.encode(.dailyAggregates(since: nil, limit: 3, after: key))),
                       .dailyAggregates(since: nil))
        // And they round-trip here.
        guard case .dailyAggregates(nil, 3, key) = try IPCCodec.decodeRequest(try IPCCodec.encode(.dailyAggregates(since: nil, limit: 3, after: key))) else {
            return XCTFail("daily round trip")
        }
    }

    /// Replies are unchanged: an older client decodes them as before.
    func testRepliesKeepTheirShape() throws {
        let reply = String(decoding: try IPCCodec.encode(IPCResponse.summaries([])), as: UTF8.self)
        XCTAssertEqual(reply, #"{"summaries":{"_0":[]}}"#)
        let daily = String(decoding: try IPCCodec.encode(IPCResponse.dailyAggregates([])), as: UTF8.self)
        XCTAssertEqual(daily, #"{"dailyAggregates":{"_0":[]}}"#)
    }
}

/// A store whose inserts fail while `failing` is set, counting every attempt.
private final class CountingStore: EventStore, @unchecked Sendable {
    private let base = InMemoryEventStore()
    private let lock = NSLock()
    private var _failing = true
    private var _attempts = 0
    struct Failure: Error {}

    var failing: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _failing }
        set { lock.lock(); _failing = newValue; lock.unlock() }
    }
    var attempts: Int { lock.lock(); defer { lock.unlock() }; return _attempts }

    func insert(_ events: [AnalyzedEvent]) throws {
        lock.lock()
        _attempts += 1
        let fail = _failing
        lock.unlock()
        if fail { throw Failure() }
        try base.insert(events)
    }
    func upsert(_ alerts: [Alert]) throws { try base.upsert(alerts) }
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

/// daemon-4: the writer's queue at its cap, and retries while the store keeps failing.
final class WriterQueueTests: XCTestCase {
    /// At the 100,000-event cap every enqueue used to shift the whole queue (removeFirst, ~50 MB) under
    /// the writer lock, on the event source's reader thread: about 1.3–1.9 ms per event. Dropping the
    /// oldest must not cost the queue's length.
    func testEnqueueAtTheCapDropsTheOldestWithoutShiftingTheQueue() throws {
        let store = InMemoryEventStore()
        let writer = EventWriter(store: store)
        let cap = 100_000
        let e = minted(1, app: 1, at: limitsT)
        func numbered(_ id: Int) -> AnalyzedEvent {
            var x = e
            x.id = Int64(id)
            return x
        }
        writer.enqueue(events: (1...cap).map(numbered))
        XCTAssertEqual(writer.droppedCount, 0)
        let extra = 2_000
        let start = Date()
        for i in 1...extra { writer.enqueue(events: [numbered(cap + i)]) }
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertEqual(writer.droppedCount, UInt64(extra), "every event past the cap is counted")
        XCTAssertLessThan(elapsed, 0.5, "\(extra) enqueues at the cap took \(elapsed) s")

        // The oldest went; the newest 100,000 are stored, in order.
        writer.flush()
        XCTAssertEqual(try store.counts().events, cap)
        XCTAssertEqual(try store.events(EventQuery(includeBenign: true, limit: 1, newestFirst: false)).first?.id, Int64(extra + 1))
        XCTAssertEqual(try store.events(EventQuery(includeBenign: true, limit: 1)).first?.id, Int64(cap + extra))
    }

    /// A store that keeps failing was retried with the whole backlog on every 250 ms tick. The timer
    /// now backs off (doubling, capped); an explicit flush still writes at once.
    func testTimerRetriesBackOffWhileTheStoreKeepsFailing() throws {
        let store = CountingStore()
        let writer = EventWriter(store: store, errorReportInterval: 3600)
        writer.enqueue(events: [minted(1, app: 1, at: limitsT)])
        writer.start(interval: 0.01)
        Thread.sleep(forTimeInterval: 0.6)
        let attempts = store.attempts
        XCTAssertGreaterThanOrEqual(attempts, 3, "it keeps retrying")
        XCTAssertLessThan(attempts, 15, "about 60 ticks in 0.6 s: \(attempts) attempts")
        XCTAssertEqual(writer.droppedCount, 0, "nothing is lost while retrying")

        store.failing = false
        // A read's flush waits for the back-off as the timer does (R5VWriterBackOffTests); an action's does not.
        try writer.flushOrThrow()
        XCTAssertEqual(try store.events(EventQuery(includeBenign: true)).map(\.id), [1], "flushOrThrow() does not wait for the back-off")
        writer.stop()
    }

    /// After the store recovers the timer writes at its normal interval again.
    func testTimerReturnsToItsIntervalAfterASuccess() throws {
        let store = CountingStore()
        let writer = EventWriter(store: store, errorReportInterval: 3600)
        writer.enqueue(events: [minted(1, app: 1, at: limitsT)])
        writer.start(interval: 0.01)
        Thread.sleep(forTimeInterval: 0.3)
        store.failing = false
        XCTAssertNotNil(waitFor(5) { (try? store.events(EventQuery(includeBenign: true)).count) == 1 })
        writer.enqueue(events: [minted(2, app: 1, at: limitsT)])
        XCTAssertNotNil(waitFor(0.5) { (try? store.events(EventQuery(includeBenign: true)).count) == 2 },
                        "the next event goes out within a few ticks, not after the back-off")
        writer.stop()
    }
}

/// daemon-4, the rest: while the writer backs off after failed writes, a read's flush (the app's alerts
/// poll every second, events, summaries) does not retry the whole backlog either; a user's action
/// (`flushOrThrow`) and a stop still try at once. The back-off runs on the uptime clock: a wall clock
/// set back does not stop the writer for as long.
final class R5VWriterBackOffTests: XCTestCase {
    final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var t: TimeInterval = 1000
        var now: TimeInterval { lock.lock(); defer { lock.unlock() }; return t }
        func advance(_ s: TimeInterval) { lock.lock(); t += s; lock.unlock() }
    }

    func testAReadsFlushWhileBackingOffLeavesTheBacklogAlone() throws {
        let store = CountingStore()
        let clock = Clock()
        let writer = EventWriter(store: store, errorReportInterval: 3600, uptime: { clock.now })
        writer.enqueue(events: [minted(1, app: 1, at: limitsT)])
        writer.flush()
        XCTAssertEqual(store.attempts, 1)
        for _ in 0..<20 { writer.flush() }
        XCTAssertEqual(store.attempts, 1, "backing off")
        // Throws only for alerts it could not write; the events stay queued either way.
        try? writer.flushOrThrow()
        XCTAssertEqual(store.attempts, 2, "an action tries at once")
        store.failing = false
        writer.stop()
        XCTAssertEqual(try store.events(EventQuery(includeBenign: true)).map(\.id), [1], "a stop writes what is left")
    }

    func testTheBackOffFollowsTheUptimeClock() throws {
        let store = CountingStore()
        let clock = Clock()
        let writer = EventWriter(store: store, errorReportInterval: 3600, maxRetryDelay: 5, uptime: { clock.now })
        writer.enqueue(events: [minted(1, app: 1, at: limitsT)])
        writer.flush()
        clock.advance(0.1)
        writer.flush()
        XCTAssertEqual(store.attempts, 1)
        store.failing = false
        clock.advance(5)
        writer.flush()
        XCTAssertEqual(store.attempts, 2)
        XCTAssertEqual(try store.events(EventQuery(includeBenign: true)).map(\.id), [1])
    }
}
