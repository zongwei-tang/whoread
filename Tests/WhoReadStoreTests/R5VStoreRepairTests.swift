import XCTest
import WhoReadCore
@testable import WhoReadStore

/// Repairs of the round-5 store fixes, after their verification: the status index made status queries
/// sort every matching alert, and the batched reads were no snapshot.
final class R5VStoreRepairTests: XCTestCase {
    private let h = StoreLimitsTests()

    override func setUpWithError() throws { try h.setUpWithError() }
    override func tearDownWithError() throws { try h.tearDownWithError() }

    /// `status IN (…) ORDER BY updated DESC, id DESC LIMIT n` (the Alerts tab's unread only, `alerts --unread`,
    /// read-all, an answer's ask alerts): with an index on status alone SQLite took every matching row and
    /// sorted it, under the store lock. On (status, updated) one status is read in order; the unread count
    /// still reads the index only.
    func testStatusQueriesReadTheStatusIndexInOrder() throws {
        let path = h.sqlitePath()
        _ = try SQLiteEventStore(path: path)
        for since in [false, true] {
            let plan = try h.queryPlan(path, SQLiteEventStore.alertsSQL(since: since, statuses: 1))
            XCTAssertTrue(plan.contains("alerts_status_updated"), "since \(since): \(plan)")
            XCTAssertFalse(plan.contains("TEMP B-TREE"), "since \(since): \(plan)")
        }
        let several = try h.queryPlan(path, SQLiteEventStore.alertsSQL(since: false, statuses: 2))
        XCTAssertTrue(several.contains("alerts_status_updated"), several)
        let count = try h.queryPlan(path, SQLiteEventStore.unreadAlertsSQL)
        XCTAssertTrue(count.contains("COVERING INDEX alerts_status_updated"), count)
    }

    /// Several statuses (an answer's ask alerts: unread and read, up to 10,000): `status IN (…)` on
    /// (status, updated) still took every alert of those statuses and sorted them, under the store lock.
    /// Each status is read in order on the index and the reads are merged: no sort, nothing read past the limit.
    func testSeveralStatusesAreMergedInOrderWithoutASort() throws {
        let path = h.sqlitePath()
        _ = try SQLiteEventStore(path: path)
        for since in [false, true] {
            for statuses in 2...3 {
                let plan = try h.queryPlan(path, SQLiteEventStore.alertsSQL(since: since, statuses: statuses))
                XCTAssertTrue(plan.contains("alerts_status_updated"), "since \(since), \(statuses) statuses: \(plan)")
                XCTAssertFalse(plan.contains("TEMP B-TREE"), "since \(since), \(statuses) statuses: \(plan)")
            }
        }
    }

    /// The merged read returns what one sorted read does: newest update first and the larger id first among
    /// equal times, across statuses, with `since` and the limit; a status named twice counts once.
    func testSeveralStatusesReturnWhatTheMemoryStoreReturns() throws {
        let sqlite = try SQLiteEventStore(path: h.sqlitePath())
        let memory = InMemoryEventStore()
        let cycle: [AlertStatus] = [.unread, .read, .resolved]
        // Three alerts per update time, each of another status.
        let alerts = (1...60).map { i -> Alert in
            var a = h.alert(Int64(i), status: cycle[i % 3])
            a.updatedAt = h.t0.addingTimeInterval(Double(i / 3) * 10)
            return a
        }
        try sqlite.upsert(alerts)
        try memory.upsert(alerts)
        let sets: [[AlertStatus]] = [[.unread, .read], [.read, .unread], [.unread, .unread], [.unread, .read, .resolved],
                                     [.resolved, .read, .resolved], [.read]]
        for statuses in sets {
            for limit in [0, 1, 5, 17, 100] {
                for since in [nil, h.t0.addingTimeInterval(55)] {
                    let q = AlertQuery(since: since, statuses: statuses, limit: limit)
                    XCTAssertEqual(try sqlite.alerts(q).map(\.id), try memory.alerts(q).map(\.id), "\(q)")
                }
            }
        }
        // 58 (read) and 57 (unread) share their update time.
        XCTAssertEqual(try sqlite.alerts(AlertQuery(statuses: [.unread, .read], limit: 4)).map(\.id), [60, 58, 57, 55])
    }

    /// A database this round's earlier build made has the status-only index: opening it replaces it.
    func testTheStatusOnlyIndexIsReplaced() throws {
        let path = h.sqlitePath()
        _ = try SQLiteEventStore(path: path)
        do {
            let db = try SQLiteDatabase(path: path)
            try db.exec("DROP INDEX IF EXISTS alerts_status_updated; CREATE INDEX IF NOT EXISTS alerts_status ON alerts(status);")
        }
        let store = try SQLiteEventStore(path: path)
        try store.upsert([h.alert(1, status: .unread), h.alert(2, status: .read), h.alert(3, status: .unread)])
        XCTAssertEqual(try store.alerts(AlertQuery(statuses: [.unread], limit: 10)).map(\.id), [3, 1])
        let db = try SQLiteDatabase(path: path)
        var indexes: [String] = []
        try db.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'alerts'").query { indexes.append($0.text(0) ?? "") }
        XCTAssertFalse(indexes.contains("alerts_status"), "\(indexes)")
        XCTAssertTrue(indexes.contains("alerts_status_updated"), "\(indexes)")
    }

    /// A capped read of the summaries (the app's full poll, `whoread apps`) is one snapshot: an app whose
    /// row a write moved to the front during the read is not left out of it.
    func testACappedSummaryReadIsOneSnapshot() throws {
        let store = try SQLiteEventStore(path: h.sqlitePath())
        store.readBatch = 100
        try h.mint(3000, into: store)
        let done = ConcurrentFlag()
        let writer = Thread {
            var id: Int64 = 10_000
            var t: TimeInterval = 4000
            while !done.value {
                // Apps 1000..1999, each moved to the front in turn.
                let events = (0..<20).map { _ -> AnalyzedEvent in
                    id += 1
                    t += 1
                    return self.h.access(id, t, app: 1000 + Int(id % 1000))
                }
                try? store.insert(events)
            }
        }
        writer.start()
        defer { done.value = true; while !writer.isFinished { usleep(1000) } }
        var short: [Int] = []
        for _ in 0..<40 {
            let rows = try store.summaries(limit: 3000)
            let apps = Set(rows.map(\.responsible.key))
            if apps.count != 3000 { short.append(apps.count) }
        }
        XCTAssertEqual(short, [], "reads that left apps out")
    }

    /// `whoread apps --since`: the events of the window and the days rolled up from it are read in pages;
    /// a retention run in between rolls counted events into days, which were counted again.
    func testActivityIsNotCountedTwiceWhenRetentionRunsDuringIt() throws {
        let store = try SQLiteEventStore(path: h.sqlitePath())
        store.scanBatch = 100
        try store.insert((0..<4000).map { h.access(Int64($0 + 1), Double($0), app: $0 % 50) })
        var ran = false
        // Between two pages of the read, as the daemon's hourly retention can.
        store.activityPageHook = {
            guard !ran else { return }
            ran = true
            _ = try? store.applyRetention(detailCutoff: self.h.t0.addingTimeInterval(2000), retentionCutoff: .distantPast)
        }
        let rows = try store.activity(since: h.t0.addingTimeInterval(-1), limit: 100)
        XCTAssertTrue(ran)
        XCTAssertEqual(try store.counts().events, 2000, "half was rolled up into days")
        XCTAssertEqual(rows.reduce(0) { $0 + $1.count }, 4000)
        store.activityPageHook = nil
        XCTAssertEqual(try store.activity(since: h.t0.addingTimeInterval(-1), limit: 100).reduce(0) { $0 + $1.count }, 4000)
    }
}

final class ConcurrentFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var _value = false
    var value: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _value }
        set { lock.lock(); _value = newValue; lock.unlock() }
    }
}
