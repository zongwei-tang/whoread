import XCTest
import WhoReadCore
@testable import WhoReadStore

/// What the summary and daily tables keep and send, and what status costs (daemon-6, ipc-1, app-7,
/// cli-6). Shared semantics are checked against both stores.
final class StoreLimitsTests: XCTestCase {
    var dir: URL!

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("whoread-limits-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    let t0 = Date(timeIntervalSince1970: 1_760_000_000)
    let day = 86_400.0

    func sqlitePath() -> String { dir.appendingPathComponent("\(UUID().uuidString).sqlite").path }

    func stores(limits: StoreLimits = StoreLimits()) throws -> [(String, EventStore)] {
        [("sqlite", try SQLiteEventStore(path: sqlitePath(), limits: limits)), ("memory", InMemoryEventStore(limits: limits))]
    }

    /// An access to the test vault by the program in a minted bundle /tmp/mN.app: every N is an app of its own.
    func access(_ id: Int64, _ dt: TimeInterval, app: Int, benign: Bool = false, access: AccessSet = .read,
                decision: EventDecision = .observed) -> AnalyzedEvent {
        let bundle = "/tmp/m\(app).app"
        return AnalyzedEvent(
            id: id, time: t0.addingTimeInterval(dt), operation: .open, access: access,
            path: "/Users/alice/WhoReadTestVault/notes/secret.txt", secondaryPath: nil, categoryID: "test-vault", severity: .critical,
            process: ProcessRecord(pid: 900, ppid: 1, executablePath: bundle + "/cat", isPlatformBinary: false, argv: ["cat"]),
            chain: [ChainLink(pid: 1, name: "launchd", path: "/sbin/launchd")],
            responsible: ResponsibleEntity(kind: .app, key: "app:" + bundle, displayName: "m\(app)", path: bundle),
            agentID: nil, isOwner: false, benignServiceID: benign ? "spotlight" : nil, decision: decision, ruleID: nil)
    }

    /// Apps 0..<n, app i accessing once at t0 + i seconds (app n-1 is the most recently active).
    func mint(_ n: Int, into store: EventStore, firstID: Int64 = 1, at base: TimeInterval = 0) throws {
        try store.insert((0..<n).map { access(firstID + Int64($0), base + Double($0), app: $0) })
    }

    /// `EXPLAIN QUERY PLAN` of `sql` on the database at `path`, one detail line per step.
    func queryPlan(_ path: String, _ sql: String) throws -> String {
        let db = try SQLiteDatabase(path: path)
        var lines: [String] = []
        try db.prepare("EXPLAIN QUERY PLAN " + sql).query { lines.append($0.text(3) ?? "") }
        return lines.joined(separator: "\n")
    }

    // MARK: - daemon-6 / app-7: status counts

    /// status() counts the unread alerts every second; without an index on status that walked every
    /// alert row, bodies included.
    func testUnreadCountUsesTheStatusIndex() throws {
        let path = sqlitePath()
        _ = try SQLiteEventStore(path: path)
        let plan = try queryPlan(path, SQLiteEventStore.unreadAlertsSQL)
        XCTAssertTrue(plan.contains("alerts_status"), plan)
    }

    /// Between writes the counts come from memory: a status poll on an idle machine reads no table.
    /// Every write the store makes is counted at once.
    func testCountsAreCachedUntilTheStoreWrites() throws {
        let path = sqlitePath()
        let store = try SQLiteEventStore(path: path)
        try mint(3, into: store)
        try store.upsert([alert(1, status: .unread), alert(2, status: .read)])
        let before = try store.counts()
        XCTAssertEqual([before.events, before.alerts, before.unreadAlerts], [3, 2, 1])

        // A change behind the store's back (it is the database's only writer) is not looked for.
        let other = try SQLiteDatabase(path: path)
        try other.exec("UPDATE alerts SET status = 'unread'")
        XCTAssertEqual(try store.counts(), before, "counts are not recomputed while the store has written nothing")

        // The store's own writes are seen at once.
        try store.upsert([alert(3, status: .unread)])
        XCTAssertEqual(try store.counts().alerts, 3)
        XCTAssertEqual(try store.counts().unreadAlerts, 3, "recomputed after the write, the change behind its back included")
        try store.insert([access(10, 100, app: 99)])
        XCTAssertEqual(try store.counts().events, 4)
        try store.applyRetention(detailCutoff: t0.addingTimeInterval(day), retentionCutoff: t0.addingTimeInterval(-day))
        XCTAssertEqual(try store.counts().events, 0)
        XCTAssertEqual(try store.counts().aggregatedDays, 1)
    }

    func alert(_ id: Int64, status: AlertStatus) -> Alert {
        var a = Alert(id: id, kind: .firstAccess, createdAt: t0, updatedAt: t0.addingTimeInterval(Double(id)),
                      windowEndsAt: t0.addingTimeInterval(600),
                      responsible: ResponsibleEntity(kind: .app, key: "app:/tmp/m\(id).app", displayName: "m\(id)"),
                      categoryID: "test-vault", severity: .critical, count: 1, accesses: .read,
                      firstPath: "/Users/alice/WhoReadTestVault/notes/secret.txt", firstEventID: id, lastEventID: id,
                      paths: ["/Users/alice/WhoReadTestVault/notes/secret.txt"], chain: [], agentID: nil, ruleID: nil)
        a.status = status
        return a
    }

    // MARK: - daemon-6 / ipc-1: summary reads

    /// The newest-N read walks the summary_last index (no sort of the whole table), with or without
    /// `since` and the paging cursor.
    func testSummaryReadsWalkTheLastSeenIndex() throws {
        let path = sqlitePath()
        _ = try SQLiteEventStore(path: path)
        for (since, after) in [(false, false), (true, false), (false, true), (true, true)] {
            let plan = try queryPlan(path, SQLiteEventStore.summariesSQL(since: since, after: after))
            XCTAssertTrue(plan.contains("summary_last"), "since \(since) after \(after): \(plan)")
            XCTAssertFalse(plan.contains("TEMP B-TREE"), "since \(since) after \(after): \(plan)")
        }
    }

    /// Daily pages walk the primary key backwards, the activity scan the events' ts index: no full
    /// scan and no sort per page.
    func testDailyAndActivityReadsUseTheirIndexes() throws {
        let path = sqlitePath()
        _ = try SQLiteEventStore(path: path)
        for (since, after) in [(false, false), (true, false), (false, true), (true, true)] {
            let plan = try queryPlan(path, SQLiteEventStore.dailySQL(since: since, after: after))
            XCTAssertTrue(plan.contains("sqlite_autoindex_daily_1"), "since \(since) after \(after): \(plan)")
            XCTAssertFalse(plan.contains("TEMP B-TREE"), "since \(since) after \(after): \(plan)")
        }
        let end = try queryPlan(path, SQLiteEventStore.activityPageEndSQL)
        XCTAssertTrue(end.contains("events_ts"), end)
        for bounded in [false, true] {
            let plan = try queryPlan(path, SQLiteEventStore.activityPageSQL(bounded: bounded))
            XCTAssertTrue(plan.contains("SEARCH events USING INDEX events_ts"), plan)
        }
    }

    func testSummariesAreTheMostRecentlyActiveFirstWithinTheLimit() throws {
        for (name, store) in try stores() {
            try mint(25, into: store)
            let newest = try store.summaries(limit: 10)
            XCTAssertEqual(newest.map(\.responsible.displayName), (15..<25).reversed().map { "m\($0)" }, name)
            XCTAssertEqual(try store.summaries(limit: 0).count, 0, name)
            XCTAssertEqual(try store.summaries(limit: 100).count, 25, name)
            XCTAssertEqual(try store.summaries(since: nil).count, 25, "\(name): the unlimited read is unchanged")
        }
    }

    /// A read longer than one batch (the store lock is released between batches) returns every row
    /// once, in order.
    func testSummaryReadsSpanningBatchesReturnEveryRowOnce() throws {
        let store = try SQLiteEventStore(path: sqlitePath())
        store.readBatch = 7
        try mint(40, into: store)
        let all = try store.summaries(limit: .max)
        XCTAssertEqual(all.map(\.responsible.displayName), (0..<40).reversed().map { "m\($0)" })
        XCTAssertEqual(try store.summaries(limit: 15).map(\.responsible.displayName), (25..<40).reversed().map { "m\($0)" })
        XCTAssertEqual(try store.summaries(since: t0.addingTimeInterval(30)).map(\.responsible.displayName),
                       (30..<40).reversed().map { "m\($0)" })
    }

    /// A row the store cannot decode (written by a newer build, or damaged) is skipped without making
    /// the reply shorter than its limit while readable rows remain.
    func testUndecodableRowsDoNotShortenAReply() throws {
        let path = sqlitePath()
        let store = try SQLiteEventStore(path: path)
        store.readBatch = 4
        try mint(20, into: store)
        try store.applyRetention(detailCutoff: t0.addingTimeInterval(day), retentionCutoff: t0.addingTimeInterval(-day))
        let other = try SQLiteDatabase(path: path)
        // The five most recently active summary rows, and the first four daily rows in reply order
        // (one day; keys descending): a whole first batch of each read.
        try other.exec("UPDATE summary SET responsible = x'00' WHERE last_ts >= \(t0.timeIntervalSince1970 + 15)")
        try other.exec("UPDATE daily SET responsible = x'00' WHERE responsible_key IN "
                       + "('app:/tmp/m6.app', 'app:/tmp/m7.app', 'app:/tmp/m8.app', 'app:/tmp/m9.app')")
        XCTAssertEqual(try store.summaries(limit: 6).map(\.responsible.displayName), (9..<15).reversed().map { "m\($0)" })
        let daily = try store.dailyAggregates(since: nil, after: nil, limit: 6)
        XCTAssertEqual(daily.map(\.summary.responsible.displayName), ["m5", "m4", "m3", "m2", "m19", "m18"])
        XCTAssertEqual(try store.dailyAggregates(since: nil).count, 16)
    }

    // MARK: - ipc-1: daily pages

    /// Pages follow the cursor (the last row of the previous page), newest day first, each row once.
    func testDailyPagesFollowTheCursor() throws {
        for (name, store) in try stores() {
            // Seven apps on each of three days, rolled up.
            var id: Int64 = 1
            for d in 0..<3 {
                for app in 0..<7 {
                    try store.insert([access(id, Double(d) * day + Double(app * 60), app: app)])
                    id += 1
                }
            }
            try store.applyRetention(detailCutoff: t0.addingTimeInterval(10 * day), retentionCutoff: t0.addingTimeInterval(-day))
            let all = try store.dailyAggregates(since: nil)
            XCTAssertEqual(all.count, 21, name)
            XCTAssertEqual(all.map(\.key), all.map(\.key).sorted(by: >), "\(name): newest day first, then by key")
            XCTAssertEqual(all.first?.day, all.max { $0.day < $1.day }?.day, name)

            var paged: [DailyAggregate] = []
            var after: DailyAggregate.Key?
            while true {
                let page = try store.dailyAggregates(since: nil, after: after, limit: 4)
                paged += page
                guard page.count == 4, let last = page.last else { break }
                after = last.key
            }
            XCTAssertEqual(paged, all, name)

            // `since` keeps the rows last seen at or after it, paged the same way.
            let since = t0.addingTimeInterval(day)
            let recent = try store.dailyAggregates(since: since)
            XCTAssertEqual(recent.count, 14, name)
            let first = try store.dailyAggregates(since: since, after: nil, limit: 10)
            let rest = try store.dailyAggregates(since: since, after: first.last?.key, limit: 10)
            XCTAssertEqual(first + rest, recent, name)
        }
    }

    /// Keys compare as SQLite compares text (bytes), so a cursor taken from one store's row continues
    /// in the same order for names outside ASCII, whatever their normalization.
    func testDailyKeysCompareByteForByte() {
        let nfc = DailyAggregate.Key(day: "2026-10-01", responsibleKey: "app:/tmp/Caf\u{E9}.app", categoryID: "test-vault", agentID: "")
        let nfd = DailyAggregate.Key(day: "2026-10-01", responsibleKey: "app:/tmp/Cafe\u{301}.app", categoryID: "test-vault", agentID: "")
        XCTAssertNotEqual(nfc, nfd, "different bytes are different rows")
        XCTAssertTrue(nfd < nfc, "0x65 0xCC 0x81 sorts before 0xC3 0xA9")
        XCTAssertFalse(nfc < nfd)
        XCTAssertTrue(DailyAggregate.Key(day: "2026-09-30", responsibleKey: "z", categoryID: "z", agentID: "z") < nfd)
    }

    // MARK: - daemon-6 / ipc-1: rows kept

    /// Minted apps add a summary row (and, once rolled up, a daily row) each: retention also evicts the
    /// least recently seen rows by count, down to a tenth below the limit, as the baseline does (dos-1).
    func testRetentionEvictsTheLeastRecentlySeenRowsByCount() throws {
        let limits = StoreLimits(summaryRows: 10, dailyRows: 10)
        for (name, store) in try stores(limits: limits) {
            try mint(25, into: store)
            try store.applyRetention(detailCutoff: t0.addingTimeInterval(day), retentionCutoff: t0.addingTimeInterval(-day))
            let kept = (16..<25).reversed().map { "m\($0)" }
            XCTAssertEqual(try store.summaries(limit: .max).map(\.responsible.displayName), kept, name)
            XCTAssertEqual(try store.dailyAggregates(since: nil).map(\.summary.responsible.displayName).sorted(), kept.sorted(), name)
            XCTAssertEqual(try store.counts().aggregatedDays, 1, name)

            // At the limit or under it, nothing goes.
            try store.insert([access(100, 3600, app: 100)])
            try store.applyRetention(detailCutoff: t0.addingTimeInterval(day), retentionCutoff: t0.addingTimeInterval(-day))
            XCTAssertEqual(try store.summaries(limit: .max).count, 10, name)
            XCTAssertEqual(try store.dailyAggregates(since: nil).count, 10, name)
        }
    }

    func testDefaultLimitsMatchTheBaseline() {
        XCTAssertEqual(StoreLimits().summaryRows, 100_000)
        XCTAssertEqual(StoreLimits().dailyRows, 100_000)
        XCTAssertEqual(StoreLimits.lowWaterMark(100_000), 90_000)
        XCTAssertEqual(StoreLimits.lowWaterMark(10), 9)
        XCTAssertEqual(StoreLimits.lowWaterMark(1), 0)
    }

    // MARK: - cli-6: activity in a window

    /// `apps --since`: FIRST, LAST and the counts cover the window only, not all time. Within the
    /// detail window they are exact; a rolled-up day counts whole.
    func testActivityCountsOnlyTheWindow() throws {
        for (name, store) in try stores() {
            // App 1: five reads two hours in, then a denied write three hours in. App 2: one read four
            // hours in. Both also ten days earlier, rolled up since.
            try store.insert((0..<5).map { access(Int64(10 + $0), -10 * day + Double($0), app: 1) })
            try store.insert([access(20, -10 * day, app: 2)])
            try store.applyRetention(detailCutoff: t0.addingTimeInterval(-day), retentionCutoff: t0.addingTimeInterval(-30 * day))
            try store.insert((0..<5).map { access(Int64(100 + $0), 2 * 3600 + Double($0), app: 1) })
            try store.insert([access(105, 3 * 3600, app: 1, access: .write, decision: .denied)])
            try store.insert([access(106, 4 * 3600, app: 2)])

            let window = try store.activity(since: t0.addingTimeInterval(2.5 * 3600), limit: 100)
            XCTAssertEqual(window.map(\.responsible.displayName), ["m2", "m1"], name)
            let one = try XCTUnwrap(window.first { $0.responsible.displayName == "m1" }, name)
            XCTAssertEqual(one.count, 1, "\(name): only the access inside the window")
            XCTAssertEqual(one.firstSeen, t0.addingTimeInterval(3 * 3600), name)
            XCTAssertEqual(one.lastSeen, t0.addingTimeInterval(3 * 3600), name)
            XCTAssertEqual([one.reads, one.writes, one.denied], [0, 1, 1], name)

            let all = try store.activity(since: t0.addingTimeInterval(-11 * day), limit: 100)
            let both = try XCTUnwrap(all.first { $0.responsible.displayName == "m1" }, name)
            XCTAssertEqual(both.count, 11, "\(name): the rolled-up day and the details")
            XCTAssertEqual(both.firstSeen, t0.addingTimeInterval(-10 * day), name)
            XCTAssertEqual(both.lastSeen, t0.addingTimeInterval(3 * 3600), name)

            // A window that starts inside a rolled-up day counts that day whole.
            let partial = try store.activity(since: t0.addingTimeInterval(-10 * day + 2.5), limit: 100)
            XCTAssertEqual(partial.first { $0.responsible.displayName == "m1" }?.count, 11, name)

            XCTAssertEqual(try store.activity(since: t0.addingTimeInterval(2.5 * 3600), limit: 1).map(\.responsible.displayName), ["m2"], name)
            XCTAssertTrue(try store.activity(since: t0.addingTimeInterval(5 * 3600), limit: 100).isEmpty, name)
            // The all-time rows are unchanged.
            XCTAssertEqual(try store.summaries(since: nil).first { $0.responsible.displayName == "m1" }?.count, 11, name)
            XCTAssertEqual(try store.summaries(since: nil).first { $0.responsible.displayName == "m1" }?.firstSeen,
                           t0.addingTimeInterval(-10 * day), name)
        }
    }

    /// A window longer than one page of events (the store lock is released between pages) counts each
    /// access once.
    func testActivityAcrossPagesCountsEachAccessOnce() throws {
        let store = try SQLiteEventStore(path: sqlitePath())
        store.scanBatch = 3
        // Same timestamps across ids, so a page can end in the middle of equal times.
        try store.insert((0..<20).map { access(Int64($0 + 1), Double($0 / 4), app: $0 % 3) })
        let window = try store.activity(since: t0, limit: 10)
        XCTAssertEqual(window.reduce(0) { $0 + $1.count }, 20)
        XCTAssertEqual(Dictionary(uniqueKeysWithValues: window.map { ($0.responsible.displayName, $0.count) }), ["m0": 7, "m1": 7, "m2": 6])
        let later = try store.activity(since: t0.addingTimeInterval(3), limit: 10)
        XCTAssertEqual(later.reduce(0) { $0 + $1.count }, 8)
    }
}
