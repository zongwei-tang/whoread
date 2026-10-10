import XCTest
import WhoReadCore
@testable import WhoReadStore

/// Roll-up and id high-water marks, checked against both stores so they keep the same semantics.
final class RetentionTests: XCTestCase {
    var dir: URL!

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), isDirectory: true).appendingPathComponent("whoread-retention-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    let t0 = Date(timeIntervalSince1970: 1_760_000_000)

    func stores() throws -> [(String, EventStore)] {
        [("sqlite", try SQLiteEventStore(path: dir.appendingPathComponent("\(UUID().uuidString).sqlite").path)),
         ("memory", InMemoryEventStore())]
    }

    func event(_ id: Int64, _ dt: TimeInterval, benign: Bool = false, access: AccessSet = .read,
               decision: EventDecision = .observed) -> AnalyzedEvent {
        AnalyzedEvent(
            id: id, time: t0.addingTimeInterval(dt), operation: .open, access: access, path: "/Users/alice/.ssh/id_rsa",
            secondaryPath: nil, categoryID: "ssh", severity: .critical,
            process: ProcessRecord(pid: Int32(id), ppid: 1, executablePath: "/bin/cat", isPlatformBinary: true, argv: ["cat"]),
            chain: [ChainLink(pid: 1, name: "launchd", path: "/sbin/launchd")],
            responsible: ResponsibleEntity(kind: .app, key: "app:/terminal", displayName: "Terminal"),
            agentID: nil, isOwner: false, benignServiceID: benign ? "spotlight" : nil, decision: decision, ruleID: nil)
    }

    func alert(_ id: Int64, at t: Date) -> Alert {
        Alert(id: id, kind: .firstAccess, createdAt: t, updatedAt: t, windowEndsAt: t.addingTimeInterval(600),
              responsible: ResponsibleEntity(kind: .app, key: "app:/z", displayName: "Zoom"), categoryID: "ssh",
              severity: .critical, count: 1, accesses: .read, firstPath: "/Users/alice/.ssh/id_rsa", firstEventID: 1,
              lastEventID: 1, paths: ["/Users/alice/.ssh/id_rsa"], chain: [], agentID: nil, ruleID: nil)
    }

    func testMixedBenignRowsRollUpOnceWithoutDoubleCounting() throws {
        for (name, store) in try stores() {
            try store.insert([event(1, 0), event(2, 60, decision: .denied), event(3, 120, benign: true)])
            try store.applyRetention(detailCutoff: t0.addingTimeInterval(3600), retentionCutoff: t0.addingTimeInterval(-86_400))
            let daily = try store.dailyAggregates(since: nil)
            XCTAssertEqual(daily.count, 1, name)
            let s = try XCTUnwrap(daily.first?.summary, name)
            XCTAssertEqual(s.count, 3, name)
            XCTAssertEqual(s.reads, 3, name)
            XCTAssertEqual(s.writes, 0, name)
            XCTAssertEqual(s.denied, 1, name)
            XCTAssertFalse(s.benign, "\(name): a day with any non-benign access is not benign")
        }
    }

    func testRollUpIntoExistingDayKeepsCountsAndBenignFlag() throws {
        for (name, store) in try stores() {
            try store.insert([event(1, 0, benign: true)])
            try store.applyRetention(detailCutoff: t0.addingTimeInterval(30), retentionCutoff: t0.addingTimeInterval(-86_400))
            XCTAssertEqual(try store.dailyAggregates(since: nil).first?.summary.benign, true, name)
            try store.insert([event(2, 60, access: .readWrite)])
            try store.applyRetention(detailCutoff: t0.addingTimeInterval(90), retentionCutoff: t0.addingTimeInterval(-86_400))
            let s = try XCTUnwrap(try store.dailyAggregates(since: nil).first?.summary, name)
            XCTAssertEqual([s.count, s.reads, s.writes, s.denied], [2, 2, 1, 0], name)
            XCTAssertFalse(s.benign, name)
        }
    }

    func testDaysAreLocalCalendarDays() throws {
        // 11 hours after t0 is 19:53 UTC: a different calendar day east of UTC+4.
        let dt: TimeInterval = 11 * 3600
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = .current
        f.dateFormat = "yyyy-MM-dd"
        for (name, store) in try stores() {
            try store.insert([event(1, dt)])
            try store.applyRetention(detailCutoff: t0.addingTimeInterval(dt + 1), retentionCutoff: t0.addingTimeInterval(-86_400))
            XCTAssertEqual(try store.dailyAggregates(since: nil).first?.day, f.string(from: t0.addingTimeInterval(dt)), name)
        }
    }

    func testAlertIDsStayMonotonicAfterRetentionPurgesEveryAlert() throws {
        for (name, store) in try stores() {
            try store.upsert([alert(3, at: t0), alert(4, at: t0)])
            XCTAssertEqual(try store.maxAlertID(), 4, name)
            try store.applyRetention(detailCutoff: t0.addingTimeInterval(86_400), retentionCutoff: t0.addingTimeInterval(86_400))
            XCTAssertEqual(try store.counts().alerts, 0, name)
            XCTAssertEqual(try store.maxAlertID(), 4, "\(name): a purged id must never be handed out again")
            try store.upsert([alert(5, at: t0.addingTimeInterval(2 * 86_400))])
            XCTAssertEqual(try store.maxAlertID(), 5, name)
        }
    }

    func testEventIDsStayMonotonicInBothStores() throws {
        for (name, store) in try stores() {
            try store.insert([event(1, 0), event(2, 60)])
            try store.applyRetention(detailCutoff: t0.addingTimeInterval(86_400), retentionCutoff: t0.addingTimeInterval(86_400))
            XCTAssertEqual(try store.counts().events, 0, name)
            XCTAssertEqual(try store.maxEventID(), 2, name)
        }
    }

    func testAlertHighWaterMarkSurvivesReopen() throws {
        let path = dir.appendingPathComponent("reopen.sqlite").path
        do {
            let store = try SQLiteEventStore(path: path)
            try store.upsert([alert(9, at: t0)])
            try store.applyRetention(detailCutoff: t0.addingTimeInterval(86_400), retentionCutoff: t0.addingTimeInterval(86_400))
        }
        XCTAssertEqual(try SQLiteEventStore(path: path).maxAlertID(), 9)
    }
}
