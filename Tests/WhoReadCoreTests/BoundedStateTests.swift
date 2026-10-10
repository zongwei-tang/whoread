import XCTest
@testable import WhoReadCore

/// dos-1: an unsigned program is keyed by its path ("bin:<path>"), so copies of one binary at N
/// paths are N apps. The baseline and the open alert windows grew by one entry per copy, for good.
final class BoundedStateTests: XCTestCase {
    func key(_ i: Int, _ category: String = "test-vault") -> BaselineKey {
        BaselineKey(responsibleKey: "bin:/tmp/d\(i)/t", categoryID: category, access: .read)
    }

    func testDistinctProgramPathsAreDistinctBaselineEntries() throws {
        // The amplification: detached copies of one binary at other paths each add an entry.
        let h = try Harness(learningDays: 0)
        for i in 0..<20 {
            let copy = proc(Int32(1000 + i), "/tmp/d\(i)/t", argv: ["t"])
            h.fork(P.launchd, copy)
            _ = h.open(copy, "/Users/alice/WhoReadTestVault/ssh/id_ed25519")
        }
        let keys = Set(h.baseline.allEntries.map(\.key.responsibleKey).filter { $0.hasPrefix("bin:") && $0.hasSuffix("/t") })
        XCTAssertEqual(keys.count, 20, "\(h.baseline.allEntries.map(\.key))")
    }

    func testUnapprovedEntriesBeyondTheLimitAreForgottenOldestFirstAndApprovalsStay() {
        let b = Baseline(learningStartedAt: t0, maxUnapproved: 50)
        b.approve(responsibleKey: "app:/applications/zoom.us.app", categoryID: "ssh", at: at(-1000))
        for i in 0..<200 { b.record(key(i), at: at(Double(i)), learning: false) }
        XCTAssertEqual(b.count, 202, "recording never sorts or evicts (that is maintenance's job)")
        _ = b.takeDirty()

        // Down to 45 (a tenth below the limit), not to the limit itself: see testPruneLeavesRoomBelowTheLimit.
        XCTAssertEqual(b.prune(), 155)
        XCTAssertEqual(b.count, 47)
        XCTAssertTrue(b.isApproved(BaselineKey(responsibleKey: "app:/applications/zoom.us.app", categoryID: "ssh", access: .read)),
                      "the user's approvals are never forgotten, however old")
        XCTAssertFalse(b.contains(key(154)), "the least recently seen go first")
        XCTAssertTrue(b.contains(key(155)))
        XCTAssertTrue(b.contains(key(199)))
        let dirty = b.takeDirty()
        XCTAssertEqual(dirty.count, 155)
        XCTAssertTrue(dirty.allSatisfy { $0.1 == nil }, "removed: the next save deletes their rows")
        XCTAssertEqual(b.prune(), 0, "under the limit: nothing to do")
        // A forgotten entry is simply new again: its next access alerts as a first access.
        XCTAssertTrue(b.record(key(0), at: at(500), learning: false))
    }

    /// Over the limit, prune evicts down to a tenth below it. Trimming to the limit exactly meant that
    /// under a sustained flood every maintenance pass (every 30 s) sorted all unapproved entries
    /// (100k) while holding the lock that `record` needs; now a sort comes once per 10k new entries.
    func testPruneLeavesRoomBelowTheLimit() {
        let b = Baseline(learningStartedAt: t0, maxUnapproved: 100)
        for i in 0..<101 { b.record(key(i), at: at(Double(i)), learning: false) }
        XCTAssertEqual(b.prune(), 11)
        XCTAssertEqual(b.count, 90)
        XCTAssertFalse(b.contains(key(10)), "the least recently seen go first")
        XCTAssertTrue(b.contains(key(11)))
        for i in 101..<111 { b.record(key(i), at: at(Double(i)), learning: false) }
        XCTAssertEqual(b.count, 100)
        XCTAssertEqual(b.prune(), 0, "at the limit: no sort, no eviction")
        b.record(key(111), at: at(111), learning: false)
        XCTAssertEqual(b.prune(), 11)
        XCTAssertEqual(b.count, 90)
        XCTAssertEqual(Baseline(learningStartedAt: t0, maxUnapproved: 5).lowWaterMark, 4, "at least one below the limit")
        XCTAssertEqual(Baseline(learningStartedAt: t0).lowWaterMark, 90_000)
    }

    /// Entries are not forgotten for age: an app's access the baseline already knows must not alert
    /// "for the first time" again a month later. Only the count limit evicts (oldest first).
    func testOldUnapprovedEntriesAreKeptWhileUnderTheLimit() {
        let b = Baseline(learningStartedAt: t0)
        b.record(key(1), at: at(-400 * 86400), learning: false)
        b.record(key(2), at: at(-40 * 86400), learning: true)
        b.record(key(3), at: at(-86400), learning: false)
        _ = b.takeDirty()
        XCTAssertEqual(b.prune(), 0)
        XCTAssertTrue(b.contains(key(1)))
        XCTAssertTrue(b.contains(key(2)))
        XCTAssertTrue(b.contains(key(3)))
        XCTAssertTrue(b.takeDirty().isEmpty, "nothing to delete")
        XCTAssertFalse(b.record(key(1), at: t0, learning: false), "still known: not a first access")
    }

    func testAnOversizedStoredTableIsCappedWhenLoaded() {
        let entries = (0..<120).map { BaselineEntry(key: key($0), firstSeen: at(Double($0)), lastSeen: at(Double($0)), count: 1, source: .observed) }
            + [BaselineEntry(key: key(0, "ssh"), firstSeen: t0, lastSeen: t0, count: 0, source: .approved)]
        let b = Baseline(learningStartedAt: t0, entries: entries, maxUnapproved: 100)
        // 90 unapproved left (a tenth below the limit) and the approval.
        XCTAssertEqual(b.count, 91)
        XCTAssertTrue(b.isApproved(key(0, "ssh")))
        XCTAssertFalse(b.contains(key(29)))
        XCTAssertTrue(b.contains(key(30)))
        XCTAssertEqual(b.takeDirty().count, 30, "the dropped rows are deleted on the first save")
    }

    func testTheNewestEntriesAreListedFirstUpToTheLimit() {
        let b = Baseline(learningStartedAt: t0)
        for i in 0..<30 { b.record(key(i), at: at(Double(i)), learning: false) }
        let newest = b.newestEntries(limit: 5)
        XCTAssertEqual(newest.map(\.key), [key(29), key(28), key(27), key(26), key(25)])
        XCTAssertEqual(b.newestEntries(limit: 100).count, 30)
        XCTAssertEqual(Baseline.defaultMaxUnapproved, 100_000)
        XCTAssertLessThanOrEqual(Baseline.replyLimit, Baseline.defaultMaxUnapproved)
    }

    func testOpenAlertWindowsAreBounded() {
        let c = AlertCoalescer(window: 600, maxOpen: 100)
        func event(_ i: Int, _ t: TimeInterval) -> AnalyzedEvent {
            AnalyzedEvent(id: Int64(i + 1), time: at(t), operation: .open, access: .read,
                          path: "/Users/alice/WhoReadTestVault/ssh/id_ed25519", secondaryPath: nil, categoryID: "test-vault",
                          severity: .critical, process: proc(Int32(1000 + i), "/tmp/d\(i)/t"), chain: [],
                          responsible: ResponsibleEntity(kind: .binary, key: "bin:/tmp/d\(i)/t", displayName: "t"),
                          agentID: nil, isOwner: false, benignServiceID: nil, decision: .allowed, ruleID: nil)
        }
        for i in 0..<1000 {
            XCTAssertEqual(c.ingest(event(i, Double(i) * 0.01), kind: .firstAccess)?.change, .created)
            XCTAssertLessThanOrEqual(c.openCount, 100)
        }
        // A window still open merges as before.
        XCTAssertEqual(c.ingest(event(999, 11), kind: .firstAccess)?.change, .merged)
        // One dropped early: a later event of that app opens a new alert (never a lost one).
        XCTAssertEqual(c.ingest(event(0, 12), kind: .firstAccess)?.change, .created)
        XCTAssertGreaterThan(c.peekNextID, 1001)
    }
}
