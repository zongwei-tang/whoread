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

        XCTAssertEqual(b.prune(), 150)
        XCTAssertEqual(b.count, 52)
        XCTAssertTrue(b.isApproved(BaselineKey(responsibleKey: "app:/applications/zoom.us.app", categoryID: "ssh", access: .read)),
                      "the user's approvals are never forgotten, however old")
        XCTAssertFalse(b.contains(key(149)), "the least recently seen go first")
        XCTAssertTrue(b.contains(key(150)))
        XCTAssertTrue(b.contains(key(199)))
        let dirty = b.takeDirty()
        XCTAssertEqual(dirty.count, 150)
        XCTAssertTrue(dirty.allSatisfy { $0.1 == nil }, "removed: the next save deletes their rows")
        XCTAssertEqual(b.prune(), 0, "under the limit: nothing to do")
        // A forgotten entry is simply new again: its next access alerts as a first access.
        XCTAssertTrue(b.record(key(0), at: at(500), learning: false))
    }

    func testEntriesNotSeenWithinRetentionAreForgotten() {
        let b = Baseline(learningStartedAt: t0)
        b.record(key(1), at: at(-40 * 86400), learning: false)
        b.record(key(2), at: at(-40 * 86400), learning: true)
        b.record(key(3), at: at(-86400), learning: false)
        b.approve(responsibleKey: "bin:/tmp/approved", categoryID: "ssh", access: .read, at: at(-400 * 86400))
        _ = b.takeDirty()
        XCTAssertEqual(b.prune(lastSeenBefore: at(-30 * 86400)), 2)
        XCTAssertFalse(b.contains(key(1)))
        XCTAssertFalse(b.contains(key(2)))
        XCTAssertTrue(b.contains(key(3)))
        XCTAssertTrue(b.isApproved(BaselineKey(responsibleKey: "bin:/tmp/approved", categoryID: "ssh", access: .read)))
        XCTAssertEqual(Set(b.takeDirty().map(\.0)), [key(1), key(2)])
    }

    func testAnOversizedStoredTableIsCappedWhenLoaded() {
        let entries = (0..<120).map { BaselineEntry(key: key($0), firstSeen: at(Double($0)), lastSeen: at(Double($0)), count: 1, source: .observed) }
            + [BaselineEntry(key: key(0, "ssh"), firstSeen: t0, lastSeen: t0, count: 0, source: .approved)]
        let b = Baseline(learningStartedAt: t0, entries: entries, maxUnapproved: 100)
        XCTAssertEqual(b.count, 101)
        XCTAssertTrue(b.isApproved(key(0, "ssh")))
        XCTAssertFalse(b.contains(key(19)))
        XCTAssertTrue(b.contains(key(20)))
        XCTAssertEqual(b.takeDirty().count, 20, "the dropped rows are deleted on the first save")
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
