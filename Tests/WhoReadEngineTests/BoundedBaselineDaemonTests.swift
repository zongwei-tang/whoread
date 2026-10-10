import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadStore
@testable import WhoReadEngine

/// dos-1 at daemon level: the baseline is bounded by count only (maintenance evicts the least
/// recently seen unapproved entries beyond the limit, and their rows go too), and one `baseline`
/// reply stays bounded.
final class BoundedBaselineDaemonTests: XCTestCase {
    private func core(_ dir: TempDir) throws -> DaemonCore {
        var config = baseConfig(dir)
        config.resolveOwners = false
        return try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
    }

    private func storedKeys(_ core: DaemonCore) throws -> Set<String> {
        let db = try SQLiteDatabase(path: core.config.databasePath)
        var keys = Set<String>()
        try db.prepare("SELECT responsible_key FROM baseline").query { keys.insert($0.text(0) ?? "") }
        return keys
    }

    /// Entries are not forgotten for age: maintenance used to drop unapproved entries not seen within
    /// the retention period (30 days), so an app's known access alerted "for the first time" again.
    func testMaintenanceKeepsUnapprovedEntriesOlderThanRetention() throws {
        let dir = TempDir()
        let now = Date()
        let old = BaselineKey(responsibleKey: "bin:/tmp/old", categoryID: "ssh", access: .read)
        do {
            let c = try core(dir)
            XCTAssertEqual(c.currentSettings.retentionDays, 30)
            c.baseline.record(old, at: now.addingTimeInterval(-40 * 86400), learning: false)
            c.baseline.record(BaselineKey(responsibleKey: "bin:/tmp/recent", categoryID: "ssh", access: .read),
                              at: now.addingTimeInterval(-86400), learning: false)
            c.baseline.approve(responsibleKey: "app:/applications/zoom.us.app", categoryID: "ssh", access: .read,
                               at: now.addingTimeInterval(-300 * 86400))
            c.persistBaseline()
            // The first pass runs the hourly retention too.
            c.maintenance(now: now)
            c.maintenance(now: now.addingTimeInterval(2 * 3600))
            let all: Set<String> = ["bin:/tmp/old", "bin:/tmp/recent", "app:/applications/zoom.us.app"]
            XCTAssertEqual(Set(c.baseline.allEntries.map(\.key.responsibleKey)), all)
            XCTAssertEqual(try storedKeys(c), all, "the rows stay")
            XCTAssertFalse(c.baseline.record(old, at: now, learning: false), "still known: not a first access")
        }
        // A restart loads them all.
        let again = try core(dir)
        XCTAssertTrue(again.baseline.contains(old))
        XCTAssertEqual(again.baseline.count, 3)
    }

    func testTheBaselineReplyIsTheNewestEntriesOnly() throws {
        let dir = TempDir()
        let c = try core(dir)
        let t = Date()
        let total = Baseline.replyLimit + 50
        for i in 0..<total {
            c.baseline.record(BaselineKey(responsibleKey: "bin:/tmp/d\(i)/t", categoryID: "ssh", access: .read),
                              at: t.addingTimeInterval(Double(i)), learning: false)
        }
        let client = InProcessClient(handler: Daemon.handlerForReplay(c))
        guard case .baseline(let entries) = try client.call(.baseline) else { return XCTFail("no baseline reply") }
        XCTAssertEqual(entries.count, Baseline.replyLimit)
        XCTAssertEqual(entries.first?.key.responsibleKey, "bin:/tmp/d\(total - 1)/t", "newest first")
        XCTAssertEqual(c.baseline.count, total, "the reply is cut, not the baseline")
    }
}
