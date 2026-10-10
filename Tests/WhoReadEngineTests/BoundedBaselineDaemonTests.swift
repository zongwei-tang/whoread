import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadStore
@testable import WhoReadEngine

/// dos-1 at daemon level: maintenance forgets unapproved baseline entries history no longer holds
/// (and any beyond the limit), their rows go too, and one `baseline` reply stays bounded.
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

    func testMaintenanceForgetsEntriesNotSeenWithinRetentionAndDeletesTheirRows() throws {
        let dir = TempDir()
        let now = Date()
        do {
            let c = try core(dir)
            XCTAssertEqual(c.currentSettings.retentionDays, 30)
            c.baseline.record(BaselineKey(responsibleKey: "bin:/tmp/old", categoryID: "ssh", access: .read),
                              at: now.addingTimeInterval(-40 * 86400), learning: false)
            c.baseline.record(BaselineKey(responsibleKey: "bin:/tmp/recent", categoryID: "ssh", access: .read),
                              at: now.addingTimeInterval(-86400), learning: false)
            c.baseline.approve(responsibleKey: "app:/applications/zoom.us.app", categoryID: "ssh", access: .read,
                               at: now.addingTimeInterval(-300 * 86400))
            c.persistBaseline()
            XCTAssertEqual(try storedKeys(c), ["bin:/tmp/old", "bin:/tmp/recent", "app:/applications/zoom.us.app"])
            c.maintenance(now: now)
            XCTAssertEqual(Set(c.baseline.allEntries.map(\.key.responsibleKey)), ["bin:/tmp/recent", "app:/applications/zoom.us.app"])
            XCTAssertEqual(try storedKeys(c), ["bin:/tmp/recent", "app:/applications/zoom.us.app"], "the forgotten row is deleted")
        }
        // A restart loads what is left.
        let again = try core(dir)
        XCTAssertEqual(Set(again.baseline.allEntries.map(\.key.responsibleKey)), ["bin:/tmp/recent", "app:/applications/zoom.us.app"])
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
