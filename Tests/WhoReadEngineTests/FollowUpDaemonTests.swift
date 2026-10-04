import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// Main-side follow-ups of review round 2.
final class FollowUpDaemonTests: XCTestCase {
    func core(_ dir: TempDir) throws -> DaemonCore {
        var c = baseConfig(dir)
        c.resolveOwners = false
        return try DaemonCore(config: c, makeSource: { _ in FakeSource(canEnforce: true) })
    }

    func testCatalogRefusesWholeDisksHomesAndTheirParents() throws {
        let dir = TempDir()
        let core = try core(dir)
        for p in ["/System/Volumes/Data", "/System/Volumes/Data/", "/Users/alice", "/Users", "~/", "/USERS/ALICE"] {
            var catalog = core.data.catalog
            let i = catalog.categories.firstIndex { $0.id == "custom" }!
            catalog.categories[i].paths = [p]
            XCTAssertThrowsError(try core.update(catalog: catalog, peer: .inProcess), p) { e in
                XCTAssertEqual((e as? IPCError)?.code, .invalid, p)
            }
        }
        // A narrower path is fine, and the default /Volumes/ stays accepted on round trips.
        var catalog = core.data.catalog
        let i = catalog.categories.firstIndex { $0.id == "custom" }!
        catalog.categories[i].paths = ["~/Documents/secret"]
        XCTAssertNoThrow(try core.update(catalog: catalog, peer: .inProcess))
        XCTAssertNoThrow(try core.update(catalog: core.data.catalog, peer: .inProcess))
    }

    func testAStaleFullCopyNeverBringsBackAUsedAllowOnce() throws {
        let now = Date()
        let exception = RuleException(subject: .anyNonOwner, expiresAt: now.addingTimeInterval(600), remainingUses: 1, createdAt: now)
        var current = Rule(id: "r", target: .category("ssh"), subject: .anyNonOwner, action: .deny, exceptions: [exception])
        let stale = current                       // what a client read before the use
        current.exceptions[0].remainingUses = 0   // used meanwhile
        var edited = stale
        edited.enabled = false                    // the client's actual change
        let merged = DaemonCore.keepingConsumedUses(edited, current: current)
        XCTAssertEqual(merged.exceptions[0].remainingUses, 0)
        XCTAssertFalse(merged.enabled)
    }

    func testStatusCarriesKernelDrops() throws {
        let dir = TempDir()
        let core = try core(dir)
        XCTAssertNil(core.status().sourceKernelDrops, "the fake source reports none")
    }
}
