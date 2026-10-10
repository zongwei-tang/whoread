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

final class AskPrivilegeFollowUpTests: XCTestCase {
    func testTurningAppleTrustOffIsStrengtheningAndOnIsNot() throws {
        var current = Settings()
        current.trustApplePrograms = true
        var off = current
        off.trustApplePrograms = false
        XCTAssertTrue(DaemonCore.onlyTurnsOffAppleTrust(off, current: current))
        var offAndMore = off
        offAndMore.retentionDays = 5
        XCTAssertFalse(DaemonCore.onlyTurnsOffAppleTrust(offAndMore, current: current), "other changes still need privilege")
        XCTAssertFalse(DaemonCore.onlyTurnsOffAppleTrust(current, current: off), "turning it on weakens")
    }
}

final class AskIDFollowUpTests: XCTestCase {
    func request() -> AskRequest {
        AskRequest(id: 0, key: AskKey(responsibleKey: "app:/x", categoryID: "ssh", access: .read, chainAgents: []),
                   responsible: ResponsibleEntity(kind: .app, key: "app:/x", displayName: "X"), severity: .critical,
                   path: "/Users/alice/.ssh/id_ed25519", process: ProcessRecord(pid: 1, ppid: 0, executablePath: "/bin/cat"),
                   chain: [], agentID: nil, appleProgram: false, firstAt: Date(), lastAt: Date())
    }

    /// Ids start where the caller says (DaemonCore passes a millisecond timestamp), so they never repeat
    /// across daemon instances.
    func testQuestionIDsStartAtTheGivenValue() {
        let broker = AskBroker(firstID: 1_760_000_000_000)
        broker.noteAnsweringClient()
        let d = broker.hold(request(), budget: 5) { _ in }
        guard case .held(let id) = d else { return XCTFail("\(d)") }
        XCTAssertEqual(id, 1_760_000_000_000)
        broker.denyAll()
    }

    func testDaemonQuestionIDsAreTimestampBased() throws {
        let dir = TempDir()
        var c = baseConfig(dir)
        c.resolveOwners = false
        let core = try DaemonCore(config: c, makeSource: { _ in FakeSource(canEnforce: true) })
        core.askBroker.noteAnsweringClient()
        let d = core.askBroker.hold(request(), budget: 5) { _ in }
        guard case .held(let id) = d else { return XCTFail("\(d)") }
        XCTAssertGreaterThan(id, 1_700_000_000_000)
        core.askBroker.denyAll()
    }
}
