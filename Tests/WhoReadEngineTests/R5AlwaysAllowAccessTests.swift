import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// daemon-1: "always allow" on an alert approves the access kinds the alert covered, and only those.
/// In monitor-only mode the baseline is all that keeps an access quiet: approving both kinds after a
/// read alert would silence every later write of the same app to the category's critical files (and
/// the other way round). ASK_MODE: "A read approval does not answer a write".
final class R5AlwaysAllowAccessTests: XCTestCase {
    private func key(_ access: AccessKind) -> BaselineKey {
        BaselineKey(responsibleKey: r5ZoomKey, categoryID: "test-vault", access: access)
    }

    func testAlwaysAllowOnAReadAlertLeavesWritesAlerting() throws {
        let dir = TempDir()
        let core = try r5Core(dir)
        let zoom = r5Zoom(core)
        let t = Date()
        r5Receive(core, r5Open(zoom, r5VaultKey, at: t))
        let first = try XCTUnwrap(try r5Alerts(core).first)
        XCTAssertEqual(first.kind, .criticalNonOwner)
        XCTAssertEqual(first.accesses, .read)
        XCTAssertEqual(first.ancestryKnown, true, "a known chain: it alerts for being new, not for its unknown starter")

        try core.apply(action: .alwaysAllow, toAlert: first.id, peer: .inProcess)
        XCTAssertTrue(core.baseline.isApproved(key(.read)))
        XCTAssertFalse(core.baseline.isApproved(key(.write)), "a read approval does not answer a write")

        // Twenty minutes later (another coalescing window), a write-only open of the same key.
        r5Receive(core, r5Open(zoom, r5VaultKey, .write, at: t.addingTimeInterval(1200)))
        var alerts = try r5Alerts(core)
        XCTAssertEqual(alerts.count, 2, r5Describe(alerts))
        XCTAssertEqual(alerts.last?.kind, .criticalNonOwner)
        XCTAssertEqual(alerts.last?.accesses, .write)
        // What was allowed stays quiet.
        r5Receive(core, r5Open(zoom, r5VaultKey, at: t.addingTimeInterval(2400)))
        alerts = try r5Alerts(core)
        XCTAssertEqual(alerts.count, 2, r5Describe(alerts))
    }

    func testAlwaysAllowOnAWriteAlertLeavesReadsOfCriticalFilesAlerting() throws {
        let dir = TempDir()
        let core = try r5Core(dir)
        let zoom = r5Zoom(core)
        let t = Date()
        r5Receive(core, r5Open(zoom, r5VaultKnownHosts, .write, at: t))
        let first = try XCTUnwrap(try r5Alerts(core).first)
        XCTAssertEqual(first.kind, .firstAccess)
        XCTAssertEqual(first.accesses, .write)
        XCTAssertEqual(first.ancestryKnown, true)

        try core.apply(action: .alwaysAllow, toAlert: first.id, peer: .inProcess)
        XCTAssertTrue(core.baseline.isApproved(key(.write)))
        XCTAssertFalse(core.baseline.isApproved(key(.read)))

        r5Receive(core, r5Open(zoom, r5VaultKey, at: t.addingTimeInterval(1200)))
        let alerts = try r5Alerts(core)
        XCTAssertEqual(alerts.count, 2, r5Describe(alerts))
        XCTAssertEqual(alerts.last?.kind, .criticalNonOwner)
        XCTAssertEqual(alerts.last?.accesses, .read)
    }

    /// An alert about opens that neither read nor wrote: nothing to allow, nothing approved.
    func testAnAlertWithoutAccessesApprovesNothing() throws {
        let dir = TempDir()
        let core = try r5Core(dir)
        let alert = Alert(id: 1, kind: .criticalNonOwner, createdAt: Date(), updatedAt: Date(), windowEndsAt: Date().addingTimeInterval(600),
                          responsible: ResponsibleEntity(kind: .app, key: r5ZoomKey, displayName: "zoom.us",
                                                         path: "/Applications/zoom.us.app"),
                          categoryID: "test-vault", severity: .critical, count: 1, accesses: [], firstPath: r5VaultKey,
                          firstEventID: 1, lastEventID: 1, paths: [r5VaultKey], chain: [], agentID: nil, ruleID: nil,
                          chainAgents: [], ancestryKnown: true)
        try core.store.upsert([alert])
        try core.apply(action: .alwaysAllow, toAlert: 1, peer: .inProcess)
        XCTAssertFalse(core.baseline.isApproved(key(.read)))
        XCTAssertFalse(core.baseline.isApproved(key(.write)))
        XCTAssertEqual(try core.store.alert(id: 1)?.status, .resolved)
    }
}
