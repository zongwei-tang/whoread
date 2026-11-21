import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// daemon-3: the eslogger reader keeps ingesting while the user acts on an alert. An escalation that
/// lands meanwhile (the same app now writing a critical file of the category) must stay unread: the
/// action applies to the alert the user saw, never by writing a copy read before the escalation over it.
final class R5DaemonAlertStatusRaceTests: XCTestCase {
    func testAnEscalationWhileAlwaysAllowIsAppliedStaysUnread() throws {
        let dir = TempDir()
        let core = try r5dCore(dir)
        let zoom = r5dZoom(core)
        let t = Date()
        r5dReceive(core, r5dOpen(zoom, r5dVaultKnownHosts, at: t))
        let first = try XCTUnwrap(try r5dAlerts(core).first)
        XCTAssertEqual(first.kind, .firstAccess)
        XCTAssertEqual(first.ancestryKnown, true)

        // While the answer rule is saved (after apply read the alert, before it stores its status), zoom
        // opens the key of the same category for writing.
        let injected = R5DaemonFlag()
        core.onPolicyChanged = { [weak core] in
            guard let core, !injected.value else { return }
            injected.value = true
            core.pipeline.receive(.file(r5dOpen(zoom, r5dVaultKey, .write, at: t.addingTimeInterval(60))), context: .monitorOnly)
        }
        try core.apply(action: .alwaysAllow, toAlert: first.id, peer: .inProcess)
        core.onPolicyChanged = nil
        XCTAssertTrue(injected.value)

        var stored = try XCTUnwrap(try core.store.alert(id: first.id))
        core.writer.flush()
        stored = try XCTUnwrap(try core.store.alert(id: first.id))
        XCTAssertEqual(stored.kind, .criticalNonOwner, r5dDescribe([stored]))
        XCTAssertEqual(stored.status, .unread, "the escalation was not seen: it stays unread")
        XCTAssertNil(stored.resolution)
        XCTAssertEqual(stored.firstPath, r5dVaultKey)
        XCTAssertEqual(stored.accesses, .readWrite)
        // The next merge keeps it so (the in-memory copy was not marked resolved either).
        r5dReceive(core, r5dOpen(zoom, r5dVaultKey, .write, at: t.addingTimeInterval(120)))
        XCTAssertEqual(try core.store.alert(id: first.id)?.status, .unread)
        // What the user answered still holds: the read is allowed.
        XCTAssertTrue(core.rules.rules.contains { $0.template == DaemonCore.askAnswerTemplate && $0.access == .read })
    }

    /// An alert whose coalescing window closed changes on its stored copy.
    func testAnAlertWhoseWindowClosedChangesOnItsStoredCopy() throws {
        let dir = TempDir()
        let core = try r5dCore(dir)
        let zoom = r5dZoom(core)
        let t = Date()
        r5dReceive(core, r5dOpen(zoom, r5dVaultKnownHosts, at: t))
        r5dReceive(core, r5dOpen(zoom, r5dVaultNote, .write, at: t.addingTimeInterval(1200)))
        let alerts = try r5dAlerts(core)
        XCTAssertEqual(alerts.count, 2, r5dDescribe(alerts))
        core.coalescer.expire(now: t.addingTimeInterval(86400))
        XCTAssertEqual(core.coalescer.openCount, 0)
        try core.markRead([alerts[1].id])
        XCTAssertEqual(try core.store.alert(id: alerts[1].id)?.status, .read)
        try core.apply(action: .ignore, toAlert: alerts[0].id, peer: .inProcess)
        XCTAssertEqual(try core.store.alert(id: alerts[0].id)?.status, .resolved)
        XCTAssertEqual(try core.store.alert(id: alerts[0].id)?.resolution, .ignore)
    }

    /// Without an escalation, the action takes as before, also on the in-memory copy.
    func testAnActionWithoutAnEscalationResolvesTheAlert() throws {
        let dir = TempDir()
        let core = try r5dCore(dir)
        let zoom = r5dZoom(core)
        let t = Date()
        r5dReceive(core, r5dOpen(zoom, r5dVaultKnownHosts, at: t))
        let first = try XCTUnwrap(try r5dAlerts(core).first)
        try core.apply(action: .ignore, toAlert: first.id, peer: .inProcess)
        XCTAssertEqual(try core.store.alert(id: first.id)?.status, .resolved)
        // A repeat merges into it and keeps it resolved.
        r5dReceive(core, r5dOpen(zoom, r5dVaultKnownHosts, at: t.addingTimeInterval(30)))
        let after = try XCTUnwrap(try core.store.alert(id: first.id))
        XCTAssertEqual(after.status, .resolved)
        XCTAssertEqual(after.resolution, .ignore)
        XCTAssertEqual(after.count, 2)
        // Marked read: an unread one only.
        r5dReceive(core, r5dOpen(zoom, r5dVaultNote, .write, at: t.addingTimeInterval(1200)))
        let second = try XCTUnwrap(try r5dAlerts(core).last)
        XCTAssertEqual(second.status, .unread)
        try core.markRead(nil)
        XCTAssertEqual(try core.store.alert(id: second.id)?.status, .read)
        XCTAssertEqual(try core.store.alert(id: first.id)?.status, .resolved)
        r5dReceive(core, r5dOpen(zoom, r5dVaultNote, .write, at: t.addingTimeInterval(1230)))
        XCTAssertEqual(try core.store.alert(id: second.id)?.status, .read, "the in-memory copy was marked read too")
    }
}
