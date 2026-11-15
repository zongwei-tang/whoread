import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// daemon-5: stored settings with a value this build cannot read (a newer build's language or
/// severity, a field whose type changed, after going back to an older checkout) keep every other
/// setting; the blob is backed up, retention does not run on a period it could not read, and a
/// later save keeps the values it could not read.
final class R5SettingsLoadTests: XCTestCase {
    /// Changes the stored settings blob of the core's store.
    private func patchStoredSettings(_ core: DaemonCore, _ change: (inout [String: Any]) -> Void) throws {
        let data = try XCTUnwrap(try core.store.value(forKey: "settings"))
        var object = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        change(&object)
        try core.store.setValue(try JSONSerialization.data(withJSONObject: object), forKey: "settings")
    }

    private func storedObject(_ core: DaemonCore) throws -> [String: Any] {
        let data = try XCTUnwrap(try core.store.value(forKey: "settings"))
        return try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    /// Settings saved by a build, then one value made unreadable for this one. Returns the stored blob.
    @discardableResult
    private func storeSettings(_ dir: TempDir, _ change: (inout [String: Any]) -> Void) throws -> Data? {
        let core = try r5Core(dir)
        try core.mutateSettings(peer: .inProcess) { s in
            s.projectRoots = ["/Users/alice/src"]
            s.retentionDays = 90
            s.detailDays = 14
            s.notifications.minimumSeverity = .high
        }
        try core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
        try patchStoredSettings(core, change)
        return try core.store.value(forKey: "settings")
    }

    func testOneUnreadableValueKeepsTheOtherSettings() throws {
        let dir = TempDir()
        let before = try storeSettings(dir) { $0["language"] = "ja" }
        let core = try r5Core(dir)
        let s = core.currentSettings
        XCTAssertEqual(s.projectRoots, ["/Users/alice/src"], "project secrets stay monitored")
        XCTAssertEqual(s.retentionDays, 90)
        XCTAssertEqual(s.detailDays, 14)
        XCTAssertTrue(s.enforcementEnabled, "enforcement stays as the user set it")
        XCTAssertEqual(s.notifications.minimumSeverity, .high)
        XCTAssertNil(s.language, "the value this build cannot read takes its default")
        XCTAssertTrue(core.enforcement.userEnabledSetting)
        XCTAssertEqual(try core.store.value(forKey: "settings_backup"), before, "the blob as it was stored")
    }

    func testANestedUnreadableValueKeepsItsNeighbours() throws {
        let dir = TempDir()
        try storeSettings(dir) { object in
            var n = object["notifications"] as? [String: Any] ?? [:]
            n["minimumSeverity"] = "catastrophic"
            n["enabled"] = false
            object["notifications"] = n
        }
        let s = try r5Core(dir).currentSettings
        XCTAssertFalse(s.notifications.enabled)
        XCTAssertEqual(s.notifications.minimumSeverity, NotificationSettings().minimumSeverity)
        XCTAssertEqual(s.retentionDays, 90)
        XCTAssertEqual(s.projectRoots, ["/Users/alice/src"])
    }

    func testRetentionDoesNotRunOnAPeriodItCouldNotRead() throws {
        let dir = TempDir()
        try storeSettings(dir) { $0["retentionDays"] = "90 days" }
        let old = Date().addingTimeInterval(-60 * 86400)
        do {
            let core = try r5Core(dir)
            try core.store.upsert([Alert(id: 1, kind: .firstAccess, createdAt: old, updatedAt: old, windowEndsAt: old.addingTimeInterval(600),
                                         responsible: ResponsibleEntity(kind: .app, key: r5ZoomKey, displayName: "zoom.us"),
                                         categoryID: "test-vault", severity: .medium, count: 1, accesses: .read,
                                         firstPath: r5VaultKnownHosts, firstEventID: 1, lastEventID: 1, paths: [r5VaultKnownHosts],
                                         chain: [], agentID: nil, ruleID: nil)])
        }
        let core = try r5Core(dir)
        core.maintenance()
        XCTAssertNotNil(try core.store.alert(id: 1), "60 days of history are not deleted on a 30-day default")
    }

    func testASaveKeepsTheValuesThisBuildCouldNotRead() throws {
        let dir = TempDir()
        try storeSettings(dir) { $0["language"] = "ja" }
        let core = try r5Core(dir)
        try core.mutateSettings(peer: .inProcess) { $0.enforcementEnabled = false }
        var saved = try storedObject(core)
        XCTAssertEqual(saved["language"] as? String, "ja", "kept for the build that wrote it")
        XCTAssertEqual(saved["enforcementEnabled"] as? Bool, false)
        XCTAssertEqual(saved["projectRoots"] as? [String], ["/Users/alice/src"])
        XCTAssertEqual(saved["retentionDays"] as? Int, 90)
        // Read back by this build as before.
        XCTAssertFalse(try core.store.settings().enforcementEnabled)
        // Set by the user: their value replaces it.
        try core.mutateSettings(peer: .inProcess) { $0.language = .en }
        saved = try storedObject(core)
        XCTAssertEqual(saved["language"] as? String, "en")
        XCTAssertEqual(try r5Core(dir).currentSettings.language, .en)
    }

    func testAnUnreadableBlobIsBackedUp() throws {
        let dir = TempDir()
        do {
            let core = try r5Core(dir)
            try core.store.setValue(Data("not settings".utf8), forKey: "settings")
        }
        let core = try r5Core(dir)
        XCTAssertEqual(core.currentSettings, Settings())
        XCTAssertEqual(try core.store.value(forKey: "settings_backup"), Data("not settings".utf8))
        core.maintenance()
    }
}
