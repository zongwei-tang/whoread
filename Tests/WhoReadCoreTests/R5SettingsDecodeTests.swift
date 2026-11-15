import XCTest
@testable import WhoReadCore

/// daemon-5: stored settings are read field by field, so one value this build cannot read keeps the
/// others. A client's settings (IPC) are still decoded strictly: a value the daemon does not know is
/// refused, never replaced by a default and saved.
final class R5SettingsDecodeTests: XCTestCase {
    private func blob(_ change: (inout [String: Any]) -> Void) throws -> Data {
        var s = Settings(enforcementEnabled: true, retentionDays: 90, detailDays: 14, projectRoots: ["/Users/alice/src"],
                         notifications: NotificationSettings(enabled: false, minimumSeverity: .high))
        s.language = .zhHans
        var object = try XCTUnwrap(try JSONSerialization.jsonObject(with: JSONEncoder().encode(s)) as? [String: Any])
        change(&object)
        return try JSONSerialization.data(withJSONObject: object)
    }

    func testTheStoreReadsEachSettingOnItsOwn() throws {
        let store = InMemoryEventStore()
        try store.setValue(try blob { $0["language"] = "ja" }, forKey: "settings")
        let s = try store.settings()
        XCTAssertNil(s.language)
        XCTAssertTrue(s.enforcementEnabled)
        XCTAssertEqual(s.retentionDays, 90)
        XCTAssertEqual(s.detailDays, 14)
        XCTAssertEqual(s.projectRoots, ["/Users/alice/src"])
        XCTAssertEqual(s.notifications, NotificationSettings(enabled: false, minimumSeverity: .high))
    }

    func testANestedValueIsReadOnItsOwnToo() throws {
        let store = InMemoryEventStore()
        try store.setValue(try blob { object in
            var n = object["notifications"] as? [String: Any] ?? [:]
            n["minimumSeverity"] = "catastrophic"
            object["notifications"] = n
        }, forKey: "settings")
        let s = try store.settings()
        XCTAssertEqual(s.notifications, NotificationSettings(enabled: false, minimumSeverity: NotificationSettings().minimumSeverity))
        XCTAssertEqual(s.language, .zhHans)
        XCTAssertEqual(s.retentionDays, 90)
    }

    func testAClientsSettingsAreStillDecodedStrictly() throws {
        XCTAssertThrowsError(try JSONDecoder().decode(Settings.self, from: try blob { $0["language"] = "ja" }))
        XCTAssertThrowsError(try JSONDecoder().decode(Settings.self, from: try blob { $0["retentionDays"] = "90 days" }))
        XCTAssertEqual(try JSONDecoder().decode(Settings.self, from: try blob { _ in }).retentionDays, 90)
    }
}
