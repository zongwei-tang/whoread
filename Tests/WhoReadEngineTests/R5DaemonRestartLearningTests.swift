import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// daemon-7: `restart-learning` without a learning period (the default) forgets what was seen, so the
/// next accesses alert as first accesses: also those already read from the source but not yet analysed,
/// which carry an earlier time stamp.
final class R5DaemonRestartLearningTests: XCTestCase {
    func testTheBacklogOfARestartAlertsAsFirstAccesses() throws {
        let dir = TempDir()
        let core = try r5dCore(dir)
        XCTAssertEqual(core.currentSettings.learningDays, 0)
        let zoom = r5dZoom(core)
        try core.restartLearning(peer: .inProcess)
        let restartedAt = core.baseline.learningStartedAt
        r5dReceive(core, r5dOpen(zoom, r5dVaultKnownHosts, at: restartedAt.addingTimeInterval(-1)))
        let alerts = try r5dAlerts(core)
        XCTAssertEqual(alerts.map(\.kind), [.firstAccess], r5dDescribe(alerts))
        XCTAssertEqual(alerts.first?.ancestryKnown, true)
        let key = BaselineKey(responsibleKey: r5dZoomKey, categoryID: "test-vault", access: .read)
        XCTAssertEqual(core.baseline.entry(key)?.source, .observed, "seen, not learned for good")
    }
}
