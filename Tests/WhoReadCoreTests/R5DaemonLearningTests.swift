import XCTest
@testable import WhoReadCore

/// daemon-7: without a learning period nothing is learned, whatever the event's time stamp.
final class R5DaemonLearningTests: XCTestCase {
    func testNoLearningPeriodMeansNoLearningEvenBeforeItsStart() {
        let b = Baseline(learningStartedAt: t0, learningDuration: 0)
        XCTAssertFalse(b.isLearning(at: at(-1)), "an event stamped before restart-learning (a pipe backlog)")
        XCTAssertFalse(b.isLearning(at: at(-86400)), "a clock stepped back")
        XCTAssertFalse(b.isLearning(at: t0))
        XCTAssertFalse(b.isLearning(at: at(1)))
    }

    func testALearningPeriodHoldsOnlyFromItsStart() {
        let b = Baseline(learningStartedAt: t0, learningDuration: 3600)
        XCTAssertFalse(b.isLearning(at: at(-1)))
        XCTAssertTrue(b.isLearning(at: t0))
        XCTAssertTrue(b.isLearning(at: at(3599)))
        XCTAssertFalse(b.isLearning(at: at(3600)))
    }

    /// Through the analyzer: a first access stamped before the start of an absent learning period alerts.
    func testABacklogEventStampedBeforeTheRestartAlerts() throws {
        let h = try Harness(learningStart: t0, learningDays: 0)
        let zoom = proc(300, "/Applications/zoom.us.app/Contents/MacOS/zoom.us", ppid: 1, start: -10, signingID: "us.zoom.xos",
                        teamID: "ZOOMTEAM01")
        h.fork(P.launchd, zoom, -10)
        let out = h.open(zoom, "/Users/alice/WhoReadTestVault/ssh/known_hosts", -1)
        XCTAssertEqual(out.events.first?.ancestryKnown, true)
        XCTAssertEqual(out.alerts.map(\.alert.kind), [.firstAccess])
        let key = BaselineKey(responsibleKey: "app:/applications/zoom.us.app", categoryID: "test-vault", access: .read)
        XCTAssertEqual(h.baseline.entry(key)?.source, .observed, "seen, not learned")
    }
}
