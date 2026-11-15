import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

// Review round 5 of the native source's lifecycle. The ES calls themselves only run in the VM; the
// helpers the source hands these decisions to are tested here.

// MARK: - native-4: the ES result cache after a wall-clock change

final class NativeCacheClearThrottleTests: XCTestCase {
    func testItIsTimedOnTheUptimeClock() {
        // On the wall clock, setting the time back by N seconds held up every es_clear_cache for up to N
        // seconds: rule, catalog and enforcement changes left the kernel's cached allows in place.
        let throttle = NativeCacheClearThrottle()
        XCTAssertEqual(throttle.now(), ProcessInfo.processInfo.systemUptime, accuracy: 1,
                       "es_clear_cache must be throttled on the uptime clock, which a wall-clock change does not move")
    }

    func testOneClearPerIntervalAndTheRetryIsAlwaysDue() {
        var clock: TimeInterval = 1_000
        var throttle = NativeCacheClearThrottle(now: { clock })
        XCTAssertTrue(throttle.begin(), "the first clear is never held back")
        XCTAssertFalse(throttle.begin(), "a burst is coalesced")
        clock += NativeCacheClearThrottle.interval
        XCTAssertFalse(throttle.begin(), "not before a full second has passed")
        clock += 0.1
        XCTAssertTrue(throttle.begin())
        // A clear held back here comes back `retryDelay` later, longer than the interval: due by then.
        XCTAssertGreaterThan(NativeCacheClearThrottle.retryDelay, NativeCacheClearThrottle.interval)
        clock += 0.5
        XCTAssertFalse(throttle.begin())
        clock += NativeCacheClearThrottle.retryDelay
        XCTAssertTrue(throttle.begin())
    }
}
