import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

// Review round 5 of the native source's lifecycle. The ES calls themselves only run in the VM; the
// helpers the source hands these decisions to are tested here.

private func exists(_ path: String) -> Bool {
    var st = stat()
    return lstat(path, &st) == 0
}


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

// MARK: - native-5: the auth-armed marker at a stop

final class NativeAuthArmedMarkerTests: XCTestCase {
    func testTheMarkerExistsWhileArmed() {
        let dir = TempDir()
        let path = dir.path("auth-armed")
        let marker = NativeAuthArmedMarker(path: path)
        XCTAssertFalse(exists(path))
        marker.arm()
        XCTAssertTrue(exists(path))
        marker.disarm()
        XCTAssertFalse(exists(path))
        marker.arm()
        XCTAssertTrue(exists(path), "armed again (enforcement off, then on)")
        marker.stop()
        XCTAssertFalse(exists(path))
        // In-memory store: no marker at all.
        NativeAuthArmedMarker(path: nil).arm()
        NativeAuthArmedMarker(path: nil).stop()
    }

    func testACleanStopIsNotReportedAsUncleanWhenASubscriptionQueuedBeforeItArmsAgain() throws {
        let dir = TempDir()
        var config = baseConfig(dir)
        config.resolveOwners = false
        let first = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        let marker = NativeAuthArmedMarker(path: config.authArmedMarkerPath)
        marker.arm() // enforcing
        XCTAssertTrue(exists(config.authArmedMarkerPath))
        // A block queued on the client thread before the stop's own block: enforcementChanged(active: true)
        // or a connect still retrying, either of which subscribes the AUTH events (setAuth(true)) and arms.
        let thread = ClientThread()
        thread.start()
        let go = DispatchSemaphore(value: 0)
        thread.run {
            go.wait()
            marker.arm()
        }
        // NativeESSource.stop(): this first, on the stopping thread; then its block on the client thread.
        marker.stop()
        go.signal()
        thread.runAndWait(timeout: 10) {}
        first.noteCleanStop() // Daemon.stop()
        XCTAssertFalse(exists(config.authArmedMarkerPath), "a stopped source leaves no marker")
        let next = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        XCTAssertNil(next.status().uncleanStop, "a clean stop must not be reported as one that stopped unexpectedly")
    }

    func testNothingArmedDuringOrAfterAStopLeavesTheMarker() {
        // The stop's flag is checked under the lock the write is made under: an arm racing the stop never
        // leaves the marker behind.
        let dir = TempDir()
        let path = dir.path("auth-armed")
        for _ in 0..<20 {
            let marker = NativeAuthArmedMarker(path: path)
            marker.arm()
            let started = DispatchSemaphore(value: 0)
            let done = DispatchSemaphore(value: 0)
            Thread.detachNewThread {
                started.signal()
                for _ in 0..<10 { marker.arm() }
                done.signal()
            }
            started.wait()
            marker.stop()
            done.wait()
            XCTAssertFalse(exists(path))
            marker.arm()
            XCTAssertFalse(exists(path), "stopped for good")
        }
    }
}
