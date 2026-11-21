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

// MARK: - native-3: a failed AUTH subscription

final class NativeAuthSubscriptionTests: XCTestCase {
    func testAFailedSubscriptionIsAFailureRetriedWithBackoff() {
        // Enforcement is on and es_subscribe fails: nothing is asked about or blocked.
        var s = NativeAuthSubscription()
        var attempts = 0
        let failing = { () -> Bool in
            attempts += 1
            return false
        }
        let first = s.set(true, current: false, subscribe: failing, unsubscribe: { XCTFail("nothing to unsubscribe") })
        XCTAssertFalse(first.subscribed)
        XCTAssertTrue(s.failed, "enforcement is on but nothing is enforced: a failure the source must show")
        XCTAssertEqual(first.retryIn, NativeAuthSubscription.initialRetryDelay,
                       "retried, not left until enforcement is switched again or the client reconnects")
        // Each failed retry waits twice as long, up to the maximum.
        var waits: [TimeInterval] = []
        for _ in 0..<6 {
            waits.append(s.set(true, current: false, subscribe: failing, unsubscribe: { XCTFail("nothing to unsubscribe") }).retryIn ?? -1)
        }
        XCTAssertEqual(waits, [10, 20, 40, 60, 60, 60])
        XCTAssertEqual(NativeAuthSubscription.maxRetryDelay, 60)
        XCTAssertEqual(attempts, 7)
        // A retry that takes: subscribed, nothing to show, no retry; a later failure backs off from the start.
        let ok = s.set(true, current: false, subscribe: { true }, unsubscribe: { XCTFail("nothing to unsubscribe") })
        XCTAssertTrue(ok.subscribed)
        XCTAssertNil(ok.retryIn)
        XCTAssertFalse(s.failed)
        let again = s.set(true, current: false, subscribe: failing, unsubscribe: { XCTFail("nothing to unsubscribe") })
        XCTAssertEqual(again.retryIn, NativeAuthSubscription.initialRetryDelay)
    }

    func testEnforcementOffEndsTheFailureAndItsRetries() {
        var s = NativeAuthSubscription()
        _ = s.set(true, current: false, subscribe: { false }, unsubscribe: { XCTFail("nothing to unsubscribe") })
        XCTAssertTrue(s.failed)
        // Nothing was subscribed, so nothing is unsubscribed either.
        let off = s.set(false, current: false, subscribe: {
            XCTFail("not wanted")
            return true
        }, unsubscribe: { XCTFail("nothing subscribed") })
        XCTAssertFalse(off.subscribed)
        XCTAssertNil(off.retryIn)
        XCTAssertFalse(s.failed, "nothing is wanted any more")
    }

    func testASubscriptionThatTookIsKeptUntilEnforcementGoesOff() {
        var s = NativeAuthSubscription()
        var unsubscribed = 0
        let on = s.set(true, current: false, subscribe: { true }, unsubscribe: { XCTFail("nothing to unsubscribe") })
        XCTAssertTrue(on.subscribed)
        XCTAssertNil(on.retryIn)
        let still = s.set(true, current: true, subscribe: {
            XCTFail("already subscribed")
            return false
        }, unsubscribe: { XCTFail("still wanted") })
        XCTAssertTrue(still.subscribed)
        XCTAssertNil(still.retryIn)
        let off = s.set(false, current: true, subscribe: {
            XCTFail("not wanted")
            return true
        }, unsubscribe: { unsubscribed += 1 })
        XCTAssertFalse(off.subscribed)
        XCTAssertNil(off.retryIn)
        XCTAssertEqual(unsubscribed, 1)
        XCTAssertFalse(s.failed)
    }
}

final class NativeSetupProblemsTests: XCTestCase {
    func testAFailedAUTHSubscriptionIsTheSourcesError() {
        var state = SourceState(running: true, deadlineMissMode: "fail-closed")
        NativeSetupProblems.apply(to: &state, mutingFailed: false, authFailed: true)
        XCTAssertFalse(state.running, "status must not show it as enforcing")
        XCTAssertEqual(state.error, NativeSetupProblems.authError)
        XCTAssertEqual(state.hint, NativeSetupProblems.authHint)
        XCTAssertEqual(state.deadlineMissMode, "fail-closed", "the file client still exists")
        // Onboarding takes an error or hint that mentions permissions for missing Full Disk Access.
        XCTAssertFalse((NativeSetupProblems.authError + " " + NativeSetupProblems.authHint).lowercased().contains("permitted"))
        NativeSetupProblems.apply(to: &state, mutingFailed: false, authFailed: false)
        XCTAssertEqual(state, SourceState(running: true, deadlineMissMode: "fail-closed"), "a retry that took clears it")
    }

    func testEachProblemClearsOnlyItself() {
        var state = SourceState(running: true)
        // Both: nothing monitored outweighs nothing enforced (it leaves nothing to enforce either).
        NativeSetupProblems.apply(to: &state, mutingFailed: true, authFailed: true)
        XCTAssertEqual(state.error, NativeSetupProblems.mutingError)
        XCTAssertFalse(state.running)
        // The mute set recovers while the AUTH subscription still fails: that one still shows.
        NativeSetupProblems.apply(to: &state, mutingFailed: false, authFailed: true)
        XCTAssertEqual(state.error, NativeSetupProblems.authError, "a muting recovery must not hide that nothing is enforced")
        XCTAssertFalse(state.running)
        // And the other way round.
        NativeSetupProblems.apply(to: &state, mutingFailed: true, authFailed: false)
        XCTAssertEqual(state.error, NativeSetupProblems.mutingError)
        XCTAssertEqual(state.hint, NativeSetupProblems.mutingHint)
        NativeSetupProblems.apply(to: &state, mutingFailed: false, authFailed: false)
        XCTAssertEqual(state, SourceState(running: true))
    }

    func testStatusShowsAnErrorInsteadOfEnforcing() throws {
        let dir = TempDir()
        var config = baseConfig(dir)
        config.resolveOwners = false
        let core = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        try core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
        core.drainPolicyQueue()
        // What the native source publishes once its clients are connected and the AUTH subscription failed.
        var state = SourceState(deadlineMissMode: "fail-closed")
        NativeSetupProblems.apply(to: &state, mutingFailed: false, authFailed: true)
        core.pipeline.sourceStateChanged(state)
        let failed = core.status()
        XCTAssertEqual(failed.mode, .error, "nothing is asked about or blocked: not Enforcing")
        XCTAssertEqual(failed.sourceError, NativeSetupProblems.authError)
        XCTAssertEqual(failed.sourceHint, NativeSetupProblems.authHint)
        XCTAssertTrue(failed.enforcementActive, "the setting stays as the user set it")
        // A retry that takes.
        NativeSetupProblems.apply(to: &state, mutingFailed: false, authFailed: false)
        core.pipeline.sourceStateChanged(state)
        XCTAssertEqual(core.status().mode, .enforcing)
        XCTAssertNil(core.status().sourceError)
    }
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
