import Foundation
import XCTest
@testable import WhoReadEngine

// Review of the native source: es_delete_client exclusivity also covers the process client,
// whose handler calls es_exec_arg_count and es_exec_arg on every exec; stop() waits long enough for
// the bounded waits before es_delete_client; and with fail-closed (macOS 27) a stuck file handler is
// no longer killed by the kernel, so a watchdog exits for launchd to restart the daemon. The ES calls
// themselves only run in the VM; the handler wrappers the clients are created with are tested here.

/// A clock the test moves by hand (uptime nanoseconds), readable from the watchdog's timer queue.
private final class ManualClock: @unchecked Sendable {
    private let lock = NSLock()
    private var ns: UInt64 = 1_000_000_000

    func now() -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        return ns
    }

    func advance(_ seconds: TimeInterval) {
        lock.lock()
        ns += UInt64(seconds * 1e9)
        lock.unlock()
    }
}

final class NativeHandlerWatchdogReviewTests: XCTestCase {
    func testIdleTimeNeverCounts() {
        // A Mac with no file activity for hours: no call is inside, nothing is stuck.
        let clock = ManualClock()
        let w = NativeHandlerWatchdog(now: clock.now)
        clock.advance(10_000)
        XCTAssertNil(w.stalled())
        w.enter()
        w.leave()
        clock.advance(10_000)
        XCTAssertNil(w.stalled(), "time after a call returned is idle time")
    }

    func testShortCallsNeverCount() {
        // A busy handler makes progress: many calls, none of them long.
        let clock = ManualClock()
        let w = NativeHandlerWatchdog(now: clock.now)
        for _ in 0..<1_000 {
            w.enter(deadlineSpan: 30_000_000_000)
            clock.advance(0.5)
            XCTAssertNil(w.stalled())
            w.leave()
            clock.advance(0.5)
        }
        XCTAssertNil(w.stalled())
    }

    func testOneLongCallIsAStallOnce() {
        let clock = ManualClock()
        let w = NativeHandlerWatchdog(now: clock.now)
        XCTAssertEqual(w.limit, NativeHandlerWatchdog.minimumStall)
        XCTAssertGreaterThanOrEqual(NativeHandlerWatchdog.minimumStall, 60, "far longer than any deadline")
        w.enter()
        clock.advance(NativeHandlerWatchdog.minimumStall - 1)
        XCTAssertNil(w.stalled())
        clock.advance(2)
        let stall = w.stalled()
        XCTAssertNotNil(stall)
        XCTAssertEqual(stall ?? 0, NativeHandlerWatchdog.minimumStall + 1, accuracy: 0.001)
        clock.advance(100)
        XCTAssertNil(w.stalled(), "reported once")
    }

    func testReturningStartsOver() {
        let clock = ManualClock()
        let w = NativeHandlerWatchdog(now: clock.now)
        w.enter()
        clock.advance(NativeHandlerWatchdog.minimumStall * 0.9)
        w.leave()
        w.enter()
        clock.advance(NativeHandlerWatchdog.minimumStall * 0.9)
        XCTAssertNil(w.stalled(), "two calls, each shorter than the limit")
        clock.advance(NativeHandlerWatchdog.minimumStall * 0.2)
        XCTAssertNotNil(w.stalled(), "the second call alone is past it")
    }

    func testTheLimitStaysFarAboveTheLongestDeadline() {
        // Deadline lengths are per message and undocumented: a stall is several times the longest one.
        let clock = ManualClock()
        let w = NativeHandlerWatchdog(now: clock.now)
        w.enter(deadlineSpan: 100_000_000_000) // 100 s
        w.leave()
        XCTAssertEqual(w.limit, 100 * NativeHandlerWatchdog.deadlineFactor, accuracy: 0.001)
        w.enter()
        clock.advance(100 * NativeHandlerWatchdog.deadlineFactor - 1)
        XCTAssertNil(w.stalled())
        clock.advance(2)
        XCTAssertNotNil(w.stalled())
        // Shorter deadlines never lower it.
        let v = NativeHandlerWatchdog(now: clock.now)
        v.enter(deadlineSpan: 5_000_000_000)
        XCTAssertEqual(v.limit, NativeHandlerWatchdog.minimumStall)
        // An absurd deadline (a garbled field) cannot switch it off.
        let u = NativeHandlerWatchdog(now: clock.now)
        u.enter(deadlineSpan: .max)
        XCTAssertEqual(u.limit, NativeHandlerWatchdog.maximumStall)
        clock.advance(NativeHandlerWatchdog.maximumStall + 1)
        XCTAssertNotNil(u.stalled())
    }

    func testCancelledNeverReports() {
        // stop() and a failed setup cancel it: a slow stop is no stall.
        let clock = ManualClock()
        let w = NativeHandlerWatchdog(now: clock.now)
        w.enter()
        w.cancel()
        clock.advance(NativeHandlerWatchdog.minimumStall * 10)
        XCTAssertNil(w.stalled())
    }

    func testTheTimerReportsAStallOnceAndStopsWhenCancelled() {
        let clock = ManualClock()
        let w = NativeHandlerWatchdog(now: clock.now)
        let queue = DispatchQueue(label: "test.watchdog")
        let stalled = expectation(description: "stall reported")
        // Fulfilled twice → the test fails (assertForOverFulfill).
        w.start(every: 0.01, queue: queue) { _ in stalled.fulfill() }
        w.enter()
        clock.advance(NativeHandlerWatchdog.minimumStall + 1)
        wait(for: [stalled], timeout: 5)
        queue.sync {}
        Thread.sleep(forTimeInterval: 0.1) // more ticks: none may report again
        w.cancel()
        queue.sync {}

        // Cancelled before the stall: never reported.
        let v = NativeHandlerWatchdog(now: clock.now)
        let never = expectation(description: "no stall after cancel")
        never.isInverted = true
        v.start(every: 0.01, queue: queue) { _ in never.fulfill() }
        v.enter()
        v.cancel()
        clock.advance(NativeHandlerWatchdog.minimumStall * 10)
        wait(for: [never], timeout: 0.2)
        // And starting a cancelled one does nothing (no timer; one never resumed would trap on release).
        let notStarted = expectation(description: "a cancelled watchdog does not start")
        notStarted.isInverted = true
        v.start(every: 0.01, queue: queue) { _ in notStarted.fulfill() }
        wait(for: [notStarted], timeout: 0.1)
    }
}

final class UncleanStopReviewTests: XCTestCase {
    func testTheUncleanStopNoteNamesTheWatchdog() throws {
        // The watchdog exits with the auth-armed marker left behind: the next start must not blame only
        // a missed deadline, which in fail-closed mode no longer kills the daemon.
        let dir = TempDir()
        var config = baseConfig(dir)
        config.resolveOwners = false
        try FileManager.default.createDirectory(atPath: config.dataDirectory, withIntermediateDirectories: true)
        XCTAssertTrue(touch(config.authArmedMarkerPath))
        let core = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        let note = try XCTUnwrap(core.status().uncleanStop)
        XCTAssertTrue(note.contains("watchdog"), note)
        XCTAssertTrue(note.contains("missed AUTH deadline"), note)
        XCTAssertFalse(FileManager.default.fileExists(atPath: config.authArmedMarkerPath))
    }
}

#if canImport(EndpointSecurity)
import EndpointSecurity

/// es_message_t in zeroed memory, with what the handler wrappers read.
private final class ZeroedMessage {
    let pointer: UnsafeMutablePointer<es_message_t>
    private let raw: UnsafeMutableRawPointer

    init(auth: Bool, machTime: UInt64 = 0, deadline: UInt64 = 0) {
        let size = MemoryLayout<es_message_t>.stride
        raw = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: max(MemoryLayout<es_message_t>.alignment, 16))
        raw.initializeMemory(as: UInt8.self, repeating: 0, count: size)
        pointer = raw.bindMemory(to: es_message_t.self, capacity: 1)
        pointer.pointee.action_type = auth ? ES_ACTION_TYPE_AUTH : ES_ACTION_TYPE_NOTIFY
        pointer.pointee.mach_time = machTime
        pointer.pointee.deadline = deadline
    }

    deinit { raw.deallocate() }
}

private func ticks(seconds: Double) -> UInt64 {
    var tb = mach_timebase_info_data_t()
    _ = mach_timebase_info(&tb)
    return UInt64(seconds * 1e9 * Double(tb.denom) / Double(tb.numer))
}

final class NativeWatchedHandlerReviewTests: XCTestCase {
    func testDeadlineSpanOfAuthAndNotifyMessages() {
        let start: UInt64 = 1_000_000
        let auth = ZeroedMessage(auth: true, machTime: start, deadline: start + ticks(seconds: 60))
        XCTAssertEqual(Double(NativeESSource.deadlineSpan(UnsafePointer(auth.pointer))) / 1e9, 60, accuracy: 0.01)
        let notify = ZeroedMessage(auth: false, machTime: start, deadline: start + ticks(seconds: 60))
        XCTAssertEqual(NativeESSource.deadlineSpan(UnsafePointer(notify.pointer)), 0)
        let past = ZeroedMessage(auth: true, machTime: start, deadline: start - 1)
        XCTAssertEqual(NativeESSource.deadlineSpan(UnsafePointer(past.pointer)), 0)
        // No creation time: the deadline alone (ticks since boot) is no span.
        let unknown = ZeroedMessage(auth: true, machTime: 0, deadline: start)
        XCTAssertEqual(NativeESSource.deadlineSpan(UnsafePointer(unknown.pointer)), 0)
    }

    func testTheFileHandlerIsWatchedForTheWholeCall() {
        // The file client is created with this wrapper: a call that never returns is seen as inside,
        // whatever the message, and the AUTH deadline it carries raises the limit.
        let clock = ManualClock()
        let w = NativeHandlerWatchdog(now: clock.now)
        let client = OpaquePointer(bitPattern: 0x10)!
        let auth = ZeroedMessage(auth: true, machTime: 1, deadline: 1 + ticks(seconds: 50))
        var insideStall: TimeInterval?
        let handler = NativeESSource.watched(w) { c, m in
            XCTAssertEqual(c, client)
            XCTAssertEqual(m, UnsafePointer(auth.pointer))
            clock.advance(NativeHandlerWatchdog.minimumStall + 1)
            XCTAssertNil(w.stalled(), "a 50 s deadline makes the limit 200 s")
            clock.advance(100)
            insideStall = w.stalled()
        }
        handler(client, UnsafePointer(auth.pointer))
        XCTAssertNotNil(insideStall, "seen inside the call")
        XCTAssertEqual(w.limit, 50 * NativeHandlerWatchdog.deadlineFactor, accuracy: 0.1)

        let v = NativeHandlerWatchdog(now: clock.now)
        let notify = ZeroedMessage(auth: false)
        let quick = NativeESSource.watched(v) { _, _ in clock.advance(1) }
        for _ in 0..<500 { quick(client, UnsafePointer(notify.pointer)) }
        XCTAssertNil(v.stalled(), "every call returned")
    }

    func testStopWaitsLongerThanItsBoundedWaits() {
        // closeAsks (held answers) and both gated deletes must fit, or the process exits before the
        // clients are deleted by us.
        XCTAssertGreaterThan(NativeESSource.stopWait, NativeESSource.stopWaitCovers)
        XCTAssertEqual(NativeESSource.stopWaitCovers, NativeHeldMessages.denyAllWait + 2 * NativeESSource.deleteWait)
    }
}

final class NativeGatedHandlerReviewTests: XCTestCase {
    func testAGatedHandlerKeepsDeleteWaitingAndRunsNothingAfterIt() {
        let gate = NativeClientGate()
        let message = UnsafeMutablePointer<es_message_t>.allocate(capacity: 1)
        defer { message.deallocate() }
        let client = OpaquePointer(bitPattern: 0x10)!
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var calls = 0
        let handler = NativeESSource.gated(gate) { c, m in
            XCTAssertEqual(c, client)
            XCTAssertEqual(m, UnsafePointer(message))
            lock.lock()
            calls += 1
            let first = calls == 1
            lock.unlock()
            if first {
                // An exec being converted (es_exec_arg) when the client is deleted.
                entered.signal()
                release.wait()
            }
        }
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            handler(client, UnsafePointer(message))
            done.signal()
        }
        entered.wait()
        XCTAssertFalse(gate.close(waitAtMost: 0.05), "a handler still inside: es_delete_client must wait")
        release.signal()
        XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
        XCTAssertTrue(gate.close(waitAtMost: 5))
        handler(client, UnsafePointer(message))
        lock.lock()
        XCTAssertEqual(calls, 1, "nothing runs once the client is being deleted")
        lock.unlock()
    }
}
#endif
