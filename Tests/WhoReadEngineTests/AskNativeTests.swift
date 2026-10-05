import Foundation
import XCTest
@testable import WhoReadEngine

// Ask mode, native source half: how long an AUTH message may be held (NativeAskBudget) and the
// exactly-once answer of held messages (NativeHeldMessages). The ES glue around them only compiles on a
// Mac (scripts/dev/es-typecheck checks its types).

final class AskNativeBudgetTests: XCTestCase {
    /// Nanosecond ticks (Intel Macs report a 1/1 timebase).
    private func budget(_ seconds: Double, now: UInt64 = 1_000_000_000) -> NativeAskBudget {
        NativeAskBudget(deadline: now + UInt64(seconds * 1_000_000_000), now: now, numer: 1, denom: 1)
    }

    func testHeadroomIsTwentyPercentOfWhatRemains() {
        let b = budget(10)
        XCTAssertEqual(b.headroom, 2, accuracy: 1e-9)
        XCTAssertEqual(b.budget, 8, accuracy: 1e-9)
    }

    func testHeadroomIsAtLeastOneSecond() {
        let b = budget(3)
        XCTAssertEqual(b.headroom, 1, accuracy: 1e-9)
        XCTAssertEqual(b.budget, 2, accuracy: 1e-9)
    }

    func testHeadroomIsAtMostFiveSeconds() {
        let b = budget(60)
        XCTAssertEqual(b.headroom, 5, accuracy: 1e-9)
        XCTAssertEqual(b.budget, 55, accuracy: 1e-9)
    }

    func testTooLittleTimeLeavesNoBudget() {
        // Under the 1 s minimum headroom: nothing to hold for (the broker then denies at once).
        XCTAssertEqual(budget(0.8).budget, 0)
        XCTAssertEqual(budget(1).budget, 0)
        // Deadline already reached or passed.
        XCTAssertEqual(NativeAskBudget(deadline: 5, now: 5, numer: 1, denom: 1).budget, 0)
        XCTAssertEqual(NativeAskBudget(deadline: 5, now: 9, numer: 1, denom: 1).budget, 0)
        // A zero denominator (never returned by mach_timebase_info) does not divide by zero.
        XCTAssertEqual(NativeAskBudget(deadline: 10_000_000_000, now: 0, numer: 1, denom: 0).budget, 0)
    }

    func testTimebaseConvertsTicksToSeconds() {
        // Apple silicon: 24 MHz ticks, timebase 125/3. 10 s = 240,000,000 ticks.
        let b = NativeAskBudget(deadline: 1_240_000_000, now: 1_000_000_000, numer: 125, denom: 3)
        XCTAssertEqual(b.headroom, 2, accuracy: 1e-9)
        XCTAssertEqual(b.budget, 8, accuracy: 1e-9)
        // Large tick counts do not overflow.
        let far = NativeAskBudget(deadline: .max, now: 0, numer: 125, denom: 3)
        XCTAssertEqual(far.headroom, 5)
        XCTAssertGreaterThan(far.budget, 0)
    }

    func testBackstopFallsInsideTheHeadroom() {
        for seconds in [1.6, 3, 10, 30, 60, 120] {
            let b = budget(seconds)
            XCTAssertGreaterThan(b.backstop, b.budget, "after the broker's own timeout (\(seconds) s)")
            XCTAssertLessThan(b.backstop, seconds, "before the kernel deadline (\(seconds) s)")
            XCTAssertGreaterThanOrEqual(b.backstop - b.budget, 0.5 - 1e-9, "at least half a second after (\(seconds) s)")
            XCTAssertGreaterThanOrEqual(seconds - b.backstop, 0.5 - 1e-9, "at least half a second before (\(seconds) s)")
        }
    }
}

extension AskNativeBudgetTests {
    func testBackstopIsBeforeTheDeadlineWheneverThereIsABudget() {
        // The source holds only with a budget (hold() denies at once otherwise).
        for ms in stride(from: UInt64(0), through: 130_000, by: 50) {
            let seconds = Double(ms) / 1000
            let b = NativeAskBudget(deadline: 1_000_000_000 + ms * 1_000_000, now: 1_000_000_000, numer: 1, denom: 1)
            if b.budget > 0 {
                XCTAssertGreaterThan(b.backstop, b.budget, "\(seconds) s")
                XCTAssertLessThan(b.backstop, seconds, "\(seconds) s")
            } else {
                XCTAssertLessThanOrEqual(ms, 1000, "a budget once more than the minimum headroom remains (\(seconds) s)")
            }
        }
    }
}

// The exactly-once bookkeeping of held AUTH messages (NativeHeldMessages). The source's closures call
// es_respond_* and es_release_message; here they only count.
final class AskNativeHeldMessagesTests: XCTestCase {
    /// What each message got: its answers and its releases (an answer releases too, as in the source).
    private final class Record: @unchecked Sendable {
        private let lock = NSLock()
        private var answers: [Int: [Bool]] = [:]
        private var releases: [Int: Int] = [:]

        func answered(_ i: Int, _ allow: Bool) {
            lock.lock()
            answers[i, default: []].append(allow)
            releases[i, default: 0] += 1
            lock.unlock()
        }

        func released(_ i: Int) {
            lock.lock()
            releases[i, default: 0] += 1
            lock.unlock()
        }

        func answers(_ i: Int) -> [Bool] {
            lock.lock(); defer { lock.unlock() }
            return answers[i] ?? []
        }

        func releases(_ i: Int) -> Int {
            lock.lock(); defer { lock.unlock() }
            return releases[i] ?? 0
        }
    }

    private func add(_ set: NativeHeldMessages, _ log: Record, _ i: Int) -> NativeHeldMessages.Held {
        set.add(answer: { log.answered(i, $0) }, release: { log.released(i) })
    }

    func testFinishAnswersAndReleasesOnce() {
        let set = NativeHeldMessages()
        let log = Record()
        let h = add(set, log, 0)
        XCTAssertEqual(set.count, 1)
        XCTAssertTrue(set.finish(h, allow: true))
        // The broker's late timeout, the backstop, a second answer: all no-ops.
        XCTAssertFalse(set.finish(h, allow: false))
        XCTAssertFalse(set.finish(h, allow: true))
        XCTAssertFalse(set.abandon(h))
        XCTAssertEqual(set.denyAll(), 0)
        XCTAssertEqual(log.answers(0), [true])
        XCTAssertEqual(log.releases(0), 1)
        XCTAssertEqual(set.count, 0)
    }

    func testAbandonReleasesWithoutAnswering() {
        // The broker did not hold it: released here, answered by the handler in scope.
        let set = NativeHeldMessages()
        let log = Record()
        let h = add(set, log, 0)
        XCTAssertTrue(set.abandon(h))
        XCTAssertFalse(set.finish(h, allow: true), "a respond against the contract after denyNow")
        XCTAssertFalse(set.abandon(h))
        XCTAssertEqual(log.answers(0), [])
        XCTAssertEqual(log.releases(0), 1)
        XCTAssertEqual(set.count, 0)
    }

    func testAbandonAfterAnAnswerReportsIt() {
        // The broker answered (against the contract) before reporting denyNow: the handler must not
        // answer again, which abandon's false tells it.
        let set = NativeHeldMessages()
        let log = Record()
        let h = add(set, log, 0)
        XCTAssertTrue(set.finish(h, allow: false))
        XCTAssertFalse(set.abandon(h))
        XCTAssertEqual(log.answers(0), [false])
        XCTAssertEqual(log.releases(0), 1)
    }

    func testDenyAllDeniesOnlyWhatIsStillHeld() {
        // Stop: what the broker's denyAll missed is denied before the ES client is deleted.
        let set = NativeHeldMessages()
        let log = Record()
        let held = (0..<4).map { add(set, log, $0) }
        XCTAssertTrue(set.finish(held[0], allow: true))
        XCTAssertTrue(set.abandon(held[1]))
        XCTAssertEqual(set.denyAll(), 2)
        XCTAssertEqual(set.count, 0)
        XCTAssertEqual(set.denyAll(), 0)
        // The broker answering afterwards changes nothing.
        XCTAssertFalse(set.finish(held[2], allow: true))
        XCTAssertEqual(log.answers(0), [true])
        XCTAssertEqual(log.answers(1), [])
        XCTAssertEqual(log.answers(2), [false])
        XCTAssertEqual(log.answers(3), [false])
        for i in 0..<4 { XCTAssertEqual(log.releases(i), 1, "message \(i)") }
    }

    func testRacingAnswersAnswerEveryMessageExactlyOnce() {
        // The broker's answer, the backstop and the source's denyAll race for each message.
        let set = NativeHeldMessages()
        let log = Record()
        let n = 500
        let held = (0..<n).map { add(set, log, $0) }
        DispatchQueue.concurrentPerform(iterations: 3 * n + 1) { k in
            if k == 3 * n {
                set.denyAll()
            } else if k % 3 == 2 {
                _ = set.abandon(held[k / 3])
            } else {
                set.finish(held[k / 3], allow: k % 3 == 0)
            }
        }
        XCTAssertEqual(set.count, 0)
        for i in 0..<n {
            XCTAssertEqual(log.releases(i), 1, "message \(i)")
            XCTAssertLessThanOrEqual(log.answers(i).count, 1, "message \(i)")
        }
    }
}
