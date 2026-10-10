import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

// The native source's accounting of what only the kernel's side shows: an allow answered after the AUTH
// deadline (or not delivered) in fail-closed mode is a denial, AUTH messages dropped from a full queue
// are counted by outcome, and the default mute set is reported (SDK D5). Also: a close of a file mapped
// writable is charged only to a process that opened it for writing (SDK D6), and a rename onto an empty
// directory is not a read of what the directory could hold (files-5).

// MARK: - Late answers

/// Records what `NativeLateAnswer.answer` sends.
private final class Sent {
    var answers: [Bool] = []
    var result: UInt32 = NativeLateAnswer.respondSuccess

    func send(_ allow: Bool) -> UInt32 {
        answers.append(allow)
        return result
    }
}

final class NativeLateAnswerTests: XCTestCase {
    func testFailClosedAllowAtOrAfterTheDeadlineIsSentAsADenyAndReported() {
        for now: UInt64 in [1_000, 1_001, 50_000] {
            let sent = Sent()
            let denied = NativeLateAnswer.answer(allow: true, failClosed: true, deadline: 1_000, now: { now }, send: sent.send)
            XCTAssertTrue(denied, "now \(now): the kernel denied it")
            XCTAssertEqual(sent.answers, [false], "a deny makes the outcome certain whoever is first")
        }
    }

    func testAnAllowInTimeIsSentAndNotReported() {
        let sent = Sent()
        XCTAssertFalse(NativeLateAnswer.answer(allow: true, failClosed: true, deadline: 1_000, now: { 999 }, send: sent.send))
        XCTAssertEqual(sent.answers, [true])
    }

    func testAnUndeliveredAllowIsADenialInFailClosedMode() {
        // ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT 1, ERR_INTERNAL 2, NOT_FOUND 3, ERR_EVENT_TYPE 5: the message
        // waits for its deadline and is denied.
        for result: UInt32 in [1, 2, 3, 5] {
            let sent = Sent()
            sent.result = result
            XCTAssertTrue(NativeLateAnswer.answer(allow: true, failClosed: true, deadline: 1_000, now: { 10 }, send: sent.send), "\(result)")
            XCTAssertEqual(sent.answers, [true])
        }
        // A duplicate: an earlier answer stands, not this one's to judge.
        let duplicate = Sent()
        duplicate.result = NativeLateAnswer.respondDuplicate
        XCTAssertFalse(NativeLateAnswer.answer(allow: true, failClosed: true, deadline: 1_000, now: { 10 }, send: duplicate.send))
    }

    func testDenialsAreNeverReported() {
        let sent = Sent()
        sent.result = 3
        XCTAssertFalse(NativeLateAnswer.answer(allow: false, failClosed: true, deadline: 1_000, now: { 5_000 }, send: sent.send),
                       "a deny is recorded as one already")
        XCTAssertEqual(sent.answers, [false])
    }

    func testKillModeSendsALateAnswerAsDecided() {
        // Before macOS 27 the kernel kills the daemon at the deadline and allows the access.
        let sent = Sent()
        sent.result = 3
        XCTAssertFalse(NativeLateAnswer.answer(allow: true, failClosed: false, deadline: 1_000, now: { 5_000 }, send: sent.send))
        XCTAssertEqual(sent.answers, [true])
    }

    func testAMissingDeadlineIsNotTakenAsPassed() {
        let sent = Sent()
        XCTAssertFalse(NativeLateAnswer.answer(allow: true, failClosed: true, deadline: 0, now: { 5_000 }, send: sent.send))
        XCTAssertEqual(sent.answers, [true])
    }

    func testTheClockIsReadOnlyForAnAllowInFailClosedMode() {
        var reads = 0
        let now: () -> UInt64 = {
            reads += 1
            return 0
        }
        _ = NativeLateAnswer.answer(allow: false, failClosed: true, deadline: 1_000, now: now) { _ in 0 }
        _ = NativeLateAnswer.answer(allow: true, failClosed: false, deadline: 1_000, now: now) { _ in 0 }
        XCTAssertEqual(reads, 0)
        _ = NativeLateAnswer.answer(allow: true, failClosed: true, deadline: 1_000, now: now) { _ in 0 }
        XCTAssertEqual(reads, 1, "read once, just before es_respond")
    }
}

// MARK: - Dropped AUTH messages

final class NativeAuthDropsTests: XCTestCase {
    func testGapsAreCountedPerEventTypeAndByOutcome() {
        var d = NativeAuthDrops()
        // Two AUTH types interleaved: each numbers its own messages, so neither has a gap.
        d.note(type: 42, seq: 1, failClosed: true)
        d.note(type: 7, seq: 1, failClosed: true)
        d.note(type: 42, seq: 2, failClosed: true)
        d.note(type: 7, seq: 2, failClosed: true)
        XCTAssertEqual(d.denied, 0)
        // Three opens never arrived.
        d.note(type: 42, seq: 6, failClosed: true)
        XCTAssertEqual(d.denied, 3)
        XCTAssertEqual(d.allowed, 0)
        // In kill mode the kernel allows what it drops.
        d.note(type: 7, seq: 4, failClosed: false)
        XCTAssertEqual(d.allowed, 1)
        XCTAssertEqual(d.denied, 3)
    }

    func testANewClientStartsItsNumbersAfreshAndTheCountsStay() {
        var d = NativeAuthDrops()
        d.note(type: 42, seq: 100, failClosed: true)
        d.note(type: 42, seq: 103, failClosed: true)
        XCTAssertEqual(d.denied, 2)
        d.reset()
        d.note(type: 42, seq: 1, failClosed: true)
        d.note(type: 42, seq: 2, failClosed: true)
        XCTAssertEqual(d.denied, 2, "a restart from 1 is no gap")
        // Out of order or repeated numbers are no gap either.
        d.note(type: 42, seq: 2, failClosed: true)
        d.note(type: 42, seq: 1, failClosed: true)
        XCTAssertEqual(d.denied, 2)
    }
}

// MARK: - Status

/// A native-like source with AUTH counts.
private final class CountingSource: EventSource, @unchecked Sendable {
    let kind: SourceKind = .native
    let canEnforce = true
    var state = SourceState(running: true)
    var counts: SourceAuthCounts?
    func start(sink: EventSink) throws {}
    func stop() {}
    func updateMonitoring(prefixes: [String], ancestors: [String], readdir: Bool) {}
    var authCounts: SourceAuthCounts? { counts }
}

final class SourceAuthCountsStatusTests: XCTestCase {
    func testStatusCarriesTheCountsAndStaysBackwardCompatible() throws {
        let dir = TempDir()
        var config = baseConfig(dir)
        config.resolveOwners = false
        let source = CountingSource()
        let core = try DaemonCore(config: config, makeSource: { _ in source })
        XCTAssertNil(core.status().sourceAuth)
        let other = TempDir()
        XCTAssertNil(try DaemonCore(config: baseConfig(other), makeSource: { _ in FakeSource(canEnforce: true) }).status().sourceAuth,
                     "other sources have none")
        source.counts = SourceAuthCounts(lateDenied: 3, droppedDenied: 2, droppedAllowed: 0, defaultMutedPrograms: 5)
        let status = core.status()
        XCTAssertEqual(status.sourceAuth, source.counts)
        let data = try JSONEncoder().encode(status)
        XCTAssertEqual(try JSONDecoder().decode(DaemonStatus.self, from: data).sourceAuth, source.counts)
        // An older daemon's status (no field) still decodes.
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        object.removeValue(forKey: "sourceAuth")
        XCTAssertNil(try JSONDecoder().decode(DaemonStatus.self, from: JSONSerialization.data(withJSONObject: object)).sourceAuth)
    }

    func testStatusLines() {
        XCTAssertEqual(SourceAuthCounts().warningLines, [])
        XCTAssertNil(SourceAuthCounts().mutedLine)
        XCTAssertNil(SourceAuthCounts(defaultMutedPrograms: 0).mutedLine)
        let c = SourceAuthCounts(lateDenied: 1, droppedDenied: 4, droppedAllowed: 2, defaultMutedPrograms: 3)
        XCTAssertEqual(c.warningLines.count, 3)
        XCTAssertTrue(c.warningLines[0].contains("1 access allowed too late"), c.warningLines[0])
        XCTAssertTrue(c.warningLines[0].contains("kernel denied it"), c.warningLines[0])
        XCTAssertTrue(c.warningLines[1].contains("4 AUTH accesses dropped by the kernel"), c.warningLines[1])
        XCTAssertTrue(c.warningLines[1].contains("denied (fail-closed)"), c.warningLines[1])
        XCTAssertTrue(c.warningLines[2].contains("allowed (kill mode)"), c.warningLines[2])
        XCTAssertTrue(c.mutedLine?.contains("3 system program paths") ?? false)
    }
}

// MARK: - Teardown: bounded broker, drain, process client gate

/// A broker that holds (an answering app is present).
private func heldBroker() -> AskBroker {
    let b = AskBroker(minimumBudget: 0.01)
    b.noteAnsweringClient()
    return b
}

private func question(_ category: String) -> AskRequest {
    let key = "app:/system/applications/utilities/terminal.app"
    let t = Date(timeIntervalSince1970: 1_760_000_000)
    return AskRequest(id: 0, key: AskKey(responsibleKey: key, categoryID: category, access: .read, chainAgents: []),
                      responsible: ResponsibleEntity(kind: .app, key: key, displayName: "Terminal"), severity: .critical,
                      path: "/Users/alice/.ssh/id_ed25519", process: proc(501, "/bin/cat", platform: true), chain: [], agentID: nil,
                      appleProgram: false, firstAt: t, lastAt: t)
}

private final class AnswerLog: @unchecked Sendable {
    private let lock = NSLock()
    private var list: [AskBroker.Answer] = []
    func add(_ a: AskBroker.Answer) {
        lock.lock()
        list.append(a)
        lock.unlock()
    }
    var answers: [AskBroker.Answer] {
        lock.lock(); defer { lock.unlock() }
        return list
    }
}

final class AskBrokerBoundedDenyAllTests: XCTestCase {
    func testDenyAllGivesUpOnAStuckQueueAndTheDenialStillArrivesLater() throws {
        let b = heldBroker()
        let inside = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        guard case .held(let first) = b.hold(question("a"), budget: 60, respond: { _ in
            inside.signal()
            release.wait()
        }) else { return XCTFail("not held") }
        b.resolve(id: first, answer: .allow)
        // The broker queue is now stuck in that response.
        XCTAssertEqual(inside.wait(timeout: .now() + 5), .success)
        let log = AnswerLog()
        guard case .held = b.hold(question("b"), budget: 60, respond: { log.add($0) }) else { return XCTFail("not held") }
        let start = Date()
        XCTAssertFalse(b.denyAll(waitAtMost: 0.2), "the queue did not get to it")
        XCTAssertLessThan(Date().timeIntervalSince(start), 3, "bounded: a stop is not held up")
        XCTAssertEqual(b.heldAccesses, 0, "nothing is held any more: the source denies what it still holds")
        XCTAssertEqual(log.answers, [])
        release.signal()
        b.drain()
        XCTAssertEqual(log.answers, [.deny], "denied once the queue frees, never allowed")
        XCTAssertTrue(b.denyAll(waitAtMost: 5), "a free queue answers in time")
    }
}

final class NativeDrainTests: XCTestCase {
    func testASyncMarkerThatCompletesDrains() {
        let ok = NativeDrain.run(sync: { block in
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { block() }
            return true
        }, quiet: { _ in XCTFail("no fallback when the marker was placed"); return false }, waitAtMost: 5)
        XCTAssertTrue(ok)
    }

    func testASyncMarkerThatNeverCompletesTimesOut() {
        let start = Date()
        var kept: (() -> Void)?
        let ok = NativeDrain.run(sync: { block in
            kept = block  // a stuck handler: the marker is never reached
            return true
        }, quiet: { _ in XCTFail("no fallback when the marker was placed"); return true }, waitAtMost: 0.1)
        XCTAssertFalse(ok, "the caller must not delete the client")
        XCTAssertLessThan(Date().timeIntervalSince(start), 3)
        // ES calls the block later (or at teardown): harmless after the wait gave up.
        kept?()
    }

    func testWithoutEsSyncClientTheHandlerMustGoQuiet() {
        var asked: [TimeInterval] = []
        XCTAssertTrue(NativeDrain.run(sync: nil, quiet: { asked.append($0); return true }, waitAtMost: 0.7))
        XCTAssertFalse(NativeDrain.run(sync: { _ in false }, quiet: { asked.append($0); return false }, waitAtMost: 0.3),
                       "placing the marker failed: the fallback decides")
        XCTAssertEqual(asked, [0.7, 0.3])
    }

    #if canImport(Darwin)
    func testTheBlockPassesThroughACFunctionPointer() throws {
        // es_sync_client is called through a pointer from dlsym: the block must survive being called later
        // from another thread. A C function with the same signature stands in for it.
        let fake: NativeDrain.SyncClientFunction = { _, block in
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.05, execute: block)
            return 0
        }
        let f = try XCTUnwrap(NativeDrain.syncClientFunction(unsafeBitCast(fake, to: UnsafeMutableRawPointer.self)))
        let client = OpaquePointer(bitPattern: 0x10)!
        XCTAssertTrue(NativeDrain.run(sync: { block in f(client, block) == 0 }, quiet: { _ in false }, waitAtMost: 5))
        XCTAssertNil(NativeDrain.syncClientFunction(nil))
    }
    #endif

    /// Runs `NativeDrain.retire` with a drain and a gate that answer as given; what it did.
    private func retire(gatedOnly: Bool, drained: Bool, gateFree: Bool) -> (NativeDrain.Outcome, closed: Int, deleted: Int) {
        var closed = 0
        var deleted = 0
        let outcome = NativeDrain.retire(gatedOnly: gatedOnly, drain: { drained }, close: {
            closed += 1
            return gateFree
        }, delete: { deleted += 1 })
        return (outcome, closed, deleted)
    }

    func testAProcessClientIsDeletedWhenOnlyItsDeliveryOutlastsTheDrain() {
        // The process client's handler converts each message inside its gate (record(), es_exec_arg) and
        // updates the process tree after it: a slow analyzer keeps the handler, and so the drain, busy,
        // but nothing on the client. Before, a drain that timed out left the client undeleted (abortSetup
        // then leaked it on every retry).
        let r = retire(gatedOnly: true, drained: false, gateFree: true)
        XCTAssertEqual(r.0, .deleted)
        XCTAssertEqual(r.closed, 1)
        XCTAssertEqual(r.deleted, 1)
    }

    func testAFileClientIsKeptWhenItsDrainTimesOut() {
        // Its handler reads message memory outside the gate (the watchdog's deadline, NOTIFY conversion).
        let r = retire(gatedOnly: false, drained: false, gateFree: true)
        XCTAssertEqual(r.0, .keptUndrained)
        XCTAssertEqual(r.closed, 0, "the gate stays open: the process is stopping, or a retry replaces the client")
        XCTAssertEqual(r.deleted, 0)
    }

    func testNoClientIsDeletedWhileACallInsideItsGateRuns() {
        for gatedOnly in [true, false] {
            for drained in [true, false] where gatedOnly || drained {
                let r = retire(gatedOnly: gatedOnly, drained: drained, gateFree: false)
                XCTAssertEqual(r.0, .keptBusy, "gated only \(gatedOnly), drained \(drained)")
                XCTAssertEqual(r.deleted, 0)
            }
            let r = retire(gatedOnly: gatedOnly, drained: true, gateFree: true)
            XCTAssertEqual(r.0, .deleted)
            XCTAssertEqual(r.deleted, 1)
        }
    }

    func testEsSyncClientIsFoundOnlyWhereTheSystemHasIt() {
        let has27 = ProcessInfo.processInfo.isOperatingSystemAtLeast(OperatingSystemVersion(majorVersion: 27, minorVersion: 0, patchVersion: 0))
        XCTAssertEqual(NativeDeadlineMissMode.symbol(NativeDrain.syncClientName) != nil, has27)
    }

    func testQuietNeedsNoCallForTheWholePeriod() {
        let idle = NativeHandlerActivity()
        let start = Date()
        XCTAssertTrue(idle.waitQuiet(0.05, waitAtMost: 5))
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(start), 0.05)

        // A call stuck inside is never quiet.
        let stuck = NativeHandlerActivity()
        stuck.enter()
        XCTAssertFalse(stuck.waitQuiet(0.02, waitAtMost: 0.2))
        stuck.leave()
        XCTAssertTrue(stuck.waitQuiet(0.02, waitAtMost: 5))

        // Messages still arriving (one every 10 ms) keep it busy; once they stop, it goes quiet.
        let busy = NativeHandlerActivity()
        let stop = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            while stop.wait(timeout: .now() + 0.01) == .timedOut {
                busy.enter()
                busy.leave()
            }
            finished.signal()
        }
        XCTAssertFalse(busy.waitQuiet(0.1, waitAtMost: 0.3))
        stop.signal()
        XCTAssertEqual(finished.wait(timeout: .now() + 5), .success)
        XCTAssertTrue(busy.waitQuiet(0.05, waitAtMost: 5))
    }
}

// MARK: - Watchdog backoff and the unclean-stop report

final class WatchdogBackoffTests: XCTestCase {
    func testTheShortestStallDoublesWithRecentExitsUpToTheMaximum() {
        XCTAssertEqual(NativeHandlerWatchdog.floor(recentExits: 0), NativeHandlerWatchdog.minimumStall)
        XCTAssertEqual(NativeHandlerWatchdog.floor(recentExits: 1), 2 * NativeHandlerWatchdog.minimumStall)
        XCTAssertEqual(NativeHandlerWatchdog.floor(recentExits: 2), 4 * NativeHandlerWatchdog.minimumStall)
        XCTAssertEqual(NativeHandlerWatchdog.floor(recentExits: 3), NativeHandlerWatchdog.maximumStall)
        XCTAssertEqual(NativeHandlerWatchdog.floor(recentExits: 1_000), NativeHandlerWatchdog.maximumStall)
        XCTAssertEqual(NativeHandlerWatchdog.floor(recentExits: -1), NativeHandlerWatchdog.minimumStall)
    }

    func testAWatchdogWithAFloorWaitsThatLong() {
        var t: UInt64 = 1_000_000_000
        let w = NativeHandlerWatchdog(now: { t }, floor: 480)
        XCTAssertEqual(w.limit, 480)
        w.enter()
        t += 479 * 1_000_000_000
        XCTAssertNil(w.stalled())
        t += 2 * 1_000_000_000
        XCTAssertNotNil(w.stalled())
        // Never below the minimum, never above the maximum.
        XCTAssertEqual(NativeHandlerWatchdog(floor: 1).limit, NativeHandlerWatchdog.minimumStall)
        XCTAssertEqual(NativeHandlerWatchdog(floor: 1e9).limit, NativeHandlerWatchdog.maximumStall)
    }

    func testStopsAreCountedWithTheFirstAndLastTime() {
        let t0 = Date(timeIntervalSince1970: 1_760_000_000)
        var s = UncleanStops()
        s.record(at: t0, stall: nil)
        XCTAssertEqual(s.count, 1)
        XCTAssertEqual(s.watchdogExits, 0)
        s.record(at: t0.addingTimeInterval(130), stall: 121)
        s.record(at: t0.addingTimeInterval(260), stall: 122)
        XCTAssertEqual(s.count, 3)
        XCTAssertEqual(s.first, t0)
        XCTAssertEqual(s.last, t0.addingTimeInterval(260))
        XCTAssertEqual(s.watchdogExits, 2)
        XCTAssertEqual(s.lastStallSeconds, 122)
        let now = t0.addingTimeInterval(260)
        XCTAssertEqual(s.recentWatchdogExitCount(now: now), 2)
        XCTAssertEqual(s.watchdogFloor(now: now), 4 * NativeHandlerWatchdog.minimumStall)
        XCTAssertEqual(s.recentWatchdogExitCount(now: now.addingTimeInterval(2 * NativeHandlerWatchdog.backoffWindow)), 0, "they age out")
        let note = s.note(now: now, armed: true, stall: 122)
        XCTAssertTrue(note.contains("exited by its watchdog"), note)
        XCTAssertTrue(note.contains("stuck in one call for 122 s"), note)
        XCTAssertTrue(note.contains("3 unclean stops since 2025-10-09T08:53:20Z, the last at 2025-10-09T08:57:40Z"), note)
        XCTAssertTrue(note.contains("the watchdog exited the daemon 2 times (2 in the last hour)"), note)
        XCTAssertTrue(note.contains("now waits 480 s"), note)
        // Only the most recent exits are kept.
        for i in 0..<100 { s.record(at: now.addingTimeInterval(Double(i)), stall: 1) }
        XCTAssertEqual(s.recentWatchdogExits.count, UncleanStops.keepRecent)
        XCTAssertEqual(s.watchdogExits, 102)
    }

    func testTheStallMarkerRoundTripsAndIsNeverFollowed() throws {
        let dir = TempDir()
        let path = dir.path("watchdog-stall")
        XCTAssertNil(NativeStallMarker.take(path), "none")
        NativeStallMarker.setPath(path)
        defer { NativeStallMarker.setPath(nil) }
        XCTAssertTrue(NativeStallMarker.write(seconds: 121.7))
        XCTAssertEqual(NativeStallMarker.take(path), 121)
        XCTAssertFalse(FileManager.default.fileExists(atPath: path), "taken")
        // A link planted there is neither read nor followed, and is removed.
        let elsewhere = dir.path("elsewhere")
        XCTAssertTrue(touch(elsewhere, Data("7\n".utf8)))
        XCTAssertEqual(symlink(elsewhere, path), 0)
        XCTAssertNil(NativeStallMarker.take(path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: elsewhere))
        var st = stat()
        XCTAssertNotEqual(lstat(path, &st), 0, "the link is gone")
        NativeStallMarker.setPath(nil)
        XCTAssertFalse(NativeStallMarker.write(seconds: 1), "no path, no marker")
    }

    /// A data directory as a daemon left it: the armed marker (AUTH was subscribed) and/or the watchdog's.
    private func leave(_ config: DaemonConfiguration, armed: Bool, stall: Int?) throws {
        try FileManager.default.createDirectory(atPath: config.dataDirectory, withIntermediateDirectories: true)
        if armed { XCTAssertTrue(touch(config.authArmedMarkerPath)) }
        if let stall { XCTAssertTrue(touch(config.watchdogStallMarkerPath, Data("\(stall)\n".utf8))) }
    }

    func testARecurringWedgeIsReportedAsOneLoopAndBacksTheWatchdogOff() throws {
        let dir = TempDir()
        var config = baseConfig(dir)
        config.resolveOwners = false
        // First instance exited by its watchdog while enforcing.
        try leave(config, armed: true, stall: 125)
        let first = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        let note1 = try XCTUnwrap(first.status().uncleanStop)
        XCTAssertTrue(note1.contains("exited by its watchdog"), note1)
        XCTAssertTrue(note1.contains("125 s"), note1)
        XCTAssertFalse(note1.contains("unclean stops since"), "only one so far")
        XCTAssertEqual(first.watchdogStallFloor, 2 * NativeHandlerWatchdog.minimumStall)
        XCTAssertFalse(FileManager.default.fileExists(atPath: config.watchdogStallMarkerPath), "taken")
        XCTAssertFalse(FileManager.default.fileExists(atPath: config.authArmedMarkerPath))

        // The wedge comes back: the second report counts both instead of replacing the first.
        try leave(config, armed: true, stall: 250)
        let second = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        let note2 = try XCTUnwrap(second.status().uncleanStop)
        XCTAssertTrue(note2.contains("2 unclean stops since"), note2)
        XCTAssertTrue(note2.contains("the watchdog exited the daemon 2 times"), note2)
        XCTAssertEqual(second.watchdogStallFloor, 4 * NativeHandlerWatchdog.minimumStall)

        // A daemon that only monitored is reported too (file events were lost), and counted.
        try leave(config, armed: false, stall: 480)
        let third = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        let note3 = try XCTUnwrap(third.status().uncleanStop)
        XCTAssertTrue(note3.contains("monitoring only"), note3)
        XCTAssertTrue(note3.contains("3 unclean stops"), note3)
        XCTAssertEqual(third.watchdogStallFloor, NativeHandlerWatchdog.maximumStall)

        // A start with no marker keeps the report and the backoff.
        let fourth = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        XCTAssertEqual(fourth.status().uncleanStop, note3)
        XCTAssertEqual(fourth.watchdogStallFloor, NativeHandlerWatchdog.maximumStall)

        // A clean stop clears both.
        fourth.noteCleanStop()
        let fifth = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        XCTAssertNil(fifth.status().uncleanStop)
        XCTAssertEqual(fifth.watchdogStallFloor, NativeHandlerWatchdog.minimumStall)
        try leave(config, armed: true, stall: nil)
        let sixth = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        let note6 = try XCTUnwrap(sixth.status().uncleanStop)
        XCTAssertFalse(note6.contains("unclean stops since"), "counted afresh: \(note6)")
        XCTAssertTrue(note6.contains("missed AUTH deadline"), note6)
    }
}

// MARK: - Default mute set (SDK D5)

final class NativeDefaultMutesTests: XCTestCase {
    func testOnlyProgramPathsMutedForAnsweredAuthEventsCount() {
        let entries: [NativeDefaultMutes.Entry] = [
            .init(type: NativeDefaultMutes.programLiteral, path: "/usr/libexec/watchdogd", events: [10, 11, 99]),
            .init(type: NativeDefaultMutes.programPrefix, path: "/System/Library/Frameworks/X.framework", events: [99]),
            .init(type: 2, path: "/private/var/db", events: [10]),  // a target mute
            .init(type: NativeDefaultMutes.programPrefix, path: "/usr/sbin/a", events: [11]),
        ]
        let programs = NativeDefaultMutes.programs(entries, authEvents: [10, 11])
        XCTAssertEqual(programs.map(\.path), ["/usr/libexec/watchdogd", "/usr/sbin/a"])
        XCTAssertEqual(programs[0].events, [10, 11], "only the events WhoRead answers")
        let line = NativeDefaultMutes.logLine(programs) { $0 == 10 ? "open" : "rename" }
        XCTAssertTrue(line.contains("2 program paths"), line)
        XCTAssertTrue(line.contains("/usr/libexec/watchdogd (open, rename)"), line)
        XCTAssertTrue(line.contains("/usr/sbin/a* (rename)"), line)
        XCTAssertTrue(NativeDefaultMutes.logLine([]) { _ in "" }.contains("no program"))
    }
}

// MARK: - Mapped-writable closes (SDK D6)

final class NativeWritableOpensTests: XCTestCase {
    private let key = "/Users/alice/.ssh/id_ed25519"

    func testOnlyTheProcessThatOpenedForWritingIsCharged() {
        var w = NativeWritableOpens()
        let vim = NativeWritableOpens.Owner(pid: 10, start: 1_000)
        w.noteWriteOpen(vim, path: key)
        XCTAssertTrue(w.contains(vim, path: key))
        XCTAssertFalse(w.contains(.init(pid: 11, start: 1_000), path: key), "a later reader")
        XCTAssertFalse(w.contains(.init(pid: 10, start: 2_000), path: key), "a new process under the reused pid")
        XCTAssertFalse(w.contains(vim, path: "/Users/alice/.ssh/id_rsa"))
        w.noteWriteOpen(vim, path: key)
        XCTAssertEqual(w.count, 1)
        // Its pid reused by a process that opens the same file: both are kept, neither replaces the other.
        w.noteWriteOpen(.init(pid: 10, start: 2_000), path: key)
        XCTAssertTrue(w.contains(vim, path: key), "the first process's closes may still come (its exit is no cue)")
        XCTAssertEqual(w.count, 2)
        // Before message version 3 there is no start time: the pid alone.
        w.noteWriteOpen(.init(pid: 12, start: nil), path: key)
        XCTAssertTrue(w.contains(.init(pid: 12, start: nil), path: key))
    }

    func testItStaysBoundedOldestFirst() {
        var w = NativeWritableOpens()
        for i in 0..<(3 * NativeWritableOpens.capacity) { w.noteWriteOpen(.init(pid: Int32(i), start: 1), path: "/p") }
        XCTAssertEqual(w.count, NativeWritableOpens.capacity)
        XCTAssertFalse(w.contains(.init(pid: 0, start: 1), path: "/p"), "the oldest went")
        XCTAssertTrue(w.contains(.init(pid: Int32(3 * NativeWritableOpens.capacity - 1), start: 1), path: "/p"))
        XCTAssertLessThanOrEqual(w.orderCount, 2 * NativeWritableOpens.capacity + 1)
    }
}

// MARK: - Renames onto an empty directory (files-5)

final class NativeEmptyDirectoryTests: XCTestCase {
    private let dir: UInt32 = 0o040755

    func testOnlyAnEmptyLocalAPFSDirectoryCounts() {
        XCTAssertTrue(NativeEmptyDirectory.isEmpty(mode: dir, nlink: 2, size: 64, flags: 0, onAPFS: true))
        XCTAssertFalse(NativeEmptyDirectory.isEmpty(mode: dir, nlink: 2, size: 64, flags: 0, onAPFS: false),
                       "elsewhere (an NFS home on XFS can report 2 and 64 with files inside)")
        XCTAssertFalse(NativeEmptyDirectory.isEmpty(mode: dir, nlink: 3, size: 96, flags: 0, onAPFS: true), "one entry")
        XCTAssertFalse(NativeEmptyDirectory.isEmpty(mode: dir, nlink: 2, size: 96, flags: 0, onAPFS: true), "inconsistent: not trusted")
        XCTAssertFalse(NativeEmptyDirectory.isEmpty(mode: dir, nlink: 2, size: 64, flags: NativeEmptyDirectory.datalessFlag, onAPFS: true),
                       "a dataless cloud folder lists nothing but has contents")
        XCTAssertFalse(NativeEmptyDirectory.isEmpty(mode: 0o100644, nlink: 2, size: 64, flags: 0, onAPFS: true), "a file")
    }

    #if canImport(Darwin)
    func testAPFSReportsEntriesTheWayTheCheckReadsThem() throws {
        // On this Mac's own APFS volume: the stat the kernel puts into an ES message is the one stat(2) gives.
        let d = TempDir()
        var fs = Darwin.statfs()
        XCTAssertEqual(statfs(d.url.path, &fs), 0)
        let type = withUnsafeBytes(of: fs.f_fstypename) { String(cString: $0.bindMemory(to: CChar.self).baseAddress!) }
        try XCTSkipUnless(type == "apfs", "the temporary directory is not on APFS")
        let empty = d.path("empty")
        XCTAssertEqual(mkdir(empty, 0o755), 0)
        func emptyNow() -> Bool {
            var st = stat()
            XCTAssertEqual(stat(empty, &st), 0)
            XCTAssertEqual(st.st_dev, fs.f_fsid.val.0, "statfs f_fsid.val[0] is st_dev")
            return NativeEmptyDirectory.isEmpty(mode: UInt32(st.st_mode), nlink: UInt32(st.st_nlink), size: Int64(st.st_size),
                                                flags: st.st_flags, onAPFS: true)
        }
        XCTAssertTrue(emptyNow())
        for entry in [".hidden", "file"] {
            XCTAssertTrue(touch(empty + "/" + entry))
            XCTAssertFalse(emptyNow(), entry)
            XCTAssertEqual(unlink(empty + "/" + entry), 0)
        }
        XCTAssertEqual(mkdir(empty + "/sub", 0o755), 0)
        XCTAssertFalse(emptyNow(), "a subdirectory")
        XCTAssertEqual(rmdir(empty + "/sub"), 0)
        XCTAssertEqual(symlink("/nonexistent", empty + "/link"), 0)
        XCTAssertFalse(emptyNow(), "a dangling link")
        XCTAssertEqual(unlink(empty + "/link"), 0)
        XCTAssertTrue(emptyNow())
    }
    #endif
}

#if canImport(EndpointSecurity)
import EndpointSecurity

/// An es_message_t built by hand in zeroed memory, laid out by the real SDK headers. Pointers it hands
/// out live as long as it does.
private final class TestESMessage {
    private var blocks: [UnsafeMutableRawPointer] = []
    private(set) var message: UnsafeMutablePointer<es_message_t>!
    private let eventOffset = MemoryLayout<es_message_t>.offset(of: \es_message_t.event)!

    init(_ type: es_event_type_t, auth: Bool = false, version: UInt32 = 7, pid: Int32 = 700) {
        message = zeroed(es_message_t.self, extra: 256)
        let process = zeroed(es_process_t.self)
        let p = UnsafeMutableRawPointer(process)
        p.storeBytes(of: file("/bin/mv", mode: 0o100755), toByteOffset: MemoryLayout<es_process_t>.offset(of: \es_process_t.executable)!,
                     as: UnsafeMutablePointer<es_file_t>.self)
        // audit_token_to_pid reads the sixth word of the token.
        p.storeBytes(of: UInt32(bitPattern: pid), toByteOffset: MemoryLayout<es_process_t>.offset(of: \es_process_t.audit_token)! + 20,
                     as: UInt32.self)
        let m = UnsafeMutableRawPointer(message!)
        m.storeBytes(of: version, toByteOffset: MemoryLayout<es_message_t>.offset(of: \es_message_t.version)!, as: UInt32.self)
        m.storeBytes(of: process, toByteOffset: MemoryLayout<es_message_t>.offset(of: \es_message_t.process)!,
                     as: UnsafeMutablePointer<es_process_t>.self)
        m.storeBytes(of: auth ? ES_ACTION_TYPE_AUTH : ES_ACTION_TYPE_NOTIFY,
                     toByteOffset: MemoryLayout<es_message_t>.offset(of: \es_message_t.action_type)!, as: es_action_type_t.self)
        m.storeBytes(of: type, toByteOffset: MemoryLayout<es_message_t>.offset(of: \es_message_t.event_type)!, as: es_event_type_t.self)
    }

    deinit { blocks.forEach { $0.deallocate() } }

    private func zeroed<T>(_: T.Type, extra: Int = 0) -> UnsafeMutablePointer<T> {
        let size = MemoryLayout<T>.stride + extra
        let raw = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: max(MemoryLayout<T>.alignment, 16))
        raw.initializeMemory(as: UInt8.self, repeating: 0, count: size)
        blocks.append(raw)
        return raw.bindMemory(to: T.self, capacity: 1)
    }

    /// Sets the process's start time (es_process_t.start_time, message version >= 3).
    func process(start: timeval) {
        let p = UnsafeMutableRawPointer(message.pointee.process)
        p.storeBytes(of: start, toByteOffset: MemoryLayout<es_process_t>.offset(of: \es_process_t.start_time)!, as: timeval.self)
    }

    /// Writes `value` at `offset` inside the event union.
    func event<T>(_ value: T, at offset: Int) {
        (UnsafeMutableRawPointer(message!) + eventOffset + offset).storeBytes(of: value, as: T.self)
    }

    /// The event union as `T`, to set fields the importer does not expose as stored properties.
    func event<T>(as: T.Type) -> UnsafeMutablePointer<T> {
        (UnsafeMutableRawPointer(message!) + eventOffset).assumingMemoryBound(to: T.self)
    }

    func file(_ path: String, mode: UInt32, nlink: UInt16 = 1, size: Int64 = 0, flags: UInt32 = 0, dev: Int32 = 0) -> UnsafeMutablePointer<es_file_t> {
        let bytes = Array(path.utf8)
        let chars = zeroed(CChar.self, extra: bytes.count + 1)
        bytes.withUnsafeBytes { UnsafeMutableRawPointer(chars).copyMemory(from: $0.baseAddress!, byteCount: bytes.count) }
        var st = stat()
        st.st_mode = mode_t(mode)
        st.st_nlink = nlink_t(nlink)
        st.st_size = off_t(size)
        st.st_flags = flags
        st.st_dev = dev_t(dev)
        let f = zeroed(es_file_t.self)
        f.initialize(to: es_file_t(path: es_string_token_t(length: bytes.count, data: UnsafePointer(chars)), path_truncated: false, stat: st))
        return f
    }

    /// The source's conversion of this message (kept alive while it runs).
    func activity(onAPFS: (Int32) -> Bool = { _ in false },
                  openedForWriting: (NativeWritableOpens.Owner, String) -> Bool = { _, _ in false }) -> FileActivity? {
        withExtendedLifetime(self) {
            NativeESSource.activity(UnsafePointer(message), onAPFS: onAPFS, openedForWriting: openedForWriting)
        }
    }
}

private let apfsDev: Int32 = 16_777_229

/// A rename of `/private/tmp/new` (a directory) onto the existing directory `destination`, whose stat
/// says `nlink` entries + 2.
private func renameOnto(_ destination: String, nlink: UInt16, size: Int64, flags: UInt32 = 0, auth: Bool = true) -> TestESMessage {
    let m = TestESMessage(auth ? ES_EVENT_TYPE_AUTH_RENAME : ES_EVENT_TYPE_NOTIFY_RENAME, auth: auth)
    m.event(m.file("/private/tmp/new", mode: 0o040755, nlink: 3, size: 96, dev: apfsDev),
            at: MemoryLayout<es_event_rename_t>.offset(of: \es_event_rename_t.source)!)
    m.event(ES_DESTINATION_TYPE_EXISTING_FILE, at: MemoryLayout<es_event_rename_t>.offset(of: \es_event_rename_t.destination_type)!)
    m.event(m.file(destination, mode: 0o040755, nlink: nlink, size: size, flags: flags, dev: apfsDev),
            at: MemoryLayout<es_event_rename_t>.offset(of: \es_event_rename_t.destination)!)
    return m
}

final class NativeEmptyDirectoryConversionTests: XCTestCase {
    func testARenameOntoAnEmptyDirectoryIsARenameToANewPath() throws {
        for auth in [true, false] {
            let m = renameOnto("/Users/alice/.ssh", nlink: 2, size: 64, auth: auth)
            let a = try XCTUnwrap(m.activity(onAPFS: { $0 == apfsDev }))
            XCTAssertEqual(a.targets.map(\.path), ["/private/tmp/new", "/Users/alice/.ssh"])
            XCTAssertEqual(a.targets[1].access, .write, "nothing below it is carried out: not a read")
            XCTAssertNil(a.targets[1].isDirectory, "takes the source's type, as a new path does")
            XCTAssertFalse(a.targets[1].carriesContent(in: .rename))
            XCTAssertTrue(a.targets[0].carriesContent(in: .rename), "the source is still carried")
        }
    }

    func testAnythingElseStaysASwapCarryingItsContents() throws {
        let cases: [(TestESMessage, (Int32) -> Bool, String)] = [
            (renameOnto("/Users/alice/.ssh", nlink: 3, size: 96), { _ in true }, "not empty"),
            (renameOnto("/Users/alice/.ssh", nlink: 2, size: 64), { _ in false }, "not on a local APFS volume"),
            (renameOnto("/Users/alice/.ssh", nlink: 2, size: 64, flags: NativeEmptyDirectory.datalessFlag), { _ in true }, "dataless"),
        ]
        for (m, onAPFS, why) in cases {
            let a = try XCTUnwrap(m.activity(onAPFS: onAPFS))
            XCTAssertEqual(a.targets[1].access, .readWrite, why)
            XCTAssertEqual(a.targets[1].isDirectory, true, why)
            XCTAssertTrue(a.targets[1].carriesContent(in: .rename), why)
        }
        // Without the source's volume list (the default), never taken as empty.
        let a = try XCTUnwrap(renameOnto("/Users/alice/.ssh", nlink: 2, size: 64).activity())
        XCTAssertTrue(a.targets[1].carriesContent(in: .rename))
    }

    func testTheEmptyDestinationIsNoLongerAReadOfTheWorstFile() throws {
        // Before: `mv /private/tmp/new ~/.config` onto an empty ~/.config was a read of gh, gcloud and git
        // credentials at critical (asked about, or denied by a read-only rule). Now it is a write, judged
        // by what the new directory brings in.
        let dir = TempDir()
        var config = baseConfig(dir)
        config.resolveOwners = false
        let core = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        let full = try XCTUnwrap(renameOnto("/Users/alice/.config", nlink: 4, size: 128).activity(onAPFS: { _ in true }))
        let empty = try XCTUnwrap(renameOnto("/Users/alice/.config", nlink: 2, size: 64).activity(onAPFS: { _ in true }))
        let before = core.analyzer.classify(full).filter(\.isSensitive)
        let after = core.analyzer.classify(empty).filter(\.isSensitive)
        XCTAssertTrue(before.contains { $0.target.access.contains(.read) && $0.categories.contains { $0.id == "gh" } })
        XCTAssertFalse(after.contains { $0.target.access.contains(.read) }, "\(after.map { ($0.path, $0.target.access) })")
    }
}

/// A message of `type` by process `pid` started at `start` seconds (es_process_t.start_time).
private func processMessage(_ type: es_event_type_t, pid: Int32, start: Int, version: UInt32) -> TestESMessage {
    let m = TestESMessage(type, version: version, pid: pid)
    m.process(start: timeval(tv_sec: start, tv_usec: 250))
    return m
}

/// A NOTIFY_CLOSE of `path` by `pid` (started at `start`).
private func closeMessage(_ path: String, pid: Int32, start: Int = 1_000, modified: Bool, mapped: Bool, version: UInt32 = 7) -> TestESMessage {
    let m = processMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, pid: pid, start: start, version: version)
    m.event(m.file(path, mode: 0o100600), at: MemoryLayout<es_event_close_t>.offset(of: \es_event_close_t.target)!)
    let c = m.event(as: es_event_close_t.self)
    c.pointee.modified = modified
    c.pointee.was_mapped_writable = mapped
    return m
}

final class NativeMappedWritableCloseTests: XCTestCase {
    private let key = "/Users/alice/.ssh/id_ed25519"

    func testAMappedCloseIsAWriteOnlyForAProcessThatOpenedTheFileForWriting() throws {
        // The open was noted under the message's own process (pid and start time).
        var writers = NativeWritableOpens()
        let open = processMessage(ES_EVENT_TYPE_NOTIFY_OPEN, pid: 700, start: 1_000, version: 7)
        writers.noteWriteOpen(withExtendedLifetime(open) { NativeESSource.owner(open.message.pointee) }, path: key)
        XCTAssertEqual(withExtendedLifetime(open) { NativeESSource.owner(open.message.pointee) },
                       NativeWritableOpens.Owner(pid: 700, start: 1_000_000_250))
        let opened: (NativeWritableOpens.Owner, String) -> Bool = { writers.contains($0, path: $1) }

        let mine = try XCTUnwrap(closeMessage(key, pid: 700, modified: false, mapped: true).activity(openedForWriting: opened))
        XCTAssertEqual(mine.operation, .close)
        XCTAssertEqual(mine.targets.map(\.path), [key])
        XCTAssertEqual(mine.targets.map(\.access), [.write], "a possible modification through its writable mapping")
        XCTAssertEqual(mine.process.pid, 700)
        // Another process closing the same file: the flag is the vnode's, not its own.
        XCTAssertNil(closeMessage(key, pid: 701, modified: false, mapped: true).activity(openedForWriting: opened))
        // The same pid reused by a later process.
        XCTAssertNil(closeMessage(key, pid: 700, start: 2_000, modified: false, mapped: true).activity(openedForWriting: opened))
        // Not mapped writable: nothing to report.
        XCTAssertNil(closeMessage(key, pid: 700, modified: false, mapped: false).activity(openedForWriting: opened))
        // Before message version 6 the field is not there to read.
        XCTAssertNil(closeMessage(key, pid: 700, modified: false, mapped: true, version: 5)
                        .activity(openedForWriting: { _, _ in XCTFail("not asked"); return true }))
        // A modified close is a write whatever the rest says.
        let written = try XCTUnwrap(closeMessage(key, pid: 701, modified: true, mapped: false)
                                        .activity(openedForWriting: { _, _ in XCTFail("not asked"); return false }))
        XCTAssertEqual(written.targets.map(\.access), [.write])
    }

    func testBeforeMessageVersion3ThePidAloneIsTheProcess() {
        let m = processMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, pid: 700, start: 1_000, version: 2)
        XCTAssertEqual(withExtendedLifetime(m) { NativeESSource.owner(m.message.pointee) }, NativeWritableOpens.Owner(pid: 700, start: nil))
    }
}

final class NativeMutedPathsConversionTests: XCTestCase {
    func testTheMutedPathsAreCopiedOut() {
        let watchdogd = Array("/usr/libexec/watchdogd".utf8)
        let target = Array("/private/var/db".utf8)
        let events = [ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_NOTIFY_OPEN]
        watchdogd.withUnsafeBufferPointer { w in
            target.withUnsafeBufferPointer { t in
                events.withUnsafeBufferPointer { e in
                    let paths = [
                        es_muted_path_t(type: ES_MUTE_PATH_TYPE_LITERAL, event_count: 3, events: e.baseAddress!,
                                        path: es_string_token_t(length: w.count, data: UnsafeRawPointer(w.baseAddress!).assumingMemoryBound(to: CChar.self))),
                        es_muted_path_t(type: ES_MUTE_PATH_TYPE_TARGET_PREFIX, event_count: 1, events: e.baseAddress!,
                                        path: es_string_token_t(length: t.count, data: UnsafeRawPointer(t.baseAddress!).assumingMemoryBound(to: CChar.self))),
                    ]
                    paths.withUnsafeBufferPointer { p in
                        var set = es_muted_paths_t(count: 2, paths: p.baseAddress!)
                        let entries = NativeESSource.mutedPathEntries(&set)
                        XCTAssertEqual(entries, [
                            .init(type: NativeDefaultMutes.programLiteral, path: "/usr/libexec/watchdogd",
                                  events: events.map(\.rawValue)),
                            .init(type: ES_MUTE_PATH_TYPE_TARGET_PREFIX.rawValue, path: "/private/var/db",
                                  events: [ES_EVENT_TYPE_AUTH_OPEN.rawValue]),
                        ])
                        let programs = NativeDefaultMutes.programs(entries, authEvents: Set(NativeESSource.authFileEvents.map(\.rawValue)))
                        XCTAssertEqual(programs.map(\.path), ["/usr/libexec/watchdogd"])
                        XCTAssertEqual(programs.first?.events, [ES_EVENT_TYPE_AUTH_OPEN.rawValue, ES_EVENT_TYPE_AUTH_RENAME.rawValue])
                    }
                }
            }
        }
        XCTAssertEqual(ES_MUTE_PATH_TYPE_PREFIX.rawValue, NativeDefaultMutes.programPrefix)
        XCTAssertEqual(ES_MUTE_PATH_TYPE_LITERAL.rawValue, NativeDefaultMutes.programLiteral)
        XCTAssertEqual(ES_RESPOND_RESULT_SUCCESS.rawValue, NativeLateAnswer.respondSuccess)
        XCTAssertEqual(ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE.rawValue, NativeLateAnswer.respondDuplicate)
    }
}

// MARK: - Recording a late denial

final class NativeLateDenialRecordingTests: XCTestCase {
    func testALateDenialIsRecordedAsBlockedByNoRuleWithoutAnAlert() throws {
        let dir = TempDir()
        var config = baseConfig(dir)
        config.resolveOwners = false
        let core = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        let cat = proc(601, "/bin/cat", ppid: 1, platform: true)
        let read = FileActivity(time: Date(timeIntervalSince1970: 1_760_000_100), operation: .open, process: cat,
                                targets: OperationSemantics.open(path: "/Users/alice/.ssh/id_ed25519", fflag: OperationSemantics.fread))
        XCTAssertEqual(NativeESSource.lateDenial.verdict, .deny)
        XCTAssertEqual(NativeESSource.lateDenial.reason, .deadlineMissed)
        core.pipeline.receive(.file(read), context: .decided(NativeESSource.lateDenial))
        // Two categories in one access: both denied, still no alert and no rule.
        let copy = FileActivity(time: Date(timeIntervalSince1970: 1_760_000_101), operation: .clone, process: cat,
                                targets: OperationSemantics.clone(source: "/Users/alice/.ssh/id_ed25519", destination: "/Users/alice/.aws/credentials"))
        core.pipeline.receive(.file(copy), context: .decided(NativeESSource.lateDenial))
        core.writer.flush()
        let events = try core.store.events(EventQuery(includeBenign: true))
        XCTAssertEqual(events.count, 3)
        XCTAssertEqual(Set(events.map(\.decision)), [.denied], "the kernel denied it: recorded, not lost")
        XCTAssertEqual(events.compactMap(\.ruleID), [], "no rule denied it")
        XCTAssertEqual(try core.store.alerts(AlertQuery()).count, 0, "nothing for the user to answer")
    }
}
#endif
