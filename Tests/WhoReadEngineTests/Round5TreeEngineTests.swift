import XCTest
import WhoReadCore
@testable import WhoReadEngine

// Round 5, process tree: libproc argv bounded where it is read (attribution-4).

/// A child of this test that runs until it is terminated, with `extra` after its script in argv (sh
/// stays the process: its loop never ends).
private func runningChild(extra: [String] = []) throws -> Process {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/sh")
    p.arguments = ["-c", "while :; do sleep 1; done", "sh"] + extra
    p.standardOutput = FileHandle.nullDevice
    p.standardError = FileHandle.nullDevice
    try p.run()
    return p
}

/// The libproc record of `child` once it runs /bin/sh's loop (right after the spawn, it may still be the
/// parent's image).
private func shellRecord(_ child: Process) -> ProcessRecord? {
    for _ in 0..<200 {
        if let r = ProcessSnapshot.record(pid: child.processIdentifier), r.argv?.dropFirst().first == "-c" { return r }
        usleep(10_000)
    }
    return nil
}

final class ProcessSnapshotBoundsTests: XCTestCase {
    /// attribution-4: argv read from libproc (KERN_PROCARGS2) is bounded as the tree bounds it, where it
    /// is read: seeding never holds the whole argv of every running process at once.
    func testLibprocArgvIsBoundedWhereItIsRead() throws {
        let element = String(repeating: "a", count: 8000)
        let child = try runningChild(extra: Array(repeating: element, count: 40))
        defer { child.terminate(); child.waitUntilExit() }
        let argv = try XCTUnwrap(shellRecord(child)?.argv)
        XCTAssertEqual(Array(argv.prefix(4)), ["/bin/sh", "-c", "while :; do sleep 1; done", "sh"])
        XCTAssertLessThanOrEqual(argv.reduce(0) { $0 + $1.utf8.count }, ProcessTree.maxArgvBytes + 32)
        XCTAssertEqual(argv[4], String(repeating: "a", count: 1024) + "…")
        XCTAssertEqual(argv.last, "…(+\(44 - (argv.count - 1)))")
        XCTAssertEqual(ProcessTree.boundedArgv(argv), argv, "the tree keeps it as it is")
    }
}

// MARK: - attribution-3: the libproc liveness probe

final class LivenessProbeTests: XCTestCase {
    /// libproc tells whether a process instance (pid and start time) still runs: not once it has exited,
    /// nor for another start time (another process holds the pid).
    func testLibprocTellsWhetherAProcessInstanceRuns() throws {
        let child = try runningChild()
        let start = try XCTUnwrap(shellRecord(child)?.startTime)
        let pid = child.processIdentifier
        XCTAssertEqual(ProcessSnapshot.isRunning(pid: pid, startTime: start), true)
        XCTAssertEqual(ProcessSnapshot.isRunning(pid: pid, startTime: start.addingTimeInterval(-60)), false)
        child.terminate()
        child.waitUntilExit()
        XCTAssertEqual(ProcessSnapshot.isRunning(pid: pid, startTime: start), false)
    }

    /// The daemon gives the seeded tree libproc (Daemon.start): maintenance (prune) then retires a live
    /// node whose process has exited without an exit event, and keeps one that still runs.
    func testMaintenanceWithLibprocRetiresProcessesThatAreGone() throws {
        let gone = try runningChild()
        let goneRecord = try XCTUnwrap(shellRecord(gone))
        gone.terminate()
        gone.waitUntilExit()
        let running = try runningChild()
        defer { running.terminate(); running.waitUntilExit() }
        let runningRecord = try XCTUnwrap(shellRecord(running))

        let tree = ProcessTree(detector: AgentDetector(catalog: AgentCatalog(agents: [])))
        Daemon.useLibproc(tree)
        XCTAssertNotNil(tree.parentResolver)
        XCTAssertNotNil(tree.livenessProbe)
        // Only the two children are looked at, not the processes that started this test.
        tree.parentResolver = nil
        // Last seen long ago (no event since): due for a check.
        let longAgo = Date().addingTimeInterval(-3600)
        tree.observe(goneRecord, at: longAgo)
        tree.observe(runningRecord, at: longAgo)
        tree.prune(now: Date())
        XCTAssertNotNil(tree.node(pid: goneRecord.pid)?.exitedAt, "its exit was missed")
        XCTAssertNil(tree.node(pid: runningRecord.pid)?.exitedAt)
    }
}
