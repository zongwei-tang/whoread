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
