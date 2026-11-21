import XCTest
import WhoReadCore
@testable import WhoReadEngine

/// True the first time only (the hook below also runs for every relaunch, on another thread).
private final class FirstTime: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func take() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if done { return false }
        done = true
        return true
    }
}

/// The last line a fake eslogger wrote, nil when none.
private func lastLine(_ path: String) -> String? {
    ((try? String(contentsOfFile: path, encoding: .utf8)) ?? "").split(separator: "\n").last.map(String.init)
}

/// Review round 5 (eslogger source): an event-list change during a launch, and the hint for an
/// immediate exit.
final class EsloggerSourceRound5Tests: XCTestCase {
    // eslogger-3: launch() builds the event list, spawns the child and only then publishes it. A readdir
    // change in between found no running child to restart, and every later change saw no difference:
    // the child kept the old list until it happened to exit.
    func testReaddirChangeWhileAChildIsSpawnedReachesIt() throws {
        for initial in [false, true] {
            let dir = TempDir()
            let args = dir.path("args")
            let fake = script(dir, "eslogger", "echo \"$@\" >> \(args)\nexec sleep 600")
            let source = EsloggerSource(executable: fake, prefixes: [], readdir: initial)
            let first = FirstTime()
            source.afterSpawn = { [weak source] in
                guard first.take() else { return }
                source?.updateMonitoring(prefixes: ["/Users/alice/WhoReadTestVault"], ancestors: [], readdir: !initial)
            }
            let sink = RecordingSink()
            try source.start(sink: sink)
            defer { source.stop() }
            let want = EsloggerSource.eventNames(readdir: !initial).joined(separator: " ")
            XCTAssertNotNil(waitFor(5) { lastLine(args) == want && source.state.running },
                            "readdir \(initial) → \(!initial): the running eslogger has \(lastLine(args) ?? "no arguments yet")")
            // A restart for a new event list is not a failure.
            XCTAssertTrue(sink.states.allSatisfy { $0.error == nil }, "\(sink.states)")
            // Settled: the same list again does not restart it.
            let launches = lineCount(args)
            source.updateMonitoring(prefixes: [], ancestors: [], readdir: !initial)
            Thread.sleep(forTimeInterval: 0.3)
            XCTAssertEqual(lineCount(args), launches)
        }
    }

    // eslogger-4: eslogger runs with the daemon's euid. As root it cannot fail for want of root, so
    // "root" or "super-user" in its message (a man-page style "must be run as super-user and requires
    // Full Disk Access", "rootless") must not turn into the root hint.
    func testDiagnosisAsRootPointsAtFullDiskAccess() {
        for stderr in ["must be run as super-user and requires TCC Full Disk Access",
                       "eslogger must be run as root with Full Disk Access",
                       "ERROR: es_new_client: ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED (rootless)",
                       "Failed to create ES client: Not permitted"] {
            XCTAssertTrue(EsloggerSource.diagnose(stderr: stderr, euid: 0).contains("Full Disk Access"), stderr)
        }
        let root = "must run as root"
        // Not root: the root hint, whatever eslogger said.
        XCTAssertTrue(EsloggerSource.diagnose(stderr: "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED", euid: 501).contains(root))
        XCTAssertTrue(EsloggerSource.diagnose(stderr: "", euid: 501).contains(root))
        // Root, and eslogger says it is not privileged: still the root hint.
        XCTAssertTrue(EsloggerSource.diagnose(stderr: "ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED", euid: 0).contains(root))
        // Root, nothing recognizable: the general hint, not the root one.
        let other = EsloggerSource.diagnose(stderr: "rootless: something else", euid: 0)
        XCTAssertFalse(other.contains(root), other)
        XCTAssertTrue(other.hasPrefix("eslogger exited immediately"), other)
    }
}
