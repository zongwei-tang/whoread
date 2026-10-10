import XCTest
import WhoReadCore
@testable import WhoReadEngine

// The AUTH entry point (Enforcer.decide) with ancestry that is unknown or deep, and the libproc
// platform guess (process-1, process-2, macos-6, dos-3).

private let t = Date(timeIntervalSince1970: 1_760_000_000)
private let key = "/Users/alice/.ssh/id_ed25519"

private func open(_ p: ProcessRecord, at time: Date = t.addingTimeInterval(100)) -> FileActivity {
    FileActivity(time: time, operation: .open, process: p, targets: OperationSemantics.open(path: key, fflag: 1))
}

final class ProcessAncestryEngineTests: XCTestCase {
    func trustingCore(_ dir: TempDir) throws -> DaemonCore {
        var config = baseConfig(dir)
        config.resolveOwners = false
        let core = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
        try core.setRules([])
        try core.mutateSettings(peer: .inProcess, reenable: true) {
            $0.enforcementEnabled = true
            $0.trustApplePrograms = true
        }
        core.drainPolicyQueue()
        return core
    }

    /// A reparented /bin/cat whose original parent was never seen (the process client lags behind the
    /// file client) is asked, not allowed as an all-Apple chain started by launchd.
    func testUnknownAncestryIsAskedOnTheAuthPath() throws {
        let dir = TempDir()
        let core = try trustingCore(dir)
        core.tree.parentResolver = { _ in nil }
        var orphan = proc(701, "/bin/cat", ppid: 1, platform: true, start: t.addingTimeInterval(3))
        orphan.originalPPID = 700
        XCTAssertEqual(core.enforcer.decide(open(orphan)).verdict, .ask)
        // Terminal → zsh → cat: trusted.
        core.tree.observe(proc(100, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", platform: true), at: t)
        core.tree.observe(proc(500, "/bin/zsh", ppid: 100, platform: true), at: t)
        let cat = proc(501, "/bin/cat", ppid: 500, platform: true, start: t.addingTimeInterval(3))
        XCTAssertEqual(core.enforcer.decide(open(cat)).reason, .trustedApple)
    }

    /// dos-3: a decision's cost does not grow with the depth of the chain an attacker builds.
    func testADecisionOnAVeryDeepChainIsBounded() throws {
        let dir = TempDir()
        let core = try trustingCore(dir)
        var parent = proc(100, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", platform: true)
        core.tree.observe(parent, at: t)
        for i in 0..<20_000 {
            let child = proc(Int32(10_000 + i), "/bin/sh", ppid: parent.pid, platform: true, start: t.addingTimeInterval(Double(i) * 0.01))
            core.tree.fork(parent: parent, child: child, at: child.startTime!)
            if i > 0 { core.tree.exit(parent, at: child.startTime!) }
            parent = child
        }
        let leaf = parent
        let start = Date()
        var d = core.enforcer.decide(open(leaf, at: t.addingTimeInterval(500)))
        for _ in 0..<49 { d = core.enforcer.decide(open(leaf, at: t.addingTimeInterval(500))) }
        let each = Date().timeIntervalSince(start) / 50
        print("decided on a 20000-deep chain in \(String(format: "%.2f", each * 1000)) ms")
        XCTAssertLessThan(each, 0.01, "well under 1 ms here; the full walk took 50 ms at this depth")
        XCTAssertEqual(d.verdict, .ask, "an all-Apple chain cut short is never trusted")
        XCTAssertEqual(d.askKey?.responsibleKey, "app:/system/applications/utilities/terminal.app")
    }

    /// macos-6: libproc's platform guess covers only SIP-protected locations; the data volume under its
    /// /System/Volumes/Data spelling is writable by the user.
    func testThePlatformGuessCoversOnlySystemLocations() {
        XCTAssertTrue(ProcessSnapshot.looksLikePlatformBinary("/usr/bin/ssh"))
        XCTAssertTrue(ProcessSnapshot.looksLikePlatformBinary("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"))
        XCTAssertFalse(ProcessSnapshot.looksLikePlatformBinary("/System/Volumes/Data/Users/alice/bin/tool"))
        XCTAssertFalse(ProcessSnapshot.looksLikePlatformBinary("/System/Volumes/Data/private/tmp/cat"))
        XCTAssertFalse(ProcessSnapshot.looksLikePlatformBinary("/usr/local/bin/ssh"))
        XCTAssertFalse(ProcessSnapshot.looksLikePlatformBinary("/opt/homebrew/bin/node"))
    }
}
