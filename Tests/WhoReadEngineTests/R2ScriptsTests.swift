import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// Review round 2, scripts and packaging: the M5 acceptance script against the current daemon,
/// `build.sh` without the ES capability, and the uninstall scripts with an active extension. The
/// shell scripts run against stub commands on PATH; the uninstall ones only on Linux, where none
/// of the paths they touch exist.
final class R2ScriptsTests: XCTestCase {
    private struct Run {
        let status: Int32
        let stderr: String
        let calls: [String]
    }

    /// Runs `script` with `/bin/bash`, PATH = stubs first. Each stub body may append to "$LOG".
    private func run(_ script: String, _ args: [String] = [], stubs: [String: String],
                     env extra: [String: String] = [:], in dir: TempDir) throws -> Run {
        let bin = dir.path("bin")
        try FileManager.default.createDirectory(atPath: bin, withIntermediateDirectories: true)
        for (name, body) in stubs {
            let p = bin + "/" + name
            try ("#!/bin/bash\n" + body + "\n").write(toFile: p, atomically: false, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: p)
        }
        let log = dir.path("calls.log")
        try? FileManager.default.removeItem(atPath: log)
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/bash")
        proc.arguments = [script] + args
        proc.environment = ["PATH": bin + ":/usr/bin:/bin", "HOME": dir.url.path, "LOG": log].merging(extra) { $1 }
        let err = Pipe()
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = err
        try proc.run()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        let calls = ((try? String(contentsOfFile: log, encoding: .utf8)) ?? "").split(separator: "\n").map(String.init)
        return Run(status: proc.terminationStatus, stderr: String(decoding: e, as: UTF8.self), calls: calls)
    }

    private func script(_ relative: String) -> String { repoRoot.appendingPathComponent(relative).path }

    private func makeCore(_ dir: TempDir) throws -> DaemonCore {
        let fake = FakeSource(canEnforce: true)
        return try DaemonCore(config: baseConfig(dir), makeSource: { _ in fake })
    }

    private static let activated = "1 extension(s)\n*\t*\tABCDE12345\tcom.example.whoread.extension (0.1.0/1)\tWhoRead Extension\t[activated enabled]"
    private static let terminated = "1 extension(s)\n*\t*\tABCDE12345\tcom.example.whoread.extension (0.1.0/1)\tWhoRead Extension\t[terminated waiting to uninstall on reboot]"

    // MARK: - acceptance-m5.sh (scripts-packaging-1)

    /// Ask mode: after a kill while enforcing, the restarted daemon keeps enforcement as set and
    /// reports the unclean stop; the restart starts an empty latency window (so the summary must be
    /// printed before the kill).
    func testRestartAfterKillWhileEnforcingKeepsEnforcementOn() throws {
        let dir = TempDir()
        do {
            let core = try makeCore(dir)
            try core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
            for _ in 0..<100 { core.enforcer.recordResponse(micros: 300, missedDeadline: false) }
            XCTAssertEqual(core.status().latency.totalResponses, 100)
        }
        touch(dir.path("data/auth-armed"))
        let core = try makeCore(dir)
        let s = core.status()
        XCTAssertTrue(s.enforcementEnabled)
        XCTAssertTrue(s.enforcementActive)
        XCTAssertEqual(s.latency.totalResponses, 0)
        XCTAssertNil(s.latencyTripReason)
        let reason = try XCTUnwrap(s.uncleanStop)
        XCTAssertTrue(reason.contains("while enforcing"), reason)
        // The script expects the same after its SIGKILL, and runs the ask-mode checks.
        let m5 = try String(contentsOfFile: script("scripts/vm/acceptance-m5.sh"), encoding: .utf8)
        XCTAssertTrue(m5.contains("\"on \"*\"while enforcing\"*)"))
        XCTAssertFalse(m5.contains("latencyTripReason"))
        XCTAssertTrue(m5.contains("echo \"== ask mode\""))
    }

    /// "enforcement on" after "off" (the CLI kill-switch step) empties the percentile window.
    func testEnforcementOnAfterOffResetsTheLatencyWindow() throws {
        let dir = TempDir()
        let core = try makeCore(dir)
        try core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
        for _ in 0..<100 { core.enforcer.recordResponse(micros: 300, missedDeadline: false) }
        XCTAssertEqual(core.status().latency.samples, 100)
        try core.mutateSettings(peer: .inProcess) { $0.enforcementEnabled = false }
        try core.mutateSettings(peer: .inProcess, reenable: true) { $0.enforcementEnabled = true }
        XCTAssertEqual(core.status().latency.samples, 0)
    }

    func testM5ReportsLatencyBeforeTheResetsAndRearmsBeforeTheStopTest() throws {
        let m5 = try String(contentsOfFile: script("scripts/vm/acceptance-m5.sh"), encoding: .utf8)
        func at(_ s: String, from: String.Index? = nil) throws -> String.Index {
            try XCTUnwrap(m5.range(of: s, range: (from ?? m5.startIndex)..<m5.endIndex)?.lowerBound, s)
        }
        let latency = try at("echo \"== latency\"")
        // A burst of denied opens right before the summary, so p99 is not the max of a few samples.
        XCTAssertLessThan(try at("for _ in $(seq 200); do as_user /bin/cat \"$KEY\" >/dev/null 2>&1; done"), latency)
        XCTAssertLessThan(latency, try at("echo \"== kill switches"))
        XCTAssertLessThan(latency, try at("echo \"== daemon killed\""))
        let stop = try at("if [ \"${1:-}\" = \"--stop-test\" ]")
        XCTAssertLessThan(try at("\"$WR\" enforcement on", from: stop), try at("kill -STOP", from: stop))
        // Listings stay allowed and new files are blocked under the vault rule, which therefore
        // covers writes too.
        XCTAssertTrue(m5.contains("\"access\":\"any\""))
        XCTAssertTrue(m5.contains("allowed /bin/ls \"$VAULT/ssh\""))
        XCTAssertTrue(m5.contains("denied /usr/bin/touch \"$VAULT/ssh/m5-new\""))
    }

    /// As a job of the VM runner the script runs as root: every probe must still be the test user's
    /// (the vault is in that user's home), the answered question must be the one holding the probe
    /// (other questions can be open), and enforcement must be left as the script found it, so the
    /// next job does not run with enforcement on and nobody answering.
    func testM5AsARootVMJob() throws {
        let m5 = try String(contentsOfFile: script("scripts/vm/acceptance-m5.sh"), encoding: .utf8)
        let lines = m5.split(separator: "\n").map(String.init)
        // A bare probe (not through as_user / denied / allowed / as_agent) would run as root.
        for line in lines where line.contains("/bin/cat \"$") {
            XCTAssertTrue(line.contains("as_user /bin/cat") || line.contains("denied /bin/cat")
                          || line.contains("allowed /bin/cat") || line.contains("as_agent /bin/cat"), line)
        }
        XCTAssertTrue(m5.contains("denied() { as_user \"$@\""))
        XCTAssertTrue(m5.contains("allowed() { as_user \"$@\""))
        XCTAssertTrue(m5.contains("select(.key.categoryID == \"test-vault\" and .holding > 0"))
        XCTAssertFalse(m5.contains("jq -r 'if length > 0 then .[0].id else \"\" end'"))
        XCTAssertTrue(m5.contains("ENFORCEMENT_BEFORE=$(\"$WR\" status --json"))
        // The cleanup switches enforcement off before it puts the key back and removes m5-new (in
        // ask mode, with nothing answering, both would be denied), and switches it on again only if
        // it was on (unknown counts as off).
        let cleanup = try XCTUnwrap(m5.range(of: "cleanup() {"))
        let cleanupEnd = try XCTUnwrap(m5.range(of: "\n}\n", range: cleanup.upperBound..<m5.endIndex))
        let body = String(m5[cleanup.upperBound..<cleanupEnd.lowerBound])
        func pos(_ s: String) throws -> String.Index { try XCTUnwrap(body.range(of: s)?.lowerBound, s) }
        let off = try pos("sudo \"$WR\" enforcement off")
        XCTAssertLessThan(off, try pos("/bin/mv \"$TMPDIR/m5-moved\" \"$KEY\""))
        XCTAssertLessThan(off, try pos("\"$VAULT/ssh/m5-new\""))
        XCTAssertLessThan(try pos("\"$VAULT/ssh/m5-new\""), try pos("[ \"$ENFORCEMENT_BEFORE\" = true ] && sudo \"$WR\" enforcement on"))
        XCTAssertFalse(body.contains("= false ]"))
        // The probes write their copies, links and the moved key into a folder the test user owns.
        XCTAssertTrue(m5.contains("chown \"$TEST_USER\" \"$WORK\""))
        XCTAssertTrue(m5.contains("TMPDIR=\"$WORK\""))
        // No Python in the VM (no Command Line Tools): jq does the JSON and the clock.
        XCTAssertFalse(m5.contains("python3 -c 'import"))
        XCTAssertTrue(m5.contains("t() { jq -n 'now'; }"))
    }

    // MARK: - build.sh (scripts-packaging-2)

    private func buildCalls(team: Bool, env: [String: String] = [:]) throws -> [String] {
        let dir = TempDir()
        let root = dir.url.appendingPathComponent("repo")
        try FileManager.default.createDirectory(at: root.appendingPathComponent("scripts"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("Xcode"), withIntermediateDirectories: true)
        let build = root.appendingPathComponent("scripts/build.sh").path
        try FileManager.default.copyItem(atPath: script("scripts/build.sh"), toPath: build)
        let xcodegen = root.appendingPathComponent("scripts/xcodegen.sh").path
        try "#!/bin/bash\nexit 0\n".write(toFile: xcodegen, atomically: false, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: xcodegen)
        try (team ? "BUNDLE_ID_PREFIX = com.example\nDEVELOPMENT_TEAM = ABCDE12345\n" : "BUNDLE_ID_PREFIX = com.example\n")
            .write(to: root.appendingPathComponent("Xcode/Local.xcconfig"), atomically: false, encoding: .utf8)
        let r = try run(build, stubs: ["xcodebuild": "echo \"xcodebuild $*\" >> \"$LOG\""], env: env, in: dir)
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertEqual(r.calls.count, 3, "\(r.calls)")
        return r.calls
    }

    func testBuildWithTeamButNoESCapabilityDropsEntitlementsAndKeepsTheTeam() throws {
        for call in try buildCalls(team: true, env: ["WHOREAD_NO_ES": "1"]) {
            XCTAssertTrue(call.contains(" CODE_SIGN_ENTITLEMENTS= "), call)
            XCTAssertFalse(call.contains("CODE_SIGN_IDENTITY=-"), call)
            XCTAssertFalse(call.contains("DEVELOPMENT_TEAM="), call)
        }
    }

    func testBuildWithTeamKeepsEntitlementsByDefault() throws {
        for call in try buildCalls(team: true) {
            XCTAssertFalse(call.contains("CODE_SIGN_ENTITLEMENTS="), call)
        }
    }

    func testBuildWithoutTeamSignsAdHocWithoutEntitlements() throws {
        for call in try buildCalls(team: false, env: ["WHOREAD_NO_ES": "1"]) {
            XCTAssertTrue(call.contains("CODE_SIGN_IDENTITY=-"), call)
            XCTAssertTrue(call.contains(" CODE_SIGN_ENTITLEMENTS= "), call)
        }
    }

    // MARK: - uninstall scripts (scripts-packaging-3)

    private func linuxOnly() throws {
        #if !os(Linux)
        throw XCTSkip("runs the uninstall scripts against stubs; only where none of their paths exist")
        #endif
    }

    private let uninstallStubs = [
        "sudo": "echo \"sudo $*\" >> \"$LOG\"",
        "pkill": "exit 1",
        "launchctl": "echo \"launchctl $*\" >> \"$LOG\"",
        "systemextensionsctl": "printf '%s\\n' \"$SYSEXT\"",
    ]

    func testUninstallStopsWhenAnExtensionIsActiveAndTheAppIsMissing() throws {
        try linuxOnly()
        let dir = TempDir()
        for args in [[], ["--purge"]] {
            let r = try run(script("scripts/release/uninstall.sh"), args, stubs: uninstallStubs,
                            env: ["SYSEXT": Self.activated], in: dir)
            XCTAssertEqual(r.status, 1, "\(args)")
            XCTAssertTrue(r.stderr.contains("missing"), r.stderr)
            XCTAssertFalse(r.calls.contains { $0.contains(" rm ") }, "\(r.calls)")
        }
    }

    func testUninstallProceedsWhenNoExtensionIsActive() throws {
        try linuxOnly()
        let dir = TempDir()
        for state in ["0 extension(s)", Self.terminated] {
            let r = try run(script("scripts/release/uninstall.sh"), ["--purge"], stubs: uninstallStubs,
                            env: ["SYSEXT": state], in: dir)
            XCTAssertEqual(r.status, 0, r.stderr)
            XCTAssertTrue(r.calls.contains("sudo rm -rf /Applications/WhoRead.app"), "\(r.calls)")
            XCTAssertTrue(r.calls.contains("sudo rm -rf /Library/Application Support/WhoRead /Library/Logs/WhoRead"), "\(r.calls)")
        }
    }

    private let devStubs = [
        "id": "echo 0",
        "launchctl": "echo \"launchctl $*\" >> \"$LOG\"",
        "rm": "echo \"rm $*\" >> \"$LOG\"",
        "systemextensionsctl": "printf '%s\\n' \"$SYSEXT\"",
    ]

    func testDevUninstallPurgeRemovesNothingWhileTheExtensionIsActive() throws {
        try linuxOnly()
        let dir = TempDir()
        let purge = try run(script("scripts/uninstall-dev-daemon.sh"), ["--purge"], stubs: devStubs,
                            env: ["SYSEXT": Self.activated], in: dir)
        XCTAssertEqual(purge.status, 1)
        XCTAssertEqual(purge.calls, [])
        // Without --purge only the daemon goes; the data directory stays either way.
        let plain = try run(script("scripts/uninstall-dev-daemon.sh"), stubs: devStubs, env: ["SYSEXT": Self.activated], in: dir)
        XCTAssertEqual(plain.status, 0, plain.stderr)
        XCTAssertTrue(plain.calls.contains { $0.hasPrefix("rm -f /Library/LaunchDaemons/com.whoread.daemon.plist") }, "\(plain.calls)")
        XCTAssertFalse(plain.calls.contains { $0.contains("Application Support") }, "\(plain.calls)")
        let free = try run(script("scripts/uninstall-dev-daemon.sh"), ["--purge"], stubs: devStubs,
                           env: ["SYSEXT": "0 extension(s)"], in: dir)
        XCTAssertEqual(free.status, 0, free.stderr)
        XCTAssertTrue(free.calls.contains("rm -rf /Library/Application Support/WhoRead /Library/Logs/WhoRead"), "\(free.calls)")
        XCTAssertTrue(free.calls.contains("rm -f /usr/local/bin/whoread"), "\(free.calls)")
    }

    /// The dev uninstall (which the --purge refusal points to) keeps the release CLI link into the app.
    func testDevUninstallKeepsTheReleaseCLILink() throws {
        try linuxOnly()
        let dir = TempDir()
        var stubs = devStubs
        stubs["readlink"] = "echo /Applications/WhoRead.app/Contents/Helpers/whoread"
        let r = try run(script("scripts/uninstall-dev-daemon.sh"), stubs: stubs, env: ["SYSEXT": Self.activated], in: dir)
        XCTAssertEqual(r.status, 0, r.stderr)
        XCTAssertTrue(r.calls.contains("rm -f /Library/LaunchDaemons/com.whoread.daemon.plist /usr/local/libexec/whoreadd"), "\(r.calls)")
        XCTAssertFalse(r.calls.contains { $0.contains("/usr/local/bin/whoread") }, "\(r.calls)")
    }
}
