import Foundation
import XCTest
import WhoReadCore
@testable import WhoReadEngine

/// Command line checks that need no daemon: the built `whoread` runs with `--socket` pointing at a
/// socket that does not exist. A command that gets past its argument checks then fails with the
/// "cannot reach the daemon" status (69); a usage error is 64 and comes first. `replay` and the
/// kill switch run locally. (Tests that need a daemon reply are in CLIStubDaemonTests.)
final class CLIArgumentsTests: XCTestCase {
    private static let binary: String? = {
        var dirs = Bundle.allBundles.filter { $0.bundlePath.hasSuffix(".xctest") }.map { $0.bundleURL.deletingLastPathComponent() }
        dirs.append(repoRoot.appendingPathComponent(".build/debug"))
        return dirs.map { $0.appendingPathComponent("whoread").path }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }()

    private struct Run {
        let status: Int32
        let reason: Process.TerminationReason
        let stdout: String
        let stderr: String
    }

    private let dir = TempDir()
    /// A socket path nothing listens on.
    private var noDaemon: String { dir.path("none.sock") }

    /// Runs `whoread --socket <none> --lang LANG ARGS` (`socket: false` leaves `--socket` out).
    /// `shell` wraps the call in `/bin/sh -c` (`"$0" "$@"` is the call).
    private func whoread(_ args: [String], lang: String = "en", socket: Bool = true, cwd: String? = nil,
                         shell: String? = nil) throws -> Run {
        guard let bin = CLIArgumentsTests.binary else { throw XCTSkip("the whoread executable is not built") }
        let p = Process()
        let argv = (socket ? ["--socket", noDaemon] : []) + ["--lang", lang] + args
        if let shell {
            p.executableURL = URL(fileURLWithPath: "/bin/sh")
            p.arguments = ["-c", shell, bin] + argv
        } else {
            p.executableURL = URL(fileURLWithPath: bin)
            p.arguments = argv
        }
        if let cwd { p.currentDirectoryURL = URL(fileURLWithPath: cwd, isDirectory: true) }
        p.environment = ["PATH": "/usr/bin:/bin", "HOME": dir.url.path, "TZ": "UTC"]
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        try p.run()
        let o = out.fileHandleForReading.readDataToEndOfFile()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Run(status: p.terminationStatus, reason: p.terminationReason,
                   stdout: String(decoding: o, as: UTF8.self), stderr: String(decoding: e, as: UTF8.self))
    }

    private func assertUsageError(_ args: [String], cwd: String? = nil, _ message: String? = nil,
                                  file: StaticString = #filePath, line: UInt = #line) throws {
        let r = try whoread(args, cwd: cwd)
        XCTAssertEqual(r.reason, .exit, "\(args) crashed: \(r.stderr)", file: file, line: line)
        XCTAssertEqual(r.status, 64, "\(args) is not a usage error: \(r.stderr)", file: file, line: line)
        XCTAssertFalse(r.stderr.contains("cannot reach"), "\(args) was checked only after connecting: \(r.stderr)", file: file, line: line)
        if let message { XCTAssertTrue(r.stderr.contains(message), "\(args): \(r.stderr)", file: file, line: line) }
    }

    /// Got past every argument check: the next step is connecting, which fails here.
    private func assertAccepted(_ args: [String], cwd: String? = nil, file: StaticString = #filePath, line: UInt = #line) throws {
        let r = try whoread(args, cwd: cwd)
        XCTAssertEqual(r.reason, .exit, "\(args) crashed: \(r.stderr)", file: file, line: line)
        XCTAssertEqual(r.status, 69, "\(args) was refused: \(r.stderr)", file: file, line: line)
        XCTAssertTrue(r.stderr.contains("cannot reach"), "\(args): \(r.stderr)", file: file, line: line)
    }

    // MARK: - cli-2: unknown, misspelled or misplaced options are usage errors

    func testUnknownAndMisspelledOptionsAreUsageErrors() throws {
        let out = dir.path("ssh.csv")
        let cases: [([String], String)] = [
            (["events", "--agent-only"], "--agent-only"),
            (["export", "--format", "csv", "--since", "7d", "--catgory", "ssh", "--output", out], "--catgory"),
            (["events", "--catgory=ssh", "--since", "1h"], "--catgory"),
            (["events", "-since", "1h"], "-since"),
            (["export", "-ofile.csv"], "-ofile.csv"),
            (["export", "--json=false"], "--json"),
            (["alerts", "--unread=no"], "--unread"),
            // An option of another command.
            (["status", "--limit", "5"], "--limit"),
            (["tail", "--since", "1h"], "--since"),
            (["daily", "--format", "csv"], "--format"),
            (["asks", "--all"], "--all"),
            // A value flag given twice keeps one value: refused, not half applied.
            (["events", "--app", "Terminal", "--app", "Zoom"], "--app"),
            // No value after it.
            (["events", "--since"], "--since"),
        ]
        for (args, word) in cases { try assertUsageError(args, word) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: out), "nothing is written for a refused export")
    }

    func testStrayPositionalsAreUsageErrors() throws {
        for args in [["status", "now"], ["events", "ssh"], ["alerts", "5"], ["asks", "7"], ["read-all", "5"], ["pause", "1h"],
                     ["version", "x"], ["apps", "Zoom"], ["rules", "list", "x"], ["catalog", "show", "ssh", "x"],
                     ["settings", "show", "x"], ["baseline", "x"], ["kill-switch", "status", "x"],
                     ["enforcement", "on", "now"], ["replay", dir.path("a.jsonl"), dir.path("b.jsonl")]] {
            try assertUsageError(args)
        }
    }

    func testValidOptionsStillReachTheDaemon() throws {
        try assertAccepted(["events", "--agents-only"])
        try assertAccepted(["events", "--since", "1h", "--until", "2026-10-04 09:30", "--category", "ssh", "--category", "aws",
                            "--app", "Terminal", "--agent", "claude-code", "--denied", "--all", "--limit", "10", "--json"])
        try assertAccepted(["events", "--since=2026-10-04", "--limit=3"])
        try assertAccepted(["alerts", "--unread", "--since", "2d", "--limit", "5"])
        try assertAccepted(["export", "--format", "csv", "-o", dir.path("x.csv"), "--since", "7d", "--category", "test-vault"])
        try assertAccepted(["export", "--aggregates", "--format", "json", "--output", dir.path("x.json"), "--since", "30d"])
        try assertAccepted(["catalog", "add-category", "tax", "Tax", "税务", "high", "--path", "~/Tax", "--path", "/Volumes/Tax"])
        try assertAccepted(["rules", "replace", "--json-file", dir.path("r.json"), "--confirm"])
        // `--` ends the options: what follows is a positional even if it starts with a dash.
        try assertAccepted(["rules", "delete", "--", "-old-rule"])
    }

    /// Every way scripts/, README.md, README.zh-CN.md, docs/ and the tests call whoread (without the
    /// `sudo`, files under a temporary folder) still gets past the argument checks. A daemon query
    /// then fails to connect (69); a local command does its job.
    func testDocumentedInvocationsStillParse() throws {
        let f = dir.path("f")
        let daemonCommands: [[String]] = [
            // README.md, README.zh-CN.md
            ["status"], ["events", "--since", "1h"], ["events", "--agents-only"], ["alerts"], ["apps"],
            ["export", "--format", "csv", "--since", "7d", "--output", f + ".csv"], ["catalog", "show"],
            ["catalog", "add-path", "ssh", "~/keys/"], ["catalog", "add-path", "ssh", "/Users/alice/keys/"],
            ["asks"], ["ask", "7", "deny"], ["ask", "7", "block"], ["ask", "7", "allow-once"], ["ask", "7", "allow"],
            ["enforcement", "off"],
            // docs/ and the help
            ["ask", "7", "trust-apple"], ["settings", "set", "trust-apple", "on"], ["settings", "set", "trust-apple", "off"],
            ["rules"], ["settings", "set", "learning-days", "3"], ["catalog", "resolve-owners"], ["baseline"],
            ["baseline", "restart-learning"], ["rules", "replace", "--json-file", f, "--confirm"], ["export", "--output", f],
            ["catalog", "export", "--output", f], ["daily"], ["export", "--aggregates"], ["export"], ["events"],
            ["tail"], ["tail", "--all"], ["alert", "5", "block"], ["alert", "5", "allow-once"], ["alert", "5", "always-allow"],
            ["alert", "5", "keep-blocking"], ["alert", "5", "ignore"], ["read-all"], ["files"], ["agents"],
            ["daily", "--since", "30d", "--category", "ssh"], ["enforcement", "on"], ["enforcement", "status"], ["enforcement"],
            ["pause"], ["resume"], ["rules", "list"], ["rules", "templates"], ["rules", "add", "--json-file", f],
            ["rules", "enable", "r1"], ["rules", "disable", "r1"], ["rules", "enforce", "r1"], ["rules", "dry-run", "r1"],
            ["rules", "delete", "r1"], ["catalog"], ["catalog", "show", "ssh"], ["catalog", "export"],
            ["catalog", "remove-path", "ssh", "~/keys/"], ["catalog", "add-category", "tax", "Tax", "税务", "high"],
            ["catalog", "remove-category", "tax"], ["catalog", "set-severity", "tax", "critical"], ["catalog", "enable", "tax"],
            ["catalog", "disable", "tax"], ["catalog", "import", f], ["catalog", "reset"], ["settings"], ["settings", "show"],
            ["settings", "set", "retention-days", "30"], ["settings", "set", "detail-days", "7"],
            ["settings", "set", "coalesce-minutes", "10"], ["settings", "set", "readdir", "on"],
            ["settings", "set", "project-root-add", "~/code"], ["settings", "set", "project-root-remove", "~/code"],
            ["settings", "set", "notifications", "off"], ["settings", "set", "min-severity", "high"],
            ["settings", "set", "latency-p99-ms", "50"], ["settings", "set", "language", "zh-Hans"],
            ["settings", "set", "language", "system"],
            // scripts/install.sh, acceptance-m2.sh, ci/install-acceptance.sh, vm/provision.sh, vm/acceptance-m5.sh
            ["status", "--json"], ["events", "--since", "2m", "--category", "test-vault", "--json"],
            ["events", "--since", "1m", "--json"], ["events", "--since", "2026-11-14T20:00:00Z", "--json"],
            ["events", "--since", "2m", "--all", "--json"], ["events", "--since", "2m", "--json"],
            ["events", "--since", "5m", "--category", "test-vault"], ["export", "--format", "json", "--since", "5m", "--output", f + ".json"],
            ["export", "--format", "csv", "--since", "5m", "--output", f + ".csv"], ["events", "--limit", "1"],
            ["events", "--limit", "1", "--json"], ["rules", "dry-run", "template.block-agents-critical"],
            ["rules", "disable", "template.block-agents-critical"], ["rules", "delete", "m5-deny-vault"],
            ["rules", "enforce", "template.block-agents-critical"], ["events", "--denied", "--since", "2m", "--json"],
            ["asks", "--json"], ["ask", "12", "allow-once"],
            // scripts/dev/e2e-dev-socket.sh
            ["files"], ["export", "--format", "csv"], ["settings", "set", "language", "zh"],
            ["ask", "999999", "deny"], ["catalog", "add-path", "custom", "/Users/alice/Tax Docs"], ["export", "--format", "jsonl"],
            // the CLI tests
            ["alert", "5", "trust-apple"], ["export", "--format", "json"], ["ask", "8", "always-allow"], ["ask", "8", "keep-blocking"],
        ]
        for args in daemonCommands { try assertAccepted(args) }

        // Local commands.
        let fixtureCopy = dir.path("raw.jsonl")
        try FileManager.default.copyItem(atPath: fixtureV10, toPath: fixtureCopy)
        let data = repoRoot.appendingPathComponent("Data").path
        let ks = dir.path("disable-enforcement")
        let local: [[String]] = [
            ["version"], ["help"],
            ["kill-switch", "engage", "--path", ks], ["kill-switch", "status", "--path", ks], ["kill-switch", "--path", ks],
            ["kill-switch", "release", "--path", ks],
            ["replay", fixtureV10, "--home", "/Users/alice", "--defaults", data],
            ["replay", fixtureV10, "--home", "/Users/alice", "--defaults", data, "--all"],
            ["replay", fixtureV10, "--home", "/Users/alice", "--defaults", data, "--all", "--json"],
            ["fixture", "sanitize", "--home", "/Users/alice", "--input", fixtureCopy, "--output", dir.path("sanitized.jsonl"),
             "--vault", "/Users/alice/WhoReadTestVault", "--capture-pid", "4242", "--sample", "40"],
        ]
        for args in local {
            let r = try whoread(args, socket: false)
            XCTAssertEqual(r.reason, .exit, "\(args) crashed: \(r.stderr)")
            XCTAssertEqual(r.status, 0, "\(args): \(r.stderr)")
        }
    }

    // MARK: - cli-10: exit codes; usage errors before connecting

    func testHelpFlagsExitZero() throws {
        for args in [["-h"], ["--help"], ["help"], ["events", "--help"], ["events", "-h"]] {
            let r = try whoread(args, socket: false)
            XCTAssertEqual(r.status, 0, "\(args): \(r.stderr)")
            XCTAssertTrue(r.stdout.contains("Usage: whoread"), "\(args)")
        }
        XCTAssertEqual(try whoread([], socket: false).status, 64, "no command at all is a usage error")
    }

    func testUsageErrorsOfKnownCommandsComeBeforeConnecting() throws {
        let rules = dir.path("rules.json")
        for args in [["alert"], ["alert", "5"], ["alert", "x", "block"], ["alert", "5", "maybe"], ["alert", "5", "block", "now"],
                     ["ask"], ["ask", "5", "maybe"], ["ask", "5", "deny", "now"],
                     ["export", "--format", "xml"], ["enforcement", "maybe"],
                     ["rules", "frob"], ["rules", "add"], ["rules", "replace", "--json-file", rules], ["rules", "delete"],
                     ["rules", "enable", "a", "b"],
                     ["catalog", "frob"], ["catalog", "add-path", "custom"], ["catalog", "add-path", "custom", "/Users/alice/Tax", "Docs"],
                     ["catalog", "add-path", "custom", "relative/path"], ["catalog", "add-path", "custom", "/"],
                     ["catalog", "set-severity", "custom", "extreme"], ["catalog", "add-category", "Bad_ID", "Tax", "税务", "high"],
                     ["catalog", "add-category", "tax", "Tax", "税务", "high", "--path", "Tax"],
                     ["settings", "set", "nope", "1"], ["settings", "set", "readdir", "maybe"], ["settings", "set", "language", "english"],
                     ["settings", "set", "retention-days", "1.5"], ["settings", "set", "min-severity", "low"], ["settings", "frob"],
                     ["baseline", "frob"], ["kill-switch", "frob"], ["fixture"], ["fixture", "sanitize"], ["replay"], ["frobnicate"]] {
            try assertUsageError(args)
        }
    }

    /// The kill switch says "run with sudo" (77) only when permission is what failed.
    func testKillSwitchFailureSaysWhatWentWrong() throws {
        let missing = dir.path("no-such-folder/disable-enforcement")
        let r = try whoread(["kill-switch", "engage", "--path", missing], socket: false)
        XCTAssertEqual(r.status, 1, r.stderr)
        XCTAssertFalse(r.stderr.contains("sudo"), r.stderr)
        XCTAssertTrue(r.stderr.contains("No such file or directory"), r.stderr)

        try XCTSkipIf(geteuid() == 0, "root may write anywhere")
        let locked = dir.path("locked")
        XCTAssertEqual(mkdir(locked, 0o500), 0)
        defer { chmod(locked, 0o700) }
        let denied = try whoread(["kill-switch", "engage", "--path", locked + "/disable-enforcement"], socket: false)
        XCTAssertEqual(denied.status, 77, denied.stderr)
        XCTAssertTrue(denied.stderr.contains("sudo"), denied.stderr)
    }

    // MARK: - cli-5: values that do not parse are usage errors, never the default

    func testLimitsAndTimesThatDoNotParseAreUsageErrors() throws {
        let out = dir.path("all.jsonl")
        for args in [["export", "--format", "jsonl", "--limit", "1e6", "--output", out], ["export", "--limit", "all"],
                     ["events", "--limit", "10k"], ["events", "--limit", "-5"], ["events", "--limit", ""], ["daily", "--limit", "all"],
                     ["alerts", "--limit", "x"],
                     // A negative span would be a window in the future.
                     ["events", "--since", "-2h"], ["alerts", "--since", "-1d"], ["export", "--until", "-3d"],
                     // Days that do not exist are not moved into the next month.
                     ["events", "--since", "2026-02-31"], ["events", "--until", "2026-02-30 10:00"], ["events", "--since", "2026-04-31T00:00:00Z"],
                     ["events", "--since", "2026-13-01"], ["daily", "--since", "2026-02-29"], ["apps", "--since", "2025-02-29"]] {
            try assertUsageError(args)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: out))
        for args in [["events", "--limit", "0"], ["events", "--since", "2028-02-29"], ["events", "--since", "1w"],
                     ["events", "--since", "2026-10-04T09:30:00+02:00"], ["export", "--limit", "10"], ["apps", "--since", "2d"]] {
            try assertAccepted(args)
        }
    }

    // MARK: - cli-1: project roots that would never be monitored

    func testProjectRootsThatCanNeverBeMonitoredAreRefusedBeforeConnecting() throws {
        for value in ["/", "~", "~/", "~code", "~alice/code", "~/..", "~/./code", "/Users", "/System/Volumes/Data", "/Users/alice/../bob", ""] {
            try assertUsageError(["settings", "set", "project-root-add", value])
        }
        // `.` in / is the whole disk.
        try assertUsageError(["settings", "set", "project-root-add", "."], cwd: "/")
        // A relative path is a folder under the current one: accepted (the daemon is asked next).
        let project = dir.path("app")
        XCTAssertEqual(mkdir(project, 0o755), 0)
        for value in [".", "src", "./src", "../app", "~/code", "/Users/alice/code/app"] {
            try assertAccepted(["settings", "set", "project-root-add", value], cwd: project)
        }
        try assertAccepted(["settings", "set", "project-root-remove", "."], cwd: project)
    }

    // MARK: - help text

    func testHelpStatesDefaultsAndWhatFiltersMatch() throws {
        let r = try whoread(["help"], socket: false)
        XCTAssertEqual(r.status, 0)
        let help = r.stdout
        // cli-3: how many lines a listing shows by default.
        XCTAssertTrue(help.contains("--limit N (default 500)"), help)
        XCTAssertTrue(help.contains("alerts [--unread] [--since …] [--limit N (default 200)]"), help)
        // cli-5: export's --limit keeps the oldest N.
        XCTAssertTrue(help.contains("--limit N: the oldest N"), help)
        // cli-7: what --app and --search match.
        XCTAssertTrue(help.contains("--app TEXT (app or program name)"), help)
        XCTAssertTrue(help.contains("--search TEXT (app or program name, or file path)"), help)
        // Ask mode stays documented without a learning period (AskCLITests).
        XCTAssertFalse(help.lowercased().contains("learning"), help)
    }

    // MARK: - cli-7: --search keeps the old match; daily has names only

    func testSearchIsAnEventFilterButNotADailyOne() throws {
        try assertAccepted(["events", "--search", "id_ed25519"])
        try assertAccepted(["export", "--format", "csv", "--search", "WhoReadTestVault"])
        try assertAccepted(["daily", "--app", "Terminal"])
        try assertUsageError(["daily", "--search", "Terminal"], "--search")
        try assertUsageError(["export", "--aggregates", "--search", "Terminal"], "--search")
    }

    // MARK: - closed standard error

    /// The legacy `FileHandle.write(_:)` raises on a write error, and an uncaught Objective-C
    /// exception aborts: with standard error closed, any message (here "cannot reach") crashed.
    func testClosedStandardErrorDoesNotAbort() throws {
        let r = try whoread(["status"], shell: "exec \"$0\" \"$@\" 2>&-")
        XCTAssertEqual(r.reason, .exit, "aborted with signal \(r.status)")
        XCTAssertEqual(r.status, 69)
        let usage = try whoread(["events", "--catgory", "ssh"], shell: "exec \"$0\" \"$@\" 2>&-")
        XCTAssertEqual(usage.reason, .exit, "aborted with signal \(usage.status)")
        XCTAssertEqual(usage.status, 64)
    }

    // MARK: - cli-4: replay reports every alert

    /// `count` unsigned programs, each reading the test vault's SSH key once (taken from the
    /// msgv10 capture's node read): one first-access alert each.
    private func manyReaders(_ count: Int) throws -> String {
        let lines = try String(contentsOfFile: fixtureV10, encoding: .utf8).split(separator: "\n")
        let source = try XCTUnwrap(lines.first { $0.contains("\"open\"") && $0.contains("bin\\/node") && $0.contains("ssh\\/id_ed25519") })
        var out: [String] = []
        for i in 0..<count {
            var event = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(source.utf8)) as? [String: Any])
            event["seq_num"] = 5000 + i
            event["global_seq_num"] = 5000 + i
            event["mach_time"] = 99_001_015_000 + i * 1000
            var process = try XCTUnwrap(event["process"] as? [String: Any])
            var token = try XCTUnwrap(process["audit_token"] as? [String: Any])
            token["pid"] = 10_000 + i
            token["pidversion"] = 20_000 + i
            process["audit_token"] = token
            process["responsible_audit_token"] = token
            var parent = try XCTUnwrap(process["parent_audit_token"] as? [String: Any])
            parent["pid"] = 1
            process["parent_audit_token"] = parent
            process["ppid"] = 1
            process["original_ppid"] = 1
            process["group_id"] = 10_000 + i
            process["signing_id"] = String(format: "tool-%03d", i)
            process["cdhash"] = String(format: "%040X", i + 1)
            var executable = try XCTUnwrap(process["executable"] as? [String: Any])
            executable["path"] = String(format: "/Users/alice/bin/tool-%03d", i)
            process["executable"] = executable
            event["process"] = process
            out.append(String(decoding: try JSONSerialization.data(withJSONObject: event, options: [.sortedKeys]), as: UTF8.self))
        }
        let path = dir.path("many.jsonl")
        try (out.joined(separator: "\n") + "\n").write(toFile: path, atomically: false, encoding: .utf8)
        return path
    }

    func testReplayReportsEveryAlert() throws {
        let capture = try manyReaders(300)
        let data = repoRoot.appendingPathComponent("Data").path
        let text = try whoread(["replay", capture, "--home", "/Users/alice", "--defaults", data], socket: false)
        XCTAssertEqual(text.status, 0, text.stderr)
        XCTAssertTrue(text.stdout.contains("300 sensitive accesses, 300 alerts"), String(text.stdout.suffix(300)))
        XCTAssertEqual(text.stdout.split(separator: "\n").filter { $0.hasPrefix("#") }.count, 300, "one line per alert")

        let json = try whoread(["replay", capture, "--home", "/Users/alice", "--defaults", data, "--json"], socket: false)
        XCTAssertEqual(json.status, 0, json.stderr)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.stdout.utf8)) as? [String: Any])
        XCTAssertEqual((object["alerts"] as? [Any])?.count, 300)
        XCTAssertEqual((object["events"] as? [Any])?.count, 300)
    }

    // MARK: - cli-11: local messages in Chinese

    func testKillSwitchMessagesFollowTheLanguage() throws {
        let path = dir.path("disable-enforcement")
        let status = try whoread(["kill-switch", "status", "--path", path], lang: "zh-Hans", socket: false)
        XCTAssertEqual(status.status, 0, status.stderr)
        XCTAssertEqual(status.stdout, "kill switch 未启用\n")
        let engage = try whoread(["kill-switch", "engage", "--path", path], lang: "zh-Hans", socket: false)
        XCTAssertEqual(engage.status, 0, engage.stderr)
        XCTAssertTrue(engage.stdout.hasPrefix("kill switch 已启用："), engage.stdout)
        XCTAssertEqual(try whoread(["kill-switch", "status", "--path", path], lang: "zh-Hans", socket: false).stdout,
                       "kill switch 已启用（\(path)）\n")
        let release = try whoread(["kill-switch", "release", "--path", path], lang: "zh-Hans", socket: false)
        XCTAssertEqual(release.stdout, "kill switch 已解除\n")
        // English stays as it was.
        XCTAssertEqual(try whoread(["kill-switch", "status", "--path", path], socket: false).stdout, "kill switch not engaged\n")
    }
}
