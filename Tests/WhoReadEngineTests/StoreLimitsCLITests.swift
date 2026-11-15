import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// The CLI side of the summary and daily caps (daemon-6, ipc-1) and of `apps --since` (cli-6). Runs
/// the built `whoread` against a daemon on a dev socket: the real handler over an in-memory store, or
/// a stub that serves full replies. Needs a Unix socket, so inside a sandbox that forbids one these
/// skip and run on CI.
final class StoreLimitsCLITests: XCTestCase {
    override func setUpWithError() throws { try skipIfSocketBindDenied() }

    private static let binary: String? = {
        var dirs = Bundle.allBundles.filter { $0.bundlePath.hasSuffix(".xctest") }.map { $0.bundleURL.deletingLastPathComponent() }
        dirs.append(repoRoot.appendingPathComponent(".build/debug"))
        return dirs.map { $0.appendingPathComponent("whoread").path }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }()

    private struct Run {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    private func whoread(_ args: [String], socket: String, lang: String = "en") throws -> Run {
        guard let bin = StoreLimitsCLITests.binary else { throw XCTSkip("the whoread executable is not built") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["--socket", socket, "--lang", lang] + args
        p.environment = ["PATH": "/usr/bin:/bin", "HOME": ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), "TZ": "UTC"]
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        try p.run()
        let o = out.fileHandleForReading.readDataToEndOfFile()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Run(status: p.terminationStatus, stdout: String(decoding: o, as: UTF8.self), stderr: String(decoding: e, as: UTF8.self))
    }

    private func serve(_ handler: IPCHandler, _ dir: TempDir) throws -> (UnixSocketServer, String) {
        let path = dir.path("s.sock")
        let server = UnixSocketServer(path: path, handler: handler)
        try server.start()
        return (server, path)
    }

    private func core(_ dir: TempDir) throws -> DaemonCore {
        var config = baseConfig(dir)
        config.inMemoryStore = true
        config.resolveOwners = false
        return try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: false) })
    }

    private func access(_ id: Int64, app: Int, at time: Date) -> AnalyzedEvent {
        let bundle = "/tmp/m\(app).app"
        return AnalyzedEvent(
            id: id, time: time, operation: .open, access: .read, path: "/Users/alice/WhoReadTestVault/notes/secret.txt",
            secondaryPath: nil, categoryID: "test-vault", severity: .critical,
            process: ProcessRecord(pid: 900, ppid: 1, executablePath: bundle + "/cat", isPlatformBinary: false, argv: ["cat"]),
            chain: [ChainLink(pid: 1, name: "launchd", path: "/sbin/launchd")],
            responsible: ResponsibleEntity(kind: .app, key: "app:" + bundle, displayName: "m\(app)", path: bundle),
            agentID: nil, isOwner: false, benignServiceID: nil, decision: .observed, ruleID: nil)
    }

    private func row(_ text: String, app: String) -> String? {
        text.split(separator: "\n").map(String.init).first { $0.hasPrefix(app + " ") }
    }

    /// cli-6: `apps --since 1h` showed all-time FIRST and COUNT for any app active in the last hour.
    func testAppsSinceShowsTheWindow() throws {
        let dir = TempDir()
        let core = try core(dir)
        let now = Date()
        try core.store.insert((0..<5).map { access(Int64($0 + 1), app: 1, at: now.addingTimeInterval(-7200 + Double($0))) })
        try core.store.insert([access(6, app: 1, at: now.addingTimeInterval(-600)), access(7, app: 2, at: now.addingTimeInterval(-3 * 3600))])
        let (server, socket) = try serve(ServiceHandler(daemon: core, policy: .permissive), dir)
        defer { server.stop() }

        let window = try whoread(["apps", "--since", "1h"], socket: socket)
        XCTAssertEqual(window.status, 0, window.stderr)
        let m1 = try XCTUnwrap(row(window.stdout, app: "m1"), window.stdout)
        XCTAssertTrue(m1.hasSuffix(" 1"), "COUNT of the last hour: \(m1)")
        XCTAssertNil(row(window.stdout, app: "m2"), "m2 was not active in the last hour")
        XCTAssertFalse(window.stderr.contains("per-day totals"), window.stderr)

        let allTime = try whoread(["apps"], socket: socket)
        XCTAssertTrue(try XCTUnwrap(row(allTime.stdout, app: "m1"), allTime.stdout).hasSuffix(" 6"), allTime.stdout)

        let json = try whoread(["apps", "--since", "1h", "--json"], socket: socket)
        let rows = try Exporter.decoder().decode([UsageSummary].self, from: Data(json.stdout.utf8))
        XCTAssertEqual(rows.map(\.count), [1])

        // Past the detail window (7 days) the note says those days count whole, in both languages.
        let month = try whoread(["apps", "--since", "30d"], socket: socket)
        XCTAssertTrue(month.stderr.contains("kept only as per-day totals, so FIRST and COUNT take those days whole"), month.stderr)
        let zh = try whoread(["apps", "--since", "30d"], socket: socket, lang: "zh-Hans")
        XCTAssertTrue(zh.stderr.contains("按整天计入"), zh.stderr)
    }

    /// Serves `rows` summary rows and `days` daily rows, whatever was asked.
    private final class FullReplies: IPCHandler, @unchecked Sendable {
        let summaries: [UsageSummary]
        let daily: [DailyAggregate]
        let data: DefaultData

        init(rows: Int, days: Int) throws {
            data = try DefaultData.load(directory: repoRoot.appendingPathComponent("Data"))
            let t = Date(timeIntervalSince1970: 1_760_000_000)
            func summary(_ i: Int) -> UsageSummary {
                UsageSummary(responsible: ResponsibleEntity(kind: .app, key: "app:/tmp/m\(i).app", displayName: "m\(i)"),
                             categoryID: "test-vault", agentID: i % 2 == 0 ? "claude-code" : nil, firstSeen: t, lastSeen: t,
                             count: 1, reads: 1, writes: 0, denied: 0, benign: false)
            }
            summaries = (0..<rows).map(summary)
            daily = (0..<days).map { DailyAggregate(day: "2025-10-01", summary: summary($0)) }
        }

        func handle(_ request: IPCRequest, peer: IPCPeer) -> IPCResponse {
            switch request {
            case .hello: return .hello(serverVersion: whoReadIPCVersion)
            case .summaries: return .summaries(summaries)
            case .dailyAggregates: return .dailyAggregates(daily)
            case .settings: return .settings(Settings())
            case .catalog: return .catalog(CatalogInfo(catalog: data.catalog, detected: [:], prefixes: [], homeDirectories: ["/Users/alice"]))
            case .agents: return .agents(data.agents)
            default: return .error(IPCError(.invalid, "not served by this stub"))
            }
        }
    }

    /// daemon-6 / ipc-1: a view built from a full reply may be missing older rows; it says so, as
    /// `whoread baseline` does. A reply under the cap gets no note.
    func testViewsNoteAReplyAtTheCap() throws {
        let dir = TempDir()
        let full = try FullReplies(rows: UsageSummary.replyLimit, days: DailyAggregate.replyLimit)
        let (server, socket) = try serve(full, dir)
        defer { server.stop() }
        for command in ["apps", "files", "agents"] {
            let run = try whoread([command], socket: socket)
            XCTAssertEqual(run.status, 0, "\(command): \(run.stderr)")
            XCTAssertTrue(run.stderr.contains("the daemon sends the 10000 most recently active rows"), "\(command): \(run.stderr)")
            let zh = try whoread([command], socket: socket, lang: "zh-Hans")
            XCTAssertTrue(zh.stderr.contains("最近活动的 10000 行"), "\(command): \(zh.stderr)")
        }
        let daily = try whoread(["daily"], socket: socket)
        XCTAssertEqual(daily.status, 0, daily.stderr)
        XCTAssertTrue(daily.stderr.contains("the daemon sends the newest 10000 per-day rows"), daily.stderr)

        let fewerDir = TempDir()
        let (fewer, fewerSocket) = try serve(try FullReplies(rows: 3, days: 3), fewerDir)
        defer { fewer.stop() }
        for command in ["apps", "files", "agents", "daily"] {
            let run = try whoread([command], socket: fewerSocket)
            XCTAssertEqual(run.status, 0, "\(command): \(run.stderr)")
            XCTAssertFalse(run.stderr.contains("note:"), "\(command): \(run.stderr)")
        }
    }

    /// ipc-1: `export --aggregates` pages with the cursor like the event export, so the cap does not
    /// cut it; `--limit N` still exports the newest N, oldest day first.
    func testExportAggregatesPagesPastTheReplyCap() throws {
        let dir = TempDir()
        let core = try core(dir)
        let n = DailyAggregate.replyLimit + 5
        let old = Date(timeIntervalSince1970: 1_760_000_000)
        // One app per row, on three days.
        try core.store.insert((0..<n).map { access(Int64($0 + 1), app: $0, at: old.addingTimeInterval(Double($0 % 3) * 86_400 + Double($0))) })
        try core.store.applyRetention(detailCutoff: old.addingTimeInterval(10 * 86_400), retentionCutoff: old.addingTimeInterval(-86_400))
        let (server, socket) = try serve(ServiceHandler(daemon: core, policy: .permissive), dir)
        defer { server.stop() }

        let export = try whoread(["export", "--aggregates", "--format", "jsonl"], socket: socket)
        XCTAssertEqual(export.status, 0, export.stderr)
        let rows = try export.stdout.split(separator: "\n").map { try Exporter.decoder().decode(DailyAggregate.self, from: Data($0.utf8)) }
        XCTAssertEqual(rows.count, n)
        XCTAssertEqual(Set(rows.map(\.key)).count, n)
        XCTAssertEqual(rows.map(\.day), rows.map(\.day).sorted(), "oldest day first")

        let limited = try whoread(["export", "--aggregates", "--format", "jsonl", "--limit", "3"], socket: socket)
        let three = try limited.stdout.split(separator: "\n").map { try Exporter.decoder().decode(DailyAggregate.self, from: Data($0.utf8)) }
        XCTAssertEqual(three.map(\.key), Array(rows.suffix(3)).map(\.key), "the newest three, oldest first")
    }
}
