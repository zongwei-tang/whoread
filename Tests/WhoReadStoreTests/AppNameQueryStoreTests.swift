import XCTest
import WhoReadCore
@testable import WhoReadStore

/// cli-7: `whoread events --app TEXT` matched the file path too (the store's `text` search covers
/// name, program and path), so `--app claude` listed other programs reading files with "claude"
/// in their path. `EventQuery.appName` matches the app's and the program's names only; `text`
/// keeps its full search (`--search`).
final class AppNameQueryStoreTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("whoread-store-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: dir) }

    private func event(_ id: Int64, app: String, program: String, path: String) -> AnalyzedEvent {
        AnalyzedEvent(id: id, time: Date(timeIntervalSince1970: 1_760_000_000 + Double(id)), operation: .open, access: .read, path: path,
                      secondaryPath: nil, categoryID: "test-vault", severity: .critical,
                      process: ProcessRecord(pid: Int32(id), ppid: 1, executablePath: "/usr/local/bin/" + program), chain: [],
                      responsible: ResponsibleEntity(kind: .app, key: "app:/applications/\(app.lowercased()).app", displayName: app),
                      agentID: nil, isOwner: false, benignServiceID: nil, decision: .observed, ruleID: nil)
    }

    func testAppNameMatchesTheAppOrProgramNameButNotThePath() throws {
        let store = try SQLiteEventStore(path: dir.appendingPathComponent("db.sqlite").path)
        try store.insert([
            event(1, app: "Claude Code", program: "node", path: "/Users/alice/WhoReadTestVault/notes/todo.txt"),
            event(2, app: "Codex", program: "codex", path: "/Users/alice/WhoReadTestVault/claude-transcripts/a.jsonl"),
            event(3, app: "Terminal", program: "claude", path: "/Users/alice/WhoReadTestVault/ssh/id_ed25519"),
            // A name with the separator in it does not reach into the path.
            event(4, app: "Odd\u{1}Name", program: "tool", path: "/Users/alice/WhoReadTestVault/notes/claude.txt"),
        ])
        XCTAssertEqual(try store.events(EventQuery(appName: "CLAUDE")).map(\.id), [3, 1])
        XCTAssertEqual(try store.events(EventQuery(text: "claude")).map(\.id), [4, 3, 2, 1], "text (--search) still matches paths")
        XCTAssertEqual(try store.events(EventQuery(text: "claude", appName: "claude")).map(\.id), [3, 1])
        XCTAssertEqual(try store.events(EventQuery(appName: "code")).map(\.id), [2, 1], "Claude Code and codex")
        XCTAssertEqual(try store.events(EventQuery(appName: "")).count, 4)
        XCTAssertTrue(try store.events(EventQuery(appName: "transcripts")).isEmpty)
        XCTAssertTrue(try store.events(EventQuery(appName: "id_ed25519")).isEmpty)
    }
}
