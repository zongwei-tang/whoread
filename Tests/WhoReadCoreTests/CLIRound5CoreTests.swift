import XCTest
@testable import WhoReadCore

/// Core parts of the round-5 command line fixes.
final class CLIRound5CoreTests: XCTestCase {
    // MARK: - cli-9: characters that display as blank

    /// U+2800 (BRAILLE PATTERN BLANK) and the few other symbols that render as nothing are not
    /// space separators, format or default-ignorable characters, so a name padded with them showed
    /// as a long blank: it could push the real path out of a banner or fake a CLI table's columns.
    func testBlankLookingSymbolsAreEscaped() {
        for u: Unicode.Scalar in ["\u{2800}", "\u{1D159}", "\u{FFFC}"] {
            XCTAssertTrue(DisplayText.isHidden(u), String(u.value, radix: 16))
        }
        let padded = "Terminal" + String(repeating: "\u{2800}", count: 30) + "SSH keys"
        let shown = DisplayText.name(padded)
        XCTAssertFalse(shown.unicodeScalars.contains("\u{2800}"), shown)
        XCTAssertTrue(shown.hasPrefix("Terminal\\u{2800}\\u{2800}"), shown)
        XCTAssertLessThanOrEqual(shown.unicodeScalars.count, DisplayText.nameLimit)
        XCTAssertEqual(DisplayText.escaped("a\u{1D159}b\u{FFFC}c"), "a\\u{1d159}b\\u{fffc}c")
        // Paths too (a folder named with blanks).
        XCTAssertEqual(DisplayText.path("~/\u{2800}\u{2800}/id_ed25519"), "~/\\u{2800}\\u{2800}/id_ed25519")
        // Braille that shows dots stays as it is.
        XCTAssertEqual(DisplayText.name("⠓⠑⠇⠇⠕"), "⠓⠑⠇⠇⠕")
        XCTAssertFalse(DisplayText.isHidden("\u{2801}"))
    }

    // MARK: - cli-4: alerts with the same update time come in id order

    private func alert(_ id: Int64, at t: Date) -> Alert {
        let who = ResponsibleEntity(kind: .binary, key: "bin:/users/alice/bin/tool-\(id)", displayName: "tool-\(id)",
                                    path: "/Users/alice/bin/tool-\(id)")
        return Alert(id: id, kind: .firstAccess, createdAt: t, updatedAt: t, windowEndsAt: t.addingTimeInterval(600), responsible: who,
                     categoryID: "test-vault", severity: .critical, count: 1, accesses: .read,
                     firstPath: "/Users/alice/WhoReadTestVault/ssh/id_ed25519", firstEventID: id, lastEventID: id, paths: [],
                     chain: [], agentID: nil, ruleID: nil)
    }

    // MARK: - cli-7: an app filter that leaves file paths out

    static func event(_ id: Int64, app: String, program: String, path: String) -> AnalyzedEvent {
        AnalyzedEvent(id: id, time: Date(timeIntervalSince1970: 1_760_000_000 + Double(id)), operation: .open, access: .read, path: path,
                      secondaryPath: nil, categoryID: "test-vault", severity: .critical,
                      process: ProcessRecord(pid: Int32(id), ppid: 1, executablePath: "/usr/local/bin/" + program), chain: [],
                      responsible: ResponsibleEntity(kind: .app, key: "app:/applications/\(app.lowercased()).app", displayName: app),
                      agentID: nil, isOwner: false, benignServiceID: nil, decision: .observed, ruleID: nil)
    }

    /// Another program reading a file whose path has the app's name in it.
    static let appFilterEvents = [
        event(1, app: "Claude Code", program: "node", path: "/Users/alice/WhoReadTestVault/notes/todo.txt"),
        event(2, app: "Codex", program: "codex", path: "/Users/alice/WhoReadTestVault/claude-transcripts/a.jsonl"),
        event(3, app: "Terminal", program: "claude", path: "/Users/alice/WhoReadTestVault/ssh/id_ed25519"),
    ]

    func testAppNameMatchesTheAppOrProgramNameButNotThePath() throws {
        let store = InMemoryEventStore()
        try store.insert(CLIRound5CoreTests.appFilterEvents)
        XCTAssertEqual(try store.events(EventQuery(appName: "CLAUDE")).map(\.id), [3, 1])
        XCTAssertEqual(try store.events(EventQuery(text: "claude")).map(\.id), [3, 2, 1], "text (--search) still matches paths")
        // What the CLI sends for --app: both (an older daemon applies text alone).
        XCTAssertEqual(try store.events(EventQuery(text: "claude", appName: "claude")).map(\.id), [3, 1])
        XCTAssertEqual(try store.events(EventQuery(appName: "")).count, 3)
        XCTAssertTrue(try store.events(EventQuery(appName: "transcripts")).isEmpty)
    }

    /// The field decodes from a query without it (an older client) and round-trips.
    func testAppNameIsOptionalOnTheWire() throws {
        let old = try JSONDecoder().decode(EventQuery.self, from: Data(#"{"agentsOnly":false,"includeBenign":false,"limit":5,"newestFirst":true}"#.utf8))
        XCTAssertNil(old.appName)
        var q = EventQuery(limit: 5)
        q.appName = "Terminal"
        XCTAssertEqual(try JSONDecoder().decode(EventQuery.self, from: JSONEncoder().encode(q)), q)
    }

    /// The in-memory store (replay) sorted only by `updatedAt`: alerts from one event (several
    /// categories) or one replayed instant came out in the dictionary's order, which differs
    /// from run to run, and a limit kept an arbitrary few. The SQLite store breaks ties by id.
    func testInMemoryAlertsBreakTiesByID() throws {
        let store = InMemoryEventStore()
        let t = Date(timeIntervalSince1970: 1_760_000_000)
        try store.upsert((1...60).map { alert($0, at: t) } + [alert(61, at: t.addingTimeInterval(-1))])
        XCTAssertEqual(try store.alerts(AlertQuery(limit: 100)).map(\.id), Array((1...60).reversed()) + [61])
        XCTAssertEqual(try store.alerts(AlertQuery(limit: 5)).map(\.id), [60, 59, 58, 57, 56])
    }
}
