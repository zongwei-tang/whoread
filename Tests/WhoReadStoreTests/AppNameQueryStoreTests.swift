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
        XCTAssertEqual(try store.events(EventQuery(appName: "tool")).map(\.id), [4], "nor cuts the program's name off")
        XCTAssertEqual(try store.events(EventQuery(text: "claude")).map(\.id), [4, 3, 2, 1], "text (--search) still matches paths")
        XCTAssertEqual(try store.events(EventQuery(text: "claude", appName: "claude")).map(\.id), [3, 1])
        XCTAssertEqual(try store.events(EventQuery(appName: "code")).map(\.id), [2, 1], "Claude Code and codex")
        XCTAssertEqual(try store.events(EventQuery(appName: "")).count, 4)
        XCTAssertTrue(try store.events(EventQuery(appName: "transcripts")).isEmpty)
        XCTAssertTrue(try store.events(EventQuery(appName: "id_ed25519")).isEmpty)
    }

    /// store-2: `appName` looks before the second \u{1} of `search`, and a \u{1} in the app's name moved that
    /// cut forward, past the program's name: a program in a bundle named "Helper\u{1}" did not show under
    /// `whoread events --app` with its own name. Both stores find it; a needle with \u{1} in it matches
    /// within one name, never across two names or into the path.
    func testANameWithTheSeparatorDoesNotHideTheProgram() throws {
        let events = [
            event(1, app: "Helper\u{1}", program: "exfil", path: "/Users/alice/WhoReadTestVault/notes/key.txt"),
            event(2, app: "Notes", program: "notes", path: "/Users/alice/WhoReadTestVault/notes/todo.txt"),
            event(3, app: "Terminal", program: "exfil", path: "/Users/alice/WhoReadTestVault/notes/key.txt"),
            event(4, app: "A\u{1}B\u{1}C", program: "tool", path: "/Users/alice/WhoReadTestVault/notes/b.txt"),
            event(5, app: "Viewer", program: "viewer", path: "/Users/alice/WhoReadTestVault/notes/a\u{1}b.txt"),
        ]
        let stores: [(String, EventStore)] = [("sqlite", try SQLiteEventStore(path: dir.appendingPathComponent("db.sqlite").path)),
                                              ("memory", InMemoryEventStore())]
        for (name, store) in stores {
            try store.insert(events)
            XCTAssertEqual(try store.events(EventQuery(text: "exfil", appName: "exfil")).map(\.id), [3, 1], name)
            XCTAssertEqual(try store.events(EventQuery(appName: "EXFIL")).map(\.id), [3, 1], name)
            XCTAssertEqual(try store.events(EventQuery(appName: "helper")).map(\.id), [1], name)
            XCTAssertEqual(try store.events(EventQuery(appName: "tool")).map(\.id), [4], name)
            XCTAssertEqual(try store.events(EventQuery(appName: "b\u{1}c")).map(\.id), [4], name)
            XCTAssertEqual(try store.events(EventQuery(appName: "c\u{1}tool")).map(\.id), [], name)
            XCTAssertEqual(try store.events(EventQuery(text: "c\u{1}tool")).map(\.id), [], name)
            XCTAssertEqual(try store.events(EventQuery(text: "tool\u{1}/users")).map(\.id), [], name)
            XCTAssertEqual(try store.events(EventQuery(text: "key.txt")).map(\.id), [3, 1], name)
            XCTAssertEqual(try store.events(EventQuery(text: "a\u{1}b.txt")).map(\.id), [5], name)
            XCTAssertEqual(try store.events(EventQuery(appName: "a\u{1}b.txt")).map(\.id), [], name)
        }
    }

    /// Rows an older build wrote keep the names as they were in `search`. The first start rebuilds those with a
    /// \u{1} too many, once, so the program is found; a row whose body cannot be read is left as it is.
    func testRowsAnOlderBuildWroteAreRebuilt() throws {
        let path = dir.appendingPathComponent("db.sqlite").path
        let hidden = event(1, app: "Helper\u{1}", program: "exfil", path: "/Users/alice/WhoReadTestVault/notes/key.txt")
        let plain = event(2, app: "Notes", program: "notes", path: "/Users/alice/WhoReadTestVault/notes/todo.txt")
        let unreadable = event(3, app: "Odd\u{1}", program: "exfil", path: "/Users/alice/WhoReadTestVault/notes/key.txt")
        try SQLiteEventStore(path: path).insert([hidden, plain, unreadable])
        do {
            // As the older build wrote them: the names as they were, and no mark of the rebuild.
            let db = try SQLiteDatabase(path: path)
            for e in [hidden, plain, unreadable] {
                let old = (e.responsible.displayName + "\u{1}" + e.process.name + "\u{1}" + e.path).lowercased()
                try db.prepare("UPDATE events SET search = ? WHERE id = ?").run([.text(old), .int(e.id)])
            }
            try db.exec("UPDATE events SET body = x'00' WHERE id = 3; DELETE FROM meta WHERE key = 'search_format'")
        }
        let store = try SQLiteEventStore(path: path)
        XCTAssertEqual(try store.events(EventQuery(appName: "exfil")).map(\.id), [1])
        XCTAssertEqual(try store.events(EventQuery(appName: "helper")).map(\.id), [1])
        XCTAssertEqual(try store.events(EventQuery(appName: "notes")).map(\.id), [2])
        XCTAssertEqual(try store.events(EventQuery(text: "todo")).map(\.id), [2])
        let db = try SQLiteDatabase(path: path)
        var marked = false
        try db.prepare("SELECT 1 FROM meta WHERE key = 'search_format'").query { _ in marked = true }
        XCTAssertTrue(marked, "the rebuild is not run again at the next start")
        var search = ""
        try db.prepare("SELECT search FROM events WHERE id = 3").query { search = $0.text(0) ?? "" }
        XCTAssertEqual(search, "odd\u{1}\u{1}exfil\u{1}/users/alice/whoreadtestvault/notes/key.txt", "an unreadable body is left alone")
    }

    /// store-2, again: `replacingOccurrences` without `.literal` takes a \u{1} and the combining mark, variation
    /// selector, emoji modifier or joiner after it for one character, which is not \u{1}, so it left that \u{1}
    /// in the name and the cut came early again: a bundle named "Helper", \u{1}, U+0301 hid its program from
    /// `--app`. Each \u{1} is replaced on its own, in the app's name and in the program's.
    func testASeparatorBeforeACombiningMarkIsReplacedToo() throws {
        let tails = ["\u{301}", "\u{FE0F}", "\u{20DD}", "\u{1F3FB}", "\u{E0100}", "\u{200C}", "\u{1}\u{301}", ""]
        let key = "/Users/alice/WhoReadTestVault/notes/key.txt"
        let helpers = tails.enumerated().map { i, tail in event(Int64(i + 1), app: "Helper\u{1}" + tail, program: "exfil", path: key) }
        let events = helpers + [event(Int64(tails.count + 1), app: "Terminal", program: "ex\u{1}\u{301}fil", path: key)]
        for e in events {
            XCTAssertEqual(SQLiteEventStore.searchText(e).unicodeScalars.filter { $0 == "\u{1}" }.count, 2,
                           "only the two separators: \(e.responsible.displayName.debugDescription), \(e.process.name.debugDescription)")
        }
        let stores: [(String, EventStore)] = [("sqlite", try SQLiteEventStore(path: dir.appendingPathComponent("db.sqlite").path)),
                                              ("memory", InMemoryEventStore())]
        for (name, store) in stores {
            try store.insert(events)
            XCTAssertEqual(try store.events(EventQuery(text: "exfil", appName: "exfil")).map(\.id), Array(helpers.map(\.id).reversed()), name)
            XCTAssertEqual(try store.events(EventQuery(appName: "helper")).map(\.id), Array(helpers.map(\.id).reversed()), name)
            XCTAssertEqual(try store.events(EventQuery(appName: "fil")).map(\.id), Array(events.map(\.id).reversed()), name)
        }
    }

    /// The earlier builds wrote such a row with that \u{1} left in, the one that marked the store "2" among
    /// them (its rebuild wrote the same again). A store not marked as this build writes `search` is rebuilt.
    func testRowsTheFirstRebuildLeftAreRebuilt() throws {
        let e = event(1, app: "Helper\u{1}\u{301}", program: "exfil", path: "/Users/alice/WhoReadTestVault/notes/key.txt")
        for mark in [nil, "2"] as [String?] {
            let path = dir.appendingPathComponent("db-\(mark ?? "none").sqlite").path
            do {
                let store = try SQLiteEventStore(path: path)
                try store.insert([e])
                // As those builds left it: the \u{1} before the combining mark in the name, and their mark.
                let db = try SQLiteDatabase(path: path)
                try db.prepare("UPDATE events SET search = ? WHERE id = 1")
                    .run([.text("helper\u{1}\u{301}\u{1}exfil\u{1}/users/alice/whoreadtestvault/notes/key.txt")])
                try store.setValue(mark.map { Data($0.utf8) }, forKey: SQLiteEventStore.searchFormatKey)
            }
            let store = try SQLiteEventStore(path: path)
            XCTAssertEqual(try store.events(EventQuery(text: "exfil", appName: "exfil")).map(\.id), [1], "marked \(mark ?? "none")")
            XCTAssertEqual(try store.events(EventQuery(appName: "helper")).map(\.id), [1], "marked \(mark ?? "none")")
            XCTAssertEqual(try store.value(forKey: SQLiteEventStore.searchFormatKey).map { String(decoding: $0, as: UTF8.self) }, "3",
                           "marked \(mark ?? "none")")
        }
    }
}
