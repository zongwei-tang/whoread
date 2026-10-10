import XCTest
import WhoReadCore
@testable import WhoReadStore

// Regression tests for review round 2, at store level.

final class RuleBackupRound2Tests: XCTestCase {
    var dir: URL!

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), isDirectory: true).appendingPathComponent("whoread-r2-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    private let future = #"{"id":"future","target":{"category":"ssh"},"subject":{"type":"teamOnly"},"action":"deny"}"#

    private func rule(_ id: String) -> Rule {
        Rule(id: id, enabled: true, target: .category("ssh"), subject: .anyNonOwner, action: .deny)
    }

    private func backup(_ path: String) throws -> [(id: String, body: Data)] {
        var out: [(String, Data)] = []
        try SQLiteDatabase(path: path).prepare("SELECT id, body FROM rules_backup ORDER BY saved_at, position").query { row in
            out.append((row.text(0) ?? "", row.blob(1)))
        }
        return out
    }

    // store-ipc-cli-1, engine-runtime-6
    func testSavingOverUnreadableRowsBacksUpEveryOldRowFirst() throws {
        let path = dir.appendingPathComponent("w.sqlite").path
        let store = try SQLiteEventStore(path: path)
        try store.saveRules([rule("a"), rule("b")])
        try store.saveRules([rule("a")])
        XCTAssertTrue(try backup(path).isEmpty, "replacing readable rows backs nothing up")

        // A row written by a newer version.
        try SQLiteDatabase(path: path).exec("INSERT INTO rules(id, position, body) VALUES('future', 1, CAST('\(future)' AS BLOB));")
        XCTAssertThrowsError(try store.loadRules())
        try store.saveRules([rule("c")])
        XCTAssertEqual(try store.loadRules()?.map(\.id), ["c"])
        let saved = try backup(path)
        XCTAssertEqual(saved.map(\.id), ["a", "future"], "the readable rows next to it are kept too")
        XCTAssertEqual(String(decoding: saved[1].body, as: UTF8.self), future, "byte for byte")
        XCTAssertEqual(try Exporter.decoder().decode(Rule.self, from: saved[0].body).id, "a")

        // Later saves of a readable table add nothing; reopening keeps the backup.
        try store.saveRules([rule("c"), rule("d")])
        let reopened = try SQLiteEventStore(path: path)
        try reopened.saveRules([rule("e")])
        XCTAssertEqual(try backup(path).count, 2)
    }

    // store-ipc-cli-1: a load that failed for another reason (an SQLite error) backs up rows that
    // decode by the time they are replaced: they were never loaded either.
    func testSavingAfterAFailedLoadBacksUpEvenReadableRows() throws {
        let path = dir.appendingPathComponent("w.sqlite").path
        let store = try SQLiteEventStore(path: path)
        try store.saveRules([rule("a"), rule("b")])
        let db = try SQLiteDatabase(path: path)
        try db.exec("ALTER TABLE rules RENAME TO rules_saved; CREATE TABLE rules(id TEXT PRIMARY KEY, position INTEGER NOT NULL);")
        XCTAssertThrowsError(try store.loadRules())
        try db.exec("DROP TABLE rules; ALTER TABLE rules_saved RENAME TO rules;")
        try store.saveRules([rule("c")])
        XCTAssertEqual(try backup(path).map(\.id), ["a", "b"])
        // Only the first save after the failure.
        try store.saveRules([rule("d")])
        XCTAssertEqual(try backup(path).count, 2)
        XCTAssertEqual(try store.loadRules()?.map(\.id), ["d"])
        try store.saveRules([rule("e")])
        XCTAssertEqual(try backup(path).count, 2, "a load that worked clears nothing it should keep")
    }

    // store-ipc-cli-1: the backup and the replacement are one transaction.
    func testAFailedBackupLeavesTheStoredRulesAsTheyWere() throws {
        let path = dir.appendingPathComponent("w.sqlite").path
        let store = try SQLiteEventStore(path: path)
        try store.saveRules([rule("a")])
        let db = try SQLiteDatabase(path: path)
        try db.exec("""
            INSERT INTO rules(id, position, body) VALUES('future', 1, CAST('\(future)' AS BLOB));
            CREATE TRIGGER fail_backup BEFORE INSERT ON rules_backup BEGIN SELECT RAISE(ABORT, 'disk full'); END;
            """)
        XCTAssertThrowsError(try store.saveRules([rule("c")]))
        var ids: [String] = []
        try db.prepare("SELECT id FROM rules ORDER BY position").query { ids.append($0.text(0) ?? "") }
        XCTAssertEqual(ids, ["a", "future"])
        XCTAssertTrue(try backup(path).isEmpty)
    }
}
