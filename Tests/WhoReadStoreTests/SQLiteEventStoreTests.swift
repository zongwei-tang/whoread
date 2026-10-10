import XCTest
import WhoReadCore
@testable import WhoReadStore

final class SQLiteEventStoreTests: XCTestCase {
    var dir: URL!

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), isDirectory: true).appendingPathComponent("whoread-store-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    let t0 = Date(timeIntervalSince1970: 1_760_000_000)

    func event(_ id: Int64, _ dt: TimeInterval, category: String = "ssh", app: String = "Terminal", agent: String? = nil,
               benign: Bool = false, access: AccessSet = .read, decision: EventDecision = .observed,
               path: String = "/Users/alice/.ssh/id_rsa") -> AnalyzedEvent {
        AnalyzedEvent(
            id: id, time: t0.addingTimeInterval(dt), operation: .open, access: access, path: path, secondaryPath: nil,
            categoryID: category, severity: .critical,
            process: ProcessRecord(pid: Int32(id), ppid: 1, executablePath: "/bin/cat", isPlatformBinary: true, argv: ["cat"]),
            chain: [ChainLink(pid: 1, name: "launchd", path: "/sbin/launchd"), ChainLink(pid: Int32(id), name: "cat", path: "/bin/cat")],
            responsible: ResponsibleEntity(kind: agent == nil ? .app : .agent, key: agent.map { "agent:" + $0 } ?? "app:/" + app.lowercased(),
                                           displayName: agent ?? app, agentID: agent),
            agentID: agent, isOwner: false, benignServiceID: benign ? "spotlight" : nil, decision: decision, ruleID: nil)
    }

    func testRoundTripAndQueries() throws {
        let path = dir.appendingPathComponent("db.sqlite").path
        let store = try SQLiteEventStore(path: path)
        let events = [
            event(1, 0), event(2, 10, category: "aws"), event(3, 20, benign: true), event(4, 30, agent: "claude-code"),
            event(5, 40, decision: .denied, path: "/Users/alice/.ssh/id_ed25519"),
        ]
        try store.insert(events)
        XCTAssertEqual(try store.events(EventQuery()).map(\.id), [5, 4, 2, 1])
        XCTAssertEqual(try store.events(EventQuery(includeBenign: true)).count, 5)
        XCTAssertEqual(try store.events(EventQuery(categoryIDs: ["aws"])).map(\.id), [2])
        XCTAssertEqual(try store.events(EventQuery(agentID: "claude-code")).map(\.id), [4])
        XCTAssertEqual(try store.events(EventQuery(agentsOnly: true)).map(\.id), [4])
        XCTAssertEqual(try store.events(EventQuery(decisions: [.denied])).map(\.id), [5])
        XCTAssertEqual(try store.events(EventQuery(afterID: 2, newestFirst: false)).map(\.id), [4, 5])
        XCTAssertEqual(try store.events(EventQuery(text: "ID_ED25519")).map(\.id), [5])
        XCTAssertEqual(try store.events(EventQuery(since: t0.addingTimeInterval(15), until: t0.addingTimeInterval(35))).map(\.id), [4])
        XCTAssertEqual(try store.events(EventQuery(limit: 2)).count, 2)
        XCTAssertEqual(try store.event(id: 4)?.agentID, "claude-code")
        XCTAssertEqual(try store.event(id: 4)?.chain.map(\.name), ["launchd", "cat"])
        XCTAssertEqual(try store.maxEventID(), 5)

        let sums = try store.summaries(since: nil)
        let terminalSSH = try XCTUnwrap(sums.first { $0.responsible.displayName == "Terminal" && $0.categoryID == "ssh" && !$0.benign })
        XCTAssertEqual(terminalSSH.count, 2)
        XCTAssertEqual(terminalSSH.denied, 1)
        XCTAssertEqual(terminalSSH.firstSeen, t0)
        XCTAssertEqual(terminalSSH.lastSeen, t0.addingTimeInterval(40))
    }

    func testFilePermissionsAndReopen() throws {
        let path = dir.appendingPathComponent("db.sqlite").path
        do {
            let store = try SQLiteEventStore(path: path)
            try store.insert([event(1, 0)])
            try store.saveSettings(Settings(learningDays: 3))
            try store.saveRules(RuleTemplates.all)
            try store.saveBaseline([(BaselineKey(responsibleKey: "app:/x", categoryID: "ssh", access: .read),
                                     BaselineEntry(key: BaselineKey(responsibleKey: "app:/x", categoryID: "ssh", access: .read),
                                                   firstSeen: t0, lastSeen: t0, count: 1, source: .learned))])
        }
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let store = try SQLiteEventStore(path: path)
        XCTAssertEqual(try store.events(EventQuery()).count, 1)
        XCTAssertEqual(try store.settings().learningDays, 3)
        XCTAssertEqual(try store.loadRules()?.map(\.id), RuleTemplates.all.map(\.id))
        XCTAssertEqual(try store.loadBaseline().count, 1)
        // Removing a baseline entry.
        try store.saveBaseline([(BaselineKey(responsibleKey: "app:/x", categoryID: "ssh", access: .read), nil)])
        XCTAssertEqual(try store.loadBaseline().count, 0)
    }

    func testRulesNilUntilSavedThenEmptyStaysEmpty() throws {
        let store = try SQLiteEventStore(path: dir.appendingPathComponent("r.sqlite").path)
        XCTAssertNil(try store.loadRules())
        try store.saveRules([])
        XCTAssertEqual(try store.loadRules()?.count, 0)
    }

    func testAlerts() throws {
        let store = try SQLiteEventStore(path: dir.appendingPathComponent("a.sqlite").path)
        var a = Alert(id: 7, kind: .firstAccess, createdAt: t0, updatedAt: t0, windowEndsAt: t0.addingTimeInterval(600),
                      responsible: ResponsibleEntity(kind: .app, key: "app:/z", displayName: "Zoom"), categoryID: "ssh",
                      severity: .critical, count: 1, accesses: .read, firstPath: "/Users/alice/.ssh/id_rsa", firstEventID: 1,
                      lastEventID: 1, paths: ["/Users/alice/.ssh/id_rsa"], chain: [], agentID: nil, ruleID: nil)
        try store.upsert([a])
        a.count = 5
        a.status = .read
        a.updatedAt = t0.addingTimeInterval(60)
        try store.upsert([a])
        XCTAssertEqual(try store.alerts(AlertQuery()).first?.count, 5)
        XCTAssertEqual(try store.alerts(AlertQuery(statuses: [.unread])).count, 0)
        XCTAssertEqual(try store.alert(id: 7)?.status, .read)
        XCTAssertEqual(try store.maxAlertID(), 7)
        XCTAssertEqual(try store.counts().alerts, 1)
    }

    func testRetentionRollsUpDetailsAndKeepsIDsMonotonic() throws {
        let store = try SQLiteEventStore(path: dir.appendingPathComponent("ret.sqlite").path)
        let day = 86_400.0
        try store.insert([
            event(1, 0), event(2, 60, access: .write), event(3, 120, decision: .denied),
            event(4, 2 * day, category: "aws"),
            event(5, 9 * day),
        ])
        let removed = try store.applyRetention(detailCutoff: t0.addingTimeInterval(8 * day), retentionCutoff: t0.addingTimeInterval(day))
        XCTAssertEqual(removed, 4)
        XCTAssertEqual(try store.events(EventQuery(includeBenign: true)).map(\.id), [5])
        let daily = try store.dailyAggregates(since: nil)
        // Day 0 is older than the retention cutoff: dropped. Day 2 (aws) is kept as an aggregate.
        XCTAssertEqual(daily.count, 1)
        XCTAssertEqual(daily.first?.summary.categoryID, "aws")
        XCTAssertEqual(try store.counts().aggregatedDays, 1)
        // ssh summary for Terminal: last seen day 9, so it survives; ids keep counting past rolled-up rows.
        XCTAssertEqual(try store.maxEventID(), 5)
        try store.applyRetention(detailCutoff: t0.addingTimeInterval(20 * day), retentionCutoff: t0)
        XCTAssertEqual(try store.maxEventID(), 5, "high-water mark remembered after all details are gone")
    }

    func testRetentionCountsReadsWritesDenied() throws {
        let store = try SQLiteEventStore(path: dir.appendingPathComponent("agg.sqlite").path)
        try store.insert([event(1, 0), event(2, 60, access: .write), event(3, 120, access: .readWrite, decision: .denied)])
        try store.applyRetention(detailCutoff: t0.addingTimeInterval(86_400), retentionCutoff: t0.addingTimeInterval(-86_400))
        let agg = try XCTUnwrap(try store.dailyAggregates(since: nil).first?.summary)
        XCTAssertEqual(agg.count, 3)
        XCTAssertEqual(agg.reads, 2)
        XCTAssertEqual(agg.writes, 2)
        XCTAssertEqual(agg.denied, 1)
        XCTAssertEqual(agg.responsible.displayName, "Terminal")
    }

    func testConcurrentWritersAndReaders() throws {
        let store = try SQLiteEventStore(path: dir.appendingPathComponent("c.sqlite").path)
        let group = DispatchGroup()
        for w in 0..<4 {
            group.enter()
            DispatchQueue.global().async {
                for i in 0..<50 { try? store.insert([self.event(Int64(w * 1000 + i), Double(i))]) }
                group.leave()
            }
            group.enter()
            DispatchQueue.global().async {
                for _ in 0..<50 { _ = try? store.events(EventQuery(limit: 10)) }
                group.leave()
            }
        }
        group.wait()
        XCTAssertEqual(try store.counts().events, 200)
    }
}

final class RuleDecodingTests: XCTestCase {
    /// A rule row this build cannot read must not be dropped silently (spec-5 / policy-8): the daemon
    /// would keep enforcing with the rest and the next save would erase it.
    func testUndecodableRuleRowThrows() throws {
        let dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), isDirectory: true).appendingPathComponent("whoread-rules-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let path = dir.appendingPathComponent("w.sqlite").path
        let store = try SQLiteEventStore(path: path)
        try store.saveRules(RuleTemplates.all)
        let db = try SQLiteDatabase(path: path)
        try db.exec("INSERT INTO rules(id, position, body) VALUES('future', 99, CAST('{\"subject\":{\"type\":\"fromTheFuture\"}}' AS BLOB));")
        XCTAssertThrowsError(try store.loadRules()) { error in
            XCTAssertTrue(error is RuleDecodingError, "\(error)")
        }
    }
}

/// The database's directory is the daemon's data directory, created and checked before the store opens
/// (macos-4). The store creates no directories of its own and does not open a database through a link.
final class StoreDirectoryTests: XCTestCase {
    var dir: URL!

    override func setUpWithError() throws {
        dir = URL(fileURLWithPath: ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), isDirectory: true).appendingPathComponent("whoread-storedir-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        XCTAssertEqual(chmod(dir.path, 0o755), 0)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    private func exists(_ path: String) -> Bool {
        var st = stat()
        return lstat(path, &st) == 0
    }

    private func assertRefused(_ path: String, owner: uid_t = geteuid(), mentioning text: String,
                               file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try SQLiteEventStore(path: path, directoryOwner: owner), file: file, line: line) { error in
            XCTAssertTrue("\(error)".contains(text), "\(error)", file: file, line: line)
        }
    }

    // daemonfs-5: the store ran mkdir -p for a missing directory (as root, through whatever links
    // the path held) instead of leaving that to the checked data directory.
    func testMissingDirectoryIsNotCreated() throws {
        let missing = dir.appendingPathComponent("missing").path
        assertRefused(missing + "/db.sqlite", mentioning: missing)
        XCTAssertFalse(exists(missing))
    }

    func testDirectoryOthersCanWriteIsRefused() throws {
        XCTAssertEqual(chmod(dir.path, 0o777), 0)
        assertRefused(dir.appendingPathComponent("db.sqlite").path, mentioning: "writable by group or others")
        XCTAssertFalse(exists(dir.appendingPathComponent("db.sqlite").path))
    }

    func testDirectoryThatIsALinkIsRefused() throws {
        let elsewhere = dir.appendingPathComponent("elsewhere").path
        XCTAssertEqual(mkdir(elsewhere, 0o755), 0)
        let link = dir.appendingPathComponent("data").path
        XCTAssertEqual(symlink(elsewhere, link), 0)
        assertRefused(link + "/db.sqlite", mentioning: "not a directory")
        XCTAssertFalse(exists(elsewhere + "/db.sqlite"))
    }

    func testDirectoryOfAnotherOwnerIsRefused() throws {
        let someoneElse: uid_t = geteuid() == 0 ? 1 : 0
        assertRefused(dir.appendingPathComponent("db.sqlite").path, owner: someoneElse, mentioning: "owned by uid")
        XCTAssertFalse(exists(dir.appendingPathComponent("db.sqlite").path))
    }

    // daemonfs-5-variant: an existing entry at the database path was opened by SQLite and chmod-ed
    // through a link, into whatever file it pointed to.
    func testDatabasePathThatIsALinkIsNotFollowed() throws {
        let target = dir.appendingPathComponent("target").path
        try SafeFile.replace(target, with: Data("not a database\n".utf8), mode: 0o644)
        let path = dir.appendingPathComponent("db.sqlite").path
        XCTAssertEqual(symlink(target, path), 0)
        assertRefused(path, mentioning: "symbolic link")
        var st = stat()
        XCTAssertEqual(stat(target, &st), 0)
        XCTAssertEqual(st.st_mode & 0o777, 0o644, "the link's target keeps its mode")
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: target)), Data("not a database\n".utf8))
        XCTAssertFalse(exists(path + "-wal"))
    }

    func testDatabaseWithAnotherNameIsRefused() throws {
        let other = dir.appendingPathComponent("other").path
        try SafeFile.replace(other, with: Data(), mode: 0o600)
        let path = dir.appendingPathComponent("db.sqlite").path
        XCTAssertEqual(link(other, path), 0)
        assertRefused(path, mentioning: "hard links")
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: other)), Data(), "nothing was written through the other name")
    }

    func testDatabasePathThatIsADirectoryIsRefused() throws {
        let path = dir.appendingPathComponent("db.sqlite").path
        XCTAssertEqual(mkdir(path, 0o755), 0)
        assertRefused(path, mentioning: "not a regular file")
    }

    func testExistingDatabaseInATrustedDirectoryOpensAgain() throws {
        let path = dir.appendingPathComponent("db.sqlite").path
        try SQLiteEventStore(path: path).saveRules(RuleTemplates.all)
        XCTAssertEqual(try SQLiteEventStore(path: path).loadRules()?.count, RuleTemplates.all.count)
        var st = stat()
        XCTAssertEqual(lstat(path, &st), 0)
        XCTAssertEqual(st.st_mode & 0o777, 0o600)
    }
}
