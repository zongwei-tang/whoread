import Foundation
import WhoReadCore

/// SQLite-backed `EventStore` for the daemon.
///
/// - File lives in `/Library/Application Support/WhoRead/` (root-owned); the database file is
///   chmod 0600 on open. WAL mode; one serialized connection.
/// - Events are stored as JSON bodies plus indexed columns, so the event model can grow without
///   migrations; summaries and daily aggregates are maintained incrementally.
public final class SQLiteEventStore: EventStore, @unchecked Sendable {
    public static let schemaVersion = 1

    private let db: SQLiteDatabase
    private let lock = NSLock()
    private let encoder = Exporter.encoder(pretty: false)
    private let decoder = Exporter.decoder()
    public let path: String
    /// Summary and daily rows kept at most (`applyRetention`).
    public let limits: StoreLimits
    /// The last loadRules failed: the next saveRules backs the old rows up whatever the cause (after
    /// an SQLite error at start, rows that decode now were still never loaded).
    private var rulesLoadFailed = false
    /// `counts()` as of the last write (app-7: status asks for them every second, also on an idle
    /// machine). Each write the store makes clears it; the store is the database's only writer.
    private var cachedCounts: StoreCounts?
    /// Rows the summary and daily reads take per hold of the store lock, and events per page of the
    /// activity scan (ipc-1): the lock is released in between, so a long read does not hold off the
    /// writer, rule saves or status. Set only before the store is used (tests).
    var readBatch = 1_000
    var scanBatch = 5_000
    /// Tests: runs after each page of an activity read, outside the lock (where a write may come in).
    var activityPageHook: (() -> Void)?
    /// Retention runs so far (guarded by `lock`): a read in several holds of the lock that saw one start
    /// meanwhile reads again (`activity`).
    private var retentionRuns: UInt64 = 0

    /// Opens or creates the database at `path`. Its directory (the daemon's data directory, created
    /// and checked before the store opens) must already exist as a real directory owned by
    /// `directoryOwner` that others cannot change: the store creates no directories. An existing
    /// database must be a regular file of that owner with one name, never a link, which SQLite and
    /// the chmod below would follow.
    public init(path: String, directoryOwner: uid_t = geteuid(), limits: StoreLimits = StoreLimits()) throws {
        self.path = path
        self.limits = limits
        let dir = (path as NSString).deletingLastPathComponent
        try SafeFile.checkTrustedDirectory(dir.isEmpty ? "." : dir, owner: directoryOwner)
        // Create with restrictive permissions before SQLite touches it.
        if !(try SafeFile.createIfAbsent(path, mode: 0o600)) {
            try SQLiteEventStore.checkExistingDatabase(path, owner: directoryOwner)
        }
        db = try SQLiteDatabase(path: path)
        chmod(path, 0o600)
        try migrate()
    }

    struct UnsafeDatabaseFile: Error, CustomStringConvertible {
        let description: String
    }

    private static func checkExistingDatabase(_ path: String, owner: uid_t) throws {
        var st = stat()
        guard lstat(path, &st) == 0 else {
            throw UnsafeDatabaseFile(description: "cannot inspect \(path): \(String(cString: strerror(errno)))")
        }
        let problem: String?
        switch st.st_mode & S_IFMT {
        case S_IFLNK: problem = "is a symbolic link"
        case S_IFREG:
            problem = st.st_uid != owner ? "is owned by uid \(st.st_uid), expected \(owner)"
                : st.st_nlink != 1 ? "has \(st.st_nlink) hard links" : nil
        default: problem = "is not a regular file"
        }
        if let problem { throw UnsafeDatabaseFile(description: "\(path) \(problem); refusing to open it") }
    }

    private func migrate() throws {
        try db.exec("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA foreign_keys=OFF;
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value BLOB);
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY,
                ts REAL NOT NULL,
                category TEXT NOT NULL,
                severity INTEGER NOT NULL,
                responsible_key TEXT NOT NULL,
                agent_id TEXT,
                benign INTEGER NOT NULL,
                decision TEXT NOT NULL,
                access INTEGER NOT NULL,
                search TEXT NOT NULL,
                body BLOB NOT NULL);
            CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS events_cat_ts ON events(category, ts);
            CREATE INDEX IF NOT EXISTS events_resp_ts ON events(responsible_key, ts);
            CREATE INDEX IF NOT EXISTS events_agent_ts ON events(agent_id, ts);
            CREATE TABLE IF NOT EXISTS summary(
                responsible_key TEXT NOT NULL, category TEXT NOT NULL, agent_id TEXT NOT NULL,
                responsible BLOB NOT NULL, first_ts REAL NOT NULL, last_ts REAL NOT NULL,
                count INTEGER NOT NULL, reads INTEGER NOT NULL, writes INTEGER NOT NULL,
                denied INTEGER NOT NULL, benign INTEGER NOT NULL,
                PRIMARY KEY(responsible_key, category, agent_id, benign));
            CREATE TABLE IF NOT EXISTS daily(
                day TEXT NOT NULL, responsible_key TEXT NOT NULL, category TEXT NOT NULL, agent_id TEXT NOT NULL,
                responsible BLOB NOT NULL, first_ts REAL NOT NULL, last_ts REAL NOT NULL,
                count INTEGER NOT NULL, reads INTEGER NOT NULL, writes INTEGER NOT NULL,
                denied INTEGER NOT NULL, benign INTEGER NOT NULL,
                PRIMARY KEY(day, responsible_key, category, agent_id));
            CREATE INDEX IF NOT EXISTS daily_last ON daily(last_ts);
            CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, updated REAL NOT NULL, status TEXT NOT NULL, body BLOB NOT NULL);
            CREATE INDEX IF NOT EXISTS alerts_updated ON alerts(updated);
            CREATE INDEX IF NOT EXISTS alerts_status_updated ON alerts(status, updated);
            DROP INDEX IF EXISTS alerts_status;
            CREATE INDEX IF NOT EXISTS summary_last ON summary(last_ts);
            CREATE TABLE IF NOT EXISTS baseline(
                responsible_key TEXT NOT NULL, category TEXT NOT NULL, access TEXT NOT NULL, body BLOB NOT NULL,
                PRIMARY KEY(responsible_key, category, access));
            CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY, position INTEGER NOT NULL, body BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS rules_backup(id TEXT, position INTEGER, body BLOB, saved_at REAL);
            """)
        try db.prepare("INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)")
            .run([.text(String(SQLiteEventStore.schemaVersion))])
        // A repair, not needed to open the store: if it fails, it runs again at the next start.
        try? rebuildOlderSearchText()
    }

    /// Set in meta once every row's `search` is as `searchText` writes it.
    static let searchFormatKey = "search_format"

    /// Rows an older build wrote hold the names in `search` as they were: those with a \u{1} past the two
    /// separators get theirs again from their body, once (store-2). A body this build cannot read is left.
    private func rebuildOlderSearchText() throws {
        guard try valueLocked(SQLiteEventStore.searchFormatKey) == nil else { return }
        try db.transaction {
            var rebuilt: [(id: Int64, search: String)] = []
            try db.prepare("SELECT id, search, body FROM events WHERE length(search) - length(replace(search, char(1), '')) > 2")
                .query { r in
                    guard let e = try? decoder.decode(AnalyzedEvent.self, from: r.blob(2)) else { return }
                    let search = SQLiteEventStore.searchText(e)
                    if search != r.text(1) { rebuilt.append((r.int(0), search)) }
                }
            let update = try db.prepare("UPDATE events SET search = ? WHERE id = ?")
            for row in rebuilt { try update.run([.text(row.search), .int(row.id)]) }
            try setValueLocked(Data("2".utf8), forKey: SQLiteEventStore.searchFormatKey)
        }
    }

    /// What `text` and `appName` look in: the app's name, the program's name and the path, each `searchable`,
    /// joined by \u{1}. None of them holds a \u{1} of its own, so the second one always ends the names, where
    /// `appName` stops: a name with a \u{1} in it moved that end forward and cut the program's name off (store-2).
    static func searchText(_ e: AnalyzedEvent) -> String {
        [e.responsible.displayName, e.process.name, e.path].map(searchable).joined(separator: "\u{1}")
    }

    /// A field of `search`, or a needle looked for in it: lowercased, a \u{1} (the separator) made \u{2}. So
    /// a needle with a \u{1} in it matches within one field, as in the other store, never across two.
    static func searchable(_ s: String) -> String {
        (s.utf8.contains(1) ? s.replacingOccurrences(of: "\u{1}", with: "\u{2}") : s).lowercased()
    }

    private func locked<T>(_ body: () throws -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        return try body()
    }

    // MARK: - Events

    public func insert(_ events: [AnalyzedEvent]) throws {
        guard !events.isEmpty else { return }
        try locked {
            cachedCounts = nil
            try db.transaction {
                let ins = try db.prepare("""
                    INSERT OR REPLACE INTO events(id, ts, category, severity, responsible_key, agent_id, benign, decision, access, search, body)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)
                    """)
                let sum = try db.prepare("""
                    INSERT INTO summary(responsible_key, category, agent_id, responsible, first_ts, last_ts, count, reads, writes, denied, benign)
                    VALUES(?,?,?,?,?,?,1,?,?,?,?)
                    ON CONFLICT(responsible_key, category, agent_id, benign) DO UPDATE SET
                        responsible = excluded.responsible,
                        first_ts = min(first_ts, excluded.first_ts),
                        last_ts = max(last_ts, excluded.last_ts),
                        count = count + 1,
                        reads = reads + excluded.reads,
                        writes = writes + excluded.writes,
                        denied = denied + excluded.denied
                    """)
                for e in events {
                    let body = try encoder.encode(e)
                    let search = SQLiteEventStore.searchText(e)
                    try ins.run([
                        .int(e.id), .double(e.time.timeIntervalSince1970), .text(e.categoryID), .int(Int64(e.severity.rank)),
                        .text(e.responsible.key), e.agentID.map { .text($0) } ?? .null, .int(e.isBenign ? 1 : 0),
                        .text(e.decision.rawValue), .int(Int64(e.access.rawValue)), .text(search), .blob(body),
                    ])
                    try sum.run([
                        .text(e.responsible.key), .text(e.categoryID), .text(e.agentID ?? ""),
                        .blob(try encoder.encode(e.responsible)), .double(e.time.timeIntervalSince1970),
                        .double(e.time.timeIntervalSince1970), .int(e.access.contains(.read) ? 1 : 0),
                        .int(e.access.contains(.write) ? 1 : 0), .int(e.decision == .denied ? 1 : 0), .int(e.isBenign ? 1 : 0),
                    ])
                }
            }
        }
    }

    public func events(_ query: EventQuery) throws -> [AnalyzedEvent] {
        var clauses: [String] = []
        var args: [Statement.Value] = []
        if let since = query.since { clauses.append("ts >= ?"); args.append(.double(since.timeIntervalSince1970)) }
        if let until = query.until { clauses.append("ts <= ?"); args.append(.double(until.timeIntervalSince1970)) }
        if let cats = query.categoryIDs {
            if cats.isEmpty { return [] }
            clauses.append("category IN (" + Array(repeating: "?", count: cats.count).joined(separator: ",") + ")")
            args += cats.map { .text($0) }
        }
        if let key = query.responsibleKey { clauses.append("responsible_key = ?"); args.append(.text(key)) }
        if let agent = query.agentID { clauses.append("agent_id = ?"); args.append(.text(agent)) }
        if query.agentsOnly { clauses.append("agent_id IS NOT NULL") }
        if !query.includeBenign { clauses.append("benign = 0") }
        if let decisions = query.decisions {
            if decisions.isEmpty { return [] }
            clauses.append("decision IN (" + Array(repeating: "?", count: decisions.count).joined(separator: ",") + ")")
            args += decisions.map { .text($0.rawValue) }
        }
        if let after = query.afterID { clauses.append("id > ?"); args.append(.int(after)) }
        if let text = query.text, !text.isEmpty {
            clauses.append("instr(search, ?) > 0")
            args.append(.text(SQLiteEventStore.searchable(text)))
        }
        if let app = query.appName, !app.isEmpty {
            // `search` is "display name \u{1} process name \u{1} path" (`searchText`): only what comes before the second \u{1}.
            clauses.append("instr(substr(search, 1, instr(search, char(1)) + instr(substr(search, instr(search, char(1)) + 1), char(1)) - 1), ?) > 0")
            args.append(.text(SQLiteEventStore.searchable(app)))
        }
        let whereSQL = clauses.isEmpty ? "" : "WHERE " + clauses.joined(separator: " AND ")
        let order = query.newestFirst ? "DESC" : "ASC"
        let sql = "SELECT body FROM events \(whereSQL) ORDER BY id \(order) LIMIT ?"
        args.append(.int(Int64(max(0, min(query.limit, 100_000)))))
        return try locked {
            var out: [AnalyzedEvent] = []
            try db.prepare(sql).query(args) { row in
                if let e = try? decoder.decode(AnalyzedEvent.self, from: row.blob(0)) { out.append(e) }
            }
            return out
        }
    }

    public func event(id: Int64) throws -> AnalyzedEvent? {
        try locked {
            var out: AnalyzedEvent?
            try db.prepare("SELECT body FROM events WHERE id = ?").query([.int(id)]) { row in
                out = try? decoder.decode(AnalyzedEvent.self, from: row.blob(0))
            }
            return out
        }
    }

    public func maxEventID() throws -> Int64 {
        try locked {
            var v: Int64 = 0
            try db.prepare("SELECT max(id) FROM events").query { v = $0.isNull(0) ? 0 : $0.int(0) }
            // Ids continue after rolled-up rows too.
            if let stored = try valueLocked("max_event_id").flatMap({ String(data: $0, encoding: .utf8) }).flatMap(Int64.init) {
                v = max(v, stored)
            }
            return v
        }
    }

    // MARK: - Alerts

    public func upsert(_ alerts: [Alert]) throws {
        guard !alerts.isEmpty else { return }
        try locked {
            cachedCounts = nil
            try db.transaction {
                let st = try db.prepare("INSERT OR REPLACE INTO alerts(id, updated, status, body) VALUES(?,?,?,?)")
                for a in alerts {
                    try st.run([.int(a.id), .double(a.updatedAt.timeIntervalSince1970), .text(a.status.rawValue),
                                .blob(try encoder.encode(a))])
                }
            }
        }
    }

    /// The newest alerts (by update), `since` and of `statuses` distinct statuses when given (0: any).
    /// Parameters: `since`, the statuses, the limit. One status is a walk of the alerts_status_updated
    /// index in order, to the limit. Several are one such walk each, merged in order (a compound select):
    /// `status IN (…)` read every alert of those statuses and sorted them under the store lock (an answer's
    /// ask alerts: unread and read, up to 10,000). The arms share `since`, so their parameters are numbered.
    static func alertsSQL(since: Bool, statuses: Int) -> String {
        guard statuses > 1 else {
            let clauses = (since ? ["updated >= ?"] : []) + (statuses == 1 ? ["status IN (?)"] : [])
            return "SELECT body FROM alerts" + (clauses.isEmpty ? "" : " WHERE " + clauses.joined(separator: " AND "))
                + " ORDER BY updated DESC, id DESC LIMIT ?"
        }
        let first = since ? 2 : 1
        return (0..<statuses).map { i in
            "SELECT body, updated, id FROM alerts WHERE status = ?\(first + i)" + (since ? " AND updated >= ?1" : "")
        }.joined(separator: " UNION ALL ") + " ORDER BY updated DESC, id DESC LIMIT ?\(first + statuses)"
    }

    /// Read in one hold of the lock, decoded after it (up to 10,000 bodies: markRead, an answer's ask alerts).
    public func alerts(_ query: AlertQuery) throws -> [Alert] {
        var args: [Statement.Value] = []
        if let since = query.since { args.append(.double(since.timeIntervalSince1970)) }
        var statuses = 0
        if let wanted = query.statuses {
            if wanted.isEmpty { return [] }
            // Each once: a status named twice would be read twice.
            var seen = Set<AlertStatus>()
            for s in wanted where seen.insert(s).inserted { args.append(.text(s.rawValue)) }
            statuses = seen.count
        }
        args.append(.int(Int64(max(0, min(query.limit, 10_000)))))
        let sql = SQLiteEventStore.alertsSQL(since: query.since != nil, statuses: statuses)
        let bodies = try locked { () -> [Data] in
            var bodies: [Data] = []
            try db.prepare(sql).query(args) { bodies.append($0.blob(0)) }
            return bodies
        }
        let decoder = Exporter.decoder()
        return bodies.compactMap { try? decoder.decode(Alert.self, from: $0) }
    }

    public func alert(id: Int64) throws -> Alert? {
        try locked {
            var out: Alert?
            try db.prepare("SELECT body FROM alerts WHERE id = ?").query([.int(id)]) { row in
                out = try? decoder.decode(Alert.self, from: row.blob(0))
            }
            return out
        }
    }

    /// In batches of 500 ids, decoded off the lock.
    public func alerts(ids: [Int64]) throws -> [Alert] {
        var bodies: [Data] = []
        for start in stride(from: 0, to: ids.count, by: 500) {
            let batch = ids[start..<min(start + 500, ids.count)]
            try locked {
                let sql = "SELECT body FROM alerts WHERE id IN (" + Array(repeating: "?", count: batch.count).joined(separator: ",") + ")"
                try db.prepare(sql).query(batch.map { .int($0) }) { row in bodies.append(row.blob(0)) }
            }
        }
        let decoder = Exporter.decoder()
        return bodies.compactMap { try? decoder.decode(Alert.self, from: $0) }
    }

    public func maxAlertID() throws -> Int64 {
        try locked {
            var v: Int64 = 0
            try db.prepare("SELECT max(id) FROM alerts").query { v = $0.isNull(0) ? 0 : $0.int(0) }
            // Ids continue after purged alerts too (a stale notification must not act on a reused id).
            if let stored = try valueLocked("max_alert_id").flatMap({ String(data: $0, encoding: .utf8) }).flatMap(Int64.init) {
                v = max(v, stored)
            }
            return v
        }
    }

    // MARK: - Summaries

    public func summaries(since: Date?) throws -> [UsageSummary] {
        try newestSummaries(since: since, limit: .max)
    }

    public func summaries(limit: Int) throws -> [UsageSummary] {
        try newestSummaries(since: nil, limit: limit)
    }

    /// One batch of summary rows, newest first: walks the summary_last index from the cursor
    /// (`after`: the last row of the previous batch), never the whole table (daemon-6).
    static func summariesSQL(since: Bool, after: Bool) -> String {
        let clauses = (since ? ["last_ts >= ?"] : []) + (after ? ["(last_ts, rowid) < (?, ?)"] : [])
        return "SELECT rowid, responsible, category, agent_id, first_ts, last_ts, count, reads, writes, denied, benign FROM summary"
            + (clauses.isEmpty ? "" : " WHERE " + clauses.joined(separator: " AND ")) + " ORDER BY last_ts DESC, rowid DESC LIMIT ?"
    }

    /// A summary row as read; decoded after the lock is released.
    private struct SummaryRow {
        var rowid: Int64
        var responsible: Data
        var category: String
        var agent: String
        var first: Double
        var last: Double
        var count: Int64
        var reads: Int64
        var writes: Int64
        var denied: Int64
        var benign: Bool

        init(_ r: Statement.Row) {
            rowid = r.int(0)
            responsible = r.blob(1)
            category = r.text(2) ?? ""
            agent = r.text(3) ?? ""
            first = r.double(4)
            last = r.double(5)
            count = r.int(6)
            reads = r.int(7)
            writes = r.int(8)
            denied = r.int(9)
            benign = r.int(10) != 0
        }

        func decoded(_ decoder: JSONDecoder) -> UsageSummary? {
            guard let app = try? decoder.decode(ResponsibleEntity.self, from: responsible) else { return nil }
            return UsageSummary(responsible: app, categoryID: category, agentID: agent.isEmpty ? nil : agent,
                                firstSeen: Date(timeIntervalSince1970: first), lastSeen: Date(timeIntervalSince1970: last),
                                count: Int(count), reads: Int(reads), writes: Int(writes), denied: Int(denied), benign: benign)
        }
    }

    /// Summary rows by last access, newest first, at most `limit`: `readBatch` rows per hold of the
    /// lock, decoded outside it (ipc-1). A row whose app cannot be decoded (a newer build's, or damaged)
    /// is skipped without making the reply shorter while readable rows remain.
    private func newestSummaries(since: Date?, limit: Int) throws -> [UsageSummary] {
        let decoder = Exporter.decoder()
        // A reply's worth in one hold of the lock (a walk of the summary_last index): one snapshot. Between
        // batches a write could move a row the read has not reached ahead of its cursor, and leave it out.
        // The rest of a longer read, or rows to make up for ones that cannot be decoded, in batches.
        var batch = max(1, min(limit, UsageSummary.replyLimit))
        var out: [UsageSummary] = []
        var after: (last: Double, rowid: Int64)?
        while out.count < limit {
            var args: [Statement.Value] = since.map { [.double($0.timeIntervalSince1970)] } ?? []
            if let after { args += [.double(after.last), .int(after.rowid)] }
            args.append(.int(Int64(batch)))
            let sql = SQLiteEventStore.summariesSQL(since: since != nil, after: after != nil)
            let rows = try locked { () -> [SummaryRow] in
                var rows: [SummaryRow] = []
                try db.prepare(sql).query(args) { rows.append(SummaryRow($0)) }
                return rows
            }
            for row in rows {
                guard let s = row.decoded(decoder) else { continue }
                out.append(s)
                if out.count == limit { break }
            }
            guard rows.count == batch, let last = rows.last else { break }
            after = (last.last, last.rowid)
            batch = max(1, readBatch)
        }
        return out
    }

    // MARK: - Activity in a window (cli-6)

    /// The end of one page of the window's events, in (ts, id) order: a walk of the events_ts index.
    static let activityPageEndSQL = "SELECT ts, id FROM events WHERE (ts, id) > (?, ?) ORDER BY ts, id LIMIT 1 OFFSET ?"

    /// One page of the window's events, counted per summary row by SQLite.
    static func activityPageSQL(bounded: Bool) -> String {
        """
        SELECT responsible_key, category, coalesce(agent_id, ''), benign, min(ts), max(ts), count(*),
               sum((access & 1) != 0), sum((access & 2) != 0), sum(decision = 'denied'), max(id)
        FROM events WHERE (ts, id) > (?, ?)\(bounded ? " AND (ts, id) <= (?, ?)" : "")
        GROUP BY responsible_key, category, coalesce(agent_id, ''), benign
        """
    }

    /// Rolled-up days last seen in the window, in batches by last access.
    static let activityDaysSQL = """
        SELECT rowid, responsible_key, category, agent_id, benign, first_ts, last_ts, count, reads, writes, denied, responsible
        FROM daily WHERE (last_ts, rowid) > (?, ?) ORDER BY last_ts, rowid LIMIT ?
        """

    public func activity(since: Date, limit: Int) throws -> [UsageSummary] {
        guard limit > 0 else { return [] }
        struct Key: Hashable {
            var responsible: String
            var category: String
            var agent: String
            var benign: Bool
            /// UsageSummary.rowKey, for the same order of equal times as the other store.
            var rowKey: String { responsible + "\u{0}" + category + "\u{0}" + agent + (benign ? "\u{0}b" : "") }
        }
        struct Totals {
            var first: Double
            var last: Double
            var count: Int64 = 0
            var reads: Int64 = 0
            var writes: Int64 = 0
            var denied: Int64 = 0
            /// The newest event counted, and the app of the newest rolled-up day: where the app comes
            /// from when its summary row is gone.
            var newestEvent: Int64 = 0
            var day: (last: Double, app: Data)?
        }
        var totals: [Key: Totals] = [:]
        func add(_ key: Key, first: Double, last: Double, _ n: [Int64], event: Int64 = 0, day: (last: Double, app: Data)? = nil) {
            var t = totals[key] ?? Totals(first: first, last: last)
            t.first = min(t.first, first)
            t.last = max(t.last, last)
            t.count += n[0]
            t.reads += n[1]
            t.writes += n[2]
            t.denied += n[3]
            t.newestEvent = max(t.newestEvent, event)
            if let day, day.last >= (t.day?.last ?? -.infinity) { t.day = day }
            totals[key] = t
        }

        // Read again when a retention run rolled counted events into days meanwhile (they would count twice),
        // at most three times.
        let batch = max(1, readBatch)
        for attempt in 1...3 {
            totals = [:]
            let runs = try locked { retentionRuns }
            // Details: pages of `scanBatch` events, each counted by SQLite in one hold of the lock.
            let page = Int64(max(1, scanBatch))
            var lo = (ts: since.timeIntervalSince1970, id: Int64.min)
            while true {
                let hi = try locked { () -> (ts: Double, id: Int64)? in
                    var hi: (ts: Double, id: Int64)?
                    try db.prepare(SQLiteEventStore.activityPageEndSQL).query([.double(lo.ts), .int(lo.id), .int(page - 1)]) {
                        hi = ($0.double(0), $0.int(1))
                    }
                    let args: [Statement.Value] = [.double(lo.ts), .int(lo.id)] + (hi.map { [.double($0.ts), .int($0.id)] } ?? [])
                    try db.prepare(SQLiteEventStore.activityPageSQL(bounded: hi != nil)).query(args) { r in
                        add(Key(responsible: r.text(0) ?? "", category: r.text(1) ?? "", agent: r.text(2) ?? "", benign: r.int(3) != 0),
                            first: r.double(4), last: r.double(5), [r.int(6), r.int(7), r.int(8), r.int(9)], event: r.int(10))
                    }
                    return hi
                }
                guard let hi else { break }
                lo = hi
                activityPageHook?()
            }

            // Days rolled up past the detail window: only per-day totals are left, so such a day counts
            // whole (one row per day for benign and other accesses: benign only if every access was).
            var dayCursor = (last: since.timeIntervalSince1970, rowid: Int64.min)
            while true {
                let read = try locked { () -> (n: Int, last: (last: Double, rowid: Int64)?) in
                    var n = 0
                    var last: (last: Double, rowid: Int64)?
                    try db.prepare(SQLiteEventStore.activityDaysSQL).query([.double(dayCursor.last), .int(dayCursor.rowid), .int(Int64(batch))]) { r in
                        n += 1
                        last = (r.double(6), r.int(0))
                        add(Key(responsible: r.text(1) ?? "", category: r.text(2) ?? "", agent: r.text(3) ?? "", benign: r.int(4) != 0),
                            first: r.double(5), last: r.double(6), [r.int(7), r.int(8), r.int(9), r.int(10)], day: (r.double(6), r.blob(11)))
                    }
                    return (n, last)
                }
                guard read.n == batch, let last = read.last else { break }
                dayCursor = last
            }
            let after = try locked { retentionRuns }
            if attempt == 3 || after == runs { break }
        }

        // The newest rows, each with its app as last seen (its summary row), else as of its newest
        // rolled-up day, else as its newest event in the window names it.
        let chosen = Array(totals.sorted { a, b in
            a.value.last != b.value.last ? a.value.last > b.value.last : b.key.rowKey.utf8.lexicographicallyPrecedes(a.key.rowKey.utf8)
        }.prefix(limit))
        var apps: [Data?] = []
        for start in stride(from: 0, to: chosen.count, by: batch) {
            apps += try locked { () -> [Data?] in
                let summaryApp = try db.prepare(
                    "SELECT responsible FROM summary WHERE responsible_key = ? AND category = ? AND agent_id = ? AND benign = ?")
                return try chosen[start..<min(start + batch, chosen.count)].map { key, _ in
                    var app: Data?
                    try summaryApp.query([.text(key.responsible), .text(key.category), .text(key.agent), .int(key.benign ? 1 : 0)]) {
                        app = $0.blob(0)
                    }
                    return app
                }
            }
        }
        let decoder = Exporter.decoder()
        var out: [UsageSummary] = []
        for ((key, t), stored) in zip(chosen, apps) {
            var app = stored.flatMap { try? decoder.decode(ResponsibleEntity.self, from: $0) }
                ?? t.day.flatMap { try? decoder.decode(ResponsibleEntity.self, from: $0.app) }
            if app == nil, t.newestEvent != 0, let e = try event(id: t.newestEvent) { app = e.responsible }
            guard let app else { continue }
            out.append(UsageSummary(responsible: app, categoryID: key.category, agentID: key.agent.isEmpty ? nil : key.agent,
                                    firstSeen: Date(timeIntervalSince1970: t.first), lastSeen: Date(timeIntervalSince1970: t.last),
                                    count: Int(t.count), reads: Int(t.reads), writes: Int(t.writes), denied: Int(t.denied), benign: key.benign))
        }
        return out
    }

    // MARK: - Baseline, rules, kv

    public func loadBaseline() throws -> [BaselineEntry] {
        try locked {
            var out: [BaselineEntry] = []
            try db.prepare("SELECT body FROM baseline").query { row in
                if let e = try? decoder.decode(BaselineEntry.self, from: row.blob(0)) { out.append(e) }
            }
            return out
        }
    }

    public func saveBaseline(_ changes: [(BaselineKey, BaselineEntry?)]) throws {
        guard !changes.isEmpty else { return }
        try locked {
            try db.transaction {
                let up = try db.prepare("INSERT OR REPLACE INTO baseline(responsible_key, category, access, body) VALUES(?,?,?,?)")
                let del = try db.prepare("DELETE FROM baseline WHERE responsible_key = ? AND category = ? AND access = ?")
                for (k, e) in changes {
                    let keyArgs: [Statement.Value] = [.text(k.responsibleKey), .text(k.categoryID), .text(k.access.rawValue)]
                    if let e {
                        try up.run(keyArgs + [.blob(try encoder.encode(e))])
                    } else {
                        try del.run(keyArgs)
                    }
                }
            }
        }
    }

    public func loadRules() throws -> [Rule]? {
        try locked {
            rulesLoadFailed = true
            var any = false
            var out: [Rule] = []
            try db.prepare("SELECT body FROM rules ORDER BY position").query { row in
                any = true
                // Strict: a row this build cannot read (written by a newer version, or damaged) must not
                // be dropped silently. The daemon then keeps enforcement off and accepts only an explicit
                // replacement of the whole list by root or the app (saveRules backs the old rows up).
                do {
                    out.append(try decoder.decode(Rule.self, from: row.blob(0)))
                } catch {
                    throw RuleDecodingError(position: out.count, underlying: "\(error)")
                }
            }
            // An explicit "no rules" state is stored as a marker so templates are not re-added.
            let initialized = try any || valueLocked("rules_initialized") != nil
            rulesLoadFailed = false
            return initialized ? out : nil
        }
    }

    public func saveRules(_ rules: [Rule]) throws {
        try locked {
            try db.transaction {
                // Replacing rows this build cannot read, or could not load (see loadRules): every old
                // row, readable or not, goes to rules_backup first, so nothing a newer version wrote is
                // lost for good.
                var unreadable = rulesLoadFailed
                try db.prepare("SELECT body FROM rules").query { row in
                    if !unreadable && (try? decoder.decode(Rule.self, from: row.blob(0))) == nil { unreadable = true }
                }
                if unreadable {
                    try db.prepare("""
                        INSERT INTO rules_backup(id, position, body, saved_at)
                        SELECT id, position, body, ? FROM rules ORDER BY position
                        """).run([.double(Date().timeIntervalSince1970)])
                }
                try db.exec("DELETE FROM rules")
                let st = try db.prepare("INSERT INTO rules(id, position, body) VALUES(?,?,?)")
                for (i, r) in rules.enumerated() {
                    try st.run([.text(r.id), .int(Int64(i)), .blob(try encoder.encode(r))])
                }
                try setValueLocked(Data("1".utf8), forKey: "rules_initialized")
            }
            rulesLoadFailed = false
        }
    }

    public func value(forKey key: String) throws -> Data? {
        try locked { try valueLocked(key) }
    }

    public func setValue(_ value: Data?, forKey key: String) throws {
        try locked { try setValueLocked(value, forKey: key) }
    }

    private func valueLocked(_ key: String) throws -> Data? {
        var out: Data?
        try db.prepare("SELECT value FROM meta WHERE key = ?").query([.text(key)]) { out = $0.blob(0) }
        return out
    }

    private func setValueLocked(_ value: Data?, forKey key: String) throws {
        if let value {
            try db.prepare("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)").run([.text(key), .blob(value)])
        } else {
            try db.prepare("DELETE FROM meta WHERE key = ?").run([.text(key)])
        }
    }

    // MARK: - Retention

    @discardableResult
    public func applyRetention(detailCutoff: Date, retentionCutoff: Date) throws -> Int {
        try locked {
            cachedCounts = nil
            retentionRuns &+= 1
            return try db.transaction {
                // Remember the high-water marks so new ids never collide with rolled-up or purged ones.
                var maxID: Int64 = 0
                try db.prepare("SELECT max(id) FROM events").query { maxID = $0.isNull(0) ? 0 : $0.int(0) }
                if maxID > 0 { try setValueLocked(Data(String(maxID).utf8), forKey: "max_event_id") }
                var maxAlert: Int64 = 0
                try db.prepare("SELECT max(id) FROM alerts").query { maxAlert = $0.isNull(0) ? 0 : $0.int(0) }
                if maxAlert > 0 { try setValueLocked(Data(String(maxAlert).utf8), forKey: "max_alert_id") }

                // Roll details older than the cutoff into daily aggregates (local calendar days, as the
                // CLI and app display them). One row per day/app/category/agent: benign and non-benign
                // accesses share it, and it counts as benign only if every access was.
                let cutoff = Statement.Value.double(detailCutoff.timeIntervalSince1970)
                let rows = try db.prepare("""
                    SELECT strftime('%Y-%m-%d', ts, 'unixepoch', 'localtime') AS day, responsible_key, category,
                           coalesce(agent_id, '') AS agent, min(ts), max(ts), count(*), min(benign), max(id),
                           sum((access & 1) != 0), sum((access & 2) != 0), sum(decision = 'denied')
                    FROM events WHERE ts < ? GROUP BY day, responsible_key, category, agent
                    """)
                struct Agg {
                    var day: String; var key: String; var cat: String; var agent: String; var first: Double; var last: Double
                    var count: Int64; var benign: Int64; var sampleID: Int64; var reads: Int64; var writes: Int64; var denied: Int64
                }
                var aggs: [Agg] = []
                try rows.query([cutoff]) { r in
                    aggs.append(Agg(day: r.text(0) ?? "", key: r.text(1) ?? "", cat: r.text(2) ?? "", agent: r.text(3) ?? "",
                                    first: r.double(4), last: r.double(5), count: r.int(6), benign: r.int(7), sampleID: r.int(8),
                                    reads: r.int(9), writes: r.int(10), denied: r.int(11)))
                }
                let sample = try db.prepare("SELECT body FROM events WHERE id = ?")
                let up = try db.prepare("""
                    INSERT INTO daily(day, responsible_key, category, agent_id, responsible, first_ts, last_ts, count, reads, writes, denied, benign)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(day, responsible_key, category, agent_id) DO UPDATE SET
                        first_ts = min(first_ts, excluded.first_ts), last_ts = max(last_ts, excluded.last_ts),
                        count = count + excluded.count, reads = reads + excluded.reads, writes = writes + excluded.writes,
                        denied = denied + excluded.denied, benign = min(benign, excluded.benign)
                    """)
                for a in aggs {
                    var responsible = Data()
                    try sample.query([.int(a.sampleID)]) { row in
                        if let e = try? decoder.decode(AnalyzedEvent.self, from: row.blob(0)) {
                            responsible = (try? encoder.encode(e.responsible)) ?? Data()
                        }
                    }
                    try up.run([.text(a.day), .text(a.key), .text(a.cat), .text(a.agent), .blob(responsible), .double(a.first),
                                .double(a.last), .int(a.count), .int(a.reads), .int(a.writes), .int(a.denied), .int(a.benign)])
                }
                try db.prepare("DELETE FROM events WHERE ts < ?").run([cutoff])
                let removed = db.changes

                let old = Statement.Value.double(retentionCutoff.timeIntervalSince1970)
                try db.prepare("DELETE FROM daily WHERE last_ts < ?").run([old])
                try db.prepare("DELETE FROM summary WHERE last_ts < ?").run([old])
                try db.prepare("DELETE FROM alerts WHERE updated < ?").run([old])
                // Bounded by count too (daemon-6): minted apps add rows faster than age removes them.
                try evictLocked("summary", limit: limits.summaryRows)
                try evictLocked("daily", limit: limits.dailyRows)
                return removed
            }
        }
    }

    /// Past `limit` rows, the least recently seen rows of `table` (summary or daily) go, down to a
    /// tenth below it: a walk of its last_ts index, as long as the rows evicted.
    private func evictLocked(_ table: String, limit: Int) throws {
        var rows: Int64 = 0
        try db.prepare("SELECT count(*) FROM \(table)").query { rows = $0.int(0) }
        guard rows > Int64(limit) else { return }
        try db.prepare("DELETE FROM \(table) WHERE rowid IN (SELECT rowid FROM \(table) ORDER BY last_ts, rowid LIMIT ?)")
            .run([.int(rows - Int64(StoreLimits.lowWaterMark(limit)))])
    }

    /// Unread alerts, counted on the alerts_status_updated index (daemon-6: without it every status walked
    /// every alert, bodies included). The index is on (status, updated), not status alone: a query of the
    /// newest alerts of a status then reads them in order and stops at its limit, instead of taking every
    /// alert of that status and sorting them under the store lock.
    static let unreadAlertsSQL = "SELECT count(*) FROM alerts WHERE status = 'unread'"

    public func counts() throws -> StoreCounts {
        try locked {
            if let cachedCounts { return cachedCounts }
            func count(_ sql: String) throws -> Int {
                var v = 0
                try db.prepare(sql).query { v = Int($0.int(0)) }
                return v
            }
            let counts = StoreCounts(
                events: try count("SELECT count(*) FROM events"),
                aggregatedDays: try count("SELECT count(DISTINCT day) FROM daily"),
                alerts: try count("SELECT count(*) FROM alerts"),
                unreadAlerts: try count(SQLiteEventStore.unreadAlertsSQL))
            cachedCounts = counts
            return counts
        }
    }

    // MARK: - Daily aggregates (for exports beyond the detail window)

    /// One batch of daily rows in reply order (newest day first, then app, category and agent, each
    /// descending): walks the primary key from the cursor. `+last_ts` keeps the last_ts index out, so
    /// a `since` filter does not turn the walk into a sort.
    static func dailySQL(since: Bool, after: Bool) -> String {
        let clauses = (since ? ["+last_ts >= ?"] : []) + (after ? ["(day, responsible_key, category, agent_id) < (?, ?, ?, ?)"] : [])
        return "SELECT day, responsible_key, category, agent_id, responsible, first_ts, last_ts, count, reads, writes, denied, benign FROM daily"
            + (clauses.isEmpty ? "" : " WHERE " + clauses.joined(separator: " AND "))
            + " ORDER BY day DESC, responsible_key DESC, category DESC, agent_id DESC LIMIT ?"
    }

    /// A daily row as read; decoded after the lock is released.
    private struct DailyRow {
        var key: DailyAggregate.Key
        var responsible: Data
        var first: Double
        var last: Double
        var count: Int64
        var reads: Int64
        var writes: Int64
        var denied: Int64
        var benign: Bool

        init(_ r: Statement.Row) {
            key = DailyAggregate.Key(day: r.text(0) ?? "", responsibleKey: r.text(1) ?? "", categoryID: r.text(2) ?? "", agentID: r.text(3) ?? "")
            responsible = r.blob(4)
            first = r.double(5)
            last = r.double(6)
            count = r.int(7)
            reads = r.int(8)
            writes = r.int(9)
            denied = r.int(10)
            benign = r.int(11) != 0
        }

        func decoded(_ decoder: JSONDecoder) -> DailyAggregate? {
            guard let app = try? decoder.decode(ResponsibleEntity.self, from: responsible) else { return nil }
            return DailyAggregate(day: key.day, summary: UsageSummary(
                responsible: app, categoryID: key.categoryID, agentID: key.agentID.isEmpty ? nil : key.agentID,
                firstSeen: Date(timeIntervalSince1970: first), lastSeen: Date(timeIntervalSince1970: last),
                count: Int(count), reads: Int(reads), writes: Int(writes), denied: Int(denied), benign: benign))
        }
    }

    public func dailyAggregates(since: Date?) throws -> [DailyAggregate] {
        try dailyAggregates(since: since, after: nil, limit: .max)
    }

    /// `readBatch` rows per hold of the lock, decoded outside it. A row whose app cannot be decoded is
    /// skipped without making the page shorter while readable rows remain, so a short page always
    /// means the end (`export --aggregates` pages until one).
    public func dailyAggregates(since: Date?, after: DailyAggregate.Key?, limit: Int) throws -> [DailyAggregate] {
        let decoder = Exporter.decoder()
        let batch = max(1, readBatch)
        var out: [DailyAggregate] = []
        var cursor = after
        while out.count < limit {
            var args: [Statement.Value] = since.map { [.double($0.timeIntervalSince1970)] } ?? []
            if let cursor { args += [.text(cursor.day), .text(cursor.responsibleKey), .text(cursor.categoryID), .text(cursor.agentID)] }
            args.append(.int(Int64(batch)))
            let sql = SQLiteEventStore.dailySQL(since: since != nil, after: cursor != nil)
            let rows = try locked { () -> [DailyRow] in
                var rows: [DailyRow] = []
                try db.prepare(sql).query(args) { rows.append(DailyRow($0)) }
                return rows
            }
            for row in rows {
                guard let a = row.decoded(decoder) else { continue }
                out.append(a)
                if out.count == limit { break }
            }
            guard rows.count == batch, let last = rows.last else { break }
            cursor = last.key
        }
        return out
    }
}

/// A stored rule could not be decoded (see `SQLiteEventStore.loadRules`).
public struct RuleDecodingError: Error, CustomStringConvertible {
    public var position: Int
    public var underlying: String
    public var description: String { "stored rule #\(position + 1) cannot be read: \(underlying)" }
}
