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
    /// The last loadRules failed: the next saveRules backs the old rows up whatever the cause (after
    /// an SQLite error at start, rows that decode now were still never loaded).
    private var rulesLoadFailed = false

    public init(path: String) throws {
        self.path = path
        let dir = (path as NSString).deletingLastPathComponent
        if !dir.isEmpty {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        }
        // Create with restrictive permissions before SQLite touches it.
        try SafeFile.createIfAbsent(path, mode: 0o600)
        db = try SQLiteDatabase(path: path)
        chmod(path, 0o600)
        try migrate()
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
            CREATE TABLE IF NOT EXISTS baseline(
                responsible_key TEXT NOT NULL, category TEXT NOT NULL, access TEXT NOT NULL, body BLOB NOT NULL,
                PRIMARY KEY(responsible_key, category, access));
            CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY, position INTEGER NOT NULL, body BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS rules_backup(id TEXT, position INTEGER, body BLOB, saved_at REAL);
            """)
        try db.prepare("INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)")
            .run([.text(String(SQLiteEventStore.schemaVersion))])
    }

    private func locked<T>(_ body: () throws -> T) throws -> T {
        lock.lock(); defer { lock.unlock() }
        return try body()
    }

    // MARK: - Events

    public func insert(_ events: [AnalyzedEvent]) throws {
        guard !events.isEmpty else { return }
        try locked {
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
                    let search = (e.responsible.displayName + "\u{1}" + e.process.name + "\u{1}" + e.path).lowercased()
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
            args.append(.text(text.lowercased()))
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
            try db.transaction {
                let st = try db.prepare("INSERT OR REPLACE INTO alerts(id, updated, status, body) VALUES(?,?,?,?)")
                for a in alerts {
                    try st.run([.int(a.id), .double(a.updatedAt.timeIntervalSince1970), .text(a.status.rawValue),
                                .blob(try encoder.encode(a))])
                }
            }
        }
    }

    public func alerts(_ query: AlertQuery) throws -> [Alert] {
        var clauses: [String] = []
        var args: [Statement.Value] = []
        if let since = query.since { clauses.append("updated >= ?"); args.append(.double(since.timeIntervalSince1970)) }
        if let statuses = query.statuses {
            if statuses.isEmpty { return [] }
            clauses.append("status IN (" + Array(repeating: "?", count: statuses.count).joined(separator: ",") + ")")
            args += statuses.map { .text($0.rawValue) }
        }
        let whereSQL = clauses.isEmpty ? "" : "WHERE " + clauses.joined(separator: " AND ")
        args.append(.int(Int64(max(0, min(query.limit, 10_000)))))
        return try locked {
            var out: [Alert] = []
            try db.prepare("SELECT body FROM alerts \(whereSQL) ORDER BY updated DESC, id DESC LIMIT ?").query(args) { row in
                if let a = try? decoder.decode(Alert.self, from: row.blob(0)) { out.append(a) }
            }
            return out
        }
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
        try locked {
            var out: [UsageSummary] = []
            let sql = "SELECT responsible, category, agent_id, first_ts, last_ts, count, reads, writes, denied, benign FROM summary"
                + (since != nil ? " WHERE last_ts >= ?" : "") + " ORDER BY last_ts DESC"
            try db.prepare(sql).query(since.map { [.double($0.timeIntervalSince1970)] } ?? []) { row in
                guard let responsible = try? decoder.decode(ResponsibleEntity.self, from: row.blob(0)) else { return }
                let agent = row.text(2) ?? ""
                out.append(UsageSummary(
                    responsible: responsible, categoryID: row.text(1) ?? "", agentID: agent.isEmpty ? nil : agent,
                    firstSeen: Date(timeIntervalSince1970: row.double(3)), lastSeen: Date(timeIntervalSince1970: row.double(4)),
                    count: Int(row.int(5)), reads: Int(row.int(6)), writes: Int(row.int(7)), denied: Int(row.int(8)),
                    benign: row.int(9) != 0))
            }
            return out
        }
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
            try db.transaction {
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
                return removed
            }
        }
    }

    public func counts() throws -> StoreCounts {
        try locked {
            func count(_ sql: String) throws -> Int {
                var v = 0
                try db.prepare(sql).query { v = Int($0.int(0)) }
                return v
            }
            return StoreCounts(
                events: try count("SELECT count(*) FROM events"),
                aggregatedDays: try count("SELECT count(DISTINCT day) FROM daily"),
                alerts: try count("SELECT count(*) FROM alerts"),
                unreadAlerts: try count("SELECT count(*) FROM alerts WHERE status = 'unread'"))
        }
    }

    /// Daily aggregates (for exports beyond the detail window).
    public func dailyAggregates(since: Date?) throws -> [DailyAggregate] {
        try locked {
            var out: [DailyAggregate] = []
            let sql = "SELECT day, responsible, category, agent_id, first_ts, last_ts, count, reads, writes, denied, benign FROM daily"
                + (since != nil ? " WHERE last_ts >= ?" : "") + " ORDER BY day DESC"
            try db.prepare(sql).query(since.map { [.double($0.timeIntervalSince1970)] } ?? []) { row in
                guard let responsible = try? decoder.decode(ResponsibleEntity.self, from: row.blob(1)) else { return }
                let agent = row.text(3) ?? ""
                out.append(DailyAggregate(day: row.text(0) ?? "", summary: UsageSummary(
                    responsible: responsible, categoryID: row.text(2) ?? "", agentID: agent.isEmpty ? nil : agent,
                    firstSeen: Date(timeIntervalSince1970: row.double(4)), lastSeen: Date(timeIntervalSince1970: row.double(5)),
                    count: Int(row.int(6)), reads: Int(row.int(7)), writes: Int(row.int(8)), denied: Int(row.int(9)),
                    benign: row.int(10) != 0)))
            }
            return out
        }
    }
}

/// A stored rule could not be decoded (see `SQLiteEventStore.loadRules`).
public struct RuleDecodingError: Error, CustomStringConvertible {
    public var position: Int
    public var underlying: String
    public var description: String { "stored rule #\(position + 1) cannot be read: \(underlying)" }
}
