import Foundation

/// Daemon settings (persisted in the store's key-value table).
public struct Settings: Codable, Hashable, Sendable {
    public var monitoringPaused: Bool
    public var enforcementEnabled: Bool
    public var learningDays: Double
    public var retentionDays: Int
    /// Detail rows older than this are rolled up into daily aggregates.
    public var detailDays: Int
    public var coalesceMinutes: Double
    public var readdirEnabled: Bool
    public var projectRoots: [String]
    public var notifications: NotificationSettings
    public var latencyP99ThresholdMs: Double
    /// nil = follow the system language.
    public var language: Language?

    public init(
        monitoringPaused: Bool = false,
        enforcementEnabled: Bool = false,
        learningDays: Double = 7,
        retentionDays: Int = 30,
        detailDays: Int = 7,
        coalesceMinutes: Double = 10,
        readdirEnabled: Bool = false,
        projectRoots: [String] = [],
        notifications: NotificationSettings = NotificationSettings(),
        latencyP99ThresholdMs: Double = 50,
        language: Language? = nil
    ) {
        self.monitoringPaused = monitoringPaused
        self.enforcementEnabled = enforcementEnabled
        self.learningDays = learningDays
        self.retentionDays = retentionDays
        self.detailDays = detailDays
        self.coalesceMinutes = coalesceMinutes
        self.readdirEnabled = readdirEnabled
        self.projectRoots = projectRoots
        self.notifications = notifications
        self.latencyP99ThresholdMs = latencyP99ThresholdMs
        self.language = language
    }

    enum CodingKeys: String, CodingKey {
        case monitoringPaused, enforcementEnabled, learningDays, retentionDays, detailDays, coalesceMinutes
        case readdirEnabled, projectRoots, notifications, latencyP99ThresholdMs, language
    }

    /// Missing keys fall back to defaults so old settings blobs keep decoding.
    public init(from decoder: Decoder) throws {
        let d = Settings()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        monitoringPaused = try c.decodeIfPresent(Bool.self, forKey: .monitoringPaused) ?? d.monitoringPaused
        enforcementEnabled = try c.decodeIfPresent(Bool.self, forKey: .enforcementEnabled) ?? d.enforcementEnabled
        learningDays = try c.decodeIfPresent(Double.self, forKey: .learningDays) ?? d.learningDays
        retentionDays = try c.decodeIfPresent(Int.self, forKey: .retentionDays) ?? d.retentionDays
        detailDays = try c.decodeIfPresent(Int.self, forKey: .detailDays) ?? d.detailDays
        coalesceMinutes = try c.decodeIfPresent(Double.self, forKey: .coalesceMinutes) ?? d.coalesceMinutes
        readdirEnabled = try c.decodeIfPresent(Bool.self, forKey: .readdirEnabled) ?? d.readdirEnabled
        projectRoots = try c.decodeIfPresent([String].self, forKey: .projectRoots) ?? d.projectRoots
        notifications = try c.decodeIfPresent(NotificationSettings.self, forKey: .notifications) ?? d.notifications
        latencyP99ThresholdMs = try c.decodeIfPresent(Double.self, forKey: .latencyP99ThresholdMs) ?? d.latencyP99ThresholdMs
        language = try c.decodeIfPresent(Language.self, forKey: .language)
    }

    /// Clamps values to sane ranges.
    public func validated() -> Settings {
        var s = self
        s.learningDays = min(max(s.learningDays, 0), 90)
        s.retentionDays = min(max(s.retentionDays, 1), 365)
        s.detailDays = min(max(s.detailDays, 1), s.retentionDays)
        s.coalesceMinutes = min(max(s.coalesceMinutes, 1), 24 * 60)
        s.latencyP99ThresholdMs = min(max(s.latencyP99ThresholdMs, 1), 10_000)
        s.projectRoots = Array(Set(s.projectRoots.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty })).sorted()
        return s
    }
}

public struct NotificationSettings: Codable, Hashable, Sendable {
    public var enabled: Bool
    public var minimumSeverity: Severity
    public var notifyWouldBlock: Bool

    public init(enabled: Bool = true, minimumSeverity: Severity = .medium, notifyWouldBlock: Bool = true) {
        self.enabled = enabled
        self.minimumSeverity = minimumSeverity
        self.notifyWouldBlock = notifyWouldBlock
    }
}

/// Filters for event queries.
public struct EventQuery: Codable, Hashable, Sendable {
    public var since: Date?
    public var until: Date?
    public var categoryIDs: [String]?
    public var responsibleKey: String?
    /// Case-insensitive substring of the responsible display name or process name.
    public var text: String?
    public var agentID: String?
    /// Only events with an agent anywhere in the chain.
    public var agentsOnly: Bool
    public var includeBenign: Bool
    public var decisions: [EventDecision]?
    /// Live tail: only events with a larger ID.
    public var afterID: Int64?
    public var limit: Int
    /// Newest first unless false.
    public var newestFirst: Bool

    public init(since: Date? = nil, until: Date? = nil, categoryIDs: [String]? = nil, responsibleKey: String? = nil,
                text: String? = nil, agentID: String? = nil, agentsOnly: Bool = false, includeBenign: Bool = false,
                decisions: [EventDecision]? = nil, afterID: Int64? = nil, limit: Int = 500, newestFirst: Bool = true) {
        self.since = since
        self.until = until
        self.categoryIDs = categoryIDs
        self.responsibleKey = responsibleKey
        self.text = text
        self.agentID = agentID
        self.agentsOnly = agentsOnly
        self.includeBenign = includeBenign
        self.decisions = decisions
        self.afterID = afterID
        self.limit = limit
        self.newestFirst = newestFirst
    }

    public func matches(_ e: AnalyzedEvent) -> Bool {
        if let since, e.time < since { return false }
        if let until, e.time > until { return false }
        if let categoryIDs, !categoryIDs.contains(e.categoryID) { return false }
        if let responsibleKey, e.responsible.key != responsibleKey { return false }
        if let agentID, e.agentID != agentID { return false }
        if agentsOnly && e.agentID == nil { return false }
        if !includeBenign && e.isBenign { return false }
        if let decisions, !decisions.contains(e.decision) { return false }
        if let afterID, e.id <= afterID { return false }
        if let text, !text.isEmpty {
            let t = text.lowercased()
            if !e.responsible.displayName.lowercased().contains(t) && !e.process.name.lowercased().contains(t)
                && !e.path.lowercased().contains(t) {
                return false
            }
        }
        return true
    }
}

public struct AlertQuery: Codable, Hashable, Sendable {
    public var since: Date?
    public var statuses: [AlertStatus]?
    public var limit: Int

    public init(since: Date? = nil, statuses: [AlertStatus]? = nil, limit: Int = 200) {
        self.since = since
        self.statuses = statuses
        self.limit = limit
    }
}

/// One (responsible app, category) pair with counts. Backs the Apps, Files and Agents tabs.
public struct UsageSummary: Codable, Hashable, Sendable {
    public var responsible: ResponsibleEntity
    public var categoryID: String
    public var agentID: String?
    public var firstSeen: Date
    public var lastSeen: Date
    public var count: Int
    public var reads: Int
    public var writes: Int
    public var denied: Int
    public var benign: Bool

    public init(responsible: ResponsibleEntity, categoryID: String, agentID: String?, firstSeen: Date, lastSeen: Date,
                count: Int, reads: Int, writes: Int, denied: Int, benign: Bool) {
        self.responsible = responsible
        self.categoryID = categoryID
        self.agentID = agentID
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.count = count
        self.reads = reads
        self.writes = writes
        self.denied = denied
        self.benign = benign
    }

    /// Key that identifies a summary row.
    public var rowKey: String { responsible.key + "\u{0}" + categoryID + "\u{0}" + (agentID ?? "") + (benign ? "\u{0}b" : "") }

    public mutating func add(_ e: AnalyzedEvent) {
        count += 1
        if e.access.contains(.read) { reads += 1 }
        if e.access.contains(.write) { writes += 1 }
        if e.decision == .denied { denied += 1 }
        if e.time < firstSeen { firstSeen = e.time }
        if e.time > lastSeen { lastSeen = e.time }
    }

    public static func from(_ e: AnalyzedEvent) -> UsageSummary {
        var s = UsageSummary(responsible: e.responsible, categoryID: e.categoryID, agentID: e.agentID, firstSeen: e.time,
                             lastSeen: e.time, count: 0, reads: 0, writes: 0, denied: 0, benign: e.isBenign)
        s.add(e)
        return s
    }
}

/// Storage interface. The daemon uses the SQLite implementation; tests use `InMemoryEventStore`.
/// Implementations must be thread-safe.
public protocol EventStore: AnyObject, Sendable {
    func insert(_ events: [AnalyzedEvent]) throws
    func upsert(_ alerts: [Alert]) throws
    func events(_ query: EventQuery) throws -> [AnalyzedEvent]
    func event(id: Int64) throws -> AnalyzedEvent?
    func alerts(_ query: AlertQuery) throws -> [Alert]
    func alert(id: Int64) throws -> Alert?
    func summaries(since: Date?) throws -> [UsageSummary]
    func maxEventID() throws -> Int64
    func maxAlertID() throws -> Int64

    func loadBaseline() throws -> [BaselineEntry]
    func saveBaseline(_ changes: [(BaselineKey, BaselineEntry?)]) throws
    func loadRules() throws -> [Rule]?
    func saveRules(_ rules: [Rule]) throws
    func value(forKey key: String) throws -> Data?
    func setValue(_ value: Data?, forKey key: String) throws

    /// Rolls details older than `detailCutoff` into daily aggregates and deletes everything older
    /// than `retentionCutoff`. Returns the number of detail rows removed.
    @discardableResult
    func applyRetention(detailCutoff: Date, retentionCutoff: Date) throws -> Int
    func counts() throws -> StoreCounts
}

public struct StoreCounts: Codable, Hashable, Sendable {
    public var events: Int
    public var aggregatedDays: Int
    public var alerts: Int
    public var unreadAlerts: Int
    public init(events: Int, aggregatedDays: Int, alerts: Int, unreadAlerts: Int) {
        self.events = events
        self.aggregatedDays = aggregatedDays
        self.alerts = alerts
        self.unreadAlerts = unreadAlerts
    }
}

extension EventStore {
    public func settings() throws -> Settings {
        guard let data = try value(forKey: "settings") else { return Settings() }
        return (try? JSONDecoder().decode(Settings.self, from: data)) ?? Settings()
    }

    public func saveSettings(_ s: Settings) throws {
        try setValue(try JSONEncoder().encode(s), forKey: "settings")
    }

    public func date(forKey key: String) throws -> Date? {
        guard let d = try value(forKey: key), let s = String(data: d, encoding: .utf8), let t = Double(s) else { return nil }
        return Date(timeIntervalSince1970: t)
    }

    public func setDate(_ date: Date, forKey key: String) throws {
        try setValue(Data(String(date.timeIntervalSince1970).utf8), forKey: key)
    }
}

/// Thread-safe in-memory store with the same semantics as the SQLite store.
public final class InMemoryEventStore: EventStore, @unchecked Sendable {
    private let lock = NSLock()
    private var eventsByID: [Int64: AnalyzedEvent] = [:]
    private var order: [Int64] = []
    private var alertsByID: [Int64: Alert] = [:]
    private var summaryRows: [String: UsageSummary] = [:]
    private var dailyRows: Set<String> = []
    private var baseline: [BaselineKey: BaselineEntry] = [:]
    private var rules: [Rule]?
    private var kv: [String: Data] = [:]

    public init() {}

    public func insert(_ events: [AnalyzedEvent]) throws {
        lock.lock(); defer { lock.unlock() }
        for e in events {
            if eventsByID[e.id] == nil { order.append(e.id) }
            eventsByID[e.id] = e
            let row = UsageSummary.from(e)
            if var existing = summaryRows[row.rowKey] {
                existing.add(e)
                summaryRows[row.rowKey] = existing
            } else {
                summaryRows[row.rowKey] = row
            }
        }
    }

    public func upsert(_ alerts: [Alert]) throws {
        lock.lock(); defer { lock.unlock() }
        for a in alerts { alertsByID[a.id] = a }
    }

    public func events(_ query: EventQuery) throws -> [AnalyzedEvent] {
        lock.lock(); defer { lock.unlock() }
        let ids = query.newestFirst ? order.reversed() : order
        var out: [AnalyzedEvent] = []
        for id in ids {
            guard let e = eventsByID[id], query.matches(e) else { continue }
            out.append(e)
            if out.count >= query.limit { break }
        }
        return out
    }

    public func event(id: Int64) throws -> AnalyzedEvent? {
        lock.lock(); defer { lock.unlock() }
        return eventsByID[id]
    }

    public func alerts(_ query: AlertQuery) throws -> [Alert] {
        lock.lock(); defer { lock.unlock() }
        return alertsByID.values
            .filter { a in
                (query.since.map { a.updatedAt >= $0 } ?? true) && (query.statuses.map { $0.contains(a.status) } ?? true)
            }
            .sorted { $0.updatedAt > $1.updatedAt }
            .prefix(query.limit)
            .map { $0 }
    }

    public func alert(id: Int64) throws -> Alert? {
        lock.lock(); defer { lock.unlock() }
        return alertsByID[id]
    }

    public func summaries(since: Date?) throws -> [UsageSummary] {
        lock.lock(); defer { lock.unlock() }
        return summaryRows.values.filter { s in since.map { s.lastSeen >= $0 } ?? true }
            .sorted { $0.lastSeen > $1.lastSeen }
    }

    public func maxEventID() throws -> Int64 {
        lock.lock(); defer { lock.unlock() }
        return order.max() ?? 0
    }

    public func maxAlertID() throws -> Int64 {
        lock.lock(); defer { lock.unlock() }
        return alertsByID.keys.max() ?? 0
    }

    public func loadBaseline() throws -> [BaselineEntry] {
        lock.lock(); defer { lock.unlock() }
        return Array(baseline.values)
    }

    public func saveBaseline(_ changes: [(BaselineKey, BaselineEntry?)]) throws {
        lock.lock(); defer { lock.unlock() }
        for (k, v) in changes { baseline[k] = v }
    }

    public func loadRules() throws -> [Rule]? {
        lock.lock(); defer { lock.unlock() }
        return rules
    }

    public func saveRules(_ rules: [Rule]) throws {
        lock.lock(); defer { lock.unlock() }
        self.rules = rules
    }

    public func value(forKey key: String) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        return kv[key]
    }

    public func setValue(_ value: Data?, forKey key: String) throws {
        lock.lock(); defer { lock.unlock() }
        kv[key] = value
    }

    public func applyRetention(detailCutoff: Date, retentionCutoff: Date) throws -> Int {
        lock.lock(); defer { lock.unlock() }
        var removed = 0
        order.removeAll { id in
            guard let e = eventsByID[id], e.time < detailCutoff else { return false }
            dailyRows.insert(InMemoryEventStore.dayKey(e.time) + e.responsible.key + e.categoryID)
            eventsByID[id] = nil
            removed += 1
            return true
        }
        summaryRows = summaryRows.filter { $0.value.lastSeen >= retentionCutoff }
        alertsByID = alertsByID.filter { $0.value.updatedAt >= retentionCutoff }
        return removed
    }

    public func counts() throws -> StoreCounts {
        lock.lock(); defer { lock.unlock() }
        return StoreCounts(events: eventsByID.count, aggregatedDays: dailyRows.count, alerts: alertsByID.count,
                           unreadAlerts: alertsByID.values.filter { $0.status == .unread }.count)
    }

    static func dayKey(_ d: Date) -> String {
        String(RFC3339.format(d, fractionDigits: 0).prefix(10))
    }
}
