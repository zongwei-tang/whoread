import Foundation

/// (responsible app, category, read|write) — the unit of "normal".
public struct BaselineKey: Hashable, Codable, Sendable {
    public var responsibleKey: String
    public var categoryID: String
    public var access: AccessKind

    public init(responsibleKey: String, categoryID: String, access: AccessKind) {
        self.responsibleKey = responsibleKey
        self.categoryID = categoryID
        self.access = access
    }
}

public struct BaselineEntry: Codable, Hashable, Sendable {
    public enum Source: String, Codable, Sendable {
        /// Seen during a learning period (none by default since ask mode).
        case learned
        /// Seen outside a learning period (it alerted once, then became known).
        case observed
        /// The user chose "always allow".
        case approved
    }

    public var key: BaselineKey
    public var firstSeen: Date
    public var lastSeen: Date
    public var count: Int
    public var source: Source

    public init(key: BaselineKey, firstSeen: Date, lastSeen: Date, count: Int, source: Source) {
        self.key = key
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.count = count
        self.source = source
    }
}

/// Known (app, category, access) triples: seen before, or approved by the user. Thread-safe.
/// A learning period (seen accesses become known without alerting) only exists when
/// `learningDuration` is set: ask mode replaced it, and new triples alert at once.
///
/// Bounded (dos-1): every distinct unsigned program path is its own app, so a process can mint new
/// triples at will. Entries the user did not approve are forgotten once not seen within the
/// retention period, and beyond `maxUnapproved` the least recently seen go first (`prune`).
/// Forgetting one only means its next access alerts as a first access again; the baseline never
/// decides an access (rules and questions do), and approvals are never forgotten.
public final class Baseline: @unchecked Sendable {
    /// Unapproved entries kept at most (about 40 MB of daemon memory and 30 MB of database).
    public static let defaultMaxUnapproved = 100_000
    /// Entries in one `baseline` reply (the newest), well under the dev socket's frame limit.
    public static let replyLimit = 10_000

    private let lock = NSLock()
    private var entries: [BaselineKey: BaselineEntry]
    private var dirty: Set<BaselineKey> = []

    public private(set) var learningStartedAt: Date
    public var learningDuration: TimeInterval
    public let maxUnapproved: Int

    /// Entries beyond `maxUnapproved` (a table grown by an older build) are dropped at once and
    /// marked dirty, so the next save deletes their rows.
    public init(learningStartedAt: Date, learningDuration: TimeInterval = 0, entries: [BaselineEntry] = [],
                maxUnapproved: Int = Baseline.defaultMaxUnapproved) {
        self.learningStartedAt = learningStartedAt
        self.learningDuration = learningDuration
        self.maxUnapproved = maxUnapproved
        self.entries = Dictionary(entries.map { ($0.key, $0) }, uniquingKeysWith: { a, _ in a })
        prune()
    }

    public func isLearning(at now: Date) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return now.timeIntervalSince(learningStartedAt) < learningDuration
    }

    public func learningEndsAt() -> Date {
        lock.lock(); defer { lock.unlock() }
        return learningStartedAt.addingTimeInterval(learningDuration)
    }

    public func restartLearning(at now: Date) {
        lock.lock(); defer { lock.unlock() }
        learningStartedAt = now
    }

    /// Forgets everything learned or observed (user approvals stay) and restarts learning.
    public func resetLearned(at now: Date) {
        lock.lock(); defer { lock.unlock() }
        for (key, entry) in entries where entry.source != .approved {
            entries[key] = nil
            dirty.insert(key)
        }
        learningStartedAt = now
    }

    public func contains(_ key: BaselineKey) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return entries[key] != nil
    }

    public func entry(_ key: BaselineKey) -> BaselineEntry? {
        lock.lock(); defer { lock.unlock() }
        return entries[key]
    }

    public func isApproved(_ key: BaselineKey) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return entries[key]?.source == .approved
    }

    /// Records an observation. Returns true if the key was new.
    @discardableResult
    public func record(_ key: BaselineKey, at now: Date, learning: Bool) -> Bool {
        lock.lock(); defer { lock.unlock() }
        dirty.insert(key)
        if var e = entries[key] {
            e.count += 1
            if now > e.lastSeen { e.lastSeen = now }
            entries[key] = e
            return false
        }
        entries[key] = BaselineEntry(key: key, firstSeen: now, lastSeen: now, count: 1, source: learning ? .learned : .observed)
        return true
    }

    /// "Always allow" for an app on a category (both accesses unless one is given).
    public func approve(responsibleKey: String, categoryID: String, access: AccessKind? = nil, at now: Date) {
        lock.lock(); defer { lock.unlock() }
        for kind in access.map({ [$0] }) ?? AccessKind.allCases {
            let key = BaselineKey(responsibleKey: responsibleKey, categoryID: categoryID, access: kind)
            var e = entries[key] ?? BaselineEntry(key: key, firstSeen: now, lastSeen: now, count: 0, source: .approved)
            e.source = .approved
            entries[key] = e
            dirty.insert(key)
        }
    }

    public func remove(responsibleKey: String, categoryID: String? = nil) {
        lock.lock(); defer { lock.unlock() }
        for key in entries.keys where key.responsibleKey == responsibleKey && (categoryID == nil || key.categoryID == categoryID) {
            entries[key] = nil
            dirty.insert(key)
        }
    }

    public var allEntries: [BaselineEntry] {
        lock.lock(); defer { lock.unlock() }
        return Array(entries.values)
    }

    public var count: Int {
        lock.lock(); defer { lock.unlock() }
        return entries.count
    }

    /// The `limit` most recently seen entries, newest first. Sorted after the lock is released: any
    /// console process may ask for this, and `record` (the analysis queue) must not wait on a sort.
    public func newestEntries(limit: Int) -> [BaselineEntry] {
        lock.lock()
        let all = Array(entries.values)
        lock.unlock()
        return Array(all.sorted { ($0.lastSeen, $0.firstSeen) > ($1.lastSeen, $1.firstSeen) }.prefix(max(0, limit)))
    }

    /// Forgets unapproved (observed or learned) entries last seen before `cutoff`, then the least
    /// recently seen unapproved ones beyond `maxUnapproved`. Approvals stay. Removed keys are marked
    /// dirty (their rows are deleted on the next save). Called by maintenance; cheap while under
    /// the limit. Returns how many were forgotten.
    @discardableResult
    public func prune(lastSeenBefore cutoff: Date? = nil) -> Int {
        lock.lock(); defer { lock.unlock() }
        var removed = 0
        if let cutoff {
            for (key, entry) in entries where entry.source != .approved && entry.lastSeen < cutoff {
                entries[key] = nil
                dirty.insert(key)
                removed += 1
            }
        }
        guard entries.count > maxUnapproved else { return removed }
        let unapproved = entries.values.filter { $0.source != .approved }
        let excess = unapproved.count - maxUnapproved
        guard excess > 0 else { return removed }
        for entry in unapproved.sorted(by: { ($0.lastSeen, $0.firstSeen) < ($1.lastSeen, $1.firstSeen) }).prefix(excess) {
            entries[entry.key] = nil
            dirty.insert(entry.key)
            removed += 1
        }
        return removed
    }

    /// Entries changed since the last call, plus keys that were removed (nil entry). For incremental persistence.
    public func takeDirty() -> [(BaselineKey, BaselineEntry?)] {
        lock.lock(); defer { lock.unlock() }
        let out = dirty.map { ($0, entries[$0]) }
        dirty.removeAll()
        return out
    }

    /// Puts keys back after a failed save so the next pass retries them.
    public func markDirty<S: Sequence>(_ keys: S) where S.Element == BaselineKey {
        lock.lock(); defer { lock.unlock() }
        dirty.formUnion(keys)
    }
}
