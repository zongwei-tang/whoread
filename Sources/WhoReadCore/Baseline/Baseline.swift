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
        /// Seen during the learning period.
        case learned
        /// Seen after learning (it alerted once, then became known).
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

/// Learned normal behaviour. Thread-safe.
public final class Baseline: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [BaselineKey: BaselineEntry]
    private var dirty: Set<BaselineKey> = []

    public private(set) var learningStartedAt: Date
    public var learningDuration: TimeInterval

    public init(learningStartedAt: Date, learningDuration: TimeInterval = 7 * 24 * 3600, entries: [BaselineEntry] = []) {
        self.learningStartedAt = learningStartedAt
        self.learningDuration = learningDuration
        self.entries = Dictionary(entries.map { ($0.key, $0) }, uniquingKeysWith: { a, _ in a })
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

    /// Entries changed since the last call, plus keys that were removed (nil entry). For incremental persistence.
    public func takeDirty() -> [(BaselineKey, BaselineEntry?)] {
        lock.lock(); defer { lock.unlock() }
        let out = dirty.map { ($0, entries[$0]) }
        dirty.removeAll()
        return out
    }
}
