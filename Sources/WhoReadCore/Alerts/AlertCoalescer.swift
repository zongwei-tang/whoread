import Foundation

/// Merges repeated events of the same app on the same category into one alert per window.
///
/// The window starts when the alert is created (default 10 minutes). While it is open, *every*
/// event of that (app, category) — alert-worthy or not — bumps the count, so "Zoom read your SSH
/// keys ×51" stays truthful after the first read made the triple known.
/// Blocked attempts and accesses that went through are counted in separate alerts, so "blocked ×6"
/// never includes a read that succeeded.
///
/// Ask mode: accesses denied because a question was not answered (kind `.ask`) get a third kind of
/// alert, apart from rule blocks: answering an ask alert answers the question, which must not
/// stand for a rule's denials (nor a rule's "allow once" for a question). Ask alerts are also kept
/// apart by the AI agents in the chain, as questions are: an answer for an app never covers it
/// driven by another agent. Read and write questions of one app on one category share an alert.
public final class AlertCoalescer: @unchecked Sendable {
    private enum Lane: Hashable {
        /// The access went through (or would have: monitor only).
        case passed
        /// Denied by a rule (or only along with another category).
        case blocked
        /// Denied while waiting for an answer; the sorted agent ids in the whole chain, and whether the
        /// chain is known (an answer for a known chain never covers one whose ancestry was lost).
        case asked(chainAgents: [String], ancestryKnown: Bool)
    }

    /// `responsibleKey`: what the baseline knows the app or AI agent by (`ResponsibleEntity.baselineKey`):
    /// an agent with a team and a process that only looks like it (no team) are not one alert
    /// (attribution-2), or the impostor's accesses would join an alert the user already handled.
    private struct Key: Hashable {
        var responsibleKey: String
        var categoryID: String
        var lane: Lane
    }

    private static func lane(kind: AlertKind?, denied: Bool, chainAgents: [String], ancestryKnown: Bool?) -> Lane {
        // Records from before the ancestry was kept count as known, as their answers were scoped then.
        if kind == .ask { return .asked(chainAgents: chainAgents, ancestryKnown: ancestryKnown ?? true) }
        return denied ? .blocked : .passed
    }

    private let lock = NSLock()
    private var open: [Key: Alert] = [:]
    private var nextID: Int64
    public var window: TimeInterval
    public var maxPaths: Int
    /// Open windows kept at most (dos-1: distinct unsigned program paths are distinct apps, so a
    /// flood is not merged). Beyond it the windows that close first are dropped: a later event of
    /// that app and category then opens a new alert instead of joining the old one.
    public let maxOpen: Int

    public init(window: TimeInterval = 600, nextID: Int64 = 1, maxPaths: Int = 8, maxOpen: Int = 10_000) {
        self.window = window
        self.nextID = nextID
        self.maxPaths = maxPaths
        self.maxOpen = max(1, maxOpen)
    }

    /// Reloads alerts whose window is still open (after a daemon restart).
    public func restore(openAlerts: [Alert], nextID: Int64) {
        lock.lock(); defer { lock.unlock() }
        self.nextID = max(self.nextID, nextID)
        for a in openAlerts {
            open[Key(responsibleKey: a.responsible.baselineKey, categoryID: a.categoryID,
                     lane: AlertCoalescer.lane(kind: a.kind, denied: a.kind == .blocked, chainAgents: a.scopeAgents,
                                               ancestryKnown: a.ancestryKnown))] = a
        }
    }

    /// Feeds one analyzed event. `kind` is non-nil if the event on its own deserves an alert;
    /// `firstTime` says the (app, category, access) was new to the baseline (wording only);
    /// `appleProgram` that the alert may offer "allow all Apple programs".
    public func ingest(_ event: AnalyzedEvent, kind: AlertKind?, firstTime: Bool = false, appleProgram: Bool = false) -> AlertUpdate? {
        lock.lock(); defer { lock.unlock() }
        let key = Key(responsibleKey: event.responsible.baselineKey, categoryID: event.categoryID,
                      lane: AlertCoalescer.lane(kind: kind, denied: event.decision == .denied,
                                                chainAgents: event.chainAgents ?? Set(event.chain.compactMap(\.agentID)).sorted(),
                                                ancestryKnown: event.ancestryKnown))
        if var alert = open[key], event.time < alert.windowEndsAt {
            // A new kind of access (a write after reads) is news even at the same alert level.
            let addsAccess = kind != nil && !alert.accesses.isSuperset(of: event.access)
            alert.count += 1
            alert.updatedAt = max(alert.updatedAt, event.time)
            alert.accesses.formUnion(event.access)
            alert.lastEventID = event.id
            if event.severity > alert.severity { alert.severity = event.severity }
            var change = AlertUpdate.Change.merged
            if let kind, kind.priority > alert.kind.priority || addsAccess {
                let raises = kind.priority > alert.kind.priority
                if raises {
                    alert.kind = kind
                    alert.ruleID = event.ruleID ?? alert.ruleID
                }
                if raises || kind == alert.kind {
                    // A new access of the same kind (another rule's, for a rule's alert): firstPath and ruleID
                    // describe the same access (daemon-8).
                    if !raises { alert.ruleID = event.ruleID ?? alert.ruleID }
                    alert.firstTime = firstTime
                    alert.appleProgram = appleProgram
                    // The event that made it worse is the one the headline and "allow once" are about. Accesses
                    // seen of that file before count too, except for a rule's alert it just became: the
                    // headline then says what the rule matched.
                    let sameFile = event.path == alert.firstPath && !(raises && AlertCoalescer.namesARule(kind))
                    alert.firstPathAccess = sameFile ? alert.firstPathAccess.map { $0.union(event.access) } : event.access
                    alert.firstPath = event.path
                    alert.chain = event.chain
                    alert.chainAgents = event.chainAgents
                    alert.ancestryKnown = event.ancestryKnown
                    alert.agentID = event.agentID ?? alert.agentID
                    alert.paths.removeAll { $0 == event.path }
                    alert.paths.insert(event.path, at: 0)
                    if alert.paths.count > maxPaths { alert.paths.removeLast(alert.paths.count - maxPaths) }
                } else if alert.paths.count < maxPaths && !alert.paths.contains(event.path) {
                    // A new access of a lower kind (a first write next to a rule's would-block): news, but the
                    // headline keeps naming the access that gave the alert its kind, and says this one apart.
                    alert.paths.append(event.path)
                }
                // Every escalation moves it (clients notify again on it; an action on the alert holds only
                // while it has not moved), a merged repeat never does.
                alert.firstEventID = event.id
                // Got worse: surface it again even if the user had dismissed it.
                alert.status = .unread
                alert.resolution = nil
                change = .escalated
            } else {
                // A repeat of the file it names, of an access no rule is named for: the headline says it too.
                if event.path == alert.firstPath && (kind == alert.kind || (kind == nil && !AlertCoalescer.namesARule(alert.kind))) {
                    alert.firstPathAccess = alert.firstPathAccess.map { $0.union(event.access) }
                }
                if alert.paths.count < maxPaths && !alert.paths.contains(event.path) { alert.paths.append(event.path) }
            }
            open[key] = alert
            return AlertUpdate(alert: alert, change: change)
        }
        guard let kind else {
            if let a = open[key], event.time >= a.windowEndsAt { open[key] = nil }
            return nil
        }
        if open.count >= maxOpen { makeRoom(at: event.time) }
        let alert = Alert(
            id: nextID, kind: kind, createdAt: event.time, updatedAt: event.time,
            windowEndsAt: event.time.addingTimeInterval(window), responsible: event.responsible,
            categoryID: event.categoryID, severity: event.severity, count: 1, accesses: event.access,
            firstPath: event.path, firstEventID: event.id, lastEventID: event.id, paths: [event.path],
            chain: event.chain, agentID: event.agentID, ruleID: event.ruleID, firstTime: firstTime, appleProgram: appleProgram,
            chainAgents: event.chainAgents, ancestryKnown: event.ancestryKnown, firstPathAccess: event.access)
        nextID += 1
        open[key] = alert
        return AlertUpdate(alert: alert, change: .created)
    }

    /// Kinds whose headline is about what a rule matched (its block, would-block or alert): only an access
    /// of that kind changes what the headline names.
    static func namesARule(_ kind: AlertKind) -> Bool { kind == .wouldBlock || kind == .blocked || kind == .ruleAlert }

    /// What became of a status change on an open alert (`setStatus`).
    public enum StatusChange: Equatable, Sendable {
        /// Open and unchanged since the copy acted on (merged repeats aside): the open copy, which now has
        /// the new status.
        case changed(Alert)
        /// It escalated since that copy (a new kind, a new access, a worse file the user has not seen):
        /// left as it is, unread.
        case escalated(Alert)
        /// Not open here (its window closed): nothing changed.
        case notOpen
    }

    /// Sets the status of the open alerts the user acted on, each only if it did not escalate since the
    /// copy acted on: compare-and-set on `firstEventID`, which every escalation moves (a new kind with
    /// it) and a merged repeat never does, so an escalation that lands while an action is applied is
    /// never marked handled (daemon-3). One result per copy.
    public func setStatus(of acted: [Alert], to status: AlertStatus, resolution: AlertAction?) -> [StatusChange] {
        lock.lock(); defer { lock.unlock() }
        guard !acted.isEmpty else { return [] }
        var keys: [Int64: Key] = [:]
        for (k, a) in open { keys[a.id] = k }
        return acted.map { seen in
            guard let k = keys[seen.id], var a = open[k] else { return .notOpen }
            guard a.firstEventID == seen.firstEventID else { return .escalated(a) }
            a.status = status
            a.resolution = resolution
            open[k] = a
            return .changed(a)
        }
    }

    /// Keeps the in-memory copy in sync when the user acts on an alert.
    public func updateStatus(alertID: Int64, status: AlertStatus, resolution: AlertAction?) {
        lock.lock(); defer { lock.unlock() }
        for (k, var a) in open where a.id == alertID {
            a.status = status
            a.resolution = resolution
            open[k] = a
        }
    }

    /// Drops closed windows, then (still full) the tenth of the windows that close first, so a
    /// flood sorts once per thousand new alerts rather than on every one. Lock held.
    private func makeRoom(at now: Date) {
        open = open.filter { now < $0.value.windowEndsAt }
        guard open.count >= maxOpen else { return }
        let drop = open.count - maxOpen + max(1, maxOpen / 10)
        for (key, _) in open.sorted(by: { $0.value.windowEndsAt < $1.value.windowEndsAt }).prefix(drop) { open[key] = nil }
    }

    /// Drops closed windows.
    public func expire(now: Date) {
        lock.lock(); defer { lock.unlock() }
        open = open.filter { now < $0.value.windowEndsAt }
    }

    public var openCount: Int {
        lock.lock(); defer { lock.unlock() }
        return open.count
    }

    public var peekNextID: Int64 {
        lock.lock(); defer { lock.unlock() }
        return nextID
    }
}
