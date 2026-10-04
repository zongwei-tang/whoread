import Foundation

/// Merges repeated events of the same app on the same category into one alert per window.
///
/// The window starts when the alert is created (default 10 minutes). While it is open, *every*
/// event of that (app, category) — alert-worthy or not — bumps the count, so "Zoom read your SSH
/// keys ×51" stays truthful after the first read made the triple known.
/// Blocked attempts and accesses that went through are counted in separate alerts, so "blocked ×6"
/// never includes a read that succeeded.
public final class AlertCoalescer: @unchecked Sendable {
    private struct Key: Hashable {
        var responsibleKey: String
        var categoryID: String
        var blocked: Bool
    }

    private let lock = NSLock()
    private var open: [Key: Alert] = [:]
    private var nextID: Int64
    public var window: TimeInterval
    public var maxPaths: Int

    public init(window: TimeInterval = 600, nextID: Int64 = 1, maxPaths: Int = 8) {
        self.window = window
        self.nextID = nextID
        self.maxPaths = maxPaths
    }

    /// Reloads alerts whose window is still open (after a daemon restart).
    public func restore(openAlerts: [Alert], nextID: Int64) {
        lock.lock(); defer { lock.unlock() }
        self.nextID = max(self.nextID, nextID)
        for a in openAlerts {
            open[Key(responsibleKey: a.responsible.key, categoryID: a.categoryID, blocked: a.kind == .blocked)] = a
        }
    }

    /// Feeds one analyzed event. `kind` is non-nil if the event on its own deserves an alert;
    /// `firstTime` says the (app, category, access) was new to the baseline (wording only).
    public func ingest(_ event: AnalyzedEvent, kind: AlertKind?, firstTime: Bool = false) -> AlertUpdate? {
        lock.lock(); defer { lock.unlock() }
        let key = Key(responsibleKey: event.responsible.key, categoryID: event.categoryID, blocked: event.decision == .denied)
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
                if kind.priority > alert.kind.priority {
                    alert.kind = kind
                    alert.ruleID = event.ruleID ?? alert.ruleID
                }
                alert.firstTime = firstTime
                // The event that made it worse is the one the headline and "allow once" are about.
                alert.firstPath = event.path
                alert.firstEventID = event.id
                alert.chain = event.chain
                alert.agentID = event.agentID ?? alert.agentID
                alert.paths.removeAll { $0 == event.path }
                alert.paths.insert(event.path, at: 0)
                if alert.paths.count > maxPaths { alert.paths.removeLast(alert.paths.count - maxPaths) }
                // Got worse: surface it again even if the user had dismissed it.
                alert.status = .unread
                alert.resolution = nil
                change = .escalated
            } else if alert.paths.count < maxPaths && !alert.paths.contains(event.path) {
                alert.paths.append(event.path)
            }
            open[key] = alert
            return AlertUpdate(alert: alert, change: change)
        }
        guard let kind else {
            if let a = open[key], event.time >= a.windowEndsAt { open[key] = nil }
            return nil
        }
        let alert = Alert(
            id: nextID, kind: kind, createdAt: event.time, updatedAt: event.time,
            windowEndsAt: event.time.addingTimeInterval(window), responsible: event.responsible,
            categoryID: event.categoryID, severity: event.severity, count: 1, accesses: event.access,
            firstPath: event.path, firstEventID: event.id, lastEventID: event.id, paths: [event.path],
            chain: event.chain, agentID: event.agentID, ruleID: event.ruleID, firstTime: firstTime)
        nextID += 1
        open[key] = alert
        return AlertUpdate(alert: alert, change: .created)
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
