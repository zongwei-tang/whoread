import Foundation
#if os(macOS)
import Observation
#endif
import WhoReadCore
import WhoReadIPC

/// One poll's worth of daemon state. Fetched off the main thread, applied on it.
public struct Snapshot: Sendable {
    public var status: DaemonStatus?
    public var alerts: [Alert] = []
    public var newLive: [AnalyzedEvent] = []
    public var summaries: [UsageSummary]?
    public var rules: [Rule]?
    public var settings: Settings?
    public var catalog: CatalogInfo?
    public var agents: AgentCatalog?
    public var error: IPCError?

    public init() {}
}

public enum SnapshotFetcher {
    /// Fast poll (every second): status, alerts, live tail. Full poll (every ~10 s, or after a
    /// change) adds summaries, rules, settings and the catalog.
    public static func fetch(_ client: IPCClient, liveAfter: Int64?, includeBenign: Bool, full: Bool) -> Snapshot {
        var s = Snapshot()
        do {
            s.status = try client.status()
            s.alerts = try client.alerts(AlertQuery(limit: 300))
            if case .events(let e) = try client.call(.live(afterID: liveAfter, limit: 500, includeBenign: includeBenign)) {
                s.newLive = e
            }
            if full {
                s.summaries = try client.summaries(since: nil)
                s.rules = try client.rules()
                s.settings = try client.settings()
                s.catalog = try client.catalog()
                s.agents = try client.agents()
            }
        } catch let e as IPCError {
            s.error = e
        } catch {
            s.error = IPCError(.unavailable, "\(error)")
        }
        return s
    }
}

/// Newest-first ring of live events.
public struct LiveFeed: Sendable {
    public private(set) var events: [AnalyzedEvent] = []
    public private(set) var lastID: Int64?
    public var capacity = 2000

    public init() {}

    public mutating func append(_ new: [AnalyzedEvent]) {
        let fresh = new.filter { e in lastID.map { e.id > $0 } ?? true }.sorted { $0.id > $1.id }
        guard !fresh.isEmpty else { return }
        events.insert(contentsOf: fresh, at: 0)
        if events.count > capacity { events.removeLast(events.count - capacity) }
        lastID = max(lastID ?? 0, fresh.first!.id)
    }

    public func visible(showSystemNoise: Bool) -> [AnalyzedEvent] {
        showSystemNoise ? events : events.filter { !$0.isBenign }
    }
}

public struct AppRow: Identifiable, Hashable, Sendable {
    public var id: String
    public var name: String
    public var kind: ResponsibleEntity.Kind
    public var categories: [String]
    public var firstSeen: Date
    public var lastSeen: Date
    public var count: Int
    public var denied: Int
}

public struct FileRow: Identifiable, Hashable, Sendable {
    public var id: String
    public var name: String
    public var severity: Severity
    public var detected: Bool
    public var apps: [String]
    public var lastSeen: Date?
    public var count: Int
}

public struct AgentRow: Identifiable, Hashable, Sendable {
    public var id: String
    public var name: String
    public var categories: [String]
    public var blocked: Int
    public var lastSeen: Date
    public var count: Int
}

public struct MenuBarState: Equatable, Sendable {
    public var symbol: String
    public var title: String
    public var unread: Int
    public var connected: Bool

    public var badge: String? { unread > 0 ? (unread > 99 ? "99+" : String(unread)) : nil }

    public static func make(status: DaemonStatus?, connected: Bool, language: Language) -> MenuBarState {
        guard connected, let s = status else {
            return MenuBarState(symbol: "eye.slash", title: L10n.t(.daemonUnreachable, language), unread: 0, connected: false)
        }
        let symbol: String
        switch s.mode {
        case .learning: symbol = "graduationcap"
        case .monitoring: symbol = "eye"
        case .enforcing: symbol = "lock.shield"
        case .paused: symbol = "pause.circle"
        case .error: symbol = "exclamationmark.triangle"
        }
        return MenuBarState(symbol: symbol, title: L10n.mode(s.mode, language), unread: s.unreadAlerts, connected: true)
    }
}

/// State for the menu bar and the main window. Mutate on the main thread only (SwiftUI).
///
/// `@Observable` on macOS only: the Linux development toolchain's libswiftObservation fails to
/// link, and the logic tested there does not depend on observation.
#if os(macOS)
@Observable
#endif
public final class AppModel {
    public private(set) var status: DaemonStatus?
    public private(set) var connected = false
    public private(set) var lastError: IPCError?
    public private(set) var alerts: [Alert] = []
    public private(set) var live = LiveFeed()
    public private(set) var summaries: [UsageSummary] = []
    public private(set) var rules: [Rule] = []
    public private(set) var settings: Settings?
    public private(set) var catalog: CatalogInfo?
    public private(set) var agents: AgentCatalog?
    public var showSystemNoise = false
    public var alertsUnreadOnly = false
    public var feedPaused = false
    public var searchText = ""
    public var language: Language

    public init(language: Language = L10n.current) {
        self.language = language
    }

    public func apply(_ s: Snapshot) {
        if let e = s.error {
            lastError = e
            connected = e.code != .unavailable
            return
        }
        lastError = nil
        connected = true
        status = s.status ?? status
        alerts = s.alerts
        if !feedPaused { live.append(s.newLive) }
        if let v = s.summaries { summaries = v }
        if let v = s.rules { rules = v }
        if let v = s.settings {
            settings = v
            if let l = v.language { language = l }
        }
        if let v = s.catalog { catalog = v }
        if let v = s.agents { agents = v }
    }

    /// Where the next live poll should start.
    public var liveCursor: Int64? { live.lastID }

    public var menuBar: MenuBarState { MenuBarState.make(status: status, connected: connected, language: language) }

    public var formatter: AlertFormatter {
        let homes = catalog?.homeDirectories ?? status?.homeDirectories ?? []
        let n = PathNormalizer(homeDirectories: homes)
        let catalog = self.catalog?.catalog
        return AlertFormatter(language: language, abbreviate: { n.abbreviate($0) }, categoryName: { catalog?.category($0)?.name })
    }

    public func abbreviate(_ path: String) -> String {
        PathNormalizer(homeDirectories: catalog?.homeDirectories ?? status?.homeDirectories ?? []).abbreviate(path)
    }

    public func categoryName(_ id: String) -> String {
        catalog?.catalog.category(id)?.name.resolve(language) ?? id
    }

    public func agentName(_ id: String) -> String {
        agents?.agent(id)?.name.resolve(language) ?? id
    }

    // MARK: - Tabs

    public var liveRows: [AnalyzedEvent] {
        let rows = live.visible(showSystemNoise: showSystemNoise)
        guard !searchText.isEmpty else { return rows }
        let q = searchText.lowercased()
        return rows.filter {
            $0.path.lowercased().contains(q) || $0.responsible.displayName.lowercased().contains(q) || $0.process.name.lowercased().contains(q)
        }
    }

    public var visibleAlerts: [Alert] {
        alertsUnreadOnly ? alerts.filter { $0.status == .unread } : alerts
    }

    public var unreadCount: Int { alerts.filter { $0.status == .unread }.count }

    public var appRows: [AppRow] {
        var groups: [String: [UsageSummary]] = [:]
        for s in summaries where showSystemNoise || !s.benign { groups[s.responsible.key, default: []].append(s) }
        return groups.map { key, list in
            AppRow(id: key, name: list[0].responsible.displayName, kind: list[0].responsible.kind,
                   categories: Array(Set(list.map(\.categoryID))).map(categoryName).sorted(),
                   firstSeen: list.map(\.firstSeen).min()!, lastSeen: list.map(\.lastSeen).max()!,
                   count: list.reduce(0) { $0 + $1.count }, denied: list.reduce(0) { $0 + $1.denied })
        }.sorted { $0.lastSeen > $1.lastSeen }
    }

    public var fileRows: [FileRow] {
        guard let info = catalog else { return [] }
        var byCategory: [String: [UsageSummary]] = [:]
        for s in summaries where showSystemNoise || !s.benign { byCategory[s.categoryID, default: []].append(s) }
        return info.catalog.categories.filter(\.enabled).map { c in
            let list = byCategory[c.id] ?? []
            return FileRow(id: c.id, name: c.name.resolve(language), severity: c.severity, detected: info.detected[c.id] ?? false,
                           apps: Array(Set(list.map(\.responsible.displayName))).sorted(), lastSeen: list.map(\.lastSeen).max(),
                           count: list.reduce(0) { $0 + $1.count })
        }.sorted { a, b in
            if (a.lastSeen != nil) != (b.lastSeen != nil) { return a.lastSeen != nil }
            if let x = a.lastSeen, let y = b.lastSeen, x != y { return x > y }
            return a.severity > b.severity
        }
    }

    public var agentRows: [AgentRow] {
        var groups: [String: [UsageSummary]] = [:]
        for s in summaries { if let a = s.agentID { groups[a, default: []].append(s) } }
        return groups.map { id, list in
            AgentRow(id: id, name: agentName(id), categories: Array(Set(list.map(\.categoryID))).map(categoryName).sorted(),
                     blocked: list.reduce(0) { $0 + $1.denied }, lastSeen: list.map(\.lastSeen).max()!,
                     count: list.reduce(0) { $0 + $1.count })
        }.sorted { $0.lastSeen > $1.lastSeen }
    }
}
