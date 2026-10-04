import Foundation
#if os(macOS)
import Observation
#endif
import WhoReadCore
import WhoReadIPC

/// Outcome of the `.hello` version handshake.
public enum Handshake: Equatable, Sendable {
    case ok
    case mismatch(String)
}

/// One poll's worth of daemon state. Fetched off the main thread, applied on it.
public struct Snapshot: Sendable {
    /// Set when the poll started with a handshake (first poll, reconnect, daemon restart).
    public var handshake: Handshake?
    public var status: DaemonStatus?
    public var alerts: [Alert] = []
    /// Live events after `liveAfter` (the cursor this poll was fetched with).
    public var newLive: [AnalyzedEvent] = []
    public var liveAfter: Int64?
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
    /// change) adds summaries, rules, settings and the catalog. `hello` starts with the version
    /// handshake, so a mismatched daemon is reported as such rather than as decoding errors.
    public static func fetch(_ client: IPCClient, liveAfter: Int64?, includeBenign: Bool, full: Bool, hello: Bool = false) -> Snapshot {
        var s = Snapshot()
        s.liveAfter = liveAfter
        do {
            if hello {
                do {
                    _ = try client.call(.hello(clientVersion: whoReadIPCVersion))
                    s.handshake = .ok
                } catch let e as IPCError where e.code == .versionMismatch {
                    s.handshake = .mismatch(e.message)
                } catch let e as DecodingError {
                    s.handshake = .mismatch("\(e)")
                }
            }
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
        } catch let e as DecodingError {
            // The daemon answered in a shape this app does not know.
            s.error = IPCError(.versionMismatch, "\(e)")
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
    /// Identity as last seen, for rules on this app (`RuleDraft.selectApp`).
    public var teamID: String?
    public var cdhash: String?
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
            // Brief §6 Error state: nothing is being recorded, or (connected) nothing the daemon
            // says can be read; the reason is shown next to it.
            return MenuBarState(symbol: "exclamationmark.triangle",
                                title: L10n.t(.modeError, language) + (connected ? "" : " — " + L10n.t(.daemonUnreachable, language)),
                                unread: 0, connected: connected)
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
    /// The app and the daemon speak different protocol versions.
    public private(set) var versionProblem: String?
    /// Incremented when status shows a new daemon instance (pid or start time changed).
    public private(set) var daemonRestarts = 0
    public var showSystemNoise = false
    public var alertsUnreadOnly = false
    public var feedPaused = false
    public var searchText = ""
    public var language: Language
    /// What "System" in the language setting means (the language at launch).
    private let systemLanguage: Language

    public init(language: Language = L10n.current) {
        self.language = language
        self.systemLanguage = language
    }

    public func apply(_ s: Snapshot) {
        switch s.handshake {
        case .ok: versionProblem = nil
        case .mismatch(let m): versionProblem = m
        case nil: break
        }
        if let e = s.error {
            lastError = e
            connected = e.code != .unavailable
            // The handshake's message (just set) reads better than a decoder dump.
            if e.code == .versionMismatch, versionProblem == nil { versionProblem = e.message }
            return
        }
        lastError = nil
        connected = true
        if let v = s.status { setStatus(v) }
        alerts = s.alerts
        // A batch fetched with an older cursor (the feed was reset meanwhile) is dropped.
        if !feedPaused && s.liveAfter == live.lastID { live.append(s.newLive) }
        if let v = s.summaries { summaries = v }
        if let v = s.rules { rules = v }
        if let v = s.settings { setSettings(v) }
        if let v = s.catalog { catalog = v }
        if let v = s.agents { agents = v }
    }

    /// Applies the daemon's answer to a change right away, so the next edit starts from it.
    public func apply(response r: IPCResponse) {
        switch r {
        case .rules(let v): rules = v
        case .settings(let v): setSettings(v)
        case .catalog(let v): catalog = v
        case .status(let v): setStatus(v)
        default: break
        }
    }

    private func setStatus(_ new: DaemonStatus) {
        if let old = status, old.pid != new.pid || abs(old.startedAt.timeIntervalSince(new.startedAt)) > 1 {
            // A new daemon instance may reuse event ids this feed has already shown (events it
            // served live but never flushed). Start over; the next poll gets its whole ring.
            live = LiveFeed()
            daemonRestarts += 1
        }
        status = new
    }

    private func setSettings(_ v: Settings) {
        settings = v
        language = v.language ?? systemLanguage
    }

    /// A Settings form draft, with the fields that have their own switches (enforcement, pause)
    /// taken from the daemon's current state: saving an old draft must not undo a kill switch.
    public func preparedForSave(_ draft: Settings) -> Settings {
        var d = draft
        if let s = status {
            d.enforcementEnabled = s.enforcementEnabled
            d.monitoringPaused = s.monitoringPaused
        } else if let s = settings {
            d.enforcementEnabled = s.enforcementEnabled
            d.monitoringPaused = s.monitoringPaused
        }
        return d
    }

    /// Where the next live poll should start.
    public var liveCursor: Int64? { live.lastID }

    /// `status` while it describes the running daemon: nil once that daemon answers in a protocol
    /// this app cannot read (another version replaced it). `status` is kept for restart detection.
    public var liveStatus: DaemonStatus? {
        lastError?.code == .versionMismatch ? nil : status
    }

    public var menuBar: MenuBarState { MenuBarState.make(status: liveStatus, connected: connected, language: language) }

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

    // MARK: - Enforcement

    /// The enforcement switch as the user experiences it: off after the kill-switch file or a
    /// latency trip, even though the daemon's setting is still on.
    public var enforcementSwitchOn: Bool {
        guard let s = status else { return false }
        return s.enforcementEnabled && !s.killSwitchFilePresent && s.latencyTripReason == nil
    }

    /// "Not active: …" when the switch is on in the settings but enforcement is not live, or after a
    /// latency trip (which also turns the setting off, so the switch alone would look user-made).
    public var enforcementInactiveText: String? {
        guard let s = status, !s.enforcementActive, s.enforcementEnabled || s.latencyTripReason != nil else { return nil }
        var inactive = s.enforcementInactiveReasons.filter { $0 != .disabledByUser }
        // After a daemon restart the trip is only the stored reason.
        if s.latencyTripReason != nil && !inactive.contains(.latencyTripped) { inactive.insert(.latencyTripped, at: 0) }
        let reasons = inactive.map { r -> String in
            let text = L10n.inactiveReason(r, language)
            guard r == .latencyTripped, let why = s.latencyTripReason else { return text }
            return language == .zhHans ? text + "（\(why)）" : text + " (\(why))"
        }
        return reasons.isEmpty ? nil : L10n.f(.enforcementInactiveFormat, reasons.joined(separator: language == .zhHans ? "，" : ", "), language: language)
    }

    /// Why block rules (and "block from now on") do not block right now; nil when they do.
    public var enforcementCaveat: String? {
        guard let s = status, !s.enforcementActive else { return nil }
        return L10n.t(s.sourceCanEnforce ? .rulesEnforcementOffNote : .sourceCannotEnforceNote, language)
    }

    // MARK: - Rules

    /// Display name: built-in template names and "Block <app> from <category>" rules created by
    /// alert actions (stored in English) are shown in the UI language.
    public func ruleName(_ r: Rule) -> String {
        if let t = r.template, let localized = L10n.templateName(t, language),
           r.name == nil || r.name == RuleTemplates.all.first(where: { $0.template == t })?.name {
            return localized
        }
        if let name = r.name, r.action == .deny, case .responsible = r.subject, case .category(let id) = r.target,
           let category = catalog?.catalog.category(id)?.name {
            let prefix = "Block ", suffix = " from " + category.en
            if name.hasPrefix(prefix), name.hasSuffix(suffix), name.count > prefix.count + suffix.count {
                let app = String(name.dropFirst(prefix.count).dropLast(suffix.count))
                return L10n.f(.ruleBlockAppFormat, app, category.resolve(language), language: language)
            }
        }
        return r.name ?? r.id
    }

    /// Whether a rule's path prefix is covered by monitoring, as the daemon decides when saving it:
    /// inside a monitored prefix, or a parent of one (the rule matches the monitored files below).
    /// Saving a rule on an uncovered path adds that path to the Custom category.
    public func isMonitored(pathPrefix: String) -> Bool {
        guard let info = catalog else { return true }
        let expanded = PathNormalizer(homeDirectories: info.homeDirectories).expand(pathPrefix).map(PathNormalizer.fold)
        guard !expanded.isEmpty else { return false }
        let monitored = info.prefixes.map { PathNormalizer.fold($0.path) }
        return expanded.allSatisfy { p in
            let key = p.hasSuffix("/") ? String(p.dropLast()) : p
            return !key.isEmpty && monitored.contains { key == $0 || key.hasPrefix($0 + "/") || $0.hasPrefix(key + "/") }
        }
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
            let latest = list.max { $0.lastSeen < $1.lastSeen }!.responsible
            return AppRow(id: key, name: list[0].responsible.displayName, kind: list[0].responsible.kind,
                          categories: Array(Set(list.map(\.categoryID))).map(categoryName).sorted(),
                          firstSeen: list.map(\.firstSeen).min()!, lastSeen: list.map(\.lastSeen).max()!,
                          count: list.reduce(0) { $0 + $1.count }, denied: list.reduce(0) { $0 + $1.denied },
                          teamID: latest.teamID, cdhash: latest.cdhash)
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
