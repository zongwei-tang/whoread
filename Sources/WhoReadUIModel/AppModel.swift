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
    /// Ask mode: questions waiting for an answer (fetched on every poll; fetching them also tells
    /// the daemon an answering app is present).
    public var asks: [AskRequest] = []
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
    /// Fast poll (every second; while questions are open, the ticks in between fetch only them):
    /// status, open questions, alerts, live tail. Full poll (every ~10 s, or after a change) adds summaries, rules, settings
    /// and the catalog. `hello` starts with the version handshake, so a mismatched daemon is
    /// reported as such rather than as decoding errors.
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
            if case .asks(let a) = try client.call(.asks) { s.asks = a }
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

    /// Only the open questions (`PollSchedule.Kind.asks`); nil when they cannot be fetched (the
    /// next fast poll reports why).
    public static func fetchAsks(_ client: IPCClient) -> [AskRequest]? {
        guard case .asks(let a)? = try? client.call(.asks) else { return nil }
        return a
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
    /// The mode's symbol (popover header, window toolbar).
    public var symbol: String
    /// The mode's name.
    public var title: String
    public var unread: Int
    public var connected: Bool
    /// Ask mode: questions waiting for an answer.
    public var openAsks: Int = 0
    var language: Language = .en

    /// Open questions come first: they hold an access that is denied unless answered soon.
    public var badge: String? {
        let n = openAsks > 0 ? openAsks : unread
        return n > 0 ? (n > 99 ? "99+" : String(n)) : nil
    }

    /// The menu bar icon: a question mark while questions are open, the mode otherwise.
    public var labelSymbol: String { openAsks > 0 ? "questionmark.circle.fill" : symbol }

    public var accessibilityLabel: String {
        openAsks > 0 ? L10n.f(.asksWaitingFormat, openAsks, language: language) + " — " + title : title
    }

    public static func make(status: DaemonStatus?, connected: Bool, openAsks: Int = 0, language: Language) -> MenuBarState {
        guard connected, let s = status else {
            // Brief §6 Error state: nothing is being recorded, or (connected) nothing the daemon
            // says can be read; the reason is shown next to it.
            return MenuBarState(symbol: "exclamationmark.triangle",
                                title: L10n.t(.modeError, language) + (connected ? "" : " — " + L10n.t(.daemonUnreachable, language)),
                                unread: 0, connected: connected, language: language)
        }
        let symbol: String
        switch s.mode {
        // Ask mode replaced the learning period: never shown as a state of its own.
        case .learning, .monitoring: symbol = "eye"
        case .enforcing: symbol = "lock.shield"
        case .paused: symbol = "pause.circle"
        case .error: symbol = "exclamationmark.triangle"
        }
        return MenuBarState(symbol: symbol, title: L10n.mode(s.mode, language), unread: s.unreadAlerts, connected: true,
                            openAsks: openAsks, language: language)
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
    /// Ask mode: questions waiting for an answer, oldest first. Empty while the daemon cannot be read.
    public private(set) var asks: [AskRequest] = []
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
        case .mismatch(let m): versionProblem = DisplayText.escaped(m, limit: 1000)
        case nil: break
        }
        if let e = s.error {
            lastError = e
            connected = e.code != .unavailable
            // Nobody can answer them through a daemon that does not answer (or cannot be read).
            asks = []
            // The handshake's message (just set) reads better than a decoder dump.
            if e.code == .versionMismatch, versionProblem == nil { versionProblem = DisplayText.escaped(e.message, limit: 1000) }
            return
        }
        lastError = nil
        connected = true
        if let v = s.status { setStatus(v) }
        asks = s.asks
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
        case .asks(let v): asks = v
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

    /// A Settings form draft, with the fields that have their own switches (enforcement, pause,
    /// trust Apple programs) taken from the daemon's current state: saving an old draft must not
    /// undo a kill switch, or an "allow all Apple programs" answered since.
    public func preparedForSave(_ draft: Settings) -> Settings {
        var d = draft
        if let s = status {
            d.enforcementEnabled = s.enforcementEnabled
            d.monitoringPaused = s.monitoringPaused
        } else if let s = settings {
            d.enforcementEnabled = s.enforcementEnabled
            d.monitoringPaused = s.monitoringPaused
        }
        if let s = settings { d.trustApplePrograms = s.trustApplePrograms }
        return d
    }

    /// Where the next live poll should start.
    public var liveCursor: Int64? { live.lastID }

    /// `status` while it describes the running daemon: nil once that daemon answers in a protocol
    /// this app cannot read (another version replaced it). `status` is kept for restart detection.
    public var liveStatus: DaemonStatus? {
        lastError?.code == .versionMismatch ? nil : status
    }

    public var menuBar: MenuBarState {
        MenuBarState.make(status: liveStatus, connected: connected, openAsks: asks.count, language: language)
    }

    /// Open questions as listed (menu bar, Alerts tab): those holding an access first, the one
    /// denied soonest on top, then the others oldest first. The menu bar shows only the first few,
    /// and old questions that hold nothing must not hide one that is about to be denied.
    public var asksByUrgency: [AskRequest] {
        asks.enumerated().sorted { a, b in
            switch (a.element.answerBy, b.element.answerBy) {
            case let (x?, y?) where x != y: return x < y
            case (_?, nil): return true
            case (nil, _?): return false
            default: return a.offset < b.offset
            }
        }.map(\.element)
    }

    /// How long until the next poll: questions are answered (and their notifications withdrawn)
    /// within a quarter second while any is open.
    public var pollInterval: TimeInterval { PollSchedule.interval(openAsks: asks.count) }

    public var formatter: AlertFormatter {
        let homes = catalog?.homeDirectories ?? status?.homeDirectories ?? []
        let n = PathNormalizer(homeDirectories: homes)
        let catalog = self.catalog?.catalog
        return AlertFormatter(language: language, abbreviate: { n.abbreviate($0) }, categoryName: { catalog?.category($0)?.name })
    }

    // MARK: - Display text
    //
    // Names, paths and argv come from the programs and files themselves: everything below is for
    // showing, escaped (`DisplayText`) so a name cannot forge lines, reorder text or hide what
    // follows it. Never feed these back into rules or requests: use the raw values (keys, paths).

    /// A path as shown (`~/…`), escaped but not shortened (tables truncate it, details show it whole).
    public func abbreviate(_ path: String) -> String {
        DisplayText.escaped(PathNormalizer(homeDirectories: catalog?.homeDirectories ?? status?.homeDirectories ?? []).abbreviate(path))
    }

    /// Any other text from an event or a process (an executable path, a signing ID, argv), whole.
    public func display(_ text: String) -> String { DisplayText.escaped(text) }

    /// The app, agent or program an access is charged to.
    public func displayName(_ r: ResponsibleEntity) -> String { DisplayText.name(r.displayName) }

    public func categoryName(_ id: String) -> String {
        DisplayText.name(catalog?.catalog.category(id)?.name.resolve(language) ?? id)
    }

    public func agentName(_ id: String) -> String {
        DisplayText.name(agents?.agent(id)?.name.resolve(language) ?? id)
    }

    /// "Claude Code → zsh → cat", trimmed to the responsible app (`displayString`), each name escaped
    /// and capped, the whole cut in the middle when long.
    public func chainText(_ chain: [ChainLink], responsible: ResponsibleEntity) -> String {
        DisplayText.chain(chain, responsible: responsible)
    }

    /// The whole chain with each process's (redacted) arguments, one process per line.
    public func chainDetail(_ chain: [ChainLink]) -> String {
        chain.map { link in
            DisplayText.name(link.name) + (link.argv.map { " " + DisplayText.escaped($0.dropFirst().joined(separator: " "), limit: 300) } ?? "")
        }.joined(separator: "\n→ ")
    }

    /// "Program: ~/x/Terminal.app (not signed by an identified developer)" for a question or alert
    /// (`AlertFormatter.identityLine`): where the program really is and who signed it.
    public func identityLine(_ alert: Alert) -> String? { formatter.identityLine(alert) }

    // MARK: - Enforcement

    /// The enforcement switch as the user experiences it: off after the kill-switch file, even
    /// though the daemon's setting is still on. Nothing else switches it off: WhoRead never turns
    /// enforcement off on its own.
    public var enforcementSwitchOn: Bool {
        guard let s = status else { return false }
        return s.enforcementEnabled && !s.killSwitchFilePresent
    }

    /// "Not active: …" when the switch is on in the settings but enforcement is not live.
    public var enforcementInactiveText: String? {
        guard let s = status, !s.enforcementActive, s.enforcementEnabled else { return nil }
        let reasons = s.enforcementInactiveReasons.filter { $0 != .disabledByUser }.map { L10n.inactiveReason($0, language) }
        return reasons.isEmpty ? nil : L10n.f(.enforcementInactiveFormat, reasons.joined(separator: language == .zhHans ? "，" : ", "), language: language)
    }

    /// p99 is judged only over this many responses (as the daemon's latency monitor does).
    static let slowMinimumSamples = 50

    /// "Slow responses: …" when the status shows missed kernel deadlines or a p99 over the
    /// threshold in Settings. Shown, never acted on: enforcement stays as the user set it.
    public var slowResponsesText: String? {
        guard let l = liveStatus?.latency else { return nil }
        let thresholdMs = (settings ?? Settings()).latencyP99ThresholdMs
        var parts: [String] = []
        if l.deadlineMisses > 0 { parts.append(L10n.f(.slowMissesFormat, l.deadlineMisses, language: language)) }
        if l.samples >= AppModel.slowMinimumSamples && l.p99Micros > thresholdMs * 1000 {
            parts.append(L10n.f(.slowP99Format, String(format: "%.1f", l.p99Micros / 1000), String(format: "%.0f", thresholdMs),
                                language: language))
        }
        guard !parts.isEmpty else { return nil }
        return L10n.f(.slowResponsesFormat, parts.joined(separator: language == .zhHans ? "，" : ", "), language: language)
    }

    /// The daemon's previous instance stopped while it could block (killed for a missed deadline,
    /// a crash, power loss). Enforcement was left as the user set it.
    public var uncleanStopText: String? {
        liveStatus?.uncleanStop.map { L10n.f(.uncleanStopFormat, $0, language: language) }
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
                // The app part is the name the app gave itself when the rule was made.
                let app = DisplayText.name(String(name.dropFirst(prefix.count).dropLast(suffix.count)))
                return L10n.f(.ruleBlockAppFormat, app, DisplayText.name(category.resolve(language)), language: language)
            }
        }
        return DisplayText.escaped(r.name ?? r.id, limit: 2 * DisplayText.nameLimit + 40)
    }

    /// The AI agents a rule is scoped to (`Rule.chainAgents`, set by answers to questions); nil
    /// for a rule that applies to any chain. Without it, an answer for Terminal and one for Claude
    /// Code inside Terminal would read the same in the Rules tab.
    public func chainScope(_ r: Rule) -> String? {
        guard let agents = r.chainAgents else { return nil }
        if agents.isEmpty { return L10n.t(.ruleChainNoAgent, language) }
        return L10n.f(.ruleChainAgentsFormat, agents.map(agentName).joined(separator: ", "), language: language)
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

    /// Button title for an alert action: `ask` alerts use the question's answer wording.
    public func actionTitle(_ action: AlertAction, for kind: AlertKind) -> String {
        kind == .ask ? L10n.askActionTitle(action, language) : formatter.actionTitle(action)
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
            return AppRow(id: key, name: DisplayText.name(list[0].responsible.displayName), kind: list[0].responsible.kind,
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
            return FileRow(id: c.id, name: DisplayText.name(c.name.resolve(language)), severity: c.severity, detected: info.detected[c.id] ?? false,
                           apps: Array(Set(list.map { DisplayText.name($0.responsible.displayName) })).sorted(), lastSeen: list.map(\.lastSeen).max(),
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
