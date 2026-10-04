import Foundation
import WhoReadCore
import WhoReadIPC

/// A user notification to post (UNUserNotificationCenter in the app).
public struct PlannedNotification: Equatable, Sendable {
    public var identifier: String
    public var alertID: Int64
    public var title: String
    public var body: String
    public var categoryIdentifier: String
    public var threadIdentifier: String
    public var actions: [AlertAction]
}

/// A notification about the daemon itself rather than an alert (e.g. enforcement switched off).
public struct SystemNotice: Equatable, Sendable {
    public var identifier: String
    public var title: String
    public var body: String

    public init(identifier: String, title: String, body: String) {
        self.identifier = identifier
        self.title = title
        self.body = body
    }
}

/// Decides which alerts deserve a notification: new ones, and ones that escalated (e.g. a
/// first-access alert that later got blocked, or a write after reads). Merged repeats never re-notify.
///
/// The alert's status does not matter: an agent running as the user could mark its own alert
/// read or ignored before the next poll.
public final class NotificationPlanner: @unchecked Sendable {
    private struct Seen {
        var createdAt: Date
        var kind: AlertKind
        /// The coalescer moves it on every escalation (also a new access kind at the same level),
        /// never on a merged repeat.
        var firstEventID: Int64
    }

    private var notified: [Int64: Seen] = [:]
    private var seeded = false
    private let launchedAt: Date
    private var lastTripReason: String?

    public static let categoryBlocked = "whoread.blocked"
    public static let categoryAlert = "whoread.alert"
    public static let categoryWouldBlock = "whoread.wouldblock"

    public static func category(for kind: AlertKind) -> String {
        switch kind {
        case .blocked: return categoryBlocked
        case .wouldBlock: return categoryWouldBlock
        default: return categoryAlert
        }
    }

    /// `launchedAt`: alerts created before this are not notified on the first plan.
    /// `notifiedTrip`: the latency trip already reported, kept by the app across launches.
    public init(launchedAt: Date = Date(), notifiedTrip: String? = nil) {
        self.launchedAt = launchedAt
        self.lastTripReason = notifiedTrip
    }

    /// The latency trip last reported (nil once a status showed none), for the app to keep.
    public var notifiedTrip: String? { lastTripReason }

    /// The first plan only records alerts from before launch (no burst of old notifications);
    /// alerts raised since launch notify even if the daemon was unreachable until now.
    public func plan(_ alerts: [Alert], settings: NotificationSettings, formatter: AlertFormatter) -> [PlannedNotification] {
        defer { seeded = true }
        var out: [PlannedNotification] = []
        for a in alerts.sorted(by: { $0.updatedAt < $1.updatedAt }) {
            // Same id, different creation time: the daemon reused the id (its alert table was
            // emptied by retention and it restarted). That is a new alert.
            let previous = notified[a.id].flatMap { abs($0.createdAt.timeIntervalSince(a.createdAt)) < 1 ? $0 : nil }
            let isNew = previous == nil
            let escalated = previous.map { a.kind.priority > $0.kind.priority || a.firstEventID != $0.firstEventID } ?? false
            let kind = previous.map { $0.kind.priority >= a.kind.priority ? $0.kind : a.kind } ?? a.kind
            notified[a.id] = Seen(createdAt: a.createdAt, kind: kind, firstEventID: a.firstEventID)
            // Not updatedAt: repeats merged since launch move it on alerts notified before.
            guard isNew || escalated, seeded || a.createdAt >= launchedAt else { continue }
            guard settings.enabled else { continue }
            guard a.severity >= settings.minimumSeverity || a.kind == .blocked else { continue }
            if a.kind == .wouldBlock && !settings.notifyWouldBlock { continue }
            let title = a.kind == .blocked ? L10n.t(.notifBlockedTitle, formatter.language) : L10n.t(.notifTitle, formatter.language)
            out.append(PlannedNotification(
                identifier: "alert-\(a.id)-\(Int(a.createdAt.timeIntervalSince1970))-\(a.kind.rawValue)-\(a.firstEventID)", alertID: a.id, title: title,
                body: formatter.headline(a) + "\n" + formatter.chainLine(a.chain),
                categoryIdentifier: NotificationPlanner.category(for: a.kind), threadIdentifier: a.categoryID,
                actions: a.availableActions))
        }
        return out
    }

    /// Brief §5: when the latency monitor switches enforcement off, tell the user (once per trip;
    /// the daemon keeps reporting a past trip until enforcement is turned on again). Posted whatever
    /// the notification settings say: blocking silently stopped.
    public func plan(status: DaemonStatus, language: Language) -> [SystemNotice] {
        defer { lastTripReason = status.latencyTripReason }
        guard let trip = status.latencyTripReason, trip != lastTripReason else { return [] }
        return [SystemNotice(identifier: "whoread.enforcement-tripped", title: L10n.t(.notifEnforcementTrippedTitle, language),
                             body: L10n.f(.notifEnforcementTrippedBodyFormat, trip, language: language))]
    }
}

/// Onboarding: Full Disk Access, system extension approval, daemon running — each detected live
/// from daemon status (FDA problems surface as the source failing with NOT_PERMITTED).
public struct OnboardingModel: Equatable, Sendable {
    public enum StepState: Equatable, Sendable {
        case pending
        case waiting
        case done
        /// The extension activates after the next restart (`.willCompleteAfterReboot`).
        case needsRestart
        case failed(String)
    }

    /// macOS 13+ first, then the pre-13 form (see docs/RESEARCH.md #1).
    public static let fullDiskAccessURLs = [
        "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles",
        "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
    ]
    public static let loginItemsExtensionsURL = "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"

    /// What this app session saw of its own activation request.
    public var extensionState: StepState = .pending

    public init(extensionState: StepState = .pending) {
        self.extensionState = extensionState
    }

    /// Done once the daemon answers through the extension's Mach service (or runs the native
    /// Endpoint Security source), even if the extension was approved before this launch.
    public func extensionStepState(_ status: DaemonStatus?, connected: Bool, viaExtension: Bool) -> StepState {
        if connected, let s = status, viaExtension || s.source == .native { return .done }
        return extensionState
    }

    public func fullDiskAccessState(_ status: DaemonStatus?, connected: Bool) -> StepState {
        guard connected, let s = status else { return .waiting }
        if s.sourceRunning { return .done }
        let text = ((s.sourceError ?? "") + " " + (s.sourceHint ?? "")).lowercased()
        if text.contains("not_permitted") || text.contains("full disk access") || text.contains("permitted") {
            return .waiting
        }
        return s.sourceError.map { .failed($0) } ?? .waiting
    }

    public func daemonState(_ status: DaemonStatus?, connected: Bool) -> StepState {
        guard connected, let s = status else { return .waiting }
        return s.sourceRunning ? .done : .waiting
    }

    public func isComplete(_ status: DaemonStatus?, connected: Bool) -> Bool {
        fullDiskAccessState(status, connected: connected) == .done && daemonState(status, connected: connected) == .done
    }
}

/// Editing state for the rule sheet.
public struct RuleDraft: Equatable, Sendable {
    public enum TargetKind: String, CaseIterable, Sendable { case category, severity, path }
    public enum SubjectKind: String, CaseIterable, Sendable { case signed, unsigned, app, anyNonOwner, agentChain }

    public var id: String?
    public var name = ""
    public var targetKind: TargetKind = .category
    public var categoryID = "ssh"
    public var severity: Severity = .critical
    public var pathPrefix = ""
    public var subjectKind: SubjectKind = .agentChain
    public var signingID = ""
    public var teamID = ""
    /// A signed subject with no Team ID matches only Apple platform and ad-hoc binaries, so that
    /// has to be chosen explicitly rather than by leaving the field empty.
    public var signedWithoutTeam = false
    public var unsignedPath = ""
    public var cdhash = ""
    public var appKey = ""
    public var appTeamID = ""
    public var appCdhash = ""
    public var appExceptOwners = false
    public var agentIDs: [String] = []
    public var exceptOwners = true
    public var access: RuleAccess = .read
    public var action: RuleAction = .deny
    public var enabled = true
    public var enforce = false
    public var includePlatformBinaries = false
    public var exceptions: [RuleException] = []
    /// The rule (or template) this draft started from: keeps what the editor does not show.
    public var original: Rule?

    public init() {}

    public init(rule r: Rule) {
        id = r.id
        name = r.name ?? ""
        switch r.target {
        case .category(let c): targetKind = .category; categoryID = c
        case .severityAtLeast(let s): targetKind = .severity; severity = s
        case .pathPrefix(let p): targetKind = .path; pathPrefix = p
        }
        switch r.subject {
        case .signed(let sid, let team): subjectKind = .signed; signingID = sid; teamID = team ?? ""; signedWithoutTeam = team == nil
        case .unsigned(let p, let cd): subjectKind = .unsigned; unsignedPath = p; cdhash = cd ?? ""
        case .responsible(let k, let t, let cd, let ex):
            subjectKind = .app; appKey = k; appTeamID = t ?? ""; appCdhash = cd ?? ""; appExceptOwners = ex
        case .anyNonOwner: subjectKind = .anyNonOwner
        case .agentAncestor(let ids, let ex): subjectKind = .agentChain; agentIDs = ids ?? []; exceptOwners = ex
        }
        access = r.access
        action = r.action
        enabled = r.enabled
        enforce = r.enforce
        includePlatformBinaries = r.includePlatformBinaries
        exceptions = r.exceptions
        original = r
    }

    /// A new rule starting from a built-in template. The name stays empty so the localized
    /// template name is shown (`AppModel.ruleName`).
    public init(template t: Rule) {
        self.init(rule: t)
        id = nil
        name = ""
    }

    /// Picking an app pins the identity it was last seen with, as "block from now on" does: its
    /// Team ID, or the cdhash of an unsigned binary (brief §5: path + cdhash). Unpinned, a rule on
    /// `bin:<path>` would match whatever binary is later written to that path.
    public mutating func selectApp(_ row: AppRow) {
        guard row.id != appKey else { return }
        appKey = row.id
        appTeamID = row.teamID ?? ""
        appCdhash = (row.kind == .binary && row.teamID == nil ? row.cdhash : nil) ?? ""
    }

    public mutating func setAgent(_ id: String, selected: Bool) {
        agentIDs.removeAll { $0 == id }
        if selected { agentIDs.append(id) }
    }

    static func isCdhash(_ s: String) -> Bool { s.count == 40 && s.allSatisfy(\.isHexDigit) }

    /// nil when valid, otherwise the hint to show.
    public func validationError() -> L? {
        switch targetKind {
        case .category where categoryID.isEmpty: return .ruleErrCategory
        case .path where !(pathPrefix.hasPrefix("/") || pathPrefix.hasPrefix("~/")): return .ruleErrPath
        default: break
        }
        let cd = cdhash.trimmingCharacters(in: .whitespaces)
        switch subjectKind {
        case .signed where signingID.isEmpty: return .ruleErrSigningID
        case .signed where teamID.isEmpty && !signedWithoutTeam: return .ruleErrTeamID
        case .unsigned where !unsignedPath.hasPrefix("/"): return .ruleErrProgramPath
        case .unsigned where !cd.isEmpty && !RuleDraft.isCdhash(cd): return .ruleErrCdhash
        case .app where appKey.isEmpty: return .ruleErrApp
        default: return nil
        }
    }

    public func build(now: Date = Date()) -> Rule {
        let target: RuleTarget
        switch targetKind {
        case .category: target = .category(categoryID)
        case .severity: target = .severityAtLeast(severity)
        case .path: target = .pathPrefix(pathPrefix)
        }
        let subject: RuleSubject
        switch subjectKind {
        case .signed:
            subject = .signed(signingID: signingID, teamID: signedWithoutTeam || teamID.isEmpty ? nil : teamID)
        case .unsigned:
            let cd = cdhash.trimmingCharacters(in: .whitespaces).lowercased()
            subject = .unsigned(path: unsignedPath, cdhash: cd.isEmpty ? nil : cd)
        case .app:
            subject = .responsible(key: appKey, teamID: appTeamID.isEmpty ? nil : appTeamID,
                                   cdhash: appCdhash.isEmpty ? nil : appCdhash, exceptOwners: appExceptOwners)
        case .anyNonOwner: subject = .anyNonOwner
        case .agentChain: subject = .agentAncestor(agentIDs: agentIDs.isEmpty ? nil : agentIDs, exceptOwners: exceptOwners)
        }
        // Editing keeps expiry, use count and creation time; a template only lends its provenance.
        let edited = id != nil && original?.id == id ? original : nil
        return Rule(id: id ?? UUID().uuidString, name: name.isEmpty ? nil : name, enabled: enabled, enforce: enforce,
                    target: target, subject: subject, access: access, action: action,
                    includePlatformBinaries: includePlatformBinaries, expiresAt: edited?.expiresAt,
                    remainingUses: edited?.remainingUses, createdAt: edited?.createdAt ?? now, template: original?.template,
                    exceptions: exceptions)
    }
}

extension Rule {
    /// This rule as edited in the app, with what the daemon changes on its own taken from its
    /// current copy: exceptions (a used "allow once", an "always allow" from a banner), use count
    /// and expiry. The editor shows none of them, and the app's copy can be up to 10 s old.
    /// Without a current copy (a new rule) it is saved as built.
    public func keepingDaemonState(of current: Rule?) -> Rule {
        guard let current else { return self }
        var r = self
        r.exceptions = current.exceptions
        r.remainingUses = current.remainingUses
        r.expiresAt = current.expiresAt
        return r
    }
}
