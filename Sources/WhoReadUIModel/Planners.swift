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

/// Decides which alerts deserve a notification: new ones, and ones that escalated (e.g. a
/// first-access alert that later got blocked). Merged repeats never re-notify.
public final class NotificationPlanner: @unchecked Sendable {
    private var notified: [Int64: AlertKind] = [:]
    private var seeded = false

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

    public init() {}

    /// The first poll after launch only records what exists: no burst of old notifications.
    public func plan(_ alerts: [Alert], settings: NotificationSettings, formatter: AlertFormatter) -> [PlannedNotification] {
        defer { seeded = true }
        var out: [PlannedNotification] = []
        for a in alerts.sorted(by: { $0.updatedAt < $1.updatedAt }) {
            let previous = notified[a.id]
            let isNew = previous == nil
            let escalated = previous.map { a.kind.priority > $0.priority } ?? false
            if let p = previous, p.priority >= a.kind.priority {
                notified[a.id] = p
            } else {
                notified[a.id] = a.kind
            }
            guard seeded, isNew || escalated else { continue }
            guard settings.enabled, a.status == .unread else { continue }
            guard a.severity >= settings.minimumSeverity || a.kind == .blocked else { continue }
            if a.kind == .wouldBlock && !settings.notifyWouldBlock { continue }
            let title = a.kind == .blocked ? L10n.t(.notifBlockedTitle, formatter.language) : L10n.t(.notifTitle, formatter.language)
            out.append(PlannedNotification(
                identifier: "alert-\(a.id)-\(a.kind.rawValue)", alertID: a.id, title: title,
                body: formatter.headline(a) + "\n" + formatter.chainLine(a.chain),
                categoryIdentifier: NotificationPlanner.category(for: a.kind), threadIdentifier: a.categoryID,
                actions: a.availableActions))
        }
        return out
    }
}

/// Onboarding: Full Disk Access, system extension approval, daemon running — each detected live
/// from daemon status (FDA problems surface as the source failing with NOT_PERMITTED).
public struct OnboardingModel: Equatable, Sendable {
    public enum StepState: Equatable, Sendable {
        case pending
        case waiting
        case done
        case failed(String)
    }

    /// macOS 13+ first, then the pre-13 form (see docs/RESEARCH.md #1).
    public static let fullDiskAccessURLs = [
        "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles",
        "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
    ]
    public static let loginItemsExtensionsURL = "x-apple.systempreferences:com.apple.LoginItems-Settings.extension"

    public var extensionState: StepState = .pending

    public init(extensionState: StepState = .pending) {
        self.extensionState = extensionState
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
    public var unsignedPath = ""
    public var cdhash = ""
    public var appKey = ""
    public var appTeamID = ""
    public var agentIDs: [String] = []
    public var exceptOwners = true
    public var access: RuleAccess = .read
    public var action: RuleAction = .deny
    public var enabled = true
    public var enforce = false
    public var includePlatformBinaries = false
    public var exceptions: [RuleException] = []

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
        case .signed(let sid, let team): subjectKind = .signed; signingID = sid; teamID = team ?? ""
        case .unsigned(let p, let cd): subjectKind = .unsigned; unsignedPath = p; cdhash = cd ?? ""
        case .responsible(let k, let t): subjectKind = .app; appKey = k; appTeamID = t ?? ""
        case .anyNonOwner: subjectKind = .anyNonOwner
        case .agentAncestor(let ids, let ex): subjectKind = .agentChain; agentIDs = ids ?? []; exceptOwners = ex
        }
        access = r.access
        action = r.action
        enabled = r.enabled
        enforce = r.enforce
        includePlatformBinaries = r.includePlatformBinaries
        exceptions = r.exceptions
    }

    /// nil when valid, otherwise what is missing (English, for logs / tests; UI shows field hints).
    public func validationError() -> String? {
        switch targetKind {
        case .category where categoryID.isEmpty: return "category"
        case .path where !(pathPrefix.hasPrefix("/") || pathPrefix.hasPrefix("~/")): return "path must start with / or ~/"
        default: break
        }
        switch subjectKind {
        case .signed where signingID.isEmpty: return "signing ID"
        case .unsigned where !unsignedPath.hasPrefix("/"): return "program path"
        case .app where appKey.isEmpty: return "app"
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
        case .signed: subject = .signed(signingID: signingID, teamID: teamID.isEmpty ? nil : teamID)
        case .unsigned: subject = .unsigned(path: unsignedPath, cdhash: cdhash.isEmpty ? nil : cdhash.lowercased())
        case .app: subject = .responsible(key: appKey, teamID: appTeamID.isEmpty ? nil : appTeamID)
        case .anyNonOwner: subject = .anyNonOwner
        case .agentChain: subject = .agentAncestor(agentIDs: agentIDs.isEmpty ? nil : agentIDs, exceptOwners: exceptOwners)
        }
        return Rule(id: id ?? UUID().uuidString, name: name.isEmpty ? nil : name, enabled: enabled, enforce: enforce,
                    target: target, subject: subject, access: access, action: action,
                    includePlatformBinaries: includePlatformBinaries, createdAt: now, exceptions: exceptions)
    }
}
