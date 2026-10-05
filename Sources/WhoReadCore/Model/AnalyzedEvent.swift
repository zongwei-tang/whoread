import Foundation

/// What happened to an access, as far as enforcement goes.
public enum EventDecision: String, Codable, Sendable {
    /// Monitor only (NOTIFY event) and no rule had an opinion.
    case observed
    /// Allowed by an AUTH decision.
    case allowed
    /// Denied by an AUTH decision (the caller got EPERM).
    case denied
    /// A deny rule matched but was in dry run or enforcement was off.
    case wouldDeny
}

/// A classified, attributed access to one sensitive path. This is what gets stored and shown.
public struct AnalyzedEvent: Codable, Hashable, Sendable, Identifiable {
    public var id: Int64
    public var time: Date
    public var operation: FileOperation
    public var access: AccessSet
    /// The sensitive path (canonical).
    public var path: String
    /// The other path of a two-path operation (rename destination, clone source…), if any.
    public var secondaryPath: String?
    /// True when `path` is a parent directory of the category (e.g. renaming `~/.config`).
    public var viaAncestor: Bool
    public var categoryID: String
    public var severity: Severity
    public var process: ProcessRecord
    /// Root first: launchd → … → process.
    public var chain: [ChainLink]
    public var responsible: ResponsibleEntity
    /// Nearest AI agent in the chain (the process itself included).
    public var agentID: String?
    public var isOwner: Bool
    /// Non-nil when a benign system service did this; such events are folded in the UI.
    public var benignServiceID: String?
    public var decision: EventDecision
    public var ruleID: String?
    public var alertID: Int64?

    public init(
        id: Int64, time: Date, operation: FileOperation, access: AccessSet, path: String, secondaryPath: String?,
        viaAncestor: Bool = false, categoryID: String, severity: Severity, process: ProcessRecord, chain: [ChainLink],
        responsible: ResponsibleEntity, agentID: String?, isOwner: Bool, benignServiceID: String?,
        decision: EventDecision, ruleID: String?, alertID: Int64? = nil
    ) {
        self.id = id
        self.time = time
        self.operation = operation
        self.access = access
        self.path = path
        self.secondaryPath = secondaryPath
        self.viaAncestor = viaAncestor
        self.categoryID = categoryID
        self.severity = severity
        self.process = process
        self.chain = chain
        self.responsible = responsible
        self.agentID = agentID
        self.isOwner = isOwner
        self.benignServiceID = benignServiceID
        self.decision = decision
        self.ruleID = ruleID
        self.alertID = alertID
    }

    public var isBenign: Bool { benignServiceID != nil }

    /// "launchd → zoom.us → cat"
    public var chainDisplay: String { chain.map(\.name).joined(separator: " → ") }
}

public enum AlertKind: String, Codable, Sendable, CaseIterable {
    /// This app had never touched this category with this access (monitor only, or an access that
    /// went through without a question). There is no learning period by default.
    case firstAccess
    /// A non-owner (or an owner driven by an AI agent) touched a critical file the user has not
    /// approved for this app (an app's approval never covers it driven by an agent); repeats alert
    /// again after each coalescing window.
    case criticalNonOwner
    /// An alert rule matched.
    case ruleAlert
    /// A deny rule would have blocked this (dry run / enforcement off).
    case wouldBlock
    /// Blocked.
    case blocked
    /// Ask mode: an access was denied for want of an answer to its question (none in time, no app
    /// to ask, or "deny"). Answering the alert is answering the question.
    case ask

    /// Higher wins when coalescing.
    public var priority: Int {
        switch self {
        case .ruleAlert: return 0
        case .firstAccess: return 1
        case .criticalNonOwner: return 2
        case .wouldBlock: return 3
        case .blocked: return 4
        case .ask: return 5
        }
    }
}

public enum AlertStatus: String, Codable, Sendable {
    case unread
    case read
    case resolved
}

/// What the user chose on an alert or notification.
public enum AlertAction: String, Codable, Sendable, CaseIterable {
    /// Blocked/would-block: let the next access through (10 minutes, one use).
    case allowOnce
    /// Blocked: permanent exception on the rule. Otherwise: approve in the baseline.
    case alwaysAllow
    /// Non-blocked alerts: create an enforcing deny rule for this app on this category.
    case blockFromNowOn
    /// Blocked: keep the rule as is.
    case keepBlocking
    case ignore
    /// Ask mode: allow Apple programs in system locations without asking (not under an AI agent).
    case trustApplePrograms
}

/// One alert, possibly standing for many coalesced events.
public struct Alert: Codable, Hashable, Sendable, Identifiable {
    public var id: Int64
    public var kind: AlertKind
    public var createdAt: Date
    public var updatedAt: Date
    /// Events for the same (app, category) until this time merge into this alert.
    public var windowEndsAt: Date
    public var responsible: ResponsibleEntity
    public var categoryID: String
    public var severity: Severity
    public var count: Int
    public var accesses: AccessSet
    /// First event's details, for the headline.
    public var firstPath: String
    public var firstEventID: Int64
    public var lastEventID: Int64
    /// Distinct paths seen (capped).
    public var paths: [String]
    public var chain: [ChainLink]
    public var agentID: String?
    public var ruleID: String?
    public var status: AlertStatus
    public var resolution: AlertAction?
    /// The (app, category, access) combination had never been seen before (outside a learning
    /// period, which is off by default).
    public var firstTime: Bool
    /// The requester was an Apple program in a system location with no AI agent in its chain
    /// (offers "trust Apple programs").
    public var appleProgram: Bool

    public init(id: Int64, kind: AlertKind, createdAt: Date, updatedAt: Date, windowEndsAt: Date,
                responsible: ResponsibleEntity, categoryID: String, severity: Severity, count: Int, accesses: AccessSet,
                firstPath: String, firstEventID: Int64, lastEventID: Int64, paths: [String], chain: [ChainLink],
                agentID: String?, ruleID: String?, status: AlertStatus = .unread, resolution: AlertAction? = nil,
                firstTime: Bool = false, appleProgram: Bool = false) {
        self.id = id
        self.kind = kind
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.windowEndsAt = windowEndsAt
        self.responsible = responsible
        self.categoryID = categoryID
        self.severity = severity
        self.count = count
        self.accesses = accesses
        self.firstPath = firstPath
        self.firstEventID = firstEventID
        self.lastEventID = lastEventID
        self.paths = paths
        self.chain = chain
        self.agentID = agentID
        self.ruleID = ruleID
        self.status = status
        self.resolution = resolution
        self.firstTime = firstTime
        self.appleProgram = appleProgram
    }

    enum CodingKeys: String, CodingKey {
        case id, kind, createdAt, updatedAt, windowEndsAt, responsible, categoryID, severity, count, accesses, firstPath
        case firstEventID, lastEventID, paths, chain, agentID, ruleID, status, resolution, firstTime, appleProgram
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(Int64.self, forKey: .id)
        kind = try c.decode(AlertKind.self, forKey: .kind)
        createdAt = try c.decode(Date.self, forKey: .createdAt)
        updatedAt = try c.decode(Date.self, forKey: .updatedAt)
        windowEndsAt = try c.decode(Date.self, forKey: .windowEndsAt)
        responsible = try c.decode(ResponsibleEntity.self, forKey: .responsible)
        categoryID = try c.decode(String.self, forKey: .categoryID)
        severity = try c.decode(Severity.self, forKey: .severity)
        count = try c.decode(Int.self, forKey: .count)
        accesses = try c.decode(AccessSet.self, forKey: .accesses)
        firstPath = try c.decode(String.self, forKey: .firstPath)
        firstEventID = try c.decode(Int64.self, forKey: .firstEventID)
        lastEventID = try c.decode(Int64.self, forKey: .lastEventID)
        paths = try c.decodeIfPresent([String].self, forKey: .paths) ?? []
        chain = try c.decodeIfPresent([ChainLink].self, forKey: .chain) ?? []
        agentID = try c.decodeIfPresent(String.self, forKey: .agentID)
        ruleID = try c.decodeIfPresent(String.self, forKey: .ruleID)
        status = try c.decodeIfPresent(AlertStatus.self, forKey: .status) ?? .unread
        resolution = try c.decodeIfPresent(AlertAction.self, forKey: .resolution)
        firstTime = try c.decodeIfPresent(Bool.self, forKey: .firstTime) ?? false
        appleProgram = try c.decodeIfPresent(Bool.self, forKey: .appleProgram) ?? false
    }

    /// Actions offered for this alert, in display order.
    public var availableActions: [AlertAction] {
        switch kind {
        case .blocked: return [.allowOnce, .alwaysAllow, .keepBlocking]
        case .ask: return [.allowOnce, .alwaysAllow, .keepBlocking, .blockFromNowOn] + (appleProgram ? [.trustApplePrograms] : [])
        case .wouldBlock: return [.alwaysAllow, .ignore]
        // Monitor-only stand-ins for a question: the same "allow all Apple programs" answer.
        case .firstAccess, .criticalNonOwner:
            return [.alwaysAllow, .blockFromNowOn, .ignore] + (appleProgram ? [.trustApplePrograms] : [])
        default: return [.alwaysAllow, .blockFromNowOn, .ignore]
        }
    }
}

/// Created or changed alert, for persistence and notifications.
public struct AlertUpdate: Sendable, Hashable {
    public enum Change: String, Sendable { case created, merged, escalated }
    public var alert: Alert
    public var change: Change

    /// Worth a user notification (new alert, or it got worse).
    public var shouldNotify: Bool { change != .merged }
}
