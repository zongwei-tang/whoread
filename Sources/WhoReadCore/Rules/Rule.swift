import Foundation

/// What a rule protects.
public enum RuleTarget: Hashable, Sendable {
    case category(String)
    /// Every path whose *effective* (file-level) severity is at least this.
    case severityAtLeast(Severity)
    /// A path prefix (component boundary). `~/` expands to each monitored home.
    case pathPrefix(String)
}

/// Who a rule applies to.
public enum RuleSubject: Hashable, Sendable {
    /// Team ID + signing ID. A nil team ID matches only binaries without one (Apple platform binaries, ad-hoc).
    case signed(signingID: String, teamID: String?)
    /// Programs without a real signature: executable path, optionally pinned to a cdhash.
    case unsigned(path: String, cdhash: String?)
    /// The attributed responsible entity (what the UI shows as "the app"), optionally pinned to the
    /// team ID of the bundle's code, or to the cdhash of an unsigned binary (brief §5: path + cdhash).
    /// Used by "block from now on" / "always allow" actions. `exceptOwners` keeps category owners
    /// (ssh, git…) working when the responsible app is a terminal or IDE.
    case responsible(key: String, teamID: String?, cdhash: String? = nil, exceptOwners: Bool = false)
    /// Any process that is not an owner of the target's category.
    case anyNonOwner
    /// Any process with a known AI agent in its ancestor chain (itself included).
    /// `agentIDs == nil` means any agent.
    case agentAncestor(agentIDs: [String]?, exceptOwners: Bool)

    /// Decisions for this subject depend on more than the executable file (chain, argv).
    var isChainDependent: Bool {
        switch self {
        case .agentAncestor, .anyNonOwner, .responsible: return true
        case .signed, .unsigned: return false
        }
    }
}

public enum RuleAccess: String, Codable, CaseIterable, Sendable {
    case read
    case write
    case any

    func intersect(_ access: AccessSet) -> AccessSet {
        switch self {
        case .read: return access.intersection(.read)
        case .write: return access.intersection(.write)
        case .any: return access
        }
    }
}

public enum RuleAction: String, Codable, CaseIterable, Sendable {
    case allow
    case deny
    case alert
}

public struct Rule: Codable, Hashable, Sendable, Identifiable {
    public var id: String
    public var name: String?
    /// The user turned this rule on.
    public var enabled: Bool
    /// For deny rules: actually block (when global enforcement is on). Off = dry run ("would block").
    public var enforce: Bool
    public var target: RuleTarget
    public var subject: RuleSubject
    public var access: RuleAccess
    public var action: RuleAction
    /// Allow `.anyNonOwner` deny rules to hit Apple platform binaries. Agent-chain rules and rules
    /// naming a specific binary always apply.
    public var includePlatformBinaries: Bool
    public var expiresAt: Date?
    /// "Allow once" rules start at 1.
    public var remainingUses: Int?
    public var createdAt: Date
    public var template: String?
    /// Carve-outs from a deny rule ("allow once", "always allow" on a blocked access). Deny keeps the
    /// highest priority; exceptions narrow what it covers instead of being overridden by allows.
    public var exceptions: [RuleException]
    /// The rule applies only to chains whose AI agents are all in this list; nil = any chain. Answers
    /// to ask-mode questions set it (an approval for an app never covers it driven by another agent).
    public var chainAgents: [String]?
    /// With `chainAgents`: also chains whose ancestry is unknown (they may hide an AI agent above the
    /// agents seen). Only answers given for such a chain, knowing it, set it.
    public var coversUnknownAncestry: Bool

    public init(
        id: String = UUID().uuidString,
        name: String? = nil,
        enabled: Bool = true,
        enforce: Bool = false,
        target: RuleTarget,
        subject: RuleSubject,
        access: RuleAccess = .any,
        action: RuleAction,
        includePlatformBinaries: Bool = false,
        expiresAt: Date? = nil,
        remainingUses: Int? = nil,
        createdAt: Date = Date(),
        template: String? = nil,
        exceptions: [RuleException] = [],
        chainAgents: [String]? = nil,
        coversUnknownAncestry: Bool = false
    ) {
        self.id = id
        self.name = name
        self.enabled = enabled
        self.enforce = enforce
        self.target = target
        self.subject = subject
        self.access = access
        self.action = action
        self.includePlatformBinaries = includePlatformBinaries
        self.expiresAt = expiresAt
        self.remainingUses = remainingUses
        self.createdAt = createdAt
        self.template = template
        self.exceptions = exceptions
        self.chainAgents = chainAgents
        self.coversUnknownAncestry = coversUnknownAncestry
    }

    /// Decisions depend on time, a use counter, or exceptions that do.
    var isTimeDependent: Bool {
        expiresAt != nil || remainingUses != nil || exceptions.contains { $0.expiresAt != nil || $0.remainingUses != nil }
    }

    var hasChainDependentExceptions: Bool { exceptions.contains { $0.subject.isChainDependent || $0.chainAgents != nil } }

    /// An allow scoped to the agents of a chain covers this one: only those agents (or none), and a chain
    /// whose ancestry is unknown only if the answer was given for such a chain.
    static func scopeCovers(agents scope: [String]?, unknownAncestry: Bool, chainAgents: Set<String>, ancestryKnown: Bool) -> Bool {
        guard let scope else { return true }
        return chainAgents.isSubset(of: Set(scope)) && (ancestryKnown || unknownAncestry)
    }

    public func isLive(at now: Date) -> Bool {
        guard enabled else { return false }
        if let expiresAt, now >= expiresAt { return false }
        if let remainingUses, remainingUses <= 0 { return false }
        return true
    }

    enum CodingKeys: String, CodingKey {
        case id, name, enabled, enforce, target, subject, access, action, includePlatformBinaries
        case expiresAt, remainingUses, createdAt, template, exceptions, chainAgents, coversUnknownAncestry
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
        name = try c.decodeIfPresent(String.self, forKey: .name)
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        enforce = try c.decodeIfPresent(Bool.self, forKey: .enforce) ?? false
        target = try c.decode(RuleTarget.self, forKey: .target)
        subject = try c.decode(RuleSubject.self, forKey: .subject)
        access = try c.decodeIfPresent(RuleAccess.self, forKey: .access) ?? .any
        action = try c.decode(RuleAction.self, forKey: .action)
        includePlatformBinaries = try c.decodeIfPresent(Bool.self, forKey: .includePlatformBinaries) ?? false
        expiresAt = try c.decodeIfPresent(Date.self, forKey: .expiresAt)
        remainingUses = try c.decodeIfPresent(Int.self, forKey: .remainingUses)
        createdAt = try c.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date(timeIntervalSince1970: 0)
        template = try c.decodeIfPresent(String.self, forKey: .template)
        exceptions = try c.decodeIfPresent([RuleException].self, forKey: .exceptions) ?? []
        chainAgents = try c.decodeIfPresent([String].self, forKey: .chainAgents)
        coversUnknownAncestry = try c.decodeIfPresent(Bool.self, forKey: .coversUnknownAncestry) ?? false
    }
}

/// A carve-out from a rule.
public struct RuleException: Codable, Hashable, Sendable, Identifiable {
    public var id: String
    public var subject: RuleSubject
    /// Narrow the exception to one path prefix; nil = everything the rule targets.
    public var pathPrefix: String?
    /// Narrow the exception to one category; nil = every category the rule targets.
    public var categoryID: String?
    /// Narrow the exception to the access kind the user approved; nil = any. A request the exception
    /// does not fully cover falls through to the deny (and does not use up an "allow once").
    public var access: RuleAccess?
    /// The AI agents that were in the chain when the user approved; nil = not scoped. A chain with
    /// any other agent is not covered (an approved app's binary cannot be a tunnel for another agent).
    public var chainAgents: [String]?
    /// As `Rule.coversUnknownAncestry`.
    public var coversUnknownAncestry: Bool
    public var expiresAt: Date?
    public var remainingUses: Int?
    public var createdAt: Date

    public init(id: String = UUID().uuidString, subject: RuleSubject, pathPrefix: String? = nil, categoryID: String? = nil,
                access: RuleAccess? = nil, chainAgents: [String]? = nil, coversUnknownAncestry: Bool = false,
                expiresAt: Date? = nil, remainingUses: Int? = nil, createdAt: Date = Date()) {
        self.id = id
        self.subject = subject
        self.pathPrefix = pathPrefix
        self.categoryID = categoryID
        self.access = access
        self.chainAgents = chainAgents
        self.coversUnknownAncestry = coversUnknownAncestry
        self.expiresAt = expiresAt
        self.remainingUses = remainingUses
        self.createdAt = createdAt
    }

    enum CodingKeys: String, CodingKey {
        case id, subject, pathPrefix, categoryID, access, chainAgents, coversUnknownAncestry, expiresAt, remainingUses, createdAt
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        subject = try c.decode(RuleSubject.self, forKey: .subject)
        pathPrefix = try c.decodeIfPresent(String.self, forKey: .pathPrefix)
        categoryID = try c.decodeIfPresent(String.self, forKey: .categoryID)
        access = try c.decodeIfPresent(RuleAccess.self, forKey: .access)
        chainAgents = try c.decodeIfPresent([String].self, forKey: .chainAgents)
        coversUnknownAncestry = try c.decodeIfPresent(Bool.self, forKey: .coversUnknownAncestry) ?? false
        expiresAt = try c.decodeIfPresent(Date.self, forKey: .expiresAt)
        remainingUses = try c.decodeIfPresent(Int.self, forKey: .remainingUses)
        createdAt = try c.decode(Date.self, forKey: .createdAt)
    }

    public func isLive(at now: Date) -> Bool {
        if let expiresAt, now >= expiresAt { return false }
        if let remainingUses, remainingUses <= 0 { return false }
        return true
    }
}

// MARK: - Readable JSON for targets and subjects

extension RuleTarget: Codable {
    enum CodingKeys: String, CodingKey { case category, severityAtLeast, pathPrefix }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        if let v = try c.decodeIfPresent(String.self, forKey: .category) {
            self = .category(v)
        } else if let v = try c.decodeIfPresent(Severity.self, forKey: .severityAtLeast) {
            self = .severityAtLeast(v)
        } else if let v = try c.decodeIfPresent(String.self, forKey: .pathPrefix) {
            self = .pathPrefix(v)
        } else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown rule target"))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .category(let v): try c.encode(v, forKey: .category)
        case .severityAtLeast(let v): try c.encode(v, forKey: .severityAtLeast)
        case .pathPrefix(let v): try c.encode(v, forKey: .pathPrefix)
        }
    }
}

extension RuleSubject: Codable {
    enum CodingKeys: String, CodingKey { case type, signingID, teamID, path, cdhash, agentIDs, exceptOwners, key }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        switch try c.decode(String.self, forKey: .type) {
        case "signed":
            self = .signed(signingID: try c.decode(String.self, forKey: .signingID),
                           teamID: try c.decodeIfPresent(String.self, forKey: .teamID))
        case "unsigned":
            self = .unsigned(path: try c.decode(String.self, forKey: .path),
                             cdhash: try c.decodeIfPresent(String.self, forKey: .cdhash))
        case "responsible":
            self = .responsible(key: try c.decode(String.self, forKey: .key),
                                teamID: try c.decodeIfPresent(String.self, forKey: .teamID),
                                cdhash: try c.decodeIfPresent(String.self, forKey: .cdhash),
                                exceptOwners: try c.decodeIfPresent(Bool.self, forKey: .exceptOwners) ?? false)
        case "anyNonOwner":
            self = .anyNonOwner
        case "agentAncestor":
            self = .agentAncestor(agentIDs: try c.decodeIfPresent([String].self, forKey: .agentIDs),
                                  exceptOwners: try c.decodeIfPresent(Bool.self, forKey: .exceptOwners) ?? true)
        case let other:
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "unknown subject \(other)"))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .signed(let sid, let team):
            try c.encode("signed", forKey: .type)
            try c.encode(sid, forKey: .signingID)
            try c.encodeIfPresent(team, forKey: .teamID)
        case .unsigned(let path, let cdhash):
            try c.encode("unsigned", forKey: .type)
            try c.encode(path, forKey: .path)
            try c.encodeIfPresent(cdhash, forKey: .cdhash)
        case .responsible(let key, let team, let cdhash, let exceptOwners):
            try c.encode("responsible", forKey: .type)
            try c.encode(key, forKey: .key)
            try c.encodeIfPresent(team, forKey: .teamID)
            try c.encodeIfPresent(cdhash, forKey: .cdhash)
            if exceptOwners { try c.encode(true, forKey: .exceptOwners) }
        case .anyNonOwner:
            try c.encode("anyNonOwner", forKey: .type)
        case .agentAncestor(let ids, let exceptOwners):
            try c.encode("agentAncestor", forKey: .type)
            try c.encodeIfPresent(ids, forKey: .agentIDs)
            try c.encode(exceptOwners, forKey: .exceptOwners)
        }
    }
}

/// Built-in rule templates. All ship disabled and in dry-run.
public enum RuleTemplates {
    /// `Rule.template` of rules saved from answers to ask-mode questions (docs/ASK_MODE.md). Expired
    /// ones ("allow once") are dropped by `RuleEngine.pruneDeadExceptions`.
    public static let askAnswer = "ask-answer"

    /// "禁止任何祖先链中包含 AI agent 的进程读取 critical 类别"
    public static func blockAgentsFromCritical() -> Rule {
        Rule(
            id: "template.block-agents-critical",
            name: "Block AI agents from reading critical files",
            enabled: false,
            enforce: false,
            target: .severityAtLeast(.critical),
            // Brief §5: deny beats owner. Turn exceptOwners on to let e.g. ssh keep reading keys for
            // an agent's `git push`; owners are matched by location/identity, which agents can abuse
            // (`curl -T ~/.netrc`, `git diff --no-index /dev/null key`).
            subject: .agentAncestor(agentIDs: nil, exceptOwners: false),
            access: .read,
            action: .deny,
            createdAt: Date(timeIntervalSince1970: 0),
            template: "block-agents-critical")
    }

    /// Alert whenever an agent chain touches anything high or above, even if the baseline knows it.
    public static func alertAgentsOnHigh() -> Rule {
        Rule(
            id: "template.alert-agents-high",
            name: "Always alert when AI agents touch high-severity files",
            enabled: false,
            target: .severityAtLeast(.high),
            subject: .agentAncestor(agentIDs: nil, exceptOwners: true),
            access: .any,
            action: .alert,
            createdAt: Date(timeIntervalSince1970: 0),
            template: "alert-agents-high")
    }

    /// Deny anything that is not an expected owner from reading SSH keys (non-platform binaries only).
    public static func denyNonOwnersSSH() -> Rule {
        Rule(
            id: "template.deny-nonowner-ssh",
            name: "Block non-owners from reading SSH keys",
            enabled: false,
            enforce: false,
            target: .category("ssh"),
            subject: .anyNonOwner,
            access: .read,
            action: .deny,
            createdAt: Date(timeIntervalSince1970: 0),
            template: "deny-nonowner-ssh")
    }

    public static var all: [Rule] { [blockAgentsFromCritical(), alertAgentsOnHigh(), denyNonOwnersSSH()] }
}
