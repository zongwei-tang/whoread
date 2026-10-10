import Foundation

/// Ask mode (replaces the learning period). While enforcement is active, an access to a sensitive
/// file that no rule, owner, benign service or "trust Apple programs" decides is held and the user
/// is asked; the answer is saved as a rule. Unanswered within the deadline budget, it is denied.

/// What an answer applies to: one app (or agent) × category × access, scoped to the AI agents that
/// were in the chain (an approval for an app never covers the same app driven by another agent).
public struct AskKey: Codable, Hashable, Sendable {
    public var responsibleKey: String
    public var categoryID: String
    /// The requested access kinds (read, write or both).
    public var access: AccessSet
    /// Agent ids in the chain, sorted; empty = no AI agent.
    public var chainAgents: [String]

    public init(responsibleKey: String, categoryID: String, access: AccessSet, chainAgents: [String]) {
        self.responsibleKey = responsibleKey
        self.categoryID = categoryID
        self.access = access
        self.chainAgents = chainAgents.sorted()
    }
}

/// How the rule engine treats undecided sensitive accesses.
public struct AskPolicy: Sendable, Equatable {
    /// Ask instead of allowing by default (only meaningful with enforcement active).
    public var enabled: Bool
    /// Apple programs in system locations are allowed without asking, unless an AI agent is in the chain.
    public var trustApplePrograms: Bool
    /// The chain is a benign system service (Spotlight, Time Machine…): never asked.
    public var benignChain: Bool

    public init(enabled: Bool, trustApplePrograms: Bool, benignChain: Bool) {
        self.enabled = enabled
        self.trustApplePrograms = trustApplePrograms
        self.benignChain = benignChain
    }

    public static let off = AskPolicy(enabled: false, trustApplePrograms: false, benignChain: false)
}

/// One pending question, as the app and the CLI see it. Many accesses with the same key share one
/// request (`attempts`); answering it answers all of them.
public struct AskRequest: Codable, Hashable, Sendable, Identifiable {
    public var id: Int64
    public var key: AskKey
    public var responsible: ResponsibleEntity
    public var severity: Severity
    /// The first path asked about (display).
    public var path: String
    /// Leaf process (argv redacted).
    public var process: ProcessRecord
    /// Root → leaf, capped like stored chains.
    public var chain: [ChainLink]
    public var agentID: String?
    /// Eligible for "trust Apple programs": an Apple program in a system location, no AI agent.
    public var appleProgram: Bool
    public var firstAt: Date
    public var lastAt: Date
    /// Accesses that asked so far (held, answered or denied while waiting).
    public var attempts: Int
    /// Accesses currently held, waiting for this answer.
    public var holding: Int
    /// When the earliest held access is answered "deny" if nobody answers (wall clock); nil = none held.
    public var answerBy: Date?

    public init(id: Int64, key: AskKey, responsible: ResponsibleEntity, severity: Severity, path: String,
                process: ProcessRecord, chain: [ChainLink], agentID: String?, appleProgram: Bool,
                firstAt: Date, lastAt: Date, attempts: Int = 1, holding: Int = 0, answerBy: Date? = nil) {
        self.id = id
        self.key = key
        self.responsible = responsible
        self.severity = severity
        self.path = path
        self.process = process
        self.chain = chain
        self.agentID = agentID
        self.appleProgram = appleProgram
        self.firstAt = firstAt
        self.lastAt = lastAt
        self.attempts = attempts
        self.holding = holding
        self.answerBy = answerBy
    }
}

extension AskPolicy {
    /// An Apple program in a root-owned system location (a copied Apple binary keeps its platform flag,
    /// so only the location tells a system tool from a copy).
    public static func isAppleProgram(_ p: ProcessRecord) -> Bool {
        p.isPlatformBinary && IdentitySpec.isSystemLocation(p.executablePath)
    }

    /// What "trust Apple programs" covers, and when "allow all Apple programs" is offered: the leaf and
    /// every ancestor up to launchd are Apple programs in system locations, and no AI agent is in the
    /// chain. Checking only the leaf would let any app read files through /bin/cat or /bin/sh
    /// (`Zoom → sh → cat`); with the whole chain, `Terminal → zsh → cat` counts and that does not.
    /// `chain` is leaf first, as ProcessTree.chain returns it. A chain that does not reach launchd is
    /// never trusted: an ancestor that is unknown (parent never seen, reparented process whose original
    /// parent is gone) or beyond a cut-short chain could be anything, an AI agent included.
    public static func isTrustableAppleProgram(_ process: ProcessRecord, chain: [ProcessNode]) -> Bool {
        guard isAppleProgram(process), chain.reachesLaunchd else { return false }
        for node in chain {
            if node.agentID != nil { return false }
            if node.image.isSystemRoot { continue }  // launchd
            // A libproc image (no event seen from it yet) has a platform flag guessed from its path.
            if node.fromSnapshot || !isAppleProgram(node.image) { return false }
        }
        return true
    }
}
