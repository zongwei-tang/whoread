import Foundation

/// The app (or agent, or binary) a file access is charged to.
public struct ResponsibleEntity: Codable, Hashable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case app
        case agent
        case binary
    }

    public var kind: Kind
    /// Stable key for baselines and grouping: "app:<bundle path>", "agent:<id>", "bin:<identity>".
    public var key: String
    public var displayName: String
    public var path: String?
    public var signingID: String?
    public var teamID: String?
    public var agentID: String?
    /// For unsigned, non-platform binaries: the cdhash, so rules can pin "path + cdhash".
    public var cdhash: String?

    public init(kind: Kind, key: String, displayName: String, path: String? = nil,
                signingID: String? = nil, teamID: String? = nil, agentID: String? = nil, cdhash: String? = nil) {
        self.kind = kind
        self.key = key
        self.displayName = displayName
        self.path = path
        self.signingID = signingID
        self.teamID = teamID
        self.agentID = agentID
        self.cdhash = cdhash
    }
}

/// One element of a displayed call chain.
public struct ChainLink: Codable, Hashable, Sendable {
    public var pid: Int32
    public var name: String
    public var path: String
    public var signingID: String?
    public var teamID: String?
    public var isPlatformBinary: Bool
    public var agentID: String?
    /// First few argv elements, for display only.
    public var argv: [String]?

    public init(node: ProcessNode, maxArgs: Int = 6, maxArgLength: Int = 200) {
        pid = node.image.pid
        name = node.image.name
        path = node.image.executablePath
        signingID = node.image.signingID
        teamID = node.image.teamID
        isPlatformBinary = node.image.isPlatformBinary
        agentID = node.agentID
        argv = ArgvRedactor.redact(node.image.argv, maxArgs: maxArgs, maxLength: maxArgLength)
    }

    public init(pid: Int32, name: String, path: String, signingID: String? = nil, teamID: String? = nil,
                isPlatformBinary: Bool = false, agentID: String? = nil, argv: [String]? = nil) {
        self.pid = pid
        self.name = name
        self.path = path
        self.signingID = signingID
        self.teamID = teamID
        self.isPlatformBinary = isPlatformBinary
        self.agentID = agentID
        self.argv = argv
    }
}

/// Walks a chain (leaf first) and decides who is responsible:
///
/// 1. the first node inside an `.app` bundle → the outermost `.app` (labelled as the agent if that
///    app is a known agent, e.g. Cursor or the Claude desktop app);
/// 2. else the first node that is a known AI agent → that agent;
/// 3. else the nearest non-platform-binary node (the leaf counts);
/// 4. else the top-most process below launchd (e.g. `sshd`, `cron`).
public struct Attributor: Sendable {
    public let agents: AgentDetector

    public init(agents: AgentDetector) {
        self.agents = agents
    }

    public func attribute(chain: [ProcessNode]) -> ResponsibleEntity {
        let walk = chain.filter { !$0.image.isSystemRoot }
        for node in walk {
            if let bundle = node.image.outermostAppBundle {
                // App agents (Cursor, Claude, ChatGPT) match on bundle name, so any helper inside the
                // bundle is detected too.
                let agentID = node.agentID ?? agents.detect(node.image)
                let key = "app:" + PathNormalizer.fold(bundle)
                return ResponsibleEntity(
                    kind: agentID != nil ? .agent : .app,
                    key: agentID.map { "agent:" + $0 } ?? key,
                    displayName: agentID.map { agents.displayName($0) } ?? BundlePath.displayName(ofBundle: bundle),
                    path: bundle,
                    signingID: node.image.signingID,
                    teamID: node.image.teamID,
                    agentID: agentID)
            }
            if let agentID = node.agentID {
                // The team of the image that made it the agent (it may have exec'd another program since).
                return ResponsibleEntity(
                    kind: .agent,
                    key: "agent:" + agentID,
                    displayName: agents.displayName(agentID),
                    path: node.image.executablePath,
                    signingID: node.image.signingID,
                    teamID: node.agentTeamID,
                    agentID: agentID)
            }
        }
        if let node = walk.first(where: { !$0.image.isPlatformBinary }) {
            return binary(node.image)
        }
        if let top = walk.last {
            return binary(top.image)
        }
        if let leaf = chain.first {
            return binary(leaf.image)
        }
        return ResponsibleEntity(kind: .binary, key: "bin:unknown", displayName: "unknown")
    }

    func binary(_ p: ProcessRecord) -> ResponsibleEntity {
        let identity: String
        if let team = p.teamID, let sid = p.signingID {
            identity = team + ":" + sid
        } else if p.isPlatformBinary, let sid = p.signingID {
            identity = "apple:" + sid
        } else {
            // Ad-hoc signing IDs embed a hash and change per build; the path is more stable.
            identity = PathNormalizer.fold(p.executablePath)
        }
        return ResponsibleEntity(
            kind: .binary, key: "bin:" + identity, displayName: p.name, path: p.executablePath,
            signingID: p.signingID, teamID: p.teamID, agentID: nil,
            cdhash: p.teamID == nil && !p.isPlatformBinary ? p.cdhash : nil)
    }

    /// Chain trimmed to start at the responsible entity, root first:
    /// `Claude Code → node → cat`. Falls back to the full chain.
    public func displayChain(_ chain: [ProcessNode], responsible: ResponsibleEntity) -> [ProcessNode] {
        let rootFirst = Array(chain.reversed()).filter { !$0.image.isSystemRoot }
        let responsibleIndex = rootFirst.lastIndex { node in
            if let agent = responsible.agentID, node.agentID == agent { return true }
            if let path = responsible.path {
                if node.image.executablePath == path { return true }
                if responsible.kind != .binary, PathNormalizer.fold(node.image.executablePath).hasPrefix(PathNormalizer.fold(path) + "/") {
                    return true
                }
            }
            return false
        }
        guard let i = responsibleIndex else { return Array(chain.reversed()) }
        // For apps, start at the first node inside the bundle (the app process, not its helpers).
        if responsible.kind != .binary, let path = responsible.path {
            let key = PathNormalizer.fold(path) + "/"
            if let first = rootFirst.firstIndex(where: { PathNormalizer.fold($0.image.executablePath).hasPrefix(key) }), first <= i {
                return Array(rootFirst[first...])
            }
        }
        return Array(rootFirst[i...])
    }
}

extension Array where Element == ChainLink {
    /// Root-first chain trimmed to start at the responsible entity: `Claude Code → node → cat`.
    /// Returns the chain without launchd if the entity is not found.
    public func trimmed(to responsible: ResponsibleEntity) -> [ChainLink] {
        let withoutRoot = filter { $0.pid > 1 }
        if let agent = responsible.agentID, let i = withoutRoot.firstIndex(where: { $0.agentID == agent }) {
            return Array(withoutRoot[i...])
        }
        if responsible.kind != .binary, let bundle = responsible.path {
            let key = PathNormalizer.fold(bundle) + "/"
            if let i = withoutRoot.firstIndex(where: { PathNormalizer.fold($0.path).hasPrefix(key) }) {
                return Array(withoutRoot[i...])
            }
        }
        if let path = responsible.path, let i = withoutRoot.lastIndex(where: { $0.path == path }) {
            return Array(withoutRoot[i...])
        }
        return withoutRoot
    }

    /// Display names, with the responsible entity's name for the first element when trimmed.
    public func displayString(responsible: ResponsibleEntity? = nil, separator: String = " → ") -> String {
        guard let responsible else { return map(\.name).joined(separator: separator) }
        let t = trimmed(to: responsible)
        guard !t.isEmpty else { return responsible.displayName }
        var names = t.map(\.name)
        names[0] = responsible.displayName
        // Collapse "Claude Code → claude" style duplicates where the agent binary is the first node.
        return names.joined(separator: separator)
    }
}
