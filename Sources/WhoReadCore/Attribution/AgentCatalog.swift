import Foundation

/// AI agent recognition rules (`Data/agents.json`).
public struct AgentCatalog: Codable, Hashable, Sendable {
    public var version: Int
    public var agents: [AgentSpec]

    public init(version: Int = 1, agents: [AgentSpec]) {
        self.version = version
        self.agents = agents
    }

    public static func load(from data: Data) throws -> AgentCatalog {
        try JSONDecoder().decode(AgentCatalog.self, from: data)
    }

    public func agent(_ id: String) -> AgentSpec? { agents.first { $0.id == id } }
}

public struct AgentSpec: Codable, Hashable, Sendable, Identifiable {
    public enum Kind: String, Codable, Sendable { case cli, app }
    public var id: String
    public var name: LocalizedText
    public var kind: Kind
    /// Any clause matching makes a process image this agent.
    public var match: [AgentMatchClause]

    public init(id: String, name: LocalizedText, kind: Kind, match: [AgentMatchClause]) {
        self.id = id
        self.name = name
        self.kind = kind
        self.match = match
    }
}

/// All provided fields must match.
public struct AgentMatchClause: Codable, Hashable, Sendable {
    /// Executable basename, case-insensitive (e.g. "codex").
    public var executableNames: [String]?
    /// Full executable path globs (e.g. "**/.local/share/claude/versions/*").
    public var executableGlobs: [Glob]?
    /// Name of any `.app` bundle on the executable path (e.g. "Cursor.app").
    public var bundleNames: [String]?
    /// basename(argv[0]).
    public var argv0Names: [String]?
    /// basename of any argv[1...] element (script paths for interpreters; `python -m aider`).
    public var argvBasenames: [String]?
    /// Substring of any argv[1...] element (e.g. "@anthropic-ai/claude-code").
    public var argvContains: [String]?
    /// Optional code identity pin, filled from `codesign -dv` on the user's machine.
    public var teamIDs: [String]?

    public init(
        executableNames: [String]? = nil,
        executableGlobs: [String]? = nil,
        bundleNames: [String]? = nil,
        argv0Names: [String]? = nil,
        argvBasenames: [String]? = nil,
        argvContains: [String]? = nil,
        teamIDs: [String]? = nil
    ) {
        self.executableNames = executableNames
        self.executableGlobs = executableGlobs?.map(Glob.init)
        self.bundleNames = bundleNames
        self.argv0Names = argv0Names
        self.argvBasenames = argvBasenames
        self.argvContains = argvContains
        self.teamIDs = teamIDs
    }

    var isEmpty: Bool {
        (executableNames ?? []).isEmpty && (executableGlobs ?? []).isEmpty && (bundleNames ?? []).isEmpty
            && (argv0Names ?? []).isEmpty && (argvBasenames ?? []).isEmpty && (argvContains ?? []).isEmpty
    }

    func matches(_ p: ProcessRecord) -> Bool {
        if isEmpty { return false }
        if let names = executableNames, !names.isEmpty {
            let n = PathNormalizer.fold(p.name)
            guard names.contains(where: { PathNormalizer.fold($0) == n }) else { return false }
        }
        if let globs = executableGlobs, !globs.isEmpty {
            guard globs.contains(where: { $0.matches(p.executablePath) }) else { return false }
        }
        if let bundles = bundleNames, !bundles.isEmpty {
            let wanted = Set(bundles.map(PathNormalizer.fold))
            let present = BundlePath.appBundles(in: p.executablePath).map {
                PathNormalizer.fold(String($0.split(separator: "/").last ?? ""))
            }
            guard present.contains(where: wanted.contains) else { return false }
        }
        let argv = p.argv ?? []
        if let names = argv0Names, !names.isEmpty {
            guard let first = argv.first else { return false }
            let n = PathNormalizer.fold(AgentMatchClause.basename(first))
            guard names.contains(where: { PathNormalizer.fold($0) == n }) else { return false }
        }
        if let names = argvBasenames, !names.isEmpty {
            let wanted = Set(names.map(PathNormalizer.fold))
            guard argv.dropFirst().contains(where: { wanted.contains(PathNormalizer.fold(AgentMatchClause.basename($0))) })
            else { return false }
        }
        if let needles = argvContains, !needles.isEmpty {
            guard argv.dropFirst().contains(where: { arg in needles.contains { arg.contains($0) } }) else { return false }
        }
        if let teams = teamIDs, !teams.isEmpty {
            guard let t = p.teamID, teams.contains(t) else { return false }
        }
        return true
    }

    static func basename(_ s: String) -> String {
        var t = Substring(s)
        while t.count > 1 && t.hasSuffix("/") { t = t.dropLast() }
        if let slash = t.lastIndex(of: "/") { return String(t[t.index(after: slash)...]) }
        return String(t)
    }
}

/// Decides whether a process image is a known AI agent.
public struct AgentDetector: Sendable {
    public let catalog: AgentCatalog

    public init(catalog: AgentCatalog) {
        self.catalog = catalog
    }

    /// Agent ID for this image, if any. First agent in catalog order wins.
    public func detect(_ p: ProcessRecord) -> String? {
        for agent in catalog.agents where agent.match.contains(where: { $0.matches(p) }) {
            return agent.id
        }
        return nil
    }

    public func displayName(_ agentID: String, language: Language = .en) -> String {
        catalog.agent(agentID)?.name.resolve(language) ?? agentID
    }
}
