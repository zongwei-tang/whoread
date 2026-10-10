import Foundation

/// The sensitive-path catalog (`Data/catalog.json`, user copy in the daemon's data directory).
public struct Catalog: Codable, Hashable, Sendable {
    public var version: Int
    public var categories: [CategorySpec]

    public init(version: Int = 1, categories: [CategorySpec]) {
        self.version = version
        self.categories = categories
    }

    public func category(_ id: String) -> CategorySpec? {
        categories.first { $0.id == id }
    }

    public static func load(from data: Data) throws -> Catalog {
        try JSONDecoder().decode(Catalog.self, from: data)
    }

    public func encoded() throws -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try enc.encode(self)
    }
}

public enum CategoryKind: String, Codable, Sendable {
    /// Fixed prefixes from the catalog.
    case standard
    /// Prefixes come from the user's project roots setting; only `patterns` are sensitive.
    case projectRoots
    /// `~/WhoReadTestVault/`. Automated tests only ever touch this.
    case test
    case custom
}

public struct CategorySpec: Codable, Hashable, Sendable, Identifiable {
    public var id: String
    public var name: LocalizedText
    public var description: LocalizedText?
    public var kind: CategoryKind
    /// UI grouping, e.g. "dev-credentials", "browser", "chat".
    public var group: String?
    public var severity: Severity
    /// Prefixes. `~/` expands to each monitored home. A trailing `/` documents a directory but
    /// matching is always on path-component boundaries.
    public var paths: [String]
    /// Optional refinements by file name or relative path; first match wins.
    public var patterns: [PatternSpec]
    /// If true, only paths matching a non-excluding pattern are sensitive.
    public var matchOnlyPatterns: Bool
    public var owners: [IdentitySpec]
    public var enabled: Bool

    public init(
        id: String,
        name: LocalizedText,
        description: LocalizedText? = nil,
        kind: CategoryKind = .standard,
        group: String? = nil,
        severity: Severity,
        paths: [String],
        patterns: [PatternSpec] = [],
        matchOnlyPatterns: Bool = false,
        owners: [IdentitySpec] = [],
        enabled: Bool = true
    ) {
        self.id = id
        self.name = name
        self.description = description
        self.kind = kind
        self.group = group
        self.severity = severity
        self.paths = paths
        self.patterns = patterns
        self.matchOnlyPatterns = matchOnlyPatterns
        self.owners = owners
        self.enabled = enabled
    }

    enum CodingKeys: String, CodingKey {
        case id, name, description, kind, group, severity, paths, patterns, matchOnlyPatterns, owners, enabled
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(LocalizedText.self, forKey: .name)
        description = try c.decodeIfPresent(LocalizedText.self, forKey: .description)
        kind = try c.decodeIfPresent(CategoryKind.self, forKey: .kind) ?? .standard
        group = try c.decodeIfPresent(String.self, forKey: .group)
        severity = try c.decode(Severity.self, forKey: .severity)
        paths = try c.decodeIfPresent([String].self, forKey: .paths) ?? []
        patterns = try c.decodeIfPresent([PatternSpec].self, forKey: .patterns) ?? []
        matchOnlyPatterns = try c.decodeIfPresent(Bool.self, forKey: .matchOnlyPatterns) ?? false
        owners = try c.decodeIfPresent([IdentitySpec].self, forKey: .owners) ?? []
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
    }
}

public struct PatternSpec: Codable, Hashable, Sendable {
    /// Matched against the file name, or against the path relative to the prefix if it contains `/`.
    public var glob: Glob
    public var severity: Severity?
    /// Excluded paths are not sensitive at all (e.g. browser caches).
    public var exclude: Bool

    public init(glob: String, severity: Severity? = nil, exclude: Bool = false) {
        self.glob = Glob(glob)
        self.severity = severity
        self.exclude = exclude
    }

    enum CodingKeys: String, CodingKey { case glob, severity, exclude }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        glob = try c.decode(Glob.self, forKey: .glob)
        severity = try c.decodeIfPresent(Severity.self, forKey: .severity)
        exclude = try c.decodeIfPresent(Bool.self, forKey: .exclude) ?? false
    }

    var matchesRelativePath: Bool { glob.pattern.contains("/") }
}
