import Foundation

/// Canonicalizes paths so that every spelling of the same file matches the same catalog entry.
///
/// - firmlinks: `/System/Volumes/Data/Users/x` and `/Users/x` are the same file
/// - root symlinks: `/tmp`, `/var`, `/etc` live under `/private`
/// - Unicode: NFC (APFS preserves whatever normalization a name was created with)
/// - case: match keys are case-folded (APFS is case-insensitive by default)
/// - `~` expands to every monitored home directory
/// - `.`/`..`/`//` are resolved lexically
///
/// Symlinks elsewhere (e.g. `~/.ssh -> ~/Dropbox/ssh`) are resolved when the catalog is
/// compiled, through an injected `SymlinkResolver`, because that needs filesystem access.
public struct PathNormalizer: Sendable {
    public var homeDirectories: [String]
    public var firmlinkRoots: [String]
    public var rootAliases: [(alias: String, target: String)]

    public static let defaultFirmlinkRoots = ["/System/Volumes/Data"]
    public static let defaultRootAliases: [(alias: String, target: String)] = [
        ("/tmp", "/private/tmp"),
        ("/var", "/private/var"),
        ("/etc", "/private/etc"),
    ]

    public init(
        homeDirectories: [String] = [],
        firmlinkRoots: [String] = PathNormalizer.defaultFirmlinkRoots,
        rootAliases: [(alias: String, target: String)] = PathNormalizer.defaultRootAliases
    ) {
        self.firmlinkRoots = firmlinkRoots
        self.rootAliases = rootAliases
        self.homeDirectories = []
        // Homes go through the same canonicalization so `~` expansion matches event paths.
        self.homeDirectories = homeDirectories.map { self.normalize($0) }
    }

    /// Canonical display form. Keeps the original case.
    public func normalize(_ raw: String) -> String {
        var path = raw
        if !isASCII(path) {
            path = path.precomposedStringWithCanonicalMapping
        }
        path = lexicallyClean(path)
        path = stripFirmlinkRoot(path)
        path = applyRootAliases(path)
        return path
    }

    /// Key used for every comparison: canonical form, case-folded.
    public func matchKey(_ raw: String) -> String {
        PathNormalizer.fold(normalize(raw))
    }

    /// Case folding used for match keys. Exposed so pre-normalized strings can be folded alone.
    public static func fold(_ s: String) -> String {
        if s.utf8.allSatisfy({ $0 < 0x80 }) {
            // Fast path: ASCII lowercasing.
            var bytes = Array(s.utf8)
            for i in bytes.indices where bytes[i] >= 0x41 && bytes[i] <= 0x5A { bytes[i] += 0x20 }
            return String(decoding: bytes, as: UTF8.self)
        }
        return s.lowercased()
    }

    /// Expands a catalog pattern. `~/x` yields one path per home directory; absolute paths pass
    /// through. Patterns that are neither are rejected (returns empty).
    public func expand(_ pattern: String) -> [String] {
        let trimmed = pattern.trimmingCharacters(in: .whitespaces)
        if trimmed == "~" {
            return homeDirectories
        }
        if trimmed.hasPrefix("~/") {
            let rest = String(trimmed.dropFirst(2))
            return homeDirectories.map { normalize($0 + "/" + rest) }
        }
        if trimmed.hasPrefix("/") {
            return [normalize(trimmed)]
        }
        return []
    }

    /// Replaces a leading home directory with `~` for display.
    public func abbreviate(_ path: String) -> String {
        let key = PathNormalizer.fold(path)
        for home in homeDirectories.sorted(by: { $0.count > $1.count }) {
            let homeKey = PathNormalizer.fold(home)
            if key == homeKey { return "~" }
            if key.hasPrefix(homeKey + "/") {
                return "~" + path.dropFirst(home.count)
            }
        }
        return path
    }

    // MARK: - Steps

    private func isASCII(_ s: String) -> Bool { s.utf8.allSatisfy { $0 < 0x80 } }

    func lexicallyClean(_ path: String) -> String {
        let absolute = path.hasPrefix("/")
        // Fast path: nothing to clean.
        if absolute && !path.contains("//") && !path.contains("/./") && !path.contains("/../")
            && !path.hasSuffix("/.") && !path.hasSuffix("/..") && (path == "/" || !path.hasSuffix("/")) {
            return path
        }
        var stack: [Substring] = []
        for component in path.split(separator: "/", omittingEmptySubsequences: true) {
            if component == "." { continue }
            if component == ".." {
                if !stack.isEmpty { stack.removeLast() }
                continue
            }
            stack.append(component)
        }
        let joined = stack.joined(separator: "/")
        return absolute ? "/" + joined : joined
    }

    func stripFirmlinkRoot(_ path: String) -> String {
        for root in firmlinkRoots {
            if path.count < root.count { continue }
            let key = PathNormalizer.fold(String(path.prefix(root.count)))
            guard key == PathNormalizer.fold(root) else { continue }
            let rest = path.dropFirst(root.count)
            if rest.isEmpty { return "/" }
            if rest.hasPrefix("/") { return String(rest) }
        }
        return path
    }

    func applyRootAliases(_ path: String) -> String {
        for (alias, target) in rootAliases {
            if path == alias { return target }
            if path.hasPrefix(alias + "/") { return target + path.dropFirst(alias.count) }
        }
        return path
    }
}

/// Resolves symlinks in a path. The real implementation calls realpath(3); tests inject a map.
public protocol SymlinkResolver: Sendable {
    /// Returns the fully resolved path, or nil if the path does not exist / cannot be resolved.
    func resolve(_ path: String) -> String?
}

public struct NoSymlinkResolver: SymlinkResolver {
    public init() {}
    public func resolve(_ path: String) -> String? { nil }
}

public struct MapSymlinkResolver: SymlinkResolver {
    public var map: [String: String]
    public init(_ map: [String: String]) { self.map = map }
    public func resolve(_ path: String) -> String? {
        // Resolve the longest mapped prefix, like a symlinked directory would.
        for (from, to) in map.sorted(by: { $0.key.count > $1.key.count }) {
            if path == from { return to }
            if path.hasPrefix(from + "/") { return to + path.dropFirst(from.count) }
        }
        return nil
    }
}

/// realpath(3)-backed resolver. Only meaningful in the daemon (needs to see the files).
public struct RealpathSymlinkResolver: SymlinkResolver {
    public init() {}
    public func resolve(_ path: String) -> String? {
        guard let resolved = realpath(path, nil) else { return nil }
        defer { free(resolved) }
        return String(cString: resolved)
    }
}
