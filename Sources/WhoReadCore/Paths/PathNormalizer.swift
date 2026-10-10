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
        // Homes go through the same canonicalization so `~` expansion matches event paths. A home and
        // its realpath spelling (HomeDirectories adds both) can normalize to one path: keep it once.
        var seen = Set<String>()
        self.homeDirectories = homeDirectories.map { self.normalize($0) }.filter { seen.insert($0).inserted }
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

    /// Path components split on Unicode scalars. Splitting on Characters would merge "/" with a
    /// following combining mark into one grapheme and lose a component boundary.
    public static func components(_ path: String) -> [String] {
        path.unicodeScalars.split(separator: "/").map { String(String.UnicodeScalarView($0)) }
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
        var stack: [String] = []
        for component in PathNormalizer.components(path) {
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
    /// Symbolic links found inside a directory (bounded walk), with their fully resolved targets.
    func symlinks(under dir: String, maxDepth: Int, maxEntries: Int) -> [(link: String, target: String)]
}

extension SymlinkResolver {
    public func symlinks(under dir: String, maxDepth: Int, maxEntries: Int) -> [(link: String, target: String)] { [] }
}

public struct NoSymlinkResolver: SymlinkResolver {
    public init() {}
    public func resolve(_ path: String) -> String? { nil }
}

public struct MapSymlinkResolver: SymlinkResolver {
    public var map: [String: String]
    /// Links inside directories: directory → [(link, target)].
    public var links: [String: [(link: String, target: String)]]
    public init(_ map: [String: String], links: [String: [(link: String, target: String)]] = [:]) {
        self.map = map
        self.links = links
    }

    public func symlinks(under dir: String, maxDepth: Int, maxEntries: Int) -> [(link: String, target: String)] {
        links[dir] ?? []
    }
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

    /// lstat-based walk; does not follow directory links (their targets are reported instead). A link
    /// to somewhere inside `dir` is not reported, whether its target is spelled like `dir` or like
    /// `dir`'s realpath (`dir` is a normalized prefix; the targets are realpaths, so for a home under
    /// /home they start with /System/Volumes/Data/home).
    public func symlinks(under dir: String, maxDepth: Int, maxEntries: Int) -> [(link: String, target: String)] {
        let roots = [dir] + (resolve(dir).map { [$0] } ?? [])
        func inside(_ target: String) -> Bool { roots.contains { target == $0 || target.hasPrefix($0 + "/") } }
        var out: [(String, String)] = []
        var visited = 0
        func walk(_ d: String, _ depth: Int) {
            guard depth <= maxDepth, let entries = try? FileManager.default.contentsOfDirectory(atPath: d) else { return }
            for name in entries {
                visited += 1
                if visited > maxEntries { return }
                let p = d.hasSuffix("/") ? d + name : d + "/" + name
                var st = stat()
                guard lstat(p, &st) == 0 else { continue }
                let type = UInt32(st.st_mode) & 0o170000
                if type == 0o120000 {
                    if let target = resolve(p), !inside(target) { out.append((p, target)) }
                } else if type == 0o040000 {
                    walk(p, depth + 1)
                }
            }
        }
        walk(dir, 1)
        return out
    }
}
