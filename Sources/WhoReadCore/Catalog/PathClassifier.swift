import Foundation

/// Result of classifying one path.
public struct Classification: Hashable, Sendable, Codable {
    public var categoryID: String
    public var severity: Severity
    /// Canonical prefix that matched (original case).
    public var prefix: String
    /// Path below the prefix; empty when the path is the prefix itself.
    public var relativePath: String
}

/// One concrete prefix after `~` expansion and symlink resolution.
public struct MonitoredPrefix: Hashable, Sendable, Codable {
    /// Canonical path, original case, no trailing slash.
    public var path: String
    public var categoryID: String
    /// True if this prefix was added because a catalog prefix resolves to it through a symlink.
    public var viaSymlink: Bool
}

/// Compiled catalog: maps any path to its category and effective severity in O(path depth).
public final class PathClassifier: @unchecked Sendable {
    public let normalizer: PathNormalizer
    public let catalog: Catalog
    public let prefixes: [MonitoredPrefix]
    /// Proper ancestors of monitored prefixes (e.g. `/Users/a/.config` for `~/.config/gh`).
    /// Renaming or cloning one of these moves sensitive files without touching their paths.
    public let ancestors: [String]

    private let root = TrieNode()
    private let categoriesByID: [String: CategorySpec]
    private let categoryOrder: [String: Int]

    final class TrieNode {
        var children: [String: TrieNode] = [:]
        /// Category IDs registered exactly at this node.
        var terminal: [String] = []
        /// Display form of the prefix ending here.
        var terminalPath: String?
        /// Every category registered at or below this node.
        var subtree: Set<String> = []
    }

    public init(
        catalog: Catalog,
        normalizer: PathNormalizer,
        projectRoots: [String] = [],
        symlinks: SymlinkResolver = NoSymlinkResolver()
    ) {
        self.normalizer = normalizer
        self.catalog = catalog
        var byID: [String: CategorySpec] = [:]
        var order: [String: Int] = [:]
        for (i, c) in catalog.categories.enumerated() where c.enabled {
            byID[c.id] = c
            order[c.id] = i
        }
        self.categoriesByID = byID
        self.categoryOrder = order

        var prefixes: [MonitoredPrefix] = []
        var seen = Set<String>()
        func add(_ path: String, _ category: String, viaSymlink: Bool) {
            let key = PathNormalizer.fold(path) + "\u{0}" + category
            guard !seen.contains(key) else { return }
            seen.insert(key)
            prefixes.append(MonitoredPrefix(path: path, categoryID: category, viaSymlink: viaSymlink))
        }
        for category in catalog.categories where category.enabled {
            let raw: [String] = category.kind == .projectRoots ? projectRoots : category.paths
            for pattern in raw {
                for expanded in normalizer.expand(pattern) {
                    let clean = PathClassifier.stripTrailingSlash(expanded)
                    guard clean != "/" && !clean.isEmpty else { continue }
                    add(clean, category.id, viaSymlink: false)
                    if let resolved = symlinks.resolve(clean) {
                        let r = PathClassifier.stripTrailingSlash(normalizer.normalize(resolved))
                        if PathNormalizer.fold(r) != PathNormalizer.fold(clean) && r != "/" {
                            add(r, category.id, viaSymlink: true)
                        }
                    }
                }
            }
        }
        self.prefixes = prefixes

        var ancestorSet = Set<String>()
        var ancestorList: [String] = []
        for p in prefixes {
            var components = p.path.split(separator: "/").map(String.init)
            components.removeLast()
            var current = ""
            for c in components {
                current += "/" + c
                let k = PathNormalizer.fold(current)
                if !ancestorSet.contains(k) {
                    ancestorSet.insert(k)
                    ancestorList.append(current)
                }
            }
        }
        // An "ancestor" that is itself monitored is not an ancestor.
        let prefixKeys = Set(prefixes.map { PathNormalizer.fold($0.path) })
        self.ancestors = ancestorList.filter { !prefixKeys.contains(PathNormalizer.fold($0)) }

        for p in prefixes { insert(p) }
    }

    private func insert(_ p: MonitoredPrefix) {
        var node = root
        node.subtree.insert(p.categoryID)
        for component in PathNormalizer.fold(p.path).split(separator: "/") {
            let key = String(component)
            let next: TrieNode
            if let existing = node.children[key] {
                next = existing
            } else {
                next = TrieNode()
                node.children[key] = next
            }
            node = next
            node.subtree.insert(p.categoryID)
        }
        if !node.terminal.contains(p.categoryID) { node.terminal.append(p.categoryID) }
        if node.terminalPath == nil { node.terminalPath = p.path }
    }

    static func stripTrailingSlash(_ s: String) -> String {
        var s = s
        while s.count > 1 && s.hasSuffix("/") { s.removeLast() }
        return s
    }

    public func spec(_ categoryID: String) -> CategorySpec? { categoriesByID[categoryID] }

    /// Classifies a raw path (normalizes first).
    public func classify(_ rawPath: String) -> Classification? {
        classify(normalized: normalizer.normalize(rawPath))
    }

    /// Classifies an already-normalized path. Longest prefix wins; among categories registered on
    /// the same prefix the highest severity wins, then catalog order.
    public func classify(normalized path: String) -> Classification? {
        let originalComponents = path.split(separator: "/")
        let folded = PathNormalizer.fold(path).split(separator: "/")
        // Folding can change the component count only in pathological Unicode; fall back safely.
        guard originalComponents.count == folded.count else { return nil }

        var node = root
        var best: (node: TrieNode, depth: Int)?
        for (i, component) in folded.enumerated() {
            guard let next = node.children[String(component)] else { break }
            node = next
            if !node.terminal.isEmpty { best = (node, i + 1) }
        }
        guard let (match, depth) = best else { return nil }

        let relative = originalComponents[depth...].joined(separator: "/")
        let lastComponent = String(originalComponents.last ?? "")

        var results: [Classification] = []
        for categoryID in match.terminal {
            guard let spec = categoriesByID[categoryID] else { continue }
            if let severity = effectiveSeverity(spec: spec, relativePath: relative, fileName: lastComponent) {
                results.append(Classification(
                    categoryID: categoryID,
                    severity: severity,
                    prefix: match.terminalPath ?? "",
                    relativePath: relative))
            }
        }
        return results.min { a, b in
            if a.severity != b.severity { return a.severity > b.severity }
            return (categoryOrder[a.categoryID] ?? 0) < (categoryOrder[b.categoryID] ?? 0)
        }
    }

    /// If `path` is a proper ancestor of monitored prefixes (and not itself inside one), returns the
    /// categories below it, most severe first.
    public func categoriesBelow(normalized path: String) -> [String] {
        var node = root
        for component in PathNormalizer.fold(path).split(separator: "/") {
            guard let next = node.children[String(component)] else { return [] }
            node = next
            if !node.terminal.isEmpty { return [] }
        }
        if node === root { return [] }
        return node.subtree.sorted { a, b in
            let sa = categoriesByID[a]?.severity ?? .medium
            let sb = categoriesByID[b]?.severity ?? .medium
            if sa != sb { return sa > sb }
            return (categoryOrder[a] ?? 0) < (categoryOrder[b] ?? 0)
        }
    }

    func effectiveSeverity(spec: CategorySpec, relativePath: String, fileName: String) -> Severity? {
        for pattern in spec.patterns {
            let subject = pattern.matchesRelativePath ? relativePath : fileName
            if pattern.glob.matches(subject) {
                if pattern.exclude { return nil }
                return pattern.severity ?? spec.severity
            }
        }
        return spec.matchOnlyPatterns ? nil : spec.severity
    }

    /// Owners of a category (expected processes).
    public func isOwner(_ process: ProcessRecord, of categoryID: String) -> Bool {
        guard let spec = categoriesByID[categoryID] else { return false }
        return spec.owners.contains { $0.matches(process) }
    }

    /// Which categories have at least one existing prefix. `exists` is injected (the daemon stats as root).
    public func detection(exists: (String) -> Bool) -> [String: Bool] {
        var out: [String: Bool] = [:]
        for c in catalog.categories { out[c.id] = false }
        for p in prefixes where exists(p.path) { out[p.categoryID] = true }
        return out
    }
}
