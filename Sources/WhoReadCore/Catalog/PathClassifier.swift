import Foundation

/// Result of classifying one path.
public struct Classification: Hashable, Sendable, Codable {
    public var categoryID: String
    public var severity: Severity
    /// Canonical prefix that matched (original case).
    public var prefix: String
    /// Path below the prefix; empty when the path is the prefix itself.
    public var relativePath: String
    /// The path is in the category only because a link the classifier followed leads into one of its
    /// prefixes (anyone can make such a link in their own files).
    public var viaLink: Bool = false
}

/// One concrete prefix after `~` expansion and symlink resolution.
public struct MonitoredPrefix: Hashable, Sendable, Codable {
    /// Canonical path, original case, no trailing slash.
    public var path: String
    public var categoryID: String
    /// True if this prefix was added because a catalog prefix (or a link inside one) resolves to it.
    public var viaSymlink: Bool
}

/// Compiled catalog: maps any path to its category and effective severity in O(path depth).
public final class PathClassifier: @unchecked Sendable {
    public let normalizer: PathNormalizer
    public let catalog: Catalog
    public let prefixes: [MonitoredPrefix]
    /// Every byte-distinct spelling of every prefix (catalog spelling and on-disk spelling, which can
    /// differ in case). Endpoint Security target muting compares the VFS path, so both are needed.
    public let mutePaths: [String]
    /// Proper ancestors of monitored prefixes (e.g. `/Users/a/.config` for `~/.config/gh`).
    /// Renaming or cloning one of these moves sensitive files without touching their paths.
    public let ancestors: [String]

    private let root = TrieNode()
    /// Followed links: a catalog spelling or a link inside a dotfile directory (folded) and the
    /// accepted target it resolves to, sorted by `from` in UTF-8 order (see `linkAliases(of:)`).
    private let links: [(from: String, to: String)]
    private let categoriesByID: [String: CategorySpec]
    private let categoryOrder: [String: Int]

    final class TrieNode {
        var children: [String: TrieNode] = [:]
        /// Category IDs registered exactly at this node.
        var terminal: [String] = []
        /// The ones registered here only because a link leads here (see `classify`).
        var viaLinkOnly: Set<String> = []
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
        var links: [(from: String, to: String)] = []
        var seen: [String: Int] = [:]
        var spellings: [String] = []
        var seenSpellings = Set<String>()
        func spelling(_ p: String) {
            if seenSpellings.insert(p).inserted { spellings.append(p) }
        }
        func add(_ path: String, _ category: String, viaSymlink: Bool) {
            spelling(path)
            let key = PathNormalizer.fold(path) + "\u{0}" + category
            if let i = seen[key] {
                // Also a catalog spelling: not "only reached through a link".
                if !viaSymlink { prefixes[i].viaSymlink = false }
                return
            }
            seen[key] = prefixes.count
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
                        if PathClassifier.isMonitorableTarget(r) && r != clean
                            && PathClassifier.isUsableLinkTarget(r, inside: clean, homes: normalizer.homeDirectories) {
                            // Same folded key (case-only difference): keep the on-disk spelling for muting.
                            let viaSymlink = PathNormalizer.fold(r) != PathNormalizer.fold(clean)
                            add(r, category.id, viaSymlink: viaSymlink)
                            if viaSymlink { links.append((PathNormalizer.fold(clean), r)) }
                        }
                    }
                    // Links inside a dotfile directory (dotfile managers: ~/.aws/credentials -> ~/dotfiles/…):
                    // ES reports the resolved path, so the target must be monitored too.
                    if PathClassifier.walksForLinks(clean, homes: normalizer.homeDirectories) {
                        for (link, target) in symlinks.symlinks(under: clean, maxDepth: PathClassifier.linkWalkMaxDepth,
                                                                maxEntries: PathClassifier.linkWalkMaxEntries) {
                            let t = PathClassifier.stripTrailingSlash(normalizer.normalize(target))
                            if PathClassifier.isMonitorableTarget(t)
                                && PathClassifier.isUsableLinkTarget(t, inside: clean, homes: normalizer.homeDirectories) {
                                add(t, category.id, viaSymlink: true)
                                links.append((PathNormalizer.fold(PathClassifier.stripTrailingSlash(normalizer.normalize(link))), t))
                            }
                        }
                    }
                }
            }
        }
        self.prefixes = prefixes
        self.links = links.sorted { $0.from.utf8.lexicographicallyPrecedes($1.from.utf8) }
        self.mutePaths = spellings

        var ancestorSet = Set<String>()
        var ancestorList: [String] = []
        let prefixKeys = Set(prefixes.map { PathNormalizer.fold($0.path) })
        for p in spellings {
            var components = PathNormalizer.components(p)
            components.removeLast()
            var current = ""
            for c in components {
                current += "/" + c
                // An "ancestor" that is itself monitored is not an ancestor.
                if !prefixKeys.contains(PathNormalizer.fold(current)) && ancestorSet.insert(current).inserted {
                    ancestorList.append(current)
                }
            }
        }
        self.ancestors = ancestorList

        for p in prefixes { insert(p) }
    }

    /// Only dotfile directories directly under a home are searched for links. App data folders are
    /// not: sandbox containers link Desktop, Downloads, Pictures… back into the home (a WeChat or
    /// Bitwarden container would make every file there "chat" or "password manager" data), and
    /// /Volumes or project roots can be huge or hang on a dead network mount.
    static func walksForLinks(_ prefix: String, homes: [String]) -> Bool {
        let p = PathNormalizer.fold(prefix)
        return homes.contains { h in
            let home = PathNormalizer.fold(stripTrailingSlash(h))
            return p.hasPrefix(home + "/.")
        }
    }

    /// How deep and how many entries a search for links goes in one directory (`SymlinkResolver`).
    /// Agent and editor data nests deeper than dotfile managers do (`~/.codex/sessions/YYYY/MM/DD`);
    /// the daemon also follows links that file events show, at any depth.
    public static let linkWalkMaxDepth = 8
    public static let linkWalkMaxEntries = 20_000

    /// The directories `init` searches for links, in the order it does: every expanded catalog path
    /// (project roots for that category) that `walksForLinks` accepts, each once.
    public static func linkWalkDirectories(catalog: Catalog, normalizer: PathNormalizer, projectRoots: [String]) -> [String] {
        var out: [String] = []
        var seen = Set<String>()
        for category in catalog.categories where category.enabled {
            for pattern in category.kind == .projectRoots ? projectRoots : category.paths {
                for expanded in normalizer.expand(pattern) {
                    let clean = stripTrailingSlash(expanded)
                    guard clean != "/" && !clean.isEmpty, walksForLinks(clean, homes: normalizer.homeDirectories) else { continue }
                    if seen.insert(PathNormalizer.fold(clean)).inserted { out.append(clean) }
                }
            }
        }
        return out
    }

    /// A link target that may become a monitored prefix: never the root, a home, or a directory
    /// containing a home or the prefix itself (that would turn whole trees into the category).
    /// A prefix in a user's own files (where an unprivileged client may add path rules) only leads to
    /// targets in a user's own files: `~/link -> /usr/lib` or `/Volumes/Macintosh HD/usr/lib` must not
    /// make system files a category (a deny rule on it would block every user's processes).
    public static func isUsableLinkTarget(_ target: String, inside prefix: String, homes: [String]) -> Bool {
        guard !target.isEmpty, target != "/" else { return false }
        let t = PathNormalizer.fold(target)
        if PathNormalizer.fold(prefix).hasPrefix(t + "/") { return false }
        if isUserLocation(prefix, homes: homes) && !isUserLocation(target, homes: homes) { return false }
        return !homes.contains { h in
            let home = PathNormalizer.fold(stripTrailingSlash(h))
            return home == t || home.hasPrefix(t + "/")
        }
    }

    /// Strictly inside a home directory, or on a volume under /Volumes: the places an unprivileged
    /// client may extend monitoring to. Expects a normalized path.
    public static func isUserLocation(_ path: String, homes: [String]) -> Bool {
        let k = PathNormalizer.fold(path)
        if k.hasPrefix("/volumes/") { return true }
        return homes.contains { h in
            let home = PathNormalizer.fold(stripTrailingSlash(h))
            return k.hasPrefix(home + "/") && k.count > home.count + 1
        }
    }

    /// Where Endpoint Security reports `path` (normalized) and the files below it when the classifier
    /// followed a link on the way: `~/secret -> ~/Dropbox/secret` gives `~/Dropbox/secret/…`, and with
    /// `includingLinksBelow`, `~/.aws` also gives the dotfile its `credentials` links to. Only accepted
    /// (monitored) targets, at most `limit` of them: rule evaluation is linear in the result.
    public func linkAliases(of path: String, includingLinksBelow: Bool = true, limit: Int = 8) -> [String] {
        let clean = PathClassifier.stripTrailingSlash(path)
        let key = PathNormalizer.fold(clean)
        let components = PathNormalizer.components(clean), folded = PathNormalizer.components(key)
        guard limit > 0, !links.isEmpty, !components.isEmpty, components.count == folded.count else { return [] }
        var out: [String] = []
        var seen = Set<String>()
        func emit(_ p: String) -> Bool {
            if seen.insert(p).inserted { out.append(p) }
            return out.count < limit
        }
        /// Targets of the links spelled `prefix` (or starting with it), until `body` returns false.
        func scan(_ prefix: String, exact: Bool, _ body: (String) -> Bool) {
            var lo = 0, hi = links.count
            while lo < hi {
                let mid = (lo + hi) / 2
                if links[mid].from.utf8.lexicographicallyPrecedes(prefix.utf8) { lo = mid + 1 } else { hi = mid }
            }
            while lo < links.count, exact ? links[lo].from.utf8.elementsEqual(prefix.utf8) : links[lo].from.utf8.starts(with: prefix.utf8) {
                if !body(links[lo].to) { return }
                lo += 1
            }
        }
        var more = true
        // At or below a followed link: the same relative path below its target. Folding keeps the
        // number of components, so the original spelling's tail can be reused.
        var ancestor = ""
        for (i, c) in folded.enumerated() where more {
            ancestor += "/" + c
            let tail = components[(i + 1)...].joined(separator: "/")
            scan(ancestor, exact: true) { to in
                more = emit(tail.isEmpty ? to : to + "/" + tail)
                return more
            }
        }
        // An ancestor of a link: everything the link leads to is below `path` too.
        if more && includingLinksBelow {
            scan(key + "/", exact: false) { emit($0) }
        }
        return out
    }

    private func insert(_ p: MonitoredPrefix) {
        var node = root
        node.subtree.insert(p.categoryID)
        for key in PathNormalizer.components(PathNormalizer.fold(p.path)) {
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
        if !node.terminal.contains(p.categoryID) {
            node.terminal.append(p.categoryID)
            if p.viaSymlink { node.viaLinkOnly.insert(p.categoryID) }
        } else if !p.viaSymlink {
            node.viaLinkOnly.remove(p.categoryID)
        }
        if node.terminalPath == nil { node.terminalPath = p.path }
    }

    /// Symlink targets that are never monitored: `~/.zsh_history -> /dev/null` must not make every
    /// /dev/null open on the system an event (or, when enforcing, an AUTH round trip).
    public static func isMonitorableTarget(_ path: String) -> Bool {
        let key = PathNormalizer.fold(path)
        return key != "/" && !key.isEmpty && key != "/dev" && !key.hasPrefix("/dev/")
    }

    public static func stripTrailingSlash(_ s: String) -> String {
        var s = s
        while s.count > 1 && s.hasSuffix("/") { s.removeLast() }
        return s
    }

    public func spec(_ categoryID: String) -> CategorySpec? { categoriesByID[categoryID] }

    /// The highest severity any file of a category can have (patterns included). Moving or cloning a
    /// directory of the category may carry such files.
    public func maxSeverity(_ categoryID: String) -> Severity? {
        guard let spec = categoriesByID[categoryID] else { return nil }
        var best: Severity? = spec.matchOnlyPatterns ? nil : spec.severity
        for p in spec.patterns where !p.exclude {
            let s = p.severity ?? spec.severity
            best = max(best ?? s, s)
        }
        return best
    }

    /// Classifies a raw path (normalizes first).
    public func classify(_ rawPath: String, truncated: Bool = false) -> Classification? {
        classify(normalized: normalizer.normalize(rawPath), truncated: truncated)
    }

    /// Every category of a raw path (normalizes first); see `classifications(normalized:)`.
    public func classifications(_ rawPath: String, truncated: Bool = false) -> [Classification] {
        classifications(normalized: normalizer.normalize(rawPath), truncated: truncated)
    }

    /// Terminals along the path, deepest first, with the depth (component count) at which each ends.
    private func terminals(_ folded: [String]) -> [(node: TrieNode, depth: Int)] {
        var node = root
        var out: [(TrieNode, Int)] = []
        for (i, component) in folded.enumerated() {
            guard let next = node.children[component] else { break }
            node = next
            if !node.terminal.isEmpty { out.append((next, i + 1)) }
        }
        return out.reversed()
    }

    /// Classifies an already-normalized path. The deepest prefix that yields a classification wins
    /// (a deeper prefix whose patterns reject the path falls back to shallower ones); among
    /// categories on one prefix the highest severity wins, then catalog order.
    /// A truncated path gets the category's worst-case severity: its real name is unknown.
    ///
    /// Some prefixes only add severity (`addsSeverityOnly`): nested in another category's prefix,
    /// they never demote what the path classifies as without them.
    /// - A category registered at a prefix only because a link leads there wins only when more
    ///   severe (ties go to the shallower prefix): anyone can create links in their own files
    ///   (`ln -s ~/.ssh/id_ed25519 ~/x` plus a path rule on `~/x`), and that must not turn an ssh key
    ///   into a Custom/high file that critical-file and ssh rules no longer cover.
    /// - A custom path (`whoread catalog add-path custom ~/.ssh/work`) is meant to monitor more, not
    ///   to demote the ssh keys in it. It wins ties: only root or the app adds one inside another
    ///   prefix, on purpose, and a carve-out in a cloud folder must not be decided by an answer
    ///   about cloud-storage.
    /// - A project root inside another prefix (a cloud folder) keeps its `.env` (it wins ties), but a
    ///   project root inside `~/.aws` does not turn the credentials there into project-secrets/high
    ///   files.
    ///
    /// This is the category the path is named by. A path inside nested prefixes also belongs to the
    /// other categories that accept it: `classifications` returns them all, and analysis and rules use
    /// every one.
    public func classify(normalized path: String, truncated: Bool = false) -> Classification? {
        memberships(path, truncated: truncated, all: false).first
    }

    /// Every category whose prefix contains the path and whose patterns accept it, each once at its
    /// most severe prefix. The first is the category the path is named by (`classify`; unless it is
    /// there only through a link, its owners also own some of the others, see `owns`); the others
    /// follow most severe first, then deepest prefix first, then catalog order. An SSH key in a custom
    /// folder inside `~/.ssh` is ssh/critical and custom/high: ssh rules keep covering it, and the
    /// custom category's rules cover it too. Nothing is demoted or dropped, so a rule or an answer
    /// about one category never decides another.
    public func classifications(normalized path: String, truncated: Bool = false) -> [Classification] {
        memberships(path, truncated: truncated, all: true)
    }

    /// `classify` first; with `all`, then every other category that accepts the path (see
    /// `classifications`).
    private func memberships(_ path: String, truncated: Bool, all: Bool) -> [Classification] {
        let originalComponents = PathNormalizer.components(path)
        let folded = PathNormalizer.components(PathNormalizer.fold(path))
        // Case folding can change component content but never the "/" count (scalar split).
        guard originalComponents.count == folded.count else { return [] }
        let lastComponent = originalComponents.last ?? ""
        func better(_ a: Classification, _ b: Classification) -> Bool {
            if a.severity != b.severity { return a.severity > b.severity }
            return (categoryOrder[a.categoryID] ?? 0) < (categoryOrder[b.categoryID] ?? 0)
        }

        var primary: Classification?
        // Every acceptance, deepest prefix first (only with `all`).
        var found: [(c: Classification, depth: Int)] = []
        // The best classification by prefixes that only add severity, so far (deeper ones first).
        var additive: (c: Classification, depth: Int, winsTies: Bool)?
        for (match, depth) in terminals(folded) {
            let relative = originalComponents[depth...].joined(separator: "/")
            var best: Classification?
            var bestAdditive: (c: Classification, winsTies: Bool)?
            for categoryID in match.terminal {
                guard let spec = categoriesByID[categoryID] else { continue }
                let severity: Severity?
                if truncated {
                    severity = maxSeverity(categoryID) ?? spec.severity
                } else {
                    severity = effectiveSeverity(spec: spec, relativePath: relative, fileName: lastComponent)
                }
                if let severity {
                    let viaLink = match.viaLinkOnly.contains(categoryID)
                    let c = Classification(categoryID: categoryID, severity: severity,
                                           prefix: match.terminalPath ?? "", relativePath: relative, viaLink: viaLink)
                    if all { found.append((c, depth)) }
                    if let winsTies = addsSeverityOnly(spec, viaLink: viaLink) {
                        if bestAdditive.map({ better(c, $0.c) }) ?? true { bestAdditive = (c, winsTies) }
                    } else if best.map({ better(c, $0) }) ?? true {
                        best = c
                    }
                }
            }
            guard primary == nil else { continue }
            // A shallower one replaces a deeper one unless the deeper one is more severe (or as severe
            // and winning ties).
            if let b = bestAdditive {
                let keep = additive.map { $0.c.severity > b.c.severity || ($0.winsTies && $0.c.severity == b.c.severity) } ?? false
                if !keep { additive = (b.c, depth, b.winsTies) }
            }
            if let best {
                // On the same prefix, only a more severe one wins.
                if let a = additive, a.c.severity > best.severity || (a.winsTies && a.depth > depth && a.c.severity == best.severity) {
                    primary = a.c
                } else {
                    primary = best
                }
                if !all { break }
            }
        }
        guard let first = primary ?? additive?.c else { return [] }
        guard all, found.count > 1 else { return [first] }
        // Each category once, at its most severe prefix (ties: the deepest, found first); through a
        // link only when no prefix of the category itself holds the path.
        var others: [(c: Classification, depth: Int)] = []
        var head = first
        for f in found {
            if f.c.categoryID == head.categoryID {
                head.severity = max(head.severity, f.c.severity)
                head.viaLink = head.viaLink && f.c.viaLink
            } else if let i = others.firstIndex(where: { $0.c.categoryID == f.c.categoryID }) {
                let viaLink = others[i].c.viaLink && f.c.viaLink
                if f.c.severity > others[i].c.severity { others[i] = f }
                others[i].c.viaLink = viaLink
            } else {
                others.append(f)
            }
        }
        others.sort { a, b in
            if a.c.severity != b.c.severity { return a.c.severity > b.c.severity }
            if a.depth != b.depth { return a.depth > b.depth }
            return (categoryOrder[a.c.categoryID] ?? 0) < (categoryOrder[b.c.categoryID] ?? 0)
        }
        return [head] + others.map(\.c)
    }

    /// nil for a prefix that classifies what is below it whatever shallower prefixes say (a standard
    /// category: a Safari file in a home on an external volume is Safari's, at Safari's severity).
    /// Otherwise the prefix only adds severity (see `classify`), and the result says whether it wins
    /// ties with a shallower prefix: links do not, custom paths and project roots do.
    func addsSeverityOnly(_ spec: CategorySpec, viaLink: Bool) -> Bool? {
        if viaLink { return false }
        if spec.kind == .custom || spec.kind == .projectRoots { return true }
        return nil
    }

    /// For a path that did not classify: the categories below it, most severe first, if it is a
    /// proper ancestor of monitored prefixes, or a prefix whose own patterns reject it (a project
    /// root). Moving or cloning such a directory carries those categories' files.
    /// Returns [] for paths inside a prefix (see `containingCategory`).
    public func categoriesBelow(normalized path: String) -> [String] {
        let folded = PathNormalizer.components(PathNormalizer.fold(path))
        var node = root
        for (i, component) in folded.enumerated() {
            guard let next = node.children[component] else { return [] }
            node = next
            if !node.terminal.isEmpty && i < folded.count - 1 { return [] }
        }
        if node === root { return [] }
        return mostSevereFirst(node.subtree)
    }

    /// Every category registered at or below the path, most severe first, wherever the path is: unlike
    /// `categoriesBelow`, also for a path inside another prefix. Moving or cloning a directory carries
    /// the files of every prefix inside it, so moving `/Volumes/Ext/bob/.config` (a home on an external
    /// volume) carries gh and gcloud, not only "volumes", and moving a cloud folder that holds a
    /// project root carries the project's keys.
    public func categoriesInside(normalized path: String) -> [String] {
        var node = root
        for component in PathNormalizer.components(PathNormalizer.fold(path)) {
            guard let next = node.children[component] else { return [] }
            node = next
        }
        if node === root { return [] }
        return mostSevereFirst(node.subtree)
    }

    private func mostSevereFirst(_ ids: Set<String>) -> [String] {
        ids.sorted { a, b in
            let sa = categoriesByID[a]?.severity ?? .medium
            let sb = categoriesByID[b]?.severity ?? .medium
            if sa != sb { return sa > sb }
            return (categoryOrder[a] ?? 0) < (categoryOrder[b] ?? 0)
        }
    }

    /// The deepest category whose prefix contains the path, ignoring `matchOnlyPatterns` (but not
    /// exclusions), at the category's base severity. Used for directories inside a pattern-only
    /// category (a project folder): moving one carries the `.env`/`*.pem` files inside.
    public func containingCategory(normalized path: String) -> TargetCategory? {
        containingCategories(normalized: path).first
    }

    /// The categories whose prefixes contain the path (at or above it) and may classify files below it,
    /// deepest first, at base severity, ignoring `matchOnlyPatterns` (but not exclusions). The walk
    /// stops at the first standard category: what is below it is that category's (see `classify`).
    /// Prefixes that only add severity do not stop it: the `.pem` under a custom path inside a project
    /// root is still a project secret.
    public func containingCategories(normalized path: String) -> [TargetCategory] {
        let originalComponents = PathNormalizer.components(path)
        let folded = PathNormalizer.components(PathNormalizer.fold(path))
        guard originalComponents.count == folded.count else { return [] }
        let name = originalComponents.last ?? ""
        var out: [TargetCategory] = []
        for (match, depth) in terminals(folded) {
            let relative = originalComponents[depth...].joined(separator: "/")
            var standard = false
            for categoryID in match.terminal {
                guard let spec = categoriesByID[categoryID] else { continue }
                let excluded = spec.patterns.contains { p in
                    p.exclude && p.glob.matches(p.matchesRelativePath ? relative : name)
                }
                if excluded { continue }
                if !out.contains(where: { $0.id == categoryID }) {
                    out.append(TargetCategory(id: categoryID, severity: spec.severity))
                }
                if addsSeverityOnly(spec, viaLink: match.viaLinkOnly.contains(categoryID)) == nil { standard = true }
            }
            if standard { break }
        }
        return out
    }

    /// Whether a classified path may be a directory holding other files of its category: true unless a
    /// specific file pattern (anything but a bare `*` / `**` catch-all) decided its severity. Used when
    /// the event source does not report the file type.
    public func mayContainFiles(_ c: Classification) -> Bool {
        guard let spec = categoriesByID[c.categoryID], !c.relativePath.isEmpty else { return true }
        let fileName = PathNormalizer.components(c.relativePath).last ?? c.relativePath
        guard let pattern = spec.patterns.first(where: { $0.glob.matches($0.matchesRelativePath ? c.relativePath : fileName) }) else {
            return true
        }
        return pattern.exclude || pattern.glob.pattern.allSatisfy { $0 == "*" || $0 == "/" }
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

    /// Whether an owner counts as owner of `category` for a path that belongs to it: an owner of the
    /// category itself, or of the category the path is named by (`naming`, see
    /// `ownerLendingCategory`) when `category` is not more severe or has no owners of its own (a
    /// volume, a custom folder). Chrome reading its cookies in a home on an external volume, or ssh its
    /// config there, owns the volume side too; ssh is no owner of a critical aws file that a medium ssh
    /// path was added inside. `isOwner` takes a category ID (callers cache it).
    public func owns(_ category: TargetCategory, namedBy naming: TargetCategory?, isOwner: (String) -> Bool) -> Bool {
        if isOwner(category.id) { return true }
        guard let naming, naming.id != category.id else { return false }
        guard naming.severity >= category.severity || categoriesByID[category.id]?.owners.isEmpty == true else { return false }
        return isOwner(naming.id)
    }

    /// The category whose owners `owns` lets own a path's other categories: the first of
    /// `classifications` (at the severity the caller judges it), when the path has several and is not
    /// in that one only through a link. Anyone can link a folder of theirs into `~/.aws`; that must not
    /// make the aws CLI an owner of what is in that folder.
    public static func ownerLendingCategory(_ classifications: [Classification], judgedAs categories: [TargetCategory]) -> TargetCategory? {
        guard categories.count > 1, let first = classifications.first, !first.viaLink,
              categories[0].id == first.categoryID else { return nil }
        return categories[0]
    }

    /// Which categories have at least one existing prefix. `exists` is injected (the daemon stats as root).
    public func detection(exists: (String) -> Bool) -> [String: Bool] {
        var out: [String: Bool] = [:]
        for c in catalog.categories { out[c.id] = false }
        for p in prefixes where exists(p.path) { out[p.categoryID] = true }
        return out
    }
}
