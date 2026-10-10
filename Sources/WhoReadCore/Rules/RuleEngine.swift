import Foundation

/// A category a target path belongs to (directly, or as an ancestor directory of the category).
public struct TargetCategory: Hashable, Sendable, Codable {
    public var id: String
    public var severity: Severity
    public init(id: String, severity: Severity) {
        self.id = id
        self.severity = severity
    }
}

/// One path of an access request, after classification.
public struct EvaluationTarget: Sendable {
    public var path: String
    /// Access requested for this path by this operation.
    public var access: AccessSet
    public var categories: [TargetCategory]

    public init(path: String, access: AccessSet, categories: [TargetCategory]) {
        self.path = path
        self.access = access
        self.categories = categories
    }
}

public enum Verdict: String, Codable, Sendable {
    case allow
    case deny
    /// Ask mode, enforcement active: nothing decides this access yet. The native source holds the
    /// access and asks the user (AskBroker); unanswered by the deadline budget, it is denied.
    case ask
}

public enum DecisionReason: String, Codable, Sendable {
    case neverBlock
    case enforcementInactive
    case explicitDeny
    /// A deny rule matched but is in dry run, or global enforcement is off.
    case wouldDeny
    case explicitAllow
    case alertRule
    case owner
    case defaultAllow
    case notSensitive
    case failOpen
    /// Ask mode: no rule, owner or trust decides; the user is asked (verdict .ask), or was asked and
    /// did not answer in time (verdict .deny).
    case askUser
    /// A benign system service chain (Spotlight, Time Machine…): never asked.
    case benign
    /// "Trust Apple programs" is on and this is an Apple program in a system location, with no AI
    /// agent in its chain.
    case trustedApple
}

public struct RuleDecision: Codable, Hashable, Sendable {
    public var verdict: Verdict
    /// Accesses enforced rules deny for this process on these paths, over *all* access kinds (not
    /// just the requested ones). An AUTH_OPEN allow is only cached when this is empty: a cached
    /// masked answer would deny later opens without an AUTH event (no log, no alert).
    public var policyDenied: AccessSet
    public var wouldDeny: Bool
    public var reason: DecisionReason
    public var ruleID: String?
    public var forceAlert: Bool
    public var suppressAlert: Bool
    /// Safe to let Endpoint Security cache (keyed on executable file + target file).
    public var cacheable: Bool
    /// Set with verdict .ask (and on the .deny an unanswered ask becomes): what the answer applies to.
    public var askKey: AskKey?

    public init(verdict: Verdict, policyDenied: AccessSet = [], wouldDeny: Bool = false, reason: DecisionReason,
                ruleID: String? = nil, forceAlert: Bool = false, suppressAlert: Bool = false, cacheable: Bool = false,
                askKey: AskKey? = nil) {
        self.verdict = verdict
        self.policyDenied = policyDenied
        self.wouldDeny = wouldDeny
        self.reason = reason
        self.ruleID = ruleID
        self.forceAlert = forceAlert
        self.suppressAlert = suppressAlert
        self.cacheable = cacheable
        self.askKey = askKey
    }

    public static func failOpen() -> RuleDecision {
        RuleDecision(verdict: .allow, reason: .failOpen)
    }
}

/// Evaluates rules for an access. Thread-safe; everything is in memory.
///
/// Priority: explicit deny > explicit allow > owner > default. `alert` rules do not change the
/// verdict, they force an alert when nothing above suppressed it.
///
/// Ask mode (`AskPolicy.enabled`, enforcement active) replaces "default allow" with a question
/// (docs/ASK_MODE.md): every (path, category) of the access must be decided by an enforced deny, by
/// allow rules covering the requested access kinds, or by an owner with no AI agent in its chain;
/// failing that, a benign service chain or a trusted Apple program allows the whole access, and
/// anything else is `.ask`. Alert rules and dry-run denies do not decide (they still alert).
public final class RuleEngine: @unchecked Sendable {
    private let lock = NSLock()
    private var compiled: [CompiledRule] = []
    private var classifier: PathClassifier
    /// Bumped whenever the classifier is replaced: a recompile for an older one is dropped.
    private var classifierGeneration = 0
    /// An "allow once" use was consumed since the last `takeConsumed()` (callers persist it).
    private var consumed = false
    private let attributor: Attributor?
    public private(set) var neverBlock: NeverBlockList

    struct CompiledRule {
        var rule: Rule
        var prefixKeys: [String]
        /// `prefixKeys` with a trailing "/" (computed once: this runs for every rule on the AUTH path).
        var prefixKeysSlash: [String]
        var exceptionPrefixKeys: [[String]]
        /// Folded, normalized program path for `.unsigned` subjects (computed once, not per event).
        var unsignedKey: String?
        var exceptionUnsignedKeys: [String?]
        /// `rule.chainAgents` as a set (computed once).
        var chainAgents: Set<String>?
    }

    public init(rules: [Rule], classifier: PathClassifier, attributor: Attributor? = nil, neverBlock: NeverBlockList = NeverBlockList()) {
        self.classifier = classifier
        self.attributor = attributor
        self.neverBlock = neverBlock
        self.compiled = rules.map { RuleEngine.compile($0, classifier) }
    }

    static func compile(_ rule: Rule, _ classifier: PathClassifier) -> CompiledRule {
        /// Endpoint Security reports resolved paths: a prefix reached through a link the classifier
        /// followed (`~/secret -> ~/Dropbox/secret`) also matches the link's target. A deny or alert
        /// rule's own target also takes the links found inside it; an exception's path does not (a link
        /// added inside an approved folder must not carry the approval to another file). An allow rule
        /// takes no link targets at all: links are re-pointed by whoever owns the files (an agent turning
        /// `~/.aws/credentials` into a link to `~/.ssh/id_ed25519` must not silence that key's alerts).
        func keys(_ prefix: String?, links: Bool, linksBelow: Bool) -> [String] {
            guard let prefix else { return [] }
            var out: [String] = []
            for expanded in classifier.normalizer.expand(prefix) {
                let aliases = links ? classifier.linkAliases(of: expanded, includingLinksBelow: linksBelow) : []
                for p in [expanded] + aliases {
                    let key = PathClassifier.stripTrailingSlash(PathNormalizer.fold(p))
                    if !out.contains(key) { out.append(key) }
                }
            }
            return out
        }
        func unsignedKey(_ s: RuleSubject) -> String? {
            if case .unsigned(let path, _) = s { return PathNormalizer.fold(classifier.normalizer.normalize(path)) }
            return nil
        }
        var prefixKeys: [String] = []
        if case .pathPrefix(let p) = rule.target { prefixKeys = keys(p, links: rule.action != .allow, linksBelow: true) }
        return CompiledRule(rule: rule, prefixKeys: prefixKeys, prefixKeysSlash: prefixKeys.map { $0 + "/" },
                            exceptionPrefixKeys: rule.exceptions.map { keys($0.pathPrefix, links: true, linksBelow: false) },
                            unsignedKey: unsignedKey(rule.subject), exceptionUnsignedKeys: rule.exceptions.map { unsignedKey($0.subject) },
                            chainAgents: rule.chainAgents.map(Set.init))
    }

    /// Compiled `rules`, reusing the entries of `old` (compiled against the same classifier) whose rule
    /// is unchanged. Compiling expands every path for every home and follows links: redoing all 512
    /// rules for each edit or answer held the lock the AUTH path evaluates under for tens of ms.
    static func compile(_ rules: [Rule], _ classifier: PathClassifier, reusing old: [CompiledRule]) -> [CompiledRule] {
        var byID: [String: CompiledRule]?
        return rules.enumerated().map { i, rule in
            if i < old.count, old[i].rule == rule { return old[i] }
            if byID == nil { byID = Dictionary(old.map { ($0.rule.id, $0) }, uniquingKeysWith: { first, _ in first }) }
            if let c = byID?[rule.id], c.rule == rule { return c }
            return compile(rule, classifier)
        }
    }

    public func replace(rules: [Rule], classifier: PathClassifier? = nil) {
        lock.lock(); defer { lock.unlock() }
        if let classifier {
            self.classifier = classifier
            classifierGeneration &+= 1
            compiled = rules.map { RuleEngine.compile($0, classifier) }
        } else {
            compiled = RuleEngine.compile(rules, self.classifier, reusing: compiled)
        }
    }

    /// Swaps the classifier and recompiles the current rules (no stale rule snapshot). The recompile
    /// runs outside the lock, so evaluation goes on (against the old classifier) meanwhile; a rule that
    /// changed in between (an edit, a used "allow once") is compiled again from its current state.
    public func replace(classifier: PathClassifier) {
        lock.lock()
        classifierGeneration &+= 1
        let generation = classifierGeneration
        let snapshot = compiled.map(\.rule)
        lock.unlock()
        let fresh = snapshot.map { RuleEngine.compile($0, classifier) }
        lock.lock(); defer { lock.unlock() }
        // A later replacement owns the classifier now.
        guard generation == classifierGeneration else { return }
        self.classifier = classifier
        compiled = RuleEngine.compile(compiled.map(\.rule), classifier, reusing: fresh)
    }

    /// Read-modify-write of the rule list under the engine lock. Returns the new list.
    @discardableResult
    public func mutate(_ f: (inout [Rule]) throws -> Void) rethrows -> [Rule] {
        lock.lock(); defer { lock.unlock() }
        var list = compiled.map(\.rule)
        try f(&list)
        compiled = RuleEngine.compile(list, classifier, reusing: compiled)
        return list
    }

    public func setNeverBlock(_ list: NeverBlockList) {
        lock.lock(); defer { lock.unlock() }
        neverBlock = list
    }

    public var rules: [Rule] {
        lock.lock(); defer { lock.unlock() }
        return compiled.map(\.rule)
    }

    /// Evaluates and, if an "allow once" exception decided the outcome, consumes one use.
    public func evaluate(
        process: ProcessRecord,
        chain: [ProcessNode],
        targets: [EvaluationTarget],
        enforcementActive: Bool,
        now: Date,
        consumeExceptions: Bool = true,
        ask: AskPolicy = .off
    ) -> RuleDecision {
        lock.lock(); defer { lock.unlock() }

        let sensitive = targets.filter { !$0.categories.isEmpty }
        guard !sensitive.isEmpty else {
            return RuleDecision(verdict: .allow, reason: .notSensitive, cacheable: true)
        }
        if neverBlock.contains(process) {
            return RuleDecision(verdict: .allow, reason: .neverBlock, cacheable: true)
        }

        var ownerCache: [String: Bool] = [:]
        func isOwner(_ category: String) -> Bool {
            if let v = ownerCache[category] { return v }
            let v = classifier.isOwner(process, of: category)
            ownerCache[category] = v
            return v
        }
        var responsibleCache: ResponsibleEntity??
        func responsible() -> ResponsibleEntity? {
            if let cached = responsibleCache { return cached }
            let r = attributor?.attribute(chain: chain)
            responsibleCache = .some(r)
            return r
        }
        let chainAgents = Set(chain.compactMap(\.agentID))

        let processPathKey = PathNormalizer.fold(process.executablePath)
        let processCdhash = process.cdhash?.lowercased()

        /// `unsignedKey` is the precompiled program path of an `.unsigned` subject. For deny rules a
        /// pinned cdhash also matches the same code at any other path (copying the binary is not a
        /// way around a block), and a responsible agent also matches wherever it is in the chain.
        func subjectMatches(_ subject: RuleSubject, category: String, unsignedKey: String? = nil, widenForDeny: Bool = false) -> Bool {
            switch subject {
            case .signed(let sid, let team):
                return process.signingID == sid && process.teamID == team
            case .unsigned(_, let cdhash):
                if widenForDeny, let cdhash, processCdhash == cdhash.lowercased() { return true }
                guard let key = unsignedKey, processPathKey == key else { return false }
                if let cdhash { return processCdhash == cdhash.lowercased() }
                return true
            case .responsible(let key, let team, let cdhash, let exceptOwners):
                if widenForDeny {
                    // "Block from now on" for an unsigned binary (a cdhash pin, no team): the same code
                    // copied to another path, or run as the leaf of a chain charged to someone else.
                    if team == nil, let pin = cdhash?.lowercased() {
                        let r = responsible()
                        if (r?.kind == .binary && r?.cdhash?.lowercased() == pin) || processCdhash == pin {
                            return !(exceptOwners && isOwner(category))
                        }
                    }
                    // For an agent: attribution picks the nearest .app first, so a leaf inside any bundle
                    // (`mkdir X.app; cp /bin/cat X.app/`) would otherwise be charged to that bundle.
                    if cdhash == nil, key.hasPrefix("agent:") {
                        let id = String(key.dropFirst("agent:".count))
                        if chain.contains(where: { $0.agentID == id && (team == nil || $0.agentTeamID == team) }) {
                            return !(exceptOwners && isOwner(category))
                        }
                    }
                }
                guard let r = responsible(), r.key == key else { return false }
                if let team, r.teamID != team { return false }
                if let cdhash, r.cdhash?.lowercased() != cdhash.lowercased() { return false }
                return !(exceptOwners && isOwner(category))
            case .anyNonOwner:
                return !isOwner(category)
            case .agentAncestor(let ids, let exceptOwners):
                let hit = ids.map { !chainAgents.isDisjoint(with: $0) } ?? !chainAgents.isEmpty
                guard hit else { return false }
                return !(exceptOwners && isOwner(category))
            }
        }

        func targetMatches(_ c: CompiledRule, _ key: String, _ keySlash: String, _ category: TargetCategory) -> Bool {
            switch c.rule.target {
            case .category(let id): return id == category.id
            case .severityAtLeast(let s): return category.severity >= s
            case .pathPrefix:
                return c.prefixKeys.indices.contains { i in
                    // Inside the prefix, or an ancestor directory of it (rename/clone of a parent).
                    key == c.prefixKeys[i] || key.hasPrefix(c.prefixKeysSlash[i]) || c.prefixKeys[i].hasPrefix(keySlash)
                }
            }
        }
        /// Ask mode: an approval scoped to a path answers for what is inside it, not for moving one of
        /// its parent directories (which carries everything else in there too).
        func coversWhole(_ c: CompiledRule, _ key: String) -> Bool {
            guard case .pathPrefix = c.rule.target else { return true }
            return c.prefixKeys.indices.contains { key == c.prefixKeys[$0] || key.hasPrefix(c.prefixKeysSlash[$0]) }
        }

        var enforcedDenied: AccessSet = []
        var enforcedDeny: Rule?
        var dryRunDeny: Rule?
        var allowHit: Rule?
        var alertHit: Rule?
        var anyCovering = false
        var dynamicCovering = false
        var consumedExceptions: [(rule: Int, exception: Int)] = []

        let asking = ask.enabled && enforcementActive
        // Ask mode, per sensitive target and category: the requested kinds that allow rules (or a deny
        // rule's exception) let through, and every kind static allow rules cover (cacheability).
        var allowed: [[AccessSet]] = asking ? sensitive.map { Array(repeating: [], count: $0.categories.count) } : []
        var allowedKinds = allowed

        for (ti, target) in sensitive.enumerated() {
            let pathKey = PathNormalizer.fold(target.path)
            let pathKeySlash = pathKey + "/"
            for (ci, category) in target.categories.enumerated() {
                for (ri, c) in compiled.enumerated() where c.rule.isLive(at: now) {
                    guard targetMatches(c, pathKey, pathKeySlash, category) else { continue }
                    let requested = c.rule.access.intersect(target.access)
                    anyCovering = true
                    if c.rule.subject.isChainDependent || c.rule.isTimeDependent || c.rule.hasChainDependentExceptions
                        || c.chainAgents != nil {
                        dynamicCovering = true
                    }
                    // Scoped to the AI agents the user saw: a chain with any other agent is not covered.
                    if let scope = c.chainAgents, !chainAgents.isSubset(of: scope) { continue }
                    guard subjectMatches(c.rule.subject, category: category.id, unsignedKey: c.unsignedKey,
                                         widenForDeny: c.rule.action == .deny) else { continue }

                    switch c.rule.action {
                    case .deny:
                        if case .anyNonOwner = c.rule.subject, process.isPlatformBinary, !c.rule.includePlatformBinaries {
                            continue
                        }
                        // Exceptions carve the subject out of this rule.
                        let exceptionIndex = c.rule.exceptions.indices.first { ei in
                            let e = c.rule.exceptions[ei]
                            guard e.isLive(at: now) else { return false }
                            if let cat = e.categoryID, cat != category.id { return false }
                            // Only requests the approval fully covers (a read approval is not a write approval).
                            if let a = e.access, a.intersect(requested) != requested { return false }
                            // Only chains whose agents the user saw when approving.
                            if let approved = e.chainAgents, !chainAgents.isSubset(of: Set(approved)) { return false }
                            let prefixes = c.exceptionPrefixKeys[ei]
                            if !prefixes.isEmpty && !prefixes.contains(where: { pathKey == $0 || pathKey.hasPrefix($0 + "/") }) {
                                return false
                            }
                            return subjectMatches(e.subject, category: category.id, unsignedKey: c.exceptionUnsignedKeys[ei])
                        }
                        if let ei = exceptionIndex {
                            if !requested.isEmpty, c.rule.exceptions[ei].remainingUses != nil {
                                consumedExceptions.append((ri, ei))
                            }
                            // The user approved this subject here ("allow once" / "always allow" on a block).
                            if asking && coversWhole(c, pathKey) { allowed[ti][ci].formUnion(requested) }
                            if enforcementActive && c.rule.enforce, let a = c.rule.exceptions[ei].access {
                                // Access kinds outside the approval stay denied (keeps AUTH_OPEN caching honest).
                                enforcedDenied.formUnion(c.rule.access.intersect(.readWrite).subtracting(a.intersect(.readWrite)))
                            }
                            continue
                        }
                        let enforced = enforcementActive && c.rule.enforce
                        if enforced { enforcedDenied.formUnion(c.rule.access.intersect(.readWrite)) }
                        guard !requested.isEmpty else { continue }
                        if enforced {
                            if enforcedDeny == nil { enforcedDeny = c.rule }
                        } else if dryRunDeny == nil {
                            dryRunDeny = c.rule
                        }
                    case .allow:
                        if !requested.isEmpty && allowHit == nil { allowHit = c.rule }
                        if asking && coversWhole(c, pathKey) {
                            allowed[ti][ci].formUnion(requested)
                            allowedKinds[ti][ci].formUnion(c.rule.access.intersect(.readWrite))
                        }
                    case .alert:
                        if !requested.isEmpty && alertHit == nil { alertHit = c.rule }
                    }
                }
            }
        }

        let cacheable = !anyCovering || !dynamicCovering

        if let rule = enforcedDeny {
            // Exceptions are only used up when they actually let an access through.
            return RuleDecision(verdict: .deny, policyDenied: enforcedDenied, reason: .explicitDeny,
                                ruleID: rule.id, forceAlert: true, cacheable: cacheable)
        }
        func consume() {
            for (ri, ei) in consumedExceptions where consumeExceptions {
                if let uses = compiled[ri].rule.exceptions[ei].remainingUses {
                    compiled[ri].rule.exceptions[ei].remainingUses = uses - 1
                    consumed = true
                }
            }
        }
        if asking {
            // Every (path, category) with a requested read or write needs a decision. An owner only
            // counts with no AI agent in the chain: an agent can drive ssh or git to read a key. A
            // chain that does not reach launchd (ancestry unknown or cut short) may hide one.
            let ancestryKnown = chain.reachesLaunchd
            var undecided: [(target: Int, category: Int)] = []
            var byOwner = false
            // ES caches an AUTH_OPEN allow for this executable and file whatever the later open's
            // flags, so only an allow static rules give for every access kind may be cached.
            var staticAllow = true
            for (ti, t) in sensitive.enumerated() {
                let needed = t.access.intersection(.readWrite)
                for (ci, category) in t.categories.enumerated() {
                    if allowedKinds[ti][ci] != .readWrite { staticAllow = false }
                    if allowed[ti][ci].isSuperset(of: needed) { continue }
                    if chainAgents.isEmpty && ancestryKnown && isOwner(category.id) {
                        byOwner = true
                        continue
                    }
                    undecided.append((ti, ci))
                }
            }
            let trusted = ask.trustApplePrograms && AskPolicy.isTrustableAppleProgram(process, chain: chain)
            if !undecided.isEmpty && !ask.benignChain && !trusted {
                // One question per access, about its most severe undecided category (ties: the first).
                // Not consumed: an "allow once" on another category waits for the answer.
                var pick = undecided[0]
                for u in undecided.dropFirst()
                where sensitive[u.target].categories[u.category].severity > sensitive[pick.target].categories[pick.category].severity {
                    pick = u
                }
                let categoryID = sensitive[pick.target].categories[pick.category].id
                let access = sensitive.reduce(AccessSet()) { acc, t in
                    t.categories.contains { $0.id == categoryID } ? acc.union(t.access) : acc
                }.intersection(.readWrite)
                // The daemon always has an attributor; without one, the program stands for itself.
                let key = AskKey(responsibleKey: responsible()?.key ?? "bin:" + PathNormalizer.fold(process.executablePath),
                                 categoryID: categoryID, access: access, chainAgents: Array(chainAgents))
                return RuleDecision(verdict: .ask, policyDenied: enforcedDenied, reason: .askUser, cacheable: false, askKey: key)
            }
            consume()
            let askCacheable = cacheable && undecided.isEmpty && staticAllow
            if let rule = dryRunDeny {
                return RuleDecision(verdict: .allow, policyDenied: enforcedDenied, wouldDeny: true, reason: .wouldDeny,
                                    ruleID: rule.id, forceAlert: true, cacheable: askCacheable)
            }
            if !undecided.isEmpty {
                // A benign service chain or a trusted Apple program: depends on the chain, never cached.
                return RuleDecision(verdict: .allow, policyDenied: enforcedDenied, reason: ask.benignChain ? .benign : .trustedApple,
                                    ruleID: alertHit?.id, forceAlert: alertHit != nil)
            }
            if let rule = allowHit {
                // An answer only answers the question: an alert rule you enabled still alerts.
                if rule.template == RuleTemplates.askAnswer, let alert = alertHit {
                    return RuleDecision(verdict: .allow, policyDenied: enforcedDenied, reason: .alertRule,
                                        ruleID: alert.id, forceAlert: true, cacheable: askCacheable)
                }
                return RuleDecision(verdict: .allow, policyDenied: enforcedDenied, reason: .explicitAllow,
                                    ruleID: rule.id, suppressAlert: true, cacheable: askCacheable)
            }
            if let rule = alertHit {
                return RuleDecision(verdict: .allow, policyDenied: enforcedDenied, reason: .alertRule,
                                    ruleID: rule.id, forceAlert: true, cacheable: askCacheable)
            }
            // Owners (no agent), or nothing read or written (a metadata-only open).
            return RuleDecision(verdict: .allow, policyDenied: enforcedDenied, reason: byOwner ? .owner : .defaultAllow,
                                cacheable: askCacheable)
        }
        consume()
        if let rule = dryRunDeny {
            return RuleDecision(verdict: .allow, policyDenied: enforcedDenied, wouldDeny: true, reason: .wouldDeny,
                                ruleID: rule.id, forceAlert: true, cacheable: cacheable)
        }
        if let rule = allowHit {
            if rule.template == RuleTemplates.askAnswer, let alert = alertHit {
                return RuleDecision(verdict: .allow, policyDenied: enforcedDenied, reason: .alertRule,
                                    ruleID: alert.id, forceAlert: true, cacheable: cacheable)
            }
            return RuleDecision(verdict: .allow, policyDenied: enforcedDenied, reason: .explicitAllow,
                                ruleID: rule.id, suppressAlert: true, cacheable: cacheable)
        }
        if let rule = alertHit {
            return RuleDecision(verdict: .allow, policyDenied: enforcedDenied, reason: .alertRule,
                                ruleID: rule.id, forceAlert: true, cacheable: cacheable)
        }
        let owner = sensitive.allSatisfy { t in t.categories.allSatisfy { isOwner($0.id) } }
        return RuleDecision(verdict: .allow, policyDenied: enforcedDenied, reason: owner ? .owner : .defaultAllow,
                            cacheable: cacheable)
    }

    /// True once after an "allow once" use was consumed (the in-memory rules differ from what was saved).
    public func takeConsumed() -> Bool {
        lock.lock(); defer { lock.unlock() }
        defer { consumed = false }
        return consumed
    }

    /// Puts the flag back after a failed save.
    public func markConsumed() {
        lock.lock(); consumed = true; lock.unlock()
    }

    /// Drops exceptions that can never match again (used up or expired), and expired answers to
    /// ask-mode questions ("allow once" is a 10-minute allow rule: otherwise every such answer would
    /// stay in the list for good, slowing the AUTH path and filling the rule limit). A rule that is
    /// only disabled is kept. Returns true if anything was dropped.
    @discardableResult
    public func pruneDeadExceptions(at now: Date) -> Bool {
        lock.lock(); defer { lock.unlock() }
        func deadAnswer(_ r: Rule) -> Bool {
            guard r.template == RuleTemplates.askAnswer else { return false }
            return (r.expiresAt.map { now >= $0 } ?? false) || (r.remainingUses.map { $0 <= 0 } ?? false)
        }
        guard compiled.contains(where: { deadAnswer($0.rule) || $0.rule.exceptions.contains { !$0.isLive(at: now) } }) else {
            return false
        }
        let list = compiled.filter { !deadAnswer($0.rule) }.map { c in
            var r = c.rule
            r.exceptions.removeAll { !$0.isLive(at: now) }
            return r
        }
        compiled = RuleEngine.compile(list, classifier, reusing: compiled)
        return true
    }

    /// Rules changed outside (e.g. an exception was consumed): callers persist this.
    public var hasConsumableState: Bool {
        lock.lock(); defer { lock.unlock() }
        return compiled.contains { $0.rule.isTimeDependent }
    }
}
