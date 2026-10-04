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

    public init(verdict: Verdict, policyDenied: AccessSet = [], wouldDeny: Bool = false, reason: DecisionReason,
                ruleID: String? = nil, forceAlert: Bool = false, suppressAlert: Bool = false, cacheable: Bool = false) {
        self.verdict = verdict
        self.policyDenied = policyDenied
        self.wouldDeny = wouldDeny
        self.reason = reason
        self.ruleID = ruleID
        self.forceAlert = forceAlert
        self.suppressAlert = suppressAlert
        self.cacheable = cacheable
    }

    public static func failOpen() -> RuleDecision {
        RuleDecision(verdict: .allow, reason: .failOpen)
    }
}

/// Evaluates rules for an access. Thread-safe; everything is in memory.
///
/// Priority: explicit deny > explicit allow > owner > default. `alert` rules do not change the
/// verdict, they force an alert when nothing above suppressed it.
public final class RuleEngine: @unchecked Sendable {
    private let lock = NSLock()
    private var compiled: [CompiledRule] = []
    private var classifier: PathClassifier
    /// An "allow once" use was consumed since the last `takeConsumed()` (callers persist it).
    private var consumed = false
    private let attributor: Attributor?
    public private(set) var neverBlock: NeverBlockList

    struct CompiledRule {
        var rule: Rule
        var prefixKeys: [String]
        var exceptionPrefixKeys: [[String]]
        /// Folded, normalized program path for `.unsigned` subjects (computed once, not per event).
        var unsignedKey: String?
        var exceptionUnsignedKeys: [String?]
    }

    public init(rules: [Rule], classifier: PathClassifier, attributor: Attributor? = nil, neverBlock: NeverBlockList = NeverBlockList()) {
        self.classifier = classifier
        self.attributor = attributor
        self.neverBlock = neverBlock
        self.compiled = rules.map { RuleEngine.compile($0, classifier) }
    }

    static func compile(_ rule: Rule, _ classifier: PathClassifier) -> CompiledRule {
        func keys(_ prefix: String?) -> [String] {
            guard let prefix else { return [] }
            return classifier.normalizer.expand(prefix).map { PathClassifier.stripTrailingSlash(PathNormalizer.fold($0)) }
        }
        func unsignedKey(_ s: RuleSubject) -> String? {
            if case .unsigned(let path, _) = s { return PathNormalizer.fold(classifier.normalizer.normalize(path)) }
            return nil
        }
        var prefixKeys: [String] = []
        if case .pathPrefix(let p) = rule.target { prefixKeys = keys(p) }
        return CompiledRule(rule: rule, prefixKeys: prefixKeys, exceptionPrefixKeys: rule.exceptions.map { keys($0.pathPrefix) },
                            unsignedKey: unsignedKey(rule.subject), exceptionUnsignedKeys: rule.exceptions.map { unsignedKey($0.subject) })
    }

    public func replace(rules: [Rule], classifier: PathClassifier? = nil) {
        lock.lock(); defer { lock.unlock() }
        if let classifier { self.classifier = classifier }
        compiled = rules.map { RuleEngine.compile($0, self.classifier) }
    }

    /// Swaps the classifier and recompiles the current rules atomically (no stale rule snapshot).
    public func replace(classifier: PathClassifier) {
        lock.lock(); defer { lock.unlock() }
        self.classifier = classifier
        compiled = compiled.map { RuleEngine.compile($0.rule, classifier) }
    }

    /// Read-modify-write of the rule list under the engine lock. Returns the new list.
    @discardableResult
    public func mutate(_ f: (inout [Rule]) throws -> Void) rethrows -> [Rule] {
        lock.lock(); defer { lock.unlock() }
        var list = compiled.map(\.rule)
        try f(&list)
        compiled = list.map { RuleEngine.compile($0, classifier) }
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
        consumeExceptions: Bool = true
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
        /// way around a block).
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

        func targetMatches(_ c: CompiledRule, _ target: EvaluationTarget, _ category: TargetCategory) -> Bool {
            switch c.rule.target {
            case .category(let id): return id == category.id
            case .severityAtLeast(let s): return category.severity >= s
            case .pathPrefix:
                let key = PathNormalizer.fold(target.path)
                return c.prefixKeys.contains { prefix in
                    // Inside the prefix, or an ancestor directory of it (rename/clone of a parent).
                    key == prefix || key.hasPrefix(prefix + "/") || prefix.hasPrefix(key + "/")
                }
            }
        }

        var enforcedDenied: AccessSet = []
        var enforcedDeny: Rule?
        var dryRunDeny: Rule?
        var allowHit: Rule?
        var alertHit: Rule?
        var anyCovering = false
        var dynamicCovering = false
        var consumedExceptions: [(rule: Int, exception: Int)] = []

        for target in sensitive {
            let pathKey = PathNormalizer.fold(target.path)
            for category in target.categories {
                for (ri, c) in compiled.enumerated() where c.rule.isLive(at: now) {
                    guard targetMatches(c, target, category) else { continue }
                    let requested = c.rule.access.intersect(target.access)
                    anyCovering = true
                    if c.rule.subject.isChainDependent || c.rule.isTimeDependent || c.rule.hasChainDependentExceptions {
                        dynamicCovering = true
                    }
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
        for (ri, ei) in consumedExceptions where consumeExceptions {
            if let uses = compiled[ri].rule.exceptions[ei].remainingUses {
                compiled[ri].rule.exceptions[ei].remainingUses = uses - 1
                consumed = true
            }
        }
        if let rule = dryRunDeny {
            return RuleDecision(verdict: .allow, policyDenied: enforcedDenied, wouldDeny: true, reason: .wouldDeny,
                                ruleID: rule.id, forceAlert: true, cacheable: cacheable)
        }
        if let rule = allowHit {
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

    /// Drops exceptions that can never match again (used up or expired). Returns true if any was dropped.
    @discardableResult
    public func pruneDeadExceptions(at now: Date) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard compiled.contains(where: { $0.rule.exceptions.contains { !$0.isLive(at: now) } }) else { return false }
        compiled = compiled.map { c in
            var r = c.rule
            r.exceptions.removeAll { !$0.isLive(at: now) }
            return RuleEngine.compile(r, classifier)
        }
        return true
    }

    /// Rules changed outside (e.g. an exception was consumed): callers persist this.
    public var hasConsumableState: Bool {
        lock.lock(); defer { lock.unlock() }
        return compiled.contains { $0.rule.isTimeDependent }
    }
}
