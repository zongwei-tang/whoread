import Foundation

public struct AnalysisOutput: Sendable {
    public var events: [AnalyzedEvent] = []
    public var alerts: [AlertUpdate] = []
    public init(events: [AnalyzedEvent] = [], alerts: [AlertUpdate] = []) {
        self.events = events
        self.alerts = alerts
    }
}

/// How the rule engine is consulted for an event that already happened.
public enum RuleContext: Sendable {
    /// Monitor-only source (eslogger, native NOTIFY without AUTH): deny rules become "would block".
    case monitorOnly
    /// NOTIFY event while the native AUTH path is active: the access was allowed at AUTH time, so
    /// do not re-run enforcement or consume "allow once" exceptions.
    case afterAuth
    /// The AUTH callback already decided (e.g. a denial, which produces no NOTIFY).
    case decided(RuleDecision)
}

/// Turns source events into classified, attributed events and alerts. Pure logic: no IO.
///
/// Pipeline for a file activity:
///   normalize → classify (prefix trie) → chain (process tree) → attribute → benign? → owner? →
///   rules (per category) → baseline/anomaly → coalesce alerts
public final class Analyzer: @unchecked Sendable {
    public let tree: ProcessTree
    public let baseline: Baseline
    public let coalescer: AlertCoalescer
    public let rules: RuleEngine
    public let attributor: Attributor

    private let lock = NSLock()
    private var _classifier: PathClassifier
    private var _benign: BenignClassifier
    private var _readdirEnabled = false
    private var _ignoredPIDs: Set<Int32> = []
    private var nextEventID: Int64

    /// Record directory listings (and opens of directories). Off by default.
    public var readdirEnabled: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _readdirEnabled }
        set { lock.lock(); _readdirEnabled = newValue; lock.unlock() }
    }

    /// Our own processes (the daemon). Their events are dropped.
    public var ignoredPIDs: Set<Int32> {
        get { lock.lock(); defer { lock.unlock() }; return _ignoredPIDs }
        set { lock.lock(); _ignoredPIDs = newValue; lock.unlock() }
    }

    public init(
        classifier: PathClassifier,
        tree: ProcessTree,
        attributor: Attributor,
        benign: BenignClassifier,
        rules: RuleEngine,
        baseline: Baseline,
        coalescer: AlertCoalescer,
        nextEventID: Int64 = 1
    ) {
        self._classifier = classifier
        self.tree = tree
        self.attributor = attributor
        self._benign = benign
        self.rules = rules
        self.baseline = baseline
        self.coalescer = coalescer
        self.nextEventID = nextEventID
    }

    public var classifier: PathClassifier {
        lock.lock(); defer { lock.unlock() }
        return _classifier
    }

    public func replace(classifier: PathClassifier, benign: BenignClassifier? = nil) {
        lock.lock()
        _classifier = classifier
        if let benign { _benign = benign }
        lock.unlock()
        rules.replace(classifier: classifier)
    }

    private func takeEventID() -> Int64 {
        lock.lock(); defer { lock.unlock() }
        let id = nextEventID
        nextEventID += 1
        return id
    }

    // MARK: - Entry point

    public func handle(_ event: SourceEvent, context: RuleContext = .monitorOnly) -> AnalysisOutput {
        switch event {
        case .fork(let parent, let child, let time):
            tree.fork(parent: parent, child: child, at: time)
            return AnalysisOutput()
        case .exec(let old, let new, let time):
            tree.exec(old: old, new: new, at: time)
            return AnalysisOutput()
        case .exit(let p, let time):
            tree.exit(p, at: time)
            return AnalysisOutput()
        case .file(let activity):
            return handleFile(activity, context: context)
        }
    }

    /// Operations that carry a source's content (and, for directories, everything below it).
    static let carryingOperations: Set<FileOperation> = [.rename, .clone, .link, .exchangedata, .copyfile]

    /// Classifies the targets of an activity for the AUTH path (no side effects). Directory listings
    /// are never blocked, so a `readdir` has no sensitive target here (it is still recorded, when
    /// listings are enabled, by `handleFile`).
    public func classify(_ activity: FileActivity) -> [ClassifiedTarget] {
        if activity.operation == .readdir { return [] }
        return classifyTargets(activity)
    }

    /// Classifies the targets of an activity.
    func classifyTargets(_ activity: FileActivity) -> [ClassifiedTarget] {
        let classifier = self.classifier
        var out: [ClassifiedTarget] = []
        for t in activity.targets {
            let path = classifier.normalizer.normalize(t.path)
            let carries = t.role == .source && Analyzer.carryingOperations.contains(activity.operation)
            if let c = classifier.classify(normalized: path, truncated: t.truncated) {
                var severity = c.severity
                // A directory of the category may hold its most sensitive files (moving a browser
                // profile carries Cookies): judge it by the worst file it can contain. When the source
                // does not say, a path a specific file pattern named (`.env.tmp`, `History`) is taken
                // as a file; anything else may be a directory.
                let mayBeDirectory = t.isDirectory ?? classifier.mayContainFiles(c)
                if carries && mayBeDirectory, let m = classifier.maxSeverity(c.categoryID), m > severity {
                    severity = m
                }
                out.append(ClassifiedTarget(target: t, path: path, categories: [TargetCategory(id: c.categoryID, severity: severity)],
                                            viaAncestor: false))
                continue
            }
            if carries {
                // Moving or cloning a parent directory carries every category below it.
                let below = classifier.categoriesBelow(normalized: path).compactMap { id -> TargetCategory? in
                    guard let spec = classifier.spec(id) else { return nil }
                    return TargetCategory(id: id, severity: classifier.maxSeverity(id) ?? spec.severity)
                }
                if !below.isEmpty {
                    out.append(ClassifiedTarget(target: t, path: path, categories: below, viaAncestor: true))
                    continue
                }
                // A folder inside a pattern-only category (a project): it carries the .env/.pem inside.
                if t.isDirectory == true, let c = classifier.containingCategory(normalized: path) {
                    out.append(ClassifiedTarget(target: t, path: path, categories: [c], viaAncestor: true))
                    continue
                }
            }
            out.append(ClassifiedTarget(target: t, path: path, categories: [], viaAncestor: false))
        }
        return out
    }

    public struct ClassifiedTarget: Sendable {
        public var target: FileTarget
        public var path: String
        public var categories: [TargetCategory]
        public var viaAncestor: Bool
        public var isSensitive: Bool { !categories.isEmpty }
        public var evaluationTarget: EvaluationTarget { EvaluationTarget(path: path, access: target.access, categories: categories) }
    }

    func handleFile(_ activity: FileActivity, context: RuleContext) -> AnalysisOutput {
        lock.lock()
        let readdirOn = _readdirEnabled
        let ignored = _ignoredPIDs.contains(activity.process.pid)
        let benign = _benign
        lock.unlock()
        if activity.operation == .readdir && !readdirOn { return AnalysisOutput() }
        if ignored { return AnalysisOutput() }
        let classified = classifyTargets(activity)
        guard classified.contains(where: \.isSensitive) else { return AnalysisOutput() }

        let time = activity.time
        let chain = tree.chain(for: activity.process, at: time)
        let process = chain.first?.image ?? activity.process
        let responsible = attributor.attribute(chain: chain)
        let agentID = chain.nearestAgent
        let benignID = benign.classify(chain: chain)
        let classifier = self.classifier
        // Stored chains are capped (nearest 64 links); rules, attribution and agentID use the full chain.
        let chainLinks = Array(chain.prefix(64).reversed()).map { ChainLink(node: $0) }

        // One event per category; two paths of the same operation in one category merge.
        var groups: [(category: TargetCategory, targets: [ClassifiedTarget])] = []
        for t in classified where t.isSensitive {
            for c in t.categories {
                if let i = groups.firstIndex(where: { $0.category.id == c.id }) {
                    groups[i].targets.append(t)
                    if c.severity > groups[i].category.severity { groups[i].category.severity = c.severity }
                } else {
                    groups.append((c, [t]))
                }
            }
        }

        var output = AnalysisOutput()
        let learning = baseline.isLearning(at: time)
        // Rules are evaluated per category: an allow for one category must not silence another
        // category touched by the same operation (copying a key to a USB stick).
        func evaluationTargets(_ group: (category: TargetCategory, targets: [ClassifiedTarget])) -> [EvaluationTarget] {
            group.targets.map { EvaluationTarget(path: $0.path, access: $0.target.access, categories: [group.category]) }
        }
        // A denied syscall is a denial for every category it touches, but only a category a rule
        // denies gets the rule and the blocked alert: "allow once" on the other one (the USB stick
        // the key was copied to) would add an exception for the wrong category. If no category is
        // denied any more (rules changed since the AUTH decision), all keep the AUTH decision.
        var ownDenials: [RuleDecision]?
        if case .decided(let d) = context, d.verdict == .deny, groups.count > 1 {
            let own = groups.map {
                rules.evaluate(process: process, chain: chain, targets: evaluationTargets($0), enforcementActive: true,
                               now: time, consumeExceptions: false)
            }
            if own.contains(where: { $0.verdict == .deny }) { ownDenials = own }
        }
        for (gi, group) in groups.enumerated() {
            let targets = evaluationTargets(group)
            var decision: RuleDecision
            var eventDecision: EventDecision
            switch context {
            case .decided(let d):
                if let own = ownDenials?[gi] {
                    decision = own.verdict == .deny ? own : RuleDecision(verdict: .deny, reason: d.reason, suppressAlert: true)
                } else {
                    decision = d
                }
                eventDecision = d.verdict == .deny ? .denied : .allowed
            case .monitorOnly:
                decision = rules.evaluate(process: process, chain: chain, targets: targets, enforcementActive: false, now: time)
                eventDecision = decision.wouldDeny ? .wouldDeny : .observed
            case .afterAuth:
                var d = rules.evaluate(process: process, chain: chain, targets: targets, enforcementActive: true,
                                       now: time, consumeExceptions: false)
                if d.verdict == .deny {
                    // It happened, so AUTH allowed it (allow once, a kill switch, cache lag, or a close
                    // on an earlier fd). Not a block, but the matching rule still deserves an alert.
                    d = RuleDecision(verdict: .allow, reason: d.reason, ruleID: d.ruleID, forceAlert: true)
                }
                decision = d
                eventDecision = d.wouldDeny ? .wouldDeny : .allowed
            }
            if activity.operation == .readdir && (decision.reason == .explicitDeny || decision.reason == .wouldDeny) {
                // Listings are never blocked (Analyzer.classify keeps them away from AUTH), so a deny rule
                // neither "would block" one nor turns it into a rule alert.
                decision = RuleDecision(verdict: .allow, reason: .defaultAllow)
                if case .monitorOnly = context { eventDecision = .observed } else { eventDecision = .allowed }
            }

            let primary = group.targets[0]
            let access = group.targets.reduce(AccessSet()) { $0.union($1.target.access) }
            let other = classified.first { $0.path != primary.path }?.path
            let isOwner = classifier.isOwner(process, of: group.category.id)
            var event = AnalyzedEvent(
                id: takeEventID(), time: time, operation: activity.operation, access: access,
                path: primary.path, secondaryPath: other, viaAncestor: primary.viaAncestor,
                categoryID: group.category.id, severity: group.category.severity, process: ArgvRedactor.redact(process),
                chain: chainLinks, responsible: responsible, agentID: agentID, isOwner: isOwner,
                benignServiceID: benignID, decision: eventDecision, ruleID: decision.ruleID)

            let keys = access.kinds.map { BaselineKey(responsibleKey: responsible.key, categoryID: group.category.id, access: $0) }
            let firstTime = !learning && benignID == nil && keys.contains { !baseline.contains($0) }
            let kind = alertKind(for: event, decision: decision, learning: learning)
            if benignID == nil && eventDecision != .denied {
                for k in keys { baseline.record(k, at: time, learning: learning) }
            }
            if benignID == nil, let update = coalescer.ingest(event, kind: kind, firstTime: firstTime) {
                event.alertID = update.alert.id
                output.alerts.append(update)
            }
            output.events.append(event)
        }
        return output
    }

    /// The anomaly policy. Evaluated before the event is recorded in the baseline.
    func alertKind(for event: AnalyzedEvent, decision: RuleDecision, learning: Bool) -> AlertKind? {
        if event.isBenign { return nil }
        switch event.decision {
        // A category that was only denied along with another one: that one's alert covers it.
        case .denied: return decision.suppressAlert ? nil : .blocked
        case .wouldDeny: return .wouldBlock
        default: break
        }
        if decision.suppressAlert { return nil }
        if decision.forceAlert { return .ruleAlert }
        if event.isOwner { return nil }
        let keys = event.access.kinds.map {
            BaselineKey(responsibleKey: event.responsible.key, categoryID: event.categoryID, access: $0)
        }
        if keys.isEmpty { return nil }
        if event.severity == .critical && !keys.allSatisfy(baseline.isApproved) {
            return .criticalNonOwner
        }
        if !learning && keys.contains(where: { !baseline.contains($0) }) {
            return .firstAccess
        }
        return nil
    }
}
