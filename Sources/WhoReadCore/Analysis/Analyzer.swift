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
///   rules → baseline/anomaly → coalesce alerts
public final class Analyzer: @unchecked Sendable {
    public let tree: ProcessTree
    public let baseline: Baseline
    public let coalescer: AlertCoalescer
    public let rules: RuleEngine
    public let attributor: Attributor

    private let lock = NSLock()
    private var _classifier: PathClassifier
    private var _benign: BenignClassifier
    private var nextEventID: Int64

    public var readdirEnabled: Bool = false
    /// Our own processes (daemon, eslogger child). Their events are dropped.
    public var ignoredPIDs: Set<Int32> = []

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
        rules.replace(rules: rules.rules, classifier: classifier)
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

    /// Classifies the targets of an activity. Used by the AUTH path too (without side effects).
    public func classify(_ activity: FileActivity) -> [ClassifiedTarget] {
        let classifier = self.classifier
        var out: [ClassifiedTarget] = []
        for t in activity.targets {
            let path = classifier.normalizer.normalize(t.path)
            if let c = classifier.classify(normalized: path) {
                out.append(ClassifiedTarget(target: t, path: path, categories: [TargetCategory(id: c.categoryID, severity: c.severity)], viaAncestor: false))
                continue
            }
            // Moving or cloning a parent directory carries the sensitive files along.
            if t.role == .source, [.rename, .clone, .link, .exchangedata].contains(activity.operation) {
                let below = classifier.categoriesBelow(normalized: path)
                if let first = below.first, let spec = classifier.spec(first) {
                    out.append(ClassifiedTarget(target: t, path: path, categories: [TargetCategory(id: first, severity: spec.severity)], viaAncestor: true))
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
        if activity.operation == .readdir && !readdirEnabled { return AnalysisOutput() }
        if ignoredPIDs.contains(activity.process.pid) { return AnalysisOutput() }
        let classified = classify(activity)
        guard classified.contains(where: \.isSensitive) else { return AnalysisOutput() }

        let time = activity.time
        let chain = tree.chain(for: activity.process, at: time)
        let process = chain.first?.image ?? activity.process
        let responsible = attributor.attribute(chain: chain)
        let agentID = chain.nearestAgent
        let benignID: String?
        do {
            lock.lock()
            let benign = _benign
            lock.unlock()
            benignID = benign.classify(chain: chain)
        }
        let classifier = self.classifier
        let chainLinks = Array(chain.reversed()).map { ChainLink(node: $0) }

        let decision: RuleDecision
        var eventDecision: EventDecision
        let evaluationTargets = classified.filter(\.isSensitive).map(\.evaluationTarget)
        switch context {
        case .decided(let d):
            decision = d
            eventDecision = d.verdict == .deny ? .denied : .allowed
        case .monitorOnly:
            decision = rules.evaluate(process: process, chain: chain, targets: evaluationTargets, enforcementActive: false, now: time)
            eventDecision = decision.wouldDeny ? .wouldDeny : .observed
        case .afterAuth:
            var d = rules.evaluate(process: process, chain: chain, targets: evaluationTargets, enforcementActive: true,
                                   now: time, consumeExceptions: false)
            if d.verdict == .deny {
                // It happened, so AUTH allowed it (exception, kill switch or race). Not a block.
                d = RuleDecision(verdict: .allow, reason: d.reason, ruleID: d.ruleID)
            }
            decision = d
            eventDecision = d.wouldDeny ? .wouldDeny : .allowed
        }

        // One event per category; two paths of the same operation in one category merge.
        var output = AnalysisOutput()
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

        let learning = baseline.isLearning(at: time)
        for group in groups {
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

            let kind = alertKind(for: event, decision: decision, learning: learning)
            if benignID == nil && eventDecision != .denied && !access.isEmpty {
                for k in access.kinds {
                    baseline.record(BaselineKey(responsibleKey: responsible.key, categoryID: group.category.id, access: k),
                                    at: time, learning: learning)
                }
            }
            if benignID == nil, let update = coalescer.ingest(event, kind: kind) {
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
        case .denied: return .blocked
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
