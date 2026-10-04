import Foundation
import WhoReadCore
import WhoReadIPC
import WhoReadStore

public struct DaemonConfiguration: Sendable {
    public var dataDirectory: String = WhoReadPaths.dataDirectory
    /// Directory with catalog.json / agents.json / benign.json defaults. nil = search.
    public var defaultsDirectory: String?
    public var source: SourceKind = .eslogger
    public var esloggerPath = "/usr/bin/eslogger"
    public var replayPath: String?
    public var replayRealtime = false
    /// Overrides home discovery (tests, replay of fixtures recorded under /Users/alice).
    public var homeDirectories: [String]?
    public var killSwitchPath: String?
    /// macOS XPC listener.
    public var machServiceName: String?
    /// Code-signing requirement every XPC client must satisfy (release builds).
    public var clientRequirement: String?
    /// Requirement that identifies the menu bar app (may weaken protection).
    public var appRequirement: String?
    public var devSocketPath: String?
    public var devSocketMode: UInt16 = 0o600
    public var permissive = false
    /// Seed the process tree from running processes (live sources only).
    public var seedProcesses = true
    /// Use an in-memory store (replay CLI, tests).
    public var inMemoryStore = false

    public init() {}

    public var resolvedKillSwitchPath: String {
        killSwitchPath ?? (dataDirectory as NSString).appendingPathComponent("disable-enforcement")
    }

    public var databasePath: String { (dataDirectory as NSString).appendingPathComponent("whoread.sqlite") }
    public var userCatalogPath: String { (dataDirectory as NSString).appendingPathComponent("catalog.json") }
}

/// The daemon's assembled state and operations, independent of process lifecycle, servers and
/// timers (see `Daemon`). Tests drive it directly.
public final class DaemonCore: @unchecked Sendable {
    public let config: DaemonConfiguration
    public let store: EventStore
    public private(set) var data: DefaultData
    let defaultCatalog: Catalog
    public let homes: [String]
    public let normalizer: PathNormalizer
    public let detector: AgentDetector
    public let tree: ProcessTree
    public let attributor: Attributor
    public let rules: RuleEngine
    public let baseline: Baseline
    public let coalescer: AlertCoalescer
    public let analyzer: Analyzer
    public let enforcement: EnforcementState
    public let latency: LatencyMonitor
    public let writer: EventWriter
    public let live: LiveBuffer
    public let pipeline: EventPipeline
    public let enforcer: Enforcer
    public private(set) var source: EventSource!
    public let startedAt = Date()

    private let lock = NSLock()
    private var settings: Settings
    private var lastRetention = Date.distantPast
    private var alertCountSinceStart = 0

    /// Rules or enforcement changed: the native source clears the ES cache.
    public var onPolicyChanged: (@Sendable () -> Void)?
    /// New or escalated alert (after it was queued for storage).
    public var onAlert: (@Sendable (AlertUpdate) -> Void)?

    public init(config: DaemonConfiguration, makeSource: ((DaemonCore) throws -> EventSource)? = nil) throws {
        self.config = config
        let now = Date()

        if !config.inMemoryStore {
            try FileManager.default.createDirectory(atPath: config.dataDirectory, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o755])
        }
        store = config.inMemoryStore ? InMemoryEventStore() : try SQLiteEventStore(path: config.databasePath)

        let (defaults, dir) = try DefaultData.locate(explicit: config.defaultsDirectory,
                                                     executablePath: CommandLine.arguments.first.map(Self.absolutePath))
        Log.debug("default data from \(dir.path)")
        defaultCatalog = defaults.catalog
        var data = defaults
        if !config.inMemoryStore, let d = FileManager.default.contents(atPath: config.userCatalogPath) {
            if let c = try? Catalog.load(from: d) {
                data.catalog = c
            } else {
                Log.warning("ignoring unreadable user catalog at \(config.userCatalogPath); using defaults")
            }
        }
        self.data = data

        settings = (try? store.settings()) ?? Settings()
        homes = config.homeDirectories ?? HomeDirectories.discover()
        normalizer = PathNormalizer(homeDirectories: homes)
        detector = AgentDetector(catalog: data.agents)
        let n = normalizer
        tree = ProcessTree(detector: detector, normalizePath: { n.normalize($0) })
        attributor = Attributor(agents: detector)

        let classifier = DaemonCore.makeClassifier(catalog: data.catalog, normalizer: normalizer, settings: settings,
                                                   resolveSymlinks: !config.inMemoryStore)
        let storedRules: [Rule]? = (try? store.loadRules()) ?? nil
        let ruleList = storedRules ?? RuleTemplates.all
        rules = RuleEngine(rules: ruleList, classifier: classifier, attributor: attributor,
                           neverBlock: NeverBlockList(selfPIDs: [getpid()]))
        if storedRules == nil { try? store.saveRules(ruleList) }

        let learningStart: Date
        if let d = try? store.date(forKey: "learning_started_at") {
            learningStart = d
        } else {
            learningStart = now
            try? store.setDate(now, forKey: "learning_started_at")
        }
        baseline = Baseline(learningStartedAt: learningStart, learningDuration: settings.learningDays * 86400,
                            entries: (try? store.loadBaseline()) ?? [])

        coalescer = AlertCoalescer(window: settings.coalesceMinutes * 60, nextID: ((try? store.maxAlertID()) ?? 0) + 1)
        if let open = try? store.alerts(AlertQuery(since: now.addingTimeInterval(-settings.coalesceMinutes * 60), limit: 1000)) {
            coalescer.restore(openAlerts: open.filter { $0.windowEndsAt > now }, nextID: ((try? store.maxAlertID()) ?? 0) + 1)
        }

        analyzer = Analyzer(classifier: classifier, tree: tree, attributor: attributor,
                            benign: BenignClassifier(catalog: data.benign), rules: rules, baseline: baseline,
                            coalescer: coalescer, nextEventID: ((try? store.maxEventID()) ?? 0) + 1)
        analyzer.readdirEnabled = settings.readdirEnabled
        analyzer.ignoredPIDs = [getpid()]

        latency = LatencyMonitor(p99ThresholdMicros: settings.latencyP99ThresholdMs * 1000)
        enforcement = EnforcementState(userEnabled: settings.enforcementEnabled, sourceCanEnforce: false)
        writer = EventWriter(store: store)
        live = LiveBuffer()
        pipeline = EventPipeline(analyzer: analyzer, writer: writer, live: live)
        enforcer = Enforcer(analyzer: analyzer, state: enforcement, latency: latency)

        pipeline.isPaused = { [weak self] in self?.currentSettings.monitoringPaused ?? false }
        pipeline.onAlert = { [weak self] update in self?.alertRaised(update) }
        pipeline.onSourceState = { state in
            if let e = state.error { Log.warning("source: \(e)" + (state.hint.map { " — \($0)" } ?? "")) }
        }
        writer.onError = { Log.error("store write failed: \($0)") }

        source = try (makeSource ?? DaemonCore.defaultSource)(self)
        enforcement.setSourceCanEnforce(source.canEnforce)
        enforcement.onChange { [weak self] active in
            guard let self else { return }
            Log.info("enforcement is now \(active ? "ACTIVE" : "inactive") \(self.enforcement.inactiveReasons.map(\.rawValue))")
            self.source.enforcementChanged(active: active)
            self.policyChanged()
        }
    }

    static func absolutePath(_ p: String) -> String {
        if p.hasPrefix("/") { return p }
        return FileManager.default.currentDirectoryPath + "/" + p
    }

    static func defaultSource(_ core: DaemonCore) throws -> EventSource {
        let prefixes = core.analyzer.classifier.prefixes.map(\.path)
        switch core.config.source {
        case .eslogger:
            let s = EsloggerSource(executable: core.config.esloggerPath, prefixes: prefixes, readdir: core.currentSettings.readdirEnabled)
            s.onChildStarted = { [weak core] pid in core?.analyzer.ignoredPIDs.insert(pid) }
            return s
        case .replay:
            guard let path = core.config.replayPath else { throw IPCError(.invalid, "replay source needs a file") }
            return ReplaySource(path: path, realtime: core.config.replayRealtime, prefixes: prefixes)
        case .native:
            #if canImport(EndpointSecurity)
            return NativeESSource(core: core)
            #else
            throw IPCError(.unavailable, "the native Endpoint Security source needs macOS")
            #endif
        }
    }

    static func makeClassifier(catalog: Catalog, normalizer: PathNormalizer, settings: Settings, resolveSymlinks: Bool) -> PathClassifier {
        PathClassifier(catalog: catalog, normalizer: normalizer, projectRoots: settings.projectRoots,
                       symlinks: resolveSymlinks ? RealpathSymlinkResolver() : NoSymlinkResolver())
    }

    func policyChanged() {
        source?.policyChanged()
        onPolicyChanged?()
    }

    public var currentSettings: Settings {
        lock.lock(); defer { lock.unlock() }
        return settings
    }

    // MARK: - Alerts

    private func alertRaised(_ update: AlertUpdate) {
        guard update.shouldNotify else { return }
        let f = AlertFormatter(language: .en, abbreviate: { [normalizer] in normalizer.abbreviate($0) },
                               categoryName: { [weak self] in self?.analyzer.classifier.spec($0)?.name })
        Log.info("ALERT #\(update.alert.id) [\(update.alert.kind.rawValue)] \(f.headline(update.alert)) | \(f.chainLine(update.alert.chain))")
        onAlert?(update)
    }

    public func apply(action: AlertAction, toAlert id: Int64, peer: IPCPeer) throws {
        writer.flush()
        guard var alert = try store.alert(id: id) else { throw IPCError(.notFound, "no alert #\(id)") }
        let now = Date()
        let subject = RuleSubject.responsible(key: alert.responsible.key, teamID: alert.responsible.teamID)
        let categoryName = analyzer.classifier.spec(alert.categoryID)?.name.en ?? alert.categoryID
        switch action {
        case .allowOnce:
            guard let ruleID = alert.ruleID else {
                throw IPCError(.invalid, "\"allow once\" applies to blocked accesses only")
            }
            try addException(toRule: ruleID, RuleException(
                subject: subject, pathPrefix: alert.firstPath, categoryID: alert.categoryID,
                expiresAt: now.addingTimeInterval(600), remainingUses: 1, createdAt: now))
        case .alwaysAllow:
            if let ruleID = alert.ruleID, alert.kind == .blocked || alert.kind == .wouldBlock {
                try addException(toRule: ruleID, RuleException(subject: subject, categoryID: alert.categoryID, createdAt: now))
            }
            baseline.approve(responsibleKey: alert.responsible.key, categoryID: alert.categoryID, at: now)
            persistBaseline()
        case .blockFromNowOn:
            let rule = Rule(
                name: "Block \(alert.responsible.displayName) from \(categoryName)", enabled: true, enforce: true,
                target: .category(alert.categoryID), subject: subject, access: .any, action: .deny,
                includePlatformBinaries: true, createdAt: now)
            try setRules(rules.rules + [rule])
            if !enforcement.isActive {
                Log.info("rule \(rule.id) added; it blocks only while enforcement is on (currently off)")
            }
        case .keepBlocking, .ignore:
            break
        }
        alert.status = .resolved
        alert.resolution = action
        try store.upsert([alert])
        coalescer.updateStatus(alertID: id, status: .resolved, resolution: action)
        Log.info("alert #\(id): \(action.rawValue) by pid \(peer.pid.map(String.init) ?? "?") (uid \(peer.euid.map(String.init) ?? "?"))")
    }

    private func addException(toRule ruleID: String, _ exception: RuleException) throws {
        var list = rules.rules
        guard let i = list.firstIndex(where: { $0.id == ruleID }) else {
            throw IPCError(.notFound, "the rule behind this alert no longer exists")
        }
        list[i].exceptions.removeAll { !$0.isLive(at: Date()) }
        list[i].exceptions.append(exception)
        try setRules(list)
    }

    public func markRead(_ ids: [Int64]?) throws {
        writer.flush()
        let targets = try store.alerts(AlertQuery(statuses: [.unread], limit: 10_000)).filter { ids == nil || ids!.contains($0.id) }
        let updated = targets.map { a -> Alert in
            var a = a
            a.status = .read
            return a
        }
        try store.upsert(updated)
        for a in updated { coalescer.updateStatus(alertID: a.id, status: .read, resolution: nil) }
    }

    // MARK: - Rules

    public func setRules(_ list: [Rule]) throws {
        let ids = list.map(\.id)
        guard Set(ids).count == ids.count else { throw IPCError(.invalid, "duplicate rule ids") }
        rules.replace(rules: list)
        try store.saveRules(list)
        enforcement.setRulesLoaded(true)
        policyChanged()
    }

    public func upsert(rule: Rule, peer: IPCPeer) throws {
        if case .category(let id) = rule.target, data.catalog.category(id) == nil {
            throw IPCError(.invalid, "unknown category \(id)")
        }
        var list = rules.rules
        if let i = list.firstIndex(where: { $0.id == rule.id }) {
            list[i] = rule
        } else {
            list.append(rule)
        }
        try setRules(list)
        Log.info("rule \(rule.id) saved by pid \(peer.pid.map(String.init) ?? "?")")
    }

    public func deleteRule(id: String, peer: IPCPeer) throws {
        var list = rules.rules
        guard let i = list.firstIndex(where: { $0.id == id }) else { throw IPCError(.notFound, "no rule \(id)") }
        list.remove(at: i)
        try setRules(list)
        Log.info("rule \(id) deleted by pid \(peer.pid.map(String.init) ?? "?")")
    }

    // MARK: - Settings & catalog

    public func update(settings new: Settings, peer: IPCPeer) throws {
        let s = new.validated()
        lock.lock()
        let old = settings
        settings = s
        lock.unlock()
        try store.saveSettings(s)
        baseline.learningDuration = s.learningDays * 86400
        coalescer.window = s.coalesceMinutes * 60
        analyzer.readdirEnabled = s.readdirEnabled
        latency.p99ThresholdMicros = s.latencyP99ThresholdMs * 1000
        if old.projectRoots != s.projectRoots || old.readdirEnabled != s.readdirEnabled {
            recompileClassifier()
        }
        if old.enforcementEnabled != s.enforcementEnabled {
            if s.enforcementEnabled { latency.reset() }
            enforcement.setUserEnabled(s.enforcementEnabled)
            Log.info("enforcement switched \(s.enforcementEnabled ? "on" : "off") by pid \(peer.pid.map(String.init) ?? "?") uid \(peer.euid.map(String.init) ?? "?")")
        }
        if old.monitoringPaused != s.monitoringPaused {
            Log.info("monitoring \(s.monitoringPaused ? "paused" : "resumed") by pid \(peer.pid.map(String.init) ?? "?")")
        }
    }

    public func update(catalog: Catalog?, peer: IPCPeer) throws {
        let c = catalog ?? defaultCatalog
        let ids = c.categories.map(\.id)
        guard Set(ids).count == ids.count else { throw IPCError(.invalid, "duplicate category ids") }
        if !config.inMemoryStore {
            if catalog == nil {
                try? FileManager.default.removeItem(atPath: config.userCatalogPath)
            } else {
                try c.encoded().write(to: URL(fileURLWithPath: config.userCatalogPath), options: .atomic)
                chmod(config.userCatalogPath, 0o600)
            }
        }
        lock.lock()
        data.catalog = c
        lock.unlock()
        recompileClassifier()
        Log.info("catalog \(catalog == nil ? "reset to defaults" : "updated") by pid \(peer.pid.map(String.init) ?? "?")")
    }

    public func recompileClassifier() {
        lock.lock()
        let catalog = data.catalog
        let s = settings
        lock.unlock()
        let c = DaemonCore.makeClassifier(catalog: catalog, normalizer: normalizer, settings: s, resolveSymlinks: !config.inMemoryStore)
        analyzer.replace(classifier: c)
        source?.updateMonitoring(prefixes: c.prefixes.map(\.path), ancestors: c.ancestors, readdir: s.readdirEnabled)
        policyChanged()
    }

    public func restartLearning(peer: IPCPeer) throws {
        let now = Date()
        baseline.resetLearned(at: now)
        try store.setDate(now, forKey: "learning_started_at")
        persistBaseline()
        Log.info("learning restarted by pid \(peer.pid.map(String.init) ?? "?")")
    }

    public func catalogInfo() -> CatalogInfo {
        let c = analyzer.classifier
        let detected = c.detection { FileManager.default.fileExists(atPath: $0) }
        return CatalogInfo(catalog: c.catalog, detected: detected, prefixes: c.prefixes, homeDirectories: homes)
    }

    // MARK: - Maintenance & status

    public func persistBaseline() {
        let dirty = baseline.takeDirty()
        guard !dirty.isEmpty else { return }
        do { try store.saveBaseline(dirty) } catch { Log.error("baseline save failed: \(error)") }
    }

    /// Periodic housekeeping (every ~30 s).
    public func maintenance(now: Date = Date()) {
        tree.prune(now: now)
        coalescer.expire(now: now)
        persistBaseline()
        if now.timeIntervalSince(lastRetention) > 3600 {
            lastRetention = now
            let s = currentSettings
            writer.flush()
            do {
                let removed = try store.applyRetention(
                    detailCutoff: now.addingTimeInterval(-Double(s.detailDays) * 86400),
                    retentionCutoff: now.addingTimeInterval(-Double(s.retentionDays) * 86400))
                if removed > 0 { Log.info("retention: rolled up \(removed) events into daily aggregates") }
            } catch {
                Log.error("retention failed: \(error)")
            }
        }
        if rules.hasConsumableState { try? store.saveRules(rules.rules) }
    }

    /// Latency check (every second while enforcing).
    public func checkLatency() {
        let stats = latency.evaluate()
        if let reason = latency.trippedReason, enforcement.latencyTripReason == nil, enforcement.userEnabledSetting {
            enforcement.tripLatency(reason)
            Log.error("enforcement disabled automatically: \(reason) (p50 \(Int(stats.p50Micros)) µs, p99 \(Int(stats.p99Micros)) µs)")
        }
    }

    public func status() -> DaemonStatus {
        let now = Date()
        let s = currentSettings
        let stats = pipeline.stats
        let counts = (try? store.counts()) ?? StoreCounts(events: 0, aggregatedDays: 0, alerts: 0, unreadAlerts: 0)
        let learning = baseline.isLearning(at: now)
        let enforcing = enforcement.isActive && rules.rules.contains { $0.isLive(at: now) && $0.action == .deny && $0.enforce }
        let mode: DaemonMode
        if !stats.source.running && stats.source.error != nil && !stats.source.finished {
            mode = .error
        } else if s.monitoringPaused {
            mode = .paused
        } else if enforcing {
            mode = .enforcing
        } else if learning {
            mode = .learning
        } else {
            mode = .monitoring
        }
        return DaemonStatus(
            version: WhoReadVersion.string, pid: getpid(), startedAt: startedAt, mode: mode, source: source.kind,
            sourceRunning: stats.source.running, sourceError: stats.source.error, sourceHint: stats.source.hint,
            sourceCanEnforce: source.canEnforce, learning: learning, learningEndsAt: baseline.learningEndsAt(),
            monitoringPaused: s.monitoringPaused, enforcementEnabled: s.enforcementEnabled,
            enforcementActive: enforcement.isActive, enforcementInactiveReasons: enforcement.inactiveReasons,
            latencyTripReason: enforcement.latencyTripReason, killSwitchFilePresent: enforcement.killSwitchFilePresent,
            latency: latency.evaluateWithoutTripping(), parser: source.parserStats, counts: counts,
            unreadAlerts: counts.unreadAlerts, lastEventAt: stats.lastEventAt, eventsProcessed: stats.processed,
            writerDropped: writer.droppedCount, monitoredPrefixes: analyzer.classifier.prefixes.count,
            homeDirectories: homes)
    }
}
