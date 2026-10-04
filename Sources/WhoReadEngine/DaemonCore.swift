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
    /// Fill third-party owner team / signing IDs from `codesign -dv` at start (macOS, in memory only).
    public var resolveOwners = true
    /// How often home directories and symlinked prefixes are re-discovered.
    public var rediscoveryInterval: TimeInterval = 300

    public init() {}

    public var resolvedKillSwitchPath: String {
        killSwitchPath ?? (dataDirectory as NSString).appendingPathComponent("disable-enforcement")
    }

    public var databasePath: String { (dataDirectory as NSString).appendingPathComponent("whoread.sqlite") }
    public var userCatalogPath: String { (dataDirectory as NSString).appendingPathComponent("catalog.json") }
    /// The default catalog the user's copy was made from, so upgrades can merge new defaults in.
    public var userCatalogBasePath: String { (dataDirectory as NSString).appendingPathComponent("catalog.base.json") }
    /// Exists while the native source has AUTH events subscribed. Found at start = the previous
    /// instance died while enforcing (the kernel kills a client that misses an AUTH deadline).
    public var authArmedMarkerPath: String { (dataDirectory as NSString).appendingPathComponent("auth-armed") }
    public var lockPath: String { (dataDirectory as NSString).appendingPathComponent("daemon.lock") }
}

/// A value shared with closures created before `self` exists (the process tree's normalizer).
final class LockedBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: T
    init(_ value: T) { stored = value }
    var value: T {
        get { lock.lock(); defer { lock.unlock() }; return stored }
        set { lock.lock(); stored = newValue; lock.unlock() }
    }
}

/// The daemon's assembled state and operations, independent of process lifecycle, servers and
/// timers (see `Daemon`). Tests drive it directly.
public final class DaemonCore: @unchecked Sendable {
    public let config: DaemonConfiguration
    public let store: EventStore
    let defaultCatalog: Catalog
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

    /// Guards `settings`, `_data`, `effectiveCatalog`, `_homes` and the bookkeeping fields below.
    private let lock = NSLock()
    /// Serializes read-modify-write operations on rules, settings and the catalog (IPC threads run
    /// concurrently). Recursive: `apply` calls `setRules`, `upsert` may update the catalog.
    private let mutation = NSRecursiveLock()
    /// Enforcement observers run here, never on the thread that flipped the state (that can be the
    /// ES callback thread, which must not do IO).
    private let policyQueue = DispatchQueue(label: "whoread.policy")
    private var settings: Settings
    private var _data: DefaultData
    /// `_data.catalog` with owner identities resolved on this Mac. Never persisted: writing it
    /// would freeze the defaults (see `merge`).
    private var effectiveCatalog: Catalog
    private var catalogGeneration = 0
    private var _homes: [String]
    private let normalizerBox: LockedBox<PathNormalizer>
    private var lastRetention = Date.distantPast
    private var lastRediscovery = Date()
    private var rulesLoadError: String?

    static let tripKey = "enforcement_trip_reason"
    /// Marks rules made by "block from now on" (the app localizes their names).
    public static let blockFromNowOnTemplate = "block-from-now-on"
    /// Limits on what a (possibly unprivileged) client can store; rule evaluation is linear in them.
    static let maxRules = 512
    static let maxExceptions = 256

    /// Tests only: runs in `rediscover` between building the new classifier and installing it.
    var rediscoveryHook: (() -> Void)?

    /// Rules or enforcement changed: the native source clears the ES cache.
    public var onPolicyChanged: (@Sendable () -> Void)?
    /// New or escalated alert (after it was queued for storage).
    public var onAlert: (@Sendable (AlertUpdate) -> Void)?

    public var data: DefaultData {
        lock.lock(); defer { lock.unlock() }
        return _data
    }

    public var homes: [String] {
        lock.lock(); defer { lock.unlock() }
        return _homes
    }

    public var normalizer: PathNormalizer { normalizerBox.value }

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
            if let stored = try? Catalog.load(from: d) {
                let base = FileManager.default.contents(atPath: config.userCatalogBasePath).flatMap { try? Catalog.load(from: $0) }
                let user = DaemonCore.stripResolvedOwners(stored, reference: base ?? defaults.catalog)
                let merged = DaemonCore.merge(user: user, base: base, defaults: defaults.catalog)
                data.catalog = merged
                if merged != stored || base != defaults.catalog {
                    DaemonCore.writeUserCatalog(merged, base: defaults.catalog, config: config)
                    if merged != stored { Log.info("user catalog updated with new defaults") }
                }
            } else {
                Log.warning("ignoring unreadable user catalog at \(config.userCatalogPath); using defaults")
            }
        }
        _data = data

        var settings = (try? store.settings()) ?? Settings()
        _homes = config.homeDirectories ?? HomeDirectories.discover()
        normalizerBox = LockedBox(PathNormalizer(homeDirectories: _homes))
        detector = AgentDetector(catalog: data.agents)
        let box = normalizerBox
        tree = ProcessTree(detector: detector, normalizePath: { box.value.normalize($0) })
        attributor = Attributor(agents: detector)

        effectiveCatalog = DaemonCore.resolveOwners(data.catalog, config: config)
        let classifier = DaemonCore.makeClassifier(catalog: effectiveCatalog, normalizer: normalizerBox.value, settings: settings,
                                                   resolveSymlinks: !config.inMemoryStore)

        // A store that cannot be read must not be mistaken for a fresh one: keep enforcement off and
        // never overwrite the stored rules with the templates.
        var rulesOK = true
        let storedRules: [Rule]?
        do {
            storedRules = try store.loadRules()
        } catch {
            storedRules = nil
            rulesOK = false
            rulesLoadError = "\(error)"
            Log.error("rules failed to load: \(error); enforcement stays off until they load")
        }
        let ruleList = storedRules ?? (rulesOK ? RuleTemplates.all : [])
        rules = RuleEngine(rules: ruleList, classifier: classifier, attributor: attributor,
                           neverBlock: NeverBlockList(selfPIDs: [getpid()]))
        if storedRules == nil && rulesOK { try? store.saveRules(ruleList) }

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
        // eslogger suppresses its own events; the daemon is the only process ignored here.
        analyzer.ignoredPIDs = [getpid()]

        // The previous instance died while AUTH events were subscribed: most likely the kernel killed it
        // for a missed deadline. Coming back with enforcement on would repeat that, so leave it off.
        if !config.inMemoryStore, FileManager.default.fileExists(atPath: config.authArmedMarkerPath) {
            try? FileManager.default.removeItem(atPath: config.authArmedMarkerPath)
            if settings.enforcementEnabled {
                settings.enforcementEnabled = false
                try? store.saveSettings(settings)
                try? store.setValue(Data("the previous daemon stopped while enforcing (likely a missed AUTH deadline)".utf8),
                                    forKey: DaemonCore.tripKey)
                Log.error("enforcement left off: the previous instance terminated while enforcing")
            }
        }
        self.settings = settings

        latency = LatencyMonitor(p99ThresholdMicros: settings.latencyP99ThresholdMs * 1000)
        enforcement = EnforcementState(userEnabled: settings.enforcementEnabled, sourceCanEnforce: false)
        if !rulesOK { enforcement.setRulesLoaded(false) }
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
            self.policyQueue.async {
                Log.info("enforcement is now \(active ? "ACTIVE" : "inactive") \(self.enforcement.inactiveReasons.map(\.rawValue))")
                self.source.enforcementChanged(active: active)
                self.policyChanged()
            }
        }
        // Also when the trip happens while enforcement is already inactive (kill-switch window).
        enforcement.onTrip { [weak self] reason in
            guard let self else { return }
            self.policyQueue.async { self.persistTrip(reason) }
        }
    }

    static func absolutePath(_ p: String) -> String {
        if p.hasPrefix("/") { return p }
        return FileManager.default.currentDirectoryPath + "/" + p
    }

    static func defaultSource(_ core: DaemonCore) throws -> EventSource {
        // Every byte-distinct spelling: ES compares VFS paths, the eslogger prefilter compares bytes.
        let prefixes = core.analyzer.classifier.mutePaths
        switch core.config.source {
        case .eslogger:
            return EsloggerSource(executable: core.config.esloggerPath, prefixes: prefixes, readdir: core.currentSettings.readdirEnabled)
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

    /// Owner team / signing IDs from `codesign -dv` of the apps installed here (brief §3). Third-party
    /// bundle owners match nothing until resolved (IdentitySpec fails closed).
    static func resolveOwners(_ catalog: Catalog, config: DaemonConfiguration) -> Catalog {
        #if os(macOS)
        guard config.resolveOwners, !config.inMemoryStore else { return catalog }
        let (resolved, report) = OwnerResolver.resolve(catalog: catalog, reader: CodesignCommandReader(),
                                                       exists: { FileManager.default.fileExists(atPath: $0) })
        Log.info("owners: \(report.resolved.count) identities resolved, \(report.missing.count) paths not installed")
        return resolved
        #else
        return catalog
        #endif
    }

    func policyChanged() {
        source?.policyChanged()
        onPolicyChanged?()
    }

    /// Waits until enforcement observers queued so far have run (tests).
    func drainPolicyQueue() { policyQueue.sync {} }

    public var currentSettings: Settings {
        lock.lock(); defer { lock.unlock() }
        return settings
    }

    // MARK: - Catalog upgrades

    /// Brings a user's catalog up to date with new defaults. `base` is the default catalog the user's
    /// copy was made from: a field the user left as it was takes the new default, a field the user
    /// changed keeps the user's value. New default categories are added, categories the user deleted
    /// stay deleted, custom categories are kept.
    static func merge(user: Catalog, base: Catalog?, defaults: Catalog) -> Catalog {
        if base == defaults { return user }
        guard let base else {
            // A copy from before base tracking: only add the categories it does not know.
            var out = user
            for d in defaults.categories where user.category(d.id) == nil { out.categories.append(d) }
            out.version = defaults.version
            return out
        }
        func pick<T: Equatable>(_ u: T, _ b: T?, _ d: T) -> T { u == b ? d : u }
        var out = Catalog(version: defaults.version, categories: [])
        for u in user.categories {
            guard let d = defaults.category(u.id) else { out.categories.append(u); continue }
            let b = base.category(u.id)
            var m = u
            m.name = pick(u.name, b?.name, d.name)
            m.description = pick(u.description, b?.description, d.description)
            m.kind = pick(u.kind, b?.kind, d.kind)
            m.group = pick(u.group, b?.group, d.group)
            m.severity = pick(u.severity, b?.severity, d.severity)
            m.paths = pick(u.paths, b?.paths, d.paths)
            m.patterns = pick(u.patterns, b?.patterns, d.patterns)
            m.matchOnlyPatterns = pick(u.matchOnlyPatterns, b?.matchOnlyPatterns, d.matchOnlyPatterns)
            m.owners = pick(u.owners, b?.owners, d.owners)
            m.enabled = pick(u.enabled, b?.enabled, d.enabled)
            out.categories.append(m)
        }
        for d in defaults.categories where user.category(d.id) == nil && base.category(d.id) == nil {
            out.categories.append(d)
        }
        return out
    }

    /// Owner identities resolved on this Mac that ended up in the user's copy (`whoread catalog
    /// resolve-owners`, or a client saving back a resolved catalog). The daemon resolves owners in
    /// memory at every start, and persisted ones would freeze that category's owners for good (`merge`
    /// takes them for a user edit). An owner spec that is its default plus added team or signing IDs
    /// goes back to the default.
    static func stripResolvedOwners(_ catalog: Catalog, reference: Catalog) -> Catalog {
        var out = catalog
        for ci in out.categories.indices {
            guard let ref = reference.category(out.categories[ci].id), ref.owners.count == out.categories[ci].owners.count else {
                continue
            }
            for oi in out.categories[ci].owners.indices {
                let u = out.categories[ci].owners[oi], d = ref.owners[oi]
                guard u != d else { continue }
                var bare = u
                bare.teamIDs = d.teamIDs
                bare.signingIDs = d.signingIDs
                let addsOnly = Set(u.teamIDs ?? []).isSuperset(of: d.teamIDs ?? [])
                    && Set(u.signingIDs ?? []).isSuperset(of: d.signingIDs ?? [])
                if bare == d && addsOnly { out.categories[ci].owners[oi] = d }
            }
        }
        return out
    }

    static func writeUserCatalog(_ catalog: Catalog, base: Catalog, config: DaemonConfiguration) {
        do {
            try catalog.encoded().write(to: URL(fileURLWithPath: config.userCatalogPath), options: .atomic)
            chmod(config.userCatalogPath, 0o600)
            try base.encoded().write(to: URL(fileURLWithPath: config.userCatalogBasePath), options: .atomic)
            chmod(config.userCatalogBasePath, 0o600)
        } catch {
            Log.error("could not write the user catalog: \(error)")
        }
    }

    // MARK: - Alerts

    private func alertRaised(_ update: AlertUpdate) {
        guard update.shouldNotify else { return }
        let f = AlertFormatter(language: .en, abbreviate: { [normalizerBox] in normalizerBox.value.abbreviate($0) },
                               categoryName: { [weak self] in self?.analyzer.classifier.spec($0)?.name })
        Log.info("ALERT #\(update.alert.id) [\(update.alert.kind.rawValue)] \(f.headline(update.alert)) | \(f.chainLine(update.alert.chain))")
        onAlert?(update)
    }

    /// Acts on an alert. `privileged`: root or the signed app. An unprivileged "block from now on"
    /// adds the rule but leaves the alert open, so an agent cannot use it to silence its own alert.
    public func apply(action: AlertAction, toAlert id: Int64, peer: IPCPeer, privileged: Bool = true) throws {
        mutation.lock(); defer { mutation.unlock() }
        writer.flush()
        guard var alert = try store.alert(id: id) else { throw IPCError(.notFound, "no alert #\(id)") }
        let now = Date()
        // Unsigned binaries are pinned to their cdhash (brief §5: path + cdhash).
        let r = alert.responsible
        let pin = r.kind == .binary && r.teamID == nil ? r.cdhash : nil
        let subject = RuleSubject.responsible(key: r.key, teamID: r.teamID, cdhash: pin)
        let chainAgents = Array(Set(alert.chain.compactMap(\.agentID))).sorted()
        let access: RuleAccess = alert.accesses == .read ? .read : (alert.accesses == .write ? .write : .any)
        let categoryName = analyzer.classifier.spec(alert.categoryID)?.name.en ?? alert.categoryID
        switch action {
        case .allowOnce:
            guard let ruleID = alert.ruleID, alert.kind == .blocked else {
                throw IPCError(.invalid, "\"allow once\" applies to blocked accesses only")
            }
            // firstPath is the access that made the alert "blocked" (the coalescer moves it on escalation).
            try addException(toRule: ruleID, RuleException(
                subject: subject, pathPrefix: alert.firstPath, categoryID: alert.categoryID, access: access,
                chainAgents: chainAgents, expiresAt: now.addingTimeInterval(600), remainingUses: 1, createdAt: now))
        case .alwaysAllow:
            if let ruleID = alert.ruleID, alert.kind == .blocked || alert.kind == .wouldBlock {
                try addException(toRule: ruleID, RuleException(subject: subject, categoryID: alert.categoryID, access: access,
                                                               chainAgents: chainAgents, createdAt: now))
            }
            baseline.approve(responsibleKey: r.key, categoryID: alert.categoryID, at: now)
            persistBaseline()
        case .blockFromNowOn:
            // Owners keep working: blocking the terminal an alert was charged to must not break ssh/git.
            let blockSubject = RuleSubject.responsible(key: r.key, teamID: r.teamID, cdhash: pin, exceptOwners: true)
            let exists = rules.rules.contains {
                $0.action == .deny && $0.target == .category(alert.categoryID) && $0.subject == blockSubject && $0.enabled
            }
            if !exists {
                let rule = Rule(
                    name: "Block \(r.displayName) from \(categoryName)", enabled: true, enforce: true,
                    target: .category(alert.categoryID), subject: blockSubject, access: .any, action: .deny,
                    includePlatformBinaries: true, createdAt: now, template: DaemonCore.blockFromNowOnTemplate)
                try saveRuleChange(peer: peer, privileged: privileged) { list in
                    guard list.count < DaemonCore.maxRules else { throw IPCError(.invalid, "too many rules") }
                    list.append(rule)
                }
                if !enforcement.isActive {
                    Log.info("rule \(rule.id) added; it blocks only while enforcement is on (currently off)")
                }
            }
        case .keepBlocking, .ignore:
            break
        }
        if privileged {
            alert.status = .resolved
            alert.resolution = action
            try store.upsert([alert])
            // Replaces a stale snapshot the writer may have re-queued after a failed flush.
            writer.enqueue(alerts: [alert])
            coalescer.updateStatus(alertID: id, status: .resolved, resolution: action)
        }
        Log.info("alert #\(id): \(action.rawValue) by pid \(peer.pid.map(String.init) ?? "?") (uid \(peer.euid.map(String.init) ?? "?"))")
    }

    private func addException(toRule ruleID: String, _ exception: RuleException) throws {
        try saveRuleChange(peer: nil, privileged: true) { list in
            guard let i = list.firstIndex(where: { $0.id == ruleID }) else {
                throw IPCError(.notFound, "the rule behind this alert no longer exists")
            }
            list[i].exceptions.removeAll { !$0.isLive(at: Date()) }
            list[i].exceptions.append(exception)
            try DaemonCore.validate(list[i])
        }
    }

    public func markRead(_ ids: [Int64]?, peer: IPCPeer = .inProcess) throws {
        writer.flush()
        Log.info("alerts \(ids.map { $0.map(String.init).joined(separator: ",") } ?? "all") marked read by pid \(peer.pid.map(String.init) ?? "?") uid \(peer.euid.map(String.init) ?? "?")")
        let targets = try store.alerts(AlertQuery(statuses: [.unread], limit: 10_000)).filter { ids == nil || ids!.contains($0.id) }
        let updated = targets.map { a -> Alert in
            var a = a
            a.status = .read
            return a
        }
        try store.upsert(updated)
        writer.enqueue(alerts: updated)
        for a in updated { coalescer.updateStatus(alertID: a.id, status: .read, resolution: nil) }
    }

    // MARK: - Rules

    /// Bounds on rule contents: rule evaluation runs on the AUTH path, so one oversized rule from an
    /// unprivileged client must not be able to slow it down (and trip enforcement off).
    static func validate(_ r: Rule) throws {
        func check(_ ok: Bool, _ what: String) throws { if !ok { throw IPCError(.invalid, "rule \(what) is too long or invalid") } }
        let idChars = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        try check(!r.id.isEmpty && r.id.utf8.count <= 128 && r.id.unicodeScalars.allSatisfy(idChars.contains), "id")
        try check((r.name?.utf8.count ?? 0) <= 256, "name")
        if case .pathPrefix(let p) = r.target { try check(!p.isEmpty && p.utf8.count <= 1024, "path") }
        func checkSubject(_ s: RuleSubject) throws {
            switch s {
            case .signed(let sid, let team):
                try check(!sid.isEmpty && sid.utf8.count <= 256 && (team?.utf8.count ?? 0) <= 32, "signing identity")
            case .unsigned(let path, let cdhash):
                try check(!path.isEmpty && path.utf8.count <= 1024 && (cdhash?.utf8.count ?? 0) <= 64, "unsigned subject")
            case .responsible(let key, let team, let cdhash, _):
                try check(!key.isEmpty && key.utf8.count <= 1024 && (team?.utf8.count ?? 0) <= 32 && (cdhash?.utf8.count ?? 0) <= 64,
                          "responsible subject")
            case .agentAncestor(let ids, _):
                try check((ids?.count ?? 0) <= 32 && (ids ?? []).allSatisfy { $0.utf8.count <= 64 }, "agent list")
            case .anyNonOwner:
                break
            }
        }
        try checkSubject(r.subject)
        try check(r.exceptions.count <= maxExceptions, "exception list")
        for e in r.exceptions {
            try checkSubject(e.subject)
            try check((e.pathPrefix?.utf8.count ?? 0) <= 1024 && (e.categoryID?.utf8.count ?? 0) <= 128, "exception")
            try check((e.chainAgents?.count ?? 0) <= 32 && (e.chainAgents ?? []).allSatisfy { $0.utf8.count <= 64 }, "exception agents")
        }
    }

    /// Read-modify-write of the rule list: applied atomically in the engine (a consumed "allow once"
    /// is never reverted by a stale copy), then persisted.
    private func saveRuleChange(peer: IPCPeer?, privileged: Bool, _ f: (inout [Rule]) throws -> Void) throws {
        mutation.lock(); defer { mutation.unlock() }
        try checkRulesWritable(privileged: privileged)
        let list = try rules.mutate { list in
            try f(&list)
            let ids = list.map(\.id)
            guard Set(ids).count == ids.count else { throw IPCError(.invalid, "duplicate rule ids") }
            guard list.count <= DaemonCore.maxRules else { throw IPCError(.invalid, "too many rules (max \(DaemonCore.maxRules))") }
        }
        try persistRules(list)
    }

    /// While stored rules could not be read, only root or the app may overwrite them.
    private func checkRulesWritable(privileged: Bool) throws {
        lock.lock(); let failed = rulesLoadError; lock.unlock()
        if failed != nil && !privileged {
            throw IPCError(.unavailable, "the stored rules could not be loaded; only root or the WhoRead app may replace them")
        }
    }

    private func persistRules(_ list: [Rule]) throws {
        do {
            try store.saveRules(list)
        } catch {
            Log.error("rules applied but not saved: \(error)")
            policyChanged()
            throw IPCError(.internalError, "rules applied but not saved: \(error)")
        }
        lock.lock()
        let wasFailed = rulesLoadError != nil
        rulesLoadError = nil
        lock.unlock()
        if wasFailed { enforcement.setRulesLoaded(true) }
        policyChanged()
    }

    public func setRules(_ list: [Rule], privileged: Bool = true) throws {
        mutation.lock(); defer { mutation.unlock() }
        for r in list { try DaemonCore.validate(r) }
        try saveRuleChange(peer: nil, privileged: privileged) { $0 = list }
    }

    /// `mustBeNew`: the caller was authorized for adding a rule (a strengthening change), so it must
    /// not replace an existing one that appeared meanwhile.
    public func upsert(rule: Rule, peer: IPCPeer, mustBeNew: Bool = false, privileged: Bool = true) throws {
        mutation.lock(); defer { mutation.unlock() }
        try DaemonCore.validate(rule)
        if case .category(let id) = rule.target, data.catalog.category(id) == nil {
            throw IPCError(.invalid, "unknown category \(id)")
        }
        if case .pathPrefix(let p) = rule.target {
            // The checks saveRuleChange makes, before the catalog changes for a rule that would be refused.
            try checkRulesWritable(privileged: privileged)
            let current = rules.rules
            if mustBeNew && current.contains(where: { $0.id == rule.id }) {
                throw IPCError(.notPermitted, "rule \(rule.id) already exists; changing it needs sudo or the app")
            }
            if !current.contains(where: { $0.id == rule.id }) && current.count >= DaemonCore.maxRules {
                throw IPCError(.invalid, "too many rules (max \(DaemonCore.maxRules))")
            }
            try ensureMonitored(prefix: p, peer: peer, privileged: privileged)
        }
        try saveRuleChange(peer: peer, privileged: privileged) { list in
            if let i = list.firstIndex(where: { $0.id == rule.id }) {
                if mustBeNew { throw IPCError(.notPermitted, "rule \(rule.id) already exists; changing it needs sudo or the app") }
                list[i] = rule
            } else {
                list.append(rule)
            }
        }
        Log.info("rule \(rule.id) saved by pid \(peer.pid.map(String.init) ?? "?")")
    }

    /// A path rule only works on monitored paths (the classifier, the eslogger prefilter and ES muting
    /// all derive from the catalog). Uncovered prefixes are added to the Custom category.
    private func ensureMonitored(prefix p: String, peer: IPCPeer, privileged: Bool) throws {
        let c = analyzer.classifier
        let expanded = c.normalizer.expand(p)
        guard !expanded.isEmpty else { throw IPCError(.invalid, "\(p): use an absolute path or ~/…") }
        let covered = expanded.allSatisfy { e in
            let n = c.normalizer.normalize(e)
            return c.classify(normalized: n) != nil || c.containingCategory(normalized: n) != nil || !c.categoriesBelow(normalized: n).isEmpty
        }
        if covered { return }
        // Editing the catalog is a privileged change. A console-user client (possibly an agent) may
        // only extend monitoring to its own files: inside a home or on an external volume, never
        // system paths (a deny rule there would block every user's processes once enforcement is on).
        if !privileged {
            let homes = c.normalizer.homeDirectories.map { h in PathNormalizer.fold(h.hasSuffix("/") ? h : h + "/") }
            let own = expanded.allSatisfy { e in
                let k = PathNormalizer.fold(c.normalizer.normalize(e))
                return homes.contains { k.hasPrefix($0) && k.count > $0.count } || k.hasPrefix("/volumes/")
            }
            guard own else {
                throw IPCError(.notPermitted, "\(p) is not monitored; adding it to the catalog needs sudo or the WhoRead app")
            }
        }
        var catalog = data.catalog
        guard let i = catalog.categories.firstIndex(where: { $0.kind == .custom }) else {
            throw IPCError(.invalid, "\(p) is not a monitored path; add it to the catalog first")
        }
        if !catalog.categories[i].paths.contains(p) { catalog.categories[i].paths.append(p) }
        catalog.categories[i].enabled = true
        try update(catalog: catalog, peer: peer)
        Log.info("added \(p) to the \(catalog.categories[i].id) category for a path rule")
    }

    public func deleteRule(id: String, peer: IPCPeer) throws {
        try saveRuleChange(peer: peer, privileged: true) { list in
            guard let i = list.firstIndex(where: { $0.id == id }) else { throw IPCError(.notFound, "no rule \(id)") }
            list.remove(at: i)
        }
        Log.info("rule \(id) deleted by pid \(peer.pid.map(String.init) ?? "?")")
    }

    // MARK: - Settings & catalog

    /// Applies settings in memory first (a kill switch must work even if the disk is full), then
    /// persists. `reenable`: an explicit "enforcement on", which also clears a latency trip.
    public func update(settings new: Settings, peer: IPCPeer, reenable: Bool = false) throws {
        mutation.lock(); defer { mutation.unlock() }
        let s = new.validated()
        lock.lock()
        let old = settings
        settings = s
        lock.unlock()
        baseline.learningDuration = s.learningDays * 86400
        coalescer.window = s.coalesceMinutes * 60
        analyzer.readdirEnabled = s.readdirEnabled
        latency.p99ThresholdMicros = s.latencyP99ThresholdMs * 1000
        if old.projectRoots != s.projectRoots || old.readdirEnabled != s.readdirEnabled {
            recompileClassifier()
        }
        // Compare with the live state, not the previous settings: a trip or a failed save may have left
        // them apart.
        let tripped = enforcement.latencyTripReason != nil
        if s.enforcementEnabled != enforcement.userEnabledSetting || (reenable && s.enforcementEnabled && tripped) {
            if s.enforcementEnabled {
                // LatencyMonitor keeps its own trip; without the reset it would trip again within a second.
                latency.reset()
                try? store.setValue(nil, forKey: DaemonCore.tripKey)
            }
            enforcement.setUserEnabled(s.enforcementEnabled)
            Log.info("enforcement switched \(s.enforcementEnabled ? "on" : "off") by pid \(peer.pid.map(String.init) ?? "?") uid \(peer.euid.map(String.init) ?? "?")")
        }
        if old.monitoringPaused != s.monitoringPaused {
            Log.info("monitoring \(s.monitoringPaused ? "paused" : "resumed") by pid \(peer.pid.map(String.init) ?? "?")")
        }
        do {
            try store.saveSettings(s)
        } catch {
            Log.error("settings applied but not saved: \(error)")
            throw IPCError(.internalError, "settings applied but not saved: \(error)")
        }
    }

    /// Read-modify-write of the settings under the mutation lock (two clients toggling different
    /// settings at once must not undo each other).
    public func mutateSettings(peer: IPCPeer, reenable: Bool = false, _ f: (inout Settings) -> Void) throws {
        mutation.lock(); defer { mutation.unlock() }
        var s = currentSettings
        f(&s)
        try update(settings: s, peer: peer, reenable: reenable)
    }

    /// A latency trip (deadline miss or p99) is kept across restarts by turning the setting off; the
    /// user's next "enforcement on" clears it.
    func persistTrip(_ reason: String) {
        mutation.lock(); defer { mutation.unlock() }
        // Queued from the observer: the user may have turned enforcement on again (which clears the
        // trip) before this ran. Persisting then would switch their explicit "on" back off.
        guard enforcement.latencyTripReason != nil else { return }
        lock.lock()
        settings.enforcementEnabled = false
        let s = settings
        lock.unlock()
        do { try store.saveSettings(s) } catch { Log.error("could not save the enforcement trip: \(error)") }
        try? store.setValue(Data(reason.utf8), forKey: DaemonCore.tripKey)
        // Already inactive (tripped), so this fires no observer; a later "on" is now a change.
        enforcement.setUserEnabled(false)
        Log.error("enforcement turned off until you turn it on again: \(reason)")
    }

    public func update(catalog: Catalog?, peer: IPCPeer) throws {
        mutation.lock(); defer { mutation.unlock() }
        let c = catalog.map { DaemonCore.stripResolvedOwners($0, reference: defaultCatalog) } ?? defaultCatalog
        let ids = c.categories.map(\.id)
        guard Set(ids).count == ids.count else { throw IPCError(.invalid, "duplicate category ids") }
        // A rule on a deleted category would silently stop protecting anything.
        let dangling = rules.rules.filter { r in
            if case .category(let id) = r.target { return r.enabled && c.category(id) == nil }
            return false
        }
        if !dangling.isEmpty {
            throw IPCError(.invalid, "rules use categories this catalog removes: "
                           + dangling.map { $0.name ?? $0.id }.joined(separator: ", ") + "; delete or change those rules first")
        }
        if !config.inMemoryStore {
            if catalog == nil {
                try? FileManager.default.removeItem(atPath: config.userCatalogPath)
                try? FileManager.default.removeItem(atPath: config.userCatalogBasePath)
            } else {
                try c.encoded().write(to: URL(fileURLWithPath: config.userCatalogPath), options: .atomic)
                chmod(config.userCatalogPath, 0o600)
                try defaultCatalog.encoded().write(to: URL(fileURLWithPath: config.userCatalogBasePath), options: .atomic)
                chmod(config.userCatalogBasePath, 0o600)
            }
        }
        let resolved = DaemonCore.resolveOwners(c, config: config)
        lock.lock()
        _data.catalog = c
        effectiveCatalog = resolved
        catalogGeneration += 1
        lock.unlock()
        recompileClassifier()
        Log.info("catalog \(catalog == nil ? "reset to defaults" : "updated") by pid \(peer.pid.map(String.init) ?? "?")")
    }

    public func recompileClassifier() {
        lock.lock()
        let catalog = effectiveCatalog
        let s = settings
        lock.unlock()
        let c = DaemonCore.makeClassifier(catalog: catalog, normalizer: normalizerBox.value, settings: s,
                                          resolveSymlinks: !config.inMemoryStore)
        install(classifier: c, readdir: s.readdirEnabled)
    }

    private func install(classifier c: PathClassifier, readdir: Bool) {
        analyzer.replace(classifier: c)
        source?.updateMonitoring(prefixes: c.mutePaths, ancestors: c.ancestors, readdir: readdir)
        policyChanged()
    }

    /// Homes come and go (new users, network homes) and symlinks inside monitored directories change
    /// (dotfile managers). Rebuilds the classifier only when the monitored set actually changed.
    func rediscover() {
        // Discovery reads the user database without any lock; the rebuild runs under the mutation
        // lock so it cannot install a classifier built from a catalog or settings that a concurrent
        // update(catalog:) / update(settings:) has just replaced.
        let found = config.homeDirectories == nil ? HomeDirectories.discover() : nil
        mutation.lock(); defer { mutation.unlock() }
        if let found {
            lock.lock()
            let changed = found != _homes
            if changed { _homes = found }
            lock.unlock()
            if changed {
                normalizerBox.value = PathNormalizer(homeDirectories: found)
                Log.info("home directories changed: \(found)")
            }
        }
        lock.lock()
        let catalog = effectiveCatalog
        let s = settings
        lock.unlock()
        let candidate = DaemonCore.makeClassifier(catalog: catalog, normalizer: normalizerBox.value, settings: s,
                                                  resolveSymlinks: !config.inMemoryStore)
        rediscoveryHook?()
        let current = analyzer.classifier
        if candidate.mutePaths != current.mutePaths || candidate.prefixes != current.prefixes || candidate.ancestors != current.ancestors {
            Log.info("monitored paths changed: \(current.mutePaths.count) → \(candidate.mutePaths.count) spellings")
            install(classifier: candidate, readdir: s.readdirEnabled)
        }
    }

    public func restartLearning(peer: IPCPeer) throws {
        let now = Date()
        baseline.resetLearned(at: now)
        try store.setDate(now, forKey: "learning_started_at")
        persistBaseline()
        Log.info("learning restarted by pid \(peer.pid.map(String.init) ?? "?")")
    }

    /// The catalog as the user edits it (owner identities resolved on this Mac are not included, so
    /// saving it back does not freeze them).
    public func catalogInfo() -> CatalogInfo {
        let c = analyzer.classifier
        let detected = c.detection { FileManager.default.fileExists(atPath: $0) }
        return CatalogInfo(catalog: data.catalog, detected: detected, prefixes: c.prefixes, homeDirectories: homes)
    }

    // MARK: - Maintenance & status

    public func persistBaseline() {
        let dirty = baseline.takeDirty()
        guard !dirty.isEmpty else { return }
        do {
            try store.saveBaseline(dirty)
        } catch {
            // Retried on the next pass ("always allow" approvals are touched only once).
            baseline.markDirty(dirty.map(\.0))
            Log.error("baseline save failed: \(error)")
        }
    }

    /// Saves consumed "allow once" uses, and drops exceptions that can never match again. Only writes
    /// when something changed: a used "allow once" used to keep the rule time-dependent and rewrite the
    /// whole rules table every 30 s for good.
    public func saveConsumableRules(now: Date = Date()) {
        mutation.lock(); defer { mutation.unlock() }
        let consumed = rules.takeConsumed()
        let pruned = rules.pruneDeadExceptions(at: now)
        guard consumed || pruned else { return }
        do {
            try store.saveRules(rules.rules)
        } catch {
            rules.markConsumed()
            Log.error("rules save failed: \(error)")
        }
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
        if now.timeIntervalSince(lastRediscovery) > config.rediscoveryInterval {
            lastRediscovery = now
            rediscover()
        }
        saveConsumableRules()
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
        lock.lock(); let rulesError = rulesLoadError; lock.unlock()
        // A trip that was persisted (or found at start) stays visible after the in-memory one is gone.
        let storedTrip = (try? store.value(forKey: DaemonCore.tripKey))?.flatMap { String(data: $0, encoding: .utf8) }
        return DaemonStatus(
            version: WhoReadVersion.string, pid: getpid(), startedAt: startedAt, mode: mode, source: source.kind,
            sourceRunning: stats.source.running, sourceError: stats.source.error, sourceHint: stats.source.hint,
            sourceCanEnforce: source.canEnforce, learning: learning, learningEndsAt: baseline.learningEndsAt(),
            monitoringPaused: s.monitoringPaused, enforcementEnabled: s.enforcementEnabled,
            enforcementActive: enforcement.isActive, enforcementInactiveReasons: enforcement.inactiveReasons,
            latencyTripReason: enforcement.latencyTripReason ?? (s.enforcementEnabled ? nil : storedTrip),
            killSwitchFilePresent: enforcement.killSwitchFilePresent,
            latency: latency.evaluateWithoutTripping(), parser: source.parserStats, counts: counts,
            unreadAlerts: counts.unreadAlerts, lastEventAt: stats.lastEventAt, eventsProcessed: stats.processed,
            writerDropped: writer.droppedCount, monitoredPrefixes: analyzer.classifier.prefixes.count,
            homeDirectories: homes, rulesLoadError: rulesError, sourceDroppedEvents: source.droppedEvents)
    }
}
