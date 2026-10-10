import Foundation
import WhoReadCore
import WhoReadIPC
import WhoReadStore

public struct DaemonConfiguration: Sendable {
    public var dataDirectory: String = WhoReadPaths.dataDirectory
    /// The only user who may be able to change the data directory and the kill switch's directory
    /// (and every directory on the way to them): the daemon's own user, so root for the system
    /// extension and the LaunchDaemon. Tests running as a user get theirs.
    public var dataDirectoryOwner: uid_t = geteuid()
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
    /// How long after an operation that may have added, replaced or removed a followed link (a create,
    /// rename or unlink in a monitored dotfile directory) the links are re-discovered (files-9). Also
    /// the shortest interval between two such runs.
    public var linkRediscoveryDelay: TimeInterval = 1.5
    /// The shortest interval between two full searches for links that lost file events cause (more
    /// link changes at once than are kept): each one reads up to LinkInventory.walkBudget entries.
    public var linkFullWalkInterval: TimeInterval = 30

    public init() {}

    public var resolvedKillSwitchPath: String {
        killSwitchPath ?? (dataDirectory as NSString).appendingPathComponent("disable-enforcement")
    }

    public var databasePath: String { (dataDirectory as NSString).appendingPathComponent("whoread.sqlite") }
    public var userCatalogPath: String { (dataDirectory as NSString).appendingPathComponent("catalog.json") }
    /// The default catalog the user's copy was made from, so upgrades can merge new defaults in.
    public var userCatalogBasePath: String { (dataDirectory as NSString).appendingPathComponent("catalog.base.json") }
    /// Exists while the native source has AUTH events subscribed. Found at start = the previous
    /// instance died while enforcing (the kernel kills a client that misses an AUTH deadline). It is
    /// reported (`DaemonStatus.uncleanStop`); enforcement stays as the user set it.
    public var authArmedMarkerPath: String { (dataDirectory as NSString).appendingPathComponent("auth-armed") }
    public var lockPath: String { (dataDirectory as NSString).appendingPathComponent("daemon.lock") }
}

/// Why a directory the daemon keeps its state in (or one on the way to it) may be changed by someone
/// other than the daemon's user, and what to do about it.
struct UntrustedDirectory: Error, CustomStringConvertible {
    let path: String
    let reason: String
    let fix: String
    var description: String { "\(path) \(reason)" }
}

/// Directory checks for the daemon's own state (macos-4). A directory is trusted when only its owner
/// (the daemon's user, root in production) and root can add, rename or remove its entries, and every
/// directory on the way to it is trusted in the same way, or is sticky like /private/tmp (others may
/// add entries there, but not move ours).
enum TrustedDirectory {
    /// Creates `dir` with `mode` if needed (missing parents with 0755, like `mkdir -p`), then checks it:
    /// a real directory (never a link), owned by `owner`, not writable by group or others, and reached
    /// only through trusted directories. An existing directory is never adopted by changing its owner
    /// or mode: it is refused. `confidential` (the data directory: every user's history): no ACL entry
    /// may grant anyone anything either, e.g. `allow read,file_inherit`, which new 0600 files inherit.
    static func ensure(_ path: String, owner: uid_t, mode: mode_t, confidential: Bool = false) throws {
        // A trailing slash would make open(2) follow a link at the last component despite O_NOFOLLOW.
        let dir = PathClassifier.stripTrailingSlash(path)
        let parent = TrustedDirectory.parent(of: dir)
        try createMissing(parent)
        if let problem = untrustedAncestor(of: dir, owner: owner) { throw problem }
        var created = false
        if mkdir(dir, mode) == 0 {
            created = true
        } else if errno != EEXIST {
            throw UntrustedDirectory(path: dir, reason: "cannot be created: \(String(cString: strerror(errno)))", fix: "")
        }
        // O_NOFOLLOW|O_DIRECTORY: the checks below are about this very directory, not a link's target.
        let fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else {
            let e = errno
            if e == ELOOP || e == ENOTDIR {
                throw UntrustedDirectory(path: dir, reason: "is a symbolic link or not a directory",
                                         fix: "remove '\(dir)' (sudo rm '\(dir)')")
            }
            throw UntrustedDirectory(path: dir, reason: "cannot be opened: \(String(cString: strerror(e)))", fix: "")
        }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0 else {
            throw UntrustedDirectory(path: dir, reason: "cannot be inspected: \(String(cString: strerror(errno)))", fix: "")
        }
        guard st.st_uid == owner else {
            throw UntrustedDirectory(path: dir, reason: "is owned by uid \(st.st_uid), not \(ownerName(owner))",
                                     fix: chownFix(dir, owner: owner))
        }
        // Created just now: the umask may have narrowed it (the CLI and the app read `mach-service` here).
        if created && (st.st_mode & 0o7777) != mode && fchmod(fd, mode) == 0 { st.st_mode = (st.st_mode & ~0o7777) | mode }
        guard st.st_mode & 0o022 == 0 else {
            throw UntrustedDirectory(path: dir, reason: "is writable by group or others (mode \(String(st.st_mode & 0o7777, radix: 8)))",
                                     fix: "check its contents, then sudo chmod go-w '\(dir)'")
        }
        // Mode bits do not show an ACL: `chmod +a "everyone allow add_file,delete_child"` on a 0755 directory.
        guard !SafeFile.aclAllows(fd: fd, changing: true) else {
            throw UntrustedDirectory(path: dir, reason: aclReason, fix: aclFix(dir))
        }
        guard !confidential || !SafeFile.aclAllows(fd: fd, changing: false) else {
            throw UntrustedDirectory(path: dir, reason: "has an access control list that lets others in", fix: aclFix(dir))
        }
    }

    /// The first directory on the way to `path` (`path` itself excluded) that someone other than `owner`
    /// or root could rename or replace entries in. Links on the way are followed (at most 32): the
    /// directory holding a link and every directory its target goes through are checked.
    static func untrustedAncestor(of path: String, owner: uid_t) -> UntrustedDirectory? {
        // Components still to walk, last one first (a link's target is pushed in front of the rest).
        var pending = Array(DaemonCore.absolutePath(TrustedDirectory.parent(of: path)).split(separator: "/").map(String.init).reversed())
        var current = "/"
        var links = 0
        var st = stat()
        guard lstat("/", &st) == 0 else { return UntrustedDirectory(path: "/", reason: "cannot be inspected", fix: "") }
        if let reason = ancestorProblem("/", st, owner: owner) { return UntrustedDirectory(path: "/", reason: reason, fix: "") }
        while let name = pending.popLast() {
            if name.isEmpty || name == "." { continue }
            if name == ".." {
                current = TrustedDirectory.parent(of: current)
                continue
            }
            let next = current == "/" ? "/" + name : current + "/" + name
            guard lstat(next, &st) == 0 else {
                return UntrustedDirectory(path: next, reason: "cannot be inspected: \(String(cString: strerror(errno)))", fix: "")
            }
            switch st.st_mode & S_IFMT {
            case S_IFLNK:
                links += 1
                guard links <= 32, let target = readLink(next) else {
                    return UntrustedDirectory(path: next, reason: "is a link that cannot be followed", fix: "")
                }
                if target.hasPrefix("/") { current = "/" }
                pending.append(contentsOf: target.split(separator: "/").map(String.init).reversed())
            case S_IFDIR:
                if let reason = ancestorProblem(next, st, owner: owner) {
                    return UntrustedDirectory(path: next, reason: reason, fix: reason == aclReason ? aclFix(next)
                                              : "make it writable by root only (sudo chown root '\(next)' && sudo chmod go-w '\(next)')")
                }
                current = next
            default:
                return UntrustedDirectory(path: next, reason: "is not a directory", fix: "")
            }
        }
        return nil
    }

    /// Why a directory on the way lets others than `owner` and root move its entries, or nil.
    static func ancestorProblem(_ path: String, _ st: stat, owner: uid_t) -> String? {
        if st.st_uid != 0 && st.st_uid != owner { return "is owned by uid \(st.st_uid), not \(ownerName(owner)) or root" }
        if st.st_mode & 0o022 != 0 && st.st_mode & S_ISVTX == 0 {
            return "is writable by group or others (mode \(String(st.st_mode & 0o7777, radix: 8)))"
        }
        // Also when sticky: an ACL's delete_child is not limited by the sticky bit.
        if SafeFile.aclAllows(path: path, changing: true) { return aclReason }
        return nil
    }

    static let aclReason = "has an access control list that lets others add, remove or rename its entries"

    private static func aclFix(_ dir: String) -> String {
        "check its contents and ls -led '\(dir)', then remove those entries (sudo chmod -N '\(dir)' removes the whole list)"
    }

    static func ownerName(_ owner: uid_t) -> String { owner == 0 ? "root" : "uid \(owner)" }

    /// Not `chown -R`: that would adopt whatever its owner left in it (rules, a catalog, links), which
    /// then looks like the daemon's own.
    private static func chownFix(_ dir: String, owner: uid_t) -> String {
        "move it aside (sudo mv '\(dir)' '\(dir).untrusted') so a fresh one is created; whoever made it may have left "
            + "rules, a catalog or links in it"
    }

    /// The first entry in `dir`, or in a directory below it (`defaults/` holds catalog defaults), that
    /// someone other than `owner` may have put there or may still change: a link (state files are
    /// opened by path, so a link would take them elsewhere), another user's entry, a file with more
    /// than one name, an entry others can write (mode or ACL), or one an ACL lets others read. `dir`
    /// itself must already be trusted. A directory that someone else controlled before an
    /// administrator fixed its owner or mode (`chmod go-w`, `chmod -N`) may still hold what they left
    /// (macos-4).
    static func untrustedEntry(in dir: String, owner: uid_t, maxEntries: Int = 4096) -> UntrustedDirectory? {
        var seen = 0
        func check(_ d: String, _ depth: Int) -> UntrustedDirectory? {
            guard let names = try? FileManager.default.contentsOfDirectory(atPath: d) else {
                return UntrustedDirectory(path: d, reason: "cannot be listed", fix: "")
            }
            for name in names.sorted() {
                seen += 1
                let p = d + "/" + name
                guard seen <= maxEntries, depth <= 4 else {
                    return UntrustedDirectory(path: dir, reason: "holds more (or deeper) entries than the daemon ever creates",
                                              fix: chownFix(dir, owner: owner))
                }
                var st = stat()
                guard lstat(p, &st) == 0 else { return UntrustedDirectory(path: p, reason: "cannot be inspected", fix: "") }
                let type = st.st_mode & S_IFMT
                let reason: String?
                if type == S_IFLNK {
                    reason = "is a symbolic link"
                } else if st.st_uid != owner {
                    reason = "is owned by uid \(st.st_uid), not \(ownerName(owner))"
                } else if type == S_IFREG && st.st_nlink != 1 {
                    reason = "has \(st.st_nlink) hard links"
                } else if st.st_mode & 0o022 != 0 {
                    reason = "is writable by group or others (mode \(String(st.st_mode & 0o7777, radix: 8)))"
                } else if SafeFile.aclAllows(path: p, changing: false) {
                    // Read too: the database and the catalog copy are 0600 for a reason.
                    reason = "has an access control list that lets others in"
                } else {
                    reason = nil
                }
                if let reason {
                    return UntrustedDirectory(path: p, reason: reason, fix: "check it and remove it, or "
                                              + "move the whole directory aside (sudo mv '\(dir)' '\(dir).untrusted')")
                }
                if type == S_IFDIR, let problem = check(p, depth + 1) { return problem }
            }
            return nil
        }
        return check(PathClassifier.stripTrailingSlash(dir), 1)
    }

    /// `mkdir -p` for the directories above the one being checked (the check then covers them).
    private static func createMissing(_ dir: String) throws {
        var st = stat()
        if stat(dir, &st) == 0 { return }
        let up = TrustedDirectory.parent(of: dir)
        if up != dir { try createMissing(up) }
        if mkdir(dir, 0o755) != 0 && errno != EEXIST {
            throw UntrustedDirectory(path: dir, reason: "cannot be created: \(String(cString: strerror(errno)))", fix: "")
        }
    }

    /// `dirname` for absolute or relative paths ("." for a bare name).
    static func parent(of path: String) -> String {
        let p = (path as NSString).deletingLastPathComponent
        return p.isEmpty ? "." : p
    }

    static func readLink(_ path: String) -> String? {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        let n = readlink(path, &buf, buf.count - 1)
        guard n > 0 else { return nil }
        buf[n] = 0
        return String(cString: buf)
    }
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
    /// Ask mode: held accesses and open questions.
    public let askBroker: AskBroker
    public private(set) var source: EventSource!
    public let startedAt = Date()

    /// Guards `settings`, `_data`, `effectiveCatalog`, `_homes` and the bookkeeping fields below.
    private let lock = NSLock()
    /// Serializes read-modify-write operations on rules, settings and the catalog (IPC threads run
    /// concurrently). Recursive: `apply` calls `setRules`, `upsert` may update the catalog.
    private let mutation = NSRecursiveLock()
    /// Enforcement observers run here, never on the thread that flipped the state (that can be the
    /// ES callback thread, which must not do IO). Internal: tests suspend it.
    let policyQueue = DispatchQueue(label: "whoread.policy")
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
    /// Where an operation may change a followed link, for the current classifier (files-9).
    private let linkWatch: LockedBox<LinkWatch>
    private let linkSink: LinkWatchingSink
    private let linkQueue = DispatchQueue(label: "whoread.links")
    /// Guarded by `lock`: a run is scheduled; the generation drops runs scheduled before a cancel.
    private var linkRediscoveryPending = false
    private var linkRediscoveryGeneration = 0
    private var pendingLinkChanges: [LinkChange] = []
    private var pendingLinkOverflow = false
    private var _linkRediscoveryRuns = 0
    /// The links the classifier follows in dotfile directories (files-9).
    let linkInventory: LinkInventory
    /// Guarded by `lock`: when links were last searched for in full, and whether a full search that
    /// lost events asked for is waiting for `linkFullWalkInterval` to pass.
    private var lastFullLinkWalk = Date()
    private var fullLinkWalkScheduled = false
    private var rulesLoadError: String?
    /// The previous instance stopped while enforcing; kept (and stored) until the next clean stop.
    private var uncleanStopNote: String?
    private var lastSlowWarning = Date.distantPast

    /// Older versions switched enforcement off on a latency trip and kept the reason here. There are
    /// no trips any more (ask mode); a leftover value is removed at start.
    static let legacyTripKey = "enforcement_trip_reason"
    static let uncleanStopKey = "unclean_stop"
    /// Marks rules made by "block from now on" (the app localizes their names).
    public static let blockFromNowOnTemplate = "block-from-now-on"
    /// Marks allow rules made from answers to ask-mode questions ("allow once", "always allow").
    public static let askAnswerTemplate = RuleTemplates.askAnswer
    /// How long an "allow once" answer's allow rule lives.
    static let allowOnceDuration: TimeInterval = 600
    /// Limits on what a (possibly unprivileged) client can store; rule evaluation is linear in them.
    static let maxRules = 512
    static let maxExceptions = 256
    static let maxNameBytes = 256

    /// Tests only: runs in `rediscover` between building the new classifier and installing it.
    var rediscoveryHook: (() -> Void)?

    /// What the event source delivers to: the pipeline, plus a look at operations that may add, replace
    /// or remove a link the classifier follows (files-9).
    public var eventSink: EventSink { linkSink }

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

        try DaemonCore.prepareDataDirectory(config)
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

        let settings = (try? store.settings()) ?? Settings()
        _homes = config.homeDirectories ?? HomeDirectories.discover()
        normalizerBox = LockedBox(PathNormalizer(homeDirectories: _homes))
        detector = AgentDetector(catalog: data.agents)
        let box = normalizerBox
        tree = ProcessTree(detector: detector, normalizePath: { box.value.normalize($0) })
        attributor = Attributor(agents: detector)

        effectiveCatalog = DaemonCore.resolveOwners(data.catalog, config: config)
        // The first build searches every dotfile directory for links.
        let links = LinkInventory()
        linkInventory = links
        if !config.inMemoryStore {
            links.walk(PathClassifier.linkWalkDirectories(catalog: effectiveCatalog, normalizer: normalizerBox.value,
                                                          projectRoots: settings.projectRoots))
        }
        let classifier = DaemonCore.makeClassifier(catalog: effectiveCatalog, normalizer: normalizerBox.value, settings: settings,
                                                   resolveSymlinks: !config.inMemoryStore, links: links)

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

        // The previous instance died while AUTH events were subscribed: the kernel killed it for a missed
        // deadline (kill mode), its watchdog exited it with the file handler stuck (fail-closed mode, see
        // NativeHandlerWatchdog), it crashed, or the Mac lost power. Enforcement is never switched off automatically
        // (ask mode): it stays as the user set it, and the stop is reported until the next clean stop.
        var unclean = (try? store.value(forKey: DaemonCore.uncleanStopKey))?.flatMap { String(data: $0, encoding: .utf8) }
        var marker = stat()
        if !config.inMemoryStore, lstat(config.authArmedMarkerPath, &marker) == 0 {
            // unlink, not removeItem: never a recursive delete, and a link goes, not its target.
            unlink(config.authArmedMarkerPath)
            let note = "the previous daemon stopped while enforcing (killed for a missed AUTH deadline, exited by its watchdog "
                + "with the event handler stuck, a crash or a power loss); "
                + "found at start \(ISO8601DateFormatter().string(from: now))"
            unclean = note
            try? store.setValue(Data(note.utf8), forKey: DaemonCore.uncleanStopKey)
            Log.error("\(note); enforcement stays \(settings.enforcementEnabled ? "on" : "off") as set")
        }
        uncleanStopNote = unclean
        if (try? store.value(forKey: DaemonCore.legacyTripKey)) != nil {
            try? store.setValue(nil, forKey: DaemonCore.legacyTripKey)
        }
        self.settings = settings

        // Statistics, and a log warning when p99 stays over the threshold for 3 consecutive checks.
        latency = LatencyMonitor(p99ThresholdMicros: settings.latencyP99ThresholdMs * 1000, breachesToWarn: 3)
        enforcement = EnforcementState(userEnabled: settings.enforcementEnabled, sourceCanEnforce: false)
        if !rulesOK { enforcement.setRulesLoaded(false) }
        writer = EventWriter(store: store)
        live = LiveBuffer()
        pipeline = EventPipeline(analyzer: analyzer, writer: writer, live: live)
        linkSink = LinkWatchingSink(pipeline: pipeline)
        linkWatch = LockedBox(LinkWatch(classifier))
        // Question ids never repeat across daemon instances: an answer meant for a question of the
        // previous instance (an old banner, a typed id) must not land on a new question.
        askBroker = AskBroker(firstID: Int64(Date().timeIntervalSince1970 * 1000))
        enforcer = Enforcer(analyzer: analyzer, state: enforcement, latency: latency, askBroker: askBroker)
        enforcer.trustApplePrograms = settings.trustApplePrograms
        analyzer.trustApplePrograms = settings.trustApplePrograms

        pipeline.isPaused = { [weak self] in self?.currentSettings.monitoringPaused ?? false }
        pipeline.onAlert = { [weak self] update in self?.alertRaised(update) }
        pipeline.onSourceState = { state in
            if let e = state.error { Log.warning("source: \(e)" + (state.hint.map { " — \($0)" } ?? "")) }
        }
        writer.onError = { Log.error("store write failed: \($0)") }
        linkSink.core = self

        source = try (makeSource ?? DaemonCore.defaultSource)(self)
        enforcement.setSourceCanEnforce(source.canEnforce)
        enforcement.onChange { [weak self] active in
            guard let self else { return }
            self.policyQueue.async {
                Log.info("enforcement is now \(active ? "ACTIVE" : "inactive") \(self.enforcement.inactiveReasons.map(\.rawValue))")
                // Checked again here: an "off" queued just before an "on" must not let through what
                // was held under the new "on".
                if !active && !self.enforcement.isActive {
                    // What enforcement off means for everything else: held accesses go through now
                    // instead of being denied when their budget runs out. Their questions are dropped
                    // (nothing can be held any more); the stored `ask` alerts remain answerable.
                    let released = self.askBroker.resolveMatching(.allow) { _ in true }
                    if !released.isEmpty { Log.info("enforcement off: \(released.count) open questions released") }
                }
                self.source.enforcementChanged(active: active)
                self.policyChanged()
            }
        }
    }

    static func absolutePath(_ p: String) -> String {
        if p.hasPrefix("/") { return p }
        return FileManager.default.currentDirectoryPath + "/" + p
    }

    /// Creates the data directory (0755: the CLI and the app read `mach-service` there) and the kill
    /// switch's directory if needed, and refuses to start unless only the daemon's user can change them
    /// (macos-4). They hold the rules database, the catalog copy, the auth-armed marker and the kill
    /// switch: whoever can write there can switch enforcement off or rewrite the rules. A directory made
    /// by someone else is refused, never adopted or moved aside (that would drop the user's rules).
    static func prepareDataDirectory(_ config: DaemonConfiguration) throws {
        guard !config.inMemoryStore else { return }
        let owner = config.dataDirectoryOwner
        let places = [("data directory", config.dataDirectory),
                      ("kill switch directory", TrustedDirectory.parent(of: config.resolvedKillSwitchPath))]
        for (what, dir) in places {
            do {
                try TrustedDirectory.ensure(dir, owner: owner, mode: 0o755, confidential: what == "data directory")
                // Its state files are opened by path: what is in it must be the daemon's own too.
                if what == "data directory", let problem = TrustedDirectory.untrustedEntry(in: dir, owner: owner) {
                    throw problem
                }
            } catch let problem as UntrustedDirectory {
                throw IPCError(.unavailable, "refusing to use the \(what) \(dir): \(problem). Only "
                               + "\(TrustedDirectory.ownerName(owner)) may be able to change it (it holds the rules, the "
                               + "kill switch and the auth-armed marker)" + (problem.fix.isEmpty ? "" : "; \(problem.fix)"))
            }
        }
    }

    static func defaultSource(_ core: DaemonCore) throws -> EventSource {
        // Every byte-distinct spelling: ES compares VFS paths, the eslogger prefilter compares bytes.
        let classifier = core.analyzer.classifier
        let prefixes = classifier.mutePaths
        switch core.config.source {
        case .eslogger:
            return EsloggerSource(executable: core.config.esloggerPath, prefixes: prefixes, ancestors: classifier.ancestors,
                                  readdir: core.currentSettings.readdirEnabled)
        case .replay:
            guard let path = core.config.replayPath else { throw IPCError(.invalid, "replay source needs a file") }
            return ReplaySource(path: path, realtime: core.config.replayRealtime, prefixes: prefixes, ancestors: classifier.ancestors)
        case .native:
            #if canImport(EndpointSecurity)
            return NativeESSource(core: core)
            #else
            throw IPCError(.unavailable, "the native Endpoint Security source needs macOS")
            #endif
        }
    }

    /// `links`: where the links in dotfile directories come from (searched there otherwise).
    static func makeClassifier(catalog: Catalog, normalizer: PathNormalizer, settings: Settings, resolveSymlinks: Bool,
                               links: LinkInventory? = nil) -> PathClassifier {
        let resolver: SymlinkResolver
        if !resolveSymlinks {
            resolver = NoSymlinkResolver()
        } else if let links {
            resolver = InventoryLinkResolver(links)
        } else {
            resolver = LinkFollowingResolver()
        }
        return PathClassifier(catalog: catalog, normalizer: normalizer, projectRoots: settings.projectRoots, symlinks: resolver)
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

    // MARK: - Ask mode (docs/ASK_MODE.md)

    /// Questions waiting for an answer. Marks an answering client present.
    public func asks(peer: IPCPeer) -> [AskRequest] {
        askBroker.noteAnsweringClient()
        // Bounded reply: questions holding an access first (earliest deadline on top), then the oldest.
        // A flood of distinct questions must not make the reply huge; the rest stay answerable as alerts.
        let all = askBroker.pending()
        guard all.count > DaemonCore.maxListedAsks else { return all }
        let holding = all.filter { $0.holding > 0 }.sorted { ($0.answerBy ?? .distantFuture) < ($1.answerBy ?? .distantFuture) }
        let rest = all.filter { $0.holding == 0 }
        return Array((holding + rest).prefix(DaemonCore.maxListedAsks))
    }

    static let maxListedAsks = 200

    /// A settings update whose only change is turning "trust Apple programs" off (strengthening).
    static func onlyTurnsOffAppleTrust(_ new: Settings, current: Settings) -> Bool {
        guard current.trustApplePrograms, !new.trustApplePrograms else { return false }
        var c = current
        c.trustApplePrograms = false
        // Enforcement and pause are taken from the current settings by updateSettings anyway.
        var n = new
        n.enforcementEnabled = c.enforcementEnabled
        n.monitoringPaused = c.monitoringPaused
        return n == c
    }

    /// Answers a question; allowing needs `privileged`. Saves the answer as a rule (or setting) and
    /// releases every held access with that key.
    public func answerAsk(id: Int64, action: AlertAction, peer: IPCPeer, privileged: Bool) throws {
        mutation.lock(); defer { mutation.unlock() }
        guard let request = askBroker.request(id: id) else { throw IPCError(.notFound, "no question #\(id) (answered or expired)") }
        let scope = AnswerScope(request)
        if action == .keepBlocking {
            // "Deny": this question only; nothing is saved.
            askBroker.resolve(id: id, answer: .deny)
        } else {
            try answer(scope, action: action, peer: peer, privileged: privileged)
        }
        // An unprivileged answer (deny, block from now on) leaves the alerts open, as `apply` does.
        if privileged { try resolveAskAlerts(answering: scope, action: action) }
        Log.info("question #\(id): \(action.rawValue) by pid \(peer.pid.map(String.init) ?? "?") (uid \(peer.euid.map(String.init) ?? "?"))")
    }

    /// What an answer applies to: from a question, or from an alert (Alerts tab, monitor-only mode).
    struct AnswerScope {
        var key: AskKey
        var responsible: ResponsibleEntity
        var appleProgram: Bool

        init(_ r: AskRequest) {
            key = r.key
            responsible = r.responsible
            appleProgram = r.appleProgram
        }

        init(_ a: Alert) {
            key = AskKey(responsibleKey: a.responsible.key, categoryID: a.categoryID, access: a.accesses,
                         chainAgents: Array(Set(a.chain.compactMap(\.agentID))))
            responsible = a.responsible
            appleProgram = a.appleProgram
        }

        /// Unsigned binaries are pinned to their cdhash (brief §5: path + cdhash).
        var cdhashPin: String? { responsible.kind == .binary && responsible.teamID == nil ? responsible.cdhash : nil }

        var ruleAccess: RuleAccess { key.access == .read ? .read : (key.access == .write ? .write : .any) }

        /// An allow rule saved from this answer covers `other` (same subject and pins, category, an
        /// access it includes, only agents it names: Rule.chainAgents).
        func allowCovers(_ other: AnswerScope) -> Bool {
            other.key.responsibleKey == key.responsibleKey && other.key.categoryID == key.categoryID
                && !other.key.access.isEmpty && other.key.access.isSubset(of: key.access)
                && Set(other.key.chainAgents).isSubset(of: Set(key.chainAgents))
                && (responsible.teamID == nil || other.responsible.teamID == responsible.teamID)
                && (cdhashPin == nil || other.responsible.cdhash?.lowercased() == cdhashPin?.lowercased())
        }

        /// Questions and alerts the answer `action` settles.
        func settles(_ other: AnswerScope, action: AlertAction) -> Bool {
            switch action {
            case .allowOnce, .alwaysAllow, .keepBlocking: return allowCovers(other)
            // The deny rule's subject: the app (or agent) on that category, whatever the access or chain.
            case .blockFromNowOn: return other.key.responsibleKey == key.responsibleKey && other.key.categoryID == key.categoryID
            case .trustApplePrograms: return other.appleProgram && other.key.chainAgents.isEmpty
            case .ignore: return false
            }
        }
    }

    /// The answers table of docs/ASK_MODE.md: saves the answer (rule or setting), then releases the
    /// held accesses of every open question it settles. Allowing needs `privileged`.
    private func answer(_ scope: AnswerScope, action: AlertAction, peer: IPCPeer, privileged: Bool, now: Date = Date()) throws {
        mutation.lock(); defer { mutation.unlock() }
        switch action {
        case .allowOnce, .alwaysAllow, .trustApplePrograms:
            guard privileged else {
                throw IPCError(.notPermitted, "allowing weakens protection: run it with sudo, or use the WhoRead app")
            }
        case .keepBlocking, .blockFromNowOn, .ignore:
            break
        }
        switch action {
        case .allowOnce, .alwaysAllow:
            do {
                try addAnswerRule(scope, once: action == .allowOnce, peer: peer, now: now)
            } catch let e as IPCError where e.code == .internalError {
                // Applied in memory but not saved (disk full): the rule already decides the next access,
                // so release the held ones too instead of letting them time out; then report it.
                askBroker.resolveMatching(.allow) { scope.settles(AnswerScope($0), action: action) }
                throw e
            }
            askBroker.resolveMatching(.allow) { scope.settles(AnswerScope($0), action: action) }
        case .trustApplePrograms:
            guard scope.appleProgram && scope.key.chainAgents.isEmpty else {
                throw IPCError(.invalid, "\"allow all Apple programs\" applies to Apple programs in system locations with no AI agent in their chain")
            }
            try mutateSettings(peer: peer) { $0.trustApplePrograms = true }
            releaseTrustedApple()
        case .keepBlocking:
            askBroker.resolveMatching(.deny) { scope.settles(AnswerScope($0), action: action) }
        case .blockFromNowOn:
            try addBlockRule(scope, peer: peer, privileged: privileged, now: now)
            askBroker.resolveMatching(.deny) { scope.settles(AnswerScope($0), action: action) }
        case .ignore:
            throw IPCError(.invalid, "\"ignore\" is not an answer to a question")
        }
    }

    /// The allow rule for "allow once" (10 minutes) or "always allow": the app or agent, the category,
    /// the access, scoped to the AI agents that were in the chain.
    private func addAnswerRule(_ scope: AnswerScope, once: Bool, peer: IPCPeer, now: Date) throws {
        // An alert about metadata-only opens (neither read nor write): nothing to allow, and the rule
        // would be `.any` (read and write).
        guard !scope.key.access.isEmpty else { return }
        let categoryID = scope.key.categoryID
        guard data.catalog.category(categoryID) != nil else {
            throw IPCError(.invalid, "category \(categoryID) is no longer in the catalog")
        }
        let r = scope.responsible
        let subject = RuleSubject.responsible(key: scope.key.responsibleKey, teamID: r.teamID, cdhash: scope.cdhashPin)
        let categoryName = analyzer.classifier.spec(categoryID)?.name.en ?? categoryID
        let verb = scope.ruleAccess == .read ? "read" : (scope.ruleAccess == .write ? "write" : "use")
        let rule = Rule(
            name: DaemonCore.truncated("Allow \(r.displayName) to \(verb) \(categoryName)\(once ? " (10 minutes)" : "")",
                                       maxBytes: DaemonCore.maxNameBytes),
            enabled: true, target: .category(categoryID), subject: subject, access: scope.ruleAccess, action: .allow,
            expiresAt: once ? now.addingTimeInterval(DaemonCore.allowOnceDuration) : nil, createdAt: now,
            template: DaemonCore.askAnswerTemplate, chainAgents: scope.key.chainAgents)
        try DaemonCore.validate(rule)
        func sameScope(_ x: Rule) -> Bool {
            x.template == DaemonCore.askAnswerTemplate && x.action == .allow && x.target == rule.target && x.subject == rule.subject
                && x.access == rule.access && x.chainAgents == rule.chainAgents
        }
        try saveRuleChange(peer: peer, privileged: true) { list in
            // Answers expire: drop the dead ones, and the earlier "allow once" this one replaces.
            list.removeAll { $0.template == DaemonCore.askAnswerTemplate && ($0.expiresAt.map { $0 <= now } ?? false) }
            if once {
                list.removeAll { sameScope($0) && $0.expiresAt != nil }
            } else if list.contains(where: { sameScope($0) && $0.expiresAt == nil && $0.enabled }) {
                return
            }
            guard list.count < DaemonCore.maxRules else { throw IPCError(.invalid, "too many rules") }
            list.append(rule)
        }
    }

    /// "Block from now on": an enforced deny rule for the app (or agent) on the category. Owners keep
    /// working: blocking the terminal an alert was charged to must not break ssh/git.
    private func addBlockRule(_ scope: AnswerScope, peer: IPCPeer, privileged: Bool, now: Date) throws {
        let categoryID = scope.key.categoryID
        // As upsert(rule:) checks: a rule on a removed category would make every later catalog edit fail.
        guard data.catalog.category(categoryID) != nil else {
            throw IPCError(.invalid, "category \(categoryID) is no longer in the catalog")
        }
        let r = scope.responsible
        let categoryName = analyzer.classifier.spec(categoryID)?.name.en ?? categoryID
        let blockSubject = RuleSubject.responsible(key: scope.key.responsibleKey, teamID: r.teamID, cdhash: scope.cdhashPin,
                                                   exceptOwners: true)
        let exists = rules.rules.contains {
            $0.action == .deny && $0.target == .category(categoryID) && $0.subject == blockSubject && $0.enabled
        }
        guard !exists else { return }
        let rule = Rule(
            name: DaemonCore.truncated("Block \(r.displayName) from \(categoryName)", maxBytes: DaemonCore.maxNameBytes),
            enabled: true, enforce: true,
            target: .category(categoryID), subject: blockSubject, access: .any, action: .deny,
            includePlatformBinaries: true, createdAt: now, template: DaemonCore.blockFromNowOnTemplate)
        // A rule that validate() refuses could not be edited later (only deleted).
        try DaemonCore.validate(rule)
        try saveRuleChange(peer: peer, privileged: privileged) { list in
            guard list.count < DaemonCore.maxRules else { throw IPCError(.invalid, "too many rules") }
            list.append(rule)
        }
        if !enforcement.isActive {
            Log.info("rule \(rule.id) added; it blocks only while enforcement is on (currently off)")
        }
    }

    /// Marks the open `ask` alerts an answer settles as resolved (privileged answers only).
    private func resolveAskAlerts(answering scope: AnswerScope, action: AlertAction, except: Int64? = nil) throws {
        writer.flush()
        let open = try store.alerts(AlertQuery(statuses: [.unread, .read], limit: 10_000))
        let settled = open.filter { $0.kind == .ask && $0.id != except && scope.settles(AnswerScope($0), action: action) }
        guard !settled.isEmpty else { return }
        let updated = settled.map { a -> Alert in
            var a = a
            a.status = .resolved
            a.resolution = action
            return a
        }
        try store.upsert(updated)
        writer.enqueue(alerts: updated)
        for a in updated { coalescer.updateStatus(alertID: a.id, status: .resolved, resolution: action) }
    }

    /// Releases the held accesses "trust Apple programs" now allows (the setting was just turned on).
    private func releaseTrustedApple() {
        let released = askBroker.resolveMatching(.allow) { $0.appleProgram && $0.key.chainAgents.isEmpty }
        if !released.isEmpty { Log.info("trust Apple programs: \(released.count) open questions allowed") }
    }

    /// The daemon stopped cleanly: an earlier unclean stop is no longer reported.
    public func noteCleanStop() {
        lock.lock(); uncleanStopNote = nil; lock.unlock()
        try? store.setValue(nil, forKey: DaemonCore.uncleanStopKey)
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
            try SafeFile.replace(config.userCatalogPath, with: catalog.encoded(), mode: 0o600,
                                 trustedDirectoryOwner: config.dataDirectoryOwner)
            try SafeFile.replace(config.userCatalogBasePath, with: base.encoded(), mode: 0o600,
                                 trustedDirectoryOwner: config.dataDirectoryOwner)
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
    /// Allowing on an alert saves the same allow rule an answer to a question does (otherwise, with
    /// enforcement on, the next access would be asked again); an `ask` alert is answered like its
    /// question.
    public func apply(action: AlertAction, toAlert id: Int64, peer: IPCPeer, privileged: Bool = true) throws {
        mutation.lock(); defer { mutation.unlock() }
        writer.flush()
        guard var alert = try store.alert(id: id) else { throw IPCError(.notFound, "no alert #\(id)") }
        let now = Date()
        let scope = AnswerScope(alert)
        let r = alert.responsible
        let subject = RuleSubject.responsible(key: r.key, teamID: r.teamID, cdhash: scope.cdhashPin)
        let chainAgents = scope.key.chainAgents
        let access = scope.ruleAccess
        // The action answered as a question would be (rule, setting, held accesses released or denied).
        var answered = true
        switch action {
        case .allowOnce:
            guard alert.kind == .blocked || alert.kind == .ask else {
                throw IPCError(.invalid, "\"allow once\" applies to blocked accesses and questions only")
            }
            // A block without a rule is an unanswered question: the allow rule alone lets it through.
            if alert.kind == .blocked, let ruleID = alert.ruleID {
                guard privileged else { throw IPCError(.notPermitted, "allowing weakens protection: run it with sudo, or use the WhoRead app") }
                // firstPath is the access that made the alert "blocked" (the coalescer moves it on escalation).
                try addException(toRule: ruleID, RuleException(
                    subject: subject, pathPrefix: alert.firstPath, categoryID: alert.categoryID, access: access,
                    chainAgents: chainAgents, expiresAt: now.addingTimeInterval(600), remainingUses: 1, createdAt: now))
                // A rule's block: the path-scoped, one-use exception is the whole answer. A category-wide
                // 10-minute allow rule would also let through files the deny rule does not cover, which
                // would otherwise be asked. (A rule denial never has an open question to release.)
                answered = false
            } else {
                try answer(scope, action: action, peer: peer, privileged: privileged, now: now)
            }
        case .alwaysAllow:
            guard privileged else { throw IPCError(.notPermitted, "allowing weakens protection: run it with sudo, or use the WhoRead app") }
            if let ruleID = alert.ruleID, alert.kind == .blocked || alert.kind == .wouldBlock {
                try addException(toRule: ruleID, RuleException(subject: subject, categoryID: alert.categoryID, access: access,
                                                               chainAgents: chainAgents, createdAt: now))
            }
            try answer(scope, action: action, peer: peer, privileged: privileged, now: now)
            baseline.approve(responsibleKey: r.key, categoryID: alert.categoryID, at: now)
            persistBaseline()
        case .blockFromNowOn, .trustApplePrograms:
            try answer(scope, action: action, peer: peer, privileged: privileged, now: now)
        case .keepBlocking:
            // On a question: "deny" (the held accesses it covers are denied now; nothing is saved).
            answered = alert.kind == .ask
            if answered { try answer(scope, action: action, peer: peer, privileged: privileged, now: now) }
        case .ignore:
            answered = false
        }
        if privileged {
            alert.status = .resolved
            alert.resolution = action
            try store.upsert([alert])
            // Replaces a stale snapshot the writer may have re-queued after a failed flush.
            writer.enqueue(alerts: [alert])
            coalescer.updateStatus(alertID: id, status: .resolved, resolution: action)
            if answered { try resolveAskAlerts(answering: scope, action: action, except: id) }
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
    /// unprivileged client must not be able to slow it down.
    static func validate(_ r: Rule) throws {
        func check(_ ok: Bool, _ what: String) throws { if !ok { throw IPCError(.invalid, "rule \(what) is too long or invalid") } }
        let idChars = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        try check(!r.id.isEmpty && r.id.utf8.count <= 128 && r.id.unicodeScalars.allSatisfy(idChars.contains), "id")
        try check((r.name?.utf8.count ?? 0) <= maxNameBytes, "name")
        if case .pathPrefix(let p) = r.target { try check(!p.isEmpty && p.utf8.count <= 1024 && isCleanPath(p), "path") }
        // Dates are stored and sent as RFC 3339 with a four-digit year: one outside 1970-9999 could not
        // be read back (every rules reply, and the rules at the next start, would fail to decode).
        func okDate(_ d: Date?) -> Bool {
            guard let t = d?.timeIntervalSince1970 else { return true }
            return t >= 0 && t < 253_402_300_800
        }
        try check(okDate(r.createdAt) && okDate(r.expiresAt), "date")
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
        try check((r.chainAgents?.count ?? 0) <= 32 && (r.chainAgents ?? []).allSatisfy { $0.utf8.count <= 64 }, "chain agents")
        try check(r.exceptions.count <= maxExceptions, "exception list")
        for e in r.exceptions {
            try checkSubject(e.subject)
            // NUL only: exception paths never reach a C API, and the event paths "allow once" copies can
            // hold other control characters (Finder's "Icon\r").
            try check((e.pathPrefix?.utf8.count ?? 0) <= 1024 && !(e.pathPrefix ?? "").unicodeScalars.contains("\u{0}")
                      && (e.categoryID?.utf8.count ?? 0) <= 128, "exception")
            try check((e.chainAgents?.count ?? 0) <= 32 && (e.chainAgents ?? []).allSatisfy { $0.utf8.count <= 64 }, "exception agents")
            try check(okDate(e.createdAt) && okDate(e.expiresAt), "exception date")
        }
    }

    /// No NUL or other control characters: C APIs (realpath, es_mute_path) cut a path at a NUL, so
    /// `~/\0x` would select the whole home.
    static func isCleanPath(_ p: String) -> Bool {
        !p.unicodeScalars.contains { $0.value < 0x20 || (0x7F...0x9F).contains($0.value) }
    }

    /// Read-modify-write of the rule list: applied atomically in the engine (a consumed "allow once"
    /// is never reverted by a stale copy), then persisted.
    private func saveRuleChange(peer: IPCPeer?, privileged: Bool, replacing: Bool = false,
                                _ f: (inout [Rule]) throws -> Void) throws {
        mutation.lock(); defer { mutation.unlock() }
        try checkRulesWritable(privileged: privileged, replacing: replacing)
        let list = try rules.mutate { list in
            try f(&list)
            let ids = list.map(\.id)
            guard Set(ids).count == ids.count else { throw IPCError(.invalid, "duplicate rule ids") }
            guard list.count <= DaemonCore.maxRules else { throw IPCError(.invalid, "too many rules (max \(DaemonCore.maxRules))") }
        }
        try persistRules(list)
    }

    /// While stored rules could not be read, the rules in memory are an empty stand-in: a single-rule
    /// change would rewrite the table from it. Only an explicit replacement of the whole list, by root
    /// or the app, may overwrite them (the store backs the old rows up).
    private func checkRulesWritable(privileged: Bool, replacing: Bool = false) throws {
        lock.lock(); let failed = rulesLoadError; lock.unlock()
        guard let failed else { return }
        if !privileged {
            throw IPCError(.notPermitted, "the stored rules could not be loaded; only root or the WhoRead app may replace them")
        }
        if !replacing {
            // Not .unavailable: clients read that as "daemon unreachable".
            throw IPCError(.invalid, "the stored rules could not be loaded (\(failed)); a change to one rule would delete "
                           + "them all. Replace the whole list instead (sudo whoread rules replace); the old rules are kept "
                           + "in the database's rules_backup table")
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
        if wasFailed {
            Log.warning("the rules that could not be loaded were replaced; unreadable rows are kept in the rules_backup table")
            enforcement.setRulesLoaded(true)
        }
        policyChanged()
    }

    /// Replaces the whole list: the only rule change accepted while the stored rules cannot be read.
    public func setRules(_ list: [Rule], privileged: Bool = true) throws {
        mutation.lock(); defer { mutation.unlock() }
        for r in list { try DaemonCore.validate(r) }
        try saveRuleChange(peer: nil, privileged: privileged, replacing: true) { $0 = list }
    }

    /// `setRules` for clients: with upsert(rule:)'s checks (known categories, path rules monitored).
    public func replaceRules(_ list: [Rule], peer: IPCPeer, privileged: Bool) throws {
        mutation.lock(); defer { mutation.unlock() }
        for r in list {
            try DaemonCore.validate(r)
            if case .category(let id) = r.target, data.catalog.category(id) == nil {
                throw IPCError(.invalid, "unknown category \(id)")
            }
        }
        // The checks saveRuleChange makes, before the catalog changes for a list that would be refused.
        try checkRulesWritable(privileged: privileged, replacing: true)
        let ids = list.map(\.id)
        guard Set(ids).count == ids.count else { throw IPCError(.invalid, "duplicate rule ids") }
        guard list.count <= DaemonCore.maxRules else { throw IPCError(.invalid, "too many rules (max \(DaemonCore.maxRules))") }
        for r in list {
            if case .pathPrefix(let p) = r.target { try ensureMonitored(prefix: p, peer: peer, privileged: privileged) }
        }
        try saveRuleChange(peer: peer, privileged: privileged, replacing: true) { $0 = list }
        Log.info("rules replaced (\(list.count)) by pid \(peer.pid.map(String.init) ?? "?") uid \(peer.euid.map(String.init) ?? "?")")
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
                // A client edits a copy it read earlier: uses consumed since then must stay consumed
                // ("allow once" never comes back through a stale full copy).
                list[i] = DaemonCore.keepingConsumedUses(rule, current: list[i])
            } else {
                list.append(rule)
            }
        }
        Log.info("rule \(rule.id) saved by pid \(peer.pid.map(String.init) ?? "?") uid \(peer.euid.map(String.init) ?? "?")")
    }

    /// A path rule only works on monitored paths (the classifier, the eslogger prefilter and ES muting
    /// all derive from the catalog). Uncovered prefixes are added to the Custom category.
    private func ensureMonitored(prefix p: String, peer: IPCPeer, privileged: Bool) throws {
        let c = analyzer.classifier
        let expanded = c.normalizer.expand(p)
        guard !expanded.isEmpty else { throw IPCError(.invalid, "\(p): use an absolute path or ~/…") }
        if DaemonCore.isCovered(expanded, by: c) { return }
        // Editing the catalog is a privileged change. A console-user client (possibly an agent) may
        // only extend monitoring to its own files: inside a home or on an external volume, never
        // system paths (a deny rule there would block every user's processes once enforcement is on).
        // Checked on the spelling and on what it resolves to on disk, as the classifier follows links:
        // `~/link -> /usr/lib` and `/Volumes/Macintosh HD/usr/lib` are system paths.
        if !privileged {
            let resolver = RealpathSymlinkResolver()
            let homeDirs = c.normalizer.homeDirectories
            let homes = (homeDirs + homeDirs.compactMap(resolver.resolve)).map { h in PathNormalizer.fold(h.hasSuffix("/") ? h : h + "/") }
            func isOwn(_ path: String) -> Bool {
                let k = PathNormalizer.fold(c.normalizer.normalize(path))
                return homes.contains { k.hasPrefix($0) && k.count > $0.count } || k.hasPrefix("/volumes/")
            }
            let own = expanded.allSatisfy { e in
                guard isOwn(e), let resolved = DaemonCore.resolveExisting(e, resolver: resolver) else { return false }
                return isOwn(resolved)
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

    /// Every expansion of a path rule's prefix is monitored by `c` (at, above or below it).
    static func isCovered(_ expanded: [String], by c: PathClassifier) -> Bool {
        !expanded.isEmpty && expanded.allSatisfy { e in
            let n = c.normalizer.normalize(e)
            return c.classify(normalized: n) != nil || c.containingCategory(normalized: n) != nil || !c.categoriesBelow(normalized: n).isEmpty
        }
    }

    /// realpath(3) of the deepest existing ancestor of `path`, plus the components below it that do
    /// not exist yet. nil when an existing component cannot be resolved (a dangling or looping link).
    static func resolveExisting(_ path: String, resolver: SymlinkResolver) -> String? {
        var head = PathNormalizer.components(path)
        var missing: [String] = []
        var st = stat()
        while !head.isEmpty && lstat("/" + head.joined(separator: "/"), &st) != 0 {
            missing.insert(head.removeLast(), at: 0)
        }
        guard let resolved = resolver.resolve("/" + head.joined(separator: "/")) else { return nil }
        return missing.isEmpty ? resolved : ([resolved == "/" ? "" : resolved] + missing).joined(separator: "/")
    }

    /// `s` cut on a character boundary to at most `maxBytes` UTF-8 bytes, marked with "…".
    static func truncated(_ s: String, maxBytes: Int) -> String {
        guard s.utf8.count > maxBytes else { return s }
        var out = ""
        var bytes = 0
        for ch in s {
            bytes += ch.utf8.count
            if bytes > maxBytes - 3 { break }
            out.append(ch)
        }
        return out + "…"
    }

    public func deleteRule(id: String, peer: IPCPeer) throws {
        try saveRuleChange(peer: peer, privileged: true) { list in
            guard let i = list.firstIndex(where: { $0.id == id }) else { throw IPCError(.notFound, "no rule \(id)") }
            list.remove(at: i)
        }
        Log.info("rule \(id) deleted by pid \(peer.pid.map(String.init) ?? "?") uid \(peer.euid.map(String.init) ?? "?")")
    }

    // MARK: - Settings & catalog

    /// Applies settings in memory first (a kill switch must work even if the disk is full), then
    /// persists. `reenable` (an explicit "enforcement on") is kept for callers; there are no latency
    /// trips to clear any more.
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
        enforcer.trustApplePrograms = s.trustApplePrograms
        analyzer.trustApplePrograms = s.trustApplePrograms
        if s.trustApplePrograms && !old.trustApplePrograms { releaseTrustedApple() }
        if old.projectRoots != s.projectRoots || old.readdirEnabled != s.readdirEnabled {
            recompileClassifier()
        }
        // Compare with the live state, not the previous settings: a failed save may have left them apart.
        if s.enforcementEnabled != enforcement.userEnabledSetting {
            // A fresh latency window for the new enforcement period.
            if s.enforcementEnabled { latency.reset() }
            enforcement.setUserEnabled(s.enforcementEnabled)
            Log.info("enforcement switched \(s.enforcementEnabled ? "on" : "off") by pid \(peer.pid.map(String.init) ?? "?") uid \(peer.euid.map(String.init) ?? "?")")
        }
        if old.monitoringPaused != s.monitoringPaused {
            Log.info("monitoring \(s.monitoringPaused ? "paused" : "resumed") by pid \(peer.pid.map(String.init) ?? "?") uid \(peer.euid.map(String.init) ?? "?")")
        }
        let changed = Mirror(reflecting: s).children.compactMap { child -> String? in
            guard let label = child.label, label != "enforcementEnabled", label != "monitoringPaused",
                  let before = Mirror(reflecting: old).children.first(where: { $0.label == label }) else { return nil }
            return "\(before.value)" == "\(child.value)" ? nil : label
        }
        if !changed.isEmpty {
            Log.info("settings changed (\(changed.joined(separator: ", "))) by pid \(peer.pid.map(String.init) ?? "?") uid \(peer.euid.map(String.init) ?? "?")")
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

    public func update(catalog: Catalog?, peer: IPCPeer) throws {
        mutation.lock(); defer { mutation.unlock() }
        let c = catalog.map { DaemonCore.stripResolvedOwners($0, reference: defaultCatalog) } ?? defaultCatalog
        let ids = c.categories.map(\.id)
        guard Set(ids).count == ids.count else { throw IPCError(.invalid, "duplicate category ids") }
        for p in c.categories.flatMap(\.paths) where !DaemonCore.isCleanPath(p) {
            throw IPCError(.invalid, "catalog path \(p.debugDescription) contains control characters")
        }
        // A whole disk, a home or a folder holding homes would make every file there "sensitive" (and,
        // with an agent rule, blocked). Checked for paths this edit adds, however they are spelled.
        let existing = Set(data.catalog.categories.flatMap(\.paths))
        for category in c.categories where category.kind != .projectRoots {
            for p in category.paths where !existing.contains(p) {
                if let reason = tooBroad(p) { throw IPCError(.invalid, "catalog path \(p) is \(reason)") }
            }
        }
        // A rule on a deleted category would silently stop protecting anything.
        let dangling = rules.rules.filter { r in
            if case .category(let id) = r.target { return r.enabled && c.category(id) == nil }
            return false
        }
        if !dangling.isEmpty {
            throw IPCError(.invalid, "rules use categories this catalog removes: "
                           + dangling.map { $0.name ?? $0.id }.joined(separator: ", ") + "; delete or change those rules first")
        }
        // So would a path rule whose prefix this catalog stops monitoring (a removed Custom path, a
        // disabled category, `catalog reset`). Rules that were not covered before do not block edits.
        let resolved = DaemonCore.resolveOwners(c, config: config)
        let s = currentSettings
        let candidate = DaemonCore.makeClassifier(catalog: resolved, normalizer: normalizerBox.value, settings: s,
                                                  resolveSymlinks: !config.inMemoryStore, links: linkInventory)
        let current = analyzer.classifier
        let orphaned = rules.rules.filter { r in
            guard r.enabled, case .pathPrefix(let p) = r.target else { return false }
            return DaemonCore.isCovered(current.normalizer.expand(p), by: current)
                && !DaemonCore.isCovered(candidate.normalizer.expand(p), by: candidate)
        }
        if !orphaned.isEmpty {
            throw IPCError(.invalid, "path rules would no longer be monitored with this catalog: "
                           + orphaned.map { $0.name ?? $0.id }.joined(separator: ", ") + "; delete or change those rules first")
        }
        if !config.inMemoryStore {
            if catalog == nil {
                try? FileManager.default.removeItem(atPath: config.userCatalogPath)
                try? FileManager.default.removeItem(atPath: config.userCatalogBasePath)
            } else {
                try SafeFile.replace(config.userCatalogPath, with: c.encoded(), mode: 0o600,
                                     trustedDirectoryOwner: config.dataDirectoryOwner)
                try SafeFile.replace(config.userCatalogBasePath, with: defaultCatalog.encoded(), mode: 0o600,
                                     trustedDirectoryOwner: config.dataDirectoryOwner)
            }
        }
        lock.lock()
        _data.catalog = c
        effectiveCatalog = resolved
        catalogGeneration += 1
        lock.unlock()
        // Settings and homes cannot have changed meanwhile: both are replaced under the mutation lock.
        install(classifier: candidate, readdir: s.readdirEnabled)
        Log.info("catalog \(catalog == nil ? "reset to defaults" : "updated") by pid \(peer.pid.map(String.init) ?? "?") uid \(peer.euid.map(String.init) ?? "?")")
    }

    public func recompileClassifier() {
        lock.lock()
        let catalog = effectiveCatalog
        let s = settings
        lock.unlock()
        let c = DaemonCore.makeClassifier(catalog: catalog, normalizer: normalizerBox.value, settings: s,
                                          resolveSymlinks: !config.inMemoryStore, links: linkInventory)
        install(classifier: c, readdir: s.readdirEnabled)
    }

    private func install(classifier c: PathClassifier, readdir: Bool) {
        linkWatch.value = LinkWatch(c)
        analyzer.replace(classifier: c)
        source?.updateMonitoring(prefixes: c.mutePaths, ancestors: c.ancestors, readdir: readdir)
        policyChanged()
    }

    /// Homes come and go (new users, network homes) and symlinks inside monitored directories change
    /// (dotfile managers). Rebuilds the classifier only when the monitored set actually changed.
    /// `includingHomes: false` (a link may have changed, files-9) skips the user database.
    /// `fullLinkWalk` (default: with the homes) searches the dotfile directories for links again;
    /// otherwise the rebuild re-reads the links already known (LinkInventory).
    func rediscover(includingHomes: Bool = true, fullLinkWalk: Bool? = nil) {
        // Discovery reads the user database without any lock; the rebuild runs under the mutation
        // lock so it cannot install a classifier built from a catalog or settings that a concurrent
        // update(catalog:) / update(settings:) has just replaced.
        let found = includingHomes && config.homeDirectories == nil ? HomeDirectories.discover() : nil
        if fullLinkWalk ?? includingHomes, !config.inMemoryStore {
            // Outside the mutation lock too: answering a question takes it, and a walk reads the disk.
            lock.lock()
            let catalog = effectiveCatalog
            let s = settings
            lock.unlock()
            let normalizer = found.map { PathNormalizer(homeDirectories: $0) } ?? normalizerBox.value
            linkInventory.walk(PathClassifier.linkWalkDirectories(catalog: catalog, normalizer: normalizer, projectRoots: s.projectRoots))
            lock.lock()
            lastFullLinkWalk = Date()
            lock.unlock()
        }
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
                                                  resolveSymlinks: !config.inMemoryStore, links: linkInventory)
        rediscoveryHook?()
        let current = analyzer.classifier
        if candidate.mutePaths != current.mutePaths || candidate.prefixes != current.prefixes || candidate.ancestors != current.ancestors {
            Log.info("monitored paths changed: \(current.mutePaths.count) → \(candidate.mutePaths.count) spellings")
            install(classifier: candidate, readdir: s.readdirEnabled)
        }
    }

    // MARK: - Link changes (files-9)

    /// A path a file operation touched where a followed link may have changed.
    struct LinkChange: Equatable {
        var operation: FileOperation
        var role: TargetRole
        /// Normalized.
        var path: String
    }

    /// A file operation the source reported (any thread, possibly right after the ES callback: memory
    /// only). A create, rename, clone, copy, link or unlink at a monitored prefix or ancestor, or inside
    /// a directory searched for links, may have added, replaced or removed a link the classifier
    /// follows: ES then reports accesses at a target that is not monitored until links are
    /// re-discovered. Instead of waiting up to `rediscoveryInterval`, the paths are looked at
    /// `linkRediscoveryDelay` later, off the event path (coalesced: one look per delay at most, which
    /// bounds the cost of a flood). See `lookAtLinkChanges`.
    func noteFileOperation(_ activity: FileActivity) {
        switch activity.operation {
        case .create, .rename, .clone, .copyfile, .link, .unlink: break
        default: return
        }
        let watch = linkWatch.value
        let changes = activity.targets.compactMap { t -> LinkChange? in
            let path = watch.normalizer.normalize(t.path)
            return watch.covers(path) ? LinkChange(operation: activity.operation, role: t.role, path: path) : nil
        }
        guard !changes.isEmpty else { return }
        lock.lock()
        // Bounded: past that, links are searched for in full without looking at each path.
        if pendingLinkChanges.count + changes.count > DaemonCore.maxPendingLinkChanges {
            pendingLinkOverflow = true
        } else {
            pendingLinkChanges += changes
        }
        guard !linkRediscoveryPending else { lock.unlock(); return }
        linkRediscoveryPending = true
        let generation = linkRediscoveryGeneration
        lock.unlock()
        linkQueue.asyncAfter(deadline: .now() + config.linkRediscoveryDelay) { [weak self] in
            self?.lookAtLinkChanges(generation: generation)
        }
    }

    /// Link changes kept for one look; past that, a full search for links follows.
    static let maxPendingLinkChanges = 64
    /// Entries one look reads in directories moved or copied into a searched directory; past that, a
    /// full search for links follows.
    static let linkLookBudget = 20_000

    /// On `linkQueue`. The links the noted paths show are added to the LinkInventory: a link created
    /// there (at any depth: the full search stops at PathClassifier.linkWalkMaxDepth), or the links in
    /// a directory moved or copied in. Then the classifier is rebuilt from the links already known,
    /// without searching the directories again, if any path was a followed link or held one, is a link
    /// now, is a directory moved or copied in, or was made on the way to a link's target. A full search
    /// runs only when changes were lost, at most once per `linkFullWalkInterval`.
    private func lookAtLinkChanges(generation: Int) {
        lock.lock()
        guard generation == linkRediscoveryGeneration else { lock.unlock(); return }
        // Taken before the look: a link that changes during it schedules another look. The next one
        // starts a delay after this one at least (the queue is serial, so runs never overlap).
        linkRediscoveryPending = false
        let changes = pendingLinkChanges
        var overflow = pendingLinkOverflow
        pendingLinkChanges.removeAll()
        pendingLinkOverflow = false
        let sinceFullWalk = Date().timeIntervalSince(lastFullLinkWalk)
        lock.unlock()
        let classifier = analyzer.classifier
        let watch = linkWatch.value
        var changed = false
        var budget = DaemonCore.linkLookBudget
        for change in changes where DaemonCore.mayChangeLinks(change, classifier: classifier, watch: watch) {
            changed = true
            var st = stat()
            guard change.role != .source, change.operation != .unlink, lstat(change.path, &st) == 0 else { continue }
            switch st.st_mode & S_IFMT {
            case S_IFLNK:
                linkInventory.report([change.path])
            case S_IFDIR where change.operation != .create:
                let found = LinkFollowingResolver.links(under: change.path, maxDepth: PathClassifier.linkWalkMaxDepth,
                                                        maxEntries: max(0, budget))
                budget -= found.visited
                if budget <= 0 { overflow = true }
                linkInventory.report(found.links)
            default:
                break
            }
        }
        if overflow && sinceFullWalk < config.linkFullWalkInterval {
            // Too soon after the last full search: it runs when the interval is over. Meanwhile the
            // links already known (and those found now) are followed.
            overflow = false
            lock.lock()
            let schedule = !fullLinkWalkScheduled
            fullLinkWalkScheduled = true
            lock.unlock()
            if schedule {
                linkQueue.asyncAfter(deadline: .now() + (config.linkFullWalkInterval - sinceFullWalk)) { [weak self] in
                    self?.runScheduledFullLinkWalk(generation: generation)
                }
            }
        }
        guard overflow || changed else { return }
        rediscover(includingHomes: false, fullLinkWalk: overflow)
        lock.lock()
        _linkRediscoveryRuns += 1
        lock.unlock()
    }

    /// On `linkQueue`: the full search for links that lost changes asked for.
    private func runScheduledFullLinkWalk(generation: Int) {
        lock.lock()
        guard generation == linkRediscoveryGeneration, fullLinkWalkScheduled else { lock.unlock(); return }
        fullLinkWalkScheduled = false
        lock.unlock()
        rediscover(includingHomes: false, fullLinkWalk: true)
        lock.lock()
        _linkRediscoveryRuns += 1
        lock.unlock()
    }

    /// Whether `change` may have changed what the classifier follows: the path was a followed link (or
    /// held one) and was removed, replaced or moved away; or what is there now is a link, or a directory
    /// moved or copied in (it may hold links), or anything made on the way to a link's target that did
    /// not exist (the target's real spelling can be read now). A regular file saved by rename, or a new
    /// directory elsewhere, is not.
    static func mayChangeLinks(_ change: LinkChange, classifier: PathClassifier, watch: LinkWatch? = nil) -> Bool {
        if !classifier.linkAliases(of: change.path, limit: 1).isEmpty { return true }
        if change.role == .source || change.operation == .unlink { return false }
        var st = stat()
        guard lstat(change.path, &st) == 0 else { return false }
        let type = st.st_mode & S_IFMT
        if type == S_IFLNK || (type == S_IFDIR && change.operation != .create) { return true }
        return watch?.isOnTheWayToALinkTarget(change.path) ?? false
    }

    /// Drops a scheduled link rediscovery (the daemon is stopping).
    public func cancelPendingLinkRediscovery() {
        lock.lock()
        linkRediscoveryGeneration += 1
        linkRediscoveryPending = false
        pendingLinkChanges.removeAll()
        pendingLinkOverflow = false
        fullLinkWalkScheduled = false
        lock.unlock()
    }

    /// Tests: how many link rediscoveries have finished (looks that found nothing are not counted).
    var linkRediscoveryRuns: Int {
        lock.lock(); defer { lock.unlock() }
        return _linkRediscoveryRuns
    }

    /// Why a catalog path is too broad to monitor, or nil.
    func tooBroad(_ p: String) -> String? {
        let n = normalizerBox.value
        let homes = n.homeDirectories.map { PathNormalizer.fold(PathClassifier.stripTrailingSlash($0)) }
        for e in n.expand(p) {
            let key = PathNormalizer.fold(PathClassifier.stripTrailingSlash(n.normalize(e)))
            if key == "/" || key.isEmpty { return "the whole disk" }
            if homes.contains(key) { return "a whole home folder" }
            if homes.contains(where: { $0.hasPrefix(key + "/") }) { return "a folder that holds home folders" }
        }
        return nil
    }

    static func keepingConsumedUses(_ incoming: Rule, current: Rule) -> Rule {
        func lower(_ a: Int?, _ b: Int?) -> Int? {
            switch (a, b) {
            case let (x?, y?): return min(x, y)
            case let (x?, nil): return x
            case let (nil, y?): return y
            default: return nil
            }
        }
        var r = incoming
        r.remainingUses = lower(incoming.remainingUses, current.remainingUses)
        for i in r.exceptions.indices {
            if let old = current.exceptions.first(where: { $0.id == r.exceptions[i].id }) {
                r.exceptions[i].remainingUses = lower(r.exceptions[i].remainingUses, old.remainingUses)
            }
        }
        return r
    }

    public func restartLearning(peer: IPCPeer) throws {
        let now = Date()
        baseline.resetLearned(at: now)
        try store.setDate(now, forKey: "learning_started_at")
        persistBaseline()
        Log.info("learning restarted by pid \(peer.pid.map(String.init) ?? "?") uid \(peer.euid.map(String.init) ?? "?")")
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
        // Never over stored rules that could not be read (see checkRulesWritable).
        lock.lock(); let failed = rulesLoadError != nil; lock.unlock()
        guard !failed else { return }
        let consumed = rules.takeConsumed()
        let pruned = rules.pruneDeadExceptions(at: now)
        // Expired "allow once" answers can never match again.
        func expiredAnswer(_ r: Rule) -> Bool { r.template == DaemonCore.askAnswerTemplate && (r.expiresAt.map { $0 <= now } ?? false) }
        let expired = rules.rules.contains(where: expiredAnswer)
        if expired { rules.mutate { $0.removeAll(where: expiredAnswer) } }
        guard consumed || pruned || expired else { return }
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
        askBroker.expire()
        // dos-1: the baseline is bounded, and with the hourly retention it forgets what history no
        // longer holds (unapproved entries not seen within the retention period).
        let retentionDue = now.timeIntervalSince(lastRetention) > 3600
        let forgotten = baseline.prune(lastSeenBefore: retentionDue ? now.addingTimeInterval(-Double(currentSettings.retentionDays) * 86400) : nil)
        if forgotten > 0 { Log.info("baseline: forgot \(forgotten) unapproved entries (not seen within retention, or over the limit)") }
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

    /// Latency check (every second): statistics, and a log warning (at most once a minute) while p99
    /// stays over the threshold. Never switches enforcement off (ask mode).
    public func checkLatency(now: Date = Date()) {
        let stats = latency.evaluate()
        guard latency.isSlow, enforcement.isActive else { return }
        lock.lock()
        let due = now.timeIntervalSince(lastSlowWarning) >= 60
        if due { lastSlowWarning = now }
        lock.unlock()
        guard due else { return }
        Log.warning(String(format: "AUTH responses are slow: p99 %.1f ms over %.1f ms (p50 %.1f ms, %d deadline misses); "
                           + "enforcement stays on", stats.p99Micros / 1000, latency.p99ThresholdMicros / 1000,
                           stats.p50Micros / 1000, stats.deadlineMisses))
    }

    public func status() -> DaemonStatus {
        let now = Date()
        let s = currentSettings
        let stats = pipeline.stats
        let counts = (try? store.counts()) ?? StoreCounts(events: 0, aggregatedDays: 0, alerts: 0, unreadAlerts: 0)
        let learning = baseline.isLearning(at: now)
        // Ask mode: with enforcement active, undecided accesses are held and asked, so it enforces even
        // without a deny rule.
        let enforcing = enforcement.isActive
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
        lock.lock()
        let rulesError = rulesLoadError
        let unclean = uncleanStopNote
        lock.unlock()
        return DaemonStatus(
            version: WhoReadVersion.string, pid: getpid(), startedAt: startedAt, mode: mode, source: source.kind,
            sourceRunning: stats.source.running, sourceError: stats.source.error, sourceHint: stats.source.hint,
            sourceCanEnforce: source.canEnforce, learning: learning, learningEndsAt: baseline.learningEndsAt(),
            monitoringPaused: s.monitoringPaused, enforcementEnabled: s.enforcementEnabled,
            enforcementActive: enforcement.isActive, enforcementInactiveReasons: enforcement.inactiveReasons,
            // No automatic switch-off any more: never set (kept in the protocol for older clients).
            latencyTripReason: nil,
            killSwitchFilePresent: enforcement.killSwitchFilePresent,
            latency: latency.snapshot(), parser: source.parserStats, counts: counts,
            unreadAlerts: counts.unreadAlerts, lastEventAt: stats.lastEventAt, eventsProcessed: stats.processed,
            writerDropped: writer.droppedCount, monitoredPrefixes: analyzer.classifier.prefixes.count,
            homeDirectories: homes, rulesLoadError: rulesError, sourceDroppedEvents: source.droppedEvents,
            sourceKernelDrops: source.kernelDroppedEvents, pendingAsks: askBroker.openRequests, uncleanStop: unclean,
            sourceDeadlineMissMode: stats.source.deadlineMissMode)
    }
}

// MARK: - Links (files-9)

/// Where a file operation may add, replace or remove a link the classifier follows, for one classifier.
struct LinkWatch {
    let normalizer: PathNormalizer
    /// Folded prefixes and ancestors: the path itself may have become, or stopped being, a link.
    private var exact = Set<String>()
    /// Folded prefixes whose contents the classifier searches for links (dot-directories directly under
    /// a home, as in PathClassifier.walksForLinks) or that a followed link leads to.
    private var walked = Set<String>()
    /// Folded proper ancestors of the targets of followed links. A target may lie below directories
    /// that do not exist yet (`~/.azure/x -> ~/dotfiles/new/x`); once they are made, the target's real
    /// spelling (its case, a link on the way) can be read.
    private var targetAncestors = Set<String>()

    init(_ c: PathClassifier) {
        normalizer = c.normalizer
        let homes = c.normalizer.homeDirectories.map { PathNormalizer.fold(PathClassifier.stripTrailingSlash($0)) + "/." }
        for p in c.prefixes {
            let key = PathNormalizer.fold(p.path)
            exact.insert(key)
            if p.viaSymlink || homes.contains(where: { key.hasPrefix($0) }) { walked.insert(key) }
            if p.viaSymlink {
                var ancestor = ""
                for component in PathNormalizer.components(key).dropLast() {
                    ancestor += "/" + component
                    targetAncestors.insert(ancestor)
                }
            }
        }
        for a in c.ancestors { exact.insert(PathNormalizer.fold(a)) }
    }

    func covers(_ normalizedPath: String) -> Bool {
        let key = PathNormalizer.fold(PathClassifier.stripTrailingSlash(normalizedPath))
        return exact.contains(key) || isInsideWalked(key)
    }

    /// Strictly inside a searched directory or a link's target (folded key). One set lookup per
    /// component: this runs for every create, rename and unlink the source reports.
    private func isInsideWalked(_ key: String) -> Bool {
        guard !walked.isEmpty else { return false }
        var ancestor = ""
        for component in PathNormalizer.components(key).dropLast() {
            ancestor += "/" + component
            if walked.contains(ancestor) { return true }
        }
        return false
    }

    /// A proper ancestor of a followed link's target (normalized path).
    func isOnTheWayToALinkTarget(_ normalizedPath: String) -> Bool {
        targetAncestors.contains(PathNormalizer.fold(PathClassifier.stripTrailingSlash(normalizedPath)))
    }
}

/// The pipeline, plus DaemonCore.noteFileOperation for every file event.
final class LinkWatchingSink: EventSink, @unchecked Sendable {
    let pipeline: EventPipeline
    weak var core: DaemonCore?

    init(pipeline: EventPipeline) { self.pipeline = pipeline }

    func receive(_ event: SourceEvent, context: RuleContext) {
        pipeline.receive(event, context: context)
        if case .file(let activity) = event { core?.noteFileOperation(activity) }
    }

    func sourceStateChanged(_ state: SourceState) { pipeline.sourceStateChanged(state) }
}

/// realpath(3), plus links whose target does not exist yet (files-9). A dotfile manager may link
/// `~/.azure/x` to a file it creates later, and a tool writing through a dangling link creates the file
/// at the link's target, where ES reports it: that path must be monitored from the start, not from the
/// first rediscovery after it exists. For the classifier only (elsewhere a missing path stays nil).
struct LinkFollowingResolver: SymlinkResolver {
    private let real = RealpathSymlinkResolver()

    /// Missing directories a dangling link's target may lie below.
    static let maxMissingComponents = 16

    func resolve(_ path: String) -> String? {
        real.resolve(path) ?? LinkFollowingResolver.danglingTarget(path)
    }

    /// Where writing through the link at `path` creates its file: the link text (relative to the
    /// link's directory) followed through at most 8 links to a name that does not exist, below the real
    /// path of its deepest existing directory. Directories missing on the way are kept as spelled (a
    /// later `mkdir -p` makes them; DaemonCore re-reads the target then). nil when `path` is not a link,
    /// for a loop, when something on the way is not a directory, or when a missing part is `..`
    /// (where it leads depends on what is made there).
    static func danglingTarget(_ path: String) -> String? {
        var link = path
        for _ in 0..<8 {
            var st = stat()
            guard lstat(link, &st) == 0, (st.st_mode & S_IFMT) == S_IFLNK, let text = TrustedDirectory.readLink(link) else {
                return nil
            }
            let next = text.hasPrefix("/") ? text : TrustedDirectory.parent(of: link) + "/" + text
            if lstat(next, &st) == 0 {
                // Another link: follow it. Anything else exists, and realpath would have resolved it.
                guard (st.st_mode & S_IFMT) == S_IFLNK else { return nil }
                link = next
                continue
            }
            // Read before any Foundation call can change it.
            guard errno == ENOENT else { return nil }
            // The missing tail, up to the deepest directory that exists.
            var missing: [String] = []
            var head = next
            while true {
                let name = (head as NSString).lastPathComponent
                guard !name.isEmpty, name != "..", head != "/", missing.count < maxMissingComponents else { return nil }
                if name != "." { missing.insert(name, at: 0) }
                head = TrustedDirectory.parent(of: head)
                if lstat(head, &st) == 0 { break }
                guard errno == ENOENT else { return nil }
            }
            guard !missing.isEmpty, let dir = RealpathSymlinkResolver().resolve(head) else { return nil }
            return (dir == "/" ? "" : dir) + "/" + missing.joined(separator: "/")
        }
        return nil
    }

    func symlinks(under dir: String, maxDepth: Int, maxEntries: Int) -> [(link: String, target: String)] {
        LinkInventory.resolved(LinkFollowingResolver.links(under: dir, maxDepth: maxDepth, maxEntries: maxEntries).links,
                               below: dir, resolver: self)
    }

    /// The links below `dir`, breadth first and in name order, so the same tree gives the same links
    /// even past the caps, and links near the top are found first. Links to directories are reported,
    /// not entered. Looks at no more than `maxEntries` entries, `maxDepth` levels down; `visited` says
    /// how many it looked at.
    static func links(under dir: String, maxDepth: Int, maxEntries: Int) -> (links: [String], visited: Int) {
        var out: [String] = []
        var visited = 0
        var level = [dir]
        var depth = 1
        while !level.isEmpty && depth <= maxDepth && visited < maxEntries {
            var next: [String] = []
            for d in level {
                guard visited < maxEntries, let stream = opendir(d) else { continue }
                // The file type comes with the entry on APFS and HFS+: no lstat per file. A directory
                // is read whole and sorted, so where the budget ends does not depend on the order the
                // file system returns entries in; only one with more than `maxEntries` entries is read
                // in part, in that order.
                var entries: [(name: String, type: Int32)] = []
                while entries.count < maxEntries, let e = readdir(stream) {
                    var entry = e.pointee
                    let name = withUnsafeBytes(of: &entry.d_name) { raw in
                        String(cString: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
                    }
                    if name == "." || name == ".." { continue }
                    entries.append((name, Int32(entry.d_type)))
                }
                closedir(stream)
                entries.sort { $0.name < $1.name }
                for (name, reported) in entries {
                    guard visited < maxEntries else { break }
                    visited += 1
                    let p = d.hasSuffix("/") ? d + name : d + "/" + name
                    var type = reported
                    if type == DT_UNKNOWN {
                        var st = stat()
                        guard lstat(p, &st) == 0 else { continue }
                        switch st.st_mode & S_IFMT {
                        case S_IFLNK: type = DT_LNK
                        case S_IFDIR: type = DT_DIR
                        default: break
                        }
                    }
                    if type == DT_LNK { out.append(p) } else if type == DT_DIR { next.append(p) }
                }
            }
            level = next
            depth += 1
        }
        return (out, visited)
    }
}

/// The links the classifier follows inside the directories it searches for them
/// (PathClassifier.walksForLinks): what the last full walk of those directories found, plus links file
/// events showed since, at any depth (files-9). A classifier rebuild after a link change re-reads only
/// these, so it costs in proportion to the number of links, not to the size of the directories. The
/// full walk (`walkBudget` entries in all, but at least `minimumEntriesPerDirectory` for each
/// directory) runs at start, at every periodic rediscovery, and after events were lost. A rebuild
/// searches a directory again only when it was not searched yet or its real path changed since (it,
/// or a directory above it, was made a link: what the walk found there is somewhere else now),
/// sharing `walkBudget` the same way. Thread-safe.
final class LinkInventory: @unchecked Sendable {
    /// Entries one full walk looks at, over every directory (each also stops at
    /// PathClassifier.linkWalkMaxEntries).
    static let walkBudget = 100_000
    /// Entries every directory may look at even when the others used up `walkBudget`: the directories
    /// are walked in catalog order, and the last ones (a custom path) still need a share.
    static let minimumEntriesPerDirectory = 2_000

    /// Entries a walk of one directory looks at, out of `budget` left.
    static func share(of budget: Int, maxEntries: Int) -> Int {
        min(maxEntries, max(minimumEntriesPerDirectory, budget))
    }

    /// Links remembered from file events (the oldest are forgotten first).
    static let maxReported = 1024
    /// Links one classifier follows: each one adds monitored prefixes, mute paths and prefilter needles.
    static let maxFollowed = 4096

    private let lock = NSLock()
    /// Folded directory → the links the last walk found below it, and `roots(of:)` the directory then.
    private var walked: [String: (links: [String], roots: [String])] = [:]
    /// Links file events showed, oldest first, with their folded paths.
    private var reported: [(path: String, key: String)] = []
    private var reportedKeys = Set<String>()
    /// Folded searched directories and their real paths: only links below one are kept from events.
    private var roots = Set<String>()
    /// Bumped by every full walk: what a rebuild read before one is not written back over it.
    private var generation = 0
    private var _fullWalks = 0

    /// Tests: how many full walks ran.
    var fullWalks: Int {
        lock.lock(); defer { lock.unlock() }
        return _fullWalks
    }

    /// Searches `dirs` again, in order, sharing `budget` (each keeps `minimumEntriesPerDirectory`), and
    /// forgets what was found before. Call it outside the daemon's locks: it reads the disk.
    func walk(_ dirs: [String], budget: Int = LinkInventory.walkBudget) {
        var found: [String: (links: [String], roots: [String])] = [:]
        var roots: [String] = []
        var budget = budget
        for d in dirs {
            let key = PathNormalizer.fold(d)
            guard found[key] == nil else { continue }
            let dirRoots = LinkInventory.roots(of: d)
            let r = LinkFollowingResolver.links(under: d, maxDepth: PathClassifier.linkWalkMaxDepth,
                                                maxEntries: LinkInventory.share(of: budget, maxEntries: PathClassifier.linkWalkMaxEntries))
            budget -= r.visited
            found[key] = (r.links, dirRoots)
            roots += dirRoots
        }
        let foundKeys = Set(found.values.flatMap(\.links).map(PathNormalizer.fold))
        lock.lock()
        walked = found
        self.roots = Set(roots)
        generation += 1
        // What the walk found itself, and what is no longer below a searched directory, is not kept.
        forgetReported { r in foundKeys.contains(r.key) || !roots.contains { r.key.hasPrefix($0 + "/") } }
        _fullWalks += 1
        lock.unlock()
    }

    /// Links a file event showed (normalized paths: a link created, or the links below a directory moved
    /// or copied in).
    func report(_ links: [String]) {
        guard !links.isEmpty else { return }
        lock.lock()
        for p in links {
            let key = PathNormalizer.fold(p)
            // Elsewhere (a link at a catalog path or an ancestor) the rebuild resolves it anyway.
            guard isBelowRoot(key), reportedKeys.insert(key).inserted else { continue }
            reported.append((p, key))
        }
        let over = reported.count - LinkInventory.maxReported
        if over > 0 {
            reported.prefix(over).forEach { reportedKeys.remove($0.key) }
            reported.removeFirst(over)
        }
        lock.unlock()
        if over > 0 { Log.warning("links: more than \(LinkInventory.maxReported) links reported since the last full walk; forgot the \(over) oldest") }
    }

    /// Under `lock`: strictly below a searched directory (folded key).
    private func isBelowRoot(_ key: String) -> Bool {
        var ancestor = ""
        for component in PathNormalizer.components(key).dropLast() {
            ancestor += "/" + component
            if roots.contains(ancestor) { return true }
        }
        return false
    }

    /// Under `lock`.
    private func forgetReported(where gone: ((path: String, key: String)) -> Bool) {
        reported.removeAll { r in
            guard gone(r) else { return false }
            reportedKeys.remove(r.key)
            return true
        }
    }

    /// The links below `dir` with their targets now, for the classifier: what the last walk found there
    /// (walking it now if it has not been, or if its real path changed since), plus reported links below
    /// it, below its real path too (spelled below `dir`). Links that are gone are forgotten. At most
    /// `limit`.
    func links(under dir: String, maxDepth: Int, maxEntries: Int, limit: Int,
               resolver: LinkFollowingResolver = LinkFollowingResolver()) -> [(link: String, target: String)] {
        var budget = LinkInventory.walkBudget
        return links(under: dir, maxDepth: maxDepth, maxEntries: maxEntries, limit: limit, resolver: resolver, budget: &budget)
    }

    /// `budget`: entries a walk of `dir` may still look at, shared by the directories one classifier
    /// build walks (each keeps `minimumEntriesPerDirectory`). A walk it cut short is not kept (the next
    /// build walks again).
    func links(under dir: String, maxDepth: Int, maxEntries: Int, limit: Int, resolver: LinkFollowingResolver,
               budget: inout Int) -> [(link: String, target: String)] {
        guard limit > 0 else { return [] }
        let key = PathNormalizer.fold(dir)
        let roots = LinkInventory.roots(of: dir)
        lock.lock()
        let known = walked[key].flatMap { $0.roots == roots ? $0.links : nil }
        let reportedNow = reported
        let readGeneration = generation
        lock.unlock()
        func isLink(_ p: String) -> Bool {
            var st = stat()
            return lstat(p, &st) == 0 && (st.st_mode & S_IFMT) == S_IFLNK
        }
        var complete = true
        let listed: [String]
        if let known {
            listed = known
        } else {
            let cap = LinkInventory.share(of: budget, maxEntries: maxEntries)
            let r = LinkFollowingResolver.links(under: dir, maxDepth: maxDepth, maxEntries: cap)
            budget -= r.visited
            complete = cap == maxEntries || r.visited < cap
            listed = r.links
        }
        let found = listed.filter(isLink)
        var candidates = found
        var seen = Set(found.map(PathNormalizer.fold))
        var gone = Set<String>()
        let dirComponents = PathNormalizer.components(dir)
        for r in reportedNow {
            guard let root = roots.first(where: { r.key.hasPrefix($0 + "/") }) else { continue }
            guard isLink(r.path) else { gone.insert(r.key); continue }
            // Folding keeps the number of components: the tail below the root, spelled below `dir`.
            let tail = PathNormalizer.components(r.path).dropFirst(PathNormalizer.components(root).count)
            let spelled = "/" + (dirComponents + tail).joined(separator: "/")
            if seen.insert(PathNormalizer.fold(spelled)).inserted { candidates.append(spelled) }
        }
        lock.lock()
        if generation == readGeneration {
            if complete { walked[key] = (found, roots) }
            self.roots.formUnion(roots)
        }
        forgetReported { gone.contains($0.key) }
        lock.unlock()
        if candidates.count > limit {
            Log.warning("links: following only \(LinkInventory.maxFollowed) links; \(candidates.count - limit) below \(dir) are not followed")
        }
        return LinkInventory.resolved(Array(candidates.prefix(limit)), below: dir, resolver: resolver)
    }

    /// Folded `dir` and its real path: the two spellings of what is below it.
    static func roots(of dir: String) -> [String] {
        let key = PathNormalizer.fold(PathClassifier.stripTrailingSlash(dir))
        guard let real = RealpathSymlinkResolver().resolve(dir) else { return [key] }
        let realKey = PathNormalizer.fold(PathClassifier.stripTrailingSlash(real))
        return realKey == key ? [key] : [key, realKey]
    }

    /// `links` with their targets, leaving out links that lead back inside `dir` (whichever way it is
    /// spelled) and links that do not resolve.
    static func resolved(_ links: [String], below dir: String, resolver: LinkFollowingResolver) -> [(link: String, target: String)] {
        let roots = LinkInventory.roots(of: dir)
        return links.compactMap { p in
            guard let target = resolver.resolve(p) else { return nil }
            let t = PathNormalizer.fold(target)
            if roots.contains(where: { t == $0 || t.hasPrefix($0 + "/") }) { return nil }
            return (p, target)
        }
    }
}

/// The resolver one classifier build uses: LinkFollowingResolver, with the links below each searched
/// directory read from the LinkInventory, at most LinkInventory.maxFollowed in all. Directories the
/// inventory walks anew share LinkInventory.walkBudget.
final class InventoryLinkResolver: SymlinkResolver, @unchecked Sendable {
    private let inventory: LinkInventory
    private let resolver = LinkFollowingResolver()
    private var followed = 0
    private var budget = LinkInventory.walkBudget

    init(_ inventory: LinkInventory) { self.inventory = inventory }

    func resolve(_ path: String) -> String? { resolver.resolve(path) }

    func symlinks(under dir: String, maxDepth: Int, maxEntries: Int) -> [(link: String, target: String)] {
        let found = inventory.links(under: dir, maxDepth: maxDepth, maxEntries: maxEntries,
                                    limit: LinkInventory.maxFollowed - followed, resolver: resolver, budget: &budget)
        followed += found.count
        return found
    }
}
