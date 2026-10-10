import Foundation
import WhoReadCore

/// The native source's target-path mute set. Outside the EndpointSecurity guard so it is unit-tested
/// on any host.
enum NativeMutePlan {
    /// A path compared byte for byte. Swift String equality is canonical equivalence, which would fold
    /// the NFC and NFD spellings into one, while ES needs each spelling registered.
    struct Path: Hashable, Sendable {
        let path: String
        init(_ path: String) { self.path = path }
        static func == (a: Path, b: Path) -> Bool { a.path.utf8.elementsEqual(b.path.utf8) }
        func hash(into h: inout Hasher) { for b in path.utf8 { h.combine(b) } }
    }

    /// Muting applies to the path as VFS sees it (F_GETPATH, after symlink resolution). Register the
    /// catalog spelling, for non-ASCII paths both its NFC and NFD forms (APFS keeps whatever
    /// normalization a name was created with), the resolved on-disk spelling (realpath: on-disk
    /// case, symlinks resolved) when the path exists and `accept` takes it, and each of them under the
    /// data volume's root (`firmlinkSpellings`). Never "/" (a link to the root, as PathClassifier skips
    /// too): an inverted "/" prefix would select every file event on the system. Nothing for a path
    /// with a NUL: realpath and es_mute_path see the C string cut there, so "~/\0x" would select the
    /// whole home.
    static func variants(_ p: String, resolve: (String) -> String?, accept: (String) -> Bool = { _ in true }) -> [String] {
        guard !p.utf8.contains(0) else { return [] }
        var out = [p]
        if !p.utf8.allSatisfy({ $0 < 0x80 }) {
            out.append(p.decomposedStringWithCanonicalMapping)
            out.append(p.precomposedStringWithCanonicalMapping)
        }
        if let r = resolve(p), r != "/", accept(r) { out.append(r) }
        return out + out.flatMap(firmlinkSpellings)
    }

    /// `p` under /System/Volumes/Data, unless it is already there. PathNormalizer folds that root
    /// away from every path, firmlinked or not, so classification never sees it; VFS does report it
    /// for data-volume paths outside the firmlinks (a home under /home, which is a symlink to the
    /// autofs mount point /System/Volumes/Data/home, or one created under /System/Volumes/Data
    /// directly). Without it those homes would never be selected. For a firmlinked path (/Users,
    /// /Volumes, /private…) it is the same file, so selecting it costs nothing; elsewhere it names a
    /// path that does not exist. The eslogger prefilter adds the same spelling.
    static func firmlinkSpellings(_ p: String) -> [String] {
        guard p.hasPrefix("/"), p != "/" else { return [] }
        let key = PathNormalizer.fold(p)
        return PathNormalizer.defaultFirmlinkRoots.compactMap { root in
            let r = PathNormalizer.fold(root)
            return key == r || key.hasPrefix(r + "/") ? nil : root + p
        }
    }

    /// A prefix's resolved spelling passes the same filters as a link target in PathClassifier: never
    /// /dev (`~/.zsh_history -> /dev/null` would select every /dev/null open on the system), a home,
    /// or a directory containing a home or the prefix itself. Those filters compare normalized paths
    /// (the homes are normalized, as the classifier's are), so the resolved spelling is normalized
    /// before it is judged and registered as resolved: realpath of a home under /home is
    /// /System/Volumes/Data/home/…, which only the normalized form recognises as inside a home.
    /// Literal ancestors match one path only.
    static func plan(prefixes: [String], ancestors: [String], homes: [String] = [],
                     normalize: (String) -> String = { $0 },
                     resolve: (String) -> String?) -> (prefixes: Set<Path>, literals: Set<Path>) {
        (Set(prefixes.flatMap { p in
            variants(p, resolve: resolve) { r in
                let n = normalize(r)
                return PathClassifier.isMonitorableTarget(n) && PathClassifier.isUsableLinkTarget(n, inside: p, homes: homes)
            }
         }.map(Path.init)),
         Set(ancestors.flatMap { variants($0, resolve: resolve) }.map(Path.init)))
    }
}

/// What the kernel does with an AUTH message the file client does not answer by its deadline
/// (es_deadline_miss_mode_t; raw values in the header's declaration order). Outside the
/// EndpointSecurity guard so it is unit-tested on any host.
public enum NativeDeadlineMissMode: UInt32, Sendable, CaseIterable {
    /// Default, and the only mode before macOS 27: the client is killed and the access allowed.
    case kill = 0
    /// The access is denied and the client lives. Also: an AUTH message dropped from a full queue is
    /// denied instead of allowed.
    case failClosed = 1
    /// The access is allowed and the client lives.
    case failOpen = 2

    /// How status and logs name it (`SourceState.deadlineMissMode`).
    public var name: String {
        switch self {
        case .kill: return "kill"
        case .failClosed: return "fail-closed"
        case .failOpen: return "fail-open"
        }
    }

    public init?(name: String) {
        guard let m = NativeDeadlineMissMode.allCases.first(where: { $0.name == name }) else { return nil }
        self = m
    }

    /// `whoread status` text for a reported mode name.
    public static func statusDescription(_ name: String) -> String {
        switch NativeDeadlineMissMode(name: name) {
        case .failClosed?:
            return "fail-closed (an access not answered in time is denied; the daemon is not killed)"
        case .kill?:
            return "kill (a missed deadline kills the daemon and allows that access, and accesses the kernel drops "
                + "from a full queue are allowed; fail-closed needs macOS 27)"
        case .failOpen?:
            return "fail-open (WARNING: an access not answered in time is allowed)"
        case nil:
            return "\(name) (could not be read back)"
        }
    }

    /// Whether the kernel denied the accesses whose deadline the daemon missed (only in fail-closed).
    public static func missesDenied(_ name: String?) -> Bool { name.flatMap(NativeDeadlineMissMode.init(name:)) == .failClosed }

    /// The file client always asks for fail-closed: unanswered means denied, and enforcement is never
    /// switched off (in the default kill mode a missed deadline kills the client and allows the access,
    /// and AUTH messages the kernel drops from a full queue are allowed). The price: a daemon whose
    /// handler hangs is no longer killed and restarted by launchd; every access it is asked about is
    /// denied at its deadline until it recovers, a kill switch turns enforcement off, or it is stopped.
    static let wanted = NativeDeadlineMissMode.failClosed

    /// The outcome of `configure`: the mode in force (nil if it could not be read back) and what to log
    /// when it is not the wanted one.
    struct Outcome: Equatable {
        let mode: NativeDeadlineMissMode?
        let problem: String?

        /// For `SourceState.deadlineMissMode`.
        var name: String { mode?.name ?? "unknown" }
    }

    /// Sets `wanted` and reads back what is in force. `set` and `get` are nil when the running system
    /// lacks es_set_deadline_miss_mode / es_get_deadline_miss_mode (before macOS 27): the kernel then
    /// uses kill, which is not a problem to report on every start. `set` returns whether it succeeded;
    /// `get` returns the raw mode, or nil when it failed.
    static func configure(set: ((UInt32) -> Bool)?, get: (() -> UInt32?)?) -> Outcome {
        guard let set else {
            // A getter without a setter would be a strange libEndpointSecurity: trust it if it answers.
            if let raw = get?(), let mode = NativeDeadlineMissMode(rawValue: raw) { return Outcome(mode: mode, problem: nil) }
            return Outcome(mode: .kill, problem: nil)
        }
        let ok = set(wanted.rawValue)
        guard let get else {
            return Outcome(mode: ok ? nil : .kill,
                           problem: ok ? "es_get_deadline_miss_mode is missing; the deadline miss mode could not be verified"
                                       : "es_set_deadline_miss_mode(fail-closed) failed; the kernel keeps the default (kill)")
        }
        guard let raw = get() else {
            return Outcome(mode: nil, problem: ok ? "es_get_deadline_miss_mode failed after setting fail-closed"
                                                  : "es_set_deadline_miss_mode(fail-closed) and es_get_deadline_miss_mode failed")
        }
        guard let mode = NativeDeadlineMissMode(rawValue: raw) else {
            return Outcome(mode: nil, problem: "es_get_deadline_miss_mode returned an unknown mode \(raw)")
        }
        if mode == wanted { return Outcome(mode: mode, problem: nil) }
        return Outcome(mode: mode, problem: (ok ? "es_set_deadline_miss_mode(fail-closed) succeeded but the client is in "
                                                : "es_set_deadline_miss_mode(fail-closed) failed; the client is in ") + mode.name)
    }

    /// Looks a libEndpointSecurity function up at run time: the macOS 27 ones are not declared by the
    /// SDKs older Xcode versions build with, and calling them directly would also need macOS 27 to load.
    static func symbol(_ name: String) -> UnsafeMutableRawPointer? {
        #if canImport(Darwin)
        // RTLD_DEFAULT (dlfcn.h), which Swift does not import: every image loaded in the process.
        return dlsym(UnsafeMutableRawPointer(bitPattern: -2), name)
        #else
        return nil
        #endif
    }

    static let setterName = "es_set_deadline_miss_mode"
    static let getterName = "es_get_deadline_miss_mode"
}

/// Denials queued for recording (the AUTH callback only counts under a lock). Every denial is
/// recorded while the backlog is short. Past `mergeThreshold`, a denial identical to one still
/// queued (same process instance, operation, targets with their access, and rule) is merged into it,
/// so a process looping on a denied open cannot grow the queue without bound; past `limit`, every
/// further denial is only counted. Neither touches the AUTH response, which is sent before. Outside
/// the EndpointSecurity guard so it is unit-tested on any host.
struct NativeDenialBacklog {
    struct Key: Hashable {
        let pid: Int32
        let pidVersion: UInt32?
        let operation: FileOperation
        /// Paths with their access: a denied write is not merged into a queued denied read.
        let targets: [FileTarget]
        let ruleID: String?

        init(_ activity: FileActivity, _ decision: RuleDecision) {
            pid = activity.process.pid
            pidVersion = activity.process.pidVersion
            operation = activity.operation
            targets = activity.targets
            ruleID = decision.ruleID
        }
    }

    /// What `finish` needs back once the queued denial was recorded.
    struct Ticket {
        let key: Key?
    }

    static let mergeThreshold = 1_000
    static let limit = 10_000

    private(set) var pending = 0
    /// Denials merged or over the limit: never recorded on their own.
    private(set) var unrecorded: UInt64 = 0
    private var queued = Set<Key>()

    /// A ticket to queue the denial with, or nil when it is merged or over the limit (counted).
    /// `key` is only built once the backlog is past the threshold.
    mutating func admit(_ key: () -> Key) -> Ticket? {
        if pending >= NativeDenialBacklog.limit {
            unrecorded &+= 1
            return nil
        }
        guard pending >= NativeDenialBacklog.mergeThreshold else {
            pending += 1
            return Ticket(key: nil)
        }
        let k = key()
        guard queued.insert(k).inserted else {
            unrecorded &+= 1
            return nil
        }
        pending += 1
        return Ticket(key: k)
    }

    mutating func finish(_ ticket: Ticket) {
        pending -= 1
        if let k = ticket.key { queued.remove(k) }
    }
}

/// Messages missing from one ES client's global_seq_num stream (message version >= 4). The handler
/// block gets messages serially and in order, and a gap means the kernel dropped messages for this
/// client (docs/research/eslogger-libproc-packaging.md, as for eslogger's own drop count).
struct NativeSequenceGaps {
    private(set) var dropped: UInt64 = 0
    private var last: UInt64?

    mutating func note(_ seq: UInt64) {
        if let last, seq > last, seq - last > 1 { dropped &+= seq - last - 1 }
        last = seq
    }

    /// A new client numbers its messages afresh.
    mutating func reset() { last = nil }
}

/// AUTH messages the kernel dropped for the file client, from seq_num (message version >= 2), which
/// counts each event type on its own: a gap in an AUTH type's numbers is an AUTH message of that type
/// that never arrived (global_seq_num gaps cannot tell AUTH from NOTIFY). The kernel denies such an
/// access in fail-closed mode (header, es_set_deadline_miss_mode) and allows it otherwise. Nothing else
/// is known about it (no process, no path), so it is counted by outcome, never recorded as an event.
/// Outside the EndpointSecurity guard so it is unit-tested on any host.
struct NativeAuthDrops {
    private var gaps: [UInt32: NativeSequenceGaps] = [:]
    /// Dropped while the client's deadline miss mode was fail-closed: the kernel denied them.
    private(set) var denied: UInt64 = 0
    /// Dropped in any other mode (kill before macOS 27): the kernel allowed them.
    private(set) var allowed: UInt64 = 0

    mutating func note(type: UInt32, seq: UInt64, failClosed: Bool) {
        var g = gaps[type] ?? NativeSequenceGaps()
        let before = g.dropped
        g.note(seq)
        gaps[type] = g
        let new = g.dropped &- before
        guard new > 0 else { return }
        if failClosed { denied &+= new } else { allowed &+= new }
    }

    /// A new client numbers its messages afresh; the counts stay.
    mutating func reset() { gaps = [:] }
}

/// Answering an AUTH message when the kernel enforces its deadline itself (fail-closed, macOS 27):
/// whatever is not answered by the deadline is denied, and no NOTIFY event follows. An allow given
/// at or after the deadline, or one es_respond did not deliver, is therefore a denial that nothing
/// else would record. Outside the EndpointSecurity guard so it is unit-tested on any host.
enum NativeLateAnswer {
    /// ES_RESPOND_RESULT_SUCCESS and ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE (ESTypes.h).
    static let respondSuccess: UInt32 = 0
    static let respondDuplicate: UInt32 = 4

    /// Sends the answer through `send` (allow or not; it returns es_respond's raw result) and returns
    /// true when the kernel denied an access the daemon allowed. In fail-closed mode an allow is never
    /// sent once `now()` (Mach absolute time, read just before es_respond) has reached the message's
    /// deadline: the kernel has denied the access by then or is about to, and sending a deny instead
    /// makes the outcome the same whoever is first, so recording it as denied is never wrong. A
    /// delivery failure leaves the message to its deadline (denied too); a duplicate means an earlier
    /// answer stands, which is not this one's to judge. In any other mode a late answer is sent as
    /// decided and nothing is reported: in kill mode the kernel kills the daemon and allows the access.
    /// A deadline of 0 (never set by the kernel for AUTH) is not taken as passed.
    static func answer(allow: Bool, failClosed: Bool, deadline: UInt64, now: () -> UInt64, send: (Bool) -> UInt32) -> Bool {
        let late = failClosed && allow && deadline != 0 && now() >= deadline
        let result = send(allow && !late)
        guard failClosed && allow else { return false }
        return late || (result != respondSuccess && result != respondDuplicate)
    }
}

/// How long ask mode may hold an AUTH message (docs/ASK_MODE.md): remaining = deadline − now,
/// headroom = 20 % of remaining clamped to [1 s, 5 s] (the pattern Santa uses), budget = remaining −
/// headroom, never below 0. Times are Mach absolute ticks; the timebase turns ticks into nanoseconds
/// (ticks × numer / denom). Outside the EndpointSecurity guard so it is unit-tested on any host.
struct NativeAskBudget: Equatable {
    /// Seconds the broker may hold the access before denying it.
    let budget: TimeInterval
    let headroom: TimeInterval

    /// When the source denies by itself if the broker has not answered: halfway through the
    /// headroom, so still before the kernel deadline.
    var backstop: TimeInterval { budget + headroom / 2 }

    init(deadline: UInt64, now: UInt64, numer: UInt32, denom: UInt32) {
        let ticks = deadline > now ? deadline - now : 0
        let remaining = denom == 0 ? 0 : Double(ticks) * Double(numer) / Double(denom) / 1_000_000_000
        headroom = min(max(remaining * 0.2, 1), 5)
        budget = max(remaining - headroom, 0)
    }
}

/// Ask mode: the AUTH messages the native source holds for the user's answer. Each one is answered
/// (or, for `abandon`, only released) exactly once, by whoever takes it out of the set first: the
/// broker (answer, timeout, denyAll), the source's backstop, `denyAll` here before the ES client is
/// deleted, or `abandon` when the broker did not hold it. Generic over how a message is answered and
/// released (es_respond_* and es_release_message in the source), so it is unit-tested on any host.
final class NativeHeldMessages: @unchecked Sendable {
    final class Held: @unchecked Sendable {
        fileprivate let answer: (Bool) -> Void
        fileprivate let release: () -> Void

        fileprivate init(answer: @escaping (Bool) -> Void, release: @escaping () -> Void) {
            self.answer = answer
            self.release = release
        }
    }

    private let lock = NSCondition()
    /// A `Held` is keyed by its identity; every caller of `finish` or `abandon` keeps it alive, so the
    /// identifier cannot be reused while it can still be passed in.
    private var held: [ObjectIdentifier: Held] = [:]
    /// Answers or releases taken out of `held` and still running (outside the lock). `denyAll` waits
    /// for them: the ES client must not be deleted while a backstop is inside es_respond.
    private var inFlight = 0

    /// Messages held right now.
    var count: Int {
        lock.lock(); defer { lock.unlock() }
        return held.count
    }

    /// Registers a message the caller has just retained. `answer(allow)` responds (never cached) and
    /// releases it; `release` only releases it.
    func add(answer: @escaping (Bool) -> Void, release: @escaping () -> Void) -> Held {
        let h = Held(answer: answer, release: release)
        lock.lock()
        held[ObjectIdentifier(h)] = h
        lock.unlock()
        return h
    }

    private func take(_ h: Held) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard held.removeValue(forKey: ObjectIdentifier(h)) != nil else { return false }
        inFlight += 1
        return true
    }

    private func done() {
        lock.lock()
        inFlight -= 1
        if inFlight == 0 { lock.broadcast() }
        lock.unlock()
    }

    /// Answers, the first time only (outside the lock: responding is a system call). False if it was
    /// already answered or abandoned.
    @discardableResult
    func finish(_ h: Held, allow: Bool) -> Bool {
        guard take(h) else { return false }
        h.answer(allow)
        done()
        return true
    }

    /// Releases without answering: the handler that retained it answers at once, while the message is
    /// still valid in its scope. False if it was already answered.
    func abandon(_ h: Held) -> Bool {
        guard take(h) else { return false }
        h.release()
        done()
        return true
    }

    /// How long `denyAll` waits by default for answers still running elsewhere.
    static let denyAllWait: TimeInterval = 2

    /// Denies everything still held, then waits (bounded) for answers already running elsewhere (a
    /// backstop, the broker queue) to return. Returns how many it denied: none when the broker's
    /// denyAll kept its contract.
    @discardableResult
    func denyAll(waitAtMost timeout: TimeInterval = NativeHeldMessages.denyAllWait) -> Int {
        lock.lock()
        let all = Array(held.values)
        lock.unlock()
        let denied = all.filter { finish($0, allow: false) }.count
        let until = Date().addingTimeInterval(timeout)
        lock.lock()
        while inFlight > 0 && lock.wait(until: until) {}
        lock.unlock()
        return denied
    }
}

/// es_delete_client is the header's one exception to "every es_* function is safe from any thread": it
/// must not run concurrently with any other es_* call on the client, es_respond_* included. Those come
/// from the handler block (AUTH answers; es_exec_arg for the process client's execs) and from other
/// queues (a held message's answer). Each runs
/// inside `use`; `close` lets nothing new in and waits for what is inside, so the caller then has the
/// exclusive access es_delete_client needs. One gate per client, never reopened. Outside the
/// EndpointSecurity guard so it is unit-tested on any host.
final class NativeClientGate: @unchecked Sendable {
    private let condition = NSCondition()
    private var inside = 0
    private var closed = false

    /// Runs `body` unless the gate is closed. False when it did not run: the client is being deleted.
    @discardableResult
    func use(_ body: () -> Void) -> Bool {
        condition.lock()
        guard !closed else {
            condition.unlock()
            return false
        }
        inside += 1
        condition.unlock()
        body()
        condition.lock()
        inside -= 1
        if inside == 0 { condition.broadcast() }
        condition.unlock()
        return true
    }

    /// Lets nothing new in and waits (bounded) for the calls inside to return. False if one was still
    /// running at the timeout: the client must not be deleted then.
    func close(waitAtMost timeout: TimeInterval) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        closed = true
        let until = Date().addingTimeInterval(timeout)
        while inside > 0 {
            if !condition.wait(until: until) { return inside == 0 }
        }
        return true
    }
}

/// Calls of one client's handler block, so that a stop can tell when the messages the kernel queued
/// before es_unsubscribe_all have been handled where es_sync_client is missing (before macOS 27).
/// Outside the EndpointSecurity guard so it is unit-tested on any host.
final class NativeHandlerActivity: @unchecked Sendable {
    private let lock = NSLock()
    private var inside = 0
    private var calls: UInt64 = 0

    func enter() {
        lock.lock()
        inside += 1
        calls &+= 1
        lock.unlock()
    }

    func leave() {
        lock.lock()
        inside -= 1
        lock.unlock()
    }

    private var snapshot: (inside: Int, calls: UInt64) {
        lock.lock(); defer { lock.unlock() }
        return (inside, calls)
    }

    /// Waits until no call is running and none has started for `quiet` seconds, at most `timeout`.
    /// False if that never happened: messages are still coming, or a call is stuck.
    func waitQuiet(_ quiet: TimeInterval, waitAtMost timeout: TimeInterval) -> Bool {
        let start = DispatchTime.now().uptimeNanoseconds
        let end = start &+ UInt64(max(timeout, 0) * 1e9)
        let quietNs = UInt64(max(quiet, 0) * 1e9)
        var seen = snapshot
        var quietSince = start
        while true {
            let t = DispatchTime.now().uptimeNanoseconds
            let s = snapshot
            if s.inside > 0 || s.calls != seen.calls {
                seen = s
                quietSince = t
            } else if t &- quietSince >= quietNs {
                return true
            }
            if t >= end { return false }
            Thread.sleep(forTimeInterval: min(max(quiet / 4, 0.001), 0.01))
        }
    }
}

/// Before a client is deleted, after es_unsubscribe_all: the kernel still delivers what it queued
/// before, and an AUTH message among it should get the daemon's answer, not be left to the client's
/// teardown. Outside the EndpointSecurity guard so it is unit-tested on any host.
enum NativeDrain {
    /// How long a drain may take per client.
    static let wait: TimeInterval = 1
    /// Before macOS 27: the handler counts as drained once it has been idle this long.
    static let quiet: TimeInterval = 0.05

    #if canImport(Darwin)
    /// The block es_sync_client runs: an Objective-C block, which ES copies and calls later, from its
    /// own queue, once every message queued in front of the marker has been handled (or when the client
    /// is destroyed).
    typealias SyncBlock = @convention(block) () -> Void

    /// es_sync_client (macOS 27, ESClient.h) as a C function pointer: absent from the SDKs older Xcode
    /// versions build with, so it is looked up at run time. It must not be called from the client's own
    /// handler block. Returns es_return_t (ES_RETURN_SUCCESS = 0).
    typealias SyncClientFunction = @convention(c) (OpaquePointer, @escaping SyncBlock) -> UInt32

    static func syncClientFunction(_ symbol: UnsafeMutableRawPointer?) -> SyncClientFunction? {
        symbol.map { unsafeBitCast($0, to: SyncClientFunction.self) }
    }
    #else
    // Linux Swift has no blocks (scripts/dev/es-typecheck compiles this file there).
    typealias SyncBlock = () -> Void
    #endif
    static let syncClientName = "es_sync_client"

    /// `sync` places a sync marker whose block is the given one and returns whether that worked (nil
    /// where es_sync_client is missing). Otherwise, or if placing failed, `quiet` waits for the
    /// handler to go idle. True once drained; false at `timeout`: the caller must not delete the client
    /// then (a call may still be running on it; the process is stopping anyway).
    static func run(sync: ((@escaping SyncBlock) -> Bool)?, quiet: (TimeInterval) -> Bool,
                    waitAtMost timeout: TimeInterval = NativeDrain.wait) -> Bool {
        if let sync {
            let done = DispatchSemaphore(value: 0)
            // The block only signals: it may also run long after this returns (timeout) or at teardown.
            if sync({ done.signal() }) { return done.wait(timeout: .now() + timeout) == .success }
        }
        return quiet(timeout)
    }
}

/// The default mute set of a new ES client (ESClient.h, es_new_client): macOS mutes most AUTH events
/// of some system programs (those watchdogd monitors, for example) for every client, so their accesses
/// arrive as NOTIFY events only and can never be asked about or blocked. Mute inversion does not clear
/// it, and the header advises against unmuting it, so it is only read at connect (es_muted_paths_events)
/// and reported. Outside the EndpointSecurity guard so it is unit-tested on any host.
enum NativeDefaultMutes {
    /// es_mute_path_type_t: ES_MUTE_PATH_TYPE_PREFIX and ES_MUTE_PATH_TYPE_LITERAL mute a program by its
    /// executable path; TARGET_PREFIX (2) and TARGET_LITERAL (3) mute targets, which inverted target
    /// muting replaces with the monitored paths anyway.
    static let programPrefix: UInt32 = 0
    static let programLiteral: UInt32 = 1

    struct Entry: Equatable {
        let type: UInt32
        let path: String
        let events: [UInt32]
    }

    /// The program paths whose muted events include any of `authEvents` (the AUTH events the file
    /// client answers), with only those events, sorted by path.
    static func programs(_ entries: [Entry], authEvents: Set<UInt32>) -> [Entry] {
        entries.compactMap { e -> Entry? in
            guard e.type == programPrefix || e.type == programLiteral else { return nil }
            let muted = e.events.filter(authEvents.contains)
            return muted.isEmpty ? nil : Entry(type: e.type, path: e.path, events: muted)
        }.sorted { $0.path.utf8.lexicographicallyPrecedes($1.path.utf8) }
    }

    /// The log line for `programs` (`name` names an event type).
    static func logLine(_ programs: [Entry], name: (UInt32) -> String) -> String {
        guard !programs.isEmpty else {
            return "Endpoint Security default mute set: no program is muted for the AUTH events WhoRead answers"
        }
        let list = programs.map { p in
            (p.type == programPrefix ? "\(p.path)* " : "\(p.path) ") + "(" + p.events.map(name).joined(separator: ", ") + ")"
        }
        return "Endpoint Security default mute set: macOS sends no AUTH event for \(programs.count) program path"
            + (programs.count == 1 ? "" : "s") + " (their accesses are recorded but can never be asked about or blocked): "
            + list.joined(separator: "; ")
    }
}

/// Which processes opened a monitored file for writing, so that a close reporting the file as mapped
/// writable is charged only to one of them (`es_event_close_t.was_mapped_writable`, message version
/// >= 6). The flag only says that something mapped the vnode writable at some point while it was alive
/// (header): on its own it would charge every later reader of the file. A shared writable mapping needs
/// a descriptor opened with FWRITE (mmap fails with EACCES otherwise), and such an open is recorded, so
/// a close of that process is a possible modification through the mapping, which no write call shows
/// (`modified` stays false). A process is its pid with its start (fork) time: a descriptor survives exec,
/// and a reused pid starts later. Entries are not dropped at exit: the process client's exit can be
/// handled before the file client's closes of that process's descriptors (no order between two
/// clients), and those closes are the common case. Bounded instead: past `capacity` the oldest entries
/// go (their mapped closes are then not reported). Outside the EndpointSecurity guard so it is
/// unit-tested on any host.
struct NativeWritableOpens {
    static let capacity = 4096

    /// A process: pid and start time (es_process_t.start_time in microseconds, message version >= 3;
    /// nil before, when only the pid tells processes apart).
    struct Owner: Hashable {
        let pid: Int32
        let start: UInt64?
    }

    private struct Entry: Hashable {
        let owner: Owner
        let path: NativeMutePlan.Path
    }

    private var entries = Set<Entry>()
    /// Insertion order, oldest first from `head`.
    private var order: [Entry] = []
    private var head = 0

    var count: Int { entries.count }

    mutating func noteWriteOpen(_ owner: Owner, path: String) {
        let e = Entry(owner: owner, path: NativeMutePlan.Path(path))
        guard entries.insert(e).inserted else { return }
        order.append(e)
        while entries.count > NativeWritableOpens.capacity, head < order.count {
            entries.remove(order[head])
            head += 1
        }
        if head > NativeWritableOpens.capacity {
            order.removeFirst(head)
            head = 0
        }
    }

    /// Entries kept for eviction order (tests: it stays bounded).
    var orderCount: Int { order.count }

    func contains(_ owner: Owner, path: String) -> Bool {
        entries.contains(Entry(owner: owner, path: NativeMutePlan.Path(path)))
    }
}

/// files-5: an existing directory a rename lands on is judged by everything it can hold, because a
/// swap (renamex_np RENAME_SWAP) moves it, with its contents, to the source path, and Endpoint Security
/// does not report the rename's flags. An EMPTY directory carries nothing out, so a rename onto it is
/// judged as a rename to a new path (a write; what the source brings in is still judged). A plain
/// rename(2) onto a directory succeeds only while it is empty (ENOTEMPTY otherwise, checked by the file
/// system when the rename happens), so it never carries anything out. For a swap, the stat is the
/// kernel's at authorization: only what is put into the directory between the AUTH event and the swap
/// can leave with it, and moving anything in is itself judged (the moved file is the carried source of
/// its own rename, clone or copy), so only new content written there in that window by someone else
/// could. Emptiness is read only where it is exact: on APFS a directory reports st_nlink = 2 + its
/// entries (files, directories, links, fifos alike) and st_size = 32 × st_nlink; other file systems
/// (network homes among them) report these fields their own way, and a dataless directory (a cloud
/// folder whose contents are not local, SF_DATALESS) lists nothing but still has contents. Outside the
/// EndpointSecurity guard so it is unit-tested on any host.
enum NativeEmptyDirectory {
    /// SF_DATALESS (sys/stat.h).
    static let datalessFlag: UInt32 = 0x4000_0000

    /// `onAPFS`: the directory's device is a local APFS volume (statfs f_fstypename).
    static func isEmpty(mode: UInt32, nlink: UInt32, size: Int64, flags: UInt32, onAPFS: Bool) -> Bool {
        onAPFS && mode & 0o170000 == 0o040000 && nlink == 2 && size == 64 && flags & datalessFlag == 0
    }
}

/// Liveness of the file client's handler block, which the kernel calls serially: one call that never
/// returns holds up every message behind it. In the default kill mode the kernel kills the daemon at
/// the first missed AUTH deadline and launchd starts a new one. In fail-closed mode (macOS 27) nothing
/// does: every AUTH access behind the stuck call is denied at its deadline, for as long as the daemon
/// lives, and nothing is recorded. The watchdog notices one call that has been running far longer than
/// any deadline and calls `onStall` (the source logs, leaves a stall marker and exits, so launchd starts
/// a fresh daemon; the enforcement setting is untouched, and the next start reports an unclean stop).
/// Only a call that entered and has not returned counts, never idle time. Uptime clock: it pauses while
/// the Mac sleeps. Outside the EndpointSecurity guard so it is unit-tested on any host.
///
/// A wedge that comes back after every restart would otherwise restart the daemon every two minutes.
/// Each restart costs the ancestry of processes started before it and leaves a gap with no client (the
/// accesses in it are allowed and not recorded), and a system that sees its ES client torn down again
/// and again may throttle or refuse it (not documented either way; docs/ASK_MODE.md names the risk),
/// which would leave nothing enforced at all. So the shortest stall
/// doubles with each watchdog exit of the last `backoffWindow` (`floor(recentExits:)`), up to
/// `maximumStall`: a recurring wedge then keeps failing closed (denied) for longer between restarts
/// instead of churning, and the unclean-stop report counts the exits.
final class NativeHandlerWatchdog: @unchecked Sendable {
    /// No AUTH deadline comes near this (they are seconds to tens of seconds). A restart costs the
    /// ancestry of processes started before it, so only a real wedge may cause one.
    static let minimumStall: TimeInterval = 120
    /// And a stall lasts at least this many times the longest AUTH deadline seen so far…
    static let deadlineFactor: Double = 4
    /// …up to this, so that one absurd deadline cannot switch the watchdog off.
    static let maximumStall: TimeInterval = 900
    /// How often the timer looks.
    static let interval: TimeInterval = 10
    /// Watchdog exits this recent count toward the backoff.
    static let backoffWindow: TimeInterval = 3600

    /// The shortest stall after `recentExits` watchdog exits in the last `backoffWindow`: doubling from
    /// `minimumStall`, never above `maximumStall`.
    static func floor(recentExits: Int) -> TimeInterval {
        let doublings = min(max(recentExits, 0), 16)
        return min(minimumStall * Double(1 << doublings), maximumStall)
    }

    private let lock = NSLock()
    /// When the call inside started (uptime ns), nil while none is.
    private var enteredAt: UInt64?
    /// The longest time an AUTH message was given to its deadline (ns).
    private var longestDeadline: UInt64 = 0
    private var fired = false
    private var cancelled = false
    private var timer: DispatchSourceTimer?
    private let now: () -> UInt64
    /// The shortest stall (`floor(recentExits:)`).
    let floor: TimeInterval

    init(now: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
         floor: TimeInterval = NativeHandlerWatchdog.minimumStall) {
        self.now = now
        self.floor = min(max(floor, NativeHandlerWatchdog.minimumStall), NativeHandlerWatchdog.maximumStall)
    }

    /// A handler call starts. `deadlineSpan`: for an AUTH message, the nanoseconds between its creation
    /// and its deadline; 0 otherwise.
    func enter(deadlineSpan: UInt64 = 0) {
        let t = now()
        lock.lock()
        enteredAt = t
        if deadlineSpan > longestDeadline { longestDeadline = deadlineSpan }
        lock.unlock()
    }

    /// The handler call returned.
    func leave() {
        lock.lock()
        enteredAt = nil
        lock.unlock()
    }

    /// How long a call must have been inside to count as a stall.
    var limit: TimeInterval {
        lock.lock(); defer { lock.unlock() }
        return limitLocked
    }

    private var limitLocked: TimeInterval {
        let byDeadline = min(NativeHandlerWatchdog.deadlineFactor * Double(longestDeadline) / 1e9, NativeHandlerWatchdog.maximumStall)
        return max(floor, byDeadline)
    }

    /// How long the call inside has been running, when that is past `limit`; nil otherwise. A stall is
    /// reported once.
    func stalled() -> TimeInterval? {
        let t = now()
        lock.lock(); defer { lock.unlock() }
        guard !fired, !cancelled, let since = enteredAt, t > since else { return nil }
        let inside = Double(t - since) / 1e9
        guard inside >= limitLocked else { return nil }
        fired = true
        return inside
    }

    /// Looks every `interval` seconds (uptime) on `queue` until cancelled; `onStall` runs at most once.
    func start(every interval: TimeInterval = NativeHandlerWatchdog.interval, queue: DispatchQueue,
               onStall: @escaping @Sendable (TimeInterval) -> Void) {
        lock.lock()
        // Checked before the timer exists: libdispatch traps on releasing a source never resumed.
        guard !cancelled, timer == nil else {
            lock.unlock()
            return
        }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + interval, repeating: interval, leeway: .milliseconds(Int(interval * 100)))
        t.setEventHandler { [weak self] in
            if let seconds = self?.stalled() { onStall(seconds) }
        }
        timer = t
        lock.unlock()
        t.resume()
    }

    /// Stops looking, for good (the client is going away; any thread). A stall is never reported after.
    func cancel() {
        lock.lock()
        cancelled = true
        let t = timer
        timer = nil
        lock.unlock()
        t?.cancel()
    }
}

#if canImport(EndpointSecurity)
#if canImport(Darwin)
import Darwin
#else
import Glibc // scripts/dev/es-typecheck compiles this file on Linux against a stub EndpointSecurity
#endif
import EndpointSecurity
import Foundation
import WhoReadCore
import WhoReadIPC

// Native Endpoint Security source (monitoring + enforcement).
//
// Compiled against the real SDK headers (macOS 27 SDK; the macOS 27 calls are looked up at run time,
// so older SDKs build it too) and checked against their documentation. Its ES calls only run in the
// test VM: the message conversion is unit-tested on hand-built messages (NativeFindingsEngineTests).
//
// Two clients, as the brief requires:
// - file client: target-path muting INVERTED, so only events touching monitored prefixes (or the
//   literal ancestor directories) are delivered (MOUNT supports no target muting: every mount is).
//   NOTIFY events always; AUTH events only while enforcement is active. Deadline miss mode
//   fail-closed on macOS 27 and later (NativeDeadlineMissMode). A multi-target event
//   (rename/clone/copyfile/link/exchangedata) is delivered if ANY of its targets is selected
//   (header), so covering source paths is enough.
//   AUTH_CREATE covers new files (open(O_CREAT) of a new file has no AUTH_OPEN). Listings and
//   directory opens are never blocked, so AUTH_READDIR is not subscribed.
// - process client: NOTIFY_FORK/EXEC/EXIT, no muting configuration shared with the file client.
//
// AUTH callback: build the FileActivity, decide from in-memory state (Enforcer: classifier +
// process tree + rules), respond immediately, then hand logging to a queue. No disk IO, no XPC,
// no UI on the callback path. Anything unexpected → allow. Ask mode (docs/ASK_MODE.md): an access
// nothing decides is retained and handed to the AskBroker, which answers it later from its own
// queue; the callback still returns at once. An ask that cannot be held is denied at once: ask
// means enforcement is active and nothing allowed the access.
public final class NativeESSource: EventSource, @unchecked Sendable {
    public let kind = SourceKind.native
    public let canEnforce = true

    private weak var core: DaemonCore?
    private let decider: AuthDecider
    private let stateBox = StateBox()
    private var sink: EventSink?

    // ES client handles are only created/deleted on `clientThread`, so a delete never races a create,
    // a mute or another delete (es_delete_client needs exclusive access to its client).
    private var fileClient: OpaquePointer?
    private var procClient: OpaquePointer?
    /// The clients' gates (client thread only). The file client's AUTH handler and held answers call
    /// es_* functions (respond, retain, release); the process client's handler calls es_exec_arg_count
    /// and es_exec_arg on every exec.
    private var fileGate: NativeClientGate?
    private var procGate: NativeClientGate?
    /// The clients' handler calls, for the drain before a delete where es_sync_client is missing
    /// (client thread only).
    private var fileActivity: NativeHandlerActivity?
    private var procActivity: NativeHandlerActivity?
    /// The shortest stall the file handler's watchdog waits for (DaemonCore.watchdogStallFloor).
    private let watchdogFloor: TimeInterval
    /// The file client's handler watchdog, armed once the client is connected. Under `lock`: stop()
    /// cancels it before waiting for the client thread.
    private var fileWatchdog: NativeHandlerWatchdog?
    private static let watchdogQueue = DispatchQueue(label: "whoread.native.watchdog", qos: .utility)
    private let clientThread = ClientThread()
    private let eventQueue = DispatchQueue(label: "whoread.native.events", qos: .userInitiated)
    private let deniedQueue = DispatchQueue(label: "whoread.native.denied", qos: .utility)
    /// What the callback must not do itself (logging). Serial, so a burst of failures queues up instead
    /// of parking a pool thread per message on Log's lock.
    private static let reportQueue = DispatchQueue(label: "whoread.native.report", qos: .userInitiated)

    /// Ask mode: held messages answer through the file client, so they are held only while it exists.
    /// Taken across the check and `AskBroker.hold` (short, never blocks), so stop and abortSetup can
    /// close it and then deny everything held before es_delete_client. Never taken in a `respond`
    /// closure, which may run under the broker's lock: hence not `lock`, which those closures take.
    private let askGate = NSLock()
    private var asksOpen = false
    /// Every message held right now, so closeAsks can answer what the broker did not.
    private let heldMessages = NativeHeldMessages()

    private let lock = NSLock()
    private var mutedPrefixes = Set<NativeMutePlan.Path>()
    private var mutedLiterals = Set<NativeMutePlan.Path>()
    private var authSubscribed = false
    private var pendingNotify = 0
    private var droppedNotify: UInt64 = 0
    private var denials = NativeDenialBacklog()
    private var fileSequence = NativeSequenceGaps()
    private var processSequence = NativeSequenceGaps()
    /// The file client's deadline miss mode is fail-closed: an answer after the deadline, and an AUTH
    /// message the kernel drops, mean denied (NativeLateAnswer, NativeAuthDrops).
    private var fileFailClosed = false
    private var authDrops = NativeAuthDrops()
    /// Accesses allowed but answered too late, or not delivered, in fail-closed mode: the kernel denied them.
    private var lateDenials: UInt64 = 0
    /// Program paths the file client's default mute set mutes for its AUTH events (nil: not read).
    private var defaultMutedPrograms: Int?
    /// Processes with a monitored file open for writing (was_mapped_writable closes).
    private var writableOpens = NativeWritableOpens()
    /// Local APFS volumes (st_dev), where a directory's stat tells whether it is empty.
    private var apfsDevices = Set<Int32>()
    // Client thread only.
    private var readdir = false
    /// The default mute set last logged, so a reconnect logs it only when it changed.
    private var loggedDefaultMutes: [NativeDefaultMutes.Entry]?
    private var retryTimer: DispatchSourceTimer?
    private var retryDelay = NativeESSource.initialRetryDelay
    private var lastError: String?
    private var stopped = false
    private var lastCacheClear = Date.distantPast
    private var cacheClearPending = false

    /// How long `delete` waits for the es_* calls still running on a client before giving up on it.
    static let deleteWait: TimeInterval = 1
    /// How long `stop` waits for the client thread. It covers closeAsks' bounded waits (the broker's
    /// denyAll, then the held messages) and both clients' drains and deletes (`stopWaitCovers`), so
    /// that held and queued accesses are answered and the clients deleted by us before the process exits.
    static let stopWait: TimeInterval = 8
    static var stopWaitCovers: TimeInterval {
        AskBroker.denyAllWait + NativeHeldMessages.denyAllWait + 2 * (NativeDrain.wait + deleteWait)
    }
    private static let initialRetryDelay: TimeInterval = 5
    private static let maxRetryDelay: TimeInterval = 60
    /// NOTIFY events queued for analysis. Past this, new ones are dropped (and counted) instead of
    /// growing memory without bound; ES never backs up because the handler returns at once.
    static let maxPendingNotify = 50_000
    private static let mutingError = "es_mute_path failed for every monitored prefix"

    private static let timebase: mach_timebase_info_data_t = {
        var tb = mach_timebase_info_data_t()
        _ = mach_timebase_info(&tb)
        return tb
    }()

    public init(core: DaemonCore) {
        self.core = core
        self.decider = core.enforcer
        self.readdir = core.currentSettings.readdirEnabled
        self.watchdogFloor = core.watchdogStallFloor
        NativeStallMarker.setPath(core.config.inMemoryStore ? nil : core.config.watchdogStallMarkerPath)
    }

    public var state: SourceState { stateBox.get() }

    public var authCounts: SourceAuthCounts? {
        lock.lock(); defer { lock.unlock() }
        return SourceAuthCounts(lateDenied: lateDenials, droppedDenied: authDrops.denied, droppedAllowed: authDrops.allowed,
                                defaultMutedPrograms: defaultMutedPrograms)
    }

    public var droppedEvents: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return droppedNotify &+ denials.unrecorded
    }

    public var kernelDroppedEvents: UInt64? {
        lock.lock(); defer { lock.unlock() }
        return fileSequence.dropped &+ processSequence.dropped
    }

    // MARK: - Event lists

    // SETMODE, SETOWNER, SETACL and SETATTRLIST support target-path muting (header list), so only
    // monitored paths are delivered. MOUNT does not: every mount on the system is delivered (they are
    // rare), and only a mount point at or inside a monitored prefix classifies.
    static let notifyFileEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_CLONE,
        ES_EVENT_TYPE_NOTIFY_COPYFILE, ES_EVENT_TYPE_NOTIFY_LINK, ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_NOTIFY_TRUNCATE,
        ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_NOTIFY_SETMODE, ES_EVENT_TYPE_NOTIFY_SETOWNER, ES_EVENT_TYPE_NOTIFY_SETACL, ES_EVENT_TYPE_NOTIFY_SETATTRLIST,
        ES_EVENT_TYPE_NOTIFY_MOUNT,
    ]
    static let authFileEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_AUTH_CLONE, ES_EVENT_TYPE_AUTH_COPYFILE,
        ES_EVENT_TYPE_AUTH_LINK, ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
        ES_EVENT_TYPE_AUTH_CREATE,
        ES_EVENT_TYPE_AUTH_SETMODE, ES_EVENT_TYPE_AUTH_SETOWNER, ES_EVENT_TYPE_AUTH_SETACL, ES_EVENT_TYPE_AUTH_SETATTRLIST,
        ES_EVENT_TYPE_AUTH_MOUNT,
    ]
    static let processEvents: [es_event_type_t] = [ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT]

    // MARK: - Lifecycle

    public func start(sink: EventSink) throws {
        self.sink = sink
        clientThread.start()
        clientThread.run { self.connect() }
    }

    public func stop() {
        // A clean stop is not a death while enforcing (see DaemonCore's start-up check).
        disarm()
        // A stop that takes a while is no stall: the watchdog must not exit under it.
        lock.lock()
        let watchdog = fileWatchdog
        lock.unlock()
        watchdog?.cancel()
        // Waits (bounded): the process exits right after Daemon.stop(), and held accesses must be
        // denied and the clients deleted by us first, not left to the kernel's teardown.
        clientThread.runAndWait(timeout: NativeESSource.stopWait) {
            // After this, a retry that was already queued finds `stopped` and creates nothing.
            self.stopped = true
            self.retryTimer?.cancel()
            self.retryTimer = nil
            // Armed by a connect that ran after the cancel above.
            self.disarmWatchdog()
            self.closeAsks()
            if let c = self.fileClient { NativeESSource.retire(c, gate: self.fileGate, activity: self.fileActivity) }
            if let c = self.procClient { NativeESSource.retire(c, gate: self.procGate, activity: self.procActivity) }
            self.forgetClients()
            self.publish {
                $0.running = false
                $0.deadlineMissMode = nil
            }
        }
    }

    private func publish(_ f: (inout SourceState) -> Void) {
        let s = stateBox.update(f)
        sink?.sourceStateChanged(s)
    }

    /// Runs on the client thread. Retries with backoff while the error can still clear (FDA is often
    /// granted after the extension starts).
    private func connect() {
        guard !stopped, fileClient == nil else { return }
        var proc: OpaquePointer?
        let pGate = NativeClientGate()
        let pActivity = NativeHandlerActivity()
        // Only the conversion (message memory, es_exec_arg) runs inside the gate, not the process tree
        // update after it: a slow analyzer must not make a delete give up on the client.
        let r1 = es_new_client(&proc, NativeESSource.tracked(pActivity, NativeESSource.converting(pGate, NativeESSource.processMessage) {
            [weak self] message in self?.receiveProcess(message)
        }))
        guard r1 == ES_NEW_CLIENT_RESULT_SUCCESS, let proc else {
            fail(r1)
            return
        }
        procGate = pGate
        procActivity = pActivity
        var file: OpaquePointer?
        let gate = NativeClientGate()
        let fActivity = NativeHandlerActivity()
        let watchdog = NativeHandlerWatchdog(floor: watchdogFloor)
        let r2 = es_new_client(&file, NativeESSource.watched(watchdog, NativeESSource.tracked(fActivity) { [weak self] client, message in
            self?.handleFile(client, message, gate)
        }))
        guard r2 == ES_NEW_CLIENT_RESULT_SUCCESS, let file else {
            // Subscribed to nothing yet, so its handler never runs: no wait needed.
            _ = es_delete_client(proc)
            procGate = nil
            procActivity = nil
            fail(r2)
            return
        }
        fileGate = gate
        fileActivity = fActivity
        // Before anything is subscribed: the file client is the one that answers AUTH messages.
        let deadlineMode = NativeESSource.setDeadlineMissMode(file)
        // Before any mute of ours: what is muted now is the default mute set.
        logDefaultMutes(NativeESSource.defaultMutes(file))
        refreshAPFSDevices()
        var token = NativeESSource.selfAuditToken()
        _ = es_mute_process(proc, &token)
        _ = es_mute_process(file, &token)

        // Header order: unmute all target paths first, invert only if not inverted yet (it toggles),
        // and do it before any AUTH subscription exists. If inversion did not take, muting the
        // catalog would deliver everything EXCEPT the sensitive paths: give up and retry instead.
        guard es_unmute_all_target_paths(file) == ES_RETURN_SUCCESS else {
            abortSetup(proc, file, "es_unmute_all_target_paths failed")
            return
        }
        if es_muting_inverted(file, ES_MUTE_INVERSION_TYPE_TARGET_PATH) != ES_MUTE_INVERTED {
            _ = es_invert_muting(file, ES_MUTE_INVERSION_TYPE_TARGET_PATH)
        }
        guard es_muting_inverted(file, ES_MUTE_INVERSION_TYPE_TARGET_PATH) == ES_MUTE_INVERTED else {
            abortSetup(proc, file, "target-path mute inversion failed")
            return
        }
        procClient = proc
        fileClient = file
        // A new client starts with nothing muted and nothing subscribed.
        lock.lock()
        mutedPrefixes = []
        mutedLiterals = []
        authSubscribed = false
        fileSequence.reset()
        processSequence.reset()
        authDrops.reset()
        fileFailClosed = deadlineMode.mode == .failClosed
        lock.unlock()
        askGate.lock()
        asksOpen = true
        askGate.unlock()
        if let core {
            let c = core.analyzer.classifier
            // Every byte-distinct spelling (catalog and on-disk); the mute plan adds realpath / NFC / NFD.
            guard applyMuting(prefixes: c.mutePaths, ancestors: c.ancestors) else {
                abortSetup(proc, file, NativeESSource.mutingError)
                return
            }
        }
        // Subscribed to nothing, the clients would report running while monitoring nothing.
        guard subscribe(proc, NativeESSource.processEvents),
              subscribe(file, NativeESSource.notifyFileEvents + (readdir ? [ES_EVENT_TYPE_NOTIFY_READDIR] : [])) else {
            abortSetup(proc, file, "es_subscribe failed")
            return
        }
        if core?.enforcement.isActive == true { setAuth(true) }
        _ = es_clear_cache(file)
        retryTimer?.cancel()
        retryTimer = nil
        retryDelay = NativeESSource.initialRetryDelay
        lastError = nil
        publish {
            $0.running = true
            $0.error = nil
            $0.hint = nil
            $0.deadlineMissMode = deadlineMode.name
        }
        lock.lock()
        fileWatchdog = watchdog
        lock.unlock()
        watchdog.start(queue: NativeESSource.watchdogQueue) { NativeESSource.exitForStall($0) }
        Log.info("Endpoint Security clients connected (\(mutedPrefixes.count) prefixes, \(mutedLiterals.count) literal ancestors, "
                 + "deadline miss mode \(deadlineMode.name))")
    }

    /// es_set_deadline_miss_mode(file, FAIL_CLOSED) where the running macOS has it (27 and later),
    /// verified with es_get_deadline_miss_mode. Looked up at run time and called through C function
    /// pointers with the raw enum value, so the source still builds with SDKs that do not declare them.
    /// Older systems keep the default: kill. Client thread (it logs).
    static func setDeadlineMissMode(_ client: OpaquePointer) -> NativeDeadlineMissMode.Outcome {
        typealias SetFn = @convention(c) (OpaquePointer, UInt32) -> UInt32
        typealias GetFn = @convention(c) (OpaquePointer, UnsafeMutablePointer<UInt32>) -> UInt32
        let success = ES_RETURN_SUCCESS.rawValue
        let setter = NativeDeadlineMissMode.symbol(NativeDeadlineMissMode.setterName).map { unsafeBitCast($0, to: SetFn.self) }
        let getter = NativeDeadlineMissMode.symbol(NativeDeadlineMissMode.getterName).map { unsafeBitCast($0, to: GetFn.self) }
        let outcome = NativeDeadlineMissMode.configure(
            set: setter.map { f in { mode in f(client, mode) == success } },
            get: getter.map { f in {
                var mode: UInt32 = .max
                return f(client, &mode) == success ? mode : nil
            } })
        if let problem = outcome.problem {
            Log.error("Endpoint Security deadline miss mode: \(problem)")
        } else if setter == nil {
            Log.info("Endpoint Security deadline miss mode: kill (es_set_deadline_miss_mode needs macOS 27): a missed AUTH "
                     + "deadline kills the client and allows the access")
        }
        return outcome
    }

    private func fail(_ r: es_new_client_result_t) {
        let (error, hint) = NativeESSource.describe(r)
        report(error: error, hint: hint)
        // Entitlement, root and argument errors cannot change while the process runs: no retry loop.
        if r == ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED || r == ES_NEW_CLIENT_RESULT_ERR_INTERNAL
            || r == ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS {
            scheduleRetry()
        }
    }

    /// Setup failed after both clients exist: delete them (on the client thread) and retry.
    private func abortSetup(_ proc: OpaquePointer, _ file: OpaquePointer, _ message: String) {
        disarm()
        disarmWatchdog()
        closeAsks()
        NativeESSource.retire(file, gate: fileGate, activity: fileActivity)
        // The process client may already be subscribed (a later step failed): its handler may be running.
        NativeESSource.retire(proc, gate: procGate, activity: procActivity)
        forgetClients()
        report(error: message, hint: "Endpoint Security setup failed; retrying.")
        scheduleRetry()
    }

    /// The clients are gone (deleted, or left to the kernel's teardown). Client thread.
    private func forgetClients() {
        procClient = nil
        fileClient = nil
        fileGate = nil
        procGate = nil
        fileActivity = nil
        procActivity = nil
        lock.lock()
        fileFailClosed = false
        lock.unlock()
    }

    /// Unsubscribes a client, lets its handler work through what the kernel queued before (NativeDrain:
    /// es_sync_client on macOS 27, an idle handler before), then deletes it. If the drain does not finish
    /// in time, a call may still be running on the client: it is not deleted then (the process is
    /// stopping and the kernel tears it down, or a retry replaces it). Client thread (es_sync_client must
    /// not be called from the client's handler).
    static func retire(_ client: OpaquePointer, gate: NativeClientGate?, activity: NativeHandlerActivity?) {
        _ = es_unsubscribe_all(client)
        #if canImport(Darwin)
        let sync = NativeDrain.syncClientFunction(NativeDeadlineMissMode.symbol(NativeDrain.syncClientName)).map { f in
            { (block: @escaping NativeDrain.SyncBlock) in f(client, block) == ES_RETURN_SUCCESS.rawValue }
        }
        #else
        let sync: ((@escaping NativeDrain.SyncBlock) -> Bool)? = nil
        #endif
        let drained = NativeDrain.run(sync: sync, quiet: { activity?.waitQuiet(NativeDrain.quiet, waitAtMost: $0) ?? true })
        guard drained else {
            Log.error("Endpoint Security client not deleted: its handler did not finish the queued messages within "
                      + "\(Int(NativeDrain.wait)) s")
            return
        }
        delete(client, gate: gate)
    }

    /// es_delete_client once no other es_* call on the client is running (header: not safe concurrently
    /// with any of them). If one still is after the wait, the client is not deleted under it: the process
    /// is stopping (the kernel tears the client down), or a retry replaces it. Client thread.
    static func delete(_ client: OpaquePointer, gate: NativeClientGate?) {
        guard gate?.close(waitAtMost: deleteWait) ?? true else {
            Log.error("Endpoint Security client not deleted: a call on it was still running after \(Int(deleteWait)) s")
            return
        }
        _ = es_delete_client(client)
    }

    /// Cancels the file client's watchdog (client thread; stop() also cancels it from its own thread).
    private func disarmWatchdog() {
        lock.lock()
        let w = fileWatchdog
        fileWatchdog = nil
        lock.unlock()
        w?.cancel()
    }

    /// A handler block that tells `watchdog` when each call of `body` starts and returns. One lock and
    /// one clock read each way: it runs for every message.
    static func watched(_ watchdog: NativeHandlerWatchdog, _ body: @escaping es_handler_block_t) -> es_handler_block_t {
        { client, message in
            watchdog.enter(deadlineSpan: deadlineSpan(message))
            defer { watchdog.leave() }
            body(client, message)
        }
    }

    /// For an AUTH message, the nanoseconds the kernel gave it from its creation to its deadline (Mach
    /// ticks, header); 0 for a NOTIFY message, or when it cannot tell (no creation time).
    static func deadlineSpan(_ message: UnsafePointer<es_message_t>) -> UInt64 {
        guard message.pointee.action_type == ES_ACTION_TYPE_AUTH else { return 0 }
        let deadline = message.pointee.deadline
        let created = message.pointee.mach_time
        guard created > 0, deadline > created, timebase.denom != 0 else { return 0 }
        let ticks = deadline - created
        let (ns, overflow) = ticks.multipliedReportingOverflow(by: UInt64(timebase.numer))
        return overflow ? .max : ns / UInt64(timebase.denom)
    }

    /// The file client's handler is stuck (NativeHandlerWatchdog): exit, so launchd starts a fresh
    /// daemon. Touches nothing the stuck call may hold (Log's lock, the source's locks, the client
    /// thread): one write(2) to stderr, where Log writes as well, the stall marker for the next start
    /// (on a thread of its own, given at most a second), then _exit. The auth-armed marker stays too;
    /// the enforcement setting is untouched.
    static func exitForStall(_ seconds: TimeInterval) {
        let line = "\(RFC3339.format(Date(), fractionDigits: 3)) ERROR Endpoint Security file handler stuck in one call for "
            + "\(Int(seconds)) s: exiting so launchd starts a new daemon (enforcement setting unchanged)\n"
        line.withCString { _ = write(STDERR_FILENO, $0, strlen($0)) }
        NativeStallMarker.write(seconds: seconds)
        _exit(70) // EX_SOFTWARE
    }

    /// A handler block that tells `activity` when each call of `body` starts and returns.
    static func tracked(_ activity: NativeHandlerActivity, _ body: @escaping es_handler_block_t) -> es_handler_block_t {
        { client, message in
            activity.enter()
            defer { activity.leave() }
            body(client, message)
        }
    }

    /// A handler block that converts each message inside `gate` (it reads message memory, and may call
    /// es_* functions such as es_exec_arg) and hands the result to `deliver` outside it, so that a slow
    /// `deliver` never keeps a delete waiting. Once the gate is closed for deletion, nothing is converted
    /// or delivered.
    static func converting<T>(_ gate: NativeClientGate, _ convert: @escaping (UnsafePointer<es_message_t>) -> T,
                              deliver: @escaping (T) -> Void) -> es_handler_block_t {
        { _, message in
            var value: T?
            gate.use { value = convert(message) }
            if let value { deliver(value) }
        }
    }

    /// Reads the file client's mute set right after es_new_client, which is then the default mute set
    /// (NativeDefaultMutes): the programs it mutes for the AUTH events the client answers. nil when it
    /// cannot be read. Never unmuted (the header advises against it). Client thread.
    static func defaultMutes(_ client: OpaquePointer) -> [NativeDefaultMutes.Entry]? {
        var set: UnsafeMutablePointer<es_muted_paths_t>?
        // An optional pointer has the layout of the C pointer it stands for (nil = NULL).
        let r = withUnsafeMutablePointer(to: &set) { p in
            p.withMemoryRebound(to: UnsafeMutablePointer<es_muted_paths_t>.self, capacity: 1) { es_muted_paths_events(client, $0) }
        }
        guard r == ES_RETURN_SUCCESS, let set else { return nil }
        defer { es_release_muted_paths(set) }
        return NativeDefaultMutes.programs(mutedPathEntries(UnsafePointer(set)), authEvents: Set(authFileEvents.map(\.rawValue)))
    }

    /// The entries of an es_muted_paths_t (es_muted_paths_events), copied out.
    static func mutedPathEntries(_ set: UnsafePointer<es_muted_paths_t>) -> [NativeDefaultMutes.Entry] {
        let s = set.pointee
        guard s.count > 0, let paths = s.paths else { return [] }
        return (0..<s.count).map { i in
            let p = paths[i]
            let events: [UInt32]
            if p.event_count > 0, let list = p.events {
                events = (0..<p.event_count).map { list[$0].rawValue }
            } else {
                events = []
            }
            return NativeDefaultMutes.Entry(type: p.type.rawValue, path: string(p.path), events: events)
        }
    }

    /// The AUTH file events by name, for the log.
    static let authEventNames: [UInt32: String] = [
        ES_EVENT_TYPE_AUTH_OPEN.rawValue: "open", ES_EVENT_TYPE_AUTH_RENAME.rawValue: "rename", ES_EVENT_TYPE_AUTH_CLONE.rawValue: "clone",
        ES_EVENT_TYPE_AUTH_COPYFILE.rawValue: "copyfile", ES_EVENT_TYPE_AUTH_LINK.rawValue: "link", ES_EVENT_TYPE_AUTH_UNLINK.rawValue: "unlink",
        ES_EVENT_TYPE_AUTH_TRUNCATE.rawValue: "truncate", ES_EVENT_TYPE_AUTH_EXCHANGEDATA.rawValue: "exchangedata",
        ES_EVENT_TYPE_AUTH_CREATE.rawValue: "create", ES_EVENT_TYPE_AUTH_SETMODE.rawValue: "setmode",
        ES_EVENT_TYPE_AUTH_SETOWNER.rawValue: "setowner", ES_EVENT_TYPE_AUTH_SETACL.rawValue: "setacl",
        ES_EVENT_TYPE_AUTH_SETATTRLIST.rawValue: "setattrlist", ES_EVENT_TYPE_AUTH_MOUNT.rawValue: "mount",
    ]

    /// Publishes the default mute set's size and logs it when it differs from the last one logged.
    /// Client thread.
    private func logDefaultMutes(_ programs: [NativeDefaultMutes.Entry]?) {
        lock.lock()
        defaultMutedPrograms = programs?.count
        lock.unlock()
        guard let programs else {
            Log.warning("Endpoint Security default mute set could not be read (es_muted_paths_events failed)")
            return
        }
        guard programs != loggedDefaultMutes else { return }
        loggedDefaultMutes = programs
        Log.info(NativeDefaultMutes.logLine(programs) { NativeESSource.authEventNames[$0] ?? "event \($0)" })
    }

    /// The local APFS volumes (statfs f_fsid.val[0], which is their st_dev), from the kernel's mount
    /// table without waiting on any file system (getfsstat MNT_NOWAIT: a dead network mount cannot
    /// block it). Client thread.
    private func refreshAPFSDevices() {
        let devices = NativeESSource.localAPFSDevices()
        lock.lock()
        apfsDevices = devices
        lock.unlock()
    }

    static func localAPFSDevices() -> Set<Int32> {
        #if canImport(Darwin)
        let n = getfsstat(nil, 0, MNT_NOWAIT)
        guard n > 0 else { return [] }
        // Room for mounts added between the two calls.
        var mounts = [Darwin.statfs](repeating: Darwin.statfs(), count: Int(n) + 8)
        let got = mounts.withUnsafeMutableBufferPointer { buf in
            getfsstat(buf.baseAddress, Int32(buf.count * MemoryLayout<Darwin.statfs>.stride), MNT_NOWAIT)
        }
        guard got > 0 else { return [] }
        return Set(mounts.prefix(Int(got)).compactMap { fs -> Int32? in
            var fs = fs
            let type = withUnsafeBytes(of: &fs.f_fstypename) { raw -> String in
                let bytes = raw.bindMemory(to: UInt8.self)
                return String(decoding: bytes[..<(bytes.firstIndex(of: 0) ?? bytes.endIndex)], as: UTF8.self)
            }
            return type == "apfs" && fs.f_flags & UInt32(MNT_LOCAL) != 0 ? fs.f_fsid.val.0 : nil
        })
        #else
        return []
        #endif
    }

    /// Before the ES clients are deleted (client thread): hold nothing more, then deny everything held
    /// while the client its `respond` closures answer through still exists. The broker's denyAll returns
    /// once every access it holds is answered; whatever is still held after it is denied here, so no
    /// message outlives its client whatever the broker does.
    private func closeAsks() {
        askGate.lock()
        asksOpen = false
        askGate.unlock()
        // Bounded: a response stuck on the broker's queue must not hold up the stop. Whatever it did not
        // answer is denied just below (fail closed).
        if decider.askBroker?.denyAll() == false {
            Log.warning("ask mode: the broker did not answer its held accesses within \(Int(AskBroker.denyAllWait)) s; denying them here")
        }
        let missed = heldMessages.denyAll()
        if missed > 0 { Log.warning("ask mode: \(missed) held accesses left unanswered by the broker; denied") }
    }

    /// Publishes and logs a setup error once, not on every retry.
    private func report(error: String, hint: String) {
        guard error != lastError else { return }
        lastError = error
        publish {
            $0.running = false
            $0.error = error
            $0.hint = hint
            // No file client exists any more (setup failed or never got that far).
            $0.deadlineMissMode = nil
        }
        Log.warning("Endpoint Security setup failed: \(error)")
    }

    /// One-shot retry, backing off from 5 s to 60 s.
    private func scheduleRetry() {
        guard !stopped, retryTimer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: .global())
        t.schedule(deadline: .now() + retryDelay)
        t.setEventHandler { [weak self] in
            self?.clientThread.run {
                self?.retryTimer?.cancel()
                self?.retryTimer = nil
                self?.connect()
            }
        }
        t.resume()
        retryTimer = t
        retryDelay = min(retryDelay * 2, NativeESSource.maxRetryDelay)
    }

    static func describe(_ r: es_new_client_result_t) -> (String, String) {
        switch r {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            return ("ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED",
                    "Full Disk Access is missing. System Settings → Privacy & Security → Full Disk Access → enable WhoRead.")
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            return ("ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED",
                    "Missing com.apple.developer.endpoint-security.client (needs Apple approval, or SIP disabled for development).")
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            return ("ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED", "Must run as root.")
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            return ("ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS", "Too many Endpoint Security clients are running.")
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
            return ("ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT", "Internal error.")
        default:
            return ("es_new_client error \(r.rawValue)", "Endpoint Security is unavailable.")
        }
    }

    @discardableResult
    private func subscribe(_ client: OpaquePointer, _ events: [es_event_type_t]) -> Bool {
        events.withUnsafeBufferPointer { buf in
            if es_subscribe(client, buf.baseAddress!, UInt32(buf.count)) != ES_RETURN_SUCCESS {
                Log.error("es_subscribe failed for \(events.map(\.rawValue))")
                return false
            }
            return true
        }
    }

    private func unsubscribe(_ client: OpaquePointer, _ events: [es_event_type_t]) {
        events.withUnsafeBufferPointer { buf in
            _ = es_unsubscribe(client, buf.baseAddress!, UInt32(buf.count))
        }
    }

    // MARK: - Muting

    /// Diffs the wanted mute set against what this client has muted. Returns false when prefixes are
    /// wanted but none is muted: inverted muting then selects nothing, so nothing is monitored.
    @discardableResult
    private func applyMuting(prefixes: [String], ancestors: [String]) -> Bool {
        guard let file = fileClient else { return true }
        let resolver = RealpathSymlinkResolver()
        let normalizer = core?.analyzer.classifier.normalizer ?? PathNormalizer()
        let plan = NativeMutePlan.plan(prefixes: prefixes, ancestors: ancestors, homes: normalizer.homeDirectories,
                                       normalize: normalizer.normalize, resolve: resolver.resolve)
        lock.lock()
        let oldPrefixes = mutedPrefixes
        let oldLiterals = mutedLiterals
        lock.unlock()
        // Diff instead of unmute-all: the header asks for no AUTH subscriptions around unmute-all.
        for p in oldPrefixes.subtracting(plan.prefixes) { _ = es_unmute_path(file, p.path, ES_MUTE_PATH_TYPE_TARGET_PREFIX) }
        for p in oldLiterals.subtracting(plan.literals) { _ = es_unmute_path(file, p.path, ES_MUTE_PATH_TYPE_TARGET_LITERAL) }
        // Remember only what actually got muted, so a failed path is retried on the next update.
        var nowPrefixes = oldPrefixes.intersection(plan.prefixes)
        var nowLiterals = oldLiterals.intersection(plan.literals)
        for p in plan.prefixes.subtracting(oldPrefixes) {
            if es_mute_path(file, p.path, ES_MUTE_PATH_TYPE_TARGET_PREFIX) == ES_RETURN_SUCCESS {
                nowPrefixes.insert(p)
            } else {
                Log.warning("es_mute_path prefix failed: \(p.path)")
            }
        }
        for p in plan.literals.subtracting(oldLiterals) {
            if es_mute_path(file, p.path, ES_MUTE_PATH_TYPE_TARGET_LITERAL) == ES_RETURN_SUCCESS {
                nowLiterals.insert(p)
            } else {
                Log.warning("es_mute_path literal failed: \(p.path)")
            }
        }
        lock.lock()
        mutedPrefixes = nowPrefixes
        mutedLiterals = nowLiterals
        lock.unlock()
        return plan.prefixes.isEmpty || !nowPrefixes.isEmpty
    }

    /// A connected client whose mute set selects nothing monitors nothing: show it in the state.
    private func reportMuting(_ ok: Bool) {
        let current = state.error
        if !ok && current != NativeESSource.mutingError {
            publish {
                $0.running = false
                $0.error = NativeESSource.mutingError
                $0.hint = "File events are not monitored; the next catalog or settings change retries."
            }
            Log.error(NativeESSource.mutingError)
        } else if ok && current == NativeESSource.mutingError {
            publish {
                $0.running = true
                $0.error = nil
                $0.hint = nil
            }
        }
    }

    public func updateMonitoring(prefixes: [String], ancestors: [String], readdir newReaddir: Bool) {
        clientThread.run {
            // Volumes come and go; the catalog changes with them (homes on external volumes).
            if self.fileClient != nil { self.refreshAPFSDevices() }
            let ok = self.applyMuting(prefixes: prefixes, ancestors: ancestors)
            if newReaddir != self.readdir, let file = self.fileClient {
                // NOTIFY only: listings are never blocked (Enforcer), so there is no AUTH_READDIR.
                if newReaddir {
                    self.subscribe(file, [ES_EVENT_TYPE_NOTIFY_READDIR])
                } else {
                    self.unsubscribe(file, [ES_EVENT_TYPE_NOTIFY_READDIR])
                }
            }
            self.readdir = newReaddir
            if self.fileClient != nil { self.reportMuting(ok) }
            self.clearCacheSoon()
        }
    }

    public func enforcementChanged(active: Bool) {
        clientThread.run { self.setAuth(active) }
    }

    private func setAuth(_ on: Bool) {
        guard let file = fileClient else { return }
        let events = NativeESSource.authFileEvents
        lock.lock()
        let current = authSubscribed
        lock.unlock()
        var now = on
        if on && !current {
            // Failed: nothing is enforced, so NOTIFY events must not be treated as `.afterAuth`.
            now = subscribe(file, events)
        } else if !on && current {
            unsubscribe(file, events)
        }
        lock.lock()
        authSubscribed = now
        lock.unlock()
        if now && !current { arm() } else if !now && current { disarm() }
        clearCacheSoon()
    }

    /// The marker exists exactly while AUTH events are subscribed. If the daemon dies while it exists
    /// (the kernel killed it for a missed deadline, a crash), the next start finds it and reports an
    /// unclean stop; enforcement stays as the user set it. Client thread only (IO).
    private func arm() {
        guard let config = core?.config, !config.inMemoryStore else { return }
        do { try SafeFile.replace(config.authArmedMarkerPath, with: Data(), mode: 0o600) } catch {
            Log.warning("could not create the auth-armed marker: \(error)")
        }
    }

    private func disarm() {
        guard let config = core?.config, !config.inMemoryStore else { return }
        unlink(config.authArmedMarkerPath)
    }

    public func policyChanged() {
        clientThread.run { self.clearCacheSoon() }
    }

    /// es_clear_cache is rate-limited (ERR_THROTTLE); coalesce bursts and retry.
    private func clearCacheSoon() {
        guard let file = fileClient else { return }
        if Date().timeIntervalSince(lastCacheClear) > 1 {
            lastCacheClear = Date()
            if es_clear_cache(file) == ES_CLEAR_CACHE_RESULT_SUCCESS { return }
        }
        guard !cacheClearPending else { return }
        cacheClearPending = true
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.2) { [weak self] in
            self?.clientThread.run {
                self?.cacheClearPending = false
                self?.clearCacheSoon()
            }
        }
    }

    // MARK: - Handlers

    /// What the process client's handler copies out of a message (inside its gate).
    struct ProcessMessage {
        let event: SourceEvent?
        /// global_seq_num (message version >= 4).
        let sequence: UInt64?
    }

    /// Reads the message and, for an exec, its arguments (es_exec_arg): only inside the client's gate.
    static func processMessage(_ msg: UnsafePointer<es_message_t>) -> ProcessMessage {
        let m = msg.pointee
        let sequence: UInt64? = m.version >= 4 ? m.global_seq_num : nil
        let time = date(m.time)
        switch m.event_type {
        case ES_EVENT_TYPE_NOTIFY_FORK:
            return ProcessMessage(event: .fork(parent: record(m.process, version: m.version),
                                               child: record(m.event.fork.child, version: m.version), time: time),
                                  sequence: sequence)
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            var target = record(m.event.exec.target, version: m.version)
            target.argv = execArgs(msg)
            return ProcessMessage(event: .exec(process: record(m.process, version: m.version), target: target, time: time),
                                  sequence: sequence)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            return ProcessMessage(event: .exit(process: record(m.process, version: m.version), time: time), sequence: sequence)
        default:
            return ProcessMessage(event: nil, sequence: sequence)
        }
    }

    /// The process client's handler, after the conversion (outside its gate).
    private func receiveProcess(_ message: ProcessMessage) {
        lock.lock()
        if let s = message.sequence { processSequence.note(s) }
        lock.unlock()
        // Process events update the in-memory tree synchronously so AUTH decisions see them asap.
        if let event = message.event { sink?.receive(event, context: .monitorOnly) }
    }

    private func handleFile(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>, _ gate: NativeClientGate) {
        let m = msg.pointee
        if m.action_type == ES_ACTION_TYPE_AUTH {
            // Its es_* calls (respond, retain) stay inside the gate: es_delete_client must not run
            // alongside. Closed means the client is being deleted; the message is left to its teardown.
            gate.use { handleAuth(client, msg, gate) }
            return
        }
        let activity = convert(msg)
        // `.afterAuth` only when this access really passed an AUTH check: AUTH subscribed and
        // enforcement live right now (the kill switch unsubscribes asynchronously). An access held in
        // ask mode and allowed by the answer passed AUTH too, so it is `.afterAuth` as well.
        // A modified close has no AUTH counterpart but is treated the same: its open passed AUTH, or
        // predates enforcement and a matching deny still alerts. As `.monitorOnly` it would turn a
        // write allowed once into "would block", and could use up a live "allow once".
        let enforcing = activity != nil && core?.enforcement.isActive == true
        lock.lock()
        if m.version >= 4 { fileSequence.note(m.global_seq_num) }
        // A descriptor opened with FWRITE, the only kind a shared writable mapping can be made from (an
        // O_TRUNC open without it writes, but cannot map): a later close reporting a writable mapping may
        // be this process's.
        if m.event_type == ES_EVENT_TYPE_NOTIFY_OPEN, UInt32(bitPattern: m.event.open.fflag) & OperationSemantics.fwrite != 0,
           let a = activity, a.operation == .open, let t = a.targets.first {
            writableOpens.noteWriteOpen(NativeESSource.owner(m), path: t.path)
        }
        let context: RuleContext = authSubscribed && enforcing ? .afterAuth : .monitorOnly
        let full = activity != nil && pendingNotify >= NativeESSource.maxPendingNotify
        if activity != nil {
            if full { droppedNotify &+= 1 } else { pendingNotify += 1 }
        }
        lock.unlock()
        guard let activity, !full else { return }
        eventQueue.async { [weak self] in
            guard let self else { return }
            self.sink?.receive(.file(activity), context: context)
            self.lock.lock()
            self.pendingNotify -= 1
            self.lock.unlock()
        }
    }

    private func handleAuth(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>, _ gate: NativeClientGate) {
        let m = msg.pointee
        let start = mach_absolute_time()
        lock.lock()
        if m.version >= 4 { fileSequence.note(m.global_seq_num) }
        let failClosed = fileFailClosed
        if m.version >= 2 { authDrops.note(type: m.event_type.rawValue, seq: m.seq_num, failClosed: failClosed) }
        lock.unlock()
        let activity = convert(msg)
        var decision = activity.map { decider.decide($0) } ?? .failOpen()
        if decision.verdict == .ask, let activity {
            // Held: the broker answers it later, and held accesses stay out of the latency stats.
            if hold(client, msg, activity, decision, gate, failClosed: failClosed) { return }
            // Not held (no broker or question, too little time, too many held, nobody to answer,
            // stopping): denied at once, recorded and timed like any other denial.
            decision = NativeESSource.askDenial(decision)
        }
        let deniedLate = NativeESSource.respond(client, msg, decision, failClosed: failClosed)
        let end = mach_absolute_time()
        let tb = NativeESSource.timebase
        // Measured from the event's Mach time (comparable to mach_absolute_time, header), so time
        // spent queued behind other messages counts toward the p99 statistics. Stats only: a slow
        // response or a missed deadline never switches enforcement off.
        let begin = m.mach_time > 0 ? min(start, m.mach_time) : start
        let micros = (end &- begin) &* UInt64(tb.numer) / UInt64(tb.denom) / 1000
        decider.recordResponse(micros: micros, missedDeadline: end >= m.deadline)
        if decision.verdict == .deny, let activity {
            recordDenial(activity, decision)
        } else if deniedLate {
            recordLateDenial(activity)
        }
    }

    /// Ask mode: hands a `.ask` access to the broker. True when held (the broker answers it, exactly
    /// once, through the closure); false when the caller must deny it at once.
    private func hold(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>, _ activity: FileActivity,
                      _ ask: RuleDecision, _ gate: NativeClientGate, failClosed: Bool) -> Bool {
        guard let broker = decider.askBroker, let request = decider.askRequest(for: activity, decision: ask) else { return false }
        let tb = NativeESSource.timebase
        let plan = NativeAskBudget(deadline: msg.pointee.deadline, now: mach_absolute_time(), numer: tb.numer, denom: tb.denom)
        // No time to ask in, and the backstop below falls before the deadline only with a budget.
        guard plan.budget > 0 else { return false }
        let denial = NativeESSource.askDenial(ask)
        askGate.lock()
        defer { askGate.unlock() }
        guard asksOpen else { return false }
        // Retained before the broker can call `respond` (from its queue, maybe before hold returns).
        // The closures use `msg` and `client` after the callback returns: valid only because the
        // message stays retained until it is answered and released, and because the client outlives
        // every held message (closeAsks answers them all before es_delete_client; the closed gate
        // holds nothing more). The denial is recorded off the callback like any other; the access is
        // answered even if the source is gone.
        es_retain_message(msg)
        let decider = self.decider
        let held = heldMessages.add(answer: { [weak self] allow in
            // A question covers one category. An "allow" is re-decided against the rules the answer
            // just saved, so the other undecided categories of the same operation (`cp ~/.ssh/id_x
            // ~/.aws/credentials`) are not let through on it; they are denied and asked on the retry.
            // Memory only, off the callback (broker queue or backstop).
            var final = denial
            if allow {
                let again = decider.decide(activity)
                final = again.verdict == .allow ? again : (again.verdict == .ask ? NativeESSource.askDenial(again) : again)
            }
            let allowed = final.verdict == .allow
            // closeAsks answers every held message before the gate closes, so it is open here.
            var deniedLate = false
            gate.use {
                deniedLate = NativeESSource.respond(client, msg, allow: allowed, cache: false, failClosed: failClosed)
                es_release_message(msg)
            }
            if !allowed {
                self?.recordDenial(activity, final)
            } else if deniedLate {
                // Answered "allow" after the deadline (a slow broker queue): the kernel denied it.
                self?.recordLateDenial(activity)
            }
        }, release: { es_release_message(msg) })
        let heldMessages = self.heldMessages
        let respond: @Sendable (Bool) -> Void = { allow in heldMessages.finish(held, allow: allow) }
        switch broker.hold(request, budget: plan.budget, respond: { respond($0 == .allow) }) {
        case .held(let id):
            // Backstop: should the broker never answer, deny before the kernel deadline (a miss gets
            // the daemon killed and the access allowed). A no-op once the broker has answered.
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + plan.backstop) { respond(false) }
            // Enforcement went off between the decision and this hold: the observer's release may
            // already have run, so release it here (the re-decide then allows: enforcement inactive).
            // The state flips before the observer is queued, so one of the two always sees it.
            if core?.enforcement.isActive == false { broker.resolve(id: id, answer: .allow) }
            return true
        case .denyNow:
            // `respond` is never called for it: release, and the caller answers at once inside the
            // handler. (Already answered, against the contract: nothing is left to do.)
            return !heldMessages.abandon(held)
        }
    }

    /// What an ask that was not answered in time (or could not be held) becomes.
    static func askDenial(_ ask: RuleDecision) -> RuleDecision {
        RuleDecision(verdict: .deny, reason: .askUser, askKey: ask.askKey)
    }

    /// What an access the daemon allowed is recorded as when the kernel denied it after all
    /// (NativeLateAnswer): denied, by no rule. No alert: nothing the user can answer or allow would have
    /// changed it (`whoread status` counts these, and the event shows it).
    static let lateDenial = RuleDecision(verdict: .deny, reason: .deadlineMissed, suppressAlert: true)

    /// The kernel denied an access the daemon allowed (fail-closed): counted, and recorded as a denial
    /// when the message could be converted.
    private func recordLateDenial(_ activity: FileActivity?) {
        lock.lock()
        lateDenials &+= 1
        lock.unlock()
        if let activity { recordDenial(activity, NativeESSource.lateDenial) }
    }

    /// A denied access produces no NOTIFY: record it off the callback path. The backlog merges repeats
    /// and counts the excess instead of growing without bound (NativeDenialBacklog).
    private func recordDenial(_ activity: FileActivity, _ decision: RuleDecision) {
        lock.lock()
        let ticket = denials.admit { NativeDenialBacklog.Key(activity, decision) }
        lock.unlock()
        guard let ticket else { return }
        deniedQueue.async { [weak self] in
            guard let self else { return }
            self.sink?.receive(.file(activity), context: .decided(decision))
            self.lock.lock()
            self.denials.finish(ticket)
            self.lock.unlock()
        }
    }

    /// Only `.allow` allows: an undecided `.ask` never gets here (handleFile holds or denies it), and
    /// would be denied. Returns true when the kernel denied it although it was allowed (NativeLateAnswer).
    @discardableResult
    static func respond(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>, _ d: RuleDecision, failClosed: Bool) -> Bool {
        let allow = d.verdict == .allow
        // Cache only if no enforced rule denies this process anything here: a cached narrower mask
        // would deny a later open in the kernel with no AUTH event (no log, no alert), and keep doing
        // so after the kill switch.
        return respond(client, msg, allow: allow, cache: allow && d.cacheable && d.policyDenied.isEmpty, failClosed: failClosed)
    }

    /// Any thread (an answer to a held message comes from the broker's queue; the message is retained).
    /// `failClosed`: the client's deadline miss mode. Returns true when the kernel denied the access
    /// although `allow` was wanted: in fail-closed mode an allow is not sent at or after the deadline
    /// (a deny is), and an allow es_respond did not deliver is denied at the deadline (NativeLateAnswer).
    @discardableResult
    static func respond(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>, allow: Bool, cache: Bool, failClosed: Bool) -> Bool {
        let isOpen = msg.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN
        var result = ES_RESPOND_RESULT_SUCCESS
        let deniedLate = NativeLateAnswer.answer(allow: allow, failClosed: failClosed, deadline: msg.pointee.deadline,
                                                 now: { mach_absolute_time() }) { send in
            if isOpen {
                // Deny with 0 and never cache it. Allow with UINT32_MAX (header: unless intentionally
                // denying flags): an allow never needs a mask, because any requested bit an enforced rule
                // denies already makes the verdict deny.
                result = es_respond_flags_result(client, msg, send ? UInt32.max : 0, send && cache)
            } else {
                // CREATE, RENAME, CLONE, COPYFILE, LINK, UNLINK, TRUNCATE, EXCHANGEDATA, SETACL, SETATTRLIST: no
                // caching (header). SETMODE, SETOWNER and MOUNT could be cached, but their cache key (executable,
                // file) ignores the process chain, so a cached allow would also let the same program through
                // under an AI agent: never cached.
                result = es_respond_auth_result(client, msg, send ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false)
            }
            return result.rawValue
        }
        if result != ES_RESPOND_RESULT_SUCCESS {
            // Logging writes to disk: never on the callback thread. Copy plain values, not `msg`.
            let r = result.rawValue
            let t = msg.pointee.event_type.rawValue
            reportQueue.async { Log.error("es_respond failed (\(r)) for event type \(t)") }
        }
        return deniedLate
    }

    // MARK: - Conversion

    static func string(_ t: es_string_token_t) -> String {
        guard t.length > 0, let data = t.data else { return "" }
        return data.withMemoryRebound(to: UInt8.self, capacity: t.length) {
            String(decoding: UnsafeBufferPointer(start: $0, count: t.length), as: UTF8.self)
        }
    }

    static func path(_ f: UnsafeMutablePointer<es_file_t>) -> (path: String, truncated: Bool) {
        (string(f.pointee.path), f.pointee.path_truncated)
    }

    /// The path plus what the es_file_t's stat says about it (file type bits of 0 = unknown).
    static func reported(_ f: UnsafeMutablePointer<es_file_t>) -> ReportedPath {
        let mode = UInt32(f.pointee.stat.st_mode)
        return ReportedPath(string(f.pointee.path), truncated: f.pointee.path_truncated,
                            isDirectory: mode & 0o170000 == 0 ? nil : OperationSemantics.isDirectory(mode: mode))
    }

    /// A "new path" destination: parent directory + file name.
    static func newPath(_ dir: UnsafeMutablePointer<es_file_t>, _ name: es_string_token_t) -> ReportedPath {
        ReportedPath(OperationSemantics.join(dir: string(dir.pointee.path), name: string(name)), truncated: dir.pointee.path_truncated)
    }

    /// statfs f_mntonname: a NUL-terminated char[MAXPATHLEN] (cut at the buffer's end if it is not).
    static func mountPoint(_ sfs: UnsafeMutablePointer<statfs>) -> String {
        withUnsafeBytes(of: &sfs.pointee.f_mntonname) { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            let end = bytes.firstIndex(of: 0) ?? bytes.endIndex
            return String(decoding: bytes[..<end], as: UTF8.self)
        }
    }

    static func record(_ p: UnsafeMutablePointer<es_process_t>, version: UInt32) -> ProcessRecord {
        let proc = p.pointee
        let cdhash = withUnsafeBytes(of: proc.cdhash) { raw in raw.map { String(format: "%02x", $0) }.joined() }
        let signing = string(proc.signing_id)
        let team = string(proc.team_id)
        var start: Date?
        var responsible: Int32?
        if version >= 3 {
            start = Date(timeIntervalSince1970: TimeInterval(proc.start_time.tv_sec) + TimeInterval(proc.start_time.tv_usec) / 1_000_000)
        }
        if version >= 4 { responsible = audit_token_to_pid(proc.responsible_audit_token) }
        return ProcessRecord(
            pid: audit_token_to_pid(proc.audit_token),
            pidVersion: UInt32(bitPattern: audit_token_to_pidversion(proc.audit_token)),
            ppid: proc.ppid,
            originalPPID: proc.original_ppid,
            responsiblePID: responsible,
            executablePath: path(proc.executable).path,
            pathTruncated: proc.executable.pointee.path_truncated,
            signingID: signing.isEmpty ? nil : signing,
            teamID: team.isEmpty ? nil : team,
            cdhash: cdhash,
            isPlatformBinary: proc.is_platform_binary,
            argv: nil,
            startTime: start,
            euid: audit_token_to_euid(proc.audit_token))
    }

    /// es_exec_arg reads data stored after the struct inside the message buffer, so it must get a
    /// pointer into the original message, not a copy of `event.exec`.
    static func execArgs(_ msg: UnsafePointer<es_message_t>) -> [String] {
        guard let offset = MemoryLayout<es_message_t>.offset(of: \es_message_t.event) else { return [] }
        let exec = (UnsafeRawPointer(msg) + offset).assumingMemoryBound(to: es_event_exec_t.self)
        let count = es_exec_arg_count(exec)
        return (0..<count).map { string(es_exec_arg(exec, $0)) }
    }

    static func date(_ ts: timespec) -> Date {
        Date(timeIntervalSince1970: TimeInterval(ts.tv_sec) + TimeInterval(ts.tv_nsec) / 1_000_000_000)
    }

    /// The message's FileActivity, with the source's own state for what the message alone cannot tell
    /// (the local APFS volumes; which processes opened a file for writing). Any thread; takes `lock`
    /// only for a rename onto an existing file and a close of an unmodified, mapped file.
    private func convert(_ msg: UnsafePointer<es_message_t>) -> FileActivity? {
        NativeESSource.activity(msg, onAPFS: { dev in
            lock.lock(); defer { lock.unlock() }
            return apfsDevices.contains(dev)
        }, openedForWriting: { owner, path in
            lock.lock(); defer { lock.unlock() }
            return writableOpens.contains(owner, path: path)
        })
    }

    /// The message's process for NativeWritableOpens: pid and start time (message version >= 3).
    static func owner(_ m: es_message_t) -> NativeWritableOpens.Owner {
        let p = m.process.pointee
        let start: UInt64? = m.version >= 3
            ? UInt64(clamping: Int64(p.start_time.tv_sec)) &* 1_000_000 &+ UInt64(clamping: Int64(p.start_time.tv_usec))
            : nil
        return NativeWritableOpens.Owner(pid: audit_token_to_pid(p.audit_token), start: start)
    }

    /// Whether an existing file reported by ES is an empty directory (NativeEmptyDirectory).
    static func isEmptyDirectory(_ f: UnsafeMutablePointer<es_file_t>, onAPFS: (Int32) -> Bool) -> Bool {
        let st = f.pointee.stat
        let mode = UInt32(st.st_mode)
        // Cheap checks first: the device lookup takes a lock.
        guard mode & 0o170000 == 0o040000, st.st_nlink == 2 else { return false }
        return NativeEmptyDirectory.isEmpty(mode: mode, nlink: UInt32(st.st_nlink), size: Int64(st.st_size), flags: st.st_flags,
                                            onAPFS: onAPFS(Int32(st.st_dev)))
    }

    /// Same per-operation semantics as the eslogger parser (OperationSemantics). `onAPFS` tells whether a
    /// device (st_dev) is a local APFS volume; `openedForWriting` whether a process opened a path
    /// for writing (NativeWritableOpens). Both are asked only when the message needs them.
    static func activity(_ msg: UnsafePointer<es_message_t>, onAPFS: (Int32) -> Bool = { _ in false },
                         openedForWriting: (NativeWritableOpens.Owner, String) -> Bool = { _, _ in false }) -> FileActivity? {
        let m = msg.pointee
        let e = m.event
        let targets: [FileTarget]
        let op: FileOperation
        switch m.event_type {
        case ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_NOTIFY_OPEN:
            // A directory open (stat says so) only lists names: reported as readdir.
            let r = OperationSemantics.open(reported(e.open.file), fflag: UInt32(bitPattern: e.open.fflag))
            op = r.0
            targets = r.1
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            op = .close
            let target = reported(e.close.target)
            // `modified`: written through write calls on this descriptor. A file changed only through a
            // writable mapping reports modified false and was_mapped_writable true (message version >= 6,
            // header), but the flag covers the vnode's whole life: it is charged only to a process that
            // opened this file for writing itself (NativeWritableOpens), as a possible modification.
            var modified = e.close.modified
            if !modified && m.version >= 6 && e.close.was_mapped_writable {
                modified = openedForWriting(owner(m), target.path)
            }
            targets = OperationSemantics.close(target, modified: modified)
        case ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_NOTIFY_RENAME:
            op = .rename
            let dst: ReportedPath
            if e.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                let existing = e.rename.destination.existing_file
                if isEmptyDirectory(existing, onAPFS: onAPFS) {
                    // Nothing below it to carry out (files-5): judged as a rename to a new path, which the
                    // source's object replaces (its type is the source's).
                    dst = ReportedPath(string(existing.pointee.path), truncated: existing.pointee.path_truncated)
                } else {
                    dst = reported(existing)
                }
            } else {
                dst = newPath(e.rename.destination.new_path.dir, e.rename.destination.new_path.filename)
            }
            targets = OperationSemantics.rename(reported(e.rename.source), dst)
        case ES_EVENT_TYPE_AUTH_CLONE, ES_EVENT_TYPE_NOTIFY_CLONE:
            op = .clone
            targets = OperationSemantics.clone(reported(e.clone.source), newPath(e.clone.target_dir, e.clone.target_name))
        case ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_NOTIFY_COPYFILE:
            op = .copyfile
            let dst: ReportedPath
            if let existing = e.copyfile.target_file {
                dst = reported(existing)
            } else {
                dst = newPath(e.copyfile.target_dir, e.copyfile.target_name)
            }
            targets = OperationSemantics.copyfile(reported(e.copyfile.source), dst)
        case ES_EVENT_TYPE_AUTH_LINK, ES_EVENT_TYPE_NOTIFY_LINK:
            op = .link
            targets = OperationSemantics.link(reported(e.link.source), newPath(e.link.target_dir, e.link.target_filename))
        case ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_NOTIFY_UNLINK:
            op = .unlink
            targets = OperationSemantics.unlink(reported(e.unlink.target))
        case ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            op = .truncate
            targets = OperationSemantics.truncate(reported(e.truncate.target))
        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
            op = .exchangedata
            targets = OperationSemantics.exchangedata(reported(e.exchangedata.file1), reported(e.exchangedata.file2))
        case ES_EVENT_TYPE_AUTH_READDIR, ES_EVENT_TYPE_NOTIFY_READDIR:
            op = .readdir
            targets = OperationSemantics.readdir(reported(e.readdir.target))
        case ES_EVENT_TYPE_AUTH_CREATE, ES_EVENT_TYPE_NOTIFY_CREATE:
            // A new file, directory, link or node. AUTH: every kind (a new file's open(O_CREAT) has no
            // AUTH_OPEN). NOTIFY: only what no open records (symlink, mkdir, mknod): a new regular file
            // comes with a creating NOTIFY_OPEN, and a NEW_PATH destination means an ES client denied
            // the create (header), so nothing exists; ours are recorded from AUTH.
            let notify = m.event_type == ES_EVENT_TYPE_NOTIFY_CREATE
            op = .create
            let dst: ReportedPath
            if e.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                let file = e.create.destination.existing_file
                if notify && UInt32(file.pointee.stat.st_mode) & 0o170000 == 0o100000 { return nil }
                dst = reported(file)
            } else {
                if notify { return nil }
                var path = newPath(e.create.destination.new_path.dir, e.create.destination.new_path.filename)
                // What is being created: a symlink at a parent of monitored prefixes is decided, a
                // directory is not. The header does not say whether `mode` holds the file type
                // (UNVERIFIED): used only when it does, the type stays unknown otherwise.
                let mode = UInt32(e.create.destination.new_path.mode)
                if mode & 0o170000 != 0 { path.isDirectory = OperationSemantics.isDirectory(mode: mode) }
                dst = path
            }
            targets = OperationSemantics.create(dst)
        case ES_EVENT_TYPE_AUTH_SETMODE, ES_EVENT_TYPE_NOTIFY_SETMODE:
            op = .setmode
            targets = OperationSemantics.attributes(reported(e.setmode.target))
        case ES_EVENT_TYPE_AUTH_SETOWNER, ES_EVENT_TYPE_NOTIFY_SETOWNER:
            op = .setowner
            targets = OperationSemantics.attributes(reported(e.setowner.target))
        case ES_EVENT_TYPE_AUTH_SETACL, ES_EVENT_TYPE_NOTIFY_SETACL:
            op = .setacl
            targets = OperationSemantics.attributes(reported(e.setacl.target))
        case ES_EVENT_TYPE_AUTH_SETATTRLIST, ES_EVENT_TYPE_NOTIFY_SETATTRLIST:
            // Only when it changes what chmod, chown or chmod +a would: anything else is allowed (AUTH)
            // and not recorded.
            guard let o = OperationSemantics.setattrlistOperation(commonattr: e.setattrlist.attrlist.commonattr) else { return nil }
            op = o
            targets = OperationSemantics.attributes(reported(e.setattrlist.target))
        case ES_EVENT_TYPE_AUTH_MOUNT, ES_EVENT_TYPE_NOTIFY_MOUNT:
            op = .mount
            targets = OperationSemantics.mount(mountPoint: mountPoint(e.mount.statfs))
        default:
            return nil
        }
        guard !targets.isEmpty else { return nil }
        let seq: UInt64? = m.version >= 4 ? m.global_seq_num : nil
        return FileActivity(time: date(m.time), sequence: seq, operation: op, process: record(m.process, version: m.version),
                            targets: targets)
    }

    static func selfAuditToken() -> audit_token_t {
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        _ = withUnsafeMutablePointer(to: &token) { p in
            p.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        return token
    }
}

/// A thread that runs blocks serially, so ES clients are created and deleted on one thread.
final class ClientThread: @unchecked Sendable {
    private var thread: Thread?
    private let condition = NSCondition()
    private var blocks: [() -> Void] = []

    func start() {
        guard thread == nil else { return }
        let t = Thread { [weak self] in self?.loop() }
        t.name = "whoread.es.clients"
        thread = t
        t.start()
    }

    func run(_ block: @escaping () -> Void) {
        condition.lock()
        blocks.append(block)
        condition.signal()
        condition.unlock()
    }

    /// Runs the block on the client thread and waits for it (bounded). Inline when already on it.
    func runAndWait(timeout: TimeInterval, _ block: @escaping () -> Void) {
        if let thread, Thread.current === thread {
            block()
            return
        }
        let done = DispatchSemaphore(value: 0)
        run {
            block()
            done.signal()
        }
        _ = done.wait(timeout: .now() + timeout)
    }

    private func loop() {
        while true {
            condition.lock()
            while blocks.isEmpty { condition.wait() }
            let next = blocks.removeFirst()
            condition.unlock()
            next()
        }
    }
}
#endif
