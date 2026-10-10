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

/// Liveness of the file client's handler block, which the kernel calls serially: one call that never
/// returns holds up every message behind it. In the default kill mode the kernel kills the daemon at
/// the first missed AUTH deadline and launchd starts a new one. In fail-closed mode (macOS 27) nothing
/// does: every AUTH access behind the stuck call is denied at its deadline, for as long as the daemon
/// lives, and nothing is recorded. The watchdog notices one call that has been running far longer than
/// any deadline and calls `onStall` (the source logs and exits, so launchd starts a fresh daemon; the
/// enforcement setting is untouched, and the auth-armed marker left behind makes the next start report
/// an unclean stop). Only a call that entered and has not returned counts, never idle time. Uptime
/// clock: it pauses while the Mac sleeps. Outside the EndpointSecurity guard so it is unit-tested on
/// any host.
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

    private let lock = NSLock()
    /// When the call inside started (uptime ns), nil while none is.
    private var enteredAt: UInt64?
    /// The longest time an AUTH message was given to its deadline (ns).
    private var longestDeadline: UInt64 = 0
    private var fired = false
    private var cancelled = false
    private var timer: DispatchSourceTimer?
    private let now: () -> UInt64

    init(now: @escaping () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }) {
        self.now = now
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
        return max(NativeHandlerWatchdog.minimumStall, byDeadline)
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
    // Client thread only.
    private var readdir = false
    private var retryTimer: DispatchSourceTimer?
    private var retryDelay = NativeESSource.initialRetryDelay
    private var lastError: String?
    private var stopped = false
    private var lastCacheClear = Date.distantPast
    private var cacheClearPending = false

    /// How long `delete` waits for the es_* calls still running on a client before giving up on it.
    static let deleteWait: TimeInterval = 1
    /// How long `stop` waits for the client thread. It covers closeAsks' bounded wait and both clients'
    /// deletes (`stopWaitCovers`), plus some for the broker's own denyAll, so that held accesses are
    /// answered and the clients deleted by us before the process exits.
    static let stopWait: TimeInterval = 5
    static var stopWaitCovers: TimeInterval { NativeHeldMessages.denyAllWait + 2 * deleteWait }
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
    }

    public var state: SourceState { stateBox.get() }

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
            if let c = self.fileClient {
                _ = es_unsubscribe_all(c)
                NativeESSource.delete(c, gate: self.fileGate)
            }
            if let c = self.procClient {
                _ = es_unsubscribe_all(c)
                NativeESSource.delete(c, gate: self.procGate)
            }
            self.fileClient = nil
            self.procClient = nil
            self.fileGate = nil
            self.procGate = nil
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
        let r1 = es_new_client(&proc, NativeESSource.gated(pGate) { [weak self] _, message in self?.handleProcess(message) })
        guard r1 == ES_NEW_CLIENT_RESULT_SUCCESS, let proc else {
            fail(r1)
            return
        }
        procGate = pGate
        var file: OpaquePointer?
        let gate = NativeClientGate()
        let watchdog = NativeHandlerWatchdog()
        let r2 = es_new_client(&file, NativeESSource.watched(watchdog) { [weak self] client, message in
            self?.handleFile(client, message, gate)
        })
        guard r2 == ES_NEW_CLIENT_RESULT_SUCCESS, let file else {
            // Subscribed to nothing yet, so its handler never runs: no wait needed.
            _ = es_delete_client(proc)
            procGate = nil
            fail(r2)
            return
        }
        fileGate = gate
        // Before anything is subscribed: the file client is the one that answers AUTH messages.
        let deadlineMode = NativeESSource.setDeadlineMissMode(file)
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
        _ = es_unsubscribe_all(file)
        NativeESSource.delete(file, gate: fileGate)
        // The process client may already be subscribed (a later step failed): its handler may be running.
        _ = es_unsubscribe_all(proc)
        NativeESSource.delete(proc, gate: procGate)
        procClient = nil
        fileClient = nil
        fileGate = nil
        procGate = nil
        report(error: message, hint: "Endpoint Security setup failed; retrying.")
        scheduleRetry()
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
    /// thread): one write(2) to stderr, where Log writes as well, then _exit. The auth-armed marker
    /// stays, so the next start reports an unclean stop; the enforcement setting is untouched.
    static func exitForStall(_ seconds: TimeInterval) {
        let line = "\(RFC3339.format(Date(), fractionDigits: 3)) ERROR Endpoint Security file handler stuck in one call for "
            + "\(Int(seconds)) s: exiting so launchd starts a new daemon (enforcement setting unchanged)\n"
        line.withCString { _ = write(STDERR_FILENO, $0, strlen($0)) }
        _exit(70) // EX_SOFTWARE
    }

    /// A handler block that runs `body` inside `gate` (nothing once the gate is closed for deletion).
    static func gated(_ gate: NativeClientGate, _ body: @escaping es_handler_block_t) -> es_handler_block_t {
        { client, message in gate.use { body(client, message) } }
    }

    /// Before the ES clients are deleted (client thread): hold nothing more, then deny everything held
    /// while the client its `respond` closures answer through still exists. The broker's denyAll returns
    /// once every access it holds is answered; whatever is still held after it is denied here, so no
    /// message outlives its client whatever the broker does.
    private func closeAsks() {
        askGate.lock()
        asksOpen = false
        askGate.unlock()
        decider.askBroker?.denyAll()
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

    private func handleProcess(_ msg: UnsafePointer<es_message_t>) {
        let m = msg.pointee
        if m.version >= 4 {
            lock.lock()
            processSequence.note(m.global_seq_num)
            lock.unlock()
        }
        let time = NativeESSource.date(m.time)
        let event: SourceEvent
        switch m.event_type {
        case ES_EVENT_TYPE_NOTIFY_FORK:
            event = .fork(parent: NativeESSource.record(m.process, version: m.version),
                          child: NativeESSource.record(m.event.fork.child, version: m.version), time: time)
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            var target = NativeESSource.record(m.event.exec.target, version: m.version)
            target.argv = NativeESSource.execArgs(msg)
            event = .exec(process: NativeESSource.record(m.process, version: m.version), target: target, time: time)
        case ES_EVENT_TYPE_NOTIFY_EXIT:
            event = .exit(process: NativeESSource.record(m.process, version: m.version), time: time)
        default:
            return
        }
        // Process events update the in-memory tree synchronously so AUTH decisions see them asap.
        sink?.receive(event, context: .monitorOnly)
    }

    private func handleFile(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>, _ gate: NativeClientGate) {
        let m = msg.pointee
        if m.action_type == ES_ACTION_TYPE_AUTH {
            // Its es_* calls (respond, retain) stay inside the gate: es_delete_client must not run
            // alongside. Closed means the client is being deleted; the message is left to its teardown.
            gate.use { handleAuth(client, msg, gate) }
            return
        }
        let activity = NativeESSource.activity(msg)
        // `.afterAuth` only when this access really passed an AUTH check: AUTH subscribed and
        // enforcement live right now (the kill switch unsubscribes asynchronously). An access held in
        // ask mode and allowed by the answer passed AUTH too, so it is `.afterAuth` as well.
        // A modified close has no AUTH counterpart but is treated the same: its open passed AUTH, or
        // predates enforcement and a matching deny still alerts. As `.monitorOnly` it would turn a
        // write allowed once into "would block", and could use up a live "allow once".
        let enforcing = activity != nil && core?.enforcement.isActive == true
        lock.lock()
        if m.version >= 4 { fileSequence.note(m.global_seq_num) }
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
        let activity = NativeESSource.activity(msg)
        var decision = activity.map { decider.decide($0) } ?? .failOpen()
        if decision.verdict == .ask, let activity {
            // Held: the broker answers it later, and held accesses stay out of the latency stats.
            if hold(client, msg, activity, decision, gate) {
                lock.lock()
                if m.version >= 4 { fileSequence.note(m.global_seq_num) }
                lock.unlock()
                return
            }
            // Not held (no broker or question, too little time, too many held, nobody to answer,
            // stopping): denied at once, recorded and timed like any other denial.
            decision = NativeESSource.askDenial(decision)
        }
        NativeESSource.respond(client, msg, decision)
        let end = mach_absolute_time()
        let tb = NativeESSource.timebase
        // Measured from the event's Mach time (comparable to mach_absolute_time, header), so time
        // spent queued behind other messages counts toward the p99 statistics. Stats only: a slow
        // response or a missed deadline never switches enforcement off.
        let begin = m.mach_time > 0 ? min(start, m.mach_time) : start
        let micros = (end &- begin) &* UInt64(tb.numer) / UInt64(tb.denom) / 1000
        decider.recordResponse(micros: micros, missedDeadline: end >= m.deadline)
        lock.lock()
        if m.version >= 4 { fileSequence.note(m.global_seq_num) }
        lock.unlock()
        if decision.verdict == .deny, let activity { recordDenial(activity, decision) }
    }

    /// Ask mode: hands a `.ask` access to the broker. True when held (the broker answers it, exactly
    /// once, through the closure); false when the caller must deny it at once.
    private func hold(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>, _ activity: FileActivity,
                      _ ask: RuleDecision, _ gate: NativeClientGate) -> Bool {
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
            gate.use {
                NativeESSource.respond(client, msg, allow: allowed, cache: false)
                es_release_message(msg)
            }
            if !allowed { self?.recordDenial(activity, final) }
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
    /// would be denied.
    static func respond(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>, _ d: RuleDecision) {
        let allow = d.verdict == .allow
        // Cache only if no enforced rule denies this process anything here: a cached narrower mask
        // would deny a later open in the kernel with no AUTH event (no log, no alert), and keep doing
        // so after the kill switch.
        respond(client, msg, allow: allow, cache: allow && d.cacheable && d.policyDenied.isEmpty)
    }

    /// Any thread (an answer to a held message comes from the broker's queue; the message is retained).
    static func respond(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>, allow: Bool, cache: Bool) {
        let result: es_respond_result_t
        if msg.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN {
            // Deny with 0 and never cache it. Allow with UINT32_MAX (header: unless intentionally
            // denying flags): an allow never needs a mask, because any requested bit an enforced rule
            // denies already makes the verdict deny.
            result = es_respond_flags_result(client, msg, allow ? UInt32.max : 0, allow && cache)
        } else {
            // CREATE, RENAME, CLONE, COPYFILE, LINK, UNLINK, TRUNCATE, EXCHANGEDATA, SETACL, SETATTRLIST: no
            // caching (header). SETMODE, SETOWNER and MOUNT could be cached, but their cache key (executable,
            // file) ignores the process chain, so a cached allow would also let the same program through
            // under an AI agent: never cached.
            result = es_respond_auth_result(client, msg, allow ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false)
        }
        if result != ES_RESPOND_RESULT_SUCCESS {
            // Logging writes to disk: never on the callback thread. Copy plain values, not `msg`.
            let r = result.rawValue
            let t = msg.pointee.event_type.rawValue
            reportQueue.async { Log.error("es_respond failed (\(r)) for event type \(t)") }
        }
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

    /// Same per-operation semantics as the eslogger parser (OperationSemantics).
    static func activity(_ msg: UnsafePointer<es_message_t>) -> FileActivity? {
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
            targets = OperationSemantics.close(reported(e.close.target), modified: e.close.modified)
        case ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_NOTIFY_RENAME:
            op = .rename
            let dst: ReportedPath
            if e.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                dst = reported(e.rename.destination.existing_file)
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
