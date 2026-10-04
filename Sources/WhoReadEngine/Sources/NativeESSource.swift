import Foundation

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
    /// normalization a name was created with), and the resolved on-disk spelling (realpath: on-disk
    /// case, symlinks resolved) when the path exists. Never "/" (a link to the root, as PathClassifier
    /// skips too): an inverted "/" prefix would select every file event on the system.
    static func variants(_ p: String, resolve: (String) -> String?) -> [String] {
        var out = [p]
        if !p.utf8.allSatisfy({ $0 < 0x80 }) {
            out.append(p.decomposedStringWithCanonicalMapping)
            out.append(p.precomposedStringWithCanonicalMapping)
        }
        if let r = resolve(p), r != "/" { out.append(r) }
        return out
    }

    static func plan(prefixes: [String], ancestors: [String], resolve: (String) -> String?) -> (prefixes: Set<Path>, literals: Set<Path>) {
        (Set(prefixes.flatMap { variants($0, resolve: resolve) }.map(Path.init)),
         Set(ancestors.flatMap { variants($0, resolve: resolve) }.map(Path.init)))
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
// NOT YET COMPILED: written on a Linux host against the API facts in docs/RESEARCH.md and
// docs/research/endpoint-security-api.md (DocC + SDK header text). First compile on the Mac.
//
// Two clients, as the brief requires:
// - file client: target-path muting INVERTED, so only events touching monitored prefixes (or the
//   literal ancestor directories) are delivered. NOTIFY events always; AUTH events only while
//   enforcement is active. A multi-target event (rename/clone/copyfile/link/exchangedata) is
//   delivered if ANY of its targets is selected (header), so covering source paths is enough.
//   AUTH_CREATE covers new files (open(O_CREAT) of a new file has no AUTH_OPEN). Listings and
//   directory opens are never blocked, so AUTH_READDIR is not subscribed.
// - process client: NOTIFY_FORK/EXEC/EXIT, no muting configuration shared with the file client.
//
// AUTH callback: build the FileActivity, decide from in-memory state (Enforcer: classifier +
// process tree + rules), respond immediately, then hand logging to a queue. No disk IO, no XPC,
// no UI on the callback path. Anything unexpected → allow.
public final class NativeESSource: EventSource, @unchecked Sendable {
    public let kind = SourceKind.native
    public let canEnforce = true

    private weak var core: DaemonCore?
    private let decider: AuthDecider
    private let stateBox = StateBox()
    private var sink: EventSink?

    // ES client handles are only created/deleted on `clientThread` (es_delete_client must be called
    // from the thread that called es_new_client).
    private var fileClient: OpaquePointer?
    private var procClient: OpaquePointer?
    private let clientThread = ClientThread()
    private let eventQueue = DispatchQueue(label: "whoread.native.events", qos: .userInitiated)
    private let deniedQueue = DispatchQueue(label: "whoread.native.denied", qos: .utility)
    /// What the callback must not do itself (logging, the latency trip's observers). Serial, so a burst
    /// of failures queues up instead of parking a pool thread per message on Log's lock.
    private static let reportQueue = DispatchQueue(label: "whoread.native.report", qos: .userInitiated)

    private let lock = NSLock()
    private var mutedPrefixes = Set<NativeMutePlan.Path>()
    private var mutedLiterals = Set<NativeMutePlan.Path>()
    private var authSubscribed = false
    private var pendingNotify = 0
    private var droppedNotify: UInt64 = 0
    // Client thread only.
    private var readdir = false
    private var retryTimer: DispatchSourceTimer?
    private var retryDelay = NativeESSource.initialRetryDelay
    private var lastError: String?
    private var stopped = false
    private var lastCacheClear = Date.distantPast
    private var cacheClearPending = false

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
        return droppedNotify
    }

    // MARK: - Event lists

    static let notifyFileEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_CLONE,
        ES_EVENT_TYPE_NOTIFY_COPYFILE, ES_EVENT_TYPE_NOTIFY_LINK, ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_NOTIFY_TRUNCATE,
        ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA,
    ]
    static let authFileEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_AUTH_CLONE, ES_EVENT_TYPE_AUTH_COPYFILE,
        ES_EVENT_TYPE_AUTH_LINK, ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
        ES_EVENT_TYPE_AUTH_CREATE,
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
        clientThread.run {
            // After this, a retry that was already queued finds `stopped` and creates nothing.
            self.stopped = true
            self.retryTimer?.cancel()
            self.retryTimer = nil
            if let c = self.fileClient {
                _ = es_unsubscribe_all(c)
                _ = es_delete_client(c)
            }
            if let c = self.procClient {
                _ = es_unsubscribe_all(c)
                _ = es_delete_client(c)
            }
            self.fileClient = nil
            self.procClient = nil
            self.publish { $0.running = false }
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
        let r1 = es_new_client(&proc) { [weak self] _, message in self?.handleProcess(message) }
        guard r1 == ES_NEW_CLIENT_RESULT_SUCCESS, let proc else {
            fail(r1)
            return
        }
        var file: OpaquePointer?
        let r2 = es_new_client(&file) { [weak self] client, message in self?.handleFile(client, message) }
        guard r2 == ES_NEW_CLIENT_RESULT_SUCCESS, let file else {
            _ = es_delete_client(proc)
            fail(r2)
            return
        }
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
        lock.unlock()
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
        }
        Log.info("Endpoint Security clients connected (\(mutedPrefixes.count) prefixes, \(mutedLiterals.count) literal ancestors)")
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

    /// Setup failed after both clients exist: delete them (still on the creating thread) and retry.
    private func abortSetup(_ proc: OpaquePointer, _ file: OpaquePointer, _ message: String) {
        disarm()
        _ = es_delete_client(file)
        _ = es_delete_client(proc)
        procClient = nil
        fileClient = nil
        report(error: message, hint: "Endpoint Security setup failed; retrying.")
        scheduleRetry()
    }

    /// Publishes and logs a setup error once, not on every retry.
    private func report(error: String, hint: String) {
        guard error != lastError else { return }
        lastError = error
        publish {
            $0.running = false
            $0.error = error
            $0.hint = hint
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
        let plan = NativeMutePlan.plan(prefixes: prefixes, ancestors: ancestors, resolve: resolver.resolve)
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

    /// The marker exists exactly while AUTH events are subscribed. If the kernel kills the daemon for a
    /// missed deadline, the next start finds it and leaves enforcement off. Client thread only (IO).
    private func arm() {
        guard let config = core?.config, !config.inMemoryStore else { return }
        if !FileManager.default.createFile(atPath: config.authArmedMarkerPath, contents: nil,
                                           attributes: [.posixPermissions: 0o600]) {
            Log.warning("could not create \(config.authArmedMarkerPath)")
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

    private func handleFile(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>) {
        let m = msg.pointee
        if m.action_type == ES_ACTION_TYPE_AUTH {
            let start = mach_absolute_time()
            let activity = NativeESSource.activity(msg)
            let decision = activity.map { decider.decide($0) } ?? .failOpen()
            NativeESSource.respond(client, msg, decision)
            let end = mach_absolute_time()
            let tb = NativeESSource.timebase
            // Measured from the event's Mach time (comparable to mach_absolute_time, header), so time
            // spent queued behind other messages counts toward the p99 guard.
            let begin = m.mach_time > 0 ? min(start, m.mach_time) : start
            let micros = (end &- begin) &* UInt64(tb.numer) / UInt64(tb.denom) / 1000
            if end >= m.deadline {
                // A miss trips enforcement, and EnforcementState runs its observers (which log) on the
                // calling thread: report it from a queue, never from the callback.
                NativeESSource.reportQueue.async { [decider] in
                    decider.recordResponse(micros: micros, missedDeadline: true)
                }
            } else {
                decider.recordResponse(micros: micros, missedDeadline: false)
            }
            if decision.verdict == .deny, let activity {
                // A denied access produces no NOTIFY: record it off the callback path. Never dropped.
                deniedQueue.async { [weak self] in self?.sink?.receive(.file(activity), context: .decided(decision)) }
            }
            return
        }
        guard let activity = NativeESSource.activity(msg) else { return }
        // `.afterAuth` only when this access really passed an AUTH check: AUTH subscribed, enforcement
        // live right now (the kill switch and latency trip unsubscribe asynchronously), and an event
        // with an AUTH counterpart (a close has none; its fd may predate enforcement).
        let enforcing = m.event_type != ES_EVENT_TYPE_NOTIFY_CLOSE && core?.enforcement.isActive == true
        lock.lock()
        let context: RuleContext = authSubscribed && enforcing ? .afterAuth : .monitorOnly
        let full = pendingNotify >= NativeESSource.maxPendingNotify
        if full { droppedNotify &+= 1 } else { pendingNotify += 1 }
        lock.unlock()
        guard !full else { return }
        eventQueue.async { [weak self] in
            guard let self else { return }
            self.sink?.receive(.file(activity), context: context)
            self.lock.lock()
            self.pendingNotify -= 1
            self.lock.unlock()
        }
    }

    static func respond(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>, _ d: RuleDecision) {
        let result: es_respond_result_t
        if msg.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN {
            // Deny with 0 and never cache it. Allow with UINT32_MAX (header: unless intentionally
            // denying flags): an allow never needs a mask, because any requested bit an enforced rule
            // denies already makes the verdict deny. Cache only if no enforced rule denies this
            // process anything here: a cached narrower mask would deny a later open in the kernel
            // with no AUTH event (no log, no alert), and keep doing so after the kill switch.
            result = d.verdict == .deny
                ? es_respond_flags_result(client, msg, 0, false)
                : es_respond_flags_result(client, msg, UInt32.max, d.cacheable && d.policyDenied.isEmpty)
        } else {
            // CREATE, RENAME, CLONE, COPYFILE, LINK, UNLINK, TRUNCATE, EXCHANGEDATA: no caching (header).
            result = es_respond_auth_result(client, msg, d.verdict == .deny ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW, false)
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
        case ES_EVENT_TYPE_AUTH_CREATE:
            // A new file, directory or link. NOTIFY_CREATE is not subscribed: NOTIFY_OPEN already logs
            // creating opens, so it would only double them.
            op = .create
            let dst: ReportedPath
            if e.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                dst = reported(e.create.destination.existing_file)
            } else {
                dst = newPath(e.create.destination.new_path.dir, e.create.destination.new_path.filename)
            }
            targets = OperationSemantics.create(dst)
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
