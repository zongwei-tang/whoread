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

    private let lock = NSLock()
    private var mutedPrefixes = Set<String>()
    private var mutedLiterals = Set<String>()
    private var authSubscribed = false
    private var readdir = false
    private var retryTimer: DispatchSourceTimer?
    private var lastCacheClear = Date.distantPast
    private var cacheClearPending = false

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

    // MARK: - Event lists

    static let notifyFileEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_CLONE,
        ES_EVENT_TYPE_NOTIFY_COPYFILE, ES_EVENT_TYPE_NOTIFY_LINK, ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_NOTIFY_TRUNCATE,
        ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA,
    ]
    static let authFileEvents: [es_event_type_t] = [
        ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_AUTH_CLONE, ES_EVENT_TYPE_AUTH_COPYFILE,
        ES_EVENT_TYPE_AUTH_LINK, ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
    ]
    static let processEvents: [es_event_type_t] = [ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT]

    // MARK: - Lifecycle

    public func start(sink: EventSink) throws {
        self.sink = sink
        clientThread.start()
        clientThread.run { self.connect() }
    }

    public func stop() {
        retryTimer?.cancel()
        clientThread.run {
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
        }
        publish { $0.running = false }
    }

    private func publish(_ f: (inout SourceState) -> Void) {
        let s = stateBox.update(f)
        sink?.sourceStateChanged(s)
    }

    /// Runs on the client thread. Retries every 5 s until ES lets us in (FDA is often granted
    /// after the extension starts).
    private func connect() {
        guard fileClient == nil else { return }
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
        // and do it before any AUTH subscription exists.
        _ = es_unmute_all_target_paths(file)
        if es_muting_inverted(file, ES_MUTE_INVERSION_TYPE_TARGET_PATH) != ES_MUTE_INVERTED {
            _ = es_invert_muting(file, ES_MUTE_INVERSION_TYPE_TARGET_PATH)
        }
        procClient = proc
        fileClient = file
        if let core {
            let c = core.analyzer.classifier
            applyMuting(prefixes: c.prefixes.map(\.path), ancestors: c.ancestors)
        }
        subscribe(proc, NativeESSource.processEvents)
        subscribe(file, NativeESSource.notifyFileEvents + (readdir ? [ES_EVENT_TYPE_NOTIFY_READDIR] : []))
        if core?.enforcement.isActive == true { setAuth(true) }
        _ = es_clear_cache(file)
        retryTimer?.cancel()
        retryTimer = nil
        publish {
            $0.running = true
            $0.error = nil
            $0.hint = nil
        }
        Log.info("Endpoint Security clients connected (\(mutedPrefixes.count) prefixes, \(mutedLiterals.count) literal ancestors)")
    }

    private func fail(_ r: es_new_client_result_t) {
        let (error, hint) = NativeESSource.describe(r)
        publish {
            $0.running = false
            $0.error = error
            $0.hint = hint
        }
        Log.warning("es_new_client failed: \(error)")
        if retryTimer == nil {
            let t = DispatchSource.makeTimerSource(queue: .global())
            t.schedule(deadline: .now() + 5, repeating: 5)
            t.setEventHandler { [weak self] in self?.clientThread.run { self?.connect() } }
            t.resume()
            retryTimer = t
        }
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

    private func subscribe(_ client: OpaquePointer, _ events: [es_event_type_t]) {
        events.withUnsafeBufferPointer { buf in
            if es_subscribe(client, buf.baseAddress!, UInt32(buf.count)) != ES_RETURN_SUCCESS {
                Log.error("es_subscribe failed for \(events.map(\.rawValue))")
            }
        }
    }

    private func unsubscribe(_ client: OpaquePointer, _ events: [es_event_type_t]) {
        events.withUnsafeBufferPointer { buf in
            _ = es_unsubscribe(client, buf.baseAddress!, UInt32(buf.count))
        }
    }

    // MARK: - Muting

    /// Muting applies to the path as VFS sees it (F_GETPATH, after symlink resolution). Register
    /// the catalog spelling and, for non-ASCII prefixes, the NFD spelling too, since APFS keeps
    /// whatever normalization a name was created with.
    static func plan(prefixes: [String], ancestors: [String]) -> (Set<String>, Set<String>) {
        func variants(_ p: String) -> [String] {
            var out = [p]
            if !p.utf8.allSatisfy({ $0 < 0x80 }) {
                out.append(p.decomposedStringWithCanonicalMapping)
                out.append(p.precomposedStringWithCanonicalMapping)
            }
            return out
        }
        return (Set(prefixes.flatMap(variants)), Set(ancestors.flatMap(variants)))
    }

    private func applyMuting(prefixes: [String], ancestors: [String]) {
        guard let file = fileClient else { return }
        let (newPrefixes, newLiterals) = NativeESSource.plan(prefixes: prefixes, ancestors: ancestors)
        lock.lock()
        let oldPrefixes = mutedPrefixes
        let oldLiterals = mutedLiterals
        lock.unlock()
        // Diff instead of unmute-all: the header asks for no AUTH subscriptions around unmute-all.
        for p in oldPrefixes.subtracting(newPrefixes) { _ = es_unmute_path(file, p, ES_MUTE_PATH_TYPE_TARGET_PREFIX) }
        for p in oldLiterals.subtracting(newLiterals) { _ = es_unmute_path(file, p, ES_MUTE_PATH_TYPE_TARGET_LITERAL) }
        for p in newPrefixes.subtracting(oldPrefixes) {
            if es_mute_path(file, p, ES_MUTE_PATH_TYPE_TARGET_PREFIX) != ES_RETURN_SUCCESS { Log.warning("es_mute_path prefix failed: \(p)") }
        }
        for p in newLiterals.subtracting(oldLiterals) {
            if es_mute_path(file, p, ES_MUTE_PATH_TYPE_TARGET_LITERAL) != ES_RETURN_SUCCESS { Log.warning("es_mute_path literal failed: \(p)") }
        }
        lock.lock()
        mutedPrefixes = newPrefixes
        mutedLiterals = newLiterals
        lock.unlock()
    }

    public func updateMonitoring(prefixes: [String], ancestors: [String], readdir newReaddir: Bool) {
        clientThread.run {
            self.applyMuting(prefixes: prefixes, ancestors: ancestors)
            if newReaddir != self.readdir, let file = self.fileClient {
                if newReaddir {
                    self.subscribe(file, [ES_EVENT_TYPE_NOTIFY_READDIR] + (self.authSubscribed ? [ES_EVENT_TYPE_AUTH_READDIR] : []))
                } else {
                    self.unsubscribe(file, [ES_EVENT_TYPE_NOTIFY_READDIR, ES_EVENT_TYPE_AUTH_READDIR])
                }
            }
            self.readdir = newReaddir
            self.clearCacheSoon()
        }
    }

    public func enforcementChanged(active: Bool) {
        clientThread.run { self.setAuth(active) }
    }

    private func setAuth(_ on: Bool) {
        guard let file = fileClient else { return }
        let events = NativeESSource.authFileEvents + (readdir ? [ES_EVENT_TYPE_AUTH_READDIR] : [])
        lock.lock()
        let current = authSubscribed
        lock.unlock()
        if on && !current {
            subscribe(file, events)
        } else if !on && current {
            unsubscribe(file, events)
        }
        lock.lock()
        authSubscribed = on
        lock.unlock()
        clearCacheSoon()
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
            let micros = (end &- start) &* UInt64(tb.numer) / UInt64(tb.denom) / 1000
            decider.recordResponse(micros: micros, missedDeadline: end >= m.deadline)
            if decision.verdict == .deny, let activity {
                // A denied access produces no NOTIFY: record it off the callback path.
                deniedQueue.async { [weak self] in self?.sink?.receive(.file(activity), context: .decided(decision)) }
            }
            return
        }
        guard let activity = NativeESSource.activity(msg) else { return }
        lock.lock()
        let context: RuleContext = authSubscribed ? .afterAuth : .monitorOnly
        lock.unlock()
        eventQueue.async { [weak self] in self?.sink?.receive(.file(activity), context: context) }
    }

    static func respond(_ client: OpaquePointer, _ msg: UnsafePointer<es_message_t>, _ d: RuleDecision) {
        let result: es_respond_result_t
        if msg.pointee.event_type == ES_EVENT_TYPE_AUTH_OPEN {
            // Deny with 0 and never cache it; allow with every flag the policy permits (header:
            // pass UINT32_MAX unless intentionally denying flags).
            result = d.verdict == .deny
                ? es_respond_flags_result(client, msg, 0, false)
                : es_respond_flags_result(client, msg, d.authorizedOpenFlags, d.cacheable)
        } else {
            result = es_respond_auth_result(client, msg, d.verdict == .deny ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW,
                                            d.verdict == .allow && d.cacheable)
        }
        if result != ES_RESPOND_RESULT_SUCCESS {
            Log.error("es_respond failed (\(result.rawValue)) for event type \(msg.pointee.event_type.rawValue)")
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
            op = .open
            let f = path(e.open.file)
            targets = OperationSemantics.open(path: f.path, fflag: UInt32(bitPattern: e.open.fflag), truncated: f.truncated)
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            op = .close
            let f = path(e.close.target)
            targets = OperationSemantics.close(path: f.path, modified: e.close.modified, truncated: f.truncated)
        case ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_NOTIFY_RENAME:
            op = .rename
            let src = path(e.rename.source).path
            let dst: String
            if e.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
                dst = path(e.rename.destination.existing_file).path
            } else {
                dst = OperationSemantics.join(dir: path(e.rename.destination.new_path.dir).path,
                                              name: string(e.rename.destination.new_path.filename))
            }
            targets = OperationSemantics.rename(source: src, destination: dst)
        case ES_EVENT_TYPE_AUTH_CLONE, ES_EVENT_TYPE_NOTIFY_CLONE:
            op = .clone
            targets = OperationSemantics.clone(source: path(e.clone.source).path,
                                               destination: OperationSemantics.join(dir: path(e.clone.target_dir).path, name: string(e.clone.target_name)))
        case ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_NOTIFY_COPYFILE:
            op = .copyfile
            let dst: String
            if let existing = e.copyfile.target_file {
                dst = path(existing).path
            } else {
                dst = OperationSemantics.join(dir: path(e.copyfile.target_dir).path, name: string(e.copyfile.target_name))
            }
            targets = OperationSemantics.copyfile(source: path(e.copyfile.source).path, destination: dst)
        case ES_EVENT_TYPE_AUTH_LINK, ES_EVENT_TYPE_NOTIFY_LINK:
            op = .link
            targets = OperationSemantics.link(source: path(e.link.source).path,
                                              destination: OperationSemantics.join(dir: path(e.link.target_dir).path, name: string(e.link.target_filename)))
        case ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_NOTIFY_UNLINK:
            op = .unlink
            targets = OperationSemantics.unlink(path: path(e.unlink.target).path)
        case ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_NOTIFY_TRUNCATE:
            op = .truncate
            targets = OperationSemantics.truncate(path: path(e.truncate.target).path)
        case ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
            op = .exchangedata
            targets = OperationSemantics.exchangedata(path(e.exchangedata.file1).path, path(e.exchangedata.file2).path)
        case ES_EVENT_TYPE_AUTH_READDIR, ES_EVENT_TYPE_NOTIFY_READDIR:
            op = .readdir
            targets = OperationSemantics.readdir(path: path(e.readdir.target).path)
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
