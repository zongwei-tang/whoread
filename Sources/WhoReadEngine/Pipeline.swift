import Foundation
import WhoReadCore
import WhoReadIPC

/// Last N events in memory, for the app's live view (no database round trip). A ring: appending
/// overwrites the oldest slot in place, so it costs O(1) under the pipeline's order lock.
public final class LiveBuffer: @unchecked Sendable {
    private let lock = NSLock()
    private var ring: [AnalyzedEvent] = []
    /// Slot of the oldest event once the ring is full (0 until then).
    private var head = 0
    private let capacity: Int

    public init(capacity: Int = 5000) {
        self.capacity = max(0, capacity)
        ring.reserveCapacity(self.capacity)
    }

    public func append(_ events: [AnalyzedEvent]) {
        lock.lock(); defer { lock.unlock() }
        guard capacity > 0 else { return }
        for e in events.suffix(capacity) {
            if ring.count < capacity {
                ring.append(e)
            } else {
                ring[head] = e
                head = (head + 1) % capacity
            }
        }
    }

    /// The i-th event, oldest first.
    private func at(_ i: Int) -> AnalyzedEvent { ring[(head + i) % ring.count] }

    /// Events with id > afterID, oldest first.
    public func after(_ afterID: Int64?, limit: Int, includeBenign: Bool) -> [AnalyzedEvent] {
        lock.lock(); defer { lock.unlock() }
        // The newest `limit` matches, collected from the newest end.
        var out: [AnalyzedEvent] = []
        var i = ring.count - 1
        while i >= 0 && out.count < limit {
            let e = at(i)
            if (afterID.map { e.id > $0 } ?? true) && (includeBenign || !e.isBenign) { out.append(e) }
            i -= 1
        }
        return out.reversed()
    }

    public var newest: AnalyzedEvent? {
        lock.lock(); defer { lock.unlock() }
        return ring.isEmpty ? nil : at(ring.count - 1)
    }
}

/// Batches events and alerts into the store off the event path.
public final class EventWriter: @unchecked Sendable {
    private let store: EventStore
    private let lock = NSLock()
    private var pendingEvents: [AnalyzedEvent] = []
    private var pendingAlerts: [Int64: Alert] = [:]
    private let maxPending: Int
    private let queue = DispatchQueue(label: "whoread.writer")
    private var timer: DispatchSourceTimer?
    private(set) var dropped: UInt64 = 0
    private(set) var lastError: String?
    private var lastErrorReport = Date.distantPast
    private let errorReportInterval: TimeInterval
    /// Store errors, at most once per `errorReportInterval` (a full disk fails every flush).
    public var onError: ((Error) -> Void)?

    public init(store: EventStore, maxPending: Int = 100_000, errorReportInterval: TimeInterval = 10) {
        self.store = store
        self.maxPending = maxPending
        self.errorReportInterval = errorReportInterval
    }

    public func start(interval: TimeInterval = 0.25) {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + interval, repeating: interval)
        t.setEventHandler { [weak self] in self?.flushLocked() }
        t.resume()
        timer = t
    }

    public func stop() {
        timer?.cancel()
        timer = nil
        flush()
    }

    public func enqueue(events: [AnalyzedEvent]) {
        lock.lock(); defer { lock.unlock() }
        pendingEvents.append(contentsOf: events)
        trimLocked()
    }

    private func trimLocked() {
        if pendingEvents.count > maxPending {
            // Prefer keeping recent events; count what was lost.
            let excess = pendingEvents.count - maxPending
            pendingEvents.removeFirst(excess)
            dropped += UInt64(excess)
        }
    }

    public func enqueue(alerts: [Alert]) {
        lock.lock(); defer { lock.unlock() }
        for a in alerts { pendingAlerts[a.id] = a }
    }

    /// Synchronous flush (queries call this so they see everything processed so far).
    public func flush() {
        queue.sync { flushLocked() }
    }

    private func flushLocked() {
        lock.lock()
        let events = pendingEvents
        let alerts = Array(pendingAlerts.values)
        pendingEvents.removeAll(keepingCapacity: true)
        pendingAlerts.removeAll(keepingCapacity: true)
        lock.unlock()
        // The two writes fail independently. A failed one is put back and retried on the next tick
        // (a failed transaction rolls back, so a retry cannot double-count summaries).
        var failure: Error?
        var failedEvents: [AnalyzedEvent] = []
        var failedAlerts: [Alert] = []
        do {
            if !events.isEmpty { try store.insert(events) }
        } catch {
            failure = error
            failedEvents = events
        }
        do {
            if !alerts.isEmpty { try store.upsert(alerts) }
        } catch {
            failure = error
            failedAlerts = alerts
        }
        guard let failure else { return }
        let now = Date()
        lock.lock()
        lastError = "\(failure)"
        pendingEvents.insert(contentsOf: failedEvents, at: 0)
        trimLocked()
        // A newer snapshot of the same alert queued meanwhile wins.
        for a in failedAlerts where pendingAlerts[a.id] == nil { pendingAlerts[a.id] = a }
        let report = now.timeIntervalSince(lastErrorReport) >= errorReportInterval
        if report { lastErrorReport = now }
        lock.unlock()
        if report { onError?(failure) }
    }

    public var droppedCount: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return dropped
    }
}

/// Source → analyzer → live buffer + writer + alert callback.
public final class EventPipeline: EventSink, @unchecked Sendable {
    public let analyzer: Analyzer
    public let writer: EventWriter
    public let live: LiveBuffer
    private let lock = NSLock()
    /// Spans id assignment (in the analyzer) and publication, so the live buffer and the writer get
    /// file events in id order even when a source delivers from two queues (native NOTIFY + denials).
    private let orderLock = NSLock()
    private var processed: UInt64 = 0
    private var lastEvent: Date?
    private var sourceState = SourceState()
    public var isPaused: @Sendable () -> Bool = { false }
    public var onAlert: (@Sendable (AlertUpdate) -> Void)?
    public var onSourceState: (@Sendable (SourceState) -> Void)?

    public init(analyzer: Analyzer, writer: EventWriter, live: LiveBuffer) {
        self.analyzer = analyzer
        self.writer = writer
        self.live = live
    }

    public func receive(_ event: SourceEvent, context: RuleContext) {
        guard case .file = event else {
            _ = analyzer.handle(event, context: context)
            return
        }
        if isPaused() {
            // Paused: keep the process tree current and record nothing, except blocks and questions.
            // Enforcement is a separate switch and keeps denying (and asking); every denial must still be
            // recorded and alerted.
            guard case .decided(let d) = context, d.verdict != .allow else { return }
        }
        orderLock.lock()
        let out = analyzer.handle(event, context: context)
        if !out.events.isEmpty {
            live.append(out.events)
            writer.enqueue(events: out.events)
        }
        if !out.alerts.isEmpty { writer.enqueue(alerts: out.alerts.map(\.alert)) }
        orderLock.unlock()
        guard !out.events.isEmpty || !out.alerts.isEmpty else { return }
        if let onAlert { out.alerts.forEach(onAlert) }
        lock.lock()
        processed += UInt64(out.events.count)
        lastEvent = out.events.last?.time ?? lastEvent
        lock.unlock()
    }

    public func sourceStateChanged(_ state: SourceState) {
        lock.lock()
        sourceState = state
        lock.unlock()
        onSourceState?(state)
    }

    public var stats: (processed: UInt64, lastEventAt: Date?, source: SourceState) {
        lock.lock(); defer { lock.unlock() }
        return (processed, lastEvent, sourceState)
    }
}

/// AUTH decisions for the native source: classification, chain and rules, all in memory.
/// Any inactive switch (user, kill-switch file) means allow. With enforcement active, an access that
/// no rule, owner, benign service or "trust Apple programs" decides is asked (verdict `.ask`): the
/// native source holds it in `askBroker` until the user answers or its budget runs out (docs/ASK_MODE.md).
public final class Enforcer: AuthDecider, @unchecked Sendable {
    let analyzer: Analyzer
    let state: EnforcementState
    let latency: LatencyMonitor
    /// Where held accesses wait. nil: nothing can be held, so nothing is asked.
    public let askBroker: AskBroker?
    private let lock = NSLock()
    private var trustApple = false

    public init(analyzer: Analyzer, state: EnforcementState, latency: LatencyMonitor, askBroker: AskBroker? = nil) {
        self.analyzer = analyzer
        self.state = state
        self.latency = latency
        self.askBroker = askBroker
    }

    /// `Settings.trustApplePrograms`, mirrored by DaemonCore: read on the ES callback thread, so a
    /// locked in-memory flag.
    public var trustApplePrograms: Bool {
        get { lock.lock(); defer { lock.unlock() }; return trustApple }
        set { lock.lock(); trustApple = newValue; lock.unlock() }
    }

    public func decide(_ activity: FileActivity) -> RuleDecision {
        // Never block a directory listing, or a directory open (reported as readdir): it reveals names
        // only, and denying it breaks ls, Finder and open panels. Depends on nothing, so cacheable.
        if activity.operation == .readdir { return RuleDecision(verdict: .allow, reason: .neverBlock, cacheable: true) }
        guard state.isActive else { return RuleDecision(verdict: .allow, reason: .enforcementInactive) }
        let classified = analyzer.classify(activity)
        let targets = classified.filter(\.isSensitive).map(\.evaluationTarget)
        guard !targets.isEmpty else { return RuleDecision(verdict: .allow, reason: .notSensitive, cacheable: true) }
        let chain = analyzer.tree.chain(for: activity.process, at: activity.time)
        let process = chain.first?.image ?? activity.process
        return analyzer.rules.evaluate(process: process, chain: chain, targets: targets, enforcementActive: true, now: activity.time,
                                       ask: askPolicy(chain: chain))
    }

    /// The ask policy for an access while enforcement is active (`decide` returns earlier otherwise).
    func askPolicy(chain: [ProcessNode]) -> AskPolicy {
        guard askBroker != nil else { return .off }
        return AskPolicy(enabled: true, trustApplePrograms: trustApplePrograms, benignChain: analyzer.isBenignChain(chain))
    }

    /// An Apple program in a root-owned system location (see AskPolicy.isAppleProgram).
    public static func isAppleProgram(_ p: ProcessRecord) -> Bool { AskPolicy.isAppleProgram(p) }

    /// The question for an `.ask` decision. Memory only (ES callback thread). nil (deny at once) when
    /// the decision carries no key or the access no longer touches the key's category. The argv in its
    /// display data is raw: redacting it is too slow for the callback, AskBroker does it off it.
    public func askRequest(for activity: FileActivity, decision: RuleDecision) -> AskRequest? {
        guard decision.verdict == .ask, let key = decision.askKey else { return nil }
        let inCategory = analyzer.classify(activity).compactMap { t -> (path: String, severity: Severity)? in
            guard let c = t.categories.first(where: { $0.id == key.categoryID }) else { return nil }
            return (t.path, c.severity)
        }
        guard let first = inCategory.first, let severity = inCategory.map(\.severity).max() else { return nil }
        let chain = analyzer.tree.chain(for: activity.process, at: activity.time)
        let process = chain.first?.image ?? activity.process
        // Stored chains are capped (nearest 64 links), as for events.
        return AskRequest(id: 0, key: key, responsible: analyzer.attributor.attribute(chain: chain), severity: severity,
                          path: first.path, process: process,
                          chain: Array(chain.prefix(64).reversed()).map(Enforcer.rawLink), agentID: chain.nearestAgent,
                          appleProgram: AskPolicy.isTrustableAppleProgram(process, chain: chain), firstAt: activity.time, lastAt: activity.time)
    }

    /// ChainLink(node:) without its argv redaction (AskBroker redacts it off the ES callback).
    static func rawLink(_ node: ProcessNode) -> ChainLink {
        let p = node.image
        return ChainLink(pid: p.pid, name: p.name, path: p.executablePath, signingID: p.signingID, teamID: p.teamID,
                         isPlatformBinary: p.isPlatformBinary, agentID: node.agentID, argv: p.argv)
    }

    /// Statistics only: slow responses and missed deadlines never switch enforcement off (ask mode).
    /// NativeESSource calls this on the ES callback thread for on-time responses (a ring store).
    public func recordResponse(micros: UInt64, missedDeadline: Bool) {
        latency.record(micros: micros, missedDeadline: missedDeadline)
    }
}

/// Watches `/Library/Application Support/WhoRead/disable-enforcement`. Polling every 200 ms keeps
/// it simple and works even if the directory is created later; the AUTH path only reads the
/// in-memory flag.
public final class KillSwitchWatcher: @unchecked Sendable {
    let path: String
    let state: EnforcementState
    private var timer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "whoread.killswitch")

    public init(path: String, state: EnforcementState) {
        self.path = path
        self.state = state
    }

    public func start(interval: TimeInterval = 0.2) {
        check()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + interval, repeating: interval)
        t.setEventHandler { [weak self] in self?.check() }
        t.resume()
        timer = t
    }

    public func check() {
        state.setKillSwitchFilePresent(FileManager.default.fileExists(atPath: path))
    }

    public func stop() {
        timer?.cancel()
        timer = nil
    }
}
