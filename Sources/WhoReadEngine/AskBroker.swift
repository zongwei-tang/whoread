import Foundation
import WhoReadCore

/// Ask mode: holds AUTH accesses that need the user's answer, and answers them.
///
/// The native source retains each such ES message and hands the broker a `respond` closure. The
/// broker calls it exactly once per held access — with the user's answer, or with `.deny` when the
/// access's deadline budget runs out — always from its own queue, never inside `hold` (which runs on
/// the ES callback thread and must not block or do IO). Accesses with the same `AskKey` share one
/// `AskRequest`; answering it answers all of them.
///
/// Thread-safe. The lock only guards in-memory tables (no IO, no callbacks under it); responses are
/// queued on `queue` while the lock is held, so they run in the order accesses left the tables and
/// `denyAll` can wait for every one of them.
public final class AskBroker: @unchecked Sendable {
    public enum Answer: Sendable, Equatable { case allow, deny }

    public enum Disposition: Sendable, Equatable {
        /// Held: `respond` will be called later (answer or timeout).
        case held(requestID: Int64)
        /// Not held (no answering app present, too little time, or too many held): the caller denies
        /// at once. `respond` is never called. The request is still listed for a later answer.
        case denyNow(requestID: Int64?)
    }

    /// Without an `.asks` poll this recent, nobody can answer: accesses are denied at once.
    public var presenceWindow: TimeInterval {
        get { locked { _presenceWindow } }
        set { locked { _presenceWindow = newValue } }
    }
    /// At most this many accesses are held at a time; beyond, they are denied at once.
    public var maxHeld: Int {
        get { locked { _maxHeld } }
        set { locked { _maxHeld = newValue } }
    }
    /// Unanswered requests are forgotten after this long.
    public var requestLifetime: TimeInterval {
        get { locked { _requestLifetime } }
        set { locked { _requestLifetime = newValue } }
    }
    /// Holding needs at least this much budget; less, and the access is denied at once.
    public var minimumBudget: TimeInterval {
        get { locked { _minimumBudget } }
        set { locked { _minimumBudget = newValue } }
    }

    public init(presenceWindow: TimeInterval = 5, maxHeld: Int = 256, requestLifetime: TimeInterval = 3600,
                minimumBudget: TimeInterval = 0.5, firstID: Int64 = 1, now: @escaping @Sendable () -> Date = { Date() }) {
        nextID = max(1, firstID)
        _presenceWindow = presenceWindow
        _maxHeld = maxHeld
        _requestLifetime = requestLifetime
        _minimumBudget = minimumBudget
        self.now = now
        queue.setSpecific(key: AskBroker.queueKey, value: queueToken)
    }

    let now: @Sendable () -> Date

    /// Open requests kept for display beyond this are dropped, oldest unheld first: every distinct
    /// binary path is its own key, so a process writing copies of itself must not grow memory.
    static let maxRequests = 1024

    /// One held access. Leaves the tables exactly once (under the broker lock); whoever takes it out
    /// owns the response. `responded` makes a second call a no-op all the same.
    private final class Held: @unchecked Sendable {
        let token: UInt64
        let answerBy: Date
        private let respond: @Sendable (Answer) -> Void
        private let lock = NSLock()
        private var responded = false
        var timer: DispatchWorkItem?

        init(token: UInt64, answerBy: Date, respond: @escaping @Sendable (Answer) -> Void) {
            self.token = token
            self.answerBy = answerBy
            self.respond = respond
        }

        func fire(_ answer: Answer) {
            lock.lock()
            let first = !responded
            responded = true
            lock.unlock()
            timer?.cancel()
            if first { respond(answer) }
        }
    }

    private struct Entry {
        var request: AskRequest
        var held: [Held] = []
        /// The display data's argv is redacted. `hold` stores it raw (see `redacted(_:)`); until then
        /// readers get no argv.
        var redacted = false
    }

    private let lock = NSLock()
    private let queue = DispatchQueue(label: "whoread.ask", qos: .userInitiated)
    /// Redacts new requests' display data soon after `hold`, so raw argv is not kept around. Not
    /// `queue`: a slow redaction must not delay answers to held accesses.
    private let redactQueue = DispatchQueue(label: "whoread.ask.redact", qos: .utility)
    private static let queueKey = DispatchSpecificKey<UInt8>()
    private let queueToken: UInt8 = 1
    private var _presenceWindow: TimeInterval
    private var _maxHeld: Int
    private var _requestLifetime: TimeInterval
    private var _minimumBudget: TimeInterval
    private var nextID: Int64 = 1
    private var nextToken: UInt64 = 1
    private var entries: [Int64: Entry] = [:]
    private var byKey: [AskKey: Int64] = [:]
    private var heldCount = 0
    private var lastPoll: Date?

    private func locked<T>(_ f: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return f()
    }

    /// ES callback thread. `budget`: seconds until the access must be answered (deadline minus
    /// headroom). `request` carries the key and display data; its id is assigned here. Its argv
    /// (process and chain) may be raw: the broker redacts it off the callback, and shows none until then.
    public func hold(_ request: AskRequest, budget: TimeInterval,
                     respond: @escaping @Sendable (Answer) -> Void) -> Disposition {
        let t = now()
        lock.lock()
        let id: Int64
        if let existing = byKey[request.key], var e = entries[existing] {
            id = existing
            e.request.attempts += 1
            e.request.lastAt = t
            if request.severity > e.request.severity { e.request.severity = request.severity }
            entries[id] = e
        } else {
            guard makeRoomLocked() else {
                lock.unlock()
                return .denyNow(requestID: nil)
            }
            id = nextID
            nextID += 1
            var r = request
            r.id = id
            r.firstAt = t
            r.lastAt = t
            r.attempts = 1
            r.holding = 0
            r.answerBy = nil
            entries[id] = Entry(request: r)
            byKey[r.key] = id
            // Non-blocking: only enqueues.
            redactQueue.async { self.redactEntry(id) }
        }
        let present = lastPoll.map { t.timeIntervalSince($0) <= _presenceWindow } ?? false
        guard present, budget >= _minimumBudget, heldCount < _maxHeld else {
            lock.unlock()
            return .denyNow(requestID: id)
        }
        let token = nextToken
        nextToken += 1
        let held = Held(token: token, answerBy: t.addingTimeInterval(budget), respond: respond)
        // Monotonic (uptime) clock, like the ES deadline; answerBy is wall clock for display only. The
        // timer keeps the broker alive until it fires: a held access is always answered.
        let timer = DispatchWorkItem { self.timeout(id: id, token: token) }
        held.timer = timer
        entries[id]?.held.append(held)
        entries[id]?.request.holding += 1
        let by = entries[id]?.request.answerBy
        entries[id]?.request.answerBy = by.map { min($0, held.answerBy) } ?? held.answerBy
        heldCount += 1
        // Non-blocking: only enqueues.
        queue.asyncAfter(deadline: .now() + budget, execute: timer)
        lock.unlock()
        return .held(requestID: id)
    }

    /// Drops the oldest request nothing is held for, if the table is full. False: every slot holds
    /// accesses (cannot happen while maxHeld < maxRequests).
    private func makeRoomLocked() -> Bool {
        guard entries.count >= AskBroker.maxRequests else { return true }
        guard let oldest = entries.values.filter({ $0.held.isEmpty }).min(by: { $0.request.lastAt < $1.request.lastAt }) else {
            return false
        }
        removeLocked(oldest.request.id)
        return true
    }

    @discardableResult
    private func removeLocked(_ id: Int64) -> Entry? {
        guard let e = entries.removeValue(forKey: id) else { return nil }
        if byKey[e.request.key] == id { byKey.removeValue(forKey: e.request.key) }
        heldCount -= e.held.count
        return e
    }

    /// Queues the responses. Called with the lock held, so queue order follows table order.
    private func respondLocked(_ held: [Held], _ answer: Answer) {
        guard !held.isEmpty else { return }
        queue.async { for h in held { h.fire(answer) } }
    }

    /// Broker queue: the budget of one held access ran out. The question stays open.
    private func timeout(id: Int64, token: UInt64) {
        lock.lock()
        guard var e = entries[id], let i = e.held.firstIndex(where: { $0.token == token }) else {
            lock.unlock()
            return
        }
        let held = e.held.remove(at: i)
        e.request.holding = e.held.count
        e.request.answerBy = e.held.map(\.answerBy).min()
        entries[id] = e
        heldCount -= 1
        lock.unlock()
        // Already on the queue: answer here, before anything queued after this.
        held.fire(.deny)
    }

    /// An app polled `.asks` (it can show the question).
    public func noteAnsweringClient() {
        let t = now()
        locked { lastPoll = t }
    }

    public var answeringClientPresent: Bool {
        let t = now()
        return locked { lastPoll.map { t.timeIntervalSince($0) <= _presenceWindow } ?? false }
    }

    /// Open requests, oldest first.
    public func pending() -> [AskRequest] {
        // Shown and sorted outside the lock: `hold` takes it on the ES callback thread.
        locked { entries.values.map { ($0.request, $0.redacted) } }.map(AskBroker.shown).sorted { $0.id < $1.id }
    }

    public func request(id: Int64) -> AskRequest? {
        locked { entries[id].map { ($0.request, $0.redacted) } }.map(AskBroker.shown)
    }

    /// Open requests (cheaper than `pending().count`).
    var openRequests: Int { locked { entries.count } }

    /// Answers one request: every held access with that key gets `answer`. Returns the request.
    @discardableResult
    public func resolve(id: Int64, answer: Answer) -> AskRequest? {
        lock.lock()
        let e = removeLocked(id)
        if let e { respondLocked(e.held, answer) }
        lock.unlock()
        return e.map { AskBroker.shown($0.request, $0.redacted) }
    }

    /// Answers every open request whose key matches (after a new rule or "trust Apple programs").
    /// `matches` runs outside the broker lock, on a snapshot.
    @discardableResult
    public func resolveMatching(_ answer: Answer, where matches: (AskRequest) -> Bool) -> [AskRequest] {
        let ids = pending().filter(matches).map(\.id)
        guard !ids.isEmpty else { return [] }
        lock.lock()
        var out: [Entry] = []
        for id in ids {
            guard let e = removeLocked(id) else { continue }
            respondLocked(e.held, answer)
            out.append(e)
        }
        lock.unlock()
        return out.map { AskBroker.shown($0.request, $0.redacted) }
    }

    /// The display data with argv redacted, as stored for events (process: ArgvRedactor.redact;
    /// chain links: as ChainLink(node:)). Never on the ES callback: the redactor runs regular
    /// expressions over up to 8 KB per process, and a chain has up to 64 of them (well over a second
    /// for a crafted chain). `hold` stores the request raw and the redact queue redacts it.
    static func redacted(_ r: AskRequest) -> AskRequest {
        var r = r
        r.process = ArgvRedactor.redact(r.process)
        r.chain = r.chain.map { link in
            var l = link
            l.argv = ArgvRedactor.redact(link.argv, maxArgs: 6, maxLength: 200)
            return l
        }
        return r
    }

    /// What readers get: until the redact queue got to it, the request without its raw argv (never
    /// the raw argv).
    private static func shown(_ request: AskRequest, _ redacted: Bool) -> AskRequest {
        guard !redacted else { return request }
        var r = request
        r.process.argv = nil
        r.chain = r.chain.map { link in
            var l = link
            l.argv = nil
            return l
        }
        return r
    }

    /// Redact queue: a new request's display data, redacted outside the lock. Only process and chain
    /// are written back: `hold` never changes them after creating the request.
    private func redactEntry(_ id: Int64) {
        guard let raw = locked({ entries[id].flatMap { $0.redacted ? nil : $0.request } }) else { return }
        let r = AskBroker.redacted(raw)
        locked {
            guard entries[id]?.redacted == false else { return }
            entries[id]?.request.process = r.process
            entries[id]?.request.chain = r.chain
            entries[id]?.redacted = true
        }
    }

    /// How long `denyAll` waits by default for the broker queue to answer.
    public static let denyAllWait: TimeInterval = 1

    /// Denies everything held (source stopping: ES clients are about to be deleted). The questions
    /// stay listed. True once every held access has been answered, including answers queued just
    /// before. False when the queue did not get to them within `timeout` (a response stuck on it): the
    /// denials then run whenever it frees, and the caller must deny what it still holds by itself (the
    /// native source does, before deleting its client). Never waits longer, so a stuck queue cannot
    /// hold up a stop.
    @discardableResult
    public func denyAll(waitAtMost timeout: TimeInterval = AskBroker.denyAllWait) -> Bool {
        lock.lock()
        var held: [Held] = []
        for (id, var e) in entries where !e.held.isEmpty {
            held += e.held
            e.held = []
            e.request.holding = 0
            e.request.answerBy = nil
            entries[id] = e
        }
        heldCount = 0
        lock.unlock()
        let run = { for h in held { h.fire(.deny) } }
        if DispatchQueue.getSpecific(key: AskBroker.queueKey) == queueToken {
            run()
            return true
        }
        // Behind every response queued so far (resolve, timeouts in progress).
        let done = DispatchSemaphore(value: 0)
        queue.async {
            run()
            done.signal()
        }
        return done.wait(timeout: .now() + timeout) == .success
    }

    /// Forgets unanswered requests older than `requestLifetime` (maintenance).
    public func expire() {
        let t = now()
        lock.lock(); defer { lock.unlock() }
        for e in entries.values where e.held.isEmpty && t.timeIntervalSince(e.request.lastAt) > _requestLifetime {
            removeLocked(e.request.id)
        }
    }

    /// Accesses currently held, over all requests.
    public var heldAccesses: Int { locked { heldCount } }

    /// Waits until responses queued so far have run (tests).
    func drain() { queue.sync {} }

    /// Waits until display data queued so far has been redacted (tests).
    func drainRedaction() { redactQueue.sync {} }
}
