import Foundation
import WhoReadCore
import WhoReadIPC

/// Where events come from: eslogger (monitor only), native Endpoint Security (monitor + AUTH),
/// or a JSONL replay file (tests, demos).
public protocol EventSource: AnyObject, Sendable {
    var kind: SourceKind { get }
    var canEnforce: Bool { get }
    var state: SourceState { get }
    /// Parser statistics, when the source parses eslogger JSON.
    var parserStats: EsloggerParser.Stats? { get }
    func start(sink: EventSink) throws
    func stop()
    /// Monitored prefixes (+ literal ancestors) changed. eslogger: rebuild the prefilter.
    /// Native: re-mute target paths.
    func updateMonitoring(prefixes: [String], ancestors: [String], readdir: Bool)
    /// Enforcement turned on/off: native source subscribes / unsubscribes AUTH events.
    func enforcementChanged(active: Bool)
}

extension EventSource {
    public var parserStats: EsloggerParser.Stats? { nil }
    public func enforcementChanged(active: Bool) {}
}

public struct SourceState: Sendable, Codable, Equatable {
    public var running: Bool
    public var error: String?
    public var hint: String?
    public var finished: Bool

    public init(running: Bool = false, error: String? = nil, hint: String? = nil, finished: Bool = false) {
        self.running = running
        self.error = error
        self.hint = hint
        self.finished = finished
    }
}

/// Receives events from a source, in order.
public protocol EventSink: AnyObject, Sendable {
    func receive(_ event: SourceEvent, context: RuleContext)
    func sourceStateChanged(_ state: SourceState)
}

/// Synchronous, in-memory decision for AUTH events (native source only).
public protocol AuthDecider: AnyObject, Sendable {
    func decide(_ activity: FileActivity) -> RuleDecision
    /// Latency accounting for every AUTH response.
    func recordResponse(micros: UInt64, missedDeadline: Bool)
}

/// Thread-safe box for source state.
final class StateBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value = SourceState()
    func get() -> SourceState { lock.lock(); defer { lock.unlock() }; return value }
    func set(_ v: SourceState) { lock.lock(); value = v; lock.unlock() }
    func update(_ f: (inout SourceState) -> Void) -> SourceState {
        lock.lock(); defer { lock.unlock() }
        f(&value)
        return value
    }
}
