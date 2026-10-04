import Foundation
import WhoReadCore

/// Version of the request/response protocol. Bumped on incompatible changes.
/// 2: daily aggregates, alert firstTime, rule subject cdhash/exceptOwners, exception access/chain
/// scoping, status rulesLoadError/sourceDroppedEvents.
public let whoReadIPCVersion = 2

/// Requests from the app / CLI to the daemon. Encoded as JSON over XPC (`Data` in, `Data` out)
/// or over the development Unix socket.
public enum IPCRequest: Codable, Sendable {
    case hello(clientVersion: Int)
    case status
    case events(EventQuery)
    /// Live tail for the UI: events after `afterID`, served from the in-memory ring buffer.
    case live(afterID: Int64?, limit: Int, includeBenign: Bool)
    case alerts(AlertQuery)
    case alertAction(alertID: Int64, action: AlertAction)
    /// nil marks every alert read.
    case markAlertsRead(ids: [Int64]?)
    case summaries(since: Date?)
    /// Rolled-up per-day activity (details older than the detail window).
    case dailyAggregates(since: Date?)
    case rules
    case upsertRule(Rule)
    case deleteRule(id: String)
    case settings
    case updateSettings(Settings)
    /// Turning enforcement *off* from a non-root peer is refused unless the peer is the signed app.
    case setEnforcement(enabled: Bool)
    case setPaused(Bool)
    case catalog
    case updateCatalog(Catalog)
    case resetCatalog
    case agents
    case baseline
    /// Clears learned entries and restarts the learning period (approvals are kept).
    case restartLearning
}

public enum IPCResponse: Codable, Sendable {
    case hello(serverVersion: Int)
    case status(DaemonStatus)
    case events([AnalyzedEvent])
    case alerts([Alert])
    case summaries([UsageSummary])
    case dailyAggregates([DailyAggregate])
    case rules([Rule])
    case settings(Settings)
    case catalog(CatalogInfo)
    case agents(AgentCatalog)
    case baseline([BaselineEntry])
    case ok
    case error(IPCError)
}

public struct IPCError: Error, Codable, Sendable, CustomStringConvertible, Equatable {
    public enum Code: String, Codable, Sendable {
        case notPermitted
        case notFound
        case invalid
        case unavailable
        case internalError
        case versionMismatch
    }

    public var code: Code
    public var message: String

    public init(_ code: Code, _ message: String) {
        self.code = code
        self.message = message
    }

    public var description: String { "\(code.rawValue): \(message)" }
}

/// The catalog plus what the daemon found on this machine.
public struct CatalogInfo: Codable, Sendable {
    public var catalog: Catalog
    /// Category id → at least one prefix exists on disk.
    public var detected: [String: Bool]
    /// Concrete prefixes after `~` expansion and symlink resolution.
    public var prefixes: [MonitoredPrefix]
    public var homeDirectories: [String]

    public init(catalog: Catalog, detected: [String: Bool], prefixes: [MonitoredPrefix], homeDirectories: [String]) {
        self.catalog = catalog
        self.detected = detected
        self.prefixes = prefixes
        self.homeDirectories = homeDirectories
    }
}

/// Menu bar states from the brief: Learning, Monitoring, Enforcing, Paused, Error.
public enum DaemonMode: String, Codable, Sendable {
    case learning
    case monitoring
    case enforcing
    case paused
    case error
}

public enum SourceKind: String, Codable, Sendable {
    case eslogger
    case native
    case replay
}

public struct DaemonStatus: Codable, Sendable {
    public var version: String
    public var pid: Int32
    public var startedAt: Date
    public var mode: DaemonMode
    public var source: SourceKind
    public var sourceRunning: Bool
    public var sourceError: String?
    /// e.g. "Full Disk Access missing for whoreadd".
    public var sourceHint: String?
    public var sourceCanEnforce: Bool
    public var learning: Bool
    public var learningEndsAt: Date
    public var monitoringPaused: Bool
    public var enforcementEnabled: Bool
    public var enforcementActive: Bool
    public var enforcementInactiveReasons: [EnforcementState.InactiveReason]
    public var latencyTripReason: String?
    public var killSwitchFilePresent: Bool
    public var latency: LatencyStats
    public var parser: EsloggerParser.Stats?
    public var counts: StoreCounts
    public var unreadAlerts: Int
    public var lastEventAt: Date?
    public var eventsProcessed: UInt64
    public var writerDropped: UInt64
    public var monitoredPrefixes: Int
    public var homeDirectories: [String]
    /// The stored rules could not be read: enforcement stays off until they load (or are replaced).
    public var rulesLoadError: String?
    /// File events the source had to drop because the analysis backlog was full (native source).
    public var sourceDroppedEvents: UInt64?

    public init(version: String, pid: Int32, startedAt: Date, mode: DaemonMode, source: SourceKind, sourceRunning: Bool,
                sourceError: String?, sourceHint: String?, sourceCanEnforce: Bool, learning: Bool, learningEndsAt: Date,
                monitoringPaused: Bool, enforcementEnabled: Bool, enforcementActive: Bool,
                enforcementInactiveReasons: [EnforcementState.InactiveReason], latencyTripReason: String?,
                killSwitchFilePresent: Bool, latency: LatencyStats, parser: EsloggerParser.Stats?, counts: StoreCounts,
                unreadAlerts: Int, lastEventAt: Date?, eventsProcessed: UInt64, writerDropped: UInt64, monitoredPrefixes: Int,
                homeDirectories: [String], rulesLoadError: String? = nil, sourceDroppedEvents: UInt64? = nil) {
        self.version = version
        self.pid = pid
        self.startedAt = startedAt
        self.mode = mode
        self.source = source
        self.sourceRunning = sourceRunning
        self.sourceError = sourceError
        self.sourceHint = sourceHint
        self.sourceCanEnforce = sourceCanEnforce
        self.learning = learning
        self.learningEndsAt = learningEndsAt
        self.monitoringPaused = monitoringPaused
        self.enforcementEnabled = enforcementEnabled
        self.enforcementActive = enforcementActive
        self.enforcementInactiveReasons = enforcementInactiveReasons
        self.latencyTripReason = latencyTripReason
        self.killSwitchFilePresent = killSwitchFilePresent
        self.latency = latency
        self.parser = parser
        self.counts = counts
        self.unreadAlerts = unreadAlerts
        self.lastEventAt = lastEventAt
        self.eventsProcessed = eventsProcessed
        self.writerDropped = writerDropped
        self.monitoredPrefixes = monitoredPrefixes
        self.homeDirectories = homeDirectories
        self.rulesLoadError = rulesLoadError
        self.sourceDroppedEvents = sourceDroppedEvents
    }
}

/// Who is on the other end of a connection.
public struct IPCPeer: Sendable {
    public var pid: Int32?
    public var euid: UInt32?
    /// Passed the code-signing requirement (XPC) — i.e. it is our app or CLI.
    public var isTrustedCode: Bool

    public init(pid: Int32?, euid: UInt32?, isTrustedCode: Bool) {
        self.pid = pid
        self.euid = euid
        self.isTrustedCode = isTrustedCode
    }

    public var isRoot: Bool { euid == 0 }

    public static let inProcess = IPCPeer(pid: getpid(), euid: geteuid(), isTrustedCode: true)
}

public protocol IPCHandler: AnyObject, Sendable {
    func handle(_ request: IPCRequest, peer: IPCPeer) -> IPCResponse
}

public protocol IPCClient: Sendable {
    func send(_ request: IPCRequest) throws -> IPCResponse
}

public enum IPCCodec {
    static let encoder = Exporter.encoder(pretty: false)
    static let decoder = Exporter.decoder()

    public static func encode(_ r: IPCRequest) throws -> Data { try encoder.encode(r) }
    public static func encode(_ r: IPCResponse) throws -> Data { try encoder.encode(r) }
    public static func decodeRequest(_ d: Data) throws -> IPCRequest { try decoder.decode(IPCRequest.self, from: d) }
    public static func decodeResponse(_ d: Data) throws -> IPCResponse { try decoder.decode(IPCResponse.self, from: d) }

    /// Server side: bytes in, bytes out, never throws.
    public static func serve(_ data: Data, handler: IPCHandler, peer: IPCPeer) -> Data {
        let response: IPCResponse
        do {
            response = handler.handle(try decodeRequest(data), peer: peer)
        } catch {
            response = .error(IPCError(.invalid, "undecodable request: \(error)"))
        }
        return (try? encode(response)) ?? Data(#"{"error":{"_0":{"code":"internalError","message":"encode failed"}}}"#.utf8)
    }
}

/// Calls the handler directly (tests, `whoread replay`, `--direct` mode).
public final class InProcessClient: IPCClient, @unchecked Sendable {
    let handler: IPCHandler
    let peer: IPCPeer
    /// Round-trip through JSON so tests exercise the codec.
    let roundTrip: Bool

    public init(handler: IPCHandler, peer: IPCPeer = .inProcess, roundTrip: Bool = true) {
        self.handler = handler
        self.peer = peer
        self.roundTrip = roundTrip
    }

    public func send(_ request: IPCRequest) throws -> IPCResponse {
        guard roundTrip else { return handler.handle(request, peer: peer) }
        return try IPCCodec.decodeResponse(IPCCodec.serve(try IPCCodec.encode(request), handler: handler, peer: peer))
    }
}

extension IPCClient {
    /// Sends and unwraps `.error` into a thrown `IPCError`.
    public func call(_ request: IPCRequest) throws -> IPCResponse {
        let r = try send(request)
        if case .error(let e) = r { throw e }
        return r
    }

    public func status() throws -> DaemonStatus {
        guard case .status(let s) = try call(.status) else { throw IPCError(.internalError, "unexpected response") }
        return s
    }

    public func events(_ q: EventQuery) throws -> [AnalyzedEvent] {
        guard case .events(let e) = try call(.events(q)) else { throw IPCError(.internalError, "unexpected response") }
        return e
    }

    public func alerts(_ q: AlertQuery) throws -> [Alert] {
        guard case .alerts(let a) = try call(.alerts(q)) else { throw IPCError(.internalError, "unexpected response") }
        return a
    }

    public func summaries(since: Date?) throws -> [UsageSummary] {
        guard case .summaries(let s) = try call(.summaries(since: since)) else { throw IPCError(.internalError, "unexpected response") }
        return s
    }

    public func dailyAggregates(since: Date?) throws -> [DailyAggregate] {
        guard case .dailyAggregates(let d) = try call(.dailyAggregates(since: since)) else { throw IPCError(.internalError, "unexpected response") }
        return d
    }

    public func rules() throws -> [Rule] {
        guard case .rules(let r) = try call(.rules) else { throw IPCError(.internalError, "unexpected response") }
        return r
    }

    public func settings() throws -> Settings {
        guard case .settings(let s) = try call(.settings) else { throw IPCError(.internalError, "unexpected response") }
        return s
    }

    public func catalog() throws -> CatalogInfo {
        guard case .catalog(let c) = try call(.catalog) else { throw IPCError(.internalError, "unexpected response") }
        return c
    }

    public func agents() throws -> AgentCatalog {
        guard case .agents(let a) = try call(.agents) else { throw IPCError(.internalError, "unexpected response") }
        return a
    }
}
