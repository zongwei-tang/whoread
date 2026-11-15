import Foundation
import WhoReadCore

/// Version of the request/response protocol. Bumped on incompatible changes.
/// 2: daily aggregates, alert firstTime, rule subject cdhash/exceptOwners, exception access/chain
/// scoping, status rulesLoadError/sourceDroppedEvents.
/// 3: ask mode (asks, answerAsk, Verdict.ask, AlertKind.ask, AlertAction.trustApplePrograms,
/// Rule.chainAgents, Settings.trustApplePrograms), no automatic enforcement trips.
/// 4: file operations setmode, setowner, setacl and mount (an older client cannot decode events that
/// carry them), status sourceDeadlineMissMode.
public let whoReadIPCVersion = 4

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
    /// Replaces the whole rule list (root or the app). The only rule change accepted while the stored
    /// rules cannot be read; the old rows are then kept in the database's `rules_backup` table.
    case replaceRules([Rule])
    /// Ask mode: questions waiting for an answer. Polling it also tells the daemon an answering app is
    /// present (without one, ask-mode accesses are denied at once instead of held).
    case asks
    /// Answers a question: allowOnce (10 minutes), alwaysAllow, keepBlocking (deny now),
    /// blockFromNowOn (deny rule), trustApplePrograms. Allowing needs root or the signed app.
    case answerAsk(id: Int64, action: AlertAction)

    /// A read of the stored history that can take long on a large store (events, alerts, per-app and
    /// per-day totals, the baseline): a client may wait longer for it (`XPCClient.queryTimeout`).
    public var mayTakeLong: Bool {
        switch self {
        case .events, .alerts, .summaries, .dailyAggregates, .baseline: return true
        default: return false
        }
    }
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
    case asks([AskRequest])
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

    /// Why a request got no answer, as far as the client's transport can tell (`code` is then
    /// `.unavailable`). Set by the transports' clients only and never encoded (see `CodingKeys`): an
    /// error the daemon replies with has none.
    public enum NoAnswer: String, Sendable {
        /// Nothing answers at that name or path: the daemon is not installed or not running (or this
        /// process may not look the service up, as inside a sandbox).
        case notFound
        /// The daemon refused this program: XPC reported a code-signing requirement it does not meet
        /// (as a rule only the side that set the requirement is told so), or the dev socket's
        /// permissions do not let this user connect.
        case refused
        /// The connection was closed before the daemon's first answer on it: the daemon refused this
        /// program (a code-signing requirement it does not meet reaches the client this way), or it
        /// stopped just then.
        case droppedBeforeAnswer
        /// The connection was closed while waiting, after earlier answers on it: the daemon stopped,
        /// crashed or restarted.
        case droppedAfterAnswer
        /// No answer in time: the daemon took the request but is busy (a large query) or stuck.
        case timedOut
        /// The answer is larger than this client takes.
        case replyTooLarge
        /// No connection, for a reason the transport cannot tell: the daemon is not running, or it
        /// refuses this program.
        case noConnection
    }

    public var code: Code
    public var message: String
    public var noAnswer: NoAnswer? = nil

    enum CodingKeys: String, CodingKey {
        case code, message
    }

    public init(_ code: Code, _ message: String, noAnswer: NoAnswer? = nil) {
        self.code = code
        self.message = message
        self.noAnswer = noAnswer
    }

    public var description: String { "\(code.rawValue): \(message)" }
}

/// What `whoread` says when a request got no answer (`IPCError.noAnswer`): what happened, and what to
/// check or do about it.
public enum NoAnswerHelp {
    /// Where the request went.
    public enum Target: Sendable, Equatable {
        case xpc(service: String)
        case socket(path: String)
    }

    /// The message, one line per element: what happened (with the transport's own account, `message`),
    /// then what to check or do. An error without a kind gets the hint for "cannot tell".
    public static func lines(for error: IPCError, target: Target) -> [String] {
        let detail = error.message
        let kind = error.noAnswer ?? .noConnection
        switch (kind, target) {
        case (.timedOut, _):
            return ["the WhoRead daemon did not answer in time: \(detail)",
                    "  It has the request but is busy or stuck. A read of a large history can take long: ask for less "
                        + "(a smaller --limit, a later --since), or use whoread export, which reads in pages."]
        case (.replyTooLarge, _):
            return ["the WhoRead daemon's answer is too large: \(detail)",
                    "  Ask for less (a smaller --limit, a later --since), or use whoread export, which reads in pages."]
        case (.refused, .xpc):
            return ["the WhoRead daemon refused this program: \(detail)", "  " + refusal]
        case (.droppedBeforeAnswer, .xpc(let service)):
            return ["the WhoRead daemon closed the connection without answering: \(detail)",
                    "  Most likely it refused this program. " + refusal,
                    "  Or it stopped just then: check it with \(check(service))"]
        case (.droppedAfterAnswer, .xpc(let service)):
            return ["the connection to the WhoRead daemon broke while waiting for its answer: \(detail)",
                    "  It had answered before, so it stopped, crashed or restarted since: try again, and check it with \(check(service))"]
        case (.notFound, .xpc(let service)) where detail.contains("Sandbox restriction"):
            // An AI agent's command sandbox, for one: the daemon may well be running.
            return ["cannot reach the WhoRead daemon: \(detail)",
                    "  A sandbox keeps this process from looking up \(service): run whoread outside it. "
                        + "Whether the daemon runs: \(check(service))"]
        case (.notFound, .xpc(let service)):
            return ["cannot reach the WhoRead daemon: \(detail)",
                    "  Nothing answers at \(service): is the daemon installed and running? Check it with \(check(service))"]
        case (.noConnection, .xpc(let service)):
            return ["cannot reach the WhoRead daemon: \(detail)",
                    "  Is it running? Check it with \(check(service))",
                    "  If it is, it may be refusing this program. " + refusal]
        case (.refused, .socket):
            return ["the WhoRead daemon refused this program: \(detail)",
                    "  The dev socket lets only its owner connect (whoreadd --dev-socket-mode sets who else may): run this with sudo."]
        case (.droppedBeforeAnswer, .socket):
            return ["the WhoRead daemon closed the connection without answering: \(detail)",
                    "  It was stopping, or it was already serving as many connections as it takes at once: try again."]
        case (.droppedAfterAnswer, .socket):
            return ["the connection to the WhoRead daemon broke while waiting for its answer: \(detail)",
                    "  It stopped or restarted: try again."]
        case (.notFound, .socket(let path)):
            return ["cannot reach the WhoRead daemon: \(detail)",
                    "  Nothing listens at \(path): is whoreadd running with --dev-socket \(path)?"]
        case (.noConnection, .socket(let path)):
            return ["cannot reach the WhoRead daemon: \(detail)",
                    "  Is whoreadd running with --dev-socket \(path)?"]
        }
    }

    /// Why a running daemon refuses a program, and what fixes it (XPC: the daemon was installed with a
    /// code-signing requirement for its whoread and app; root may use any build).
    static let refusal = "It takes only the whoread and WhoRead app it was installed with, so a rebuilt or re-signed "
        + "copy is refused: run scripts/install.sh again, or use the whoread that ships with the installed WhoRead app "
        + "(sudo whoread works with any build)."

    /// How to see whether the daemon behind `service` runs: the dev LaunchDaemon has the built-in name,
    /// the system extension its own.
    static func check(_ service: String) -> String {
        service == WhoReadPaths.machServiceName
            ? "sudo launchctl print system/com.whoread.daemon"
            : "systemextensionsctl list (the WhoRead extension should be activated and enabled)"
    }
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
    /// Why an older daemon switched enforcement off automatically. Always nil since protocol 3 (ask
    /// mode: nothing switches enforcement off automatically).
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
    /// NOTIFY events the kernel dropped before the source saw them (sequence-number gaps).
    public var sourceKernelDrops: UInt64?
    /// Ask mode: questions waiting for an answer.
    public var pendingAsks: Int?
    /// The previous daemon instance stopped while AUTH events were subscribed (likely killed for a
    /// missed deadline). Enforcement stays as the user set it; this is for the user to know.
    public var uncleanStop: String?
    /// Native source: what the kernel does with an AUTH message not answered by its deadline
    /// ("fail-closed", "kill", "fail-open", "unknown"); nil for other sources or while no client exists.
    /// Optional, so older clients and daemons still decode the status.
    public var sourceDeadlineMissMode: String?
    /// Native source: AUTH accesses the kernel denied although the daemon allowed them or never saw them,
    /// and the default mute set. nil for other sources; optional, so older clients and daemons still
    /// decode the status.
    public var sourceAuth: SourceAuthCounts?

    public init(version: String, pid: Int32, startedAt: Date, mode: DaemonMode, source: SourceKind, sourceRunning: Bool,
                sourceError: String?, sourceHint: String?, sourceCanEnforce: Bool, learning: Bool, learningEndsAt: Date,
                monitoringPaused: Bool, enforcementEnabled: Bool, enforcementActive: Bool,
                enforcementInactiveReasons: [EnforcementState.InactiveReason], latencyTripReason: String?,
                killSwitchFilePresent: Bool, latency: LatencyStats, parser: EsloggerParser.Stats?, counts: StoreCounts,
                unreadAlerts: Int, lastEventAt: Date?, eventsProcessed: UInt64, writerDropped: UInt64, monitoredPrefixes: Int,
                homeDirectories: [String], rulesLoadError: String? = nil, sourceDroppedEvents: UInt64? = nil,
                sourceKernelDrops: UInt64? = nil, pendingAsks: Int? = nil, uncleanStop: String? = nil,
                sourceDeadlineMissMode: String? = nil, sourceAuth: SourceAuthCounts? = nil) {
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
        self.sourceKernelDrops = sourceKernelDrops
        self.pendingAsks = pendingAsks
        self.uncleanStop = uncleanStop
        self.sourceDeadlineMissMode = sourceDeadlineMissMode
        self.sourceAuth = sourceAuth
    }
}

/// What the native source learns about AUTH outcomes from the kernel's side, since the daemon started.
public struct SourceAuthCounts: Codable, Sendable, Equatable {
    /// Accesses the daemon allowed but answered at or after their deadline, or whose answer es_respond
    /// did not deliver, while the deadline miss mode was fail-closed (macOS 27): the kernel denied them.
    /// Each is recorded as a denied event with no rule.
    public var lateDenied: UInt64
    /// AUTH messages the kernel dropped from a full queue (sequence-number gaps per event type) while
    /// the mode was fail-closed: denied. Nothing is known about them, so they are not recorded as events.
    public var droppedDenied: UInt64
    /// The same in any other mode (kill before macOS 27): allowed.
    public var droppedAllowed: UInt64
    /// Program paths macOS mutes for the AUTH events WhoRead answers (the ES default mute set): their
    /// accesses are recorded but can never be asked about or blocked. nil when it could not be read.
    public var defaultMutedPrograms: Int?

    public init(lateDenied: UInt64 = 0, droppedDenied: UInt64 = 0, droppedAllowed: UInt64 = 0, defaultMutedPrograms: Int? = nil) {
        self.lateDenied = lateDenied
        self.droppedDenied = droppedDenied
        self.droppedAllowed = droppedAllowed
        self.defaultMutedPrograms = defaultMutedPrograms
    }

    /// The `whoread status` line about the default mute set, if anything is muted.
    public var mutedLine: String? {
        guard let n = defaultMutedPrograms, n > 0 else { return nil }
        return "  muted:        macOS sends no AUTH event for \(n) system program path\(n == 1 ? "" : "s") "
            + "(its default mute set): seen, but never asked about or blocked"
    }

    /// The `whoread status` warning for messages the kernel dropped for the source (sequence gaps over
    /// every event type). The AUTH messages among them are counted again, by outcome, in `warningLines`.
    public static func kernelDropLine(total: UInt64, auth: SourceAuthCounts?) -> String? {
        guard total > 0 else { return nil }
        let ofAuth = min((auth?.droppedDenied ?? 0) &+ (auth?.droppedAllowed ?? 0), total)
        return "  WARNING: \(total) events dropped by the kernel before the source saw them"
            + (ofAuth > 0 ? " (\(ofAuth) of them AUTH accesses, counted below)" : "")
    }

    /// The `whoread status` warnings for these counts (none when there is nothing to warn about).
    public var warningLines: [String] {
        var out: [String] = []
        if lateDenied > 0 {
            out.append("  WARNING: \(lateDenied) access\(lateDenied == 1 ? "" : "es") allowed too late: the answer missed the AUTH "
                       + "deadline and the kernel denied \(lateDenied == 1 ? "it" : "them") (an access to a sensitive file is "
                       + "recorded as blocked, by no rule)")
        }
        if droppedDenied > 0 {
            out.append("  WARNING: \(droppedDenied) AUTH access\(droppedDenied == 1 ? "" : "es") dropped by the kernel from a full "
                       + "queue and denied (fail-closed); not recorded, nothing is known about \(droppedDenied == 1 ? "it" : "them")")
        }
        if droppedAllowed > 0 {
            out.append("  WARNING: \(droppedAllowed) AUTH access\(droppedAllowed == 1 ? "" : "es") dropped by the kernel from a full "
                       + "queue and allowed (kill mode); not recorded, nothing is known about \(droppedAllowed == 1 ? "it" : "them")")
        }
        return out
    }
}

/// Who is on the other end of a connection.
public struct IPCPeer: Sendable, Equatable {
    /// For logs only: a pid names whoever holds it now, not the code that sent a message.
    public var pid: Int32?
    public var euid: UInt32?
    /// Passed the code-signing requirement (XPC) — i.e. it is our app or CLI.
    public var isTrustedCode: Bool
    /// The WhoRead app: XPC checks every message on this connection, by the audit token it carries,
    /// against the app's requirement (`XPCPeerPolicy`). Set only by the transport, never from a pid.
    public var isApp: Bool

    public init(pid: Int32?, euid: UInt32?, isTrustedCode: Bool, isApp: Bool = false) {
        self.pid = pid
        self.euid = euid
        self.isTrustedCode = isTrustedCode
        self.isApp = isApp
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

    /// Largest request the daemon decodes: as large as the largest reply a client takes
    /// (`UnixSocket.maxFrame`). What whoread and the app send is far smaller (a catalog, or a rule with
    /// 256 exceptions, is about 1 MiB). It does refuse some extreme rule lists the validator would still
    /// accept; the dev socket refuses them already (`UnixSocket.maxRequestFrame`), and their `.rules`
    /// reply would be larger than a client takes anyway.
    public static let maxRequestSize = 64 * 1024 * 1024

    public static func encode(_ r: IPCRequest) throws -> Data { try encoder.encode(r) }
    public static func encode(_ r: IPCResponse) throws -> Data { try encoder.encode(r) }
    public static func decodeRequest(_ d: Data) throws -> IPCRequest { try decoder.decode(IPCRequest.self, from: d) }
    public static func decodeResponse(_ d: Data) throws -> IPCResponse { try decoder.decode(IPCResponse.self, from: d) }

    /// Server side: bytes in, bytes out, never throws. A request larger than `maxRequestSize` is refused
    /// unread: it is neither decoded nor handed to the handler, which is where peers are authorized. Over
    /// XPC any local process may send one when the daemon runs without a client requirement, and the
    /// whole request would otherwise be decoded (another copy of it) before being refused (ipc-4).
    public static func serve(_ data: Data, handler: IPCHandler, peer: IPCPeer) -> Data {
        let response: IPCResponse
        if data.count > maxRequestSize {
            response = .error(IPCError(.invalid, "request too large: \(data.count) bytes, the daemon accepts at most "
                                       + "\(maxRequestSize / (1024 * 1024)) MiB"))
        } else {
            do {
                response = handler.handle(try decodeRequest(data), peer: peer)
            } catch {
                response = .error(IPCError(.invalid, "undecodable request: \(error)"))
            }
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
