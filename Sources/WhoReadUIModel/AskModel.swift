import Foundation
import WhoReadCore
import WhoReadIPC

/// Ask mode (docs/ASK_MODE.md): the answers the app offers for an open question.
public enum AskAnswers {
    /// "Allow once (10 min)", "Always allow", and "Allow all Apple programs" when the requester is
    /// an Apple program with no AI agent in its chain. Allowing needs root or the signed app.
    public static func allowActions(for ask: AskRequest) -> [AlertAction] {
        [.allowOnce, .alwaysAllow] + (ask.appleProgram ? [.trustApplePrograms] : [])
    }

    /// "Deny" (this access and the other held ones) and "Always deny" (a deny rule). Open to the
    /// console user.
    public static let denyActions: [AlertAction] = [.keepBlocking, .blockFromNowOn]

    /// Display order, as on `ask` alerts (`Alert.availableActions`).
    public static func actions(for ask: AskRequest) -> [AlertAction] { actions(apple: ask.appleProgram) }

    /// `apple`: the notification category that offers "Allow all Apple programs".
    public static func actions(apple: Bool) -> [AlertAction] {
        [.allowOnce, .alwaysAllow] + denyActions + (apple ? [.trustApplePrograms] : [])
    }

    public static func isAllow(_ a: AlertAction) -> Bool {
        a == .allowOnce || a == .alwaysAllow || a == .trustApplePrograms
    }

    /// The `whoread ask ID <verb>` spelling of an answer.
    public static func cliVerb(_ a: AlertAction) -> String {
        switch a {
        case .allowOnce: return "allow-once"
        case .alwaysAllow: return "allow"
        case .keepBlocking: return "deny"
        case .blockFromNowOn: return "block"
        case .trustApplePrograms: return "trust-apple"
        case .ignore: return "ignore"
        }
    }
}

extension AskRequest {
    /// "AI agent in the chain: Claude Code" when one is: the answer covers the app only as driven by
    /// that agent, and the headline may name just the app (Terminal). nil without an agent.
    public func agentsLine(_ language: Language, agentName: (String) -> String = { $0 }) -> String? {
        guard !key.chainAgents.isEmpty else { return nil }
        return L10n.f(.askAgentsFormat, key.chainAgents.map { DisplayText.name(agentName($0)) }.joined(separator: ", "), language: language)
    }

    /// This question as an `ask` alert, so it reads like one (`AlertFormatter.headline`).
    public var asAlert: Alert {
        Alert(id: id, kind: .ask, createdAt: firstAt, updatedAt: lastAt, windowEndsAt: lastAt, responsible: responsible,
              categoryID: key.categoryID, severity: severity, count: attempts, accesses: key.access, firstPath: path,
              firstEventID: 0, lastEventID: 0, paths: [path], chain: chain, agentID: agentID, ruleID: nil,
              appleProgram: appleProgram, chainAgents: key.chainAgents, ancestryKnown: key.ancestryKnown)
    }

    /// "Allow once (10 min) and Always allow cover: Terminal (any program run in it) reading SSH keys,
    /// only when the chain has no AI agent." The answer is per app, not per program: shown with every
    /// question (banner, menu bar, Alerts tab) next to the program that asked.
    public func allowCoverageLine(_ f: AlertFormatter, agentName: (String) -> String = { $0 }) -> String {
        L10n.f(.askCoversFormat, f.allowCoverage(responsible, categoryID: key.categoryID, access: key.access,
                                                 chainAgents: key.chainAgents, agentName: agentName), language: f.language)
    }

    /// The daemon left out the file path (and the command lines): it does not serve this connection
    /// as the signed app or root, and the file may lie in a folder only Full Disk Access can read.
    /// The daemon puts a note there instead; every real path is absolute.
    public var pathHidden: Bool { !path.hasPrefix("/") }

    /// `asAlert` for showing: a hidden path reads as such, in the UI language.
    public func displayAlert(_ language: Language) -> Alert {
        var a = asAlert
        if pathHidden {
            a.firstPath = L10n.t(.askPathHidden, language)
            a.paths = [a.firstPath]
        }
        return a
    }
}

extension Alert {
    /// "Always allow covers: Terminal (any program run in it) reading SSH keys, only when the chain has
    /// no AI agent." for an open alert that offers "always allow" (it saves the same app × category
    /// answer as a question). Where "allow once" saves the 10-minute answer for the whole app too (a
    /// question's alert, a block without a rule) it is named as well; on a rule's block it allows only
    /// that file, once (DaemonCore.apply). nil otherwise.
    public func allowCoverageLine(_ f: AlertFormatter, agentName: (String) -> String = { $0 }) -> String? {
        guard status != .resolved, availableActions.contains(.alwaysAllow) else { return nil }
        // The AI agents the answer is scoped to, as the daemon takes them from an alert.
        let agents = chain.compactMap(\.agentID)
        let coverage = f.allowCoverage(responsible, categoryID: categoryID, access: accesses, chainAgents: agents, agentName: agentName)
        let allowOnceIsAppWide = kind == .ask || (kind == .blocked && ruleID == nil)
        return L10n.f(allowOnceIsAppWide ? .askCoversFormat : .alertCoversFormat, coverage, language: f.language)
    }
}

/// When the app polls the daemon. Two loops on two connections: the questions every second, every
/// 250 ms while any is open (a held access is denied within seconds if nobody answers); status and
/// history every second, with a full poll at most every 10 s. A slow or refused history read never
/// delays a question or an answer.
public struct PollSchedule: Equatable, Sendable {
    public static let idleInterval: TimeInterval = 1
    public static let askingInterval: TimeInterval = 0.25
    public static let fullInterval: TimeInterval = 10

    public enum Kind: Equatable, Sendable {
        /// Status, alerts, live tail.
        case fast
        /// Adds settings, the catalog, agents, summaries and rules.
        case full
    }

    public private(set) var lastFull: Date?
    /// The last fast or full poll.
    public private(set) var lastFast: Date?

    public init() {}

    /// How often the questions are read.
    public static func interval(openAsks: Int) -> TimeInterval {
        openAsks > 0 ? askingInterval : idleInterval
    }

    /// Time-based, so the faster cadence does not make full polls more frequent.
    public func isFullDue(now: Date) -> Bool {
        lastFull.map { now.timeIntervalSince($0) >= PollSchedule.fullInterval } ?? true
    }

    /// What a tick of the status and history loop (once a second) fetches. `needsFull`: nothing to
    /// plan notifications with yet (no settings).
    public func kind(now: Date, needsFull: Bool = false) -> Kind {
        needsFull || isFullDue(now: now) ? .full : .fast
    }

    public mutating func fullStarted(at now: Date) {
        lastFull = now
        lastFast = now
    }

    public mutating func fastStarted(at now: Date) {
        lastFast = now
    }
}

/// When to drop a connection the daemon does not serve as the signed app, and open a new one.
///
/// The daemon decides once per connection, when it is accepted, whether the peer is the app (a look
/// at its pid picks the code requirement XPC then checks on every message). A wrong guess leaves the
/// genuine app with a connection that may not read history, see question paths or allow; only a new
/// connection gets a new decision. At once on the first refusal, then after 30 s, doubling up to
/// 10 minutes while refusals continue (a development build is refused for good). A read that is
/// served again starts over.
public struct ConnectionRecovery: Equatable, Sendable {
    public static let firstRetry: TimeInterval = 30
    public static let maxRetry: TimeInterval = 600

    public private(set) var lastAttempt: Date?
    /// The wait before the next attempt (0 before the first).
    public private(set) var wait: TimeInterval = 0

    public init() {}

    /// `refused`: the last read on this connection was refused for want of the app's privileges.
    public mutating func shouldReconnect(now: Date, refused: Bool) -> Bool {
        guard refused else {
            lastAttempt = nil
            wait = 0
            return false
        }
        if let last = lastAttempt, now.timeIntervalSince(last) < wait { return false }
        lastAttempt = now
        wait = wait == 0 ? ConnectionRecovery.firstRetry : min(wait * 2, ConnectionRecovery.maxRetry)
        return true
    }
}
