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
}

/// When the app polls the daemon: every second, every 250 ms while questions are open (a held
/// access is denied within seconds if nobody answers), with a full poll at most every 10 s.
public struct PollSchedule: Equatable, Sendable {
    public static let idleInterval: TimeInterval = 1
    public static let askingInterval: TimeInterval = 0.25
    public static let fullInterval: TimeInterval = 10

    public enum Kind: Equatable, Sendable {
        /// Status, questions, alerts, live tail.
        case fast
        /// Adds summaries, rules, settings, the catalog and agents.
        case full
        /// Only the questions: the ticks between fast polls while questions are open.
        case asks
    }

    public private(set) var lastFull: Date?
    /// The last fast or full poll.
    public private(set) var lastFast: Date?

    public init() {}

    public static func interval(openAsks: Int) -> TimeInterval {
        openAsks > 0 ? askingInterval : idleInterval
    }

    /// Time-based, so the faster cadence does not make full polls more frequent.
    public func isFullDue(now: Date) -> Bool {
        lastFull.map { now.timeIntervalSince($0) >= PollSchedule.fullInterval } ?? true
    }

    /// What a timer tick fetches. Status, alerts and the live tail stay at once a second: an
    /// unanswered question can stay open for an hour, and the alerts list is large. `needsFull`:
    /// nothing to plan notifications with yet (no settings).
    public func kind(now: Date, openAsks: Int, needsFull: Bool = false) -> Kind {
        if needsFull || isFullDue(now: now) { return .full }
        // Half a tick of slack: timers fire late, never early.
        if openAsks > 0, let last = lastFast,
           now.timeIntervalSince(last) < PollSchedule.idleInterval - PollSchedule.askingInterval / 2 {
            return .asks
        }
        return .fast
    }

    public mutating func fullStarted(at now: Date) {
        lastFull = now
        lastFast = now
    }

    public mutating func fastStarted(at now: Date) {
        lastFast = now
    }
}
