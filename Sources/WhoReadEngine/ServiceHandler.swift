import Foundation
import WhoReadCore
import WhoReadIPC

/// Serves app / CLI requests. Runs on IPC threads; everything it touches is thread-safe.
///
/// Permission policy (see docs/THREAT_MODEL.md):
/// - non-root peers must be the console user, and both must be known (fail closed);
/// - status, settings, catalog, the agent list and the open questions (without their file path and
///   command lines) are open to the console user, and so are *strengthening* requests (enforcement on,
///   new deny/alert rule, "block from now on", denying a question, unpause, trust in Apple programs off);
/// - what the daemon recorded (events, live tail, alerts, summaries, daily totals, baseline, rules)
///   needs root or the signed app: it names files the daemon saw with Full Disk Access (Mail,
///   Messages, iCloud Drive…), which a process running as the user may not be able to read, and stored
///   command lines;
/// - *weakening* requests (enforcement off, pause, allow / exceptions — also as answers to questions —,
///   ignore / keep blocking / mark read on alerts — they silence alerts —, rule edits, deletes and
///   replacement, settings, catalog, restart learning) need root (`sudo whoread …`) or the signed
///   WhoRead app. An AI agent running as the user can run `whoread`, but can neither disable its own
///   guard nor dismiss the alert about itself; it can list questions and deny them, never allow.
///
/// The app is the peer the transport marked `isApp` (XPC checks each of its messages against the app
/// requirement); no pid is looked up here.
public final class ServiceHandler: IPCHandler, @unchecked Sendable {
    public enum Policy: Sendable {
        case strict
        /// Development: any peer may do anything (dev socket in tests).
        case permissive
    }

    let daemon: DaemonCore
    public var policy: Policy
    public var consoleUID: @Sendable () -> uid_t? = { ConsoleUser.uid() }

    init(daemon: DaemonCore, policy: Policy) {
        self.daemon = daemon
        self.policy = policy
    }

    @available(*, deprecated, message: "ignored: the transport recognises the app (IPCPeer.isApp), never a pid look-up")
    convenience init(daemon: DaemonCore, policy: Policy, peerVerifier: PeerVerifier) {
        self.init(daemon: daemon, policy: policy)
    }

    /// `recorded`: a read of what the daemon recorded (file paths, process chains, command lines).
    enum Privilege { case read, recorded, strengthen, weaken }

    func privilege(of request: IPCRequest) -> Privilege {
        switch request {
        case .hello, .status, .settings, .catalog, .agents, .asks:
            return .read
        case .events, .live, .alerts, .summaries, .dailyAggregates, .baseline, .rules:
            return .recorded
        case .answerAsk(_, let action):
            // Denying is strengthening; allowing (once, always, all Apple programs) weakens protection.
            switch action {
            case .keepBlocking, .blockFromNowOn: return .strengthen
            case .allowOnce, .alwaysAllow, .trustApplePrograms, .ignore: return .weaken
            }
        case .markAlertsRead:
            return .weaken
        case .setEnforcement(let on):
            return on ? .strengthen : .weaken
        case .setPaused(let paused):
            return paused ? .weaken : .strengthen
        case .alertAction(let id, .keepBlocking) where (try? daemon.store.alert(id: id))?.kind == .ask:
            // On a question's alert, "deny" only denies (like answerAsk's keepBlocking).
            return .strengthen
        case .updateSettings(let s) where DaemonCore.onlyTurnsOffAppleTrust(s, current: daemon.currentSettings):
            return .strengthen
        case .alertAction(_, let action):
            switch action {
            // An unprivileged "block from now on" adds the rule but leaves the alert open (DaemonCore.apply).
            case .blockFromNowOn: return .strengthen
            case .keepBlocking, .ignore, .allowOnce, .alwaysAllow, .trustApplePrograms: return .weaken
            }
        case .upsertRule(let rule):
            let exists = daemon.rules.rules.contains { $0.id == rule.id }
            return !exists && rule.enabled && (rule.action == .deny || rule.action == .alert) && rule.exceptions.isEmpty
                ? .strengthen : .weaken
        case .deleteRule, .replaceRules, .updateSettings, .updateCatalog, .resetCatalog, .restartLearning:
            return .weaken
        }
    }

    /// Root, the signed app, or permissive (dev) mode: may weaken protection and read what was recorded.
    /// Decided from the connection alone, so authorize and dispatch always agree.
    func isPrivileged(_ peer: IPCPeer) -> Bool {
        policy == .permissive || peer.isRoot || (peer.isTrustedCode && peer.isApp)
    }

    static let recordedReadRefusal = "reading recorded accesses, alerts and rules needs root (they name files, also in folders "
        + "only Full Disk Access can read, and keep command lines): run it with sudo, or use the WhoRead app"

    func authorize(_ request: IPCRequest, peer: IPCPeer) -> IPCError? {
        if policy == .permissive || peer.isRoot { return nil }
        // Unknown peer or unknown console user: refuse rather than serve someone else's history.
        guard let euid = peer.euid, let console = consoleUID(), euid == console else {
            return IPCError(.notPermitted, "only root or the console user may talk to the WhoRead daemon")
        }
        switch privilege(of: request) {
        case .read, .strengthen:
            return nil
        case .recorded:
            if isPrivileged(peer) { return nil }
            return IPCError(.notPermitted, ServiceHandler.recordedReadRefusal)
        case .weaken:
            if isPrivileged(peer) { return nil }
            return IPCError(.notPermitted, "this change weakens protection: run it with sudo, or use the WhoRead app")
        }
    }

    /// Shown instead of a question's file path to a peer that may not read what was recorded.
    public static let hiddenPath = "(path hidden: run with sudo to see it)"

    /// Open questions as `peer` may see them. Without privilege: no file path (it may lie in a folder the
    /// peer cannot read) and no command lines (argv often names the file too, and may carry secrets).
    func asks(for peer: IPCPeer) -> [AskRequest] {
        let all = daemon.asks(peer: peer)
        return isPrivileged(peer) ? all : all.map(ServiceHandler.withoutRecordedDetail)
    }

    static func withoutRecordedDetail(_ request: AskRequest) -> AskRequest {
        var r = request
        r.path = hiddenPath
        r.process.argv = nil
        r.chain = r.chain.map { link in
            var l = link
            l.argv = nil
            return l
        }
        return r
    }

    public func handle(_ request: IPCRequest, peer: IPCPeer) -> IPCResponse {
        if let denied = authorize(request, peer: peer) { return .error(denied) }
        do {
            return try dispatch(request, peer: peer)
        } catch let e as IPCError {
            return .error(e)
        } catch {
            return .error(IPCError(.internalError, "\(error)"))
        }
    }

    /// Serves an authorized request (`handle` authorizes first; internal for tests that interleave).
    func dispatch(_ request: IPCRequest, peer: IPCPeer) throws -> IPCResponse {
        let d = daemon
        switch request {
        case .hello(let v):
            if v != whoReadIPCVersion {
                return .error(IPCError(.versionMismatch, "client speaks protocol \(v), daemon \(whoReadIPCVersion)"))
            }
            return .hello(serverVersion: whoReadIPCVersion)
        case .status:
            return .status(d.status())
        case .events(let q):
            d.writer.flush()
            return .events(try d.store.events(q))
        case .live(let after, let limit, let benign):
            return .events(d.live.after(after, limit: min(limit, 5000), includeBenign: benign))
        case .alerts(let q):
            d.writer.flush()
            return .alerts(try d.store.alerts(q))
        case .alertAction(let id, let action):
            try d.apply(action: action, toAlert: id, peer: peer, privileged: isPrivileged(peer))
            return .ok
        case .markAlertsRead(let ids):
            try d.markRead(ids, peer: peer)
            return .ok
        case .summaries(let since):
            d.writer.flush()
            return .summaries(try d.store.summaries(since: since))
        case .dailyAggregates(let since):
            d.writer.flush()
            return .dailyAggregates(try d.store.dailyAggregates(since: since))
        case .rules:
            return .rules(d.rules.rules)
        case .upsertRule(let rule):
            let privileged = isPrivileged(peer)
            try d.upsert(rule: rule, peer: peer, mustBeNew: !privileged, privileged: privileged)
            // The rule list is a recorded read (rules made from alerts name apps and files).
            return privileged ? .rules(d.rules.rules) : .ok
        case .deleteRule(let id):
            try d.deleteRule(id: id, peer: peer)
            return .rules(d.rules.rules)
        case .replaceRules(let list):
            try d.replaceRules(list, peer: peer, privileged: isPrivileged(peer))
            return .rules(d.rules.rules)
        case .asks:
            return .asks(asks(for: peer))
        case .answerAsk(let id, let action):
            try d.answerAsk(id: id, action: action, peer: peer, privileged: isPrivileged(peer))
            return .asks(asks(for: peer))
        case .settings:
            return .settings(d.currentSettings)
        case .updateSettings(var s):
            guard isPrivileged(peer) else {
                // Authorized only as "turn trust in Apple programs off", checked against the settings of
                // that moment. Apply just that, on the live settings: the rest of this copy may already be
                // stale (a root or app change in between), and replacing the whole object would undo it.
                try d.mutateSettings(peer: peer) { $0.trustApplePrograms = false }
                return .settings(d.currentSettings)
            }
            // Enforcement and pause have their own requests (and privilege checks): a stale copy of the
            // settings must never flip them.
            try d.mutateSettings(peer: peer) { current in
                s.enforcementEnabled = current.enforcementEnabled
                s.monitoringPaused = current.monitoringPaused
                current = s
            }
            return .settings(d.currentSettings)
        case .setEnforcement(let on):
            try d.mutateSettings(peer: peer, reenable: on) { $0.enforcementEnabled = on }
            return .status(d.status())
        case .setPaused(let paused):
            try d.mutateSettings(peer: peer) { $0.monitoringPaused = paused }
            return .status(d.status())
        case .catalog:
            return .catalog(d.catalogInfo())
        case .updateCatalog(let c):
            try d.update(catalog: c, peer: peer)
            return .catalog(d.catalogInfo())
        case .resetCatalog:
            try d.update(catalog: nil, peer: peer)
            return .catalog(d.catalogInfo())
        case .agents:
            return .agents(d.data.agents)
        case .baseline:
            // The newest only: one reply stays far below the transports' frame limits (dos-1).
            return .baseline(d.baseline.newestEntries(limit: Baseline.replyLimit))
        case .restartLearning:
            try d.restartLearning(peer: peer)
            return .status(d.status())
        }
    }
}
