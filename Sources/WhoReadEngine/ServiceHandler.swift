import Foundation
import WhoReadCore
import WhoReadIPC

/// Serves app / CLI requests. Runs on IPC threads; everything it touches is thread-safe.
///
/// Permission policy (see docs/THREAT_MODEL.md):
/// - non-root peers must be the console user, and both must be known (fail closed);
/// - reading and *strengthening* requests (enforcement on, new deny/alert rule, "block from now on",
///   denying a question, unpause) are open to the console user;
/// - *weakening* requests (enforcement off, pause, allow / exceptions — also as answers to questions —,
///   ignore / keep blocking / mark read on alerts — they silence alerts —, rule edits, deletes and
///   replacement, settings, catalog, restart learning) need root (`sudo whoread …`) or the signed
///   WhoRead app. An AI agent running as the user can run `whoread`, but can neither disable its own
///   guard nor dismiss the alert about itself; it can list questions and deny them, never allow.
public final class ServiceHandler: IPCHandler, @unchecked Sendable {
    public enum Policy: Sendable {
        case strict
        /// Development: any peer may do anything (dev socket in tests).
        case permissive
    }

    let daemon: DaemonCore
    public var policy: Policy
    public var peerVerifier: PeerVerifier
    public var consoleUID: @Sendable () -> uid_t? = { ConsoleUser.uid() }

    init(daemon: DaemonCore, policy: Policy, peerVerifier: PeerVerifier) {
        self.daemon = daemon
        self.policy = policy
        self.peerVerifier = peerVerifier
    }

    enum Privilege { case read, strengthen, weaken }

    func privilege(of request: IPCRequest) -> Privilege {
        switch request {
        case .hello, .status, .events, .live, .alerts, .summaries, .dailyAggregates, .rules, .settings, .catalog, .agents, .baseline,
             .asks:
            return .read
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

    /// Root, the signed app, or permissive (dev) mode: may weaken protection.
    func isPrivileged(_ peer: IPCPeer) -> Bool {
        if policy == .permissive || peer.isRoot { return true }
        if peer.isTrustedCode, let pid = peer.pid, peerVerifier.isApp(pid: pid) { return true }
        return false
    }

    func authorize(_ request: IPCRequest, peer: IPCPeer) -> IPCError? {
        if policy == .permissive || peer.isRoot { return nil }
        // Unknown peer or unknown console user: refuse rather than serve someone else's history.
        guard let euid = peer.euid, let console = consoleUID(), euid == console else {
            return IPCError(.notPermitted, "only root or the console user may talk to the WhoRead daemon")
        }
        switch privilege(of: request) {
        case .read, .strengthen:
            return nil
        case .weaken:
            if isPrivileged(peer) { return nil }
            return IPCError(.notPermitted, "this change weakens protection: run it with sudo, or use the WhoRead app")
        }
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

    private func dispatch(_ request: IPCRequest, peer: IPCPeer) throws -> IPCResponse {
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
            return .rules(d.rules.rules)
        case .deleteRule(let id):
            try d.deleteRule(id: id, peer: peer)
            return .rules(d.rules.rules)
        case .replaceRules(let list):
            try d.replaceRules(list, peer: peer, privileged: isPrivileged(peer))
            return .rules(d.rules.rules)
        case .asks:
            return .asks(d.asks(peer: peer))
        case .answerAsk(let id, let action):
            try d.answerAsk(id: id, action: action, peer: peer, privileged: isPrivileged(peer))
            return .asks(d.asks(peer: peer))
        case .settings:
            return .settings(d.currentSettings)
        case .updateSettings(var s):
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
            return .baseline(d.baseline.allEntries.sorted { $0.lastSeen > $1.lastSeen })
        case .restartLearning:
            try d.restartLearning(peer: peer)
            return .status(d.status())
        }
    }
}
