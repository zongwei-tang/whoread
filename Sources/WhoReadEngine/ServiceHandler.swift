import Foundation
import WhoReadCore
import WhoReadIPC

/// Serves app / CLI requests. Runs on IPC threads; everything it touches is thread-safe.
///
/// Permission policy (see docs/THREAT_MODEL.md):
/// - non-root peers must be the console user (no reading other users' history);
/// - reading and *strengthening* requests (enforcement on, new deny/alert rule, block, ignore,
///   mark read, unpause) are open to the console user;
/// - *weakening* requests (enforcement off, pause, allow / exceptions, rule edits and deletes,
///   settings, catalog, restart learning) need root (`sudo whoread …`) or the signed WhoRead app.
///   An AI agent running as the user can run `whoread`, but cannot disable its own guard.
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
        case .hello, .status, .events, .live, .alerts, .summaries, .rules, .settings, .catalog, .agents, .baseline:
            return .read
        case .markAlertsRead:
            return .strengthen
        case .setEnforcement(let on):
            return on ? .strengthen : .weaken
        case .setPaused(let paused):
            return paused ? .weaken : .strengthen
        case .alertAction(_, let action):
            switch action {
            case .blockFromNowOn, .keepBlocking, .ignore: return .strengthen
            case .allowOnce, .alwaysAllow: return .weaken
            }
        case .upsertRule(let rule):
            let exists = daemon.rules.rules.contains { $0.id == rule.id }
            return !exists && rule.enabled && (rule.action == .deny || rule.action == .alert) && rule.exceptions.isEmpty
                ? .strengthen : .weaken
        case .deleteRule, .updateSettings, .updateCatalog, .resetCatalog, .restartLearning:
            return .weaken
        }
    }

    func authorize(_ request: IPCRequest, peer: IPCPeer) -> IPCError? {
        if policy == .permissive || peer.isRoot { return nil }
        if let console = consoleUID(), let euid = peer.euid, euid != console {
            return IPCError(.notPermitted, "only root or the console user may talk to the WhoRead daemon")
        }
        switch privilege(of: request) {
        case .read, .strengthen:
            return nil
        case .weaken:
            if peer.isTrustedCode, let pid = peer.pid, peerVerifier.isApp(pid: pid) { return nil }
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
            try d.apply(action: action, toAlert: id, peer: peer)
            return .ok
        case .markAlertsRead(let ids):
            try d.markRead(ids)
            return .ok
        case .summaries(let since):
            d.writer.flush()
            return .summaries(try d.store.summaries(since: since))
        case .rules:
            return .rules(d.rules.rules)
        case .upsertRule(let rule):
            try d.upsert(rule: rule, peer: peer)
            return .rules(d.rules.rules)
        case .deleteRule(let id):
            try d.deleteRule(id: id, peer: peer)
            return .rules(d.rules.rules)
        case .settings:
            return .settings(d.currentSettings)
        case .updateSettings(let s):
            try d.update(settings: s, peer: peer)
            return .settings(d.currentSettings)
        case .setEnforcement(let on):
            var s = d.currentSettings
            s.enforcementEnabled = on
            try d.update(settings: s, peer: peer)
            return .status(d.status())
        case .setPaused(let paused):
            var s = d.currentSettings
            s.monitoringPaused = paused
            try d.update(settings: s, peer: peer)
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
