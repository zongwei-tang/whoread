import Foundation
import WhoReadCore
import WhoReadIPC

/// Process lifecycle around `DaemonCore`: process-tree seeding, writer, kill-switch watcher,
/// timers, the event source and the IPC servers.
public final class Daemon: @unchecked Sendable {
    public let core: DaemonCore
    public let handler: ServiceHandler
    private let killSwitch: KillSwitchWatcher
    private var timers: [DispatchSourceTimer] = []
    private let timerQueue = DispatchQueue(label: "whoread.maintenance")
    private var unixServer: UnixSocketServer?
    #if os(macOS)
    private var xpcServer: XPCServer?
    #endif

    public init(configuration: DaemonConfiguration, makeSource: ((DaemonCore) throws -> EventSource)? = nil) throws {
        core = try DaemonCore(config: configuration, makeSource: makeSource)
        var verifier: PeerVerifier = NoAppPeers()
        #if os(macOS)
        if let req = configuration.appRequirement { verifier = SignedAppPeerVerifier(requirement: req) }
        #endif
        handler = ServiceHandler(daemon: core, policy: configuration.permissive ? .permissive : .strict, peerVerifier: verifier)
        killSwitch = KillSwitchWatcher(path: configuration.resolvedKillSwitchPath, state: core.enforcement)
    }

    /// Handler over a bare core (replay CLI, tests): permissive, no servers.
    public static func handlerForReplay(_ core: DaemonCore) -> ServiceHandler {
        ServiceHandler(daemon: core, policy: .permissive, peerVerifier: NoAppPeers())
    }

    public func start() throws {
        let config = core.config
        if config.seedProcesses && core.source.kind != .replay {
            let snapshot = ProcessSnapshot.all()
            core.tree.seed(snapshot, at: Date())
            core.tree.parentResolver = { ProcessSnapshot.record(pid: $0) }
            Log.info("process tree seeded with \(snapshot.count) processes")
        }
        core.writer.start()
        killSwitch.start()
        schedule(every: 30) { [core] in core.maintenance() }
        schedule(every: 1) { [core] in core.checkLatency() }

        if let path = config.devSocketPath {
            let server = UnixSocketServer(path: path, handler: handler, mode: mode_t(config.devSocketMode))
            try server.start()
            unixServer = server
            Log.info("dev IPC socket at \(path)")
        }
        #if os(macOS)
        if let name = config.machServiceName {
            let server = XPCServer(machServiceName: name, handler: handler, codeSigningRequirement: config.clientRequirement)
            server.start()
            xpcServer = server
            // Lets the CLI find the service without flags (world-readable, not secret).
            let marker = (config.dataDirectory as NSString).appendingPathComponent("mach-service")
            try? (name + "\n").write(toFile: marker, atomically: true, encoding: .utf8)
            chmod(marker, 0o644)
            Log.info("XPC listener on \(name)")
        }
        #endif

        let classifier = core.analyzer.classifier
        Log.info("WhoRead \(WhoReadVersion.string) starting: source=\(core.source.kind.rawValue), homes=\(core.homes), \(classifier.prefixes.count) monitored prefixes, \(core.rules.rules.filter(\.enabled).count) enabled rules")
        try core.source.start(sink: core.pipeline)
    }

    public func stop() {
        core.source.stop()
        timers.forEach { $0.cancel() }
        timers.removeAll()
        killSwitch.stop()
        unixServer?.stop()
        #if os(macOS)
        xpcServer?.stop()
        #endif
        core.writer.stop()
        core.persistBaseline()
        Log.info("stopped")
    }

    private func schedule(every interval: TimeInterval, _ block: @escaping @Sendable () -> Void) {
        let t = DispatchSource.makeTimerSource(queue: timerQueue)
        t.schedule(deadline: .now() + interval, repeating: interval)
        t.setEventHandler(handler: block)
        t.resume()
        timers.append(t)
    }
}
