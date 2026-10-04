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
    /// flock on the data directory: one daemon per store (the dev LaunchDaemon and the system
    /// extension must not both run, or the kill switches would reach only one of them).
    private var lockFD: Int32 = -1
    #if os(macOS)
    private var xpcServer: XPCServer?
    #endif

    public init(configuration: DaemonConfiguration, makeSource: ((DaemonCore) throws -> EventSource)? = nil) throws {
        // Locked before the core opens the store: building it consumes the auth-armed marker (and may
        // turn enforcement off, rewrite the user catalog or seed rules). A second instance must not do
        // that to the store of the one that is running.
        let fd = try Daemon.acquireLock(configuration)
        let c: DaemonCore
        do {
            c = try DaemonCore(config: configuration, makeSource: makeSource)
        } catch {
            if fd >= 0 { close(fd) }
            throw error
        }
        core = c
        lockFD = fd
        var verifier: PeerVerifier = NoAppPeers()
        #if os(macOS)
        if let req = configuration.appRequirement { verifier = SignedAppPeerVerifier(requirement: req) }
        #endif
        if configuration.appRequirement != nil && configuration.clientRequirement == nil {
            // isApp is only trusted for connections whose code signature was verified against the
            // client requirement; without one the app is never recognised.
            Log.error("--app-requirement has no effect without --client-requirement: the app cannot be recognised")
        }
        handler = ServiceHandler(daemon: core, policy: configuration.permissive ? .permissive : .strict, peerVerifier: verifier)
        killSwitch = KillSwitchWatcher(path: configuration.resolvedKillSwitchPath, state: core.enforcement)
    }

    /// Handler over a bare core (replay CLI, tests): permissive, no servers.
    public static func handlerForReplay(_ core: DaemonCore) -> ServiceHandler {
        ServiceHandler(daemon: core, policy: .permissive, peerVerifier: NoAppPeers())
    }

    /// flock on `daemon.lock` in the data directory; -1 for in-memory stores.
    static func acquireLock(_ config: DaemonConfiguration) throws -> Int32 {
        guard !config.inMemoryStore else { return -1 }
        try FileManager.default.createDirectory(atPath: config.dataDirectory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o755])
        let fd = open(config.lockPath, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw IPCError(.internalError, "cannot open \(config.lockPath)") }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            close(fd)
            throw IPCError(.unavailable, "another WhoRead daemon already uses \(config.dataDirectory) "
                           + "(dev LaunchDaemon and system extension both installed?). Remove one: "
                           + "sudo scripts/uninstall-dev-daemon.sh (dev daemon) or scripts/release/uninstall.sh (extension)")
        }
        return fd
    }

    deinit {
        if lockFD >= 0 { close(lockFD) }
    }

    public func start() throws {
        let config = core.config
        // Started again after stop(): take the lock back.
        if lockFD < 0 { lockFD = try Daemon.acquireLock(config) }
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
        // A used "allow once" must not work again after a restart.
        core.saveConsumableRules()
        if lockFD >= 0 {
            close(lockFD)
            lockFD = -1
        }
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
