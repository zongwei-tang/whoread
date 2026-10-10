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
        // record an unclean stop, rewrite the user catalog or seed rules). A second instance must not do
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
        if configuration.appRequirement != nil && configuration.clientRequirement == nil {
            // isApp is only trusted for connections whose code signature was verified against the
            // client requirement; without one the app is never recognised.
            Log.error("--app-requirement has no effect without --client-requirement: the app cannot be recognised")
        }
        handler = ServiceHandler(daemon: core, policy: configuration.permissive ? .permissive : .strict)
        killSwitch = KillSwitchWatcher(path: configuration.resolvedKillSwitchPath, state: core.enforcement)
    }

    /// Handler over a bare core (replay CLI, tests): permissive, no servers.
    public static func handlerForReplay(_ core: DaemonCore) -> ServiceHandler {
        ServiceHandler(daemon: core, policy: .permissive)
    }

    /// flock on `daemon.lock` in the data directory; -1 for in-memory stores. The directory is checked
    /// first (DaemonCore.prepareDataDirectory): a lock in a directory someone else controls proves nothing.
    static func acquireLock(_ config: DaemonConfiguration) throws -> Int32 {
        guard !config.inMemoryStore else { return -1 }
        try DaemonCore.prepareDataDirectory(config)
        let fd = open(config.lockPath, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else {
            throw IPCError(.internalError, "cannot open \(config.lockPath): \(String(cString: strerror(errno)))")
        }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == config.dataDirectoryOwner else {
            close(fd)
            throw IPCError(.unavailable, "\(config.lockPath) is not a regular file owned by "
                           + "\(TrustedDirectory.ownerName(config.dataDirectoryOwner)); remove it")
        }
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
            // libproc has no fork-time parent: the agents running processes had before the restart.
            core.restoreAgentAncestry()
            core.tree.parentResolver = { ProcessSnapshot.record(pid: $0) }
            Log.info("process tree seeded with \(snapshot.count) processes")
            schedule(every: 5) { [core] in core.persistAgentAncestry() }
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
            let policy = XPCPeerPolicy(clientRequirement: config.clientRequirement, appRequirement: config.appRequirement)
            policy.errors.forEach { Log.error($0) }
            policy.warnings.forEach { Log.warning($0) }
            let hint = policy.appCandidate
            let server = XPCServer(machServiceName: name, handler: handler, policy: policy, appCandidate: { hint.isApp(pid: $0) })
            server.start()
            xpcServer = server
            // Lets the CLI find the service without flags (world-readable, not secret).
            let marker = (config.dataDirectory as NSString).appendingPathComponent("mach-service")
            do {
                try SafeFile.replace(marker, with: Data((name + "\n").utf8), mode: 0o644,
                                     trustedDirectoryOwner: config.dataDirectoryOwner)
            } catch {
                Log.warning("\(error)")
            }
            Log.info("XPC listener on \(name)")
        }
        #endif

        let classifier = core.analyzer.classifier
        Log.info("WhoRead \(WhoReadVersion.string) starting: source=\(core.source.kind.rawValue), homes=\(core.homes), \(classifier.prefixes.count) monitored prefixes, \(core.rules.rules.filter(\.enabled).count) enabled rules")
        // The pipeline, plus a prompt link rediscovery after operations that may change a followed link.
        try core.source.start(sink: core.eventSink)
    }

    public func stop() {
        core.source.stop()
        core.cancelPendingLinkRediscovery()
        timers.forEach { $0.cancel() }
        timers.removeAll()
        killSwitch.stop()
        unixServer?.stop()
        #if os(macOS)
        xpcServer?.stop()
        #endif
        core.writer.stop()
        core.persistBaseline()
        if core.config.seedProcesses && core.source.kind != .replay { core.persistAgentAncestry() }
        // A used "allow once" must not work again after a restart.
        core.saveConsumableRules()
        // A clean stop: an earlier unclean one (DaemonStatus.uncleanStop) is no longer reported.
        core.noteCleanStop()
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
