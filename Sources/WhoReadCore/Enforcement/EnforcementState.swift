import Foundation

/// Whether enforcement is live right now. Read on every AUTH callback, so `isActive` is a single
/// locked load of in-memory flags — no filesystem access. The kill-switch file is watched by the
/// daemon in the background, which flips `killSwitchFilePresent`.
///
/// Enforcement is active only if all hold:
/// - the user enabled it (setting / `whoread enforcement on` / UI switch),
/// - `/Library/Application Support/WhoRead/disable-enforcement` does not exist,
/// - rules loaded successfully,
/// - the source can enforce.
///
/// Nothing switches it off automatically (ask mode): slow responses and missed deadlines are only
/// counted (LatencyMonitor). The user's switch and the kill-switch file are the manual off switches.
public final class EnforcementState: @unchecked Sendable {
    public enum InactiveReason: String, Codable, Sendable {
        case disabledByUser
        case killSwitchFile
        /// Never reported since ask mode (no automatic switch-off); kept so statuses from older
        /// daemons still decode.
        case latencyTripped
        case rulesFailedToLoad
        case sourceCannotEnforce
    }

    private let lock = NSLock()
    private var userEnabled: Bool
    private var killFile = false
    private var rulesOK = true
    private var sourceCanEnforce: Bool
    private var observers: [(Bool) -> Void] = []

    public init(userEnabled: Bool, sourceCanEnforce: Bool) {
        self.userEnabled = userEnabled
        self.sourceCanEnforce = sourceCanEnforce
    }

    public var isActive: Bool {
        lock.lock(); defer { lock.unlock() }
        return activeLocked
    }

    private var activeLocked: Bool {
        userEnabled && !killFile && rulesOK && sourceCanEnforce
    }

    public var inactiveReasons: [InactiveReason] {
        lock.lock(); defer { lock.unlock() }
        var out: [InactiveReason] = []
        if !userEnabled { out.append(.disabledByUser) }
        if killFile { out.append(.killSwitchFile) }
        if !rulesOK { out.append(.rulesFailedToLoad) }
        if !sourceCanEnforce { out.append(.sourceCannotEnforce) }
        return out
    }

    public var userEnabledSetting: Bool {
        lock.lock(); defer { lock.unlock() }
        return userEnabled
    }

    public var killSwitchFilePresent: Bool {
        lock.lock(); defer { lock.unlock() }
        return killFile
    }

    /// Called with the new `isActive` value whenever it changes, on the mutating thread: observers
    /// must only hand work to a queue (the mutating thread can be latency-critical).
    public func onChange(_ observer: @escaping (Bool) -> Void) {
        lock.lock(); observers.append(observer); lock.unlock()
    }

    private func mutate(_ f: () -> Void) {
        lock.lock()
        let before = activeLocked
        f()
        let after = activeLocked
        let obs = observers
        lock.unlock()
        if before != after { obs.forEach { $0(after) } }
    }

    public func setUserEnabled(_ v: Bool) { mutate { userEnabled = v } }
    public func setKillSwitchFilePresent(_ v: Bool) { mutate { killFile = v } }
    public func setRulesLoaded(_ ok: Bool) { mutate { rulesOK = ok } }
    public func setSourceCanEnforce(_ v: Bool) { mutate { sourceCanEnforce = v } }
}

/// Canonical locations.
public enum WhoReadPaths {
    public static let dataDirectory = "/Library/Application Support/WhoRead"
    public static let killSwitchFile = "/Library/Application Support/WhoRead/disable-enforcement"
    public static let databaseFile = "/Library/Application Support/WhoRead/whoread.sqlite"
    public static let testVaultName = "WhoReadTestVault"
    public static let machServiceName = "com.whoread.daemon.xpc"
}
