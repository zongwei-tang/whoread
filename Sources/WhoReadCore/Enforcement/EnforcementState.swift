import Foundation

/// Whether enforcement is live right now. Read on every AUTH callback, so `isActive` is a single
/// locked load of in-memory flags — no filesystem access. The kill-switch file is watched by the
/// daemon in the background, which flips `killSwitchFilePresent`.
///
/// Enforcement is active only if all hold:
/// - the user enabled it (setting / `whoread enforcement on` / UI switch),
/// - `/Library/Application Support/WhoRead/disable-enforcement` does not exist,
/// - the latency monitor has not tripped,
/// - rules loaded successfully.
public final class EnforcementState: @unchecked Sendable {
    public enum InactiveReason: String, Codable, Sendable {
        case disabledByUser
        case killSwitchFile
        case latencyTripped
        case rulesFailedToLoad
        case sourceCannotEnforce
    }

    private let lock = NSLock()
    private var userEnabled: Bool
    private var killFile = false
    private var latencyTrip: String?
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
        userEnabled && !killFile && latencyTrip == nil && rulesOK && sourceCanEnforce
    }

    public var inactiveReasons: [InactiveReason] {
        lock.lock(); defer { lock.unlock() }
        var out: [InactiveReason] = []
        if !userEnabled { out.append(.disabledByUser) }
        if killFile { out.append(.killSwitchFile) }
        if latencyTrip != nil { out.append(.latencyTripped) }
        if !rulesOK { out.append(.rulesFailedToLoad) }
        if !sourceCanEnforce { out.append(.sourceCannotEnforce) }
        return out
    }

    public var userEnabledSetting: Bool {
        lock.lock(); defer { lock.unlock() }
        return userEnabled
    }

    public var latencyTripReason: String? {
        lock.lock(); defer { lock.unlock() }
        return latencyTrip
    }

    public var killSwitchFilePresent: Bool {
        lock.lock(); defer { lock.unlock() }
        return killFile
    }

    /// Called with the new `isActive` value whenever it changes (from the mutating thread).
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

    public func setUserEnabled(_ v: Bool) {
        mutate {
            userEnabled = v
            // Re-enabling is an explicit decision to try again after a latency trip.
            if v { latencyTrip = nil }
        }
    }

    public func setKillSwitchFilePresent(_ v: Bool) { mutate { killFile = v } }
    public func tripLatency(_ reason: String) { mutate { if latencyTrip == nil { latencyTrip = reason } } }
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
