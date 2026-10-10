import Foundation
import WhoReadCore

/// The daemon's unclean stops across instances (`DaemonStatus.uncleanStop`): how many since the last
/// clean stop, when the first and the last were found, and how many of them the native source's handler
/// watchdog caused. The watchdog exits of the last hour set its backoff (`NativeHandlerWatchdog.floor`),
/// so a wedge that comes back after every restart is reported as one loop with its count instead of
/// each restart overwriting the previous report. Stored as JSON in the store's meta table; a clean stop
/// clears it.
public struct UncleanStops: Codable, Equatable, Sendable {
    public var count = 0
    public var first: Date?
    public var last: Date?
    /// Unclean stops the watchdog caused (it left its stall marker).
    public var watchdogExits = 0
    /// Seconds the handler was stuck at the last watchdog exit.
    public var lastStallSeconds: Int?
    /// When the most recent watchdog exits were found, oldest first, at most `keepRecent`.
    public var recentWatchdogExits: [Date] = []

    public init() {}

    static let key = "unclean_stops"
    static let keepRecent = 16

    /// One unclean stop, found at start `at`. `stall`: the watchdog's marker (seconds the handler was
    /// stuck), nil when it did not leave one.
    mutating func record(at time: Date, stall: Int?) {
        count += 1
        if first == nil { first = time }
        last = time
        guard let stall else { return }
        watchdogExits += 1
        lastStallSeconds = stall
        recentWatchdogExits.append(time)
        if recentWatchdogExits.count > UncleanStops.keepRecent {
            recentWatchdogExits.removeFirst(recentWatchdogExits.count - UncleanStops.keepRecent)
        }
    }

    /// Watchdog exits found within `window` before `now`.
    func recentWatchdogExitCount(now: Date, window: TimeInterval = NativeHandlerWatchdog.backoffWindow) -> Int {
        recentWatchdogExits.filter { now.timeIntervalSince($0) <= window }.count
    }

    /// The shortest stall the watchdog of an instance started at `now` waits for.
    func watchdogFloor(now: Date) -> TimeInterval {
        NativeHandlerWatchdog.floor(recentExits: recentWatchdogExitCount(now: now))
    }

    /// The report for the stop just recorded at `now`. `armed`: AUTH events were subscribed (the
    /// auth-armed marker); `stall`: as for `record`.
    func note(now: Date, armed: Bool, stall: Int?) -> String {
        let format = ISO8601DateFormatter()
        var text: String
        if let stall {
            // 0: the marker was there but unreadable.
            text = "the previous daemon was exited by its watchdog: its event handler was stuck in one call"
                + (stall > 0 ? " for \(stall) s (" : " (")
                + (armed ? "while enforcing: in fail-closed mode the accesses behind it were denied at their deadline"
                         : "monitoring only: the file events behind it were not recorded")
                + "); found at start \(format.string(from: now))"
        } else {
            text = "the previous daemon stopped while enforcing (killed for a missed AUTH deadline, exited by its watchdog "
                + "with the event handler stuck, a crash or a power loss); found at start \(format.string(from: now))"
        }
        if count > 1, let first, let last {
            text += "; \(count) unclean stops since \(format.string(from: first)), the last at \(format.string(from: last))"
        }
        if watchdogExits > 0 {
            let recent = recentWatchdogExitCount(now: now)
            text += "; the watchdog exited the daemon \(watchdogExits) time\(watchdogExits == 1 ? "" : "s") (\(recent) in the last hour)"
            let floor = watchdogFloor(now: now)
            if floor > NativeHandlerWatchdog.minimumStall {
                text += ", so it now waits \(Int(floor)) s for a stuck handler before exiting again"
            }
        }
        return text
    }
}

/// The watchdog's note to the next daemon: a file holding the seconds the file handler was stuck,
/// written just before the watchdog exits and read (and removed) by DaemonCore at the next start. Its
/// path is set once when the source is made. Writing it touches nothing the stuck call may hold and
/// runs on a thread of its own, given at most `wait`: a stuck file system must not stop the exit.
public enum NativeStallMarker {
    private static let lock = NSLock()
    private static var path: String?

    static let wait: TimeInterval = 1

    /// nil: no marker (in-memory store).
    public static func setPath(_ p: String?) {
        lock.lock()
        path = p
        lock.unlock()
    }

    /// Writes the marker. False when it failed, or did not finish within `timeout`.
    @discardableResult
    static func write(seconds: TimeInterval, waitAtMost timeout: TimeInterval = NativeStallMarker.wait) -> Bool {
        lock.lock()
        let p = path
        lock.unlock()
        guard let p else { return false }
        final class Result: @unchecked Sendable { var ok = false }
        let result = Result()
        let done = DispatchSemaphore(value: 0)
        let text = Data("\(Int(max(0, min(seconds, 1e9))))\n".utf8)
        Thread.detachNewThread {
            result.ok = (try? SafeFile.replace(p, with: text, mode: 0o600)) != nil
            done.signal()
        }
        // `ok` is written before the signal and read only after it.
        return done.wait(timeout: .now() + timeout) == .success && result.ok
    }

    /// Reads and removes the marker at `path`: the seconds it holds, or nil when there is none (or it is
    /// not a regular file: never followed through a link).
    static func take(_ path: String) -> Int? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else {
            // Something else than the watchdog's file (a link): not a marker, but not left there either.
            if errno != ENOENT { unlink(path) }
            return nil
        }
        var st = stat()
        var bytes = [UInt8](repeating: 0, count: 32)
        let n = fstat(fd, &st) == 0 && st.st_mode & S_IFMT == S_IFREG ? read(fd, &bytes, bytes.count) : -1
        close(fd)
        unlink(path)
        guard n >= 0 else { return nil }
        let text = String(decoding: bytes.prefix(n), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        // A marker that cannot be read still says the watchdog exited.
        return Int(text).map { max(0, $0) } ?? 0
    }
}
