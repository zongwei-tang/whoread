import Foundation
import WhoReadCore

/// Minimal logger: timestamped lines on stderr (the LaunchDaemon plist redirects stderr to
/// /Library/Logs/WhoRead/whoreadd.log). Never logs file contents; paths and process names only.
public enum Log {
    public enum Level: Int, Comparable, Sendable {
        case debug, info, warning, error
        public static func < (a: Level, b: Level) -> Bool { a.rawValue < b.rawValue }
    }

    nonisolated(unsafe) public static var minimum: Level = .info
    private static let lock = NSLock()

    public static func debug(_ m: @autoclosure () -> String) { write(.debug, m()) }
    public static func info(_ m: @autoclosure () -> String) { write(.info, m()) }
    public static func warning(_ m: @autoclosure () -> String) { write(.warning, m()) }
    public static func error(_ m: @autoclosure () -> String) { write(.error, m()) }

    private static func write(_ level: Level, _ message: String) {
        guard level >= minimum else { return }
        let tag = ["DEBUG", "INFO", "WARN", "ERROR"][level.rawValue]
        let line = "\(RFC3339.format(Date(), fractionDigits: 3)) \(tag) \(message)\n"
        lock.lock()
        FileHandle.standardError.write(Data(line.utf8))
        lock.unlock()
    }
}

public enum WhoReadVersion {
    public static let string = "0.1.0"
}
