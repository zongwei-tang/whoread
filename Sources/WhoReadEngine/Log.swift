import Foundation
import WhoReadCore

/// Minimal logger: timestamped lines on stderr. The dev LaunchDaemon plist redirects stderr to
/// /Library/Logs/WhoRead/whoreadd.log; the system extension redirects its own stderr to
/// /Library/Logs/WhoRead/extension.log (both root-only). Never logs file contents; paths and process
/// names only, sanitized to one line each.
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
        let line = "\(RFC3339.format(Date(), fractionDigits: 3)) \(tag) \(sanitize(message))\n"
        lock.lock()
        FileHandle.standardError.write(Data(line.utf8))
        lock.unlock()
    }
}

extension Log {
    /// File names, rule ids and process names are attacker-controlled: escape control characters and
    /// line separators so one message is always one line (no forged log entries), and cap the length.
    static func sanitize(_ message: String, maxLength: Int = 4096) -> String {
        var out = String.UnicodeScalarView()
        var count = 0
        for s in message.unicodeScalars {
            if count >= maxLength { out.append(contentsOf: "…".unicodeScalars); break }
            if s.value < 0x20 || s.value == 0x7F || (0x80...0x9F).contains(s.value) || s.value == 0x2028 || s.value == 0x2029 {
                out.append(contentsOf: "\\u{\(String(s.value, radix: 16))}".unicodeScalars)
            } else {
                out.append(s)
            }
            count += 1
        }
        return String(out)
    }
}

public enum WhoReadVersion {
    public static let string = "0.1.0"
}
