import Foundation
import WhoReadCore

enum Format {
    static func time(_ d: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f.string(from: d)
    }

    static func ago(_ d: Date?, now: Date = Date()) -> String {
        guard let d else { return "never" }
        let s = Int(now.timeIntervalSince(d))
        if s < 60 { return "\(s)s ago" }
        if s < 3600 { return "\(s / 60)m ago" }
        if s < 86400 { return "\(s / 3600)h ago" }
        return "\(s / 86400)d ago"
    }

    /// "15m", "2h", "3d", "1w"; "YYYY-MM-DD[ HH:MM[:SS]]" in local time (the zone `time` prints in,
    /// so a timestamp copied from the output round-trips); or RFC 3339 with `Z` / `±hh:mm`.
    static func parseSince(_ s: String, now: Date = Date(), timeZone: TimeZone = .current) throws -> Date {
        let units: [Character: Double] = ["s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400]
        if let last = s.last, let unit = units[last], let n = Double(s.dropLast()) {
            // Bounded so "infd" or "1e300w" is a usage error, not a trap when the date is encoded.
            guard n.isFinite, abs(n * unit) < 1e10 else { throw CLIError("time span out of range: \(s)") }
            return now.addingTimeInterval(-n * unit)
        }
        let zoned = s.count > 19 && s.dropFirst(19).contains { "Zz+-".contains($0) }
        if zoned {
            if let d = RFC3339.parse(s) { return d }
        } else {
            var wall = s
            if wall.count == 10 { wall += "T00:00:00" } else if wall.count == 16 { wall += ":00" }
            // Parse the wall-clock time as if UTC, then shift by the zone's offset at that moment.
            if let utc = RFC3339.parse(wall) {
                let guess = utc.addingTimeInterval(-Double(timeZone.secondsFromGMT(for: utc)))
                return utc.addingTimeInterval(-Double(timeZone.secondsFromGMT(for: guess)))
            }
        }
        throw CLIError("cannot parse time \"\(s)\" (use 15m, 2h, 3d, 1w, 2026-10-04, \"2026-10-04 09:30\" or RFC 3339)")
    }

    static func pad(_ s: String, _ n: Int) -> String {
        let w = displayWidth(s)
        return w >= n ? s : s + String(repeating: " ", count: n - w)
    }

    /// East Asian wide characters take two columns.
    static func displayWidth(_ s: String) -> Int {
        s.unicodeScalars.reduce(0) { w, u in
            let v = u.value
            let wide = (0x1100...0x115F).contains(v) || (0x2E80...0xA4CF).contains(v) || (0xAC00...0xD7A3).contains(v)
                || (0xF900...0xFAFF).contains(v) || (0xFE30...0xFE4F).contains(v) || (0xFF00...0xFF60).contains(v)
                || (0xFFE0...0xFFE6).contains(v)
            return w + (wide ? 2 : 1)
        }
    }

    static func table(_ rows: [[String]], header: [String]) -> String {
        let all = [header] + rows
        var widths = Array(repeating: 0, count: header.count)
        for r in all { for (i, c) in r.enumerated() where i < widths.count { widths[i] = max(widths[i], displayWidth(c)) } }
        return all.enumerated().map { (idx, r) in
            let line = r.enumerated().map { (i, c) in i == r.count - 1 ? c : pad(c, widths[i]) }.joined(separator: "  ")
            return idx == 0 ? line + "\n" + widths.map { String(repeating: "─", count: $0) }.joined(separator: "  ") : line
        }.joined(separator: "\n")
    }

    static func json<T: Encodable>(_ v: T) throws -> String {
        String(decoding: try Exporter.encoder(pretty: true).encode(v), as: UTF8.self)
    }
}
