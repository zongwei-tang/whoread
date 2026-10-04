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

    /// "15m", "2h", "3d", "1w", RFC 3339, or "YYYY-MM-DD".
    static func parseSince(_ s: String, now: Date = Date()) throws -> Date {
        if let last = s.last, let n = Double(s.dropLast()) {
            switch last {
            case "s": return now.addingTimeInterval(-n)
            case "m": return now.addingTimeInterval(-n * 60)
            case "h": return now.addingTimeInterval(-n * 3600)
            case "d": return now.addingTimeInterval(-n * 86400)
            case "w": return now.addingTimeInterval(-n * 7 * 86400)
            default: break
            }
        }
        if let d = RFC3339.parse(s) { return d }
        if s.count == 10, let d = RFC3339.parse(s + "T00:00:00Z") { return d }
        throw CLIError("cannot parse time \"\(s)\" (use 15m, 2h, 3d, 1w, 2026-10-04 or RFC 3339)")
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
