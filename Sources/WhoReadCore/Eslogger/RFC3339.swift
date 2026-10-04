import Foundation

/// Fast, allocation-light RFC 3339 parser for eslogger timestamps such as
/// `2022-10-25T00:51:21.118377744Z` (nanosecond fractions; DateFormatter-based parsers vary in
/// how many fraction digits they accept). Also accepts `+hh:mm` / `-hh:mm` offsets.
public enum RFC3339 {
    public static func parse(_ string: String) -> Date? {
        var s = string
        return s.withUTF8 { parse(utf8: $0) }
    }

    public static func parse(utf8 b: UnsafeBufferPointer<UInt8>) -> Date? {
        // YYYY-MM-DDTHH:MM:SS
        guard b.count >= 19 else { return nil }
        func digits(_ start: Int, _ count: Int) -> Int? {
            var v = 0
            for i in start..<(start + count) {
                let c = b[i]
                guard c >= 0x30 && c <= 0x39 else { return nil }
                v = v * 10 + Int(c - 0x30)
            }
            return v
        }
        guard let year = digits(0, 4), b[4] == 0x2D, let month = digits(5, 2), b[7] == 0x2D,
              let day = digits(8, 2), b[10] == 0x54 || b[10] == 0x74 || b[10] == 0x20,
              let hour = digits(11, 2), b[13] == 0x3A, let minute = digits(14, 2), b[16] == 0x3A,
              let second = digits(17, 2)
        else { return nil }
        guard (1...12).contains(month), (1...31).contains(day), hour < 24, minute < 60, second <= 60 else { return nil }

        var i = 19
        var fraction = 0.0
        if i < b.count && b[i] == 0x2E {
            i += 1
            var scale = 0.1
            while i < b.count, b[i] >= 0x30 && b[i] <= 0x39 {
                fraction += Double(b[i] - 0x30) * scale
                scale /= 10
                i += 1
            }
        }
        var offset = 0
        if i < b.count {
            let c = b[i]
            if c == 0x5A || c == 0x7A {
                i += 1
            } else if c == 0x2B || c == 0x2D {
                guard i + 6 <= b.count, let oh = digits(i + 1, 2), b[i + 3] == 0x3A, let om = digits(i + 4, 2) else { return nil }
                offset = (oh * 3600 + om * 60) * (c == 0x2B ? 1 : -1)
                i += 6
            } else {
                return nil
            }
        }
        guard i == b.count else { return nil }

        let days = daysFromCivil(year: year, month: month, day: day)
        let seconds = Double(days * 86400 + hour * 3600 + minute * 60 + second - offset) + fraction
        return Date(timeIntervalSince1970: seconds)
    }

    /// Howard Hinnant's days_from_civil.
    static func daysFromCivil(year: Int, month: Int, day: Int) -> Int {
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let mp = (month + 9) % 12
        let doy = (153 * mp + 2) / 5 + day - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146097 + doe - 719468
    }

    /// Formats a date with nanosecond precision, UTC. Used by fixtures and exports.
    public static func format(_ date: Date, fractionDigits: Int = 9) -> String {
        // Never trap on a value Int cannot hold: clamp to what four year digits can show.
        let raw = date.timeIntervalSince1970
        let range = Exporter.representableDates
        let t = raw.isFinite ? min(max(raw, range.lowerBound), range.upperBound.nextDown) : range.lowerBound
        var whole = Int(t.rounded(.down))
        var frac = t - Double(whole)
        if frac < 0 { frac += 1; whole -= 1 }
        let days = Int((Double(whole) / 86400).rounded(.down))
        let secsOfDay = whole - days * 86400
        let (y, m, d) = civilFromDays(days)
        var out = String(format: "%04d-%02d-%02dT%02d:%02d:%02d", y, m, d, secsOfDay / 3600, (secsOfDay % 3600) / 60, secsOfDay % 60)
        if fractionDigits > 0 {
            var scale = 1.0
            for _ in 0..<fractionDigits { scale *= 10 }
            var f = Int((frac * scale).rounded())
            if Double(f) >= scale { f = Int(scale) - 1 }
            out += "." + String(format: "%0\(fractionDigits)d", f)
        }
        return out + "Z"
    }

    static func civilFromDays(_ z0: Int) -> (Int, Int, Int) {
        let z = z0 + 719468
        let era = (z >= 0 ? z : z - 146096) / 146097
        let doe = z - era * 146097
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
        let y = yoe + era * 400
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let d = doy - (153 * mp + 2) / 5 + 1
        let m = mp < 10 ? mp + 3 : mp - 9
        return (m <= 2 ? y + 1 : y, m, d)
    }
}
