import Foundation

/// JSON / JSON Lines / CSV export of events and alerts. Used by `whoread export` and the app.
public enum Exporter {
    public enum Format: String, Codable, CaseIterable, Sendable {
        case json
        case jsonl
        case csv
    }

    /// Dates RFC3339 can write and read back: years 0000 through 9999, UTC. Anything else is refused
    /// on both sides, so a stored date always decodes again (and a huge number cannot make
    /// `RFC3339.format` trap converting it to Int).
    public static let representableDates: Range<TimeInterval> = -62_167_219_200 ..< 253_402_300_800

    public static func encoder(pretty: Bool) -> JSONEncoder {
        let enc = JSONEncoder()
        enc.outputFormatting = pretty ? [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes] : [.sortedKeys, .withoutEscapingSlashes]
        enc.dateEncodingStrategy = .custom { date, encoder in
            guard representableDates.contains(date.timeIntervalSince1970) else {
                throw EncodingError.invalidValue(date, EncodingError.Context(
                    codingPath: encoder.codingPath, debugDescription: "date outside years 0000-9999"))
            }
            var c = encoder.singleValueContainer()
            try c.encode(RFC3339.format(date, fractionDigits: 6))
        }
        return enc
    }

    public static func decoder() -> JSONDecoder {
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .custom { decoder in
            let c = try decoder.singleValueContainer()
            let t: TimeInterval
            if let s = try? c.decode(String.self), let d = RFC3339.parse(s) {
                t = d.timeIntervalSince1970
            } else {
                t = try c.decode(Double.self)
            }
            // An offset can move a 0000/9999 timestamp out of range too (`9999-12-31T23:30:00-01:00`).
            guard representableDates.contains(t) else {
                throw DecodingError.dataCorruptedError(in: c, debugDescription: "date outside years 0000-9999")
            }
            return Date(timeIntervalSince1970: t)
        }
        return dec
    }

    public static func export(events: [AnalyzedEvent], format: Format, catalog: Catalog? = nil) throws -> Data {
        switch format {
        case .json:
            return try encoder(pretty: true).encode(events)
        case .jsonl:
            let enc = encoder(pretty: false)
            var out = Data()
            for e in events {
                out.append(try enc.encode(e))
                out.append(0x0A)
            }
            return out
        case .csv:
            return Data(csv(events: events, catalog: catalog).utf8)
        }
    }

    public static let csvColumns = [
        "id", "time", "operation", "access", "path", "secondary_path", "category", "category_name", "severity",
        "pid", "executable", "signing_id", "team_id", "platform_binary", "responsible", "responsible_kind",
        "responsible_key", "agent", "chain", "owner", "benign_service", "decision", "rule_id", "alert_id",
    ]

    public static func csv(events: [AnalyzedEvent], catalog: Catalog? = nil) -> String {
        var lines = [csvColumns.joined(separator: ",")]
        for e in events {
            let row: [String] = [
                String(e.id), RFC3339.format(e.time, fractionDigits: 6), e.operation.rawValue, e.access.label,
                e.path, e.secondaryPath ?? "", e.categoryID, catalog?.category(e.categoryID)?.name.en ?? "",
                e.severity.rawValue, String(e.process.pid), e.process.executablePath, e.process.signingID ?? "",
                e.process.teamID ?? "", e.process.isPlatformBinary ? "true" : "false", e.responsible.displayName,
                e.responsible.kind.rawValue, e.responsible.key, e.agentID ?? "", e.chainDisplay,
                e.isOwner ? "true" : "false", e.benignServiceID ?? "", e.decision.rawValue, e.ruleID ?? "",
                e.alertID.map(String.init) ?? "",
            ]
            lines.append(row.map(csvField).joined(separator: ","))
        }
        return lines.joined(separator: "\n") + "\n"
    }

    public static func csv(alerts: [Alert]) -> String {
        let header = ["id", "kind", "created", "updated", "responsible", "category", "severity", "count", "access",
                      "first_path", "chain", "agent", "status", "resolution"]
        var lines = [header.joined(separator: ",")]
        for a in alerts {
            let row = [
                String(a.id), a.kind.rawValue, RFC3339.format(a.createdAt, fractionDigits: 3),
                RFC3339.format(a.updatedAt, fractionDigits: 3), a.responsible.displayName, a.categoryID,
                a.severity.rawValue, String(a.count), a.accesses.label, a.firstPath,
                a.chain.map(\.name).joined(separator: " → "), a.agentID ?? "", a.status.rawValue,
                a.resolution?.rawValue ?? "",
            ]
            lines.append(row.map(csvField).joined(separator: ","))
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// CSV as printed to a terminal. CSV has no escape of its own, so names and paths with ESC, C1
    /// controls, bidi overrides and the other hidden characters (`DisplayText.isHidden`) would act
    /// on the terminal: they become visible `\u{…}` escapes, as in the CLI's tables. A line break
    /// inside a quoted cell is escaped too (it cannot fake a row); the one that ends a row is kept.
    /// Only for a terminal: files and pipes get `csv` exactly. Takes whole rows.
    public static func terminalSafeCSV(_ csv: String) -> String {
        guard csv.unicodeScalars.contains(where: { $0 == "\"" || ($0 != "\n" && DisplayText.isHidden($0)) }) else { return csv }
        var out = String.UnicodeScalarView()
        var quoted = false
        for u in csv.unicodeScalars {
            // A doubled quote inside a quoted cell flips twice: still inside.
            if u == "\"" { quoted.toggle() }
            if DisplayText.isHidden(u) && (u != "\n" || quoted) {
                out.append(contentsOf: DisplayText.escaped(String(u)).unicodeScalars)
            } else {
                out.append(u)
            }
        }
        return String(out)
    }

    /// RFC 4180 quoting, plus a leading apostrophe on cells a spreadsheet would treat as a formula.
    public static func csvField(_ raw: String) -> String {
        var s = raw
        if let first = s.unicodeScalars.first, "=+-@\t\r".unicodeScalars.contains(first) {
            s = "'" + s
        }
        if s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r") {
            return "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\""
        }
        return s
    }
}
