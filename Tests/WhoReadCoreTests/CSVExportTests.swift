import XCTest
@testable import WhoReadCore

/// CSV export: exact in files and pipes, readable and inert on a terminal, and no cell a
/// spreadsheet would run as a formula.
final class CSVExportTests: XCTestCase {
    /// A program and a file named to act on a terminal (clear the screen, a C1 CSI, a right-to-left
    /// override, DEL) or to fake a row of its own (a line break inside a quoted cell).
    func craftedEvent() -> AnalyzedEvent {
        let name = "Terminal\u{1B}[2J\u{9B}8m\u{202E}x\u{7F}"
        return AnalyzedEvent(id: 7, time: at(0), operation: .open, access: .read,
                             path: "/Users/alice/WhoReadTestVault/a\nb\r\u{1B}]0;title\u{07}.txt", secondaryPath: nil,
                             categoryID: "test-vault", severity: .critical, process: proc(60, "/tmp/x/\(name)"), chain: [],
                             responsible: ResponsibleEntity(kind: .binary, key: "bin:/tmp/x/t", displayName: name),
                             agentID: nil, isOwner: false, benignServiceID: nil, decision: .allowed, ruleID: nil)
    }

    func testTerminalCSVEscapesHiddenCharactersAndKeepsTheRows() {
        let csv = Exporter.csv(events: [craftedEvent()])
        XCTAssertTrue(csv.contains("\u{1B}[2J"), "the export itself is exact")
        let shown = Exporter.terminalSafeCSV(csv)
        let raw = shown.unicodeScalars.filter { $0 != "\n" && DisplayText.isHidden($0) }
        XCTAssertTrue(raw.isEmpty, "raw \(raw.map(\.value)) in \(shown)")
        XCTAssertEqual(shown.split(separator: "\n", omittingEmptySubsequences: false).count, 3, "header, one row, final line break")
        for escaped in ["Terminal\\u{1b}[2J\\u{9b}8m\\u{202e}x\\u{7f}", "a\\u{a}b\\u{d}\\u{1b}]0;title\\u{7}.txt"] {
            XCTAssertTrue(shown.contains(escaped), "\(escaped) in \(shown)")
        }
        // Text with nothing hidden is unchanged, quoted cells and doubled quotes included.
        let plain = Exporter.csv(alerts: []) + "1,\"a,b\",\"say \"\"hi\"\"\",'=x\n"
        XCTAssertEqual(Exporter.terminalSafeCSV(plain), plain)
        // A quote inside a quoted cell does not end it: the line break after it is still the cell's.
        XCTAssertEqual(Exporter.terminalSafeCSV("\"a\"\"\nb\",c\n"), "\"a\"\"\\u{a}b\",c\n")
    }

    /// Cells starting with = + - @ (and tab or carriage return) get a leading apostrophe on every CSV
    /// path: events, alerts, and the cells of the daily aggregates (`csvField`, used by the CLI).
    func testFormulaCellsGetALeadingQuoteOnEveryCSVPath() {
        var e = craftedEvent()
        e.path = "=HYPERLINK(\"http://example.invalid\",\"x\")"
        e.responsible = ResponsibleEntity(kind: .binary, key: "bin:/tmp/x/t", displayName: "+cmd")
        e.agentID = "@SUM(1)"
        e.ruleID = "-2+3"
        let row = Exporter.csv(events: [e]).split(separator: "\n")[1]
        for cell in ["\"'=HYPERLINK(\"\"http://example.invalid\"\",\"\"x\"\")\"", ",'+cmd,", ",'@SUM(1),", ",'-2+3,"] {
            XCTAssertTrue(row.contains(cell), "\(cell) in \(row)")
        }
        let alert = Alert(id: 1, kind: .firstAccess, createdAt: at(0), updatedAt: at(0), windowEndsAt: at(600),
                          responsible: e.responsible, categoryID: "test-vault", severity: .critical, count: 1, accesses: .read,
                          firstPath: "@x", firstEventID: 1, lastEventID: 1, paths: ["@x"], chain: [], agentID: nil, ruleID: nil)
        let alertRow = Exporter.csv(alerts: [alert]).split(separator: "\n")[1]
        XCTAssertTrue(alertRow.contains(",'+cmd,"), String(alertRow))
        XCTAssertTrue(alertRow.contains(",'@x,"), String(alertRow))
        for (cell, field) in [("=1+1", "'=1+1"), ("+1", "'+1"), ("-1", "'-1"), ("@A1", "'@A1"), ("\t=1", "'\t=1"),
                              ("\r=1", "\"'\r=1\""), ("a=1", "a=1"), ("", "")] {
            XCTAssertEqual(Exporter.csvField(cell), field)
        }
    }
}
