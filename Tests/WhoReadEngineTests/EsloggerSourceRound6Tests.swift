import XCTest
import WhoReadCore
@testable import WhoReadEngine

/// Review round 6 (eslogger source): a close of a file changed through a writable mapping gets past the
/// prefilter and reaches the pipeline as a possible write (E2-mapped-writable).
final class EsloggerSourceRound6Tests: XCTestCase {
    private func line(_ seq: Int, _ event: String) -> String {
        #"{"schema_version":1,"version":10,"global_seq_num":\#(seq),"time":"2025-10-09T08:53:21.000000000Z","process":{"audit_token":{"pid":700,"pidversion":5},"ppid":1,"start_time":"2025-10-09T08:53:20.000000Z","executable":{"path":"\/usr\/bin\/python3"}},"event":{\#(event)}}"#
    }

    func testCloseOfAFileWrittenThroughAMappingReachesTheSink() throws {
        let dir = TempDir()
        let lines = dir.path("lines.jsonl")
        let file = #"\/Users\/alice\/WhoReadTestVault\/notes\/mmap.txt"#
        try ([line(1, #""open":{"fflag":3,"file":{"path":"\#(file)"}}"#),
              line(2, #""close":{"modified":false,"target":{"path":"\#(file)"},"was_mapped_writable":true}"#),
              exitLine(3)].joined(separator: "\n") + "\n").write(toFile: lines, atomically: false, encoding: .utf8)
        let fake = script(dir, "eslogger", "cat \(lines)\nexec sleep 600")
        let source = EsloggerSource(executable: fake, prefixes: ["/Users/alice/WhoReadTestVault"])
        let sink = RecordingSink()
        try source.start(sink: sink)
        defer { source.stop() }
        XCTAssertNotNil(waitFor(5) { sink.events.contains { if case .exit = $0 { return true } else { return false } } })
        let closes = sink.events.compactMap { e -> FileActivity? in
            if case .file(let f) = e, f.operation == .close { return f } else { return nil }
        }
        XCTAssertEqual(closes.map(\.note), [EventNote.mappedWritable], "the close was dropped or not marked")
        XCTAssertEqual(closes.first?.targets.map(\.access), [.write])
        XCTAssertEqual(source.parserStats?.droppedByKernel, 0)
    }
}
