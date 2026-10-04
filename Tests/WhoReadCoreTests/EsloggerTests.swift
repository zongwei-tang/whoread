import XCTest
@testable import WhoReadCore

final class RFC3339Tests: XCTestCase {
    func testEsloggerFormats() {
        let t = RFC3339.parse("2026-09-14T07:01:00.256453461Z")!
        XCTAssertEqual(t.timeIntervalSince1970, 1_789_369_260.256453461, accuracy: 1e-6)
        let s = RFC3339.parse("2026-09-14T07:01:00.255117Z")!
        XCTAssertEqual(s.timeIntervalSince1970, 1_789_369_260.255117, accuracy: 1e-6)
        XCTAssertEqual(RFC3339.parse("2026-09-14T07:01:00Z")!.timeIntervalSince1970, 1_789_369_260)
        XCTAssertEqual(RFC3339.parse("2026-09-14T09:01:00+02:00")!.timeIntervalSince1970, 1_789_369_260)
        XCTAssertEqual(RFC3339.parse("1970-01-01T00:00:00Z")!.timeIntervalSince1970, 0)
        XCTAssertEqual(RFC3339.parse("2000-02-29T12:00:00Z")!.timeIntervalSince1970, 951_825_600)
    }

    func testRejectsGarbage() {
        for bad in ["", "2026-13-01T00:00:00Z", "2026-09-14 07:01", "2026-09-14T07:01:00.1Zjunk", "yesterday"] {
            XCTAssertNil(RFC3339.parse(bad), bad)
        }
    }

    func testFormatRoundTrip() {
        let d = Date(timeIntervalSince1970: 1_789_369_260.256453)
        let s = RFC3339.format(d, fractionDigits: 6)
        XCTAssertEqual(s, "2026-09-14T07:01:00.256453Z")
        XCTAssertEqual(RFC3339.parse(s)!.timeIntervalSince1970, d.timeIntervalSince1970, accuracy: 1e-6)
    }
}

final class EsloggerParserTests: XCTestCase {
    static let shapes = ["schema-v1-msgv7", "schema-v1-msgv10", "schema-v2-synthetic"]

    func lines(_ shape: String) throws -> [String] {
        let text = try String(contentsOf: fixtureURL("eslogger/\(shape)/scenario.jsonl"), encoding: .utf8)
        return text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
    }

    func events(_ shape: String) throws -> (EsloggerParser, [SourceEvent]) {
        let p = EsloggerParser()
        var out: [SourceEvent] = []
        for l in try lines(shape) {
            if case .event(let e) = p.parse(line: l) { out.append(e) }
        }
        return (p, out)
    }

    func testEveryShapeParsesTheSameEvents() throws {
        var signatures: [[String]] = []
        for shape in Self.shapes {
            let (_, evs) = try events(shape)
            signatures.append(evs.map(signature))
        }
        XCTAssertEqual(signatures[0], signatures[1], "message version 7 vs 10 (\\/ escaping, key order)")
        XCTAssertEqual(signatures[0], signatures[2], "future schema with missing optional fields")
        XCTAssertGreaterThan(signatures[0].count, 30)
    }

    func signature(_ e: SourceEvent) -> String {
        switch e {
        case .fork(let p, let c, _): return "fork \(p.pid)->\(c.pid)"
        case .exec(let o, let n, _): return "exec \(o.pid) \(n.executablePath) \(n.argv ?? [])"
        case .exit(let p, _): return "exit \(p.pid)"
        case .file(let f): return "\(f.operation) \(f.process.pid) " + f.targets.map { "\($0.role):\($0.path):\($0.access.label)" }.joined(separator: " ")
        }
    }

    func testStatsAndTolerance() throws {
        let (v1, _) = try events("schema-v1-msgv10")
        XCTAssertEqual(v1.stats.malformed, 0)
        XCTAssertEqual(v1.stats.unknownSchemaLines, 0)
        XCTAssertEqual(v1.stats.schemaVersions["1"], v1.stats.lines - 1, "one trailing empty line")
        XCTAssertEqual(v1.stats.droppedByKernel, 0)

        let (v2, _) = try events("schema-v2-synthetic")
        XCTAssertGreaterThan(v2.stats.unknownSchemaLines, 0)
        XCTAssertEqual(v2.stats.malformed, 2, "a non-JSON line and an open without file")
        XCTAssertGreaterThan(v2.stats.events, 30)
    }

    func testFieldsFromRealisticLine() throws {
        let (_, evs) = try events("schema-v1-msgv10")
        guard case .exec(_, let target, _)? = evs.first(where: { if case .exec(_, let t, _) = $0 { return t.pid == 501 } else { return false } }) else {
            return XCTFail("no exec for pid 501")
        }
        XCTAssertEqual(target.executablePath, "/bin/cat")
        XCTAssertEqual(target.argv, ["cat", "/Users/alice/WhoReadTestVault/ssh/id_ed25519"])
        XCTAssertEqual(target.signingID, "com.apple.cat")
        XCTAssertNil(target.teamID)
        XCTAssertTrue(target.isPlatformBinary)
        XCTAssertEqual(target.cdhash?.count, 40)
        XCTAssertEqual(target.cdhash, target.cdhash?.lowercased())
        XCTAssertNotNil(target.startTime)
        XCTAssertEqual(target.ppid, 500)

        // Opens carry FREAD/FWRITE semantics.
        let opens = evs.compactMap { e -> FileActivity? in if case .file(let f) = e, f.operation == .open { return f } else { return nil } }
        XCTAssertTrue(opens.contains { $0.targets[0].path.hasSuffix("/ssh/id_ed25519") && $0.targets[0].access == .read })
        // Unmodified close dropped; modified close kept as a write.
        let closes = evs.compactMap { e -> FileActivity? in if case .file(let f) = e, f.operation == .close { return f } else { return nil } }
        XCTAssertEqual(closes.count, 1)
        XCTAssertEqual(closes[0].targets[0].access, .write)
        // Rename new_path destination is dir + filename.
        let renames = evs.compactMap { e -> FileActivity? in if case .file(let f) = e, f.operation == .rename { return f } else { return nil } }
        XCTAssertEqual(renames.first?.targets.map(\.path), ["/Users/alice/WhoReadTestVault/ssh/id_rsa", "/private/tmp/x"])
        XCTAssertEqual(renames.last?.targets.last?.path, "/Users/alice/WhoReadTestVault/ssh/config")
        // Copyfile with null target_file uses target_dir + target_name.
        let copies = evs.compactMap { e -> FileActivity? in if case .file(let f) = e, f.operation == .copyfile { return f } else { return nil } }
        XCTAssertEqual(copies.first?.targets.last?.path, "/private/tmp/c2")
        // Link uses target_filename.
        let links = evs.compactMap { e -> FileActivity? in if case .file(let f) = e, f.operation == .link { return f } else { return nil } }
        XCTAssertEqual(links.first?.targets.last?.path, "/private/tmp/l")
    }

    func testEnvIsNeverParsed() throws {
        let (_, evs) = try events("schema-v1-msgv7")
        for case .exec(_, let t, _) in evs {
            XCTAssertFalse((t.argv ?? []).contains { $0.contains("SECRET_TOKEN") })
        }
    }

    func testMalformedAndUnknown() {
        let p = EsloggerParser()
        if case .malformed = p.parse(line: "{") {} else { XCTFail() }
        if case .malformed = p.parse(line: "[1,2]") {} else { XCTFail() }
        if case .malformed = p.parse(line: #"{"schema_version":1,"event":{"open":{"fflag":1,"file":{"path":"/x"}}}}"#) {} else {
            XCTFail("no process")
        }
        let unknown = #"{"schema_version":1,"process":{"audit_token":{"pid":5},"executable":{"path":"/bin/x"}},"event":{"mmap":{"source":{"path":"/x"}}}}"#
        if case .ignored = p.parse(line: unknown) {} else { XCTFail() }
        XCTAssertEqual(p.stats.unknownEventKinds["mmap"], 1)
    }

    func testDroppedEventsFromSequenceGaps() {
        let p = EsloggerParser()
        func line(_ seq: Int) -> String {
            #"{"schema_version":1,"global_seq_num":\#(seq),"process":{"audit_token":{"pid":5},"executable":{"path":"/bin/x"}},"event":{"exit":{"stat":0}}}"#
        }
        _ = p.parse(line: line(10))
        _ = p.parse(line: line(11))
        _ = p.parse(line: line(15))
        XCTAssertEqual(p.stats.droppedByKernel, 3)
    }

    func testNumbersAsStringsAndBoolsAsInts() {
        let p = EsloggerParser()
        let l = #"{"schema_version":"1","process":{"audit_token":{"pid":"42"},"ppid":1,"is_platform_binary":1,"executable":{"path":"\/bin\/cat","path_truncated":0}},"event":{"open":{"fflag":"3","file":{"path":"\/Users\/a\/x"}}}}"#
        guard case .event(.file(let f)) = p.parse(line: l) else { return XCTFail() }
        XCTAssertEqual(f.process.pid, 42)
        XCTAssertTrue(f.process.isPlatformBinary)
        XCTAssertEqual(f.targets[0].access, .readWrite)
        XCTAssertEqual(f.targets[0].path, "/Users/a/x")
    }
}

final class LinePrefilterTests: XCTestCase {
    let filter = LinePrefilter(prefixes: ["/Users/alice/.ssh", "/Users/alice/WhoReadTestVault", "/Users/alice/Work/项目"])

    func testLifecycleAlwaysParsed() {
        XCTAssertEqual(filter.verdict(#"{"event":{"exec":{"target":{}}}}"#), .parse)
        XCTAssertEqual(filter.verdict(#"{"event":{"fork":{}}}"#), .parse)
        XCTAssertEqual(filter.verdict(#"{"event": {"exit": {"stat":0}}}"#), .parse)
    }

    func testPrefixMatchingIsCaseInsensitiveAndEscapeAware() {
        XCTAssertEqual(filter.verdict(#"{"event":{"open":{"file":{"path":"/Users/alice/.ssh/id_rsa"}}}}"#), .parse)
        XCTAssertEqual(filter.verdict(#"{"event":{"open":{"file":{"path":"\/Users\/alice\/.ssh\/id_rsa"}}}}"#), .parse)
        XCTAssertEqual(filter.verdict(#"{"event":{"open":{"file":{"path":"/USERS/ALICE/.SSH/id_rsa"}}}}"#), .parse)
        XCTAssertEqual(filter.verdict(#"{"event":{"open":{"file":{"path":"/System/Volumes/Data/Users/alice/.ssh/x"}}}}"#), .parse)
        XCTAssertEqual(filter.verdict(#"{"event":{"open":{"file":{"path":"/usr/lib/libz.dylib"}}}}"#), .drop)
    }

    func testMultiPathAndEscapes() {
        XCTAssertEqual(filter.verdict(#"{"event":{"rename":{"source":{"path":"/Users/alice/.config"}}}}"#), .parse)
        // eslogger may escape non-ASCII as a backslash-u sequence: such lines are always parsed.
        let backslash = "\u{5C}"
        let escaped = #"{"event":{"open":{"file":{"path":"/Users/alice/Caf"# + backslash + #"u00e9"}}}}"#
        XCTAssertEqual(filter.verdict(escaped), .parse)
        // Raw UTF-8 outside monitored prefixes is dropped.
        XCTAssertEqual(filter.verdict(#"{"event":{"open":{"file":{"path":"/Users/alice/Caf"# + "\u{E9}" + #""}}}}"#), .drop)
    }

    func testUnmodifiedCloseDropped() {
        XCTAssertEqual(filter.verdict(#"{"event":{"close":{"modified":false,"target":{"path":"/Users/alice/.ssh/id_rsa"}}}}"#), .drop)
        XCTAssertEqual(filter.verdict(#"{"event":{"close":{"modified":true,"target":{"path":"/Users/alice/.ssh/id_rsa"}}}}"#), .parse)
    }

    func testNonASCIIPrefixUsesASCIIFragment() {
        XCTAssertEqual(LinePrefilter.needle(for: "/Users/alice/Work/项目"), "/Users/alice/Work/")
        XCTAssertNil(LinePrefilter.needle(for: "/项目"))
        let all = LinePrefilter(prefixes: ["/项目"])
        XCTAssertEqual(all.verdict(#"{"event":{"open":{"file":{"path":"/tmp/x"}}}}"#), .parse, "no usable fragment: parse every file event")
    }

    func testFixtureLinesThatMatterAllPass() throws {
        let h = try Harness()
        let filter = LinePrefilter(prefixes: h.classifier.prefixes.map(\.path))
        let parser = EsloggerParser()
        for shape in ["schema-v1-msgv7", "schema-v1-msgv10"] {
            let text = try String(contentsOf: fixtureURL("eslogger/\(shape)/scenario.jsonl"), encoding: .utf8)
            for line in text.split(separator: "\n").map(String.init) {
                guard case .event(let e) = parser.parse(line: line) else { continue }
                if case .file(let f) = e, h.analyzer.classify(f).contains(where: \.isSensitive) {
                    XCTAssertEqual(filter.verdict(line), .parse, line.prefix(120) + "…")
                }
                if case .file = e {} else { XCTAssertEqual(filter.verdict(line), .parse) }
            }
        }
    }
}

final class FixtureReplayTests: XCTestCase {
    /// The M2 scenario, replayed through the full analyzer from each fixture shape.
    func replay(_ shape: String) throws -> (Harness, [AnalyzedEvent], [AlertUpdate]) {
        let h = try Harness()
        let parser = EsloggerParser()
        var events: [AnalyzedEvent] = []
        var alerts: [AlertUpdate] = []
        let text = try String(contentsOf: fixtureURL("eslogger/\(shape)/scenario.jsonl"), encoding: .utf8)
        for line in text.split(separator: "\n") {
            if case .event(let e) = parser.parse(line: String(line)) {
                let out = h.analyzer.handle(e)
                events += out.events
                alerts += out.alerts
            }
        }
        return (h, events, alerts)
    }

    func testScenario() throws {
        for shape in EsloggerParserTests.shapes {
            let (_, events, alerts) = try replay(shape)
            func find(_ pid: Int32, _ suffix: String) -> AnalyzedEvent? {
                events.first { $0.process.pid == pid && $0.path.hasSuffix(suffix) }
            }
            // cat, python3, node each produce a record with the right chain.
            let cat = try XCTUnwrap(find(501, "/ssh/id_ed25519"), shape)
            XCTAssertEqual(cat.chainDisplay, "launchd → Terminal → zsh → cat", shape)
            XCTAssertEqual(cat.categoryID, "test-vault")
            XCTAssertEqual(cat.severity, .critical)
            let py = try XCTUnwrap(find(502, "/aws/credentials"), shape)
            XCTAssertEqual(py.chain.map(\.name), ["launchd", "Terminal", "zsh", "Python"], shape)
            let node = try XCTUnwrap(find(503, "/ssh/id_ed25519"), shape)
            XCTAssertEqual(node.responsible.displayName, "Terminal")
            // Agent chain.
            let agentCat = try XCTUnwrap(find(602, "/aws/credentials"), shape)
            XCTAssertEqual(agentCat.agentID, "claude-code", shape)
            XCTAssertEqual(agentCat.chain.displayString(responsible: agentCat.responsible), "Claude Code → zsh → cat", shape)
            // Reparented background cat keeps its real ancestry.
            let orphan = try XCTUnwrap(find(603, "/ssh/id_ed25519"), shape)
            XCTAssertEqual(orphan.agentID, "claude-code", "\(shape): original_ppid or tree link")
            // Spotlight folded.
            XCTAssertEqual(find(700, "/notes/todo.txt")?.benignServiceID, "spotlight", shape)
            // Firmlinked spelling classified.
            XCTAssertTrue(events.contains { $0.path == "/Users/alice/WhoReadTestVault/ssh/id_ed25519" && $0.process.pid == 500 }, shape)
            // Exfil ops recorded.
            for op in [FileOperation.rename, .clone, .copyfile, .link, .truncate, .unlink, .close] {
                XCTAssertTrue(events.contains { $0.operation == op }, "\(shape): \(op)")
            }
            // Non-sensitive and unmodified-close events are gone.
            XCTAssertFalse(events.contains { $0.path.hasPrefix("/usr/lib") })
            // Critical non-owner reads alert during learning.
            XCTAssertTrue(alerts.contains { $0.alert.kind == .criticalNonOwner && $0.alert.responsible.key == "agent:claude-code" }, shape)
        }
    }

    func testAllShapesProduceIdenticalRecords() throws {
        func digest(_ e: AnalyzedEvent) -> String {
            "\(e.operation) \(e.path) \(e.secondaryPath ?? "-") \(e.categoryID) \(e.severity) \(e.access.label) \(e.responsible.key) \(e.agentID ?? "-") \(e.chain.map(\.name)) \(e.benignServiceID ?? "-")"
        }
        let a = try replay("schema-v1-msgv7").1.map(digest)
        let b = try replay("schema-v1-msgv10").1.map(digest)
        XCTAssertEqual(a, b)
    }
}
