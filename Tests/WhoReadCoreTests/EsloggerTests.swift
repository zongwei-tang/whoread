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

    func testSequenceExtractionWithoutParsing() {
        let line = #"{"schema_version":1,"global_seq_num":  123456,"event":{"open":{}}}"#
        let seq = Data(line.utf8).withUnsafeBytes { LinePrefilter.globalSequence($0) }
        XCTAssertEqual(seq, 123456)
        XCTAssertNil(Data("{}".utf8).withUnsafeBytes { LinePrefilter.globalSequence($0) })
        let p = EsloggerParser()
        p.noteSequence(5)
        p.noteSequence(6)
        p.noteSequence(9)
        XCTAssertEqual(p.stats.droppedByKernel, 2)
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
            // Schema v2 has no original_ppid: a process reporting ppid 1 may have been reparented, so
            // its ancestry is unknown there (no launchd at the top, Spotlight not folded).
            let knowsOrigin = shape != "schema-v2-synthetic"
            let top = knowsOrigin ? ["launchd"] : []
            // cat, python3, node each produce a record with the right chain.
            let cat = try XCTUnwrap(find(501, "/ssh/id_ed25519"), shape)
            XCTAssertEqual(cat.chain.map(\.name), top + ["Terminal", "zsh", "cat"], shape)
            XCTAssertEqual(cat.categoryID, "test-vault")
            XCTAssertEqual(cat.severity, .critical)
            let py = try XCTUnwrap(find(502, "/aws/credentials"), shape)
            XCTAssertEqual(py.chain.map(\.name), top + ["Terminal", "zsh", "Python"], shape)
            XCTAssertEqual(py.responsible.displayName, "Terminal", "\(shape): framework helper app is not an app")
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
            XCTAssertEqual(find(700, "/notes/todo.txt")?.benignServiceID, knowsOrigin ? "spotlight" : nil, shape)
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

/// Review round 1 (ingest): copyfile/create prefiltering, anchored needles, sequence accounting,
/// directory semantics.
final class EsloggerIngestFixTests: XCTestCase {
    func esLine(_ event: String, seq: Int? = nil, exe: String = "/bin/cat") -> String {
        let s = seq.map { #""global_seq_num":\#($0),"# } ?? ""
        return #"{"schema_version":1,\#(s)"time":"2025-10-09T08:53:20.000000000Z","process":{"audit_token":{"pid":501,"pidversion":5},"ppid":1,"executable":{"path":"\#(exe)"}},"event":{\#(event)}}"#
    }

    func fileEvent(_ line: String, _ p: EsloggerParser = EsloggerParser()) -> FileActivity? {
        if case .event(.file(let f)) = p.parse(line: line) { return f }
        return nil
    }

    func testCopyfileAndCreateToNewSensitivePathAreParsed() {
        let filter = LinePrefilter(prefixes: ["/Users/alice/.npmrc", "/Users/alice/.docker/config.json"])
        // eslogger emits target_file null and splits the destination into dir + name.
        let npmrc = esLine(#""copyfile":{"flags":0,"target_dir":{"path":"\/Users\/alice"},"source":{"path":"\/private\/tmp\/x"},"target_file":null,"target_name":".npmrc","mode":420}"#)
        XCTAssertEqual(filter.verdict(npmrc), .parse)
        let docker = esLine(#""copyfile":{"target_dir":{"path":"/Users/alice/.docker"},"source":{"path":"/private/tmp/x"},"target_file":null,"target_name":"config.json"}"#)
        XCTAssertEqual(filter.verdict(docker), .parse)
        let create = esLine(#""create":{"destination_type":1,"destination":{"new_path":{"dir":{"path":"\/Users\/alice"},"filename":".npmrc","mode":384}},"acl":null}"#)
        XCTAssertEqual(filter.verdict(create), .parse)
        // The parser joins dir + name and records a write of the new file.
        let f = fileEvent(npmrc)
        XCTAssertEqual(f?.operation, .copyfile)
        XCTAssertEqual(f?.targets.last?.path, "/Users/alice/.npmrc")
        XCTAssertEqual(f?.targets.last?.access, .write)
        XCTAssertEqual(fileEvent(create)?.targets.map(\.path), ["/Users/alice/.npmrc"])
    }

    func testPrefixNeedlesAreAnchoredToStringStart() {
        let filter = LinePrefilter(prefixes: ["/Volumes", "/Users/alice/.ssh"])
        // /volumes inside /System/Volumes/… (here the process executable) no longer matches.
        let cryptex = esLine(#""open":{"fflag":1,"file":{"path":"\/System\/Library\/Fonts\/x.ttf"}}"#,
                             exe: #"\/System\/Volumes\/Preboot\/Cryptexes\/App\/System\/Applications\/Safari.app\/Contents\/MacOS\/Safari"#)
        XCTAssertEqual(filter.verdict(cryptex), .drop)
        XCTAssertEqual(filter.verdict(esLine(#""open":{"fflag":1,"file":{"path":"\/System\/Volumes\/Data\/.Spotlight-V100\/x"}}"#)), .drop)
        // Real matches: plain, escaped, firmlinked, case-insensitive.
        XCTAssertEqual(filter.verdict(esLine(#""open":{"fflag":1,"file":{"path":"\/Volumes\/USB\/x"}}"#)), .parse)
        XCTAssertEqual(filter.verdict(esLine(#""open":{"fflag":1,"file":{"path":"/volumes/USB/x"}}"#)), .parse)
        XCTAssertEqual(filter.verdict(esLine(#""open":{"fflag":1,"file":{"path":"\/System\/Volumes\/Data\/Users\/alice\/.ssh\/id_rsa"}}"#)), .parse)
        XCTAssertEqual(filter.verdict(esLine(#""open":{"fflag":1,"file":{"path":"/System/Volumes/Data/Users/alice/.ssh/id_rsa"}}"#)), .parse)
        // A non-ASCII prefix still matches by its (unanchored) ASCII fragment.
        let cjk = LinePrefilter(prefixes: ["/Users/alice/Work/项目"])
        XCTAssertEqual(cjk.verdict(esLine(#""open":{"fflag":1,"file":{"path":"\/Users\/alice\/Work\/"# + "项目" + #"\/a"}}"#)), .parse)
    }

    func testSequenceRestartsWithNewStream() {
        let p = EsloggerParser()
        p.noteSequence(20_000_000)
        // A restarted eslogger counts from 0 again; its own gap (2…4) is still counted.
        p.noteSequence(0)
        p.noteSequence(1)
        p.noteSequence(5)
        XCTAssertEqual(p.stats.droppedByKernel, 3)
        // resetSequence forgets the previous stream even when the new one starts higher.
        let q = EsloggerParser()
        q.noteSequence(5)
        q.resetSequence()
        q.noteSequence(7)
        XCTAssertEqual(q.stats.droppedByKernel, 0)
        // Noting the same number twice (malformed after the parser saw it) is harmless.
        q.noteSequence(7)
        q.noteSequence(8)
        XCTAssertEqual(q.stats.droppedByKernel, 0)
    }

    func testDirectoryOpenBecomesReaddir() throws {
        let dirStat = #""stat":{"st_mode":16877,"st_size":192}"#
        let fileStat = #""stat":{"st_mode":33188,"st_size":411}"#
        // Directory by stat.
        let byStat = try XCTUnwrap(fileEvent(esLine(#""open":{"fflag":1,"file":{"path":"\/Users\/alice\/.ssh","path_truncated":false,\#(dirStat)}}"#)))
        XCTAssertEqual(byStat.operation, .readdir)
        XCTAssertEqual(byStat.targets.map(\.isDirectory), [true])
        XCTAssertEqual(byStat.targets.map(\.access), [.read])
        // Directory by O_DIRECTORY in fflag (the documented sample 0x1100001), no stat.
        let byFlag = try XCTUnwrap(fileEvent(esLine(#""open":{"fflag":17825793,"file":{"path":"/Users/alice/.ssh"}}"#)))
        XCTAssertEqual(byFlag.operation, .readdir)
        // A regular file stays an open, with what its stat says.
        let regular = try XCTUnwrap(fileEvent(esLine(#""open":{"fflag":1,"file":{"path":"/Users/alice/.ssh/id_rsa","path_truncated":true,\#(fileStat)}}"#)))
        XCTAssertEqual(regular.operation, .open)
        XCTAssertEqual(regular.targets.map(\.isDirectory), [false])
        XCTAssertEqual(regular.targets.map(\.truncated), [true])
        // No stat: unknown.
        let unknown = try XCTUnwrap(fileEvent(esLine(#""open":{"fflag":1,"file":{"path":"/Users/alice/.ssh/id_rsa"}}"#)))
        XCTAssertEqual(unknown.targets.map(\.isDirectory), [nil])
        // Other operations carry the stat too; new-path destinations are dir + filename.
        let unlink = try XCTUnwrap(fileEvent(esLine(#""unlink":{"target":{"path":"/Users/alice/.ssh/old",\#(dirStat)},"parent_dir":{"path":"/Users/alice/.ssh"}}"#)))
        XCTAssertEqual(unlink.targets.map(\.isDirectory), [true])
        let rename = try XCTUnwrap(fileEvent(esLine(#""rename":{"source":{"path":"/Users/alice/.ssh",\#(dirStat)},"destination_type":1,"destination":{"new_path":{"dir":{"path":"/private/tmp","path_truncated":true},"filename":"s"}}}"#)))
        XCTAssertEqual(rename.targets.map(\.path), ["/Users/alice/.ssh", "/private/tmp/s"])
        XCTAssertEqual(rename.targets.map(\.isDirectory), [true, nil])
        XCTAssertEqual(rename.targets.map(\.truncated), [false, true])
        let link = try XCTUnwrap(fileEvent(esLine(#""link":{"target_dir":{"path":"/private/tmp/"},"target_filename":"k","source":{"path":"/Users/alice/.ssh/id_rsa",\#(fileStat)}}"#)))
        XCTAssertEqual(link.targets.map(\.path), ["/Users/alice/.ssh/id_rsa", "/private/tmp/k"])

        // The analyzer drops readdir unless it is enabled.
        let h = try Harness()
        let open = esLine(#""open":{"fflag":1,"file":{"path":"\/Users\/alice\/.ssh",\#(dirStat)}}"#)
        guard case .event(let e) = EsloggerParser().parse(line: open) else { return XCTFail() }
        XCTAssertTrue(h.analyzer.handle(e).events.isEmpty)
        h.analyzer.readdirEnabled = true
        let listed = h.analyzer.handle(e).events
        XCTAssertFalse(listed.isEmpty)
        XCTAssertTrue(listed.allSatisfy { $0.operation == .readdir })
    }
}
