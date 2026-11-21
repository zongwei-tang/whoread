import XCTest
@testable import WhoReadCore

/// Review round 6 (eslogger): project roots spelled on disk in a form canonically equivalent to the
/// configured one but neither its NFC nor its NFD (E1), and files changed through a writable mapping (E2).
final class EsloggerRound6Tests: XCTestCase {
    private static let start = "2025-10-09T08:53:20.000000Z"

    private func esLine(_ event: String, pid: Int = 501, start: String = EsloggerRound6Tests.start, version: Int = 10,
                        exe: String = "/bin/cat") -> String {
        #"{"schema_version":1,"version":\#(version),"global_seq_num":7,"time":"2025-10-09T08:53:21.000000000Z","process":{"audit_token":{"pid":\#(pid),"pidversion":5},"ppid":1,"start_time":"\#(start)","executable":{"path":"\#(exe)"}},"event":{\#(event)}}"#
    }

    private func open(_ jsonPath: String, fflag: Int = 1, pid: Int = 501, start: String = EsloggerRound6Tests.start,
                      exe: String = "/bin/cat") -> String {
        esLine(#""open":{"fflag":\#(fflag),"file":{"path":"\#(jsonPath)"}}"#, pid: pid, start: start, exe: exe)
    }

    /// A close as eslogger writes it; `mapped` nil leaves `was_mapped_writable` out.
    private func close(_ jsonPath: String, modified: Bool = false, mapped: Bool?, pid: Int = 501,
                       start: String = EsloggerRound6Tests.start, version: Int = 10, exe: String = "/bin/cat") -> String {
        let flag = mapped.map { #","was_mapped_writable":\#($0)"# } ?? ""
        return esLine(#""close":{"modified":\#(modified),"target":{"path":"\#(jsonPath)"}\#(flag)}"#,
                      pid: pid, start: start, version: version, exe: exe)
    }

    /// A create as the kernel reports it once it happened: the new object as an existing file.
    private func create(_ jsonPath: String, mode: Int = 0o120755) -> String {
        esLine(#""create":{"destination_type":0,"destination":{"existing_file":{"path":"\#(jsonPath)","stat":{"st_mode":\#(mode)}}},"acl":null}"#)
    }

    /// `/` as eslogger escapes it, scalar by scalar (Foundation's replacing could renormalize).
    private func slashEscaped(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        for scalar in s.unicodeScalars {
            if scalar == "/" { out.append("\\") }
            out.append(scalar)
        }
        return String(out)
    }

    private func sameBytes(_ a: String, _ b: String) -> Bool { a.utf8.elementsEqual(b.utf8) }

    // MARK: E1-nfc-nfd

    /// Names as configured (NFC) and as a folder can be spelled on disk: APFS finds it by either, and
    /// the disk spelling is neither the name's NFC nor its NFD.
    private let equivalentSpellings: [(what: String, root: String, onDisk: String)] = [
        ("CJK compatibility ideograph U+FA10 for 塚", "\u{5927}\u{585A}", "\u{5927}\u{FA10}"),
        ("CJK compatibility ideograph U+FA26 for 都", "\u{4EAC}\u{90FD}", "\u{4EAC}\u{FA26}"),
        ("Devanagari nukta letter U+095B", "\u{091C}\u{093C}\u{092E}\u{0940}\u{0928}", "\u{095B}\u{092E}\u{0940}\u{0928}"),
        ("Arabic shadda typed before fatha", "\u{0645}\u{064E}\u{0651}\u{062F}", "\u{0645}\u{0651}\u{064E}\u{062F}"),
        ("Hangul LV syllable and a final jamo", "\u{D55C}\u{AD6D}", "\u{D558}\u{11AB}\u{AD6D}"),
        ("Hebrew presentation form U+FB2A", "\u{05E9}\u{05C1}\u{05DC}\u{05D5}\u{05DD}", "\u{FB2A}\u{05DC}\u{05D5}\u{05DD}"),
        ("kana half NFC, half NFD", "\u{30C0}\u{30A6}\u{30F3}\u{30ED}\u{30FC}\u{30C9}",
         "\u{30C0}\u{30A6}\u{30F3}\u{30ED}\u{30FC}\u{30C8}\u{3099}"),
    ]

    /// The prefix the classifier monitors for a root typed as `typed` (`~/` expanded, normalized).
    private func prefix(_ typed: String) -> String {
        PathNormalizer(homeDirectories: [home]).expand("~/" + typed)[0]
    }

    // The prefilter listed each component only in NFC and in NFD, so an open below a root spelled on
    // disk in another equivalent form was dropped before the parser (the analyzer would have recorded
    // it as project-secrets). Each such spelling is now listed, or the root falls back to its ASCII
    // fragment, also when the root is typed in the disk spelling.
    func testEveryEquivalentSpellingOfARootOnDiskIsParsed() throws {
        for (what, root, onDisk) in equivalentSpellings {
            XCTAssertEqual(onDisk, root, "\(what): canonically equivalent")
            XCTAssertFalse(sameBytes(onDisk, root.precomposedStringWithCanonicalMapping), what)
            XCTAssertFalse(sameBytes(onDisk, root.decomposedStringWithCanonicalMapping), what)
            let listed = LinePrefilter.spellings(prefix(root))
            XCTAssertTrue(listed.map { $0.contains { sameBytes($0, home + "/" + onDisk) } } ?? true,
                          "\(what): listed without the disk spelling: \(listed ?? [])")
            let path = home + "/" + onDisk + "/certs/server.key"
            for typed in [root, onDisk] {
                let filter = LinePrefilter(prefixes: [prefix(typed)], ancestors: ["/Users", home])
                for spelled in [path, slashEscaped(path), "/System/Volumes/Data" + path] {
                    XCTAssertEqual(filter.verdict(open(spelled)), .parse, "\(what), typed \(typed.debugDescription): \(spelled.debugDescription)")
                }
            }
        }
        // With the whole catalog, and through the analyzer: recorded as project-secrets.
        for typed in [equivalentSpellings.map(\.root), equivalentSpellings.map(\.onDisk)] {
            let h = try Harness(projectRoots: typed.map { "~/" + $0 })
            let filter = LinePrefilter(prefixes: h.classifier.mutePaths, ancestors: h.classifier.ancestors)
            for (what, _, onDisk) in equivalentSpellings {
                let line = open(slashEscaped(home + "/" + onDisk + "/certs/server.key"))
                XCTAssertEqual(filter.verdict(line), .parse, what)
                guard case .event(.file(let f)) = EsloggerParser().parse(line: line) else {
                    XCTFail("\(what): not parsed")
                    continue
                }
                XCTAssertEqual(h.analyzer.handle(.file(f)).events.map(\.categoryID), ["project-secrets"], what)
            }
        }
    }

    // A link planted at a non-ASCII ancestor spelled on disk that way: its create was dropped too (before
    // round 5 every create was parsed for a non-ASCII ancestor).
    func testCreateAtAnAncestorSpelledOnDiskAnotherWayIsParsed() throws {
        let h = try Harness(projectRoots: equivalentSpellings.map { "~/" + $0.root + "/keys" })
        for (what, root, onDisk) in equivalentSpellings {
            guard let ancestor = h.classifier.ancestors.first(where: { $0 == home + "/" + root }) else {
                XCTFail("\(what): no ancestor")
                continue
            }
            let filter = LinePrefilter(prefixes: [prefix(root + "/keys")], ancestors: ["/Users", home, ancestor])
            let line = create(slashEscaped(home + "/" + onDisk))
            XCTAssertEqual(filter.verdict(line), .parse, what)
            guard case .event(.file(let f)) = EsloggerParser().parse(line: line) else {
                XCTFail("\(what): not parsed")
                continue
            }
            XCTAssertFalse(h.analyzer.handle(.file(f)).events.isEmpty, what)
        }
    }

    // What the fix lists and what it gives up: names whose spellings are only their composed and
    // decomposed characters stay exact (an unrelated line in the home is dropped); the others fall
    // back to the ASCII fragment, which over-matches but never misses.
    func testListableNamesStayExact() throws {
        let downloads = "\u{30C0}\u{30A6}\u{30F3}\u{30ED}\u{30FC}\u{30C9}" // ダウンロード: two voiced kana
        XCTAssertEqual(LinePrefilter.spellings(prefix(downloads))?.count, 4, "each voiced kana composed or not")
        XCTAssertEqual(LinePrefilter.spellings(prefix("\u{9879}\u{76EE}"))?.count, 1)
        for (what, root, _) in equivalentSpellings where !what.hasPrefix("kana") {
            XCTAssertNil(LinePrefilter.spellings(prefix(root)), what)
        }
        let unrelated = open(#"\/Users\/alice\/Library\/Caches\/com.apple.Safari\/Cache.db"#)
        for root in ["\u{9879}\u{76EE}", "\u{30C7}\u{30FC}\u{30BF}", downloads] {
            let filter = LinePrefilter(prefixes: [prefix(root)], ancestors: ["/Users", home])
            XCTAssertEqual(filter.verdict(unrelated), .drop, root.debugDescription)
            XCTAssertEqual(filter.verdict(create(#"\/private\/tmp\/x"#)), .drop, root.debugDescription)
        }
        let fallback = LinePrefilter(prefixes: [prefix("\u{5927}\u{585A}")], ancestors: ["/Users", home])
        XCTAssertEqual(fallback.verdict(unrelated), .parse, "the home is the ASCII fragment of ~/大塚")
        XCTAssertEqual(fallback.verdict(open("/opt/mirror/Users/alice/x")), .drop, "still anchored to the start of a string")
        // An ancestor that cannot be listed lets every create through, as before round 5.
        let deep = LinePrefilter(prefixes: [prefix("\u{5927}\u{585A}/keys")], ancestors: ["/Users", home, prefix("\u{5927}\u{585A}")])
        XCTAssertEqual(deep.verdict(create(#"\/private\/tmp\/x"#)), .parse)
    }

    // MARK: E2-mapped-writable

    private let vaultFile = #"\/Users\/alice\/WhoReadTestVault\/notes\/mmap.txt"#
    private let python = "/usr/bin/python3"

    // A close that reports no write call was dropped before the parser even when it said the file was
    // mapped writable: a change made only through mmap was never recorded.
    func testPrefilterKeepsAnUnmodifiedCloseOfAFileMappedWritable() {
        let filter = LinePrefilter(prefixes: ["/Users/alice/WhoReadTestVault"])
        XCTAssertEqual(filter.verdict(close(vaultFile, mapped: true)), .parse)
        let spaced = #"{"event":{"close":{"modified": false,"target":{"path":"/Users/alice/WhoReadTestVault/notes/mmap.txt"},"was_mapped_writable": true}}}"#
        XCTAssertEqual(filter.verdict(spaced), .parse)
        XCTAssertEqual(filter.verdict(close(vaultFile, mapped: false)), .drop)
        XCTAssertEqual(filter.verdict(close(vaultFile, mapped: nil)), .drop)
        XCTAssertEqual(filter.verdict(close(#"\/private\/tmp\/x.db"#, mapped: true)), .drop, "not a monitored path")
    }

    // Recorded as the native source records it: a possible write (note mapped-writable), only for a
    // process that opened that file for writing itself.
    func testCloseOfAFileTheProcessMappedWritableIsAPossibleWrite() throws {
        let p = EsloggerParser()
        guard case .event(.file(let o)) = p.parse(line: open(vaultFile, fflag: 3, exe: python)) else { return XCTFail("open") }
        XCTAssertEqual(o.targets.map(\.access), [.readWrite])
        guard case .event(.file(let c)) = p.parse(line: close(vaultFile, mapped: true, exe: python)) else {
            return XCTFail("a close after writes through a mapping is not recorded")
        }
        XCTAssertEqual(c.operation, .close)
        XCTAssertEqual(c.targets.map(\.path), ["/Users/alice/WhoReadTestVault/notes/mmap.txt"])
        XCTAssertEqual(c.targets.map(\.access), [.write])
        XCTAssertEqual(c.note, EventNote.mappedWritable)
        // A close that reports write calls is a plain write, as before.
        guard case .event(.file(let w)) = p.parse(line: close(vaultFile, modified: true, mapped: true, exe: python)) else {
            return XCTFail("modified close")
        }
        XCTAssertNil(w.note)

        // End to end: recorded as a write with the note.
        let h = try Harness(learningDays: 0)
        _ = h.analyzer.handle(.file(o))
        let events = h.analyzer.handle(.file(c)).events
        XCTAssertEqual(events.map(\.operation), [.close])
        XCTAssertEqual(events.map(\.access), [.write])
        XCTAssertEqual(events.map(\.note), [EventNote.mappedWritable])
    }

    // The flag covers the file's whole life: a reader, another process, a reused pid, another file of
    // the writer, or a message before version 6 (no such field) is not charged with a change.
    func testMappedCloseCountsOnlyForTheProcessThatOpenedThatFileForWriting() {
        let p = EsloggerParser()
        _ = p.parse(line: open(vaultFile, fflag: 3, pid: 700, exe: python))
        _ = p.parse(line: open(vaultFile, fflag: 1, pid: 701))
        let other = #"\/Users\/alice\/WhoReadTestVault\/notes\/other.txt"#
        let cases: [(String, String)] = [
            ("a reader", close(vaultFile, mapped: true, pid: 701)),
            ("a process that never opened it", close(vaultFile, mapped: true, pid: 702)),
            ("the writer's pid reused", close(vaultFile, mapped: true, pid: 700, start: "2025-10-09T08:59:00.000000Z", exe: python)),
            ("another file of the writer", close(other, mapped: true, pid: 700, exe: python)),
            ("message version 5", close(vaultFile, mapped: true, pid: 700, version: 5, exe: python)),
            ("not mapped writable", close(vaultFile, mapped: false, pid: 700, exe: python)),
        ]
        for (what, line) in cases {
            if case .event(let e) = p.parse(line: line) { XCTFail("\(what): recorded \(e)") }
        }
        // The descriptor survives exec: the same process under another image is still the writer.
        guard case .event(.file(let c)) = p.parse(line: close(vaultFile, mapped: true, pid: 700, exe: "/bin/sh")) else {
            return XCTFail("the writer after an exec")
        }
        XCTAssertEqual(c.note, EventNote.mappedWritable)
    }

    func testWritableOpensStayBounded() {
        var w = EsloggerWritableOpens()
        let start = Date(timeIntervalSince1970: 1)
        for i in 0..<(3 * EsloggerWritableOpens.capacity) { w.note(.init(pid: Int32(i), start: start), path: "/p") }
        XCTAssertEqual(w.count, EsloggerWritableOpens.capacity)
        XCTAssertFalse(w.contains(.init(pid: 0, start: start), path: "/p"), "the oldest go first")
        XCTAssertTrue(w.contains(.init(pid: Int32(3 * EsloggerWritableOpens.capacity - 1), start: start), path: "/p"))
        // A repeated open is one entry.
        var once = EsloggerWritableOpens()
        once.note(.init(pid: 1, start: nil), path: "/p")
        once.note(.init(pid: 1, start: nil), path: "/p")
        XCTAssertEqual(once.count, 1)
    }
}
