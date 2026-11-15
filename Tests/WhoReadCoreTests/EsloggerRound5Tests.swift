import XCTest
@testable import WhoReadCore

/// Review round 5 (eslogger): creates another ES client denied, and non-ASCII prefixes and ancestors
/// in the prefilter.
final class EsloggerRound5Tests: XCTestCase {
    private func esLine(_ event: String, exe: String = "/bin/cat") -> String {
        #"{"schema_version":1,"global_seq_num":7,"time":"2025-10-09T08:53:20.000000000Z","process":{"audit_token":{"pid":501,"pidversion":5},"ppid":1,"executable":{"path":"\#(exe)"}},"event":{\#(event)}}"#
    }

    private func open(_ jsonPath: String, exe: String = "/bin/cat") -> String {
        esLine(#""open":{"fflag":1,"file":{"path":"\#(jsonPath)"}}"#, exe: exe)
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

    private func nfc(_ s: String) -> String { s.precomposedStringWithCanonicalMapping }
    private func nfd(_ s: String) -> String { s.decomposedStringWithCanonicalMapping }

    // MARK: eslogger-1

    // A NOTIFY_CREATE with a new-path destination is one an ES client denied (ESMessage.h): nothing was
    // created. The native backend skips it; eslogger recorded it as a write and alerted.
    func testCreateDeniedByAnotherESClientIsNotRecorded() throws {
        let typed = esLine(#""create":{"destination_type":1,"destination":{"new_path":{"dir":{"path":"\/Users\/alice\/WhoReadTestVault\/ssh"},"filename":"authorized_keys","mode":420}},"acl":null}"#,
                           exe: "/usr/bin/python3")
        let untyped = esLine(#""create":{"destination":{"new_path":{"dir":{"path":"\/Users\/alice\/WhoReadTestVault\/ssh"},"filename":"authorized_keys","mode":420}}}"#,
                             exe: "/usr/bin/python3")
        let p = EsloggerParser()
        for line in [typed, untyped] {
            switch p.parse(line: line) {
            case .ignored(let why): XCTAssertTrue(why.contains("denied"), why)
            case .event(let e): XCTFail("a create that never happened is recorded: \(e)")
            case .malformed(let why): XCTFail("malformed: \(why)")
            }
        }
        XCTAssertEqual(p.stats.events, 0)
        XCTAssertEqual(p.stats.ignored, 2)
        XCTAssertEqual(p.stats.malformed, 0)

        // End to end, without learning (a first access alerts at once): no record, no alert.
        let h = try Harness(learningDays: 0)
        for line in [typed, untyped] {
            if case .event(let e) = EsloggerParser().parse(line: line) {
                let out = h.analyzer.handle(e)
                XCTFail("recorded \(out.events.map { "\($0.operation) \($0.access.label) \($0.categoryID)" }), \(out.alerts.count) alerts")
            }
        }

        // A create reported after it happened (existing_file) is still recorded: a link planted there.
        let made = create(#"\/Users\/alice\/WhoReadTestVault\/ssh\/authorized_keys"#)
        guard case .event(.file(let f)) = p.parse(line: made) else { return XCTFail("a planted link is not recorded") }
        XCTAssertEqual(f.operation, .create)
        XCTAssertEqual(f.targets.map(\.path), ["/Users/alice/WhoReadTestVault/ssh/authorized_keys"])
        XCTAssertFalse(h.analyzer.handle(.file(f)).events.isEmpty)

        // The prefilter no longer parses a create for its new_path key alone (the parser ignores it).
        let filter = LinePrefilter(prefixes: ["/Users/alice/WhoReadTestVault"])
        let vault = esLine(#""create":{"destination_type":1,"destination":{"new_path":{"dir":{"path":"\/Users\/alice"},"filename":"WhoReadTestVault","mode":448}},"acl":null}"#,
                           exe: "/bin/mkdir")
        XCTAssertEqual(filter.verdict(vault), .drop)
        XCTAssertEqual(filter.verdict(made), .parse)
    }

    // MARK: eslogger-2

    // For ~/项目 the longest ASCII fragment was the home itself: every line naming anything in the
    // home (an executable installed there, an app's caches) was parsed. A non-ASCII prefix is now
    // matched exactly, from the start of a JSON string, like an ASCII one.
    func testCJKProjectRootIsMatchedExactly() throws {
        let node = #"\/Users\/alice\/.nvm\/versions\/node\/v22.9.0\/bin\/node"#
        let unrelated = [
            "home node loading a system dylib": open(#"\/usr\/lib\/libz.1.dylib"#, exe: node),
            "Safari's cache in the home": open(#"\/Users\/alice\/Library\/Caches\/com.apple.Safari\/Cache.db"#,
                                               exe: #"\/Applications\/Safari.app\/Contents\/MacOS\/Safari"#),
        ]
        for root in ["~/code/app", "~/项目"] {
            let h = try Harness(projectRoots: [root])
            let filter = LinePrefilter(prefixes: h.classifier.mutePaths, ancestors: h.classifier.ancestors)
            for (what, line) in unrelated.sorted(by: { $0.key < $1.key }) {
                XCTAssertEqual(filter.verdict(line), .drop, "\(root): \(what)")
            }
        }
        let h = try Harness(projectRoots: ["~/项目"])
        let filter = LinePrefilter(prefixes: h.classifier.mutePaths, ancestors: h.classifier.ancestors)
        for path in [#"\/Users\/alice\/项目\/certs\/server.key"#, "/Users/alice/项目/certs/server.key",
                     "/System/Volumes/Data/Users/alice/项目/certs/server.key", #"\/USERS\/ALICE\/项目\/certs\/server.key"#] {
            XCTAssertEqual(filter.verdict(open(path)), .parse, path)
        }
        // The line that matters still reaches the analyzer.
        guard case .event(.file(let f)) = EsloggerParser().parse(line: open(#"\/Users\/alice\/项目\/certs\/server.key"#)) else {
            return XCTFail("not parsed")
        }
        XCTAssertEqual(h.analyzer.handle(.file(f)).events.map(\.categoryID), ["project-secrets"])
        // A path that only contains the prefix (not a spelling of it) is no match.
        XCTAssertEqual(filter.verdict(open("/opt/mirror/Users/alice/项目/certs/server.key")), .drop)
    }

    // A non-ASCII ancestor (~/工作 for ~/工作/keys) made every create on the system go through the
    // parser. It is matched exactly as well, as a whole JSON string.
    func testCJKAncestorIsMatchedExactly() throws {
        let h = try Harness(projectRoots: ["~/工作/keys"])
        XCTAssertTrue(h.classifier.ancestors.contains("/Users/alice/工作"))
        let filter = LinePrefilter(prefixes: h.classifier.mutePaths, ancestors: h.classifier.ancestors)
        for line in [create(#"\/private\/tmp\/whoread-x\/new.txt"#, mode: 0o100644), create("/Users/bob/link"),
                     create(#"\/Users\/alice\/工作\/other"#), create("/Users/alice/工作x")] {
            XCTAssertEqual(filter.verdict(line), .drop, line)
        }
        for path in ["/Users/alice/工作", #"\/Users\/alice\/工作"#, "/System/Volumes/Data/Users/alice/工作", "/USERS/alice/工作"] {
            XCTAssertEqual(filter.verdict(create(path)), .parse, path)
        }
        // A link planted at the ancestor is still an event.
        guard case .event(.file(let f)) = EsloggerParser().parse(line: create(#"\/Users\/alice\/工作"#)) else { return XCTFail() }
        XCTAssertFalse(h.analyzer.handle(.file(f)).events.isEmpty)
    }

    // NFC and NFD differ for kana with a voicing mark (and Hangul). APFS keeps each name in the form
    // it was created in, so the folders of one path can differ (Finder and Terminal create them
    // differently): every combination is matched.
    func testEveryNormalFormOfEachComponentIsMatched() {
        let docs = "ドキュメント", project = "プロジェクト"
        XCTAssertNotEqual(nfc(docs).unicodeScalars.count, nfd(docs).unicodeScalars.count)
        XCTAssertNotEqual(nfc(project).unicodeScalars.count, nfd(project).unicodeScalars.count)
        let filter = LinePrefilter(prefixes: ["/Users/alice/" + nfc(docs) + "/" + nfc(project)],
                                   ancestors: ["/Users", "/Users/alice", "/Users/alice/" + nfc(docs)])
        for (a, b) in [(nfc(docs), nfc(project)), (nfd(docs), nfd(project)), (nfd(docs), nfc(project)), (nfc(docs), nfd(project))] {
            let path = "/Users/alice/" + a + "/" + b + "/server.key"
            XCTAssertEqual(filter.verdict(open(path)), .parse, path.debugDescription)
            XCTAssertEqual(filter.verdict(open(slashEscaped(path))), .parse, path.debugDescription)
        }
        for docsForm in [nfc(docs), nfd(docs)] {
            XCTAssertEqual(filter.verdict(create(slashEscaped("/Users/alice/" + docsForm))), .parse)
        }
        XCTAssertEqual(filter.verdict(open(#"\/Users\/alice\/Library\/Caches\/x.db"#)), .drop)
        XCTAssertEqual(filter.verdict(create(#"\/private\/tmp\/x"#)), .drop)

        // Past eight combinations the prefix falls back to its ASCII fragment: over-matching, never missing.
        let deep = "/Users/alice/" + [docs, project, "ガイド", "データ"].map(nfc).joined(separator: "/")
        let wide = LinePrefilter(prefixes: [deep])
        let mixed = "/Users/alice/" + [nfd(docs), nfc(project), nfd("ガイド"), nfc("データ")].joined(separator: "/") + "/x"
        XCTAssertEqual(wide.verdict(open(mixed)), .parse)
    }

    // APFS also ignores case, but the scan folds only ASCII: É and é are different bytes. A prefix with
    // such letters keeps its ASCII fragment, anchored when it is the start of the prefix.
    func testCasedNonASCIILettersKeepTheirASCIIFallback() {
        let filter = LinePrefilter(prefixes: ["/Users/alice/Café"], ancestors: ["/Users", "/Users/alice"])
        for path in ["/Users/alice/Café/x", "/Users/alice/CAFÉ/x", "/Users/alice/Cafe\u{301}/x", "/Users/alice/CAFE\u{301}/x",
                     slashEscaped("/System/Volumes/Data/Users/alice/CAFÉ/x")] {
            XCTAssertEqual(filter.verdict(open(path)), .parse, path.debugDescription)
        }
        XCTAssertEqual(filter.verdict(open(#"\/Users\/alice\/Library\/Caches\/x.db"#)), .drop)
        XCTAssertEqual(filter.verdict(open("/opt/mirror/Users/alice/Café/x")), .drop, "anchored to the start of a string")
        // A fragment from the middle of the prefix stays unanchored, JSON-escaped.
        let middle = LinePrefilter(prefixes: [#"/Users/é/code"dir"#])
        XCTAssertEqual(middle.verdict(open(#"\/Users\/É\/code\"dir\/x"#)), .parse)
        XCTAssertEqual(middle.verdict(open(#"/Users/é/code\"dir/x"#)), .parse)
        // No fragment at all: every file event is parsed, as before.
        XCTAssertEqual(LinePrefilter(prefixes: ["/Été"]).verdict(open("/private/tmp/x")), .parse)
        // A cased non-ASCII ancestor cannot be matched exactly either: every create is parsed.
        let deep = LinePrefilter(prefixes: ["/Users/alice/Café/app"], ancestors: ["/Users", "/Users/alice", "/Users/alice/Café"])
        XCTAssertEqual(deep.verdict(create(#"\/private\/tmp\/x"#)), .parse)
        XCTAssertEqual(deep.verdict(open(#"\/private\/tmp\/x"#)), .drop)
    }

    // A non-ASCII prefix without any ASCII fragment no longer parses every file event.
    func testNonASCIIPrefixWithoutASCIIFragmentIsMatchedExactly() {
        let filter = LinePrefilter(prefixes: ["/项目"])
        XCTAssertEqual(filter.verdict(open("/private/tmp/x")), .drop)
        XCTAssertEqual(filter.verdict(open(#"\/项目\/x"#)), .parse)
        XCTAssertEqual(filter.verdict(open("/System/Volumes/Data/项目/x")), .parse)
    }
}
