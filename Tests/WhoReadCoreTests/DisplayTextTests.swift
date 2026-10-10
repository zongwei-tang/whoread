import XCTest
@testable import WhoReadCore

/// guard-4 / privacy-3: names and paths are attacker-controlled; what WhoRead shows a person goes
/// through one sanitizer (`DisplayText`).
final class DisplayTextTests: XCTestCase {
    func testHiddenCharactersBecomeVisibleEscapesAndOrdinaryTextIsKept() {
        let raw = "a\u{202E}b\u{2067}c\u{200B}d\u{2028}e\u{009B}f\u{1B}[8mg\rh\u{7F}i\n微信\u{F8FF}\u{FEFF}\u{061C}\u{200E}\u{2029}\u{00AD}\t"
        XCTAssertEqual(DisplayText.escaped(raw),
                       "a\\u{202e}b\\u{2067}c\\u{200b}d\\u{2028}e\\u{9b}f\\u{1b}[8mg\\u{d}h\\u{7f}i\\u{a}微信\\u{f8ff}\\u{feff}\\u{61c}\\u{200e}\\u{2029}\\u{ad}\\u{9}")
        // "\r\n" is one Character in Swift: both scalars are still caught.
        XCTAssertEqual(DisplayText.escaped("x\r\ny"), "x\\u{d}\\u{a}y")
        // ESC followed by a combining mark is one grapheme too.
        XCTAssertEqual(DisplayText.escaped("\u{1B}\u{301}[2K"), "\\u{1b}\u{301}[2K")
        for plain in ["Zoom", "微信", "Google Chrome", "~/WhoReadTestVault/ssh/id_ed25519", "Claude Code → zsh → cat", "café", "👍🏽", ""] {
            XCTAssertEqual(DisplayText.escaped(plain), plain)
            XCTAssertEqual(DisplayText.name(plain), plain)
            XCTAssertEqual(DisplayText.path(plain), plain)
        }
        for s in DisplayText.escaped(raw).unicodeScalars { XCTAssertFalse(DisplayText.isHidden(s), "\(s.value)") }
    }

    func testNamesAreCappedWithoutCuttingAnEscapeAndEscapingTwiceChangesNothing() {
        let long = String(repeating: "a", count: 100)
        let name = DisplayText.name(long)
        XCTAssertEqual(name.unicodeScalars.count, DisplayText.nameLimit)
        XCTAssertTrue(name.hasSuffix("a…"))
        // An escape that does not fit is dropped whole, never cut to "\u{2".
        let edge = String(repeating: "b", count: 60) + "\u{202E}" + "tail"
        let capped = DisplayText.name(edge)
        XCTAssertEqual(capped, String(repeating: "b", count: 60) + "…")
        XCTAssertLessThanOrEqual(capped.unicodeScalars.count, DisplayText.nameLimit)
        // Lots of combining marks count as what they are (scalars), not as one character.
        let zalgo = "T" + String(repeating: "\u{301}", count: 500)
        XCTAssertEqual(DisplayText.name(zalgo).unicodeScalars.count, DisplayText.nameLimit)

        let samples = [long, edge, zalgo, "x\u{1B}]0;title\u{07}y", String(repeating: "\u{202E}", count: 40),
                       "/Users/alice/" + String(repeating: "d/", count: 200) + "id_ed25519\u{1B}"]
        for s in samples {
            XCTAssertEqual(DisplayText.escaped(DisplayText.escaped(s)), DisplayText.escaped(s))
            XCTAssertEqual(DisplayText.name(DisplayText.name(s)), DisplayText.name(s))
            XCTAssertEqual(DisplayText.path(DisplayText.path(s)), DisplayText.path(s))
            XCTAssertEqual(DisplayText.escaped(DisplayText.name(s)), DisplayText.name(s))
        }
    }

    /// Review round: characters that render as nothing or as blank space without being "format"
    /// characters, and blank padding inside the name cap.
    func testInvisibleFillersAreEscapedAndBlankRunsInNamesCollapse() {
        // Hangul fillers (letters by category), the combining grapheme joiner and variation selectors
        // (marks), an unassigned default-ignorable code point.
        XCTAssertEqual(DisplayText.escaped("a\u{3164}b\u{115F}c\u{FFA0}d\u{34F}e\u{FE00}f\u{E0100}g\u{2065}h"),
                       "a\\u{3164}b\\u{115f}c\\u{ffa0}d\\u{34f}e\\u{fe00}f\\u{e0100}g\\u{2065}h")
        // The emoji presentation selector only picks a glyph: kept.
        XCTAssertEqual(DisplayText.escaped("I \u{2764}\u{FE0F} cats"), "I \u{2764}\u{FE0F} cats")
        // 56 ideographic spaces (112 columns) after a lure pushed the real path two banner lines down.
        let padded = "Terminal" + String(repeating: "\u{3000}", count: 56)
        XCTAssertEqual(DisplayText.name(padded), "Terminal ")
        XCTAssertEqual(DisplayText.name("Terminal" + String(repeating: "\u{3164}", count: 56)),
                       "Terminal" + String(repeating: "\\u{3164}", count: 6) + "…", "fillers are escaped, so the cap counts what is shown")
        // Fake CLI columns.
        XCTAssertEqual(DisplayText.name("Terminal  SSH keys\u{A0}\u{A0}read"), "Terminal SSH keys read")
        XCTAssertEqual(DisplayText.name("Google Chrome"), "Google Chrome")
        for s in [padded, "a \u{3000} b", "  x  "] {
            XCTAssertEqual(DisplayText.name(DisplayText.name(s)), DisplayText.name(s))
        }
        // Paths are evidence: their spaces stay as they are.
        XCTAssertEqual(DisplayText.path("~/x/Terminal  SSH keys.app"), "~/x/Terminal  SSH keys.app")
    }

    func testLongPathsKeepTheirFileName() {
        let path = "~/" + String(repeating: "deep/", count: 60) + "id_ed25519"
        let shown = DisplayText.path(path)
        XCTAssertEqual(shown.unicodeScalars.count, DisplayText.pathLimit)
        XCTAssertTrue(shown.hasPrefix("~/deep/"), shown)
        XCTAssertTrue(shown.hasSuffix("/id_ed25519"), shown)
        XCTAssertTrue(shown.contains("…"))
    }
}

/// guard-4: the headline of a question or alert, which the user allows or denies on, put the app's
/// display name (a bundle folder's name) and the path into the text unchanged.
final class AlertTextSanitizingTests: XCTestCase {
    let n = PathNormalizer(homeDirectories: [home])
    var en: AlertFormatter { AlertFormatter(language: .en, abbreviate: { [n] in n.abbreviate($0) }) }
    var zh: AlertFormatter { AlertFormatter(language: .zhHans, abbreviate: { [n] in n.abbreviate($0) }) }

    /// A review probe: a bundle named to read like a harmless request, then newlines and a
    /// right-to-left override that push the real path and the agent line out of a collapsed banner.
    /// (U+2215 looks like "/", which a file name cannot contain.)
    static let lure = "Terminal wants to read ~∕notes\n\n\n\n\u{202E}x"
    static let bundle = "/Users/alice/x/\(lure).app"
    static let key = "/Users/alice/WhoReadTestVault/ssh/id_ed25519"

    func testACraftedBundleNameCannotForgeOrHideLinesOfTheQuestion() throws {
        let h = try Harness(learningDays: 0)
        let reader = proc(700, AlertTextSanitizingTests.bundle + "/Contents/MacOS/r", argv: ["r"])
        h.fork(P.launchd, reader)
        let out = h.open(reader, AlertTextSanitizingTests.key)
        let alert = try XCTUnwrap(out.alerts.first?.alert)
        XCTAssertEqual(alert.responsible.kind, .app)
        XCTAssertEqual(alert.responsible.displayName, AlertTextSanitizingTests.lure, "the stored name stays exact")

        for f in [en, zh] {
            for text in [f.headline(alert), f.chainLine(alert.chain), f.line(alert), try XCTUnwrap(f.identityLine(alert))] {
                XCTAssertFalse(text.unicodeScalars.contains(where: DisplayText.isHidden), text)
                XCTAssertFalse(text.contains("\n"), text)
            }
        }
        let headline = en.headline(alert)
        XCTAssertTrue(headline.hasPrefix("Terminal wants to read ~∕notes\\u{a}\\u{a}\\u{a}\\u{a}\\u{202e}x read ~/WhoReadTestVault/ssh/id_ed25519"),
                      headline)
        // Real identity next to the made-up name: the bundle's real place, and nobody signed it.
        XCTAssertEqual(en.identityLine(alert),
                       "Program: ~/x/Terminal wants to read ~∕notes\\u{a}\\u{a}\\u{a}\\u{a}\\u{202e}x.app (not signed by an identified developer)")
        XCTAssertEqual(zh.identityLine(alert)?.hasSuffix("（没有已识别开发者的签名）"), true)
    }

    func testLongNamesAreCappedSoTheRealPathStaysInTheHeadline() throws {
        let name = "Terminal" + String(repeating: "\u{2015}", count: 300) + "x"
        let alert = Alert(id: 1, kind: .ask, createdAt: t0, updatedAt: t0, windowEndsAt: at(600),
                          responsible: ResponsibleEntity(kind: .binary, key: "bin:/tmp/x", displayName: name, path: "/tmp/x"),
                          categoryID: "test-vault", severity: .critical, count: 1, accesses: .read, firstPath: AlertTextSanitizingTests.key,
                          firstEventID: 1, lastEventID: 1, paths: [], chain: [], agentID: nil, ruleID: nil)
        let headline = en.headline(alert)
        XCTAssertLessThan(headline.count, 160, headline)
        XCTAssertTrue(headline.contains("…"), headline)
        XCTAssertTrue(headline.contains("~/WhoReadTestVault/ssh/id_ed25519"), headline)
        // Blank padding is shown as one space.
        var spaced = alert
        spaced.responsible.displayName = "Terminal" + String(repeating: " ", count: 300) + "x"
        XCTAssertEqual(en.headline(spaced), "Terminal x wants to read ~/WhoReadTestVault/ssh/id_ed25519: not allowed until you decide")
    }

    func testChainNamesAndCategoryNamesAreEscaped() {
        let chain = [ChainLink(pid: 1, name: "launchd", path: "/sbin/launchd"),
                     ChainLink(pid: 9, name: "node\r\u{1B}[2K", path: "/opt/homebrew/bin/node"),
                     ChainLink(pid: 10, name: "cat", path: "/bin/cat")]
        XCTAssertEqual(en.chainLine(chain), "Chain: launchd → node\\u{d}\\u{1b}[2K → cat")
        let deep = (0..<64).map { ChainLink(pid: Int32($0 + 2), name: String(repeating: "p", count: 64), path: "/x/\($0)") }
            + [ChainLink(pid: 99, name: "cat", path: "/bin/cat")]
        let line = en.chainLine(deep)
        XCTAssertLessThanOrEqual(line.unicodeScalars.count, DisplayText.chainLimit + "Chain: ".count)
        XCTAssertTrue(line.hasSuffix(" → cat"), "the leaf stays visible")

        let custom = AlertFormatter(language: .en, abbreviate: { $0 },
                                    categoryName: { _ in LocalizedText(en: "Keys\u{1B}[8m", zhHans: "密钥") })
        var alert = Alert(id: 1, kind: .criticalNonOwner, createdAt: t0, updatedAt: t0, windowEndsAt: at(600),
                          responsible: ResponsibleEntity(kind: .agent, key: "agent:claude-code", displayName: "Claude Code", agentID: "claude-code"),
                          categoryID: "test-vault", severity: .critical, count: 1, accesses: .read, firstPath: "/k\u{2028}x",
                          firstEventID: 1, lastEventID: 1, paths: [], chain: [], agentID: "claude-code", ruleID: nil)
        XCTAssertEqual(custom.headline(alert), "Claude Code read /k\\u{2028}x (Keys\\u{1b}[8m, not an expected owner)")
        XCTAssertNil(custom.identityLine(alert), "an AI agent is named from the agent catalog")
        alert.responsible = ResponsibleEntity(kind: .app, key: "app:/applications/zoom.us.app", displayName: "Zoom",
                                              path: "/Applications/zoom.us.app")
        XCTAssertEqual(custom.identityLine(alert), "Program: /Applications/zoom.us.app (signature not known)",
                       "the program is not in the stored chain")
    }

    func testSignerComesFromTheResponsibleProcessInTheChain() {
        func link(_ path: String, team: String? = nil, platform: Bool = false) -> ChainLink {
            ChainLink(pid: 5, name: "p", path: path, teamID: team, isPlatformBinary: platform)
        }
        let terminal = ResponsibleEntity(kind: .app, key: "app:/system/applications/utilities/terminal.app", displayName: "Terminal",
                                         path: "/System/Applications/Utilities/Terminal.app")
        let launchd = link("/sbin/launchd", platform: true)
        XCTAssertEqual(AlertFormatter.signer(of: terminal, chain: [launchd, link("/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", platform: true)]), .apple,
                       "an Apple app has no Team ID and is not 'unsigned'")
        let copy = ResponsibleEntity(kind: .app, key: "app:/users/alice/x/terminal.app", displayName: "Terminal",
                                     path: "/Users/alice/x/Terminal.app")
        XCTAssertEqual(AlertFormatter.signer(of: copy, chain: [launchd, link("/Users/alice/x/Terminal.app/Contents/MacOS/Terminal", platform: true)]),
                       .appleCopy, "a copied Apple binary keeps its platform flag, not its location")
        XCTAssertEqual(AlertFormatter.signer(of: copy, chain: [launchd, link("/Users/alice/x/Terminal.app/Contents/MacOS/Terminal")]), .unidentified)
        let zoom = ResponsibleEntity(kind: .app, key: "app:/applications/zoom.us.app", displayName: "Zoom", path: "/Applications/zoom.us.app")
        XCTAssertEqual(AlertFormatter.signer(of: zoom, chain: [link("/Applications/zoom.us.app/Contents/Frameworks/x", team: "BJ4HAAB9B3")]),
                       .team("BJ4HAAB9B3"))
        let bin = ResponsibleEntity(kind: .binary, key: "bin:/tmp/t", displayName: "t", path: "/tmp/t", cdhash: String(repeating: "a", count: 40))
        XCTAssertEqual(AlertFormatter.signer(of: bin, chain: []), .unidentified, "cdhash kept: no Team ID, not Apple's")
        XCTAssertEqual(AlertFormatter.signer(of: bin, chain: [link("/tmp/t", team: "T1")]), .team("T1"))
        XCTAssertNil(AlertFormatter.signer(of: ResponsibleEntity(kind: .agent, key: "agent:x", displayName: "X", path: "/x"), chain: []))
        XCTAssertEqual(en.signerName(.team("T\u{1B}")), "developer team T\\u{1b}")
        // Where it is, not a guess at how it got there (an Apple-signed tool can live outside the
        // system folders without being a copy).
        XCTAssertEqual(en.signerName(.appleCopy), "Apple-signed, outside the system folders")
    }
}
