import XCTest
@testable import WhoReadCore

final class PathNormalizerTests: XCTestCase {
    let n = PathNormalizer(homeDirectories: ["/Users/alice", "/Users/bob"])

    func testFirmlinkIsStripped() {
        XCTAssertEqual(n.normalize("/System/Volumes/Data/Users/alice/.ssh/id_rsa"), "/Users/alice/.ssh/id_rsa")
        XCTAssertEqual(n.normalize("/System/Volumes/Data"), "/")
        // Not a firmlink root: only the exact prefix component counts.
        XCTAssertEqual(n.normalize("/System/Volumes/DataX/a"), "/System/Volumes/DataX/a")
        XCTAssertEqual(n.matchKey("/system/volumes/data/Users/Alice/.SSH"), "/users/alice/.ssh")
    }

    func testRootAliases() {
        XCTAssertEqual(n.normalize("/tmp/x"), "/private/tmp/x")
        XCTAssertEqual(n.normalize("/var/folders/a"), "/private/var/folders/a")
        XCTAssertEqual(n.normalize("/etc"), "/private/etc")
        XCTAssertEqual(n.normalize("/tmpfoo"), "/tmpfoo")
        XCTAssertEqual(n.normalize("/private/tmp/x"), "/private/tmp/x")
    }

    func testUnicodeNFC() {
        let decomposed = "/Users/alice/Documents/Cafe\u{0301}/文件.txt"
        let composed = "/Users/alice/Documents/Caf\u{00E9}/文件.txt"
        XCTAssertNotEqual(Array(decomposed.unicodeScalars), Array(composed.unicodeScalars))
        XCTAssertEqual(Array(n.normalize(decomposed).unicodeScalars), Array(composed.unicodeScalars))
        XCTAssertEqual(n.matchKey(decomposed), n.matchKey(composed))
        // Hangul decomposed jamo compose too.
        XCTAssertEqual(n.normalize("/a/\u{1100}\u{1161}"), "/a/\u{AC00}")
    }

    func testCaseFolding() {
        XCTAssertEqual(n.matchKey("/Users/Alice/Library/KEYCHAINS/login.keychain-db"), "/users/alice/library/keychains/login.keychain-db")
        XCTAssertEqual(n.matchKey("/Users/alice/ÉCOLE"), "/users/alice/école")
        // Display form keeps case.
        XCTAssertEqual(n.normalize("/Users/Alice/X"), "/Users/Alice/X")
    }

    func testLexicalCleanup() {
        XCTAssertEqual(n.normalize("/Users//alice/./.ssh/../.aws/credentials"), "/Users/alice/.aws/credentials")
        XCTAssertEqual(n.normalize("/Users/alice/.ssh/"), "/Users/alice/.ssh")
        XCTAssertEqual(n.normalize("/../.."), "/")
        XCTAssertEqual(n.normalize("/"), "/")
    }

    func testTildeExpansionForEveryHome() {
        XCTAssertEqual(n.expand("~/.ssh/"), ["/Users/alice/.ssh", "/Users/bob/.ssh"])
        XCTAssertEqual(n.expand("~"), ["/Users/alice", "/Users/bob"])
        XCTAssertEqual(n.expand("/Volumes/"), ["/Volumes"])
        XCTAssertEqual(n.expand("relative/path"), [])
    }

    func testAbbreviate() {
        XCTAssertEqual(n.abbreviate("/Users/alice/.ssh/id_ed25519"), "~/.ssh/id_ed25519")
        XCTAssertEqual(n.abbreviate("/Users/alice"), "~")
        XCTAssertEqual(n.abbreviate("/Users/alicex/a"), "/Users/alicex/a")
        XCTAssertEqual(n.abbreviate("/Volumes/USB/a"), "/Volumes/USB/a")
    }

    func testLongPathsSurvive() {
        let long = "/Users/alice/" + String(repeating: "deep/", count: 4000) + "file"
        XCTAssertGreaterThan(long.utf8.count, 16_000)
        XCTAssertEqual(n.normalize(long), long)
        XCTAssertEqual(n.normalize("/System/Volumes/Data" + long), long)
    }
}

final class GlobTests: XCTestCase {
    func testStarStopsAtSlash() {
        XCTAssertTrue(Glob("id_*").matches("id_ed25519"))
        XCTAssertTrue(Glob("*.pub").matches("id_rsa.pub"))
        XCTAssertFalse(Glob("*.pub").matches("dir/id_rsa.pub"))
        XCTAssertTrue(Glob("/usr/*/ssh").matches("/usr/bin/ssh"))
        XCTAssertFalse(Glob("/usr/*/ssh").matches("/usr/local/bin/ssh"))
    }

    func testDoubleStar() {
        XCTAssertTrue(Glob("/System/**/mds").matches("/System/Library/Frameworks/CoreServices.framework/Versions/A/Support/mds"))
        XCTAssertTrue(Glob("/bin/**/zsh").matches("/bin/zsh"))
        XCTAssertFalse(Glob("/System/**/mds").matches("/System/Library/mds_stores"))
        XCTAssertTrue(Glob("**/node_modules/**").matches("web/node_modules/x/.env"))
        XCTAssertTrue(Glob("**/bin/claude").matches("/opt/homebrew/bin/claude"))
    }

    func testQuestionAndCase() {
        XCTAssertTrue(Glob("known_hosts?").matches("known_hosts2"))
        XCTAssertFalse(Glob("known_hosts?").matches("known_hosts"))
        XCTAssertTrue(Glob("COOKIES").matches("Cookies"))
        XCTAssertTrue(Glob("Login Data*").matches("Login Data For Account"))
    }

    func testCodableRoundTrip() throws {
        let g = Glob("**/*.pem")
        let data = try JSONEncoder().encode([g])
        XCTAssertEqual(String(data: data, encoding: .utf8), "[\"**\\/*.pem\"]")
        XCTAssertEqual(try JSONDecoder().decode([Glob].self, from: data), [g])
    }
}
