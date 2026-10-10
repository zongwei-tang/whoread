import Foundation
import XCTest
@testable import WhoReadCore

final class SafeFileTests: XCTestCase {
    private var dir = ""

    override func setUpWithError() throws {
        let base = ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory()
        dir = (base as NSString).appendingPathComponent("whoread-safefile-\(UUID().uuidString.prefix(8))")
        XCTAssertEqual(mkdir(dir, 0o755), 0)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: dir)
    }

    private func path(_ name: String) -> String { (dir as NSString).appendingPathComponent(name) }

    private func mode(_ p: String) -> mode_t {
        var st = stat()
        XCTAssertEqual(lstat(p, &st), 0)
        return st.st_mode & 0o7777
    }

    private func entries() -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: dir).sorted()) ?? []
    }

    func testReplaceWritesContentWithTheExactModeWhateverTheUmask() throws {
        let old = umask(0o077)
        defer { umask(old) }
        try SafeFile.replace(path("a"), with: Data("one".utf8), mode: 0o644)
        XCTAssertEqual(try String(contentsOfFile: path("a"), encoding: .utf8), "one")
        XCTAssertEqual(mode(path("a")), 0o644)
        try SafeFile.replace(path("a"), with: Data("two".utf8), mode: 0o600)
        XCTAssertEqual(try String(contentsOfFile: path("a"), encoding: .utf8), "two")
        XCTAssertEqual(mode(path("a")), 0o600)
        XCTAssertEqual(entries(), ["a"], "no temporary file is left behind")
    }

    func testReplaceSwapsOutASymlinkInsteadOfWritingThroughIt() throws {
        let victim = path("victim")
        try SafeFile.replace(victim, with: Data("keep".utf8))
        XCTAssertEqual(symlink(victim, path("link")), 0)
        try SafeFile.replace(path("link"), with: Data("new".utf8))
        XCTAssertEqual(try String(contentsOfFile: victim, encoding: .utf8), "keep", "the link target is untouched")
        var st = stat()
        XCTAssertEqual(lstat(path("link"), &st), 0)
        XCTAssertEqual(st.st_mode & S_IFMT, S_IFREG, "the link itself was replaced by a regular file")
        XCTAssertEqual(try String(contentsOfFile: path("link"), encoding: .utf8), "new")
    }

    func testAFailedReplaceLeavesTheOldFileAndNoTemporaryFile() throws {
        try SafeFile.replace(path("a"), with: Data("old".utf8))
        // A directory at the target makes rename(2) fail after the temporary file was written.
        XCTAssertEqual(mkdir(path("d"), 0o755), 0)
        XCTAssertThrowsError(try SafeFile.replace(path("d"), with: Data("x".utf8)))
        XCTAssertEqual(try String(contentsOfFile: path("a"), encoding: .utf8), "old")
        XCTAssertEqual(entries(), ["a", "d"], "the temporary file is removed on failure")
    }

    func testReplaceRefusesAnUntrustedDirectory() throws {
        let me = geteuid()
        try SafeFile.replace(path("ok"), with: Data(), trustedDirectoryOwner: me)
        XCTAssertThrowsError(try SafeFile.replace(path("x"), with: Data(), trustedDirectoryOwner: me &+ 1), "wrong owner")
        XCTAssertEqual(chmod(dir, 0o777), 0)
        XCTAssertThrowsError(try SafeFile.replace(path("x"), with: Data(), trustedDirectoryOwner: me), "group/world writable")
        XCTAssertEqual(chmod(dir, 0o755), 0)
        let real = path("real")
        XCTAssertEqual(mkdir(real, 0o755), 0)
        XCTAssertEqual(symlink(real, path("dirlink")), 0)
        XCTAssertThrowsError(try SafeFile.replace(path("dirlink/x"), with: Data(), trustedDirectoryOwner: me), "symlinked directory")
        XCTAssertFalse(FileManager.default.fileExists(atPath: (real as NSString).appendingPathComponent("x")))
    }

    func testCreateNewNeverOpensAnExistingFileOrSymlink() throws {
        try SafeFile.replace(path("taken"), with: Data("x".utf8))
        XCTAssertThrowsError(try SafeFile.createNew(path("taken")))
        XCTAssertEqual(symlink(path("elsewhere"), path("dangling")), 0)
        XCTAssertThrowsError(try SafeFile.createNew(path("dangling")), "a dangling symlink is not followed")
        XCTAssertFalse(FileManager.default.fileExists(atPath: path("elsewhere")))
        let old = umask(0)
        defer { umask(old) }
        let h = try SafeFile.createNew(path("new"), mode: 0o600)
        try h.write(contentsOf: Data("hi".utf8))
        try h.close()
        XCTAssertEqual(mode(path("new")), 0o600)
        XCTAssertEqual(try String(contentsOfFile: path("new"), encoding: .utf8), "hi")
    }

    func testCreateIfAbsentLeavesExistingFilesAlone() throws {
        XCTAssertTrue(try SafeFile.createIfAbsent(path("db"), mode: 0o600))
        XCTAssertEqual(mode(path("db")), 0o600)
        try SafeFile.replace(path("db"), with: Data("data".utf8), mode: 0o600)
        XCTAssertFalse(try SafeFile.createIfAbsent(path("db"), with: Data("other".utf8)))
        XCTAssertEqual(try String(contentsOfFile: path("db"), encoding: .utf8), "data")
        XCTAssertEqual(symlink(path("target"), path("link")), 0)
        XCTAssertFalse(try SafeFile.createIfAbsent(path("link")), "a symlink counts as existing and is not followed")
        XCTAssertFalse(FileManager.default.fileExists(atPath: path("target")))
    }

    func testEnsureTrustedDirectoryCreatesAndChecks() throws {
        let sub = path("a/b/c")
        try SafeFile.ensureTrustedDirectory(sub, owner: geteuid(), mode: 0o700)
        XCTAssertEqual(mode(sub), 0o700)
        XCTAssertNoThrow(try SafeFile.checkTrustedDirectory(sub, owner: geteuid()))
        XCTAssertEqual(symlink(sub, path("l")), 0)
        XCTAssertThrowsError(try SafeFile.ensureTrustedDirectory(path("l"), owner: geteuid()))
    }
}
