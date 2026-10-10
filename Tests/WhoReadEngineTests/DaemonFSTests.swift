import Foundation
import XCTest
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

// Regression tests for the daemon's own files: the data directory (macos-4), the log file
// (macos-3), export files (privacy-4) and links in dotfile directories (files-9).

private func fsConfig(_ dir: TempDir) -> DaemonConfiguration {
    var config = baseConfig(dir)
    config.resolveOwners = false
    return config
}

private func makeCore(_ config: DaemonConfiguration) throws -> DaemonCore {
    try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: true) })
}

private func exists(_ path: String) -> Bool {
    var st = stat()
    return lstat(path, &st) == 0
}

private func mode(_ path: String) -> mode_t {
    var st = stat()
    guard lstat(path, &st) == 0 else { return 0 }
    return st.st_mode & 0o7777
}

/// A uid that is not the test process's (the daemon's user in production is root).
private var someoneElse: uid_t { geteuid() == 0 ? 1 : 0 }

/// `chmod +a ENTRY PATH`: an access control entry, which mode bits do not show (macOS only).
private func addACL(_ entry: String, _ path: String) throws {
    try chmodACL(["+a", entry, path])
}

private func chmodACL(_ arguments: [String]) throws {
    #if canImport(Darwin)
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/chmod")
    p.arguments = arguments
    try p.run()
    p.waitUntilExit()
    XCTAssertEqual(p.terminationStatus, 0, "chmod \(arguments)")
    #else
    throw XCTSkip("no extended ACLs here")
    #endif
}

// MARK: - Data directory (macos-4)

final class DataDirectoryTrustTests: XCTestCase {
    private func assertRefused(_ config: DaemonConfiguration, mentioning text: String,
                               file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try makeCore(config), file: file, line: line) { error in
            XCTAssertTrue("\(error)".contains(text), "\(error)", file: file, line: line)
        }
        XCTAssertThrowsError(try Daemon.acquireLock(config), file: file, line: line) { error in
            XCTAssertTrue("\(error)".contains(text), "\(error)", file: file, line: line)
        }
    }

    // macos-4: an existing directory that others can write was adopted as is (createDirectory accepts it).
    func testGroupOrWorldWritableDataDirectoryIsRefused() throws {
        let dir = TempDir()
        let config = fsConfig(dir)
        XCTAssertEqual(mkdir(config.dataDirectory, 0o755), 0)
        XCTAssertEqual(chmod(config.dataDirectory, 0o777), 0)
        assertRefused(config, mentioning: "writable by group or others")
        XCTAssertFalse(exists(config.databasePath), "nothing is created in a directory others control")
        XCTAssertFalse(exists(config.lockPath))
        XCTAssertEqual(mode(config.dataDirectory), 0o777, "the daemon does not quietly adopt it either")
    }

    func testDataDirectoryThatIsASymlinkIsRefused() throws {
        let dir = TempDir()
        let config = fsConfig(dir)
        let elsewhere = dir.path("elsewhere")
        XCTAssertEqual(mkdir(elsewhere, 0o755), 0)
        XCTAssertEqual(symlink(elsewhere, config.dataDirectory), 0)
        assertRefused(config, mentioning: "symbolic link")
        // A trailing slash makes open(2) follow the link despite O_NOFOLLOW.
        var slash = config
        slash.dataDirectory += "/"
        assertRefused(slash, mentioning: "symbolic link")
        XCTAssertFalse(exists(elsewhere + "/whoread.sqlite"))
        XCTAssertFalse(exists(elsewhere + "/daemon.lock"))
    }

    // Root in production: a directory a user made (before install, or after uninstall --purge) is refused.
    func testDataDirectoryNotOwnedByTheDaemonUserIsRefused() throws {
        let dir = TempDir()
        var config = fsConfig(dir)
        XCTAssertEqual(mkdir(config.dataDirectory, 0o755), 0)
        config.dataDirectoryOwner = someoneElse
        assertRefused(config, mentioning: "is owned by uid \(geteuid())")
        XCTAssertFalse(exists(config.databasePath))
        // Missing: created, then refused all the same (it cannot be given away), never looping.
        let other = TempDir()
        var fresh = fsConfig(other)
        fresh.dataDirectoryOwner = someoneElse
        assertRefused(fresh, mentioning: "is owned by uid \(geteuid())")
    }

    func testMissingDataDirectoryIsCreatedWithItsExactMode() throws {
        let dir = TempDir()
        let config = fsConfig(dir)
        let old = umask(0o077)
        defer { umask(old) }
        _ = try makeCore(config)
        XCTAssertEqual(mode(config.dataDirectory), 0o755, "the CLI and the app read mach-service from it")
        XCTAssertTrue(exists(config.databasePath))
    }

    // Variant: an ancestor others can write lets them rename the directory away and put their own in its place.
    func testDirectoryOnTheWayThatOthersCanWriteIsRefused() throws {
        let dir = TempDir()
        var config = fsConfig(dir)
        let shared = dir.path("shared")
        XCTAssertEqual(mkdir(shared, 0o755), 0)
        XCTAssertEqual(chmod(shared, 0o777), 0)
        config.dataDirectory = shared + "/data"
        config.killSwitchPath = nil
        assertRefused(config, mentioning: shared)
        // A sticky directory (like /private/tmp) lets others add entries but not move ours.
        XCTAssertEqual(chmod(shared, 0o1777), 0)
        _ = try makeCore(config)
    }

    // Variant: the ancestor check follows links on the way (here a link to an unsafe directory).
    func testLinkOnTheWayIsFollowedForTheAncestorCheck() throws {
        let dir = TempDir()
        var config = fsConfig(dir)
        let shared = dir.path("shared")
        XCTAssertEqual(mkdir(shared, 0o777), 0)
        XCTAssertEqual(chmod(shared, 0o777), 0)
        XCTAssertEqual(symlink("shared", dir.path("via")), 0)
        config.dataDirectory = dir.path("via/data")
        config.killSwitchPath = nil
        assertRefused(config, mentioning: shared)
    }

    // Variant: a kill switch configured outside the data directory needs the same protection.
    func testKillSwitchOutsideTheDataDirectoryNeedsATrustedDirectory() throws {
        let dir = TempDir()
        var config = fsConfig(dir)
        let open = dir.path("open")
        XCTAssertEqual(mkdir(open, 0o755), 0)
        XCTAssertEqual(chmod(open, 0o777), 0)
        config.killSwitchPath = open + "/disable-enforcement"
        assertRefused(config, mentioning: "kill switch")
        // A missing one is created for the daemon's user.
        config.killSwitchPath = dir.path("switch/disable-enforcement")
        _ = try makeCore(config)
        XCTAssertEqual(mode(dir.path("switch")), 0o755)
    }

    // Variant: the lock is never opened through a link.
    func testLockFileLinkIsNotFollowed() throws {
        let dir = TempDir()
        let config = fsConfig(dir)
        XCTAssertEqual(mkdir(config.dataDirectory, 0o755), 0)
        let victim = dir.path("victim")
        XCTAssertEqual(symlink(victim, config.lockPath), 0)
        XCTAssertThrowsError(try Daemon.acquireLock(config))
        XCTAssertFalse(exists(victim))
    }

    // Variant: files written while running (catalog copy, mach-service marker) check the directory again.
    func testCatalogIsNotWrittenIntoADataDirectoryOpenedUpLater() throws {
        let dir = TempDir()
        let config = fsConfig(dir)
        let core = try makeCore(config)
        var catalog = core.data.catalog
        catalog.categories[0].enabled.toggle()
        XCTAssertEqual(chmod(config.dataDirectory, 0o777), 0)
        XCTAssertThrowsError(try core.update(catalog: catalog, peer: .inProcess))
        XCTAssertFalse(exists(config.userCatalogPath))
        XCTAssertEqual(chmod(config.dataDirectory, 0o755), 0)
        // Opened up by an ACL instead of mode bits.
        try addACL("everyone allow add_file,delete_child", config.dataDirectory)
        XCTAssertThrowsError(try core.update(catalog: catalog, peer: .inProcess))
        XCTAssertFalse(exists(config.userCatalogPath))
        try chmodACL(["-N", config.dataDirectory])
        XCTAssertNoThrow(try core.update(catalog: catalog, peer: .inProcess))
        XCTAssertTrue(exists(config.userCatalogPath))
    }

    // macos-4 variant: a 0755 directory whose ACL lets others add, remove or rename entries passed the
    // mode-bit check (`chmod go-w` keeps an ACL, and so does `chown -R` after a planted directory).
    func testDataDirectoryWithAnACLThatLetsOthersChangeItIsRefused() throws {
        let dir = TempDir()
        let config = fsConfig(dir)
        XCTAssertEqual(mkdir(config.dataDirectory, 0o755), 0)
        try addACL("everyone allow add_file,add_subdirectory,delete_child", config.dataDirectory)
        assertRefused(config, mentioning: "access control list")
        XCTAssertFalse(exists(config.databasePath))
        XCTAssertFalse(exists(config.lockPath))
        // A deny entry only takes rights away (homes carry `everyone deny delete`).
        let other = TempDir()
        let fine = fsConfig(other)
        XCTAssertEqual(mkdir(fine.dataDirectory, 0o755), 0)
        try addACL("everyone deny delete", fine.dataDirectory)
        _ = try makeCore(fine)
        // Every user's history: an entry new files inherit (the database is 0600) is refused too.
        let third = TempDir()
        let leaky = fsConfig(third)
        XCTAssertEqual(mkdir(leaky.dataDirectory, 0o755), 0)
        try addACL("everyone allow read,file_inherit", leaky.dataDirectory)
        assertRefused(leaky, mentioning: "lets others in")
        XCTAssertFalse(exists(leaky.databasePath))
    }

    // An ACL on a directory on the way lets others rename the data directory away, sticky or not
    // (delete_child granted by an ACL is not limited by the sticky bit).
    func testDirectoryOnTheWayWithAnACLThatLetsOthersChangeItIsRefused() throws {
        let dir = TempDir()
        var config = fsConfig(dir)
        let shared = dir.path("shared")
        XCTAssertEqual(mkdir(shared, 0o755), 0)
        try addACL("everyone allow delete_child", shared)
        config.dataDirectory = shared + "/data"
        config.killSwitchPath = nil
        assertRefused(config, mentioning: shared)
        let sticky = dir.path("sticky")
        XCTAssertEqual(mkdir(sticky, 0o755), 0)
        XCTAssertEqual(chmod(sticky, 0o1777), 0)
        try addACL("everyone allow delete_child", sticky)
        config.dataDirectory = sticky + "/data"
        assertRefused(config, mentioning: sticky)
    }

    // macos-4 variant: a directory someone else controlled before it was fixed (the refusal's advice:
    // chown, chmod go-w, chmod -N) may still hold what they left. State files are opened by path.
    func testWhatOthersLeftInTheDataDirectoryIsRefused() throws {
        let dir = TempDir()
        let config = fsConfig(dir)
        XCTAssertEqual(mkdir(config.dataDirectory, 0o755), 0)
        // A planted link: SQLite or the catalog read would follow it to a file its maker controls.
        let theirs = dir.path("theirs.sqlite")
        XCTAssertEqual(symlink(theirs, config.databasePath), 0)
        assertRefused(config, mentioning: "whoread.sqlite is a symbolic link")
        XCTAssertFalse(exists(theirs))
        XCTAssertEqual(unlink(config.databasePath), 0)
        // A second name for a file elsewhere.
        let elsewhere = dir.path("elsewhere")
        XCTAssertTrue(touch(elsewhere))
        XCTAssertEqual(link(elsewhere, config.userCatalogPath), 0)
        assertRefused(config, mentioning: "catalog.json has 2 hard links")
        XCTAssertEqual(unlink(config.userCatalogPath), 0)
        // A file or a folder others can still change (catalog defaults live in defaults/).
        XCTAssertTrue(touch(config.userCatalogPath))
        try addACL("everyone allow write,append", config.userCatalogPath)
        assertRefused(config, mentioning: "catalog.json has an access control list")
        XCTAssertEqual(unlink(config.userCatalogPath), 0)
        XCTAssertTrue(touch(config.databasePath))
        try addACL("everyone allow read", config.databasePath)
        assertRefused(config, mentioning: "whoread.sqlite has an access control list")
        XCTAssertEqual(unlink(config.databasePath), 0)
        let defaults = config.dataDirectory + "/defaults"
        XCTAssertEqual(mkdir(defaults, 0o755), 0)
        XCTAssertEqual(chmod(defaults, 0o777), 0)
        assertRefused(config, mentioning: "defaults is writable by group or others")
        XCTAssertEqual(chmod(defaults, 0o755), 0)
        XCTAssertTrue(touch(defaults + "/catalog.json"))
        _ = try makeCore(config)
    }

    func testTrustedDataDirectoryStillStarts() throws {
        let dir = TempDir()
        let config = fsConfig(dir)
        let fd = try Daemon.acquireLock(config)
        defer { close(fd) }
        XCTAssertGreaterThanOrEqual(fd, 0)
        _ = try makeCore(config)
    }
}

// MARK: - Log file (macos-3)

final class PrivateLogFileTests: XCTestCase {
    private func put(_ fd: Int32, _ s: String) {
        let bytes = Array(s.utf8)
        XCTAssertEqual(write(fd, bytes, bytes.count), bytes.count)
    }

    private func contents(_ path: String) -> String? {
        FileManager.default.contents(atPath: path).map { String(decoding: $0, as: UTF8.self) }
    }

    func testFreshLogDirectoryAndFileAreOwnerOnly() throws {
        let dir = TempDir()
        let logs = dir.path("Logs")
        let old = umask(0)
        defer { umask(old) }
        let log = try Log.openPrivateLogFile(directory: logs, name: "extension.log")
        put(log.descriptor, "one\n")
        close(log.descriptor)
        XCTAssertEqual(mode(logs), 0o700)
        XCTAssertEqual(mode(logs + "/extension.log"), 0o600)
        XCTAssertEqual(log.movedAside, [])
        // Opened again: appended, not truncated.
        let again = try Log.openPrivateLogFile(directory: logs, name: "extension.log")
        put(again.descriptor, "two\n")
        close(again.descriptor)
        XCTAssertEqual(contents(logs + "/extension.log"), "one\ntwo\n")
    }

    // macos-3: chmod(dir, 0700) and open(O_CREAT) followed a planted link as root.
    func testLinkedLogDirectoryIsMovedAsideNotFollowed() throws {
        let dir = TempDir()
        let logs = dir.path("Logs")
        let victim = dir.path("victim")
        XCTAssertEqual(mkdir(victim, 0o755), 0)
        XCTAssertEqual(chmod(victim, 0o755), 0)
        XCTAssertEqual(symlink(victim, logs), 0)
        let log = try Log.openPrivateLogFile(directory: logs, name: "extension.log")
        put(log.descriptor, "line\n")
        close(log.descriptor)
        XCTAssertEqual(mode(victim), 0o755, "the link's target was not chmodded")
        XCTAssertFalse(exists(victim + "/extension.log"), "nor written into")
        var st = stat()
        XCTAssertEqual(lstat(logs, &st), 0)
        XCTAssertEqual(st.st_mode & S_IFMT, S_IFDIR)
        XCTAssertEqual(log.movedAside.count, 1)
        let aside = try XCTUnwrap(try FileManager.default.contentsOfDirectory(atPath: dir.url.path).first { $0.hasPrefix("Logs.untrusted-") })
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: dir.path(aside)), victim)
        XCTAssertTrue(log.movedAside[0].contains(dir.path(aside)), log.movedAside[0])
    }

    func testLogDirectoryOthersCanWriteIsMovedAside() throws {
        let dir = TempDir()
        let logs = dir.path("Logs")
        XCTAssertEqual(mkdir(logs, 0o777), 0)
        XCTAssertEqual(chmod(logs, 0o777), 0)
        XCTAssertTrue(touch(logs + "/planted"))
        let log = try Log.openPrivateLogFile(directory: logs, name: "extension.log")
        close(log.descriptor)
        XCTAssertEqual(mode(logs), 0o700)
        XCTAssertFalse(exists(logs + "/planted"), "nothing of the old directory is used")
        XCTAssertEqual(log.movedAside.count, 1)
    }

    // A directory the daemon's user does not own (root in production) is never used; no endless renaming.
    func testLogDirectoryOfAnotherUserFailsClosed() throws {
        let dir = TempDir()
        let logs = dir.path("Logs")
        XCTAssertEqual(mkdir(logs, 0o700), 0)
        XCTAssertThrowsError(try Log.openPrivateLogFile(directory: logs, name: "extension.log", owner: someoneElse))
        let entries = try FileManager.default.contentsOfDirectory(atPath: dir.url.path)
        XCTAssertLessThanOrEqual(entries.filter { $0.hasPrefix("Logs") }.count, 2, "\(entries)")
        XCTAssertFalse(exists(logs + "/extension.log"))
    }

    func testLogFileLinkIsNotFollowed() throws {
        let dir = TempDir()
        let logs = dir.path("Logs")
        XCTAssertEqual(mkdir(logs, 0o700), 0)
        let victim = dir.path("victim")
        XCTAssertTrue(touch(victim, Data("keep\n".utf8)))
        XCTAssertEqual(chmod(victim, 0o644), 0)
        XCTAssertEqual(symlink(victim, logs + "/extension.log"), 0)
        let log = try Log.openPrivateLogFile(directory: logs, name: "extension.log")
        put(log.descriptor, "line\n")
        close(log.descriptor)
        XCTAssertEqual(contents(victim), "keep\n")
        XCTAssertEqual(mode(victim), 0o644)
        XCTAssertEqual(contents(logs + "/extension.log"), "line\n")
        XCTAssertEqual(log.movedAside.count, 1)
    }

    // A hard link to another file passes an owner check (same inode) but has a link count above 1.
    func testHardLinkedLogFileIsNotAppendedTo() throws {
        let dir = TempDir()
        let logs = dir.path("Logs")
        XCTAssertEqual(mkdir(logs, 0o700), 0)
        let victim = dir.path("victim")
        XCTAssertTrue(touch(victim, Data("keep\n".utf8)))
        XCTAssertEqual(link(victim, logs + "/extension.log"), 0)
        let log = try Log.openPrivateLogFile(directory: logs, name: "extension.log")
        put(log.descriptor, "line\n")
        close(log.descriptor)
        XCTAssertEqual(contents(victim), "keep\n")
        XCTAssertEqual(contents(logs + "/extension.log"), "line\n")
    }

    // macos-3 variant: fchmod(0700/0600) keeps an ACL, so `everyone allow list,search,read` (left by
    // whoever made the directory before it was chowned to root) would keep the log readable by all.
    func testLogDirectoryOrFileWithAnACLIsMovedAside() throws {
        let dir = TempDir()
        let logs = dir.path("Logs")
        XCTAssertEqual(mkdir(logs, 0o700), 0)
        try addACL("everyone allow list,search,read", logs)
        let log = try Log.openPrivateLogFile(directory: logs, name: "extension.log")
        close(log.descriptor)
        XCTAssertEqual(log.movedAside.count, 1, "\(log.movedAside)")
        XCTAssertFalse(SafeFile.aclAllows(path: logs, changing: false), "a fresh directory")

        try addACL("everyone allow read", logs + "/extension.log")
        let again = try Log.openPrivateLogFile(directory: logs, name: "extension.log")
        close(again.descriptor)
        XCTAssertEqual(again.movedAside.count, 1, "\(again.movedAside)")
        XCTAssertFalse(SafeFile.aclAllows(path: logs + "/extension.log", changing: false), "a fresh file")
        // A deny entry is no reason to move anything.
        try addACL("everyone deny delete", logs)
        let third = try Log.openPrivateLogFile(directory: logs, name: "extension.log")
        close(third.descriptor)
        XCTAssertEqual(third.movedAside, [])
    }

    func testExistingLogFileBecomesOwnerOnly() throws {
        let dir = TempDir()
        let logs = dir.path("Logs")
        XCTAssertEqual(mkdir(logs, 0o755), 0)
        XCTAssertTrue(touch(logs + "/extension.log", Data("old\n".utf8)))
        XCTAssertEqual(chmod(logs + "/extension.log", 0o644), 0)
        let log = try Log.openPrivateLogFile(directory: logs, name: "extension.log")
        put(log.descriptor, "new\n")
        close(log.descriptor)
        XCTAssertEqual(mode(logs), 0o700)
        XCTAssertEqual(mode(logs + "/extension.log"), 0o600)
        XCTAssertEqual(contents(logs + "/extension.log"), "old\nnew\n")
        XCTAssertEqual(log.movedAside, [])
    }

    // Variant (dev daemon): launchd opens whoreadd.log itself; the daemon reports one others can read.
    func testLogDescriptorProblems() throws {
        let dir = TempDir()
        let path = dir.path("whoreadd.log")
        XCTAssertTrue(touch(path))
        XCTAssertEqual(chmod(path, 0o600), 0)
        var fd = open(path, O_WRONLY | O_APPEND)
        XCTAssertNil(Log.privateLogProblem(descriptor: fd, owner: geteuid()))
        XCTAssertNotNil(Log.privateLogProblem(descriptor: fd, owner: someoneElse))
        XCTAssertEqual(chmod(path, 0o644), 0)
        XCTAssertNotNil(Log.privateLogProblem(descriptor: fd, owner: geteuid()))
        XCTAssertEqual(chmod(path, 0o600), 0)
        XCTAssertEqual(link(path, dir.path("other")), 0)
        XCTAssertNotNil(Log.privateLogProblem(descriptor: fd, owner: geteuid()))
        close(fd)
        // Not a file (a terminal, a pipe, /dev/null): nothing to say.
        fd = open("/dev/null", O_WRONLY)
        XCTAssertNil(Log.privateLogProblem(descriptor: fd, owner: someoneElse))
        close(fd)
    }
}

// MARK: - Export files (privacy-4)

final class StagedFileTests: XCTestCase {
    private func contents(_ path: String) -> String? {
        FileManager.default.contents(atPath: path).map { String(decoding: $0, as: UTF8.self) }
    }

    // privacy-4: the export (every user's history) followed the umask (0644 in a staff-readable home).
    func testPartialAndFinalFileAreOwnerOnlyWhateverTheUmask() throws {
        let dir = TempDir()
        let path = dir.path("out.csv")
        let old = umask(0)
        defer { umask(old) }
        let staged = try StagedFile(path: path)
        XCTAssertEqual(mode(path + ".partial"), 0o600)
        staged.handle.write(Data("a,b\n".utf8))
        try staged.commit()
        XCTAssertEqual(mode(path), 0o600)
        XCTAssertEqual(contents(path), "a,b\n")
        XCTAssertFalse(exists(path + ".partial"))
        // An existing export is replaced (a regular file of the user's).
        let again = try StagedFile(path: path)
        again.handle.write(Data("c\n".utf8))
        try again.commit()
        XCTAssertEqual(contents(path), "c\n")
    }

    // privacy-4 variant: 0600 is not owner-only when the file inherits the folder's ACL entries.
    func testExportDoesNotInheritTheFoldersACL() throws {
        let dir = TempDir()
        try addACL("everyone allow read,file_inherit", dir.url.path)
        let path = dir.path("out.csv")
        let staged = try StagedFile(path: path)
        XCTAssertFalse(SafeFile.aclAllows(path: path + ".partial", changing: false))
        staged.handle.write(Data("a\n".utf8))
        try staged.commit()
        XCTAssertEqual(mode(path), 0o600)
        XCTAssertFalse(SafeFile.aclAllows(path: path, changing: false), "nobody else may read the export")
    }

    // A link at the output path is refused, not replaced (it may be the user's own, or planted).
    func testOutputPathThatIsALinkIsRefused() throws {
        let dir = TempDir()
        let path = dir.path("out.csv")
        let victim = dir.path("victim")
        XCTAssertTrue(touch(victim, Data("keep\n".utf8)))
        XCTAssertEqual(symlink(victim, path), 0)
        XCTAssertThrowsError(try StagedFile(path: path)) { XCTAssertTrue("\($0)".contains("symbolic link"), "\($0)") }
        XCTAssertEqual(contents(victim), "keep\n")
        XCTAssertFalse(exists(path + ".partial"))
        // A dangling one too: the export must not create its target.
        let dangling = dir.path("dangling.csv")
        XCTAssertEqual(symlink(dir.path("created-by-root"), dangling), 0)
        XCTAssertThrowsError(try StagedFile(path: dangling))
        XCTAssertFalse(exists(dir.path("created-by-root")))
    }

    func testOutputPathThatIsADirectoryIsRefused() throws {
        let dir = TempDir()
        XCTAssertEqual(mkdir(dir.path("out"), 0o755), 0)
        XCTAssertThrowsError(try StagedFile(path: dir.path("out")))
        XCTAssertThrowsError(try StagedFile(path: dir.url.path + "/x/"))
    }

    // Created with O_EXCL|O_NOFOLLOW: a leftover or planted .partial (file or link) is never written.
    func testExistingPartialIsNeverWritten() throws {
        let dir = TempDir()
        let path = dir.path("out.csv")
        XCTAssertTrue(touch(path + ".partial", Data("leftover\n".utf8)))
        XCTAssertThrowsError(try StagedFile(path: path)) { XCTAssertTrue("\($0)".contains("leftover"), "\($0)") }
        XCTAssertEqual(contents(path + ".partial"), "leftover\n")
        XCTAssertEqual(unlink(path + ".partial"), 0)
        let victim = dir.path("victim")
        XCTAssertTrue(touch(victim, Data("keep\n".utf8)))
        XCTAssertEqual(symlink(victim, path + ".partial"), 0)
        XCTAssertThrowsError(try StagedFile(path: path))
        XCTAssertEqual(contents(victim), "keep\n")
    }

    // The directory is pinned: swapping it for a link while the export runs (`sudo whoread export`
    // into a folder an agent can write) does not move the rename somewhere else.
    func testDirectorySwappedForALinkKeepsTheRenameInTheOriginalDirectory() throws {
        let dir = TempDir()
        let a = dir.path("a"), b = dir.path("b")
        XCTAssertEqual(mkdir(a, 0o755), 0)
        XCTAssertEqual(mkdir(b, 0o755), 0)
        let staged = try StagedFile(path: a + "/out.csv")
        staged.handle.write(Data("x\n".utf8))
        XCTAssertEqual(rename(a, dir.path("a-moved")), 0)
        XCTAssertEqual(symlink(b, a), 0)
        try staged.commit()
        XCTAssertEqual(contents(dir.path("a-moved/out.csv")), "x\n")
        XCTAssertFalse(exists(b + "/out.csv"))
    }

    // Only the file this process wrote is renamed into place.
    func testReplacedPartialIsNotRenamedIntoPlace() throws {
        let dir = TempDir()
        let path = dir.path("out.csv")
        let staged = try StagedFile(path: path)
        staged.handle.write(Data("export\n".utf8))
        XCTAssertEqual(unlink(path + ".partial"), 0)
        XCTAssertTrue(touch(path + ".partial", Data("planted\n".utf8)))
        XCTAssertThrowsError(try staged.commit())
        XCTAssertFalse(exists(path))
        XCTAssertEqual(contents(path + ".partial"), "planted\n")
    }

    func testAbandonRemovesOnlyItsOwnPartial() throws {
        let dir = TempDir()
        let path = dir.path("out.csv")
        let staged = try StagedFile(path: path)
        staged.abandon()
        XCTAssertFalse(exists(path + ".partial"))
        let other = try StagedFile(path: path)
        XCTAssertEqual(unlink(path + ".partial"), 0)
        XCTAssertTrue(touch(path + ".partial", Data("planted\n".utf8)))
        other.abandon()
        XCTAssertEqual(contents(path + ".partial"), "planted\n")
    }

    // `sudo whoread export --output ~/x.csv`: the user who ran sudo gets the file in their own folder.
    func testOwnerOfAnExportMadeWithSudo() {
        let env = ["SUDO_UID": "501", "SUDO_GID": "20"]
        XCTAssertEqual(StagedFile.owner(euid: 0, environment: env, directoryOwner: 501), .init(uid: 501, gid: 20))
        XCTAssertNil(StagedFile.owner(euid: 0, environment: env, directoryOwner: 0), "a root-owned folder keeps a root-owned file")
        XCTAssertNil(StagedFile.owner(euid: 0, environment: env, directoryOwner: 502), "someone else's folder")
        XCTAssertNil(StagedFile.owner(euid: 501, environment: env, directoryOwner: 501), "not root: nothing to give away")
        XCTAssertNil(StagedFile.owner(euid: 0, environment: [:], directoryOwner: 501), "a root shell, not sudo")
        XCTAssertNil(StagedFile.owner(euid: 0, environment: ["SUDO_UID": "0"], directoryOwner: 0))
        XCTAssertNil(StagedFile.owner(euid: 0, environment: ["SUDO_UID": "x"], directoryOwner: 501))
        XCTAssertEqual(StagedFile.owner(euid: 0, environment: ["SUDO_UID": "501"], directoryOwner: 501),
                       .init(uid: 501, gid: gid_t.max), "no SUDO_GID: the group is left as is")
    }
}

// MARK: - Links in dotfile directories (files-9)

final class LinkRediscoveryTests: XCTestCase {
    private var homes: [String] = []

    override func tearDown() {
        homes.forEach { try? FileManager.default.removeItem(atPath: $0) }
        homes.removeAll()
        super.tearDown()
    }

    /// A home outside /tmp (the normalizer maps /tmp to /private/tmp) with a dotfiles folder.
    private func makeHome() throws -> String {
        let home = repoRoot.appendingPathComponent(".build/fs-home-\(UUID().uuidString.prefix(8))").path
        homes.append(home)
        for d in ["/dotfiles/azure", "/dotfiles/git", "/.azure", "/.config/git"] {
            try FileManager.default.createDirectory(atPath: home + d, withIntermediateDirectories: true)
        }
        return home
    }

    private func linkCore(home: String, delay: TimeInterval = 0.05, fullWalkInterval: TimeInterval = 30) throws -> (DaemonCore, TempDir) {
        let dir = TempDir()
        var config = fsConfig(dir)
        config.homeDirectories = [home]
        config.linkRediscoveryDelay = delay
        config.linkFullWalkInterval = fullWalkInterval
        return (try makeCore(config), dir)
    }

    private func real(_ path: String) -> String { RealpathSymlinkResolver().resolve(path) ?? path }

    private func operation(_ core: DaemonCore, _ op: FileOperation, _ targets: [FileTarget]) {
        let p = proc(700, "/opt/homebrew/bin/stow")
        core.eventSink.receive(.file(FileActivity(time: Date(), operation: op, process: p, targets: targets)), context: .monitorOnly)
    }

    // files-9: `aws configure`-style writes through a dangling link create the file at the link's
    // target, which ES reports; the link was skipped until the target existed and rediscovery ran.
    func testDanglingLinkTargetsAreMonitoredBeforeTheyExist() throws {
        let home = try makeHome()
        XCTAssertEqual(symlink(home + "/dotfiles/azure/accessTokens.json", home + "/.azure/accessTokens.json"), 0)
        XCTAssertEqual(symlink("../dotfiles/azure/config", home + "/.azure/config"), 0)
        // A catalog path that is itself a dangling link.
        XCTAssertEqual(symlink("../../dotfiles/git/credentials", home + "/.config/git/credentials"), 0)
        let (core, _) = try linkCore(home: home)
        let c = core.analyzer.classifier
        let dotfiles = real(home + "/dotfiles")
        XCTAssertEqual(c.classify(dotfiles + "/azure/accessTokens.json")?.categoryID, "azure")
        XCTAssertEqual(c.classify(dotfiles + "/azure/config")?.categoryID, "azure")
        XCTAssertEqual(c.classify(dotfiles + "/git/credentials")?.categoryID, "git-credentials")
        XCTAssertTrue(c.mutePaths.contains(dotfiles + "/azure/accessTokens.json"))
        XCTAssertNil(c.classify(dotfiles + "/azure/other"), "only the link's own target")
    }

    func testDanglingTargetResolution() throws {
        let home = try makeHome()
        let r = LinkFollowingResolver()
        let dotfiles = real(home + "/dotfiles")
        XCTAssertNil(r.resolve(home + "/.azure/missing"), "a missing path that is not a link stays unresolved")
        // The target's directory does not exist either: the target is below the deepest one that does.
        XCTAssertEqual(symlink(home + "/nowhere/x", home + "/.azure/a"), 0)
        XCTAssertEqual(r.resolve(home + "/.azure/a"), real(home) + "/nowhere/x")
        XCTAssertEqual(symlink("../dotfiles/new/sub/./token", home + "/.azure/g"), 0)
        XCTAssertEqual(r.resolve(home + "/.azure/g"), dotfiles + "/new/sub/token")
        // A chain of links ending below a missing directory.
        XCTAssertEqual(symlink(home + "/.azure/k", home + "/.azure/j"), 0)
        XCTAssertEqual(symlink("../dotfiles/new2/x", home + "/.azure/k"), 0)
        XCTAssertEqual(r.resolve(home + "/.azure/j"), dotfiles + "/new2/x")
        // Where a missing `..` leads depends on what is made there.
        XCTAssertEqual(symlink("../dotfiles/new/../token", home + "/.azure/h"), 0)
        XCTAssertNil(r.resolve(home + "/.azure/h"))
        // Something on the way that is not a directory.
        XCTAssertTrue(touch(home + "/dotfiles/plain"))
        XCTAssertEqual(symlink("../dotfiles/plain/token", home + "/.azure/i"), 0)
        XCTAssertNil(r.resolve(home + "/.azure/i"))
        // A chain of links ending in a missing name.
        XCTAssertEqual(symlink(home + "/.azure/c", home + "/.azure/b"), 0)
        XCTAssertEqual(symlink("../dotfiles/azure/final", home + "/.azure/c"), 0)
        XCTAssertEqual(r.resolve(home + "/.azure/b"), dotfiles + "/azure/final")
        // A loop.
        XCTAssertEqual(symlink(home + "/.azure/e", home + "/.azure/d"), 0)
        XCTAssertEqual(symlink(home + "/.azure/d", home + "/.azure/e"), 0)
        XCTAssertNil(r.resolve(home + "/.azure/d"))
        // Existing targets resolve as before.
        XCTAssertTrue(touch(home + "/dotfiles/azure/there"))
        XCTAssertEqual(symlink(home + "/dotfiles/azure/there", home + "/.azure/f"), 0)
        XCTAssertEqual(r.resolve(home + "/.azure/f"), dotfiles + "/azure/there")
    }

    // files-9: a link created in a dotfile directory was followed only at the next 5-minute
    // rediscovery, although the create itself is an event.
    func testLinkCreatedInADotfileDirectoryIsFollowedWithinSeconds() throws {
        let home = try makeHome()
        let target = home + "/dotfiles/azure/accessTokens.json"
        XCTAssertTrue(touch(target))
        let (core, _) = try linkCore(home: home)
        XCTAssertNil(core.analyzer.classifier.classify(real(target)))
        XCTAssertEqual(symlink(target, home + "/.azure/accessTokens.json"), 0)
        operation(core, .create, OperationSemantics.create(path: home + "/.azure/accessTokens.json"))
        XCTAssertNotNil(waitFor(5) { core.analyzer.classifier.classify(self.real(target))?.categoryID == "azure" })
    }

    // A catalog path replaced by a link (`mv` of a link onto it) is a rename onto the prefix itself.
    func testCatalogPathReplacedByALinkIsFollowedWithinSeconds() throws {
        let home = try makeHome()
        let target = home + "/dotfiles/git/credentials"
        XCTAssertTrue(touch(target))
        XCTAssertTrue(touch(home + "/.config/git/credentials"))
        let (core, _) = try linkCore(home: home)
        XCTAssertNil(core.analyzer.classifier.classify(real(target)))
        XCTAssertEqual(symlink(target, home + "/.config/git/tmp-link"), 0)
        XCTAssertEqual(rename(home + "/.config/git/tmp-link", home + "/.config/git/credentials"), 0)
        operation(core, .rename, OperationSemantics.rename(source: home + "/.config/git/tmp-link",
                                                           destination: home + "/.config/git/credentials"))
        XCTAssertNotNil(waitFor(5) { core.analyzer.classifier.classify(self.real(target))?.categoryID == "git-credentials" })
    }

    // Debounced: a burst is one rebuild; reads, writes, paths outside the watched set, and changes that
    // touch no link (a file saved by rename, a new directory, a removed file) are none.
    func testOnlyOperationsThatChangeALinkTriggerOneRebuild() throws {
        let home = try makeHome()
        let (core, _) = try linkCore(home: home, delay: 0.5)
        let p = proc(700, "/bin/cat")
        for _ in 0..<5 {
            core.eventSink.receive(.file(FileActivity(time: Date(), operation: .open, process: p,
                                                      targets: OperationSemantics.open(path: home + "/.azure/x", fflag: 3))),
                                   context: .monitorOnly)
            operation(core, .create, OperationSemantics.create(path: home + "/Documents/x"))
            operation(core, .create, OperationSemantics.create(path: home + "/dotfiles/unrelated"))
        }
        XCTAssertTrue(touch(home + "/.azure/saved"))
        operation(core, .rename, OperationSemantics.rename(source: home + "/.azure/saved.tmp", destination: home + "/.azure/saved"))
        XCTAssertEqual(mkdir(home + "/.azure/sub", 0o755), 0)
        operation(core, .create, OperationSemantics.create(path: home + "/.azure/sub"))
        operation(core, .unlink, OperationSemantics.unlink(path: home + "/.azure/removed"))
        Thread.sleep(forTimeInterval: 1.2)
        XCTAssertEqual(core.linkRediscoveryRuns, 0)

        let dotfiles = real(home + "/dotfiles")
        for i in 0..<5 {
            XCTAssertEqual(symlink(home + "/dotfiles/azure/t\(i)", home + "/.azure/l\(i)"), 0)
            operation(core, .create, OperationSemantics.create(path: home + "/.azure/l\(i)"))
        }
        XCTAssertNotNil(waitFor(5) { core.linkRediscoveryRuns == 1 })
        Thread.sleep(forTimeInterval: 1.0)
        XCTAssertEqual(core.linkRediscoveryRuns, 1)
        XCTAssertEqual(core.analyzer.classifier.classify(dotfiles + "/azure/t0")?.categoryID, "azure")

        // Removing a followed link stops following it.
        XCTAssertEqual(unlink(home + "/.azure/l0"), 0)
        operation(core, .unlink, OperationSemantics.unlink(path: home + "/.azure/l0"))
        XCTAssertNotNil(waitFor(5) { core.linkRediscoveryRuns == 2 })
        XCTAssertNil(core.analyzer.classifier.classify(dotfiles + "/azure/t0"))

        // Pending work is dropped when the daemon stops.
        XCTAssertEqual(symlink(home + "/dotfiles/azure/later", home + "/.azure/later"), 0)
        operation(core, .create, OperationSemantics.create(path: home + "/.azure/later"))
        core.cancelPendingLinkRediscovery()
        Thread.sleep(forTimeInterval: 1.2)
        XCTAssertEqual(core.linkRediscoveryRuns, 2)
    }

    // files-9-walk-caps: the search for links stopped 3 levels down, so a link created deeper in a
    // dotfile directory was never followed, even after the event that made it.
    func testLinkCreatedDeepInADotfileDirectoryIsFollowedWithinSeconds() throws {
        let home = try makeHome()
        let deep = home + "/.azure/a/b/c/d/e/f/g/h/i"
        try FileManager.default.createDirectory(atPath: deep, withIntermediateDirectories: true)
        let target = home + "/dotfiles/azure/deep.json"
        XCTAssertTrue(touch(target))
        let (core, _) = try linkCore(home: home)
        let walks = core.linkInventory.fullWalks
        XCTAssertEqual(symlink(target, deep + "/token.json"), 0)
        operation(core, .create, OperationSemantics.create(path: deep + "/token.json"))
        XCTAssertNotNil(waitFor(5) { core.analyzer.classifier.classify(self.real(target))?.categoryID == "azure" })
        XCTAssertEqual(core.linkInventory.fullWalks, walks, "the directories were not searched again")
        // Kept by the next full search, though it is past its depth.
        core.rediscover()
        XCTAssertEqual(core.analyzer.classifier.classify(real(target))?.categoryID, "azure")
        // Removing it stops following it.
        XCTAssertEqual(unlink(deep + "/token.json"), 0)
        operation(core, .unlink, OperationSemantics.unlink(path: deep + "/token.json"))
        XCTAssertNotNil(waitFor(5) { core.analyzer.classifier.classify(self.real(target)) == nil })
    }

    // files-9-walk-caps variant: the dotfile directory is itself a link (`~/.azure -> dotfiles/azure`), so
    // ES reports a link made deep inside it at its real path.
    func testLinkCreatedDeepInALinkedDotfileDirectoryIsFollowed() throws {
        let home = try makeHome()
        try FileManager.default.removeItem(atPath: home + "/.azure")
        XCTAssertEqual(symlink(home + "/dotfiles/azure", home + "/.azure"), 0)
        let deep = real(home + "/dotfiles/azure") + "/a/b/c/d/e/f/g/h/i"
        try FileManager.default.createDirectory(atPath: deep, withIntermediateDirectories: true)
        let target = home + "/vault/deep.json"
        try FileManager.default.createDirectory(atPath: home + "/vault", withIntermediateDirectories: true)
        XCTAssertTrue(touch(target))
        let (core, _) = try linkCore(home: home)
        XCTAssertNil(core.analyzer.classifier.classify(real(target)))
        XCTAssertEqual(symlink(target, deep + "/token.json"), 0)
        operation(core, .create, OperationSemantics.create(path: deep + "/token.json"))
        XCTAssertNotNil(waitFor(5) { core.analyzer.classifier.classify(self.real(target))?.categoryID == "azure" })
    }

    // files-9-walk-caps variant: a directory moved in brings the links inside it, at any depth the
    // search reaches from there.
    func testDirectoryMovedIntoADotfileDirectoryBringsItsLinks() throws {
        let home = try makeHome()
        let staged = home + "/staging/a/b/c/d"
        try FileManager.default.createDirectory(atPath: staged, withIntermediateDirectories: true)
        let target = home + "/dotfiles/azure/moved.json"
        XCTAssertTrue(touch(target))
        XCTAssertEqual(symlink(target, staged + "/token.json"), 0)
        let (core, _) = try linkCore(home: home)
        XCTAssertNil(core.analyzer.classifier.classify(real(target)))
        XCTAssertEqual(rename(home + "/staging", home + "/.azure/moved"), 0)
        operation(core, .rename, OperationSemantics.rename(ReportedPath(home + "/staging", isDirectory: true),
                                                           ReportedPath(home + "/.azure/moved")))
        XCTAssertNotNil(waitFor(5) { core.analyzer.classifier.classify(self.real(target))?.categoryID == "azure" })
        // Moved away again: no longer followed.
        XCTAssertEqual(rename(home + "/.azure/moved", home + "/staging"), 0)
        operation(core, .rename, OperationSemantics.rename(ReportedPath(home + "/.azure/moved", isDirectory: true),
                                                           ReportedPath(home + "/staging")))
        XCTAssertNotNil(waitFor(5) { core.analyzer.classifier.classify(self.real(target)) == nil })
    }

    // The search goes breadth first in name order: the same tree gives the same links past the caps,
    // and the links nearest the top come first.
    func testTheSearchForLinksIsBreadthFirstAndStable() throws {
        let home = try makeHome()
        let root = home + "/.azure"
        try FileManager.default.createDirectory(atPath: root + "/m/n", withIntermediateDirectories: true)
        for name in ["z", "b", "y", "a"] { XCTAssertTrue(touch(root + "/" + name)) }
        XCTAssertEqual(symlink("/x/deep", root + "/m/n/deep"), 0)
        XCTAssertEqual(symlink("/x/mid", root + "/m/mid"), 0)
        XCTAssertEqual(symlink("/x/top2", root + "/top2"), 0)
        XCTAssertEqual(symlink("/x/top1", root + "/top1"), 0)
        let all = LinkFollowingResolver.links(under: root, maxDepth: 8, maxEntries: 100)
        XCTAssertEqual(all.links, [root + "/top1", root + "/top2", root + "/m/mid", root + "/m/n/deep"])
        XCTAssertEqual(all.visited, 10)
        // Eight entries: the top level (seven), then the first of the next in name order.
        let capped = LinkFollowingResolver.links(under: root, maxDepth: 8, maxEntries: 8)
        XCTAssertEqual(capped.links, [root + "/top1", root + "/top2", root + "/m/mid"])
        XCTAssertEqual(capped.visited, 8)
        for _ in 0..<3 { XCTAssertEqual(LinkFollowingResolver.links(under: root, maxDepth: 8, maxEntries: 8).links, capped.links) }
        XCTAssertEqual(LinkFollowingResolver.links(under: root, maxDepth: 1, maxEntries: 100).links, [root + "/top1", root + "/top2"])
    }

    // More link changes at once than are kept: the directories are searched again, at most once per
    // interval, and the links already known are followed meanwhile.
    func testLostChangesCauseOneFullSearchPerInterval() throws {
        let home = try makeHome()
        // A delay long enough for each burst to land in one look.
        let (core, _) = try linkCore(home: home, delay: 0.5, fullWalkInterval: 3)
        let walks = core.linkInventory.fullWalks
        let target = home + "/dotfiles/azure/burst.json"
        XCTAssertTrue(touch(target))
        XCTAssertEqual(symlink(target, home + "/.azure/burst.json"), 0)
        for round in 0..<2 {
            for i in 0...DaemonCore.maxPendingLinkChanges {
                operation(core, .unlink, OperationSemantics.unlink(path: home + "/.azure/gone-\(round)-\(i)"))
            }
            Thread.sleep(forTimeInterval: 0.8)
        }
        XCTAssertEqual(core.linkInventory.fullWalks, walks, "not yet: the start was a full search")
        XCTAssertNil(core.analyzer.classifier.classify(real(target)))
        XCTAssertNotNil(waitFor(5) { core.analyzer.classifier.classify(self.real(target))?.categoryID == "azure" })
        XCTAssertEqual(core.linkInventory.fullWalks, walks + 1)
        Thread.sleep(forTimeInterval: 3.5)
        XCTAssertEqual(core.linkInventory.fullWalks, walks + 1, "one search for both bursts")
    }

    // Links reported outside every searched directory take no room among the remembered ones (they
    // would push out deep links that only events found).
    func testOnlyLinksBelowASearchedDirectoryAreRemembered() throws {
        let home = try makeHome()
        let inventory = LinkInventory()
        inventory.walk([home + "/.azure"])
        let target = home + "/dotfiles/azure/kept.json"
        XCTAssertTrue(touch(target))
        let deep = home + "/.azure/a/b/c/d/e/f/g/h/i"
        try FileManager.default.createDirectory(atPath: deep, withIntermediateDirectories: true)
        XCTAssertEqual(symlink(target, deep + "/kept.json"), 0)
        inventory.report([deep + "/kept.json"])
        inventory.report((0..<(LinkInventory.maxReported + 10)).map { home + "/elsewhere/\($0)" })
        let found = inventory.links(under: home + "/.azure", maxDepth: 8, maxEntries: 100, limit: 10)
        XCTAssertEqual(found.map(\.link), [deep + "/kept.json"])
        XCTAssertEqual(found.map(\.target), [real(target)])
    }

    // files-9-dangling-missing-dir: a link whose target lies below directories that do not exist yet
    // was followed only by the periodic rediscovery after they were made.
    func testALinkWhoseTargetDirectoryIsMissingIsMonitoredAtOnce() throws {
        let home = try makeHome()
        XCTAssertEqual(symlink("../dotfiles/new/sub/token.json", home + "/.azure/token.json"), 0)
        let (core, _) = try linkCore(home: home)
        let c = core.analyzer.classifier
        let dotfiles = real(home + "/dotfiles")
        XCTAssertEqual(c.classify(dotfiles + "/new/sub/token.json")?.categoryID, "azure")
        XCTAssertTrue(c.mutePaths.contains(dotfiles + "/new/sub/token.json"))
        XCTAssertTrue(c.ancestors.contains(dotfiles + "/new"), "making the missing directory is an event")
        XCTAssertNil(c.classify(dotfiles + "/new/other"))
    }

    // files-9-dangling-missing-dir variant: once the missing directory is made, the target's real
    // spelling is read at once. Made in another case, it is where the file goes on a case-insensitive
    // volume, and Endpoint Security selects events by the spelling on disk.
    func testMakingTheMissingDirectoryRereadsTheTargetsSpelling() throws {
        let home = try makeHome()
        let dotfiles = real(home + "/dotfiles")
        XCTAssertEqual(symlink("../dotfiles/Fresh/token.json", home + "/.azure/token.json"), 0)
        let (core, _) = try linkCore(home: home)
        XCTAssertTrue(core.analyzer.classifier.mutePaths.contains(dotfiles + "/Fresh/token.json"))
        XCTAssertEqual(mkdir(home + "/dotfiles/fresh", 0o755), 0)
        var st = stat()
        guard lstat(home + "/dotfiles/FRESH", &st) == 0 else { throw XCTSkip("this volume is case-sensitive") }
        operation(core, .create, OperationSemantics.create(path: home + "/dotfiles/fresh"))
        XCTAssertNotNil(waitFor(5) { core.analyzer.classifier.mutePaths.contains(dotfiles + "/fresh/token.json") })
        XCTAssertEqual(core.analyzer.classifier.classify(dotfiles + "/fresh/token.json")?.categoryID, "azure")
    }

    // files-9-dangling-missing-dir variant: the missing directory made as a link moves the target with
    // it, or drops it when it leads to system files.
    func testMissingDirectoryMadeAsALinkMovesOrDropsTheTarget() throws {
        let home = try makeHome()
        let dotfiles = real(home + "/dotfiles")
        XCTAssertEqual(symlink("../dotfiles/linked/sub/key.json", home + "/.azure/key.json"), 0)
        XCTAssertEqual(symlink("../dotfiles/system/sub/x.json", home + "/.azure/x.json"), 0)
        let (core, _) = try linkCore(home: home)
        XCTAssertTrue(core.analyzer.classifier.mutePaths.contains(dotfiles + "/linked/sub/key.json"))
        XCTAssertTrue(core.analyzer.classifier.mutePaths.contains(dotfiles + "/system/sub/x.json"))

        try FileManager.default.createDirectory(atPath: home + "/elsewhere/sub", withIntermediateDirectories: true)
        XCTAssertEqual(symlink(home + "/elsewhere", home + "/dotfiles/linked"), 0)
        operation(core, .create, OperationSemantics.create(path: home + "/dotfiles/linked"))
        XCTAssertNotNil(waitFor(5) { core.analyzer.classifier.classify(self.real(home + "/elsewhere") + "/sub/key.json")?.categoryID == "azure" })
        XCTAssertFalse(core.analyzer.classifier.mutePaths.contains(dotfiles + "/linked/sub/key.json"))

        XCTAssertEqual(symlink("/usr/share", home + "/dotfiles/system"), 0)
        operation(core, .create, OperationSemantics.create(path: home + "/dotfiles/system"))
        XCTAssertNotNil(waitFor(5) { !core.analyzer.classifier.mutePaths.contains(dotfiles + "/system/sub/x.json") })
        XCTAssertNil(core.analyzer.classifier.classify("/usr/share/sub/x.json"), "system files never become a category")
    }
}
