import Foundation
import XCTest
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
import WhoReadCore
@testable import WhoReadEngine

// Regression tests for scripts/install-dev-daemon.sh: the dev daemon's log file (daemonfs-1) and the
// directories it installs into.

private func exists(_ path: String) -> Bool {
    var st = stat()
    return lstat(path, &st) == 0
}

private func lstatOf(_ path: String) -> stat? {
    var st = stat()
    return lstat(path, &st) == 0 ? st : nil
}

private func mode(_ path: String) -> mode_t { (lstatOf(path)?.st_mode ?? 0) & 0o7777 }

private func isLink(_ path: String) -> Bool { ((lstatOf(path)?.st_mode ?? 0) & S_IFMT) == S_IFLNK }

private func entries(_ dir: String) -> [String] {
    ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []).sorted()
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

/// scripts/install-dev-daemon.sh pre-creates /Library/Logs/WhoRead/whoreadd.log, which launchd then
/// opens as root for the daemon's output. Its `: >>`, chown and chmod followed a link planted there,
/// and adopted another user's file. The script's functions run here against a temporary directory,
/// with the test's own user standing in for root (another user's file cannot be made without root).
final class InstallScriptLogTests: XCTestCase {
    private var dir: TempDir!
    private var logs: String { dir.path("logs") }
    private var log: String { logs + "/whoreadd.log" }

    override func setUpWithError() throws {
        #if !os(macOS)
        throw XCTSkip("the install script uses BSD stat and ls -e")
        #endif
        dir = TempDir()
        XCTAssertEqual(chmod(dir.url.path, 0o755), 0)
    }

    private struct Run {
        let status: Int32
        let stderr: String
    }

    /// Sources the script (which then only defines its functions) and runs `call` with bash.
    private func shell(_ call: String, _ args: [String] = []) throws -> Run {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash")
        let script = repoRoot.appendingPathComponent("scripts/install-dev-daemon.sh").path
        p.arguments = ["-c", ". \"$1\"; shift; " + call, "bash", script] + args
        p.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": dir.url.path]
        let err = Pipe()
        p.standardOutput = FileHandle.nullDevice
        p.standardError = err
        try p.run()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Run(status: p.terminationStatus, stderr: String(decoding: e, as: UTF8.self))
    }

    @discardableResult
    private func privateLog(file: StaticString = #filePath, line: UInt = #line) throws -> Run {
        let r = try shell(#"private_log "$1" whoreadd.log "$(id -un)" "$(id -gn)""#, [logs])
        XCTAssertEqual(r.status, 0, r.stderr, file: file, line: line)
        // Whatever was there, a root-only directory with a root-only regular file is left.
        XCTAssertEqual(mode(logs), 0o700, file: file, line: line)
        let st = try XCTUnwrap(lstatOf(log), file: file, line: line)
        XCTAssertEqual(st.st_mode & S_IFMT, S_IFREG, file: file, line: line)
        XCTAssertEqual(st.st_mode & 0o7777, 0o600, file: file, line: line)
        XCTAssertEqual(st.st_nlink, 1, file: file, line: line)
        XCTAssertEqual(st.st_uid, geteuid(), file: file, line: line)
        return r
    }

    private func movedAside(_ name: String, in d: String) -> [String] {
        entries(d).filter { $0.hasPrefix(name + ".untrusted-") }
    }

    func testFreshLogDirectoryAndFileAreOwnerOnly() throws {
        let old = umask(0)
        defer { umask(old) }
        try privateLog()
        XCTAssertEqual(entries(logs), ["whoreadd.log"])
    }

    // daemonfs-1: `: >> whoreadd.log` appended to, and chmod 600 changed, the file a link pointed to.
    func testLinkAtTheLogFileIsMovedAsideNotFollowed() throws {
        XCTAssertEqual(mkdir(logs, 0o700), 0)
        let target = dir.path("target")
        try SafeFile.replace(target, with: Data("not a log\n".utf8), mode: 0o644)
        XCTAssertEqual(symlink(target, log), 0)
        let r = try privateLog()
        XCTAssertTrue(r.stderr.contains("symbolic link"), r.stderr)
        XCTAssertEqual(mode(target), 0o644, "the link's target keeps its mode")
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: target)), Data("not a log\n".utf8))
        let aside = movedAside("whoreadd.log", in: logs)
        XCTAssertEqual(aside.count, 1, "\(entries(logs))")
        XCTAssertTrue(aside.allSatisfy { isLink(logs + "/" + $0) }, "the link itself is kept for a look, unfollowed")
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: log)), Data())
    }

    func testDanglingLinkAtTheLogFileCreatesNothingAtItsTarget() throws {
        XCTAssertEqual(mkdir(logs, 0o700), 0)
        let target = dir.path("would-be-created")
        XCTAssertEqual(symlink(target, log), 0)
        try privateLog()
        XCTAssertFalse(exists(target))
    }

    // daemonfs-1-variant: chown and chmod of a file with a second name change that other file too, and
    // launchd would append the daemon's output to it.
    func testHardLinkedLogFileIsMovedAside() throws {
        XCTAssertEqual(mkdir(logs, 0o700), 0)
        let other = dir.path("other")
        try SafeFile.replace(other, with: Data("someone's file\n".utf8), mode: 0o644)
        XCTAssertEqual(link(other, log), 0)
        let r = try privateLog()
        XCTAssertTrue(r.stderr.contains("2 hard links"), r.stderr)
        XCTAssertEqual(mode(other), 0o644)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: other)), Data("someone's file\n".utf8))
    }

    func testNonRegularEntryAtTheLogFileIsMovedAside() throws {
        XCTAssertEqual(mkdir(logs, 0o700), 0)
        XCTAssertEqual(mkdir(log, 0o755), 0)
        try privateLog()
        XCTAssertEqual(movedAside("whoreadd.log", in: logs).count, 1)
        XCTAssertEqual(unlink(log), 0)
        XCTAssertEqual(mkfifo(log, 0o600), 0)
        try privateLog()
        XCTAssertEqual(movedAside("whoreadd.log", in: logs).count, 2)
    }

    func testLogFileOthersCanWriteIsMovedAside() throws {
        XCTAssertEqual(mkdir(logs, 0o700), 0)
        try SafeFile.replace(log, with: Data("written by others\n".utf8), mode: 0o666)
        let r = try privateLog()
        XCTAssertTrue(r.stderr.contains("writable by group or others"), r.stderr)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: log)), Data())
    }

    // daemonfs-1-variant: the directory itself, a link to elsewhere (install -d and chmod 700 followed
    // it), or one others could change entries in.
    func testLinkedLogDirectoryIsMovedAsideNotFollowed() throws {
        let elsewhere = dir.path("elsewhere")
        XCTAssertEqual(mkdir(elsewhere, 0o755), 0)
        XCTAssertEqual(chmod(elsewhere, 0o755), 0)
        XCTAssertEqual(symlink(elsewhere, logs), 0)
        let r = try privateLog()
        XCTAssertTrue(r.stderr.contains("symbolic link or not a directory"), r.stderr)
        XCTAssertEqual(entries(elsewhere), [], "nothing is created through the link")
        XCTAssertEqual(mode(elsewhere), 0o755)
        XCTAssertFalse(isLink(logs))
        XCTAssertEqual(movedAside("logs", in: dir.url.path).count, 1)
    }

    func testLogDirectoryOthersCanWriteIsMovedAside() throws {
        XCTAssertEqual(mkdir(logs, 0o700), 0)
        XCTAssertEqual(chmod(logs, 0o777), 0)
        try SafeFile.replace(log, with: Data("planted\n".utf8), mode: 0o600)
        let r = try privateLog()
        XCTAssertTrue(r.stderr.contains("writable by group or others"), r.stderr)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: log)), Data(), "a fresh directory with a fresh log")
        XCTAssertEqual(movedAside("logs", in: dir.url.path).count, 1)
    }

    func testLogDirectoryOrFileWithAnACLIsMovedAside() throws {
        XCTAssertEqual(mkdir(logs, 0o700), 0)
        try chmodACL(["+a", "everyone allow list,search,add_file", logs])
        let r = try privateLog()
        XCTAssertTrue(r.stderr.contains("access control list"), r.stderr)
        XCTAssertEqual(movedAside("logs", in: dir.url.path).count, 1)

        try chmodACL(["+a", "everyone allow read", log])
        try privateLog()
        XCTAssertEqual(movedAside("whoreadd.log", in: logs).count, 1)
    }

    // What an earlier install left (a 0755 directory and a 0644 log): kept, with its content, and
    // closed to others.
    func testEarlierInstallsLogIsKeptAndClosedToOthers() throws {
        XCTAssertEqual(mkdir(logs, 0o755), 0)
        XCTAssertEqual(chmod(logs, 0o755), 0)
        try SafeFile.replace(log, with: Data("earlier lines\n".utf8), mode: 0o644)
        let r = try privateLog()
        XCTAssertEqual(r.stderr, "")
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: log)), Data("earlier lines\n".utf8))
        XCTAssertEqual(entries(logs), ["whoreadd.log"])
    }

    // daemonfs-1-variant: `install -d` chowned an existing data directory to root (adopting whatever
    // its owner left in it) and chmod-ed, and copied the defaults into, whatever a link there pointed to.
    func testDataDirectoryOthersCouldChangeIsRefusedNotAdopted() throws {
        let data = dir.path("data")
        let check = #"require_trusted_dirs "$(id -u)" "fix it" "$1" "$1/defaults""#
        XCTAssertEqual(try shell(check, [data]).status, 0, "nothing there yet: install creates it")
        XCTAssertEqual(mkdir(data, 0o755), 0)
        XCTAssertEqual(chmod(data, 0o755), 0)
        XCTAssertEqual(mkdir(data + "/defaults", 0o755), 0)
        XCTAssertEqual(chmod(data + "/defaults", 0o755), 0)
        XCTAssertEqual(try shell(check, [data]).status, 0)

        XCTAssertEqual(chmod(data, 0o775), 0)
        var r = try shell(check, [data])
        XCTAssertEqual(r.status, 1)
        XCTAssertTrue(r.stderr.contains("refusing to install: \(data) is writable by group or others"), r.stderr)
        XCTAssertTrue(r.stderr.contains("fix it"), r.stderr)
        XCTAssertEqual(mode(data), 0o775, "nothing is changed")
        XCTAssertEqual(chmod(data, 0o755), 0)

        let elsewhere = dir.path("elsewhere")
        XCTAssertEqual(mkdir(elsewhere, 0o755), 0)
        XCTAssertEqual(rmdir(data + "/defaults"), 0)
        XCTAssertEqual(symlink(elsewhere, data + "/defaults"), 0)
        r = try shell(check, [data])
        XCTAssertEqual(r.status, 1)
        XCTAssertTrue(r.stderr.contains("\(data)/defaults is a symbolic link"), r.stderr)

        try chmodACL(["+a", "everyone allow add_file", elsewhere])
        r = try shell(#"require_trusted_dirs "$(id -u)" "fix it" "$1""#, [elsewhere])
        XCTAssertEqual(r.status, 1)
        XCTAssertTrue(r.stderr.contains("access control list"), r.stderr)
    }

    /// The early return for the tests' sourcing does not end a normal run: it goes on to its checks.
    func testRunWithoutSudoStillStopsBeforeAnything() throws {
        try XCTSkipIf(geteuid() == 0, "as root the script would install")
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash")
        p.arguments = [repoRoot.appendingPathComponent("scripts/install-dev-daemon.sh").path]
        p.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        p.waitUntilExit()
        XCTAssertEqual(p.terminationStatus, 77)
    }
}
