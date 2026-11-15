import Foundation
import XCTest
import WhoReadCore
@testable import WhoReadEngine

/// daemon-2, native-1: a log line that cannot be written (full disk, a log file gone bad, a closed
/// pipe) is dropped; it must never end the daemon. Foundation's FileHandle.write(_: Data) raises an
/// Objective-C exception on a failed write, which aborts the process, so these run the built
/// `whoreadd` with a standard error every write to fails (a read-only descriptor: EBADF). Neither run
/// gets as far as an event source: an unknown source, and a data directory the daemon refuses.
final class R5LogFailureTests: XCTestCase {
    /// The `whoreadd` executable next to the test bundle.
    private static let binary: String? = {
        var dirs: [URL] = []
        #if os(macOS)
        dirs += Bundle.allBundles.filter { $0.bundlePath.hasSuffix(".xctest") }.map { $0.bundleURL.deletingLastPathComponent() }
        #else
        dirs.append(Bundle.main.bundleURL)
        #endif
        dirs.append(repoRoot.appendingPathComponent(".build/debug"))
        return dirs.map { $0.appendingPathComponent("whoreadd").path }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }()

    private struct Run {
        let reason: Process.TerminationReason
        let status: Int32
        let stderr: String
    }

    /// `stderr` nil: a pipe, read back. Otherwise the descriptor given.
    private func whoreadd(_ args: [String], stderr: FileHandle? = nil) throws -> Run {
        guard let bin = R5LogFailureTests.binary else { throw XCTSkip("the whoreadd executable is not built") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = args
        p.environment = ["PATH": "/usr/bin:/bin", "HOME": ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory()]
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = FileHandle.nullDevice
        let pipe = Pipe()
        p.standardError = stderr ?? pipe
        try p.run()
        let text = stderr == nil ? String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self) : ""
        p.waitUntilExit()
        return Run(reason: p.terminationReason, status: p.terminationStatus, stderr: text)
    }

    /// A descriptor every write to fails on.
    private func unwritable() throws -> FileHandle {
        try XCTUnwrap(FileHandle(forReadingAtPath: "/dev/null"))
    }

    /// Arguments for a daemon that refuses its data directory (writable by its group) and logs why.
    private func refusedDataDirectory(_ dir: TempDir) throws -> [String] {
        let data = dir.path("data")
        try FileManager.default.createDirectory(atPath: data, withIntermediateDirectories: true)
        XCTAssertEqual(chmod(data, 0o775), 0)
        return ["run", "--source", "replay:" + dir.path("none.jsonl"), "--data-dir", data, "--kill-switch", data + "/disable-enforcement",
                "--home", "/Users/alice", "--no-xpc", "--no-seed"]
    }

    func testTheRefusalIsLogged() throws {
        let dir = TempDir()
        let run = try whoreadd(try refusedDataDirectory(dir))
        XCTAssertEqual(run.reason, .exit, run.stderr)
        XCTAssertEqual(run.status, 1, run.stderr)
        XCTAssertTrue(run.stderr.contains("ERROR failed to start: "), run.stderr)
        XCTAssertTrue(run.stderr.contains("refusing to use the data directory"), run.stderr)
    }

    func testALogLineThatCannotBeWrittenDoesNotEndTheDaemon() throws {
        let dir = TempDir()
        let run = try whoreadd(try refusedDataDirectory(dir), stderr: try unwritable())
        XCTAssertEqual(run.reason, .exit, "ended by signal \(run.status) while logging")
        XCTAssertEqual(run.status, 1, "it went on to exit as it meant to")
    }

    /// A standard error that is a pipe nobody reads any more: EPIPE, and no SIGPIPE either.
    func testALogLineOnAClosedPipeDoesNotEndTheDaemon() throws {
        let dir = TempDir()
        let pipe = Pipe()
        try pipe.fileHandleForReading.close()
        let run = try whoreadd(try refusedDataDirectory(dir), stderr: pipe.fileHandleForWriting)
        XCTAssertEqual(run.reason, .exit, "ended by signal \(run.status) while logging")
        XCTAssertEqual(run.status, 1)
    }

    func testAnUnwritableUsageErrorStillExitsWithItsStatus() throws {
        let run = try whoreadd(["run", "--source", "bogus"], stderr: try unwritable())
        XCTAssertEqual(run.reason, .exit, "ended by signal \(run.status) while writing the error")
        XCTAssertEqual(run.status, 64)
        let shown = try whoreadd(["run", "--source", "bogus"])
        XCTAssertEqual(shown.status, 64)
        XCTAssertEqual(shown.stderr, "unknown source bogus\n")
    }
}
