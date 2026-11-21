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

// Regression tests for `whoread catalog export --output` (a privacy-4 variant).

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

/// Runs the built `whoread` against a stub daemon on a dev socket (no test target links the CLI).
final class CatalogExportCLITests: XCTestCase {
    override func setUpWithError() throws { try skipIfSocketBindDenied() }

    private static let binary: String? = {
        var dirs: [URL] = []
        #if os(macOS)
        dirs += Bundle.allBundles.filter { $0.bundlePath.hasSuffix(".xctest") }.map { $0.bundleURL.deletingLastPathComponent() }
        #else
        dirs.append(Bundle.main.bundleURL)
        #endif
        dirs.append(repoRoot.appendingPathComponent(".build/debug"))
        return dirs.map { $0.appendingPathComponent("whoread").path }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }()

    private final class Stub: IPCHandler, @unchecked Sendable {
        let catalog: Catalog
        init() throws { catalog = try DefaultData.load(directory: repoRoot.appendingPathComponent("Data")).catalog }
        func handle(_ request: IPCRequest, peer: IPCPeer) -> IPCResponse {
            switch request {
            case .hello: return .hello(serverVersion: whoReadIPCVersion)
            case .catalog: return .catalog(CatalogInfo(catalog: catalog, detected: [:], prefixes: [], homeDirectories: ["/Users/alice"]))
            default: return .error(IPCError(.invalid, "not served by this stub"))
            }
        }
    }

    private struct Run {
        let status: Int32
        let stderr: String
    }

    private func export(to output: String, socket: String) throws -> Run {
        guard let bin = CatalogExportCLITests.binary else { throw XCTSkip("the whoread executable is not built") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["--socket", socket, "--lang", "en", "catalog", "export", "--output", output]
        p.environment = ["PATH": "/usr/bin:/bin", "HOME": ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory()]
        let err = Pipe()
        p.standardOutput = FileHandle.nullDevice
        p.standardError = err
        try p.run()
        let e = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return Run(status: p.terminationStatus, stderr: String(decoding: e, as: UTF8.self))
    }

    private func withStub(_ body: (TempDir, String, Stub) throws -> Void) throws {
        let dir = TempDir()
        let stub = try Stub()
        let socket = dir.path("s.sock")
        let server = UnixSocketServer(path: socket, handler: stub)
        try server.start()
        defer { server.stop() }
        try body(dir, socket, stub)
    }

    // privacy-4 variant: the export was written 0644, readable by every user, whatever the user wanted.
    func testExportIsOwnerOnlyWhateverTheUmask() throws {
        try withStub { dir, socket, stub in
            let old = umask(0o022)
            defer { umask(old) }
            let out = dir.path("catalog.json")
            let r = try export(to: out, socket: socket)
            XCTAssertEqual(r.status, 0, r.stderr)
            XCTAssertEqual(mode(out), 0o600)
            XCTAssertEqual(try Catalog.load(from: Data(contentsOf: URL(fileURLWithPath: out))), stub.catalog)
            XCTAssertEqual(entries(dir.url.path).filter { $0.hasSuffix(".partial") }, [])
            // Again over the file it wrote: replaced, still owner-only.
            XCTAssertEqual(chmod(out, 0o644), 0)
            XCTAssertEqual(try export(to: out, socket: socket).status, 0)
            XCTAssertEqual(mode(out), 0o600)
        }
    }

    // privacy-4 variant: a link at the output path was replaced (SafeFile.replace renames over it) instead of
    // refused like the history export does.
    func testLinkOrDirectoryAtTheOutputPathIsRefused() throws {
        try withStub { dir, socket, _ in
            let target = dir.path("target")
            try SafeFile.replace(target, with: Data("keep\n".utf8), mode: 0o644)
            let out = dir.path("catalog.json")
            XCTAssertEqual(symlink(target, out), 0)
            var r = try export(to: out, socket: socket)
            XCTAssertNotEqual(r.status, 0)
            XCTAssertTrue(r.stderr.contains("symbolic link"), r.stderr)
            XCTAssertTrue(isLink(out), "the link is left as it was")
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: target)), Data("keep\n".utf8))
            XCTAssertEqual(mode(target), 0o644)

            let dangling = dir.path("dangling.json")
            XCTAssertEqual(symlink(dir.path("nowhere"), dangling), 0)
            r = try export(to: dangling, socket: socket)
            XCTAssertNotEqual(r.status, 0)
            XCTAssertFalse(exists(dir.path("nowhere")))

            let folder = dir.path("folder")
            XCTAssertEqual(mkdir(folder, 0o755), 0)
            r = try export(to: folder, socket: socket)
            XCTAssertNotEqual(r.status, 0)
            XCTAssertTrue(r.stderr.contains("directory"), r.stderr)
            XCTAssertEqual(entries(dir.url.path).filter { $0.hasSuffix(".partial") }, [])
        }
    }
}
