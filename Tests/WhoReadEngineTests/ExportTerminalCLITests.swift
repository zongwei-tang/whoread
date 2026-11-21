import Darwin
import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// `whoread export --format csv` writes to standard output by default. CSV has no escape of its
/// own, so on a terminal a name or path with ESC, a C1 control, a bidi override or a line break is
/// shown escaped; a pipe or a file gets the exact CSV. Runs the built `whoread` against a stub
/// daemon on a dev socket, once with standard output on a pseudo-terminal.
final class ExportTerminalCLITests: XCTestCase {
    private static let binary: String? = {
        var dirs = Bundle.allBundles.filter { $0.bundlePath.hasSuffix(".xctest") }.map { $0.bundleURL.deletingLastPathComponent() }
        dirs.append(repoRoot.appendingPathComponent(".build/debug"))
        return dirs.map { $0.appendingPathComponent("whoread").path }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }()

    private final class Stub: IPCHandler, @unchecked Sendable {
        let data: DefaultData
        var events: [AnalyzedEvent] = []
        init() throws { data = try DefaultData.load(directory: repoRoot.appendingPathComponent("Data")) }
        func handle(_ request: IPCRequest, peer: IPCPeer) -> IPCResponse {
            switch request {
            case .hello: return .hello(serverVersion: whoReadIPCVersion)
            case .events(let q): return .events(Array(events.filter { e in q.afterID.map { e.id > $0 } ?? true }.prefix(q.limit)))
            case .catalog: return .catalog(CatalogInfo(catalog: data.catalog, detected: [:], prefixes: [], homeDirectories: ["/Users/alice"]))
            default: return .error(IPCError(.invalid, "not served by this stub"))
            }
        }
    }

    private func process(_ args: [String]) throws -> Process {
        guard let bin = ExportTerminalCLITests.binary else { throw XCTSkip("the whoread executable is not built") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["--lang", "en"] + args
        p.environment = ["PATH": "/usr/bin:/bin", "HOME": ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory(), "TZ": "UTC"]
        p.standardError = FileHandle.nullDevice
        return p
    }

    /// Standard output to a pipe.
    private func piped(_ args: [String]) throws -> (Int32, Data) {
        let p = try process(args)
        let out = Pipe()
        p.standardOutput = out
        try p.run()
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, data)
    }

    /// Standard output to a pseudo-terminal in raw mode (no line-break translation), read as written.
    private func onTerminal(_ args: [String]) throws -> (Int32, Data) {
        var master: Int32 = -1, slave: Int32 = -1
        guard openpty(&master, &slave, nil, nil, nil) == 0 else {
            // Like the socket tests: only a sandbox that says so may skip (it denies /dev/ptmx too).
            let reason = "cannot open a pseudo-terminal (errno \(errno))"
            if ProcessInfo.processInfo.environment["WHOREAD_ALLOW_SOCKET_SKIP"] == "1" { throw XCTSkip(reason) }
            throw NSError(domain: "ExportTerminalCLITests", code: 1, userInfo: [NSLocalizedDescriptionKey: reason])
        }
        defer { close(master) }
        var mode = termios()
        tcgetattr(slave, &mode)
        cfmakeraw(&mode)
        tcsetattr(slave, TCSANOW, &mode)
        let p = try process(args)
        p.standardOutput = FileHandle(fileDescriptor: slave, closeOnDealloc: false)
        do { try p.run() } catch { close(slave); throw error }
        close(slave)
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        // Until the child's end of the terminal is closed (EIO or end of file).
        while true {
            let n = read(master, &buffer, buffer.count)
            if n <= 0 { break }
            data.append(buffer, count: n)
        }
        p.waitUntilExit()
        return (p.terminationStatus, data)
    }

    func testCSVExportIsEscapedOnATerminalAndExactInPipesAndFiles() throws {
        try skipIfSocketBindDenied()
        let dir = TempDir()
        let stub = try Stub()
        let name = "Terminal\u{1B}[2J\u{9B}8m\u{202E}x"
        let bundle = "/Users/alice/x/\(name).app"
        stub.events = [AnalyzedEvent(id: 1, time: Date(timeIntervalSince1970: 1_760_000_000), operation: .open, access: .read,
                                     path: "/Users/alice/WhoReadTestVault/a\nb\u{1B}]0;t\u{07}", secondaryPath: nil,
                                     categoryID: "test-vault", severity: .critical,
                                     process: ProcessRecord(pid: 60, ppid: 50, executablePath: bundle + "/Contents/MacOS/r"), chain: [],
                                     responsible: ResponsibleEntity(kind: .app, key: "app:" + PathNormalizer.fold(bundle), displayName: name,
                                                                    path: bundle),
                                     agentID: nil, isOwner: false, benignServiceID: nil, decision: .allowed, ruleID: nil)]
        let server = UnixSocketServer(path: dir.path("s.sock"), handler: stub)
        try server.start()
        defer { server.stop() }
        let exact = Exporter.csv(events: stub.events, catalog: stub.data.catalog)
        let args = ["--socket", dir.path("s.sock"), "export", "--format", "csv"]

        let (status, terminal) = try onTerminal(args)
        XCTAssertEqual(status, 0)
        let shown = String(decoding: terminal, as: UTF8.self)
        let raw = shown.unicodeScalars.filter { $0 != "\n" && DisplayText.isHidden($0) }
        XCTAssertTrue(raw.isEmpty, "raw \(raw.map(\.value)) on the terminal:\n\(shown)")
        XCTAssertEqual(shown, Exporter.terminalSafeCSV(exact))
        XCTAssertTrue(shown.contains("Terminal\\u{1b}[2J\\u{9b}8m\\u{202e}x"), shown)
        XCTAssertTrue(shown.contains("a\\u{a}b\\u{1b}]0;t\\u{7}"), shown)
        XCTAssertEqual(shown.split(separator: "\n").count, 2, "the header and one row")

        let (pipeStatus, pipe) = try piped(args)
        XCTAssertEqual(pipeStatus, 0)
        XCTAssertEqual(String(decoding: pipe, as: UTF8.self), exact, "a pipe gets the exact CSV")

        let file = dir.path("out.csv")
        XCTAssertEqual(try piped(args + ["--output", file]).0, 0)
        XCTAssertEqual(try String(contentsOfFile: file, encoding: .utf8), exact, "a file gets the exact CSV")
    }
}
