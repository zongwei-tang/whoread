import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

/// Round 6 (exec-rollback): only the native source analyzes a process's file events apart from its process
/// events, so only there can a record reach the tree after a later exec of its process. eslogger and replay
/// deliver in order: an unseen pidversion is a missed exec (ProcessTree.recordsMayArriveLate).
final class R6TreeWiringTests: XCTestCase {
    func testOnlyTheNativeSourceDeliversRecordsLate() throws {
        let dir = TempDir()
        var config = baseConfig(dir)
        config.inMemoryStore = true
        let native = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: false) })
        XCTAssertEqual(native.source.kind, .native)
        XCTAssertTrue(native.tree.recordsMayArriveLate)
        let eslogger = try DaemonCore(config: config, makeSource: { _ in EsloggerSource(executable: "/usr/bin/false", prefixes: []) })
        XCTAssertEqual(eslogger.source.kind, .eslogger)
        XCTAssertFalse(eslogger.tree.recordsMayArriveLate)
        let replay = try DaemonCore(config: config)
        XCTAssertEqual(replay.source.kind, .replay)
        XCTAssertFalse(replay.tree.recordsMayArriveLate)
    }
}
