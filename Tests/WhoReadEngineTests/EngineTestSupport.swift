import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

let repoRoot: URL = {
    var url = URL(fileURLWithPath: #filePath)
    while url.path != "/" {
        url.deleteLastPathComponent()
        if FileManager.default.fileExists(atPath: url.appendingPathComponent("Package.swift").path) { return url }
    }
    fatalError("repo root not found")
}()

let fixtureV10 = repoRoot.appendingPathComponent("Tests/Fixtures/eslogger/schema-v1-msgv10/scenario.jsonl").path
let fixtureV7 = repoRoot.appendingPathComponent("Tests/Fixtures/eslogger/schema-v1-msgv7/scenario.jsonl").path

final class TempDir {
    let url: URL
    init() {
        url = FileManager.default.temporaryDirectory.appendingPathComponent("whoread-\(UUID().uuidString.prefix(8))")
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }
    func path(_ name: String) -> String { url.appendingPathComponent(name).path }
    deinit { try? FileManager.default.removeItem(at: url) }
}

func baseConfig(_ dir: TempDir, source: SourceKind = .replay, replay: String? = fixtureV10) -> DaemonConfiguration {
    var c = DaemonConfiguration()
    c.dataDirectory = dir.path("data")
    c.defaultsDirectory = repoRoot.appendingPathComponent("Data").path
    c.source = source
    c.replayPath = replay
    c.homeDirectories = ["/Users/alice"]
    c.killSwitchPath = dir.path("data/disable-enforcement")
    c.seedProcesses = false
    return c
}

/// Writes an executable shell script.
func script(_ dir: TempDir, _ name: String, _ body: String) -> String {
    let p = dir.path(name)
    try! ("#!/bin/sh\n" + body + "\n").write(toFile: p, atomically: true, encoding: .utf8)
    chmod(p, 0o755)
    return p
}

/// Polls until `condition` holds or the timeout passes. Returns elapsed seconds or nil.
@discardableResult
func waitFor(_ timeout: TimeInterval, _ condition: () -> Bool) -> TimeInterval? {
    let start = Date()
    while Date().timeIntervalSince(start) < timeout {
        if condition() { return Date().timeIntervalSince(start) }
        Thread.sleep(forTimeInterval: 0.02)
    }
    return condition() ? Date().timeIntervalSince(start) : nil
}

/// A source that does nothing but can claim to enforce (for Enforcer tests).
final class FakeSource: EventSource, @unchecked Sendable {
    let kind: SourceKind = .native
    let canEnforce: Bool
    var state = SourceState(running: true)
    var enforcementCalls: [Bool] = []
    var monitoringUpdates = 0
    init(canEnforce: Bool) { self.canEnforce = canEnforce }
    func start(sink: EventSink) throws {}
    func stop() {}
    func updateMonitoring(prefixes: [String], ancestors: [String], readdir: Bool) { monitoringUpdates += 1 }
    func enforcementChanged(active: Bool) { enforcementCalls.append(active) }
}

func proc(_ pid: Int32, _ path: String, ppid: Int32 = 1, platform: Bool = false, argv: [String]? = nil,
          start: Date = Date(timeIntervalSince1970: 1_760_000_000)) -> ProcessRecord {
    ProcessRecord(pid: pid, pidVersion: UInt32(pid), ppid: ppid, originalPPID: ppid, executablePath: path,
                  isPlatformBinary: platform, argv: argv, startTime: start)
}
