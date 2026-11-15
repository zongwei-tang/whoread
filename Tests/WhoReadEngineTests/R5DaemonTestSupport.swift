import Foundation
import XCTest
import WhoReadCore
import WhoReadIPC
@testable import WhoReadEngine

// Shared fixtures of the round-5 daemon regression tests: the synthetic home /Users/alice and the
// test-vault category of the default catalog (critical, with medium patterns).

let r5T = Date(timeIntervalSince1970: 1_760_000_000)
/// Critical: no pattern of the category lowers it.
let r5VaultKey = "/Users/alice/WhoReadTestVault/ssh/id_ed25519"
/// Medium (`ssh/known_hosts*`).
let r5VaultKnownHosts = "/Users/alice/WhoReadTestVault/ssh/known_hosts"
/// Medium (`notes/**`).
let r5VaultNote = "/Users/alice/WhoReadTestVault/notes/todo.txt"
let r5ZoomKey = "app:/applications/zoom.us.app"

/// A core on a temporary data directory with a source that cannot enforce (monitor only, as eslogger),
/// and launchd in its process tree, so that the chains the tests build are known.
func r5Core(_ dir: TempDir, canEnforce: Bool = false, _ configure: (inout DaemonConfiguration) -> Void = { _ in }) throws -> DaemonCore {
    var config = baseConfig(dir)
    config.resolveOwners = false
    configure(&config)
    let core = try DaemonCore(config: config, makeSource: { _ in FakeSource(canEnforce: canEnforce) })
    core.tree.observe(proc(1, "/sbin/launchd", ppid: 0, platform: true), at: r5T)
    return core
}

@discardableResult
func r5Observe(_ core: DaemonCore, _ p: ProcessRecord) -> ProcessRecord {
    core.tree.observe(p, at: r5T)
    return p
}

/// zoom.us started by launchd: a known chain without an AI agent, owner of nothing.
func r5Zoom(_ core: DaemonCore) -> ProcessRecord {
    var p = proc(300, "/Applications/zoom.us.app/Contents/MacOS/zoom.us", ppid: 1)
    p.signingID = "us.zoom.xos"
    p.teamID = "ZOOMTEAM01"
    return r5Observe(core, p)
}

/// An open of `path`: read (FREAD), write only (FWRITE) or both.
func r5Open(_ p: ProcessRecord, _ path: String, _ access: AccessSet = .read, at time: Date) -> FileActivity {
    let fflag: UInt32 = (access.contains(.read) ? 1 : 0) | (access.contains(.write) ? 2 : 0)
    return FileActivity(time: time, operation: .open, process: p, targets: OperationSemantics.open(path: path, fflag: fflag))
}

/// Delivers a file event as the eslogger source does (monitor only), then stores it.
func r5Receive(_ core: DaemonCore, _ a: FileActivity) {
    core.pipeline.receive(.file(a), context: .monitorOnly)
    core.writer.flush()
}

/// Stored alerts, oldest first.
func r5Alerts(_ core: DaemonCore) throws -> [Alert] {
    core.writer.flush()
    return try core.store.alerts(AlertQuery(limit: 1000)).sorted { $0.id < $1.id }
}

func r5Describe(_ alerts: [Alert]) -> String {
    alerts.map { "#\($0.id) \($0.kind.rawValue) \($0.accesses.label) \($0.status.rawValue) \($0.firstPath)" }.joined(separator: "; ")
}

/// A flag a @Sendable callback can set.
final class R5Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var _value = false
    var value: Bool {
        get { lock.lock(); defer { lock.unlock() }; return _value }
        set { lock.lock(); _value = newValue; lock.unlock() }
    }
}
