// Endpoint Security system extension entry point: the release form of whoreadd.
// NOT YET COMPILED (written on Linux; see docs/RESEARCH.md).
import Foundation
import WhoReadCore
import WhoReadEngine

// launchd discards a system extension's stderr, where Log writes, so send it to a root-only file
// (alert headlines and chains of every user end up there).
let logDirectory = "/Library/Logs/WhoRead"
try? FileManager.default.createDirectory(atPath: logDirectory, withIntermediateDirectories: true)
chmod(logDirectory, 0o700)
let logFD = open(logDirectory + "/extension.log", O_WRONLY | O_APPEND | O_CREAT, 0o600)
if logFD >= 0 {
    dup2(logFD, STDERR_FILENO)
    close(logFD)
}

var config = DaemonConfiguration()
config.source = .native
let info = Bundle.main.infoDictionary ?? [:]
config.machServiceName = info["NSEndpointSecurityMachServiceName"] as? String
// Xcode copies the ../Data folder reference under its on-disk name; accept the display name too.
config.defaultsDirectory = ["Data", "WhoReadData"]
    .compactMap { Bundle.main.resourceURL?.appendingPathComponent($0) }
    .first { FileManager.default.fileExists(atPath: $0.appendingPathComponent(DefaultData.catalogFile).path) }?
    .path
// Only our signed app and CLI may connect; only the app may weaken protection. A build without a
// team expands these to `leaf[subject.OU] = ""`, which no peer satisfies (root included): drop them.
func requirement(_ key: String) -> String? {
    guard let s = info[key] as? String, !s.isEmpty, !s.contains("leaf[subject.OU] = \"\"") else { return nil }
    return s
}
config.clientRequirement = requirement("WhoReadClientRequirement")
config.appRequirement = requirement("WhoReadAppRequirement")

do {
    let daemon = try Daemon(configuration: config)
    try daemon.start()
    // launchd sends SIGTERM on update, deactivation and shutdown: flush events and the baseline.
    signal(SIGTERM, SIG_IGN)
    signal(SIGINT, SIG_IGN)
    let signalQueue = DispatchQueue(label: "whoread.signals")
    let signalSources = [SIGTERM, SIGINT].map { sig -> DispatchSourceSignal in
        let s = DispatchSource.makeSignalSource(signal: sig, queue: signalQueue)
        s.setEventHandler {
            Log.info("signal \(sig): shutting down")
            daemon.stop()
            exit(0)
        }
        s.resume()
        return s
    }
    withExtendedLifetime((daemon, signalSources)) { dispatchMain() }
} catch {
    Log.error("WhoRead extension failed to start: \(error)")
    exit(1)
}
