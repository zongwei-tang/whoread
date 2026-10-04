// Endpoint Security system extension entry point: the release form of whoreadd.
// NOT YET COMPILED (written on Linux; see docs/RESEARCH.md).
import Foundation
import WhoReadCore
import WhoReadEngine

var config = DaemonConfiguration()
config.source = .native
let info = Bundle.main.infoDictionary ?? [:]
config.machServiceName = info["NSEndpointSecurityMachServiceName"] as? String
config.defaultsDirectory = Bundle.main.resourceURL?.appendingPathComponent("WhoReadData").path
// Only our signed app and CLI may connect; only the app may weaken protection.
config.clientRequirement = info["WhoReadClientRequirement"] as? String
config.appRequirement = info["WhoReadAppRequirement"] as? String

do {
    let daemon = try Daemon(configuration: config)
    try daemon.start()
    withExtendedLifetime(daemon) { dispatchMain() }
} catch {
    Log.error("WhoRead extension failed to start: \(error)")
    exit(1)
}
