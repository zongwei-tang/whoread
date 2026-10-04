import Foundation
import WhoReadCore
import WhoReadEngine
import WhoReadIPC
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

let usage = """
whoreadd — WhoRead root daemon

Usage:
  whoreadd run [options]
  whoreadd version

Options:
  --source eslogger|native|replay:FILE   event source (default eslogger; replay:- reads stdin)
  --realtime                             replay at the recorded pace
  --data-dir DIR                         default /Library/Application Support/WhoRead
  --defaults DIR                         catalog.json / agents.json / benign.json (default: search)
  --eslogger PATH                        default /usr/bin/eslogger
  --home DIR                             monitored home (repeatable; default: all local users)
  --kill-switch PATH                     default <data-dir>/disable-enforcement
  --mach-service NAME                    XPC listener (macOS; default com.whoread.daemon.xpc)
  --no-xpc                               do not listen on XPC
  --client-requirement REQ               code-signing requirement for XPC clients
  --app-requirement REQ                  requirement identifying the WhoRead app
  --dev-socket PATH                      also serve the dev Unix socket (tests, Linux)
  --dev-socket-mode MODE                 octal, default 600
  --permissive                           dev only: any peer may change anything
  --no-seed                              do not seed the process tree from running processes
  --verbose
"""

var argv = Array(CommandLine.arguments.dropFirst())
guard let command = argv.first else {
    print(usage)
    exit(64)
}
argv.removeFirst()

func value(_ flag: String) -> String? {
    guard let i = argv.firstIndex(of: flag), i + 1 < argv.count else { return nil }
    return argv[i + 1]
}
func values(_ flag: String) -> [String] {
    var out: [String] = []
    var i = 0
    while i < argv.count {
        if argv[i] == flag, i + 1 < argv.count { out.append(argv[i + 1]); i += 2 } else { i += 1 }
    }
    return out
}
func has(_ flag: String) -> Bool { argv.contains(flag) }

switch command {
case "version":
    print("whoreadd \(WhoReadVersion.string)")
    exit(0)
case "run":
    break
default:
    print(usage)
    exit(64)
}

if has("--verbose") { Log.minimum = .debug }
var config = DaemonConfiguration()
let source = value("--source") ?? "eslogger"
if source.hasPrefix("replay:") {
    config.source = .replay
    config.replayPath = String(source.dropFirst("replay:".count))
} else if let kind = SourceKind(rawValue: source) {
    config.source = kind
} else {
    FileHandle.standardError.write(Data("unknown source \(source)\n".utf8))
    exit(64)
}
config.replayRealtime = has("--realtime")
if let d = value("--data-dir") { config.dataDirectory = d }
config.defaultsDirectory = value("--defaults")
if let e = value("--eslogger") { config.esloggerPath = e }
let homes = values("--home")
if !homes.isEmpty { config.homeDirectories = homes }
config.killSwitchPath = value("--kill-switch")
#if os(macOS)
if !has("--no-xpc") { config.machServiceName = value("--mach-service") ?? WhoReadPaths.machServiceName }
#endif
config.clientRequirement = value("--client-requirement")
config.appRequirement = value("--app-requirement")
config.devSocketPath = value("--dev-socket")
if let m = value("--dev-socket-mode"), let mode = UInt16(m, radix: 8) { config.devSocketMode = mode }
config.permissive = has("--permissive")
config.seedProcesses = !has("--no-seed")

if geteuid() != 0 && config.source != .replay {
    Log.warning("not running as root: \(config.source.rawValue) needs root (and Full Disk Access)")
}

umask(0o022)
// A client that hangs up mid-reply must cost one EPIPE, not the daemon.
signal(SIGPIPE, SIG_IGN)
let daemon: Daemon
do {
    daemon = try Daemon(configuration: config)
    try daemon.start()
} catch {
    Log.error("failed to start: \(error)")
    exit(1)
}

// Graceful shutdown on SIGINT / SIGTERM.
signal(SIGINT, SIG_IGN)
signal(SIGTERM, SIG_IGN)
let signalQueue = DispatchQueue(label: "whoread.signals")
var signalSources: [DispatchSourceSignal] = []
for sig in [SIGINT, SIGTERM] {
    let s = DispatchSource.makeSignalSource(signal: sig, queue: signalQueue)
    s.setEventHandler {
        Log.info("signal \(sig): shutting down")
        daemon.stop()
        exit(0)
    }
    s.resume()
    signalSources.append(s)
}
dispatchMain()
