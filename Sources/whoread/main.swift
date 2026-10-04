import Foundation
import WhoReadCore
import WhoReadEngine
import WhoReadIPC

let usage = """
whoread — who read my sensitive files?

Usage: whoread <command> [options]

Daemon queries (talk to whoreadd over XPC; --socket PATH for the dev socket):
  status                         daemon state, source, enforcement, counters
  events [filters]               recorded accesses (newest first)
      --since 1h|2d|2026-10-04   --until …   --category ID (repeatable)   --app TEXT
      --agent ID   --agents-only   --denied   --all (include folded system noise)   --limit N
  tail [--all]                   follow new events live
  alerts [--unread] [--limit N]
  alert <id> <allow-once|always-allow|block|keep-blocking|ignore>
  read-all                       mark every alert read
  apps | files | agents          who touched what (Apps / Files / Agents tabs)
  export --format json|jsonl|csv [--output FILE] [filters]
  enforcement on|off|status      off needs sudo (or the WhoRead app)
  pause | resume                 pause needs sudo (or the WhoRead app)
  rules [list|templates|add --json-file F|enable ID|disable ID|enforce ID|dry-run ID|delete ID]
  catalog [show|resolve-owners [--dry-run]|reset]
  settings [show | set KEY VALUE]   keys: learning-days retention-days detail-days coalesce-minutes
                                       readdir on|off  project-root-add PATH  project-root-remove PATH
                                       notifications on|off  min-severity medium|high|critical
                                       latency-p99-ms N  language en|zh-Hans|system
  baseline [restart-learning]

Local (no daemon):
  kill-switch engage|release|status [--path P]   creates/removes the disable-enforcement file (root)
  replay FILE [--home DIR] [--defaults DIR] [--learning-days N] [--all] [--json]
                                 run an eslogger JSONL capture through the full pipeline
  fixture sanitize --input RAW --output OUT [--home DIR] [--vault DIR] [--sample N]
  version

Global: --json   --lang en|zh-Hans   --service MACH_NAME   --socket PATH
"""

let args = Args(Array(CommandLine.arguments.dropFirst()))
let language: Language = {
    if let l = args.value("lang") { return l.lowercased().hasPrefix("zh") ? .zhHans : .en }
    if let env = ProcessInfo.processInfo.environment["WHOREAD_LANG"] { return env.hasPrefix("zh") ? .zhHans : .en }
    return Language.preferred(from: Locale.preferredLanguages)
}()

func out(_ s: String) { print(s) }

func makeClient() throws -> IPCClient {
    if let socket = args.value("socket") ?? ProcessInfo.processInfo.environment["WHOREAD_SOCKET"] {
        return UnixSocketClient(path: socket)
    }
    #if os(macOS)
    let name = args.value("service")
        ?? ProcessInfo.processInfo.environment["WHOREAD_MACH_SERVICE"]
        ?? (try? String(contentsOfFile: WhoReadPaths.dataDirectory + "/mach-service", encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        ?? WhoReadPaths.machServiceName
    return XPCClient(machServiceName: name)
    #else
    throw CLIError("no XPC on this platform: pass --socket PATH (whoreadd --dev-socket PATH)")
    #endif
}

func explain(_ e: IPCError) -> CLIError {
    switch e.code {
    case .notPermitted:
        return CLIError("not permitted: \(e.message)\n  e.g. sudo whoread \(CommandLine.arguments.dropFirst().joined(separator: " "))", exitCode: 77)
    case .unavailable:
        return CLIError("cannot reach the WhoRead daemon: \(e.message)\n  Is whoreadd running? (sudo launchctl print system/com.whoread.daemon)", exitCode: 69)
    default:
        return CLIError("\(e.code.rawValue): \(e.message)")
    }
}

func eventQuery() throws -> EventQuery {
    var q = EventQuery()
    if let s = args.value("since") { q.since = try Format.parseSince(s) }
    if let u = args.value("until") { q.until = try Format.parseSince(u) }
    let cats = args.all("category")
    if !cats.isEmpty { q.categoryIDs = cats }
    q.text = args.value("app")
    q.agentID = args.value("agent")
    q.agentsOnly = args.has("agents-only")
    q.includeBenign = args.has("all")
    if args.has("denied") { q.decisions = [.denied] }
    if let l = args.value("limit"), let n = Int(l) { q.limit = n }
    return q
}

struct Context {
    let catalog: Catalog?
    let homes: [String]

    var normalizer: PathNormalizer { PathNormalizer(homeDirectories: homes) }

    func categoryName(_ id: String) -> String {
        catalog?.category(id)?.name.resolve(language) ?? id
    }

    var formatter: AlertFormatter {
        let n = normalizer
        let cat = catalog
        return AlertFormatter(language: language, abbreviate: { n.abbreviate($0) }, categoryName: { cat?.category($0)?.name })
    }

    func eventLine(_ e: AnalyzedEvent) -> [String] {
        let decision: String
        switch e.decision {
        case .denied: decision = language == .zhHans ? "已拦截" : "BLOCKED"
        case .wouldDeny: decision = language == .zhHans ? "将被拦截" : "would block"
        default: decision = e.isBenign ? (language == .zhHans ? "系统(折叠)" : "system (folded)") : ""
        }
        return [Format.time(e.time), e.operation.rawValue + ":" + e.access.label,
                categoryName(e.categoryID) + "/" + e.severity.rawValue, normalizer.abbreviate(e.path),
                e.chain.displayString(responsible: e.responsible), decision]
    }
}

func context(_ client: IPCClient) -> Context {
    if let info = try? client.catalog() { return Context(catalog: info.catalog, homes: info.homeDirectories) }
    return Context(catalog: nil, homes: [])
}

func printEvents(_ events: [AnalyzedEvent], _ ctx: Context) {
    let header = language == .zhHans ? ["时间", "操作", "类别", "路径", "调用链", ""] : ["TIME", "OP", "CATEGORY", "PATH", "CHAIN", ""]
    out(Format.table(events.map(ctx.eventLine), header: header))
}

// MARK: - Commands

func cmdStatus(_ c: IPCClient) throws {
    let s = try c.status()
    if args.json { return out(try Format.json(s)) }
    let modeName: [DaemonMode: (String, String)] = [
        .learning: ("Learning", "学习中"), .monitoring: ("Monitoring", "监控中"), .enforcing: ("Enforcing", "拦截中"),
        .paused: ("Paused", "已暂停"), .error: ("Error", "错误"),
    ]
    let m = modeName[s.mode].map { language == .zhHans ? $0.1 : $0.0 } ?? s.mode.rawValue
    out("WhoRead \(s.version) — \(m)" + (s.learning ? "  (learning until \(Format.time(s.learningEndsAt)))" : ""))
    out("  source:       \(s.source.rawValue) \(s.sourceRunning ? "running" : "stopped")" + (s.sourceError.map { "  ERROR: \($0)" } ?? ""))
    if let h = s.sourceHint { out("                hint: \(h)") }
    out("  enforcement:  \(s.enforcementActive ? "ACTIVE" : "inactive") (setting \(s.enforcementEnabled ? "on" : "off"))"
        + (s.enforcementInactiveReasons.isEmpty ? "" : " — " + s.enforcementInactiveReasons.map(\.rawValue).joined(separator: ", ")))
    out("  kill switch:  file \(s.killSwitchFilePresent ? "PRESENT (enforcement forced off)" : "absent")")
    if let t = s.latencyTripReason { out("  latency trip: \(t)") }
    out("  events:       \(s.counts.events) stored (+\(s.counts.aggregatedDays) days aggregated), \(s.eventsProcessed) since start, last \(Format.ago(s.lastEventAt))")
    out("  alerts:       \(s.unreadAlerts) unread of \(s.counts.alerts)")
    out("  coverage:     \(s.monitoredPrefixes) monitored prefixes, homes \(s.homeDirectories.joined(separator: ", "))")
    if let p = s.parser {
        out("  eslogger:     \(p.lines) lines read, \(p.events) events parsed, \(p.malformed) malformed, schema \(p.schemaVersions), kernel drops \(p.droppedByKernel)")
    }
    if s.latency.samples > 0 {
        out(String(format: "  AUTH latency: p50 %.0f µs, p99 %.0f µs, max %.0f µs, %d deadline misses", s.latency.p50Micros,
                   s.latency.p99Micros, s.latency.maxMicros, s.latency.deadlineMisses))
    }
    if s.writerDropped > 0 { out("  WARNING: \(s.writerDropped) events dropped before storage") }
}

func cmdEvents(_ c: IPCClient) throws {
    let events = try c.events(try eventQuery())
    if args.json { return out(try Format.json(events)) }
    printEvents(events, context(c))
}

func cmdTail(_ c: IPCClient) throws {
    let ctx = context(c)
    var after: Int64? = (try? c.events(EventQuery(includeBenign: true, limit: 1)))?.first?.id
    out(language == .zhHans ? "正在跟踪新事件（Ctrl-C 退出）…" : "Following new events (Ctrl-C to stop)…")
    while true {
        if case .events(let events) = try c.call(.live(afterID: after, limit: 500, includeBenign: args.has("all"))), !events.isEmpty {
            for e in events {
                out(ctx.eventLine(e).filter { !$0.isEmpty }.joined(separator: "  "))
                after = e.id
            }
        }
        Thread.sleep(forTimeInterval: 0.5)
    }
}

func cmdAlerts(_ c: IPCClient) throws {
    var q = AlertQuery()
    if args.has("unread") { q.statuses = [.unread] }
    if let l = args.value("limit"), let n = Int(l) { q.limit = n }
    if let s = args.value("since") { q.since = try Format.parseSince(s) }
    let alerts = try c.alerts(q)
    if args.json { return out(try Format.json(alerts)) }
    let f = context(c).formatter
    for a in alerts {
        let status = a.status == .unread ? "●" : (a.status == .read ? "○" : "✓")
        out("\(status) #\(a.id) \(Format.time(a.updatedAt)) [\(f.kindTitle(a.kind))] \(f.line(a))")
    }
    if alerts.isEmpty { out(language == .zhHans ? "没有告警。" : "No alerts.") }
}

func cmdAlertAction(_ c: IPCClient) throws {
    guard args.positional.count >= 3, let id = Int64(args.positional[1]) else {
        throw CLIError("usage: whoread alert <id> <allow-once|always-allow|block|keep-blocking|ignore>")
    }
    let map: [String: AlertAction] = ["allow-once": .allowOnce, "always-allow": .alwaysAllow, "block": .blockFromNowOn,
                                      "keep-blocking": .keepBlocking, "ignore": .ignore]
    guard let action = map[args.positional[2]] else { throw CLIError("unknown action \(args.positional[2])") }
    _ = try c.call(.alertAction(alertID: id, action: action))
    out("alert #\(id): \(action.rawValue)")
}

func groupSummaries(_ sums: [UsageSummary], by key: (UsageSummary) -> String) -> [(String, [UsageSummary])] {
    var groups: [String: [UsageSummary]] = [:]
    var order: [String] = []
    for s in sums {
        let k = key(s)
        if groups[k] == nil { order.append(k) }
        groups[k, default: []].append(s)
    }
    return order.map { ($0, groups[$0]!) }
}

func cmdApps(_ c: IPCClient) throws {
    let since = try args.value("since").map { try Format.parseSince($0) }
    let sums = try c.summaries(since: since).filter { args.has("all") || !$0.benign }
    if args.json { return out(try Format.json(sums)) }
    let ctx = context(c)
    var rows: [[String]] = []
    for (_, group) in groupSummaries(sums, by: { $0.responsible.key }) {
        let first = group.map(\.firstSeen).min()!
        let last = group.map(\.lastSeen).max()!
        let count = group.reduce(0) { $0 + $1.count }
        let cats = Set(group.map(\.categoryID)).map(ctx.categoryName).sorted().joined(separator: ", ")
        rows.append([group[0].responsible.displayName, group[0].responsible.kind.rawValue, cats, Format.time(first), Format.time(last), String(count)])
    }
    out(Format.table(rows, header: language == .zhHans ? ["应用", "类型", "碰过的类别", "首次", "最近", "次数"] : ["APP", "KIND", "CATEGORIES", "FIRST", "LAST", "COUNT"]))
}

func cmdFiles(_ c: IPCClient) throws {
    let sums = try c.summaries(since: nil).filter { args.has("all") || !$0.benign }
    if args.json { return out(try Format.json(sums)) }
    let ctx = context(c)
    var rows: [[String]] = []
    for (cat, group) in groupSummaries(sums, by: { $0.categoryID }) {
        let apps = Set(group.map(\.responsible.displayName)).sorted().joined(separator: ", ")
        rows.append([ctx.categoryName(cat), apps, Format.time(group.map(\.lastSeen).max()!), String(group.reduce(0) { $0 + $1.count })])
    }
    out(Format.table(rows, header: language == .zhHans ? ["类别", "碰过它的应用", "最近", "次数"] : ["CATEGORY", "APPS", "LAST", "COUNT"]))
}

func cmdAgents(_ c: IPCClient) throws {
    let sums = try c.summaries(since: nil).filter { $0.agentID != nil }
    if args.json { return out(try Format.json(sums)) }
    let ctx = context(c)
    let agents = (try? c.agents()) ?? AgentCatalog(agents: [])
    var rows: [[String]] = []
    for (agent, group) in groupSummaries(sums, by: { $0.agentID! }) {
        let name = agents.agent(agent)?.name.resolve(language) ?? agent
        let cats = Set(group.map(\.categoryID)).map(ctx.categoryName).sorted().joined(separator: ", ")
        rows.append([name, cats, String(group.reduce(0) { $0 + $1.denied }), Format.time(group.map(\.lastSeen).max()!), String(group.reduce(0) { $0 + $1.count })])
    }
    out(Format.table(rows, header: language == .zhHans ? ["AI agent", "碰过的类别", "被拦截", "最近", "次数"] : ["AI AGENT", "CATEGORIES", "BLOCKED", "LAST", "COUNT"]))
}

func cmdExport(_ c: IPCClient) throws {
    guard let f = Exporter.Format(rawValue: args.value("format") ?? "json") else { throw CLIError("--format json|jsonl|csv") }
    var q = try eventQuery()
    if args.value("limit") == nil { q.limit = 1_000_000 }
    q.newestFirst = false
    let events = try c.events(q)
    let data = try Exporter.export(events: events, format: f, catalog: try? c.catalog().catalog)
    if let path = args.value("output") ?? args.value("o") {
        try data.write(to: URL(fileURLWithPath: path))
        FileHandle.standardError.write(Data("exported \(events.count) events to \(path)\n".utf8))
    } else {
        FileHandle.standardOutput.write(data)
    }
}

func cmdEnforcement(_ c: IPCClient) throws {
    switch args.positional.dropFirst().first ?? "status" {
    case "on":
        _ = try c.call(.setEnforcement(enabled: true))
    case "off":
        _ = try c.call(.setEnforcement(enabled: false))
    case "status":
        break
    case let other:
        throw CLIError("unknown: enforcement \(other)")
    }
    let s = try c.status()
    out("enforcement \(s.enforcementActive ? "ACTIVE" : "inactive") (setting \(s.enforcementEnabled ? "on" : "off"))"
        + (s.enforcementInactiveReasons.isEmpty ? "" : ": " + s.enforcementInactiveReasons.map(\.rawValue).joined(separator: ", ")))
}

func cmdRules(_ c: IPCClient) throws {
    let sub = args.positional.dropFirst().first ?? "list"
    func describe(_ r: Rule) -> [String] {
        let target: String
        switch r.target {
        case .category(let id): target = "category " + id
        case .severityAtLeast(let s): target = "severity ≥ " + s.rawValue
        case .pathPrefix(let p): target = "path " + p
        }
        let subject: String
        switch r.subject {
        case .signed(let sid, let team): subject = "signed \(sid)" + (team.map { " (\($0))" } ?? "")
        case .unsigned(let p, _): subject = "unsigned \(p)"
        case .responsible(let k, _): subject = "app \(k)"
        case .anyNonOwner: subject = "any non-owner"
        case .agentAncestor(let ids, let ex): subject = "agent chain " + (ids?.joined(separator: ",") ?? "any") + (ex ? " except owners" : "")
        }
        let state = !r.enabled ? "off" : (r.action == .deny ? (r.enforce ? "ENFORCE" : "dry-run") : "on")
        return [r.id, state, r.action.rawValue, r.access.rawValue, target, subject, r.name ?? ""]
    }
    func modify(_ id: String, _ f: (inout Rule) -> Void) throws {
        guard var r = try c.rules().first(where: { $0.id == id }) else { throw CLIError("no rule \(id)") }
        f(&r)
        _ = try c.call(.upsertRule(r))
        out(Format.table([describe(r)], header: ["ID", "STATE", "ACTION", "ACCESS", "TARGET", "SUBJECT", "NAME"]))
    }
    switch sub {
    case "list":
        let rules = try c.rules()
        if args.json { return out(try Format.json(rules)) }
        out(Format.table(rules.map(describe), header: ["ID", "STATE", "ACTION", "ACCESS", "TARGET", "SUBJECT", "NAME"]))
    case "templates":
        out(try Format.json(RuleTemplates.all))
    case "add":
        guard let file = args.value("json-file") else { throw CLIError("rules add --json-file RULE.json") }
        let data = try Data(contentsOf: URL(fileURLWithPath: file))
        let rules: [Rule]
        if let list = try? Exporter.decoder().decode([Rule].self, from: data) {
            rules = list
        } else {
            rules = [try Exporter.decoder().decode(Rule.self, from: data)]
        }
        for r in rules { _ = try c.call(.upsertRule(r)) }
        out("saved \(rules.count) rule(s)")
    case "enable": try modify(try idArg()) { $0.enabled = true }
    case "disable": try modify(try idArg()) { $0.enabled = false }
    case "enforce": try modify(try idArg()) { $0.enforce = true; $0.enabled = true }
    case "dry-run": try modify(try idArg()) { $0.enforce = false }
    case "delete":
        _ = try c.call(.deleteRule(id: try idArg()))
        out("deleted")
    default:
        throw CLIError("unknown: rules \(sub)")
    }
}

func idArg() throws -> String {
    guard args.positional.count >= 3 else { throw CLIError("missing rule id") }
    return args.positional[2]
}

func cmdCatalog(_ c: IPCClient) throws {
    switch args.positional.dropFirst().first ?? "show" {
    case "show":
        let info = try c.catalog()
        if args.json { return out(try Format.json(info)) }
        var rows: [[String]] = []
        for cat in info.catalog.categories {
            let prefixes = info.prefixes.filter { $0.categoryID == cat.id }
            let detected = info.detected[cat.id] == true ? (language == .zhHans ? "已检测到" : "detected") : (language == .zhHans ? "未检测到" : "not detected")
            rows.append([cat.id, cat.name.resolve(language), cat.severity.rawValue, cat.enabled ? detected : "disabled",
                         String(prefixes.count), String(cat.owners.count)])
        }
        out(Format.table(rows, header: ["ID", language == .zhHans ? "名称" : "NAME", "SEVERITY", "STATE", "PREFIXES", "OWNERS"]))
    case "resolve-owners":
        #if os(macOS)
        let info = try c.catalog()
        let (resolved, report) = OwnerResolver.resolve(catalog: info.catalog, reader: CodesignCommandReader(),
                                                       exists: { FileManager.default.fileExists(atPath: $0) })
        report.resolved.forEach { out("  resolved \($0)") }
        out("\(report.resolved.count) resolved, \(report.missing.count) not installed, \(report.skippedGlobs) glob patterns left as is")
        if !args.has("dry-run") {
            _ = try c.call(.updateCatalog(resolved))
            out("catalog updated")
        }
        #else
        throw CLIError("resolve-owners runs codesign and needs macOS")
        #endif
    case "reset":
        _ = try c.call(.resetCatalog)
        out("catalog reset to defaults")
    case let other:
        throw CLIError("unknown: catalog \(other)")
    }
}

func cmdSettings(_ c: IPCClient) throws {
    var s = try c.settings()
    guard args.positional.dropFirst().first == "set" else {
        return out(try Format.json(s))
    }
    guard args.positional.count >= 4 else { throw CLIError("settings set KEY VALUE") }
    let key = args.positional[2]
    let value = args.positional[3]
    func bool(_ v: String) throws -> Bool {
        switch v { case "on", "true", "yes", "1": return true; case "off", "false", "no", "0": return false
        default: throw CLIError("expected on/off") }
    }
    func number(_ v: String) throws -> Double {
        guard let d = Double(v) else { throw CLIError("expected a number") }
        return d
    }
    switch key {
    case "learning-days": s.learningDays = try number(value)
    case "retention-days": s.retentionDays = Int(try number(value))
    case "detail-days": s.detailDays = Int(try number(value))
    case "coalesce-minutes": s.coalesceMinutes = try number(value)
    case "readdir": s.readdirEnabled = try bool(value)
    case "project-root-add": s.projectRoots.append(value)
    case "project-root-remove": s.projectRoots.removeAll { $0 == value }
    case "notifications": s.notifications.enabled = try bool(value)
    case "min-severity":
        guard let sev = Severity(rawValue: value) else { throw CLIError("medium|high|critical") }
        s.notifications.minimumSeverity = sev
    case "latency-p99-ms": s.latencyP99ThresholdMs = try number(value)
    case "language": s.language = value == "system" ? nil : Language(rawValue: value)
    default: throw CLIError("unknown setting \(key)")
    }
    _ = try c.call(.updateSettings(s))
    out(try Format.json(try c.settings()))
}

func cmdBaseline(_ c: IPCClient) throws {
    if args.positional.dropFirst().first == "restart-learning" {
        _ = try c.call(.restartLearning)
        return out("learning restarted")
    }
    guard case .baseline(let entries) = try c.call(.baseline) else { return }
    if args.json { return out(try Format.json(entries)) }
    out(Format.table(entries.map { [$0.key.responsibleKey, $0.key.categoryID, $0.key.access.rawValue, $0.source.rawValue, String($0.count), Format.time($0.lastSeen)] },
                     header: ["RESPONSIBLE", "CATEGORY", "ACCESS", "SOURCE", "COUNT", "LAST"]))
}

func cmdKillSwitch() throws {
    let path = args.value("path") ?? WhoReadPaths.killSwitchFile
    switch args.positional.dropFirst().first ?? "status" {
    case "engage":
        guard FileManager.default.createFile(atPath: path, contents: Data("disabled by whoread kill-switch\n".utf8),
                                             attributes: [.posixPermissions: 0o644]) else {
            throw CLIError("cannot create \(path) (run with sudo)", exitCode: 77)
        }
        out("kill switch ENGAGED: \(path) exists; enforcement is off within ~0.2 s")
    case "release":
        if FileManager.default.fileExists(atPath: path) {
            do { try FileManager.default.removeItem(atPath: path) } catch { throw CLIError("cannot remove \(path) (run with sudo)", exitCode: 77) }
        }
        out("kill switch released")
    case "status":
        out(FileManager.default.fileExists(atPath: path) ? "kill switch ENGAGED (\(path))" : "kill switch not engaged")
    case let other:
        throw CLIError("unknown: kill-switch \(other)")
    }
}

func cmdReplay() throws {
    guard args.positional.count >= 2 else { throw CLIError("whoread replay FILE.jsonl") }
    if !args.has("verbose") { Log.minimum = .warning }
    var config = DaemonConfiguration()
    config.source = .replay
    config.replayPath = args.positional[1]
    config.inMemoryStore = true
    config.defaultsDirectory = args.value("defaults")
    config.seedProcesses = false
    let homes = args.all("home")
    config.homeDirectories = homes.isEmpty ? nil : homes
    let core = try DaemonCore(config: config)
    if let d = args.value("learning-days"), let days = Double(d) {
        var s = core.currentSettings
        s.learningDays = days
        try core.update(settings: s, peer: .inProcess)
    }
    try core.source.start(sink: core.pipeline)
    guard let replay = core.source as? ReplaySource, replay.waitUntilFinished(timeout: 600) else { throw CLIError("replay timed out") }
    core.writer.flush()
    let client = InProcessClient(handler: Daemon.handlerForReplay(core))
    let events = try client.events(EventQuery(includeBenign: args.has("all"), limit: 1_000_000, newestFirst: false))
    let alerts = try client.alerts(AlertQuery())
    if args.json {
        struct Result: Encodable { var events: [AnalyzedEvent]; var alerts: [Alert]; var parser: EsloggerParser.Stats? }
        return out(try Format.json(Result(events: events, alerts: alerts, parser: replay.parserStats)))
    }
    let ctx = Context(catalog: core.analyzer.classifier.catalog, homes: core.homes)
    printEvents(events, ctx)
    out("")
    let f = ctx.formatter
    for a in alerts.reversed() { out("#\(a.id) [\(f.kindTitle(a.kind))] \(f.line(a))") }
    if let p = replay.parserStats {
        out("\nparsed \(p.events) events from \(p.lines) lines (\(p.malformed) malformed, schema \(p.schemaVersions)); \(events.count) sensitive accesses, \(alerts.count) alerts")
    }
}

func cmdFixture() throws {
    guard args.positional.dropFirst().first == "sanitize", let input = args.value("input"), let output = args.value("output") else {
        throw CLIError("whoread fixture sanitize --input RAW.jsonl --output OUT.jsonl [--home DIR] [--vault DIR] [--sample N]")
    }
    let home = args.value("home") ?? NSHomeDirectory()
    let text = try String(contentsOfFile: input, encoding: .utf8)
    let lines = text.split(separator: "\n", omittingEmptySubsequences: true).map(String.init)
    let sanitizer = FixtureSanitizer(home: home, vault: args.value("vault"), samplePerKind: Int(args.value("sample") ?? "40") ?? 40)
    let (kept, report) = sanitizer.sanitize(lines: lines)
    try (kept.joined(separator: "\n") + "\n").write(toFile: output, atomically: true, encoding: .utf8)
    out("kept \(report.kept) of \(report.inputLines) lines: \(report.vaultEvents) vault events, \(report.lifecycle) lifecycle, \(report.samples) samples; by kind \(report.byKind)")
}

// MARK: - Dispatch

do {
    guard let command = args.positional.first, !args.has("help"), !args.has("h") else {
        out(usage)
        exit(args.positional.isEmpty && !args.has("help") ? 64 : 0)
    }
    switch command {
    case "version": out("whoread \(WhoReadVersion.string)")
    case "kill-switch": try cmdKillSwitch()
    case "replay": try cmdReplay()
    case "fixture": try cmdFixture()
    case "help": out(usage)
    default:
        let client = try makeClient()
        do {
            switch command {
            case "status": try cmdStatus(client)
            case "events": try cmdEvents(client)
            case "tail": try cmdTail(client)
            case "alerts": try cmdAlerts(client)
            case "alert": try cmdAlertAction(client)
            case "read-all": _ = try client.call(.markAlertsRead(ids: nil)); out("all alerts marked read")
            case "apps": try cmdApps(client)
            case "files": try cmdFiles(client)
            case "agents": try cmdAgents(client)
            case "export": try cmdExport(client)
            case "enforcement": try cmdEnforcement(client)
            case "pause": _ = try client.call(.setPaused(true)); out("monitoring paused")
            case "resume": _ = try client.call(.setPaused(false)); out("monitoring resumed")
            case "rules": try cmdRules(client)
            case "catalog": try cmdCatalog(client)
            case "settings": try cmdSettings(client)
            case "baseline": try cmdBaseline(client)
            default: throw CLIError("unknown command \(command)\n\n\(usage)", exitCode: 64)
            }
        } catch let e as IPCError {
            throw explain(e)
        }
    }
} catch let e as CLIError {
    FileHandle.standardError.write(Data("whoread: \(e.message)\n".utf8))
    exit(e.exitCode)
} catch {
    FileHandle.standardError.write(Data("whoread: \(error)\n".utf8))
    exit(1)
}
