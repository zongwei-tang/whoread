import Foundation
import WhoReadCore
import WhoReadEngine
import WhoReadIPC

let usage = """
whoread — who read my sensitive files?

Usage: whoread <command> [options]

Daemon queries (talk to whoreadd over XPC; --socket PATH for the dev socket):
  status                         daemon state, source, enforcement, open questions, counters
  events [filters]               recorded accesses (newest first)
      --since 1h|2d|2026-10-04|"2026-10-04 09:30"   --until …   (no offset = local time)
      --category ID (repeatable)   --app TEXT   --agent ID   --agents-only   --denied
      --all (include folded system noise)   --limit N
  tail [--all]                   follow new events live
  asks [--json]                  questions waiting for your answer (ask mode, see below)
  ask <id> deny|block            deny now | deny now and from now on (saves a deny rule)
  ask <id> allow-once|allow      allow for 10 minutes | always (saves an allow rule); needs sudo
  ask <id> trust-apple           allow all Apple programs without asking (never under an AI agent);
                                 needs sudo
  alerts [--unread] [--since …] [--limit N]
  alert <id> block               deny this app from now on (alert stays open without sudo)
  alert <id> allow-once|always-allow|keep-blocking|ignore|trust-apple   needs sudo (or the WhoRead app)
  read-all                       mark every alert read; needs sudo (or the WhoRead app)
  apps | files | agents          who touched what (Apps / Files / Agents tabs)
  daily [--since …] [filters]    per-day totals for days past the detail window (detail-days)
  export --format json|jsonl|csv [--output FILE] [filters]      all matching events, oldest first
  export --aggregates --format json|jsonl|csv [--output FILE] [--since …]   per-day totals
  enforcement on|off|status      off needs sudo (or the WhoRead app)
  pause | resume                 pause needs sudo (or the WhoRead app)
  rules [list|templates|add --json-file F|enable ID|disable ID|enforce ID|dry-run ID|delete ID]
  rules replace --json-file F --confirm   replace every rule (recovery after stored rules failed to
                                          load; the old rows are kept in the rules_backup table)
  catalog [show [ID]|export [--output FILE]|resolve-owners]
                                   resolve-owners: show the owner team/signing IDs codesign reports
                                   for installed apps (the daemon applies them in memory at start)
  catalog add-path|remove-path CATEGORY PATH        PATH starts with / or ~/
  catalog add-category ID NAME_EN NAME_ZH medium|high|critical [--path PATH]...
  catalog remove-category ID | set-severity ID SEVERITY | enable ID | disable ID
  catalog import FILE | reset
  settings [show | set KEY VALUE]   keys: retention-days detail-days coalesce-minutes
                                       readdir on|off  project-root-add PATH  project-root-remove PATH
                                       notifications on|off  min-severity medium|high|critical
                                       latency-p99-ms N (status warning)  language en|zh-Hans|system
                                       trust-apple on|off (allow Apple programs without asking)
  baseline                       (app, category, access) combinations seen so far
  Changes that can weaken protection (settings set, rule edits other than adding a deny or alert
  rule, catalog changes, allowing a question) need sudo (or the WhoRead app).

Ask mode: with enforcement on, an access that nothing decides yet (no rule, not an owner, not a
system service) is held and you are asked: `whoread asks`, or the WhoRead app. Your answer is saved
as a rule, so each app × category × access is asked once. Unanswered in time, the access is denied
and the question stays open. Enforcement is never switched off automatically: only
`sudo whoread enforcement off`, the app's switch or `sudo whoread kill-switch engage` turn it off.

Local (no daemon):
  kill-switch engage|release|status [--path P]   creates/removes the disable-enforcement file (root)
  replay FILE [--home DIR] [--defaults DIR] [--all] [--json]
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

/// Text for a person, line by line: every line is escaped (`DisplayText.lines`), so nothing printed
/// here can carry a terminal escape sequence, whatever a value inside it missed. Values are escaped
/// (and names capped) where they are put in, too, so tables line up.
func out(_ s: String) { print(DisplayText.lines(s)) }

/// JSON stays exact for programs (it decodes to the same values) and inert in a terminal: hidden
/// characters JSONEncoder leaves raw are written as `\u` escapes (`Format.terminalSafeJSON`).
func outJSON(_ s: String) { print(Format.terminalSafeJSON(s)) }

/// Writes text for a person to stderr, escaped like `out`.
func note(_ s: String) { FileHandle.standardError.write(Data((DisplayText.lines(s) + "\n").utf8)) }

/// The request never got an answer (no daemon, timeout, connection lost), as opposed to an
/// `.error` the daemon replied with.
struct Unreachable: Error { let error: IPCError }

/// Turns the errors a transport throws into `Unreachable`; the daemon's own `.error` replies still
/// come out of `call` as `IPCError`.
struct TransportClient: IPCClient {
    let transport: IPCClient
    func send(_ request: IPCRequest) throws -> IPCResponse {
        do { return try transport.send(request) } catch let e as IPCError { throw Unreachable(error: e) }
    }
}

func makeClient() throws -> IPCClient {
    if let socket = args.value("socket") ?? ProcessInfo.processInfo.environment["WHOREAD_SOCKET"] {
        return TransportClient(transport: UnixSocketClient(path: socket))
    }
    #if os(macOS)
    let name = args.value("service")
        ?? ProcessInfo.processInfo.environment["WHOREAD_MACH_SERVICE"]
        ?? (try? String(contentsOfFile: WhoReadPaths.dataDirectory + "/mach-service", encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        ?? WhoReadPaths.machServiceName
    return TransportClient(transport: XPCClient(machServiceName: name))
    #else
    throw CLIError("no XPC on this platform: pass --socket PATH (whoreadd --dev-socket PATH)")
    #endif
}

/// `s` as one shell word, so a suggested command can be pasted as is. `~` is quoted too: the shell
/// would expand it to one home, while whoread takes `~/` to mean every monitored home.
func shellWord(_ s: String) -> String {
    let plain = !s.isEmpty && !s.hasPrefix("=")
        && s.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "-_./=:@%+,".unicodeScalars.contains($0)) }
    return plain ? s : "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

/// This very command under sudo, pasteable as is.
var sudoCommand: String { "sudo whoread " + CommandLine.arguments.dropFirst().map(shellWord).joined(separator: " ") }

/// An error the daemon replied with.
func explain(_ e: IPCError) -> CLIError {
    switch e.code {
    case .notPermitted:
        return CLIError("not permitted: \(DisplayText.escaped(e.message))\n  e.g. \(sudoCommand)", exitCode: 77)
    default:
        return CLIError("\(e.code.rawValue): \(DisplayText.escaped(e.message))")
    }
}

func explain(_ u: Unreachable) -> CLIError {
    CLIError("cannot reach the WhoRead daemon: \(DisplayText.escaped(u.error.message))\n  Is whoreadd running? (sudo launchctl print system/com.whoread.daemon)", exitCode: 69)
}

/// One `.hello` before the first real request, so a whoread/daemon version skew is reported as
/// such instead of as an undecodable request or reply.
func handshake(_ c: IPCClient) throws {
    func mismatch(_ detail: String) -> CLIError {
        CLIError("whoread (IPC protocol \(whoReadIPCVersion)) and the running daemon do not match: \(detail)\n"
                 + "  Use the whoread that ships with the installed WhoRead app, or restart the daemon after an update.",
                 exitCode: 69)
    }
    let reply: IPCResponse
    do {
        reply = try c.send(.hello(clientVersion: whoReadIPCVersion))
    } catch is DecodingError {
        throw mismatch("unreadable reply")
    }
    switch reply {
    case .hello(let v) where v == whoReadIPCVersion: return
    case .hello(let v): throw mismatch("daemon speaks protocol \(v)")
    case .error(let e) where e.code == .versionMismatch: throw mismatch(e.message)
    case .error(let e): throw e
    default: throw mismatch("unexpected reply")
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
        DisplayText.name(catalog?.category(id)?.name.resolve(language) ?? id)
    }

    func agentName(_ id: String, _ agents: AgentCatalog) -> String {
        DisplayText.name(agents.agent(id)?.name.resolve(language) ?? id)
    }

    /// "Program: ~/x/Terminal.app (not signed by an identified developer)" (guard-4: the name is the
    /// program's own choice, its place and signer are not).
    func identity(_ alert: Alert) -> String? { formatter.identityLine(alert) }

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
        // `tail` prints these cells without `Format.table`: each is escaped here.
        return [Format.time(e.time), e.operation.rawValue + ":" + e.access.label,
                categoryName(e.categoryID) + "/" + e.severity.rawValue, DisplayText.escaped(normalizer.abbreviate(e.path)),
                DisplayText.chain(e.chain, responsible: e.responsible), decision]
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
    if args.json { return outJSON(try Format.json(s)) }
    let modeName: [DaemonMode: (String, String)] = [
        .learning: ("Learning", "学习中"), .monitoring: ("Monitoring", "监控中"), .enforcing: ("Enforcing", "拦截中"),
        .paused: ("Paused", "已暂停"), .error: ("Error", "错误"),
    ]
    let m = modeName[s.mode].map { language == .zhHans ? $0.1 : $0.0 } ?? s.mode.rawValue
    // Settings only add warnings: a daemon that cannot send them still gets a full status.
    let settings = try? c.settings()
    out("WhoRead \(s.version) — \(m)")
    out("  source:       \(s.source.rawValue) \(s.sourceRunning ? "running" : "stopped")"
        + (s.sourceError.map { "  ERROR: \(DisplayText.escaped($0))" } ?? ""))
    if let h = s.sourceHint { out("                hint: \(DisplayText.escaped(h))") }
    if let d = s.sourceDeadlineMissMode { out("  deadline:     AUTH " + NativeDeadlineMissMode.statusDescription(d)) }
    out("  enforcement:  \(s.enforcementActive ? "ACTIVE" : "inactive") (setting \(s.enforcementEnabled ? "on" : "off"))"
        + (s.enforcementInactiveReasons.isEmpty ? "" : " — " + s.enforcementInactiveReasons.map(\.rawValue).joined(separator: ", ")))
    out("  kill switch:  file \(s.killSwitchFilePresent ? "PRESENT (enforcement forced off)" : "absent")")
    if let n = s.pendingAsks {
        out("  questions:    " + (n == 0 ? "none waiting" : "\(n) waiting for your answer (whoread asks)"))
    }
    if settings?.trustApplePrograms == true {
        out("  trust Apple:  on (Apple programs in system locations are not asked, unless an AI agent is in the chain)")
    }
    if let u = s.uncleanStop {
        out("  unclean stop: \(DisplayText.escaped(u)); enforcement was kept as you set it")
    }
    out("  events:       \(s.counts.events) stored (+\(s.counts.aggregatedDays) days aggregated), \(s.eventsProcessed) since start, last \(Format.ago(s.lastEventAt))")
    out("  alerts:       \(s.unreadAlerts) unread of \(s.counts.alerts)")
    out("  coverage:     \(s.monitoredPrefixes) monitored prefixes, homes \(s.homeDirectories.map { DisplayText.escaped($0) }.joined(separator: ", "))")
    if let p = s.parser {
        out("  eslogger:     \(p.lines) lines read, \(p.events) events parsed, \(p.malformed) malformed, schema \(p.schemaVersions), kernel drops \(p.droppedByKernel)")
    }
    if s.latency.samples > 0 {
        out(String(format: "  AUTH latency: p50 %.0f µs, p99 %.0f µs, max %.0f µs, %d deadline misses", s.latency.p50Micros,
                   s.latency.p99Micros, s.latency.maxMicros, s.latency.deadlineMisses))
        if let t = settings?.latencyP99ThresholdMs, s.latency.p99Micros > t * 1000 {
            out(String(format: "  WARNING: AUTH p99 latency %.1f ms is over latency-p99-ms %.0f ms (enforcement stays on)",
                       s.latency.p99Micros / 1000, t))
        }
    }
    // Missed deadlines never switch enforcement off: only counted. The kernel allowed those accesses,
    // unless the native client runs in fail-closed mode (macOS 27), where it denied them.
    if s.latency.deadlineMisses > 0 {
        let outcome = NativeDeadlineMissMode.missesDenied(s.sourceDeadlineMissMode) ? "denied" : "allowed"
        out("  WARNING: \(s.latency.deadlineMisses) AUTH deadline miss\(s.latency.deadlineMisses == 1 ? "" : "es"): "
            + "the kernel \(outcome) those accesses; enforcement stays on (turn it off by hand: sudo whoread enforcement off)")
    }
    if s.writerDropped > 0 { out("  WARNING: \(s.writerDropped) events dropped before storage") }
    if let d = s.sourceDroppedEvents, d > 0 {
        out("  WARNING: \(d) events dropped or merged by the source (analysis backlog full; denials were still enforced)")
    }
    if s.parser == nil, let k = s.sourceKernelDrops, k > 0 { out("  WARNING: \(k) events dropped by the kernel before the source saw them") }
    if let e = s.rulesLoadError { out("  WARNING: stored rules failed to load (\(DisplayText.escaped(e))); enforcement stays off") }
}

/// Details older than `detailDays` survive only as per-day totals: say so when `--since` reaches
/// past them, instead of silently returning a shorter history.
func noteRolledUp(_ c: IPCClient, since: Date?) {
    guard let since, let s = try? c.settings(), since < Date().addingTimeInterval(-Double(s.detailDays) * 86400) else { return }
    let text = language == .zhHans
        ? "注意：超过 \(s.detailDays) 天的明细只保留按天汇总，见 `whoread daily` 或 `whoread export --aggregates`。"
        : "note: details older than \(s.detailDays) day\(s.detailDays == 1 ? "" : "s") are kept only as per-day totals; "
            + "see `whoread daily` or `whoread export --aggregates`."
    note(text)
}

func cmdEvents(_ c: IPCClient) throws {
    let q = try eventQuery()
    noteRolledUp(c, since: q.since)
    let events = try c.events(q)
    if args.json { return outJSON(try Format.json(events)) }
    printEvents(events, context(c))
}

/// The store applies a page's LIMIT before it drops rows it cannot decode (written by a newer
/// build, or damaged), so a page can come back short, or empty, with matching events still
/// beyond it. For a page `q` that came back empty: true when it held only such rows, so every
/// matching row in (afterID, afterID + limit] is undecodable and can be stepped over. A newer
/// matching event must exist, and the page must still be empty when read again after that probe
/// (so an event arriving in between does not pass for a skipped block).
func onlyUndecodable(_ c: IPCClient, _ q: EventQuery) throws -> Bool {
    var probe = q
    probe.limit = 1
    probe.newestFirst = true
    guard try !c.events(probe).isEmpty else { return false }
    return try c.events(q).isEmpty
}

func cmdTail(_ c: IPCClient) throws {
    let ctx = context(c)
    var after: Int64? = try c.events(EventQuery(includeBenign: true, limit: 1)).first?.id
    out(language == .zhHans ? "正在跟踪新事件（Ctrl-C 退出）…" : "Following new events (Ctrl-C to stop)…")
    fflush(stdout)
    // Pages from the store in id order (not the live ring's newest-N), so a burst larger than one
    // page is printed in full.
    let page = 1000
    while true {
        let q = EventQuery(includeBenign: args.has("all"), afterID: after, limit: page, newestFirst: false)
        let events = try c.events(q)
        if events.isEmpty, try onlyUndecodable(c, q) {
            after = (after ?? 0) + Int64(page)
            continue
        }
        for e in events {
            out(ctx.eventLine(e).filter { !$0.isEmpty }.joined(separator: "  "))
            after = e.id
        }
        fflush(stdout)
        if events.count < page { Thread.sleep(forTimeInterval: 0.5) }
    }
}

/// `whoread alert ID WORD`.
let alertActionWords: [(word: String, action: AlertAction)] = [
    ("allow-once", .allowOnce), ("always-allow", .alwaysAllow), ("keep-blocking", .keepBlocking), ("block", .blockFromNowOn),
    ("ignore", .ignore), ("trust-apple", .trustApplePrograms),
]

func cmdAlerts(_ c: IPCClient) throws {
    var q = AlertQuery()
    if args.has("unread") { q.statuses = [.unread] }
    if let l = args.value("limit"), let n = Int(l) { q.limit = n }
    if let s = args.value("since") { q.since = try Format.parseSince(s) }
    let alerts = try c.alerts(q)
    if args.json { return outJSON(try Format.json(alerts)) }
    let ctx = context(c)
    let f = ctx.formatter
    for a in alerts {
        let status = a.status == .unread ? "●" : (a.status == .read ? "○" : "✓")
        out("\(status) #\(a.id) \(Format.time(a.updatedAt)) [\(f.kindTitle(a.kind))] \(f.line(a))")
        // Before answering one: where the program really is and who signed it.
        if a.status != .resolved, let identity = ctx.identity(a) { out("    " + identity) }
        // An ask alert waits for a decision: show how to give it from here.
        if a.kind == .ask && a.status != .resolved {
            let words = a.availableActions.compactMap { action in alertActionWords.first { $0.action == action }?.word }
            out("    " + (language == .zhHans ? "回答：" : "answer: ") + "whoread alert \(a.id) " + words.joined(separator: "|"))
        }
    }
    if alerts.isEmpty { out(language == .zhHans ? "没有告警。" : "No alerts.") }
}

func cmdAlertAction(_ c: IPCClient) throws {
    guard args.positional.count >= 3, let id = Int64(args.positional[1]) else {
        throw CLIError("usage: whoread alert <id> <" + alertActionWords.map(\.word).joined(separator: "|") + ">")
    }
    guard let action = alertActionWords.first(where: { $0.word == args.positional[2] })?.action else {
        throw CLIError("unknown action \(args.positional[2])")
    }
    _ = try c.call(.alertAction(alertID: id, action: action))
    out("alert #\(id): \(action.rawValue)")
    if action == .blockFromNowOn && geteuid() != 0 {
        // The daemon adds the deny rule for anyone, but only root or the app may close the alert.
        out(language == .zhHans ? "  已添加拦截规则；告警本身仍保持打开，请在 WhoRead 应用中处理（或用 sudo）。"
                                : "  deny rule added; the alert itself stays open: handle it in the WhoRead app (or with sudo).")
    }
}

// MARK: - Ask mode (docs/ASK_MODE.md)

/// `whoread ask ID WORD`. `always-allow` and `keep-blocking` are the `alert` command's words for
/// the same answers.
let askAnswerWords: [(word: String, action: AlertAction)] = [
    ("allow-once", .allowOnce), ("allow", .alwaysAllow), ("deny", .keepBlocking), ("block", .blockFromNowOn),
    ("trust-apple", .trustApplePrograms), ("always-allow", .alwaysAllow), ("keep-blocking", .keepBlocking),
]

func cmdAsks(_ c: IPCClient) throws {
    guard case .asks(let asks) = try c.call(.asks) else { throw IPCError(.internalError, "unexpected response") }
    if args.json { return outJSON(try Format.json(asks)) }
    let zh = language == .zhHans
    if asks.isEmpty { return out(zh ? "没有等待回答的问题。" : "No questions waiting.") }
    let ctx = context(c)
    let agents = (try? c.agents()) ?? AgentCatalog(agents: [])
    let rows = asks.map { r -> [String] in
        let agentIDs = r.key.chainAgents.isEmpty ? (r.agentID.map { [$0] } ?? []) : r.key.chainAgents
        // The APP name is the program's own choice (a bundle can be called "Terminal"): PROGRAM says
        // where it really is and who signed it.
        let program = r.responsible.path.map { DisplayText.path(ctx.normalizer.abbreviate($0)) }.map { path in
            AlertFormatter.signer(of: r.responsible, chain: r.chain).map { path + " (" + ctx.formatter.signerName($0) + ")" } ?? path
        } ?? ""
        return [String(r.id), DisplayText.name(r.responsible.displayName), program, ctx.categoryName(r.key.categoryID) + "/" + r.severity.rawValue,
                r.key.access.label, ctx.normalizer.abbreviate(r.path),
                agentIDs.map { ctx.agentName($0, agents) }.joined(separator: ", "),
                "\(r.holding)/\(r.attempts)", r.appleProgram ? (zh ? "是" : "yes") : ""]
    }
    out(Format.table(rows, header: zh ? ["编号", "应用", "程序", "类别", "访问", "路径", "AI agent", "等待/次数", "苹果程序"]
                                      : ["ID", "APP", "PROGRAM", "CATEGORY", "ACCESS", "PATH", "AGENT", "WAITING/ATTEMPTS", "APPLE"]))
    out(zh ? "\n回答：whoread ask 编号 allow-once|allow|deny|block|trust-apple（允许需要 sudo）"
           : "\nanswer: whoread ask ID allow-once|allow|deny|block|trust-apple (allowing needs sudo)")
}

func cmdAsk(_ c: IPCClient) throws {
    let usage = "usage: whoread ask <id> allow-once|allow|deny|block|trust-apple"
    guard args.positional.count == 3, let id = Int64(args.positional[1]) else { throw CLIError(usage) }
    guard let action = askAnswerWords.first(where: { $0.word == args.positional[2] })?.action else {
        throw CLIError("unknown answer \(args.positional[2])\n\(usage)")
    }
    let zh = language == .zhHans
    let reply: IPCResponse
    do {
        reply = try c.call(.answerAsk(id: id, action: action))
    } catch let e as IPCError where e.code == .notPermitted && [.allowOnce, .alwaysAllow, .trustApplePrograms].contains(action) {
        // Denying is open to the console user; allowing needs root or the signed app, so an AI agent
        // running as the user can turn its own question down but never approve it.
        throw CLIError(zh ? "不允许：\(DisplayText.escaped(e.message))\n  允许访问需要 root 或 WhoRead 应用（以你的身份运行的 AI agent 只能拒绝，不能允许）。\n  例如 \(sudoCommand)"
                          : "not permitted: \(DisplayText.escaped(e.message))\n  Allowing needs root or the WhoRead app (an AI agent running as you can deny, never allow).\n  e.g. \(sudoCommand)",
                       exitCode: 77)
    }
    let done: (en: String, zh: String)
    switch action {
    case .allowOnce: done = ("allowed for 10 minutes", "已允许 10 分钟")
    case .alwaysAllow: done = ("always allowed (saved as an allow rule)", "已始终允许（已保存为允许规则）")
    case .blockFromNowOn: done = ("denied, now and from now on (saved as a deny rule)", "已拒绝，以后也拦截（已保存为拦截规则）")
    case .trustApplePrograms: done = ("allowed; Apple programs are no longer asked (trust-apple on)", "已允许；以后不再询问苹果程序（trust-apple 已打开）")
    default: done = ("denied", "已拒绝")
    }
    out((zh ? "问题 #\(id)：" : "question #\(id): ") + (zh ? done.zh : done.en))
    if case .asks(let remaining) = reply, !remaining.isEmpty {
        out(zh ? "  还有 \(remaining.count) 个问题等待回答：whoread asks" : "  \(remaining.count) more waiting: whoread asks")
    }
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
    if args.json { return outJSON(try Format.json(sums)) }
    let ctx = context(c)
    var rows: [[String]] = []
    for (_, group) in groupSummaries(sums, by: { $0.responsible.key }) {
        let first = group.map(\.firstSeen).min()!
        let last = group.map(\.lastSeen).max()!
        let count = group.reduce(0) { $0 + $1.count }
        let cats = Set(group.map(\.categoryID)).map(ctx.categoryName).sorted().joined(separator: ", ")
        rows.append([DisplayText.name(group[0].responsible.displayName), group[0].responsible.kind.rawValue, cats, Format.time(first), Format.time(last), String(count)])
    }
    out(Format.table(rows, header: language == .zhHans ? ["应用", "类型", "碰过的类别", "首次", "最近", "次数"] : ["APP", "KIND", "CATEGORIES", "FIRST", "LAST", "COUNT"]))
}

func cmdFiles(_ c: IPCClient) throws {
    let sums = try c.summaries(since: nil).filter { args.has("all") || !$0.benign }
    if args.json { return outJSON(try Format.json(sums)) }
    let ctx = context(c)
    var rows: [[String]] = []
    for (cat, group) in groupSummaries(sums, by: { $0.categoryID }) {
        let apps = Set(group.map { DisplayText.name($0.responsible.displayName) }).sorted().joined(separator: ", ")
        rows.append([ctx.categoryName(cat), apps, Format.time(group.map(\.lastSeen).max()!), String(group.reduce(0) { $0 + $1.count })])
    }
    out(Format.table(rows, header: language == .zhHans ? ["类别", "碰过它的应用", "最近", "次数"] : ["CATEGORY", "APPS", "LAST", "COUNT"]))
}

func cmdAgents(_ c: IPCClient) throws {
    let sums = try c.summaries(since: nil).filter { $0.agentID != nil }
    if args.json { return outJSON(try Format.json(sums)) }
    let ctx = context(c)
    let agents = (try? c.agents()) ?? AgentCatalog(agents: [])
    var rows: [[String]] = []
    for (agent, group) in groupSummaries(sums, by: { $0.agentID! }) {
        let name = ctx.agentName(agent, agents)
        let cats = Set(group.map(\.categoryID)).map(ctx.categoryName).sorted().joined(separator: ", ")
        rows.append([name, cats, String(group.reduce(0) { $0 + $1.denied }), Format.time(group.map(\.lastSeen).max()!), String(group.reduce(0) { $0 + $1.count })])
    }
    out(Format.table(rows, header: language == .zhHans ? ["AI agent", "碰过的类别", "被拦截", "最近", "次数"] : ["AI AGENT", "CATEGORIES", "BLOCKED", "LAST", "COUNT"]))
}

/// Daily aggregates matching the event filters (the daemon applies `--since`).
func dailyRows(_ c: IPCClient) throws -> [DailyAggregate] {
    let q = try eventQuery()
    let rows = try c.dailyAggregates(since: q.since).filter { a in
        let s = a.summary
        if let until = q.until, s.firstSeen > until { return false }
        if let cats = q.categoryIDs, !cats.contains(s.categoryID) { return false }
        if let agent = q.agentID, s.agentID != agent { return false }
        if q.agentsOnly && s.agentID == nil { return false }
        if !q.includeBenign && s.benign { return false }
        if q.decisions != nil && s.denied == 0 { return false }
        if let t = q.text?.lowercased(), !t.isEmpty, !s.responsible.displayName.lowercased().contains(t) { return false }
        return true
    }
    return args.value("limit") == nil ? rows : Array(rows.prefix(max(0, q.limit)))
}

func cmdDaily(_ c: IPCClient) throws {
    let rows = try dailyRows(c)
    if args.json { return outJSON(try Format.json(rows)) }
    if rows.isEmpty {
        return out(language == .zhHans ? "还没有按天汇总的历史（超过 detail-days 天的明细会汇总到这里）。"
                                       : "No per-day history yet (details older than detail-days are rolled up here).")
    }
    let ctx = context(c)
    let agents = (try? c.agents()) ?? AgentCatalog(agents: [])
    let table = rows.map { a -> [String] in
        let s = a.summary
        return [a.day, DisplayText.name(s.responsible.displayName), ctx.categoryName(s.categoryID),
                s.agentID.map { ctx.agentName($0, agents) } ?? "",
                String(s.count), String(s.reads), String(s.writes), String(s.denied)]
    }
    out(Format.table(table, header: language == .zhHans ? ["日期", "应用", "类别", "AI agent", "次数", "读", "写", "被拦截"]
                                                        : ["DAY", "APP", "CATEGORY", "AI AGENT", "COUNT", "READS", "WRITES", "BLOCKED"]))
}

/// Writes an export to stdout, or to FILE through FILE.partial renamed at the end so a failed
/// export never leaves a truncated file. Buffered, so a small export goes out in one write.
final class ExportWriter {
    private let handle: FileHandle
    private let staged: StagedFile?
    private var buffer = Data()

    init(path: String?) throws {
        if let path {
            // Owner-only (0600) from the first byte whatever the umask (history names every user's
            // protected files), never through a link or into a file someone else created, and renamed
            // inside the directory opened at the start (privacy-4).
            do { staged = try StagedFile(path: path, mode: 0o600) } catch {
                throw CLIError("cannot write \(path): \(error)")
            }
            handle = staged!.handle
        } else {
            staged = nil
            handle = FileHandle.standardOutput
        }
    }

    func write(_ data: Data) throws {
        buffer.append(data)
        if buffer.count >= 1 << 20 { try flush() }
    }

    func write(_ s: String) throws { try write(Data(s.utf8)) }

    private func flush() throws {
        guard !buffer.isEmpty else { return }
        try handle.write(contentsOf: buffer)
        buffer.removeAll(keepingCapacity: true)
    }

    func finish() throws {
        try flush()
        guard let staged else { return }
        do { try staged.commit() } catch let e as StagedFile.Failure { throw CLIError(e.description) }
    }

    func abandon() {
        staged?.abandon()
    }
}

/// Events per request: far below the dev socket's 64 MiB reply frame and the store's 100k cap.
let exportPageSize = 5_000

func cmdExport(_ c: IPCClient) throws {
    guard let f = Exporter.Format(rawValue: args.value("format") ?? "json") else { throw CLIError("--format json|jsonl|csv") }
    let path = args.value("output") ?? args.value("o")
    let writer = try ExportWriter(path: path)
    let count: Int
    do {
        count = args.has("aggregates") ? try exportAggregates(c, format: f, to: writer) : try exportEvents(c, format: f, to: writer)
        try writer.finish()
    } catch {
        writer.abandon()
        throw error
    }
    if let path {
        FileHandle.standardError.write(Data("exported \(count) \(args.has("aggregates") ? "daily aggregates" : "events") to \(path)\n".utf8))
    }
}

/// Every matching event, oldest first, fetched in pages and streamed out.
func exportEvents(_ c: IPCClient, format f: Exporter.Format, to w: ExportWriter) throws -> Int {
    var q = try eventQuery()
    noteRolledUp(c, since: q.since)
    let total = args.value("limit") == nil ? Int.max : max(0, q.limit)
    q.newestFirst = false
    // Pin the end of the window so a busy machine cannot keep the export chasing new events.
    if q.until == nil { q.until = Date() }
    let catalog = try? c.catalog().catalog
    let pretty = Exporter.encoder(pretty: true)
    let compact = Exporter.encoder(pretty: false)
    switch f {
    case .json: try w.write("[")
    case .jsonl: break
    case .csv: try w.write(Exporter.csvColumns.joined(separator: ",") + "\n")
    }
    var count = 0
    // Pages shrink when the store drops rows it cannot decode: page on until an empty one, and
    // say so when rows went missing (a short page with more after it, or a skipped block).
    var short = false
    var skipped = false
    while count < total {
        q.limit = min(exportPageSize, total - count)
        let page = try c.events(q)
        guard let last = page.last else {
            guard try onlyUndecodable(c, q) else { break }
            q.afterID = (q.afterID ?? 0) + Int64(q.limit)
            skipped = true
            continue
        }
        skipped = skipped || short
        short = page.count < q.limit
        switch f {
        case .json:
            for (i, e) in page.enumerated() {
                // Hidden characters as \u escapes, as for --json (the same values decode).
                let item = Format.terminalSafeJSON(String(decoding: try pretty.encode(e), as: UTF8.self)).replacingOccurrences(of: "\n", with: "\n  ")
                try w.write((count + i == 0 ? "\n  " : ",\n  ") + item)
            }
        case .jsonl:
            for e in page {
                try w.write(Format.terminalSafeJSON(String(decoding: try compact.encode(e), as: UTF8.self)))
                try w.write("\n")
            }
        case .csv:
            // The header went out once above; drop the one Exporter puts on every page.
            let csv = Exporter.csv(events: page, catalog: catalog)
            if let nl = csv.firstIndex(of: "\n") { try w.write(String(csv[csv.index(after: nl)...])) }
        }
        count += page.count
        q.afterID = last.id
    }
    if f == .json { try w.write(count == 0 ? "]\n" : "\n]\n") }
    if skipped {
        FileHandle.standardError.write(Data("warning: the daemon could not decode some stored events (written by a newer build, or damaged); they are not in the export\n".utf8))
    }
    return count
}

/// Per-day totals (details older than detail-days live only here), oldest day first.
func exportAggregates(_ c: IPCClient, format f: Exporter.Format, to w: ExportWriter) throws -> Int {
    let rows = Array(try dailyRows(c).reversed())
    switch f {
    case .json:
        try w.write(Format.terminalSafeJSON(String(decoding: try Exporter.encoder(pretty: true).encode(rows), as: UTF8.self)))
        try w.write("\n")
    case .jsonl:
        let enc = Exporter.encoder(pretty: false)
        for r in rows {
            try w.write(Format.terminalSafeJSON(String(decoding: try enc.encode(r), as: UTF8.self)))
            try w.write("\n")
        }
    case .csv:
        let catalog = try? c.catalog().catalog
        try w.write(["day", "responsible", "responsible_kind", "responsible_key", "category", "category_name", "agent",
                     "first", "last", "count", "reads", "writes", "denied", "benign"].joined(separator: ",") + "\n")
        for a in rows {
            let s = a.summary
            let cells = [a.day, s.responsible.displayName, s.responsible.kind.rawValue, s.responsible.key, s.categoryID,
                         catalog?.category(s.categoryID)?.name.en ?? "", s.agentID ?? "",
                         RFC3339.format(s.firstSeen, fractionDigits: 6), RFC3339.format(s.lastSeen, fractionDigits: 6),
                         String(s.count), String(s.reads), String(s.writes), String(s.denied), s.benign ? "true" : "false"]
            try w.write(cells.map(Exporter.csvField).joined(separator: ",") + "\n")
        }
    }
    return rows.count
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
        case .responsible(let k, let team, let cdhash, let exceptOwners):
            subject = "app \(k)" + (team.map { " (\($0))" } ?? "") + (cdhash.map { " cdhash \($0.prefix(12))…" } ?? "")
                + (exceptOwners ? " except owners" : "")
        case .anyNonOwner: subject = "any non-owner"
        case .agentAncestor(let ids, let ex): subject = "agent chain " + (ids?.joined(separator: ",") ?? "any") + (ex ? " except owners" : "")
        }
        // Answers to questions are scoped to the AI agents seen in the chain, and "allow once" expires:
        // without both, an approval for Terminal and one for Claude Code in Terminal look the same.
        let scope = r.chainAgents.map { $0.isEmpty ? ", no AI agent in chain" : ", chain agents " + $0.joined(separator: ",") } ?? ""
        let state = (!r.enabled ? "off" : (r.action == .deny ? (r.enforce ? "ENFORCE" : "dry-run") : "on"))
            + (r.expiresAt.map { " until " + Format.time($0) } ?? "")
        return [r.id, state, r.action.rawValue, r.access.rawValue, target, subject + scope, r.name ?? ""]
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
        if let e = try? c.status().rulesLoadError {
            note("warning: the stored rules could not be loaded (\(DisplayText.escaped(e))); enforcement is off. "
                + "Fix with: sudo whoread rules replace --json-file RULES.json --confirm "
                + "(unreadable rows are kept in the rules_backup table)")
        }
        if args.json { return outJSON(try Format.json(rules)) }
        out(Format.table(rules.map(describe), header: ["ID", "STATE", "ACTION", "ACCESS", "TARGET", "SUBJECT", "NAME"]))
    case "templates":
        outJSON(try Format.json(RuleTemplates.all))
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
    case "replace":
        guard let file = args.value("json-file") else { throw CLIError("rules replace --json-file RULES.json --confirm") }
        guard args.has("confirm") else {
            throw CLIError("rules replace deletes every current rule and stores the file's rules instead; add --confirm")
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: file))
        let rules: [Rule]
        if let list = try? Exporter.decoder().decode([Rule].self, from: data) {
            rules = list
        } else {
            rules = [try Exporter.decoder().decode(Rule.self, from: data)]
        }
        _ = try c.call(.replaceRules(rules))
        out("replaced: \(rules.count) rule(s)")
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
    // A stray extra word is a mistake (an unquoted name with a space), not something to ignore.
    guard args.positional.count == 3 else { throw CLIError("one rule id at a time: whoread rules \(args.positional[1]) ID") }
    return args.positional[2]
}

/// A catalog prefix as the classifier expects it: absolute or `~/`, no `.`/`..`, narrower than a
/// whole disk or home. `homes` are the daemon's monitored homes: a home, or a folder holding one,
/// is refused however it is spelled (`~/` alone, `/Users/alice`, `/Users`, a firmlinked form).
func catalogPath(_ raw: String, homes: [String]) throws -> String {
    let p = raw.trimmingCharacters(in: .whitespaces)
    guard p.hasPrefix("/") || p.hasPrefix("~/") else { throw CLIError("path must start with / or ~/: \(raw)") }
    let parts = p.split(separator: "/")
    guard !parts.contains("..") && !parts.contains(".") else { throw CLIError("path must not contain . or ..: \(raw)") }
    guard parts.count > (p.hasPrefix("~/") ? 1 : 0) else { throw CLIError("\(p) is too broad to monitor") }
    if p.hasPrefix("/") {
        let normalizer = PathNormalizer(homeDirectories: homes)
        let key = normalizer.matchKey(p)
        // The data volume's own spelling (/System/Volumes/Data) is the whole disk too.
        guard key != "/" else { throw CLIError("\(p) is too broad to monitor") }
        let homeKeys = normalizer.homeDirectories.map(PathNormalizer.fold) + ["/users"]
        if homeKeys.contains(where: { $0 == key || $0.hasPrefix(key + "/") }) {
            throw CLIError("\(p) is too broad to monitor: it is or holds a home folder (use ~/FOLDER for a folder in every home)")
        }
    }
    return p
}

func severityArg(_ v: String) throws -> Severity {
    guard let s = Severity(rawValue: v.lowercased()) else { throw CLIError("severity must be medium, high or critical") }
    return s
}

func cmdCatalog(_ c: IPCClient) throws {
    let sub = args.positional.dropFirst().first ?? "show"
    func arg(_ n: Int, _ usage: String) throws -> String {
        guard args.positional.count > n else { throw CLIError("usage: whoread catalog \(usage)") }
        return args.positional[n]
    }
    /// Exactly `count` positionals (counting "catalog" and the subcommand): a stray word, such as
    /// the tail of an unquoted path with a space, must not be silently dropped.
    func expect(_ count: Int, _ usage: String) throws {
        guard args.positional.count == count else { throw CLIError("usage: whoread catalog \(usage)") }
    }
    var fetched: CatalogInfo?
    func info() throws -> CatalogInfo {
        if let fetched { return fetched }
        let i = try c.catalog()
        fetched = i
        return i
    }
    func index(_ catalog: Catalog, _ id: String) throws -> Int {
        guard let i = catalog.categories.firstIndex(where: { $0.id == id }) else {
            throw CLIError("unknown category \(id) (see whoread catalog show)")
        }
        return i
    }
    /// Read-modify-write of the whole catalog (the daemon takes it through `.updateCatalog`).
    func edit(_ change: (inout Catalog) throws -> String) throws {
        var catalog = try info().catalog
        let message = try change(&catalog)
        _ = try c.call(.updateCatalog(catalog))
        out(message)
    }
    switch sub {
    case "show":
        let info = try c.catalog()
        if let id = args.positional.dropFirst(2).first {
            guard let cat = info.catalog.category(id) else { throw CLIError("unknown category \(id) (see whoread catalog show)") }
            if args.json { return outJSON(try Format.json(cat)) }
            out("\(cat.id) — \(cat.name.resolve(language))  [\(cat.kind.rawValue), \(cat.severity.rawValue)\(cat.enabled ? "" : ", disabled")]")
            out(cat.paths.isEmpty ? "  (no paths)" : cat.paths.map { "  " + $0 }.joined(separator: "\n"))
            if !cat.patterns.isEmpty { out("  \(cat.patterns.count) file pattern(s), \(cat.owners.count) owner(s)") }
            let prefixes = info.prefixes.filter { $0.categoryID == id }
            if !prefixes.isEmpty {
                out(language == .zhHans ? "本机监控的前缀：" : "monitored on this machine:")
                prefixes.forEach { out("  " + $0.path + ($0.viaSymlink ? " (via symlink)" : "")) }
            }
            return
        }
        if args.json { return outJSON(try Format.json(info)) }
        var rows: [[String]] = []
        for cat in info.catalog.categories {
            let prefixes = info.prefixes.filter { $0.categoryID == cat.id }
            let detected = info.detected[cat.id] == true ? (language == .zhHans ? "已检测到" : "detected") : (language == .zhHans ? "未检测到" : "not detected")
            rows.append([cat.id, cat.name.resolve(language), cat.severity.rawValue, cat.enabled ? detected : "disabled",
                         String(prefixes.count), String(cat.owners.count)])
        }
        out(Format.table(rows, header: ["ID", language == .zhHans ? "名称" : "NAME", "SEVERITY", "STATE", "PREFIXES", "OWNERS"]))
    case "add-path", "remove-path":
        let usage = "\(sub) CATEGORY PATH"
        try expect(4, usage)
        let id = try arg(2, usage)
        let path = sub == "add-path" ? try catalogPath(try arg(3, usage), homes: try info().homeDirectories)
            : try arg(3, usage).trimmingCharacters(in: .whitespaces)
        try edit { cat in
            let i = try index(cat, id)
            if cat.categories[i].kind == .projectRoots {
                throw CLIError("\(id) takes its folders from the project roots setting: whoread settings set project-root-add PATH")
            }
            if sub == "remove-path" {
                guard cat.categories[i].paths.contains(path) else { throw CLIError("\(id) has no path \(path)") }
                cat.categories[i].paths.removeAll { $0 == path }
                return "removed \(path) from \(id)"
            }
            guard !cat.categories[i].paths.contains(path) else { throw CLIError("\(id) already has \(path)") }
            cat.categories[i].paths.append(path)
            return "added \(path) to \(id)" + (cat.categories[i].enabled ? "" : " (category is disabled: whoread catalog enable \(id))")
        }
    case "add-category":
        let usage = "add-category ID NAME_EN NAME_ZH medium|high|critical [--path PATH]..."
        try expect(6, usage)
        let id = try arg(2, usage), en = try arg(3, usage), zh = try arg(4, usage)
        let severity = try severityArg(try arg(5, usage))
        guard id.range(of: "^[a-z0-9][a-z0-9-]*$", options: .regularExpression) != nil else {
            throw CLIError("category id: lowercase letters, digits and -")
        }
        guard !en.trimmingCharacters(in: .whitespaces).isEmpty else { throw CLIError("NAME_EN must not be empty") }
        let homes = try info().homeDirectories
        let paths = try args.all("path").map { try catalogPath($0, homes: homes) }
        try edit { cat in
            guard cat.category(id) == nil else { throw CLIError("category \(id) already exists") }
            cat.categories.append(CategorySpec(id: id, name: LocalizedText(en: en, zhHans: zh), kind: .custom, group: "custom",
                                               severity: severity, paths: paths))
            return "added category \(id)" + (paths.isEmpty ? " (no paths yet: whoread catalog add-path \(id) PATH)" : " with \(paths.count) path(s)")
        }
    case "remove-category":
        try expect(3, "remove-category ID")
        let id = try arg(2, "remove-category ID")
        try edit { cat in
            let i = try index(cat, id)
            guard cat.categories[i].kind == .custom else { throw CLIError("\(id) is built in: turn it off with whoread catalog disable \(id)") }
            cat.categories.remove(at: i)
            return "removed category \(id)"
        }
    case "set-severity":
        let usage = "set-severity ID medium|high|critical"
        try expect(4, usage)
        let id = try arg(2, usage)
        let severity = try severityArg(try arg(3, usage))
        try edit { cat in
            let i = try index(cat, id)
            cat.categories[i].severity = severity
            return "\(id): severity \(severity.rawValue)"
        }
    case "enable", "disable":
        try expect(3, "\(sub) ID")
        let id = try arg(2, "\(sub) ID")
        try edit { cat in
            let i = try index(cat, id)
            cat.categories[i].enabled = sub == "enable"
            return "\(id): \(sub)d"
        }
    case "export":
        let data = try c.catalog().catalog.encoded() + Data("\n".utf8)
        if let path = args.value("output") ?? args.value("o") {
            try SafeFile.replace(path, with: data, mode: 0o644)
            FileHandle.standardError.write(Data("catalog written to \(path)\n".utf8))
        } else {
            FileHandle.standardOutput.write(data)
        }
    case "import":
        try expect(3, "import FILE")
        let file = try arg(2, "import FILE")
        let catalog: Catalog
        do {
            catalog = try Catalog.load(from: Data(contentsOf: URL(fileURLWithPath: file)))
        } catch {
            throw CLIError("cannot read catalog \(file): \(error)")
        }
        let ids = catalog.categories.map(\.id)
        guard Set(ids).count == ids.count else { throw CLIError("\(file): duplicate category ids") }
        let homes = try info().homeDirectories
        // Paths already in the catalog are not new breadth (the default /Volumes/ holds a home
        // that lives on an external disk), so an exported catalog always imports again.
        let current = Set(try info().catalog.categories.flatMap(\.paths))
        for cat in catalog.categories where cat.kind != .projectRoots {
            for p in cat.paths where !current.contains(p) { _ = try catalogPath(p, homes: homes) }
        }
        _ = try c.call(.updateCatalog(catalog))
        out("catalog imported: \(catalog.categories.count) categories")
    case "resolve-owners":
        #if os(macOS)
        let info = try c.catalog()
        let (resolved, report) = OwnerResolver.resolve(catalog: info.catalog, reader: CodesignCommandReader(),
                                                       exists: { FileManager.default.fileExists(atPath: $0) })
        _ = resolved
        report.resolved.forEach { out("  resolved \($0)") }
        out("\(report.resolved.count) resolved, \(report.missing.count) not installed, \(report.skippedGlobs) glob patterns left as is")
        // Writing these into catalog.json would freeze the owners against later default updates; the
        // daemon resolves them in memory at every start and after catalog changes instead.
        out("Nothing was written: the daemon applies these identities in memory at start.")
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
        return outJSON(try Format.json(s))
    }
    // Exactly one VALUE: the tail of an unquoted path with a space must not be dropped.
    guard args.positional.count == 4 else { throw CLIError("settings set KEY VALUE (quote a VALUE that has spaces)") }
    let key = args.positional[2]
    let value = args.positional[3]
    func bool(_ v: String) throws -> Bool {
        switch v { case "on", "true", "yes", "1": return true; case "off", "false", "no", "0": return false
        default: throw CLIError("expected on/off") }
    }
    func number(_ v: String) throws -> Double {
        guard let d = Double(v), d.isFinite else { throw CLIError("expected a number") }
        return d
    }
    func integer(_ v: String) throws -> Int {
        guard let n = Int(v) else { throw CLIError("expected a whole number") }
        return n
    }
    switch key {
    case "learning-days": s.learningDays = try number(value)
    case "retention-days": s.retentionDays = try integer(value)
    case "detail-days": s.detailDays = try integer(value)
    case "coalesce-minutes": s.coalesceMinutes = try number(value)
    case "readdir": s.readdirEnabled = try bool(value)
    case "project-root-add": s.projectRoots.append(value)
    case "project-root-remove": s.projectRoots.removeAll { $0 == value }
    case "notifications": s.notifications.enabled = try bool(value)
    case "min-severity":
        guard let sev = Severity(rawValue: value) else { throw CLIError("medium|high|critical") }
        s.notifications.minimumSeverity = sev
    case "latency-p99-ms": s.latencyP99ThresholdMs = try number(value)
    case "trust-apple": s.trustApplePrograms = try bool(value)
    case "language":
        // zh* means Simplified Chinese, as with --lang; an unknown value is an error, not "system".
        switch value.lowercased() {
        case "system": s.language = nil
        case "en": s.language = .en
        case let v where v.hasPrefix("zh"): s.language = .zhHans
        default: throw CLIError("language: en|zh-Hans|system")
        }
    default: throw CLIError("unknown setting \(key)")
    }
    _ = try c.call(.updateSettings(s))
    outJSON(try Format.json(try c.settings()))
}

func cmdBaseline(_ c: IPCClient) throws {
    if args.positional.dropFirst().first == "restart-learning" {
        _ = try c.call(.restartLearning)
        return out("learning restarted")
    }
    guard case .baseline(let entries) = try c.call(.baseline) else { return }
    if args.json { return outJSON(try Format.json(entries)) }
    out(Format.table(entries.map { [$0.key.responsibleKey, $0.key.categoryID, $0.key.access.rawValue, $0.source.rawValue, String($0.count), Format.time($0.lastSeen)] },
                     header: ["RESPONSIBLE", "CATEGORY", "ACCESS", "SOURCE", "COUNT", "LAST"]))
    if entries.count >= Baseline.replyLimit { note("note: the daemon sends the \(Baseline.replyLimit) most recently seen entries") }
}

func cmdKillSwitch() throws {
    let path = args.value("path") ?? WhoReadPaths.killSwitchFile
    switch args.positional.dropFirst().first ?? "status" {
    case "engage":
        do { try SafeFile.replace(path, with: Data("disabled by whoread kill-switch\n".utf8), mode: 0o644) } catch {
            throw CLIError("cannot create \(path) (run with sudo): \(error)", exitCode: 77)
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
        return outJSON(try Format.json(Result(events: events, alerts: alerts, parser: replay.parserStats)))
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
    try SafeFile.replace(output, with: Data((kept.joined(separator: "\n") + "\n").utf8), mode: 0o600)
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
        let commands: [String: (IPCClient) throws -> Void] = [
            "status": cmdStatus, "events": cmdEvents, "tail": cmdTail, "alerts": cmdAlerts, "alert": cmdAlertAction,
            "asks": cmdAsks, "ask": cmdAsk,
            "read-all": { c in _ = try c.call(.markAlertsRead(ids: nil)); out("all alerts marked read") },
            "apps": cmdApps, "files": cmdFiles, "agents": cmdAgents, "daily": cmdDaily, "export": cmdExport,
            "enforcement": cmdEnforcement,
            "pause": { c in _ = try c.call(.setPaused(true)); out("monitoring paused") },
            "resume": { c in _ = try c.call(.setPaused(false)); out("monitoring resumed") },
            "rules": cmdRules, "catalog": cmdCatalog, "settings": cmdSettings, "baseline": cmdBaseline,
        ]
        guard let run = commands[command] else { throw CLIError("unknown command \(command)\n\n\(usage)", exitCode: 64) }
        let client = try makeClient()
        do {
            try handshake(client)
            try run(client)
        } catch let e as IPCError {
            throw explain(e)
        } catch let u as Unreachable {
            throw explain(u)
        }
    }
} catch let e as CLIError {
    note("whoread: \(e.message)")
    exit(e.exitCode)
} catch {
    note("whoread: \(error)")
    exit(1)
}
