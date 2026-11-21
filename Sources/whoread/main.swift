import Foundation
import WhoReadCore
import WhoReadEngine
import WhoReadIPC

let usage = """
whoread — who read my sensitive files?

Usage: whoread <command> [options]

Daemon queries (talk to whoreadd over XPC; --socket PATH for the dev socket). [sudo] marks what
needs sudo (or the WhoRead app): reading what the daemon recorded (it names files and keeps command
lines), and changes that can weaken protection (settings set, rule edits other than adding a deny
or alert rule, catalog changes, allowing a question).
  status                         state, source, deadline mode, enforcement, questions, counters
  events [filters]               [sudo] recorded accesses (newest first)
      --since 1h|2d|2026-10-04|"2026-10-04 09:30"   --until …   (no offset = local time)
      --category ID (repeatable)   --agent ID   --agents-only   --denied
      --app TEXT (app or program name)   --search TEXT (app or program name, or file path)
      --all (include folded system noise)   --limit N (default 500)
                                 a note on stderr says when more events match than are shown
  tail [--all]                   [sudo] follow new events live
  asks [--json]                  questions waiting for your answer (ask mode, see below); file paths
                                 and command lines are shown only with sudo; at most 200 are listed
                                 (those holding an access first): answer the rest in whoread alerts
  ask <id> deny|block            deny now | deny now and from now on (saves a deny rule)
  ask <id> allow-once|allow      [sudo] allow for 10 minutes | always (saves an allow rule)
  ask <id> trust-apple           [sudo] allow all Apple programs without asking (never under an
                                 AI agent)
  alerts [--unread] [--since …] [--limit N (default 200)]   [sudo] newest first
  alert <id> block               deny this app from now on (the alert stays open without sudo)
  alert <id> allow-once|always-allow|keep-blocking|ignore|trust-apple
                                 [sudo] (keep-blocking on a question's alert only denies: no sudo)
  read-all                       [sudo] mark every alert read
  apps | files | agents          [sudo] who touched what (Apps / Files / Agents tabs)
      apps --since 1h|2d|…       FIRST and COUNT of that window only (days past detail-days count whole)
  daily [--since …] [filters]    [sudo] per-day totals for days past the detail window (detail-days);
                                 newest first; --app matches the app name (no --search)
  export --format json|jsonl|csv [--output FILE] [filters]      [sudo] all matching events, oldest first
  export --aggregates --format json|jsonl|csv [--output FILE] [--since …]   [sudo] per-day totals
                                 --limit N: the oldest N (events or per-day rows)
                                 FILE is owner-only (0600); under sudo, in a folder you own, it is
                                 yours. CSV: a cell that starts like a formula (= + - @) gets a
                                 leading apostrophe; on a terminal, hidden characters are escaped
  enforcement on|off|status      off: [sudo]
  pause | resume                 pause: [sudo]
  rules [list]                   [sudo] every rule, with the scope of each saved answer
  rules templates                the rule templates (JSON)
  rules add --json-file F        [sudo], except for a new, enabled deny or alert rule without
                                 exceptions
  rules enable|disable|enforce|dry-run|delete ID   [sudo]
  rules replace --json-file F --confirm   [sudo] replace every rule (recovery after stored rules
                                          failed to load; the old rows are kept in rules_backup)
  catalog [show [ID]|export [--output FILE]|resolve-owners]
                                   resolve-owners: show the owner team/signing IDs codesign reports
                                   for installed apps (the daemon applies them in memory at start)
  catalog add-path|remove-path CATEGORY PATH        [sudo] PATH starts with / or ~/
  catalog add-category ID NAME_EN NAME_ZH medium|high|critical [--path PATH]...   [sudo]
  catalog remove-category ID | set-severity ID SEVERITY | enable ID | disable ID   [sudo]
  catalog import FILE | reset    [sudo]
  settings [show | set KEY VALUE]   set: [sudo], except turning trust-apple off
                                    keys: retention-days detail-days coalesce-minutes
                                       readdir on|off  project-root-add PATH  project-root-remove PATH
                                       notifications on|off  min-severity medium|high|critical
                                       latency-p99-ms N (status warning)  language en|zh-Hans|system
                                       trust-apple on|off (allow Apple programs without asking)
                                    PATH: absolute, ~/FOLDER (in every home), or relative to the
                                    current folder (stored as an absolute path)
  baseline                       [sudo] (app, category, access) combinations seen so far (the
                                 10,000 seen most recently)

Ask mode: with enforcement on, an access that nothing decides yet (no rule, not an owner with no AI
agent in its chain, not a system service) is held and you are asked: `whoread asks`, or the WhoRead
app. Your answer is saved as a rule for that app × category × access and the AI agents in the
chain, so each is asked once (a program whose starter is unknown is asked about separately).
Unanswered in time, the access is denied and the question stays open. On macOS 27 the kernel also
denies an access the daemon does not answer in time.
Enforcement is never switched off automatically: only `sudo whoread enforcement off`, the app's
switch or `sudo whoread kill-switch engage` turn it off.

Local (no daemon):
  kill-switch engage|release|status [--path P]   engage|release: [sudo] creates/removes the
                                                 disable-enforcement file
  replay FILE [--home DIR] [--defaults DIR] [--all] [--json]
                                 run an eslogger JSONL capture through the full pipeline
  fixture sanitize --input RAW|/dev/stdin --output OUT [--home DIR] [--vault DIR] [--capture-pid PID] [--sample N]
  version

Global: --json   --lang en|zh-Hans   --service MACH_NAME   --socket PATH   -h|--help
An option a command does not take, or a value that does not parse, is a usage error (exit 64).
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

/// Writes text for a person to stderr, escaped like `out`. A closed or broken stderr loses the
/// message instead of raising (the legacy `write(_:)` throws an Objective-C exception, which
/// aborts).
func note(_ s: String) { try? FileHandle.standardError.write(contentsOf: Data((DisplayText.lines(s) + "\n").utf8)) }

/// English or Chinese, as the output language says.
func tr(_ en: String, _ zh: String) -> String { language == .zhHans ? zh : en }

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
        ?? announcedServiceName()
        ?? WhoReadPaths.machServiceName
    return TransportClient(transport: XPCClient(machServiceName: name, queryTimeout: XPCClient.queryTimeout))
    #else
    throw CLIError("no XPC on this platform: pass --socket PATH (whoreadd --dev-socket PATH)")
    #endif
}

/// The service name the running daemon wrote to its data directory, unless someone other than root
/// could have written it there: such a name could lead the CLI to another service (macos-4).
func announcedServiceName() -> String? {
    do {
        return try TrustedFile.machServiceName(inDataDirectory: WhoReadPaths.dataDirectory)
    } catch {
        note("not using the daemon's service name: \(error); using \(WhoReadPaths.machServiceName)")
        return nil
    }
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

/// What happened to a request that got no answer, and what to check or do (`NoAnswerHelp`): a daemon
/// that refuses this program, or one that is busy, is not reported as one that is not running.
func explain(_ u: Unreachable) -> CLIError {
    // Refused by the transport before sending (a request too large for the dev socket, a socket path
    // too long): said as the daemon would.
    guard u.error.code == .unavailable else { return explain(u.error) }
    var e = u.error
    e.message = DisplayText.escaped(e.message)
    return CLIError(NoAnswerHelp.lines(for: e, target: noAnswerTarget()).joined(separator: "\n"), exitCode: 69)
}

/// Where `makeClient` sent the request, for the hint: the same choice, without its note about an
/// untrusted announced name (it was printed already).
func noAnswerTarget() -> NoAnswerHelp.Target {
    let env = ProcessInfo.processInfo.environment
    if let socket = args.value("socket") ?? env["WHOREAD_SOCKET"] { return .socket(path: socket) }
    return .xpc(service: args.value("service") ?? env["WHOREAD_MACH_SERVICE"]
        ?? (try? TrustedFile.machServiceName(inDataDirectory: WhoReadPaths.dataDirectory)) ?? WhoReadPaths.machServiceName)
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

/// `--limit N`: a whole number, 0 or more. Anything else is a usage error, never the default.
func limitArg() throws -> Int? {
    guard let l = args.value("limit") else { return nil }
    guard let n = Int(l), n >= 0 else { throw CLIError.usage("--limit: a whole number, 0 or more (not \"\(l)\")") }
    return n
}

/// The event filters of `events`, `daily` and `export` (no daemon needed: also the argument check).
func eventQuery() throws -> EventQuery {
    var q = EventQuery()
    if let s = args.value("since") { q.since = try Format.parseSince(s) }
    if let u = args.value("until") { q.until = try Format.parseSince(u) }
    let cats = args.all("category")
    if !cats.isEmpty { q.categoryIDs = cats }
    // --app: the app's or the program's name only. `text` goes along so that a daemon that predates
    // `appName` still narrows by it (with its wider match, paths included) instead of ignoring it.
    if let app = args.value("app") {
        q.appName = app
        q.text = app
    }
    // --search: the name of the app or program, or the file path.
    if let search = args.value("search") { q.text = search }
    q.agentID = args.value("agent")
    q.agentsOnly = args.has("agents-only")
    q.includeBenign = args.has("all")
    if args.has("denied") { q.decisions = [.denied] }
    if let n = try limitArg() { q.limit = n }
    return q
}

/// The most events and alerts one reply of the daemon's store holds (SQLiteEventStore).
let storeEventReplyCap = 100_000
let storeAlertReplyCap = 10_000

/// The newest `limit` items, and whether more match: asks for one more than it shows (a reply
/// that fills the store's cap may hide more as well).
func newest<T>(_ limit: Int, cap: Int, _ fetch: (Int) throws -> [T]) rethrows -> (shown: [T], more: Bool) {
    let reply = try fetch(limit < Int.max ? limit + 1 : limit)
    return (Array(reply.prefix(limit)), reply.count > limit || (limit >= cap && reply.count >= cap))
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
        var decision: String
        switch e.decision {
        case .denied: decision = language == .zhHans ? "已拦截" : "BLOCKED"
        case .wouldDeny: decision = language == .zhHans ? "将被拦截" : "would block"
        default: decision = e.isBenign ? (language == .zhHans ? "系统(折叠)" : "system (folded)") : ""
        }
        if let note = e.note {
            decision += (decision.isEmpty ? "" : language == .zhHans ? "，" : ", ") + EventNote.describe(note, language: language)
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
    let zh = language == .zhHans
    /// "  source:       " (the labels line up at 16 columns, Chinese ones too).
    func field(_ en: String, _ zhLabel: String) -> String { "  " + Format.pad(zh ? zhLabel + "：" : en + ":", 14) }
    let warning = tr("  WARNING: ", "  警告：")
    out("WhoRead \(s.version) — \(m)")
    out(field("source", "事件源") + "\(s.source.rawValue) " + (s.sourceRunning ? tr("running", "运行中") : tr("stopped", "已停止"))
        + (s.sourceError.map { tr("  ERROR: ", "  错误：") + DisplayText.escaped($0) } ?? ""))
    if let h = s.sourceHint { out("                " + tr("hint: ", "提示：") + DisplayText.escaped(h)) }
    if let d = s.sourceDeadlineMissMode { out(field("deadline", "截止模式") + "AUTH " + NativeDeadlineMissMode.statusDescription(d)) }
    out(field("enforcement", "拦截") + enforcementText(s, reasonsAfter: tr(" — ", "：")))
    out(field("kill switch", "kill switch") + (s.killSwitchFilePresent ? tr("file PRESENT (enforcement forced off)", "文件存在（拦截被强制关闭）")
                                                                    : tr("file absent", "文件不存在")))
    if let n = s.pendingAsks {
        out(field("questions", "问题") + (n == 0 ? tr("none waiting", "没有等待回答的问题")
                                             : tr("\(n) waiting for your answer (whoread asks)", "\(n) 个等待你回答（whoread asks）")))
    }
    if settings?.trustApplePrograms == true {
        out(field("trust Apple", "信任苹果程序") + tr("on (Apple programs in system locations are not asked, unless an AI agent is in the chain)",
                                                  "已打开（系统位置中的苹果程序不会被询问，除非调用链中有 AI agent）"))
    }
    if let u = s.uncleanStop {
        out(field("unclean stop", "异常停止") + DisplayText.escaped(u) + tr("; enforcement was kept as you set it", "；拦截保持你设定的状态"))
    }
    out(field("events", "事件") + tr("\(s.counts.events) stored (+\(s.counts.aggregatedDays) days aggregated), \(s.eventsProcessed) since start, last \(Format.ago(s.lastEventAt))",
                                    "已存储 \(s.counts.events) 条（另有 \(s.counts.aggregatedDays) 天按天汇总），启动以来 \(s.eventsProcessed) 条，最近一次 \(Format.ago(s.lastEventAt, language: language))"))
    out(field("alerts", "告警") + tr("\(s.unreadAlerts) unread of \(s.counts.alerts)", "未读 \(s.unreadAlerts) 条，共 \(s.counts.alerts) 条"))
    let homes = s.homeDirectories.map { DisplayText.escaped($0) }.joined(separator: ", ")
    out(field("coverage", "覆盖范围") + tr("\(s.monitoredPrefixes) monitored prefixes, homes \(homes)", "监控 \(s.monitoredPrefixes) 个前缀，主目录 \(homes)"))
    if let m = s.sourceAuth?.mutedLine { out(m) }
    if let p = s.parser {
        out(field("eslogger", "eslogger") + tr("\(p.lines) lines read, \(p.events) events parsed, \(p.malformed) malformed, schema \(p.schemaVersions), kernel drops \(p.droppedByKernel)",
                                              "读取 \(p.lines) 行，解析 \(p.events) 个事件，\(p.malformed) 行格式错误，schema \(p.schemaVersions)，内核丢弃 \(p.droppedByKernel)"))
    }
    if s.latency.samples > 0 {
        out(field("AUTH latency", "AUTH 延迟") + String(format: tr("p50 %.0f µs, p99 %.0f µs, max %.0f µs, %d deadline misses",
                                                                   "p50 %.0f µs，p99 %.0f µs，最大 %.0f µs，%d 次错过截止时间"),
                                                         s.latency.p50Micros, s.latency.p99Micros, s.latency.maxMicros, s.latency.deadlineMisses))
        if let t = settings?.latencyP99ThresholdMs, s.latency.p99Micros > t * 1000 {
            out(warning + String(format: tr("AUTH p99 latency %.1f ms is over latency-p99-ms %.0f ms (enforcement stays on)",
                                            "AUTH p99 延迟 %.1f ms 超过 latency-p99-ms %.0f ms（拦截保持开启）"),
                                 s.latency.p99Micros / 1000, t))
        }
    }
    // Missed deadlines never switch enforcement off: only counted. The kernel allowed those accesses,
    // unless the native client runs in fail-closed mode (macOS 27), where it denied them.
    if s.latency.deadlineMisses > 0 {
        let denied = NativeDeadlineMissMode.missesDenied(s.sourceDeadlineMissMode)
        let n = s.latency.deadlineMisses
        out(warning + tr("\(n) AUTH deadline miss\(n == 1 ? "" : "es"): the kernel \(denied ? "denied" : "allowed") those accesses; "
                            + "enforcement stays on (turn it off by hand: sudo whoread enforcement off)",
                         "\(n) 次错过 AUTH 截止时间：内核\(denied ? "拒绝" : "允许")了这些访问；拦截保持开启（手动关闭：sudo whoread enforcement off）"))
    }
    if s.writerDropped > 0 { out(warning + tr("\(s.writerDropped) events dropped before storage", "\(s.writerDropped) 个事件在存储前被丢弃")) }
    if let d = s.sourceDroppedEvents, d > 0 {
        out(warning + tr("\(d) events dropped or merged by the source (analysis backlog full; denials were still enforced)",
                         "事件源丢弃或合并了 \(d) 个事件（分析队列已满；拒绝仍然生效）"))
    }
    if s.parser == nil, let line = SourceAuthCounts.kernelDropLine(total: s.sourceKernelDrops ?? 0, auth: s.sourceAuth) { out(line) }
    s.sourceAuth?.warningLines.forEach(out)
    if let e = s.rulesLoadError {
        out(warning + tr("stored rules failed to load (\(DisplayText.escaped(e))); enforcement stays off",
                         "已存储的规则加载失败（\(DisplayText.escaped(e))）；拦截保持关闭"))
    }
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
    var q = try eventQuery()
    noteRolledUp(c, since: q.since)
    let (events, more) = try newest(q.limit, cap: storeEventReplyCap) { n in
        q.limit = n
        return try c.events(q)
    }
    if args.json { outJSON(try Format.json(events)) } else { printEvents(events, context(c)) }
    if more {
        note(tr("note: only the newest \(events.count) matching events are shown; use --limit N for more, or whoread export for all of them",
                "注意：只显示了最新的 \(events.count) 条匹配事件；用 --limit N 显示更多，或用 whoread export 导出全部"))
    }
}

/// The store applies a page's LIMIT before it drops rows it cannot decode (written by a newer
/// build, or damaged), so a page can come back short, or empty, with matching events still
/// beyond it. For a page `q` that came back empty: true when it held only such rows, so every
/// matching row in (afterID, afterID + limit] is undecodable and can be stepped over. A newer
/// matching event must exist, and the page must still be empty when read again after that probe
/// (so an event arriving in between does not pass for a skipped block). The newest matching row
/// can itself be undecodable: with `depth` above 1, up to that many of the newest are looked at
/// before deciding that nothing matches beyond the page (an export would otherwise end early and
/// leave out every event after such a block).
func onlyUndecodable(_ c: IPCClient, _ q: EventQuery, depth: Int = 1) throws -> Bool {
    var probe = q
    probe.limit = 1
    probe.newestFirst = true
    if try c.events(probe).isEmpty {
        guard depth > 1 else { return false }
        probe.limit = depth
        guard try !c.events(probe).isEmpty else { return false }
    }
    return try c.events(q).isEmpty
}

/// How far back from the newest matching rows `export` and `tail` look for one they can decode.
let undecodableProbeDepth = 1_000

/// Where `tail` starts: after the newest stored event. The newest rows can be undecodable (the
/// store applies LIMIT before decoding), so it looks further back before taking the store for
/// empty: starting from nothing would print the whole history as if it were new.
func tailStart(_ c: IPCClient) throws -> Int64? {
    for depth in [1, undecodableProbeDepth] {
        if let id = try c.events(EventQuery(includeBenign: true, limit: depth)).map(\.id).max() { return id }
    }
    guard ((try? c.status())?.counts.events ?? 0) == 0 else {
        throw CLIError(tr("cannot find the newest stored event (the newest \(undecodableProbeDepth) could not be decoded: "
                            + "written by a newer build, or damaged); not printing the whole history as new",
                          "找不到最新存储的事件（最新的 \(undecodableProbeDepth) 条都无法解码：由较新的版本写入，或已损坏）；"
                            + "不会把全部历史当作新事件打印"))
    }
    return nil
}

func cmdTail(_ c: IPCClient) throws {
    let ctx = context(c)
    var after: Int64? = try tailStart(c)
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

/// The filters of `alerts` (no daemon needed: also the argument check).
func alertQuery() throws -> AlertQuery {
    var q = AlertQuery()
    if args.has("unread") { q.statuses = [.unread] }
    if let n = try limitArg() { q.limit = n }
    if let s = args.value("since") { q.since = try Format.parseSince(s) }
    return q
}

func cmdAlerts(_ c: IPCClient) throws {
    var q = try alertQuery()
    let (alerts, more) = try newest(q.limit, cap: storeAlertReplyCap) { n in
        q.limit = n
        return try c.alerts(q)
    }
    defer {
        if more {
            note(tr("note: only the \(alerts.count) most recently updated alerts are shown; use --limit N for more",
                    "注意：只显示了最近更新的 \(alerts.count) 条告警；用 --limit N 显示更多"))
        }
    }
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

/// `whoread alert ID WORD`, checked (also before connecting).
func alertArgs() throws -> (id: Int64, action: AlertAction) {
    let usage = "usage: whoread alert <id> <" + alertActionWords.map(\.word).joined(separator: "|") + ">"
    guard args.positional.count == 3, let id = Int64(args.positional[1]) else { throw CLIError.usage(usage) }
    guard let action = alertActionWords.first(where: { $0.word == args.positional[2] })?.action else {
        throw CLIError.usage("unknown action \(args.positional[2])\n\(usage)")
    }
    return (id, action)
}

func cmdAlertAction(_ c: IPCClient) throws {
    let (id, action) = try alertArgs()
    _ = try c.call(.alertAction(alertID: id, action: action))
    // What was done, in the words the alert lines use ("Block from now on"), not the enum's name.
    out(tr("alert #\(id): ", "告警 #\(id)：") + AlertFormatter(language: language).actionTitle(action))
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

/// The most questions the daemon lists (DaemonCore.maxListedAsks), those holding an access first.
let daemonListedAsksLimit = 200

/// The daemon left a question's file path out (it does not serve this connection as root or the
/// signed app): its note instead, in the output language. Every real path is absolute.
func askPath(_ path: String, _ ctx: Context) -> String {
    path.hasPrefix("/") ? ctx.normalizer.abbreviate(path)
        : tr(ServiceHandler.hiddenPath, "（文件路径已隐藏：用 sudo 运行才能看到）")
}

func cmdAsks(_ c: IPCClient) throws {
    guard case .asks(let asks) = try c.call(.asks) else { throw IPCError(.internalError, "unexpected response") }
    defer {
        if asks.count >= daemonListedAsksLimit {
            note(tr("note: the daemon lists at most \(daemonListedAsksLimit) questions (those holding an access first); "
                        + "more may be waiting: answer the rest in whoread alerts",
                    "注意：daemon 最多列出 \(daemonListedAsksLimit) 个问题（正在等待访问的优先）；可能还有更多问题在等待："
                        + "其余的可以在 whoread alerts 中回答"))
        }
    }
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
        // Who started the program was not seen: an AI agent may be behind it.
        let unknown = r.key.ancestryKnown ? [] : [zh ? "启动者未知" : "unknown starter"]
        return [String(r.id), DisplayText.name(r.responsible.displayName), program, ctx.categoryName(r.key.categoryID) + "/" + r.severity.rawValue,
                r.key.access.label, askPath(r.path, ctx),
                (agentIDs.map { ctx.agentName($0, agents) } + unknown).joined(separator: ", "),
                "\(r.holding)/\(r.attempts)", r.appleProgram ? (zh ? "是" : "yes") : ""]
    }
    out(Format.table(rows, header: zh ? ["编号", "应用", "程序", "类别", "访问", "路径", "AI agent", "等待/次数", "苹果程序"]
                                      : ["ID", "APP", "PROGRAM", "CATEGORY", "ACCESS", "PATH", "AGENT", "WAITING/ATTEMPTS", "APPLE"]))
    // An answer is per app, not per program (docs/ASK_MODE.md): what allowing each question covers.
    out("")
    for r in asks {
        let coverage = ctx.formatter.allowCoverage(r.responsible, categoryID: r.key.categoryID, access: r.key.access,
                                                   chainAgents: r.key.chainAgents, ancestryKnown: r.key.ancestryKnown,
                                                   agentName: { ctx.agentName($0, agents) })
        out(zh ? "#\(r.id) 允许（allow-once、allow）适用于：\(coverage)" : "#\(r.id) allow-once / allow cover: \(coverage)")
    }
    out(zh ? "\n回答：whoread ask 编号 allow-once|allow|deny|block|trust-apple（允许需要 sudo）"
           : "\nanswer: whoread ask ID allow-once|allow|deny|block|trust-apple (allowing needs sudo)")
}

/// `whoread ask ID WORD`, checked (also before connecting).
func askArgs() throws -> (id: Int64, action: AlertAction) {
    let usage = "usage: whoread ask <id> allow-once|allow|deny|block|trust-apple"
    guard args.positional.count == 3, let id = Int64(args.positional[1]) else { throw CLIError.usage(usage) }
    guard let action = askAnswerWords.first(where: { $0.word == args.positional[2] })?.action else {
        throw CLIError.usage("unknown answer \(args.positional[2])\n\(usage)")
    }
    return (id, action)
}

func cmdAsk(_ c: IPCClient) throws {
    let (id, action) = try askArgs()
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

/// The daemon sends the most recently active summary rows only (`UsageSummary.replyLimit`): say so
/// when a view may be missing older ones, as `whoread baseline` does.
func noteSummaryCap(_ rows: Int) {
    guard rows >= UsageSummary.replyLimit else { return }
    note(language == .zhHans ? "注意：守护进程只发送最近活动的 \(UsageSummary.replyLimit) 行，更早的没有列出，也不在计数里。"
                             : "note: the daemon sends the \(UsageSummary.replyLimit) most recently active rows; older ones are not shown or counted")
}

/// `apps --since` past the detail window: accesses there survive only as per-day totals, which the
/// daemon counts whole.
func noteWholeDays(_ c: IPCClient, since: Date) {
    guard let s = try? c.settings(), since < Date().addingTimeInterval(-Double(s.detailDays) * 86400) else { return }
    note(language == .zhHans
         ? "注意：超过 \(s.detailDays) 天的访问只保留按天汇总，所以那些天按整天计入首次时间和次数。"
         : "note: accesses older than \(s.detailDays) day\(s.detailDays == 1 ? "" : "s") are kept only as per-day totals, "
           + "so FIRST and COUNT take those days whole")
}

func cmdApps(_ c: IPCClient) throws {
    let since = try args.value("since").map { try Format.parseSince($0) }
    // With --since the daemon counts that window only: FIRST and COUNT are not all-time totals (cli-6).
    let all = try c.summaries(since: since)
    noteSummaryCap(all.count)
    if let since { noteWholeDays(c, since: since) }
    let sums = all.filter { args.has("all") || !$0.benign }
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
    let all = try c.summaries(since: nil)
    noteSummaryCap(all.count)
    let sums = all.filter { args.has("all") || !$0.benign }
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
    let all = try c.summaries(since: nil)
    noteSummaryCap(all.count)
    let sums = all.filter { $0.agentID != nil }
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

/// The event filters as they apply to daily aggregates (the daemon applies `--since`). `--app`
/// matches the app's name (a day's row has no program name or path).
func dailyFilter(_ q: EventQuery) -> (DailyAggregate) -> Bool {
    { a in
        let s = a.summary
        if let until = q.until, s.firstSeen > until { return false }
        if let cats = q.categoryIDs, !cats.contains(s.categoryID) { return false }
        if let agent = q.agentID, s.agentID != agent { return false }
        if q.agentsOnly && s.agentID == nil { return false }
        if !q.includeBenign && s.benign { return false }
        if q.decisions != nil && s.denied == 0 { return false }
        if let t = q.appName?.lowercased(), !t.isEmpty, !s.responsible.displayName.lowercased().contains(t) { return false }
        return true
    }
}

/// `daily`: daily aggregates matching the event filters, newest day first, from one reply (the newest
/// `DailyAggregate.replyLimit`). `--limit N` keeps the newest N.
func dailyRows(_ c: IPCClient) throws -> [DailyAggregate] {
    let q = try eventQuery()
    let all = try c.dailyAggregates(since: q.since)
    if all.count >= DailyAggregate.replyLimit {
        note(language == .zhHans ? "注意：守护进程只发送最新的 \(DailyAggregate.replyLimit) 行按天汇总；全部见 `whoread export --aggregates`。"
                                 : "note: the daemon sends the newest \(DailyAggregate.replyLimit) per-day rows; "
                                   + "`whoread export --aggregates` has them all")
    }
    let rows = all.filter(dailyFilter(q))
    return try limitArg().map { Array(rows.prefix($0)) } ?? rows
}

/// `export --aggregates`: every daily aggregate matching the event filters, oldest day first, read
/// page by page (a reply holds at most `DailyAggregate.replyLimit`, newest day first). `--limit N`
/// keeps the oldest N, as for the events `export` writes, so every page is read first.
func allDailyRows(_ c: IPCClient) throws -> [DailyAggregate] {
    let q = try eventQuery()
    let keep = dailyFilter(q)
    var rows: [DailyAggregate] = []
    var seen = Set<DailyAggregate.Key>()
    var after: DailyAggregate.Key?
    while true {
        let page = try c.dailyAggregates(since: q.since, limit: exportPageSize, after: after)
        // A daemon that ignores the cursor (an older build) sends the same rows again: keep each row
        // once, and stop.
        let fresh = page.filter { seen.insert($0.key).inserted }
        rows += fresh.filter(keep)
        guard page.count == exportPageSize, fresh.count == page.count, let last = page.last else { break }
        after = last.key
    }
    let oldestFirst = Array(rows.reversed())
    return try limitArg().map { Array(oldestFirst.prefix($0)) } ?? oldestFirst
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
    /// Standard output is a terminal: CSV cells are shown with hidden characters escaped. A file or
    /// a pipe gets the exact CSV.
    let toTerminal: Bool

    init(path: String?) throws {
        if let path {
            // Owner-only (0600) from the first byte whatever the umask (history names every user's
            // protected files), never through a link or into a file someone else created, and renamed
            // inside the directory opened at the start (privacy-4).
            do { staged = try StagedFile(path: path, mode: 0o600) } catch {
                throw CLIError("cannot write \(path): \(error)")
            }
            handle = staged!.handle
            toTerminal = false
        } else {
            staged = nil
            handle = FileHandle.standardOutput
            toTerminal = isatty(STDOUT_FILENO) != 0
        }
    }

    func write(_ data: Data) throws {
        buffer.append(data)
        if buffer.count >= 1 << 20 { try flush() }
    }

    func write(_ s: String) throws { try write(Data(s.utf8)) }

    /// Whole CSV rows: on a terminal, ESC, C1, bidi and the other hidden characters (and line breaks
    /// inside a cell) are written as `\u{…}` escapes (`Exporter.terminalSafeCSV`).
    func writeCSV(_ rows: String) throws { try write(toTerminal ? Exporter.terminalSafeCSV(rows) : rows) }

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

func exportFormat() throws -> Exporter.Format {
    guard let f = Exporter.Format(rawValue: args.value("format") ?? "json") else { throw CLIError.usage("--format json|jsonl|csv") }
    return f
}

func cmdExport(_ c: IPCClient) throws {
    let f = try exportFormat()
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
        note(args.has("aggregates") ? tr("exported \(count) daily aggregates to \(path)", "已导出 \(count) 条按天汇总到 \(path)")
                                    : tr("exported \(count) events to \(path)", "已导出 \(count) 条事件到 \(path)"))
    }
}

/// Every matching event, oldest first, fetched in pages and streamed out (`--limit N`: the oldest N).
func exportEvents(_ c: IPCClient, format f: Exporter.Format, to w: ExportWriter) throws -> Int {
    var q = try eventQuery()
    noteRolledUp(c, since: q.since)
    let total = try limitArg() ?? Int.max
    q.newestFirst = false
    // Pin the end of the window so a busy machine cannot keep the export chasing new events.
    if q.until == nil { q.until = Date() }
    let catalog = try? c.catalog().catalog
    let pretty = Exporter.encoder(pretty: true)
    let compact = Exporter.encoder(pretty: false)
    switch f {
    case .json: try w.write("[")
    case .jsonl: break
    case .csv: try w.writeCSV(Exporter.csvColumns.joined(separator: ",") + "\n")
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
            guard try onlyUndecodable(c, q, depth: undecodableProbeDepth) else { break }
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
            if let nl = csv.firstIndex(of: "\n") { try w.writeCSV(String(csv[csv.index(after: nl)...])) }
        }
        count += page.count
        q.afterID = last.id
    }
    if f == .json { try w.write(count == 0 ? "]\n" : "\n]\n") }
    if skipped {
        note(tr("warning: the daemon could not decode some stored events (written by a newer build, or damaged); they are not in the export",
                "警告：daemon 无法解码部分已存储的事件（由较新的版本写入，或已损坏）；它们不在导出结果中"))
    }
    return count
}

/// Per-day totals (details older than detail-days live only here), oldest day first.
func exportAggregates(_ c: IPCClient, format f: Exporter.Format, to w: ExportWriter) throws -> Int {
    let rows = try allDailyRows(c)
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
        try w.writeCSV(["day", "responsible", "responsible_kind", "responsible_key", "category", "category_name", "agent",
                        "first", "last", "count", "reads", "writes", "denied", "benign"].joined(separator: ",") + "\n")
        for a in rows {
            let s = a.summary
            let cells = [a.day, s.responsible.displayName, s.responsible.kind.rawValue, s.responsible.key, s.categoryID,
                         catalog?.category(s.categoryID)?.name.en ?? "", s.agentID ?? "",
                         RFC3339.format(s.firstSeen, fractionDigits: 6), RFC3339.format(s.lastSeen, fractionDigits: 6),
                         String(s.count), String(s.reads), String(s.writes), String(s.denied), s.benign ? "true" : "false"]
            try w.writeCSV(cells.map(Exporter.csvField).joined(separator: ",") + "\n")
        }
    }
    return rows.count
}

/// `whoread enforcement [on|off|status]`, checked (also before connecting).
func enforcementWord() throws -> String {
    let word = args.positional.dropFirst().first ?? "status"
    guard ["on", "off", "status"].contains(word) else {
        throw CLIError.usage("unknown: enforcement \(word)\nusage: whoread enforcement on|off|status")
    }
    return word
}

/// Why enforcement is not in effect, in the output language.
func reasonText(_ r: EnforcementState.InactiveReason) -> String {
    guard language == .zhHans else { return r.rawValue }
    switch r {
    case .disabledByUser: return "已被关闭"
    case .killSwitchFile: return "kill switch 文件存在"
    case .latencyTripped: return "延迟超限"
    case .rulesFailedToLoad: return "规则加载失败"
    case .sourceCannotEnforce: return "当前事件源不能拦截"
    }
}

/// "ACTIVE (setting on)", "inactive (setting off)" and why, as `status` and `enforcement` show it.
func enforcementText(_ s: DaemonStatus, reasonsAfter sep: String) -> String {
    tr("\(s.enforcementActive ? "ACTIVE" : "inactive") (setting \(s.enforcementEnabled ? "on" : "off"))",
       "\(s.enforcementActive ? "已生效" : "未生效")（设置：\(s.enforcementEnabled ? "开" : "关")）")
        + (s.enforcementInactiveReasons.isEmpty ? "" : sep + s.enforcementInactiveReasons.map(reasonText).joined(separator: tr(", ", "、")))
}

func cmdEnforcement(_ c: IPCClient) throws {
    switch try enforcementWord() {
    case "on": _ = try c.call(.setEnforcement(enabled: true))
    case "off": _ = try c.call(.setEnforcement(enabled: false))
    default: break
    }
    let s = try c.status()
    out(tr("enforcement ", "拦截") + enforcementText(s, reasonsAfter: tr(": ", "：")))
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
        let scope = r.chainAgents.map { $0.isEmpty ? ", no AI agent in chain" : ", chain agents " + $0.joined(separator: ",") }
            .map { r.coversUnknownAncestry ? $0 + " (also unknown starter)" : $0 } ?? ""
        let state = (!r.enabled ? "off" : (r.action == .deny ? (r.enforce ? "ENFORCE" : "dry-run") : "on"))
            + (r.expiresAt.map { " until " + Format.time($0) } ?? "")
        return [r.id, state, r.action.rawValue, r.access.rawValue, target, subject + scope, r.name ?? ""]
    }
    let rulesHeader = language == .zhHans ? ["编号", "状态", "动作", "访问", "目标", "主体", "名称"] : ["ID", "STATE", "ACTION", "ACCESS", "TARGET", "SUBJECT", "NAME"]
    func modify(_ id: String, _ f: (inout Rule) -> Void) throws {
        guard var r = try c.rules().first(where: { $0.id == id }) else { throw CLIError("no rule \(id)") }
        f(&r)
        _ = try c.call(.upsertRule(r))
        out(Format.table([describe(r)], header: rulesHeader))
    }
    switch sub {
    case "list":
        let rules = try c.rules()
        if let e = try? c.status().rulesLoadError {
            note(tr("warning: the stored rules could not be loaded (\(DisplayText.escaped(e))); enforcement is off. "
                        + "Fix with: sudo whoread rules replace --json-file RULES.json --confirm "
                        + "(unreadable rows are kept in the rules_backup table)",
                    "警告：已存储的规则无法加载（\(DisplayText.escaped(e))）；拦截已关闭。"
                        + "修复：sudo whoread rules replace --json-file RULES.json --confirm"
                        + "（无法读取的行保存在 rules_backup 表中）"))
        }
        if args.json { return outJSON(try Format.json(rules)) }
        out(Format.table(rules.map(describe), header: rulesHeader))
    case "templates":
        outJSON(try Format.json(RuleTemplates.all))
    case "add":
        let file = try rulesFileArg()
        let data = try Data(contentsOf: URL(fileURLWithPath: file))
        let rules: [Rule]
        if let list = try? Exporter.decoder().decode([Rule].self, from: data) {
            rules = list
        } else {
            rules = [try Exporter.decoder().decode(Rule.self, from: data)]
        }
        for r in rules { _ = try c.call(.upsertRule(r)) }
        out(tr("saved \(rules.count) rule(s)", "已保存 \(rules.count) 条规则"))
    case "replace":
        let file = try rulesFileArg()
        let data = try Data(contentsOf: URL(fileURLWithPath: file))
        let rules: [Rule]
        if let list = try? Exporter.decoder().decode([Rule].self, from: data) {
            rules = list
        } else {
            rules = [try Exporter.decoder().decode(Rule.self, from: data)]
        }
        _ = try c.call(.replaceRules(rules))
        out(tr("replaced: \(rules.count) rule(s)", "已替换：\(rules.count) 条规则"))
    case "enable": try modify(try idArg()) { $0.enabled = true }
    case "disable": try modify(try idArg()) { $0.enabled = false }
    case "enforce": try modify(try idArg()) { $0.enforce = true; $0.enabled = true }
    case "dry-run": try modify(try idArg()) { $0.enforce = false }
    case "delete":
        _ = try c.call(.deleteRule(id: try idArg()))
        out(tr("deleted", "已删除"))
    default:
        throw CLIError.usage("unknown: rules \(sub)")
    }
}

func idArg() throws -> String {
    guard args.positional.count >= 3 else { throw CLIError.usage("missing rule id") }
    // A stray extra word is a mistake (an unquoted name with a space), not something to ignore.
    guard args.positional.count == 3 else { throw CLIError.usage("one rule id at a time: whoread rules \(args.positional[1]) ID") }
    return args.positional[2]
}

/// `rules add|replace --json-file F` (`replace` also needs `--confirm`), checked (also before connecting).
func rulesFileArg() throws -> String {
    let replace = args.positional.dropFirst().first == "replace"
    guard let file = args.value("json-file") else {
        throw CLIError.usage(replace ? "usage: whoread rules replace --json-file RULES.json --confirm" : "usage: whoread rules add --json-file RULE.json")
    }
    if replace && !args.has("confirm") {
        throw CLIError.usage("rules replace deletes every current rule and stores the file's rules instead; add --confirm")
    }
    return file
}

/// A catalog prefix as the classifier expects it: absolute or `~/`, no `.`/`..`, narrower than a
/// whole disk or home. `homes` are the daemon's monitored homes: a home, or a folder holding one,
/// is refused however it is spelled (`~/` alone, `/Users/alice`, `/Users`, a firmlinked form).
func catalogPath(_ raw: String, homes: [String]) throws -> String {
    let p = raw.trimmingCharacters(in: .whitespaces)
    guard p.hasPrefix("/") || p.hasPrefix("~/") else { throw CLIError.usage("path must start with / or ~/: \(raw)") }
    let parts = p.split(separator: "/")
    guard !parts.contains("..") && !parts.contains(".") else { throw CLIError.usage("path must not contain . or ..: \(raw)") }
    guard parts.count > (p.hasPrefix("~/") ? 1 : 0) else { throw CLIError.usage("\(p) is too broad to monitor") }
    if p.hasPrefix("/") {
        let normalizer = PathNormalizer(homeDirectories: homes)
        let key = normalizer.matchKey(p)
        // The data volume's own spelling (/System/Volumes/Data) is the whole disk too.
        guard key != "/" else { throw CLIError.usage("\(p) is too broad to monitor") }
        let homeKeys = normalizer.homeDirectories.map(PathNormalizer.fold) + ["/users"]
        if homeKeys.contains(where: { $0 == key || $0.hasPrefix(key + "/") }) {
            throw CLIError.usage("\(p) is too broad to monitor: it is or holds a home folder (use ~/FOLDER for a folder in every home)")
        }
    }
    return p
}

func severityArg(_ v: String) throws -> Severity {
    guard let s = Severity(rawValue: v.lowercased()) else { throw CLIError.usage("severity must be medium, high or critical") }
    return s
}

/// A project root as typed (`settings set project-root-add`): absolute, `~/FOLDER` (that folder in
/// every home), or relative to the current folder, which is made absolute here (`.` in a project
/// means that project; the daemon has no current folder). Then the checks of a catalog path
/// (`catalogPath`): an entry the classifier cannot expand, or one as broad as a home, would be
/// stored and never monitored. `~name` (another user's home) is not a form the catalog knows.
func projectRoot(_ raw: String, homes: [String] = []) throws -> String {
    let p = raw.trimmingCharacters(in: .whitespaces)
    guard !p.isEmpty else { throw CLIError.usage("project root: the path is empty") }
    if p.hasPrefix("~") && !p.hasPrefix("~/") {
        throw CLIError.usage("project root \(raw): use ~/FOLDER for that folder in every home, or an absolute path")
    }
    return try catalogPath(fromCurrentFolder(p) ?? p, homes: homes)
}

/// A relative path made absolute against the current folder; nil for one that is absolute or
/// starts with `~`.
func fromCurrentFolder(_ p: String) -> String? {
    guard !p.hasPrefix("/") && !p.hasPrefix("~") else { return nil }
    return PathNormalizer().normalize(FileManager.default.currentDirectoryPath + "/" + p)
}

/// The key two spellings of one project root share (a trailing /, case, a firmlinked form).
func projectRootKey(_ p: String) -> String { PathNormalizer().matchKey(p.trimmingCharacters(in: .whitespaces)) }

/// `catalog add-category ID NAME_EN NAME_ZH SEVERITY [--path PATH]...`, checked (also before
/// connecting, with no homes: the daemon's homes are checked again once it answers).
func newCategory(homes: [String]) throws -> CategorySpec {
    let p = args.positional
    guard p.count == 6 else { throw CLIError.usage("usage: whoread catalog add-category ID NAME_EN NAME_ZH medium|high|critical [--path PATH]...") }
    let id = p[2], en = p[3], zh = p[4]
    let severity = try severityArg(p[5])
    guard id.range(of: "^[a-z0-9][a-z0-9-]*$", options: .regularExpression) != nil else {
        throw CLIError.usage("category id: lowercase letters, digits and -")
    }
    guard !en.trimmingCharacters(in: .whitespaces).isEmpty else { throw CLIError.usage("NAME_EN must not be empty") }
    let paths = try args.all("path").map { try catalogPath($0, homes: homes) }
    return CategorySpec(id: id, name: LocalizedText(en: en, zhHans: zh), kind: .custom, group: "custom", severity: severity, paths: paths)
}

func cmdCatalog(_ c: IPCClient) throws {
    let sub = args.positional.dropFirst().first ?? "show"
    func arg(_ n: Int, _ usage: String) throws -> String {
        guard args.positional.count > n else { throw CLIError.usage("usage: whoread catalog \(usage)") }
        return args.positional[n]
    }
    /// Exactly `count` positionals (counting "catalog" and the subcommand): a stray word, such as
    /// the tail of an unquoted path with a space, must not be silently dropped.
    func expect(_ count: Int, _ usage: String) throws {
        guard args.positional.count == count else { throw CLIError.usage("usage: whoread catalog \(usage)") }
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
            out("\(cat.id) — \(cat.name.resolve(language))  [\(cat.kind.rawValue), \(cat.severity.rawValue)\(cat.enabled ? "" : tr(", disabled", "，已停用"))]")
            out(cat.paths.isEmpty ? tr("  (no paths)", "  （没有路径）") : cat.paths.map { "  " + $0 }.joined(separator: "\n"))
            if !cat.patterns.isEmpty {
                out(tr("  \(cat.patterns.count) file pattern(s), \(cat.owners.count) owner(s)",
                       "  \(cat.patterns.count) 个文件模式，\(cat.owners.count) 个拥有者"))
            }
            let prefixes = info.prefixes.filter { $0.categoryID == id }
            if !prefixes.isEmpty {
                out(language == .zhHans ? "本机监控的前缀：" : "monitored on this machine:")
                prefixes.forEach { out("  " + $0.path + ($0.viaSymlink ? tr(" (via symlink)", "（经由符号链接）") : "")) }
            }
            return
        }
        if args.json { return outJSON(try Format.json(info)) }
        var rows: [[String]] = []
        for cat in info.catalog.categories {
            let prefixes = info.prefixes.filter { $0.categoryID == cat.id }
            let detected = info.detected[cat.id] == true ? (language == .zhHans ? "已检测到" : "detected") : (language == .zhHans ? "未检测到" : "not detected")
            rows.append([cat.id, cat.name.resolve(language), cat.severity.rawValue, cat.enabled ? detected : tr("disabled", "已停用"),
                         String(prefixes.count), String(cat.owners.count)])
        }
        out(Format.table(rows, header: language == .zhHans ? ["编号", "名称", "严重性", "状态", "前缀", "拥有者"]
                                                           : ["ID", "NAME", "SEVERITY", "STATE", "PREFIXES", "OWNERS"]))
    case "add-path", "remove-path":
        let usage = "\(sub) CATEGORY PATH"
        try expect(4, usage)
        let id = try arg(2, usage)
        let path = sub == "add-path" ? try catalogPath(try arg(3, usage), homes: try info().homeDirectories)
            : try arg(3, usage).trimmingCharacters(in: .whitespaces)
        try edit { cat in
            let i = try index(cat, id)
            if cat.categories[i].kind == .projectRoots {
                throw CLIError.usage("\(id) takes its folders from the project roots setting: whoread settings set project-root-add PATH")
            }
            if sub == "remove-path" {
                guard cat.categories[i].paths.contains(path) else { throw CLIError("\(id) has no path \(path)") }
                cat.categories[i].paths.removeAll { $0 == path }
                return tr("removed \(path) from \(id)", "已从 \(id) 移除 \(path)")
            }
            guard !cat.categories[i].paths.contains(path) else { throw CLIError("\(id) already has \(path)") }
            cat.categories[i].paths.append(path)
            return tr("added \(path) to \(id)", "已把 \(path) 加入 \(id)")
                + (cat.categories[i].enabled ? "" : tr(" (category is disabled: whoread catalog enable \(id))", "（类别已停用：whoread catalog enable \(id)）"))
        }
    case "add-category":
        let spec = try newCategory(homes: try info().homeDirectories)
        let id = spec.id, paths = spec.paths
        try edit { cat in
            guard cat.category(id) == nil else { throw CLIError("category \(id) already exists") }
            cat.categories.append(spec)
            return tr("added category \(id)", "已添加类别 \(id)")
                + (paths.isEmpty ? tr(" (no paths yet: whoread catalog add-path \(id) PATH)", "（还没有路径：whoread catalog add-path \(id) PATH）")
                                 : tr(" with \(paths.count) path(s)", "，含 \(paths.count) 个路径"))
        }
    case "remove-category":
        try expect(3, "remove-category ID")
        let id = try arg(2, "remove-category ID")
        try edit { cat in
            let i = try index(cat, id)
            guard cat.categories[i].kind == .custom else { throw CLIError("\(id) is built in: turn it off with whoread catalog disable \(id)") }
            cat.categories.remove(at: i)
            return tr("removed category \(id)", "已删除类别 \(id)")
        }
    case "set-severity":
        let usage = "set-severity ID medium|high|critical"
        try expect(4, usage)
        let id = try arg(2, usage)
        let severity = try severityArg(try arg(3, usage))
        try edit { cat in
            let i = try index(cat, id)
            cat.categories[i].severity = severity
            return tr("\(id): severity \(severity.rawValue)", "\(id)：严重性 \(severity.rawValue)")
        }
    case "enable", "disable":
        try expect(3, "\(sub) ID")
        let id = try arg(2, "\(sub) ID")
        try edit { cat in
            let i = try index(cat, id)
            cat.categories[i].enabled = sub == "enable"
            return "\(id)" + tr(": \(sub)d", sub == "enable" ? "：已启用" : "：已停用")
        }
    case "export":
        let data = try c.catalog().catalog.encoded() + Data("\n".utf8)
        if let path = args.value("output") ?? args.value("o") {
            // Like the history export: owner-only (it names the paths the user protects), never through
            // or over a link or another non-regular file, and given to the user who ran sudo in their
            // own folder (privacy-4).
            let writer = try ExportWriter(path: path)
            do {
                try writer.write(data)
                try writer.finish()
            } catch {
                writer.abandon()
                throw error
            }
            note(tr("catalog written to \(path)", "catalog 已写入 \(path)"))
        } else {
            // Hidden characters (a bidi override in a path a rule added, say) as \u escapes, like
            // --json: inert on a terminal, and the same catalog decodes from it (it imports again).
            // A closed or broken standard output is an error, not an abort.
            try FileHandle.standardOutput.write(contentsOf: Data(Format.terminalSafeJSON(String(decoding: data, as: UTF8.self)).utf8))
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
        out(tr("catalog imported: \(catalog.categories.count) categories", "catalog 已导入：\(catalog.categories.count) 个类别"))
    case "resolve-owners":
        #if os(macOS)
        let info = try c.catalog()
        let (resolved, report) = OwnerResolver.resolve(catalog: info.catalog, reader: CodesignCommandReader(),
                                                       exists: { FileManager.default.fileExists(atPath: $0) })
        _ = resolved
        report.resolved.forEach { out(tr("  resolved ", "  已解析 ") + $0) }
        out(tr("\(report.resolved.count) resolved, \(report.missing.count) not installed, \(report.skippedGlobs) glob patterns left as is",
               "已解析 \(report.resolved.count) 个，\(report.missing.count) 个未安装，\(report.skippedGlobs) 个通配模式保持不变"))
        // Writing these into catalog.json would freeze the owners against later default updates; the
        // daemon resolves them in memory at every start and after catalog changes instead.
        out(tr("Nothing was written: the daemon applies these identities in memory at start.",
               "没有写入任何内容：daemon 每次启动时在内存中应用这些身份。"))
        #else
        throw CLIError("resolve-owners runs codesign and needs macOS")
        #endif
    case "reset":
        _ = try c.call(.resetCatalog)
        out(tr("catalog reset to defaults", "catalog 已恢复为默认"))
    case let other:
        throw CLIError.usage("unknown: catalog \(other)")
    }
}

/// `settings set KEY VALUE` as a change to the daemon's settings, checked before anything is sent: an
/// unknown key or a value that does not parse is a usage error.
enum SettingChange {
    case apply((inout Settings) -> Void)
    /// Absolute or `~/…`, checked (`projectRoot`); the daemon's homes are checked once it answers.
    case addProjectRoot(String)
    /// As typed, and made absolute when it is relative.
    case removeProjectRoot(typed: String, absolute: String?)
}

func settingChange(_ key: String, _ value: String) throws -> SettingChange {
    func bool() throws -> Bool {
        switch value {
        case "on", "true", "yes", "1": return true
        case "off", "false", "no", "0": return false
        default: throw CLIError.usage("\(key): expected on or off, not \"\(value)\"")
        }
    }
    func number() throws -> Double {
        guard let d = Double(value), d.isFinite else { throw CLIError.usage("\(key): expected a number, not \"\(value)\"") }
        return d
    }
    func integer() throws -> Int {
        guard let n = Int(value) else { throw CLIError.usage("\(key): expected a whole number, not \"\(value)\"") }
        return n
    }
    switch key {
    case "learning-days": let d = try number(); return .apply { $0.learningDays = d }
    case "retention-days": let n = try integer(); return .apply { $0.retentionDays = n }
    case "detail-days": let n = try integer(); return .apply { $0.detailDays = n }
    case "coalesce-minutes": let d = try number(); return .apply { $0.coalesceMinutes = d }
    case "readdir": let b = try bool(); return .apply { $0.readdirEnabled = b }
    case "project-root-add": return .addProjectRoot(try projectRoot(value))
    case "project-root-remove": return .removeProjectRoot(typed: value, absolute: fromCurrentFolder(value.trimmingCharacters(in: .whitespaces)))
    case "notifications": let b = try bool(); return .apply { $0.notifications.enabled = b }
    case "min-severity":
        guard let sev = Severity(rawValue: value) else { throw CLIError.usage("min-severity: medium|high|critical") }
        return .apply { $0.notifications.minimumSeverity = sev }
    case "latency-p99-ms": let d = try number(); return .apply { $0.latencyP99ThresholdMs = d }
    case "trust-apple": let b = try bool(); return .apply { $0.trustApplePrograms = b }
    case "language":
        // zh* means Simplified Chinese, as with --lang; an unknown value is an error, not "system".
        switch value.lowercased() {
        case "system": return .apply { $0.language = nil }
        case "en": return .apply { $0.language = .en }
        case let v where v.hasPrefix("zh"): return .apply { $0.language = .zhHans }
        default: throw CLIError.usage("language: en|zh-Hans|system")
        }
    default:
        throw CLIError.usage("unknown setting \(key) (keys: retention-days detail-days coalesce-minutes readdir project-root-add "
                             + "project-root-remove notifications min-severity latency-p99-ms language trust-apple)")
    }
}

func cmdSettings(_ c: IPCClient) throws {
    var s = try c.settings()
    guard args.positional.dropFirst().first == "set" else {
        return outJSON(try Format.json(s))
    }
    // Exactly one VALUE: the tail of an unquoted path with a space must not be dropped.
    guard args.positional.count == 4 else { throw CLIError.usage("settings set KEY VALUE (quote a VALUE that has spaces)") }
    switch try settingChange(args.positional[2], args.positional[3]) {
    case .apply(let change):
        change(&s)
    case .addProjectRoot(let root):
        // A home, or a folder holding one, however spelled: refused like a catalog path.
        _ = try catalogPath(root, homes: try c.catalog().homeDirectories)
        if let same = s.projectRoots.first(where: { projectRootKey($0) == projectRootKey(root) }) {
            note(tr("\(root) is already a project root (\(same))", "\(root) 已经是项目根目录（\(same)）"))
            return outJSON(try Format.json(s))
        }
        s.projectRoots.append(root)
    case .removeProjectRoot(let typed, let absolute):
        // The spelling stored (an entry that never worked, such as ".", can still be removed), or
        // the same folder spelled another way (a trailing /, case, relative to the current folder).
        let keys = Set([typed, absolute].compactMap { $0 }.map(projectRootKey))
        let kept = s.projectRoots.filter { $0 != typed && !keys.contains(projectRootKey($0)) }
        guard kept.count < s.projectRoots.count else {
            let list = s.projectRoots.isEmpty ? tr("none", "无") : s.projectRoots.joined(separator: ", ")
            throw CLIError(tr("no project root \(typed) (project roots: \(list))", "没有项目根目录 \(typed)（项目根目录：\(list)）"))
        }
        s.projectRoots = kept
    }
    _ = try c.call(.updateSettings(s))
    outJSON(try Format.json(try c.settings()))
}

func cmdBaseline(_ c: IPCClient) throws {
    if args.positional.dropFirst().first == "restart-learning" {
        _ = try c.call(.restartLearning)
        return out(tr("learning restarted", "学习已重新开始"))
    }
    guard case .baseline(let entries) = try c.call(.baseline) else { return }
    if args.json { return outJSON(try Format.json(entries)) }
    out(Format.table(entries.map { [$0.key.responsibleKey, $0.key.categoryID, $0.key.access.rawValue, $0.source.rawValue, String($0.count), Format.time($0.lastSeen)] },
                     header: language == .zhHans ? ["应用", "类别", "访问", "来源", "次数", "最近"]
                                                 : ["RESPONSIBLE", "CATEGORY", "ACCESS", "SOURCE", "COUNT", "LAST"]))
    if entries.count >= Baseline.replyLimit {
        note(tr("note: the daemon sends the \(Baseline.replyLimit) most recently seen entries",
                "注意：daemon 只发送最近见到的 \(Baseline.replyLimit) 条"))
    }
}

/// `whoread kill-switch [engage|release|status]`, checked (also before anything is changed).
func killSwitchWord() throws -> String {
    let word = args.positional.dropFirst().first ?? "status"
    guard ["engage", "release", "status"].contains(word) else {
        throw CLIError.usage("unknown: kill-switch \(word)\nusage: whoread kill-switch engage|release|status [--path P]")
    }
    return word
}

/// The errno behind a failed file operation, if there is one.
func posixCode(_ error: Error) -> Int32? {
    if let f = error as? SafeFile.Failure { return f.errno == 0 ? nil : f.errno }
    let ns = error as NSError
    if ns.domain == NSPOSIXErrorDomain { return Int32(ns.code) }
    if let u = ns.userInfo[NSUnderlyingErrorKey] as? NSError, u.domain == NSPOSIXErrorDomain { return Int32(u.code) }
    if ns.domain == NSCocoaErrorDomain && [NSFileWriteNoPermissionError, NSFileReadNoPermissionError].contains(ns.code) { return EACCES }
    return nil
}

/// The kill switch could not be created or removed: "run with sudo" (77) only when permission is
/// what failed; anything else (a missing folder, say) is reported as the system put it.
func killSwitchFailure(_ what: String, _ error: Error) -> CLIError {
    let code = posixCode(error)
    guard code == EACCES || code == EPERM else { return CLIError("\(what): \(error)") }
    return CLIError(tr("\(what) (run with sudo): \(error)", "\(what)（请用 sudo 运行）：\(error)"), exitCode: 77)
}

func cmdKillSwitch() throws {
    let path = args.value("path") ?? WhoReadPaths.killSwitchFile
    switch try killSwitchWord() {
    case "engage":
        do { try SafeFile.replace(path, with: Data("disabled by whoread kill-switch\n".utf8), mode: 0o644) } catch {
            throw killSwitchFailure(tr("cannot create \(path)", "无法创建 \(path)"), error)
        }
        out(tr("kill switch ENGAGED: \(path) exists; enforcement is off within ~0.2 s", "kill switch 已启用：\(path) 已存在；拦截会在约 0.2 秒内关闭"))
    case "release":
        if FileManager.default.fileExists(atPath: path) {
            do { try FileManager.default.removeItem(atPath: path) } catch {
                throw killSwitchFailure(tr("cannot remove \(path)", "无法删除 \(path)"), error)
            }
        }
        out(tr("kill switch released", "kill switch 已解除"))
    default:
        out(FileManager.default.fileExists(atPath: path) ? tr("kill switch ENGAGED (\(path))", "kill switch 已启用（\(path)）")
                                                         : tr("kill switch not engaged", "kill switch 未启用"))
    }
}

/// `replay`'s `--learning-days N` (left out of the help), checked.
func replayLearningDays() throws -> Double? {
    guard let d = args.value("learning-days") else { return nil }
    guard let days = Double(d), days.isFinite, days >= 0 else { throw CLIError.usage("--learning-days: a number of days, 0 or more (not \"\(d)\")") }
    return days
}

func cmdReplay() throws {
    guard args.positional.count == 2 else { throw CLIError.usage("usage: whoread replay FILE.jsonl [--home DIR]... [--defaults DIR] [--all] [--json]") }
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
    if let days = try replayLearningDays() {
        var s = core.currentSettings
        s.learningDays = days
        try core.update(settings: s, peer: .inProcess)
    }
    try core.source.start(sink: core.pipeline)
    guard let replay = core.source as? ReplaySource, replay.waitUntilFinished(timeout: 600) else { throw CLIError("replay timed out") }
    core.writer.flush()
    let client = InProcessClient(handler: Daemon.handlerForReplay(core))
    let events = try client.events(EventQuery(includeBenign: args.has("all"), limit: 1_000_000, newestFirst: false))
    // Every alert: the in-memory store has no cap of its own, and the count below is the total.
    let alerts = try client.alerts(AlertQuery(limit: Int.max))
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

/// `fixture sanitize …`, checked (also before anything is read or written).
struct FixtureArgs {
    var input: String
    var output: String
    var home: String
    var vault: String?
    var sample: Int
    var capturePID: Int32?
}

func fixtureArgs() throws -> FixtureArgs {
    guard args.positional.count == 2, args.positional[1] == "sanitize", let input = args.value("input"), let output = args.value("output") else {
        throw CLIError.usage("usage: whoread fixture sanitize --input RAW.jsonl|/dev/stdin --output OUT.jsonl [--home DIR] [--vault DIR] [--capture-pid PID] [--sample N]")
    }
    var sample = 40
    if let n = args.value("sample") {
        guard let v = Int(n), v >= 0 else { throw CLIError.usage("--sample: a whole number, 0 or more (not \"\(n)\")") }
        sample = v
    }
    var pid: Int32?
    if let p = args.value("capture-pid") {
        guard let v = Int32(p), v > 1 else { throw CLIError.usage("--capture-pid: not a pid: \(p)") }
        pid = v
    }
    return FixtureArgs(input: input, output: output, home: args.value("home") ?? NSHomeDirectory(), vault: args.value("vault"),
                       sample: sample, capturePID: pid)
}

func cmdFixture() throws {
    let a = try fixtureArgs()
    // A file or a pipe (capture-fixture.sh streams the root-only raw capture through `sudo cat`).
    guard let handle = FileHandle(forReadingAtPath: a.input) else { throw CLIError("cannot read \(a.input)") }
    let data = try handle.readToEnd() ?? Data()
    var sanitizer = FixtureSanitizer(home: a.home, vault: a.vault, samplePerKind: a.sample)
    if let pid = a.capturePID { sanitizer.capturePID = pid }
    let (kept, report) = sanitizer.sanitize(data: data)
    try SafeFile.replace(a.output, with: Data((kept.joined(separator: "\n") + "\n").utf8), mode: 0o600)
    out("kept \(report.kept) of \(report.inputLines) lines: \(report.vaultEvents) vault events, \(report.lifecycle) lifecycle, \(report.samples) samples; by kind \(report.byKind); dropped \(report.foreignVaultEvents) vault events of other programs, \(report.undecodableLines) lines not UTF-8")
}

// MARK: - Arguments

/// What `events`, `daily` and `export` filter by.
let eventFilterValues: Set<String> = ["since", "until", "category", "app", "search", "agent", "limit"]
let eventFilterSwitches: Set<String> = ["agents-only", "all", "denied"]

/// What `whoread COMMAND …` takes, as typed (the subcommand decides for rules, catalog, settings,
/// baseline). Built from the names each command's code reads; a few are left out of the help on
/// purpose (`learning-days`, `verbose`, `baseline restart-learning`).
func commandSpec(_ command: String) throws -> CommandSpec {
    let sub = args.positional.dropFirst().first
    let named = ["rules", "catalog", "settings", "baseline", "fixture"].contains(command)
    func spec(_ usage: String, _ positionals: ClosedRange<Int> = 1...1, switches: Set<String> = [], values: Set<String> = [],
              repeatable: Set<String> = []) -> CommandSpec {
        CommandSpec(name: command + (named && positionals.lowerBound > 1 ? " " + (sub ?? "") : ""), usage: usage, positionals: positionals,
                    switches: switches, values: values, repeatable: repeatable)
    }
    let filters = "[--since …] [--until …] [--category ID]... [--app TEXT] [--agent ID] [--agents-only] [--denied] [--all] [--limit N]"
    switch command {
    case "status", "asks", "read-all", "pause", "resume", "agents", "version": return spec(command)
    case "help": return spec("help", 1...2)
    case "events":
        return spec("events " + filters + " [--search TEXT]", switches: eventFilterSwitches, values: eventFilterValues, repeatable: ["category"])
    case "tail": return spec("tail [--all]", switches: ["all"])
    case "alerts": return spec("alerts [--unread] [--since …] [--limit N]", switches: ["unread"], values: ["since", "limit"])
    case "alert": return spec("alert <id> <" + alertActionWords.map(\.word).joined(separator: "|") + ">", 3...3)
    case "ask": return spec("ask <id> allow-once|allow|deny|block|trust-apple", 3...3)
    case "apps": return spec("apps [--since …] [--all]", switches: ["all"], values: ["since"])
    case "files": return spec("files [--all]", switches: ["all"])
    case "daily":
        // A day's row names the app only: no program name or path to --search.
        return spec("daily " + filters, switches: eventFilterSwitches, values: eventFilterValues.subtracting(["search"]), repeatable: ["category"])
    case "export":
        if args.has("aggregates") {
            return spec("export --aggregates --format json|jsonl|csv [--output FILE] " + filters, switches: eventFilterSwitches.union(["aggregates"]),
                        values: eventFilterValues.subtracting(["search"]).union(["format", "output", "o"]), repeatable: ["category"])
        }
        return spec("export --format json|jsonl|csv [--output FILE] " + filters + " [--search TEXT]",
                    switches: eventFilterSwitches.union(["aggregates"]), values: eventFilterValues.union(["format", "output", "o"]),
                    repeatable: ["category"])
    case "enforcement": return spec("enforcement on|off|status", 1...2)
    case "rules":
        switch sub ?? "list" {
        case "list": return spec("rules [list]", 1...2)
        case "templates": return spec("rules templates", 2...2)
        case "add": return spec("rules add --json-file RULE.json", 2...2, values: ["json-file"])
        case "replace": return spec("rules replace --json-file RULES.json --confirm", 2...2, switches: ["confirm"], values: ["json-file"])
        case "enable", "disable", "enforce", "dry-run", "delete": return spec("rules \(sub ?? "") ID", 3...3)
        case let other:
            throw CLIError.usage("unknown: rules \(other)\nusage: whoread rules [list|templates|add|replace|enable|disable|enforce|dry-run|delete] …")
        }
    case "catalog":
        switch sub ?? "show" {
        case "show": return spec("catalog [show [ID]]", 1...3)
        case "export": return spec("catalog export [--output FILE]", 2...2, values: ["output", "o"])
        case "resolve-owners": return spec("catalog resolve-owners", 2...2)
        case "add-path", "remove-path": return spec("catalog \(sub ?? "") CATEGORY PATH", 4...4)
        case "add-category":
            return spec("catalog add-category ID NAME_EN NAME_ZH medium|high|critical [--path PATH]...", 6...6, values: ["path"], repeatable: ["path"])
        case "remove-category", "enable", "disable": return spec("catalog \(sub ?? "") ID", 3...3)
        case "set-severity": return spec("catalog set-severity ID medium|high|critical", 4...4)
        case "import": return spec("catalog import FILE", 3...3)
        case "reset": return spec("catalog reset", 2...2)
        case let other:
            throw CLIError.usage("unknown: catalog \(other)\nusage: whoread catalog [show [ID]|export|resolve-owners|add-path|remove-path|"
                                 + "add-category|remove-category|set-severity|enable|disable|import|reset] …")
        }
    case "settings":
        switch sub ?? "show" {
        case "show": return spec("settings [show]", 1...2)
        case "set": return spec("settings set KEY VALUE (quote a VALUE that has spaces)", 4...4)
        case let other: throw CLIError.usage("unknown: settings \(other)\nusage: whoread settings [show | set KEY VALUE]")
        }
    case "baseline":
        switch sub {
        case nil: return spec("baseline")
        case "restart-learning"?: return spec("baseline restart-learning", 2...2)
        case let other?: throw CLIError.usage("unknown: baseline \(other)\nusage: whoread baseline")
        }
    case "kill-switch": return spec("kill-switch engage|release|status [--path P]", 1...2, values: ["path"])
    case "replay":
        return spec("replay FILE [--home DIR]... [--defaults DIR] [--all] [--json]", 2...2, switches: ["all", "verbose"],
                    values: ["home", "defaults", "learning-days"], repeatable: ["home"])
    case "fixture":
        return spec("fixture sanitize --input RAW|/dev/stdin --output OUT [--home DIR] [--vault DIR] [--capture-pid PID] [--sample N]", 2...2,
                    values: ["input", "output", "home", "vault", "sample", "capture-pid"])
    default:
        throw CLIError.usage("unknown command \(command)\n\n\(usage)")
    }
}

/// Values that must parse before anything is sent or changed (the same functions the commands use).
func checkValues(_ command: String) throws {
    let p = args.positional
    switch command {
    case "events", "daily": _ = try eventQuery()
    case "export":
        _ = try eventQuery()
        _ = try exportFormat()
    case "alerts": _ = try alertQuery()
    case "apps": _ = try args.value("since").map { try Format.parseSince($0) }
    case "alert": _ = try alertArgs()
    case "ask": _ = try askArgs()
    case "enforcement": _ = try enforcementWord()
    case "rules" where p.count > 1 && (p[1] == "add" || p[1] == "replace"): _ = try rulesFileArg()
    case "catalog" where p.count > 1:
        switch p[1] {
        case "add-path": _ = try catalogPath(p[3], homes: [])
        case "add-category": _ = try newCategory(homes: [])
        case "set-severity": _ = try severityArg(p[3])
        default: break
        }
    case "settings" where p.count == 4: _ = try settingChange(p[2], p[3])
    case "kill-switch": _ = try killSwitchWord()
    case "replay": _ = try replayLearningDays()
    case "fixture": _ = try fixtureArgs()
    default: break
    }
}

/// Everything about the arguments that can be checked without the daemon, before connecting or
/// changing anything. A usage error (64) is reported as such, never hidden behind "cannot reach
/// the daemon", and a mistyped filter is never silently dropped.
func checkArguments(_ command: String) throws {
    do {
        try args.check(try commandSpec(command))
        try checkValues(command)
    } catch var e as CLIError {
        e.exitCode = 64
        throw e
    }
}

// MARK: - Dispatch

do {
    if args.has("help") || args.has("h") {
        out(usage)
        exit(0)
    }
    guard let command = args.positional.first else {
        out(usage)
        exit(64)
    }
    try checkArguments(command)
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
            "read-all": { c in _ = try c.call(.markAlertsRead(ids: nil)); out(tr("all alerts marked read", "所有告警已标为已读")) },
            "apps": cmdApps, "files": cmdFiles, "agents": cmdAgents, "daily": cmdDaily, "export": cmdExport,
            "enforcement": cmdEnforcement,
            "pause": { c in _ = try c.call(.setPaused(true)); out(tr("monitoring paused", "监控已暂停")) },
            "resume": { c in _ = try c.call(.setPaused(false)); out(tr("monitoring resumed", "监控已恢复")) },
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
