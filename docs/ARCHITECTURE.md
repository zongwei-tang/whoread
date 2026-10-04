# Architecture

```
                 ┌──────────────── user space, root ────────────────┐
  kernel ES ──►  │ EventSource                                       │
                 │  ├─ EsloggerSource  (/usr/bin/eslogger, NOTIFY)   │
                 │  ├─ NativeESSource  (file client: inverted target │
                 │  │                   muting, NOTIFY + AUTH;       │
                 │  │                   process client: fork/exec/   │
                 │  │                   exit)                        │
                 │  └─ ReplaySource    (JSONL file / stdin)          │
                 │          │ SourceEvent                            │
                 │          ▼                                        │
                 │  EventPipeline ──► Analyzer (WhoReadCore)         │
                 │          │          normalize → classify → chain  │
                 │          │          → attribute → benign? owner?  │
                 │          │          → rules → baseline → coalesce │
                 │          ├─► LiveBuffer (last 5000, for the UI)   │
                 │          └─► EventWriter ──► SQLiteEventStore     │
                 │                                                   │
                 │  AUTH callback ─► Enforcer (in-memory decision) ─►│ es_respond_*
                 │  ServiceHandler ◄── XPC (app, CLI) / dev socket   │
                 └───────────────────────────────────────────────────┘
       WhoRead.app (user)  ── XPC ──►  whoreadd / system extension
       whoread CLI (user/root) ─ XPC ─┘
```

## Modules

| Module | Depends on | Role | Tested on Linux |
|---|---|---|---|
| `WhoReadCore` | Foundation | All logic: models, path normalization, catalog trie, process tree, agent detection, attribution, benign services, rule engine, baseline, alert coalescing, eslogger parser + prefilter, latency monitor, enforcement state, export, alert text (en/zh). No EndpointSecurity, no IO besides what callers inject. | yes |
| `WhoReadStore` | Core, SQLite3 | `EventStore` on SQLite (WAL, 0600). | yes |
| `WhoReadIPC` | Core | Codable request/response protocol; in-process client; dev Unix socket; XPC server/client (macOS). | yes (XPC: no) |
| `WhoReadEngine` | Core, Store, IPC | Daemon runtime: sources, pipeline, writer, enforcer, kill-switch watcher, service handler, daemon lifecycle, process snapshot, owner resolver, fixture sanitizer. | yes (native ES, libproc, SecCode: no) |
| `WhoReadUIModel` | Core, IPC | App view models: snapshot fetcher, live feed, tab tables, menu bar state, notification planner, onboarding, rule draft, the en/zh UI string table. | yes |
| `whoreadd` | Engine | Daemon executable (dev LaunchDaemon). | yes |
| `whoread` | Engine | CLI. | yes |
| `App/` (Xcode) | UIModel, IPC | SwiftUI menu bar app. | no |
| `Extension/` (Xcode) | Engine | Endpoint Security system extension = whoreadd with the native source. | no |

## Data files

`Data/catalog.json` (sensitive categories, prefixes, file patterns, owners), `Data/agents.json`
(AI agent recognition) and `Data/benign.json` (system services folded as noise) are the source of
truth, generated once by `scripts/dev/gen_catalog.py`. The daemon:
- loads defaults from the bundle / `/Library/Application Support/WhoRead/defaults/`;
- keeps the user's edited catalog in `/Library/Application Support/WhoRead/catalog.json`, next to
  `catalog.base.json`, the defaults it was made from. At start the user copy is merged with the
  current defaults field by field: a field the user left as it was takes the new default, a field
  the user changed is kept, new default categories are added, deleted ones stay deleted;
- resolves third-party owner team IDs with `codesign -dv` at start and after catalog changes, in
  memory only (`OwnerResolver`), so the user copy never freezes them;
- re-discovers home directories and symlinks inside monitored directories every 5 minutes and
  swaps the classifier (and ES muting) only when the monitored set changed;
- marks categories whose prefixes do not exist as "not detected".

## Event flow

1. **Source.**
   - eslogger: every line first goes through an Aho–Corasick prefilter. It always passes
     lifecycle and multi-path events (rename, clone, link, exchangedata, copyfile, create), drops
     unmodified closes, and passes lines in which a JSON string value starts with a monitored
     prefix (case-insensitive, `/` or `\/`, with or without `/System/Volumes/Data`) and lines
     with `\u` escapes. Then the JSON is parsed. Malformed lines still advance the kernel-drop
     sequence check, which restarts with each new eslogger.
   - Native: the kernel delivers only monitored-prefix events, thanks to inverted target-path
     muting over every spelling of each prefix (catalog, on-disk/realpath, NFC and NFD). NOTIFY
     events go to an analysis queue capped at 50,000; past that they are dropped and counted
     (`whoread status`).
2. **Process events** update the `ProcessTree`. It is keyed by (pid, fork time), with images keyed
   by pidversion, which changes on exec. Children link to parents by node id, so reparenting to
   launchd and pid reuse do not break chains. Tombstones keep exited ancestors for late events.
   Unknown parents are resolved through libproc.
3. **File events** are normalized (firmlink, `/private` aliases, NFC, case fold, `~` per home) and
   classified by a component trie, split on Unicode scalars. The deepest prefix whose patterns
   accept the path wins, falling back to shallower ones; file patterns refine severity; a
   truncated path gets the category's worst severity. A directory open is a readdir (dropped
   unless readdir is enabled). Moving or cloning a directory is judged by the worst file it can
   hold, and moving a parent directory maps to *every* category below it (one event each).
   Non-sensitive events are dropped here.
4. **Attribution** walks the chain leaf → root:
   - the first `.app` gives the outermost `.app` (framework-embedded helper apps excepted);
   - otherwise the first known AI agent;
   - otherwise the nearest non-platform binary;
   - otherwise the top-most process below launchd.

   The nearest agent anywhere in the chain is also recorded.
5. **Benign services** (Spotlight, Time Machine, iCloud/File Provider, Quick Look, XProtect) are
   folded. They only count as benign when launched by launchd or another benign service.
6. **Rules**, evaluated per category (an allow for one category never silences another touched by
   the same operation):
   - monitor-only sources evaluate them in dry-run mode, where deny becomes "would block";
   - native NOTIFY events while AUTH is subscribed and enforcement is active are evaluated without
     consuming "allow once"; a deny rule that matches there (the access happened anyway, e.g.
     allowed once) still raises a rule alert;
   - denials arrive already decided from the AUTH path.
7. **Anomaly policy**:
   - benign → nothing;
   - blocked / would block → alert;
   - explicit allow → nothing;
   - alert rule → alert;
   - owner → nothing;
   - critical and not user-approved → alert, even while learning;
   - after learning, a new (app, category, access) triple → alert.

   The baseline records everything except benign and denied accesses.
8. **Coalescing**: one alert per (app, category, blocked or not) per 10 minutes, so "blocked ×6"
   never counts reads that went through. Repeats bump the count. An escalation (e.g. first access
   → critical) or a new access kind (a write after reads) re-surfaces the alert and moves its
   headline path to the access that caused it; "allow once" targets that path. The alert text
   says read / wrote / read and modified, and "for the first time" when the triple was new.
9. **Storage**: batched every 250 ms. Per-(app, category) summaries are maintained incrementally;
   details older than 7 days are rolled into daily aggregates (by the daemon's local calendar day;
`whoread daily`, `whoread export --aggregates`); history is kept for 30 days.

## Enforcement path (native source)

`handleFile` (ES callback):
1. Build a `FileActivity` from the `es_message_t`.
2. `Enforcer.decide`:
   - enforcement inactive → allow;
   - classify; not sensitive → allow (cacheable);
   - chain from the tree;
   - `RuleEngine.evaluate`.
   AUTH events: OPEN, RENAME, CLONE, COPYFILE, LINK, UNLINK, TRUNCATE, EXCHANGEDATA and CREATE
   (READDIR is not subscribed: listings are never blocked).
3. Respond:
   - AUTH_OPEN deny → flags `0`, never cached;
   - AUTH_OPEN allow → `UINT32_MAX`, cached only if identity-only and no enforced deny rule
     covers this process and file;
   - readdir / directory opens → always allow (never blocked);
   - other AUTH events → `es_respond_auth_result`, never cached (none of them support caching).
4. Record the latency from the message's `mach_time` against `deadline`. A missed deadline is
   reported from a serial queue (so the enforcement trip and its logging never run on the
   callback); es_respond failures are logged from the same queue without touching the message.
5. Denials are queued for logging; NOTIFY events of allowed accesses carry the normal log.

Rule priority: explicit deny > explicit allow > owner > default. "Allow once" and "always allow"
on a blocked access are **exceptions** on the deny rule, so deny keeps the highest priority.

## IPC and permissions

There is a single protocol, `IPCRequest`/`IPCResponse` (JSON). XPC carries it as one `Data` →
`Data` method; the dev socket carries it as length-prefixed frames. `ServiceHandler` authorizes
each request by peer euid and code identity (see THREAT_MODEL "Protecting the guard from the
guarded"). Rule, settings and catalog read-modify-writes are serialized by one recursive lock in
`DaemonCore`; settings are applied in memory before they are persisted, so a kill switch works
even when the disk is full. The protocol version (`whoReadIPCVersion`, now 2) is checked with a
`hello` by the CLI and the app. The app polls every second (status, alerts, live tail) and every
10 s (summaries, rules, settings, catalog), plus a full poll right after any change.

## Threads

| Thread / queue | Work |
|---|---|
| ES process client handler | fork/exec/exit → tree (synchronous, in memory) |
| ES file client handler | AUTH decide + respond; NOTIFY → `whoread.native.events` queue (bounded) |
| native report queue | deadline-miss trips, es_respond failure logs |
| `whoread.eslogger.reader` | read eslogger stdout, prefilter, parse, analyze |
| `whoread.eslogger.stderr` | blocking read of eslogger stderr (4 KB tail for the source error and hint) |
| `whoread.writer` | SQLite batches |
| `whoread.maintenance` | prune tree, expire alert windows, baseline flush, retention, latency check, home / symlink re-discovery, save used "allow once" |
| `whoread.policy` | enforcement on/off observers: ES cache clear, AUTH subscribe/unsubscribe, trip persistence |
| `whoread.killswitch` | stat the kill-switch file every 200 ms |
| IPC threads | `ServiceHandler` |

Core objects (`ProcessTree`, `RuleEngine`, `Baseline`, `AlertCoalescer`, `EnforcementState`,
`LatencyMonitor`, stores) are internally locked.
