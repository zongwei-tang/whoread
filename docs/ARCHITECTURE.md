# Architecture

```
                 ┌──────────────── user space, root ──────────────────────┐
  kernel ES ──►  │ EventSource                                            │
                 │  ├─ EsloggerSource  (/usr/bin/eslogger, NOTIFY)        │
                 │  ├─ NativeESSource  (file client: inverted target      │
                 │  │                   muting, NOTIFY + AUTH,            │
                 │  │                   fail-closed on macOS 27;          │
                 │  │                   process client: fork/exec/exit)   │
                 │  └─ ReplaySource    (JSONL file / stdin)               │
                 │          │ SourceEvent                                 │
                 │          ▼                                             │
                 │  LinkWatchingSink ──► link changes (whoread.links)     │
                 │          ▼                                             │
                 │  EventPipeline ──► Analyzer (WhoReadCore)              │
                 │          │          normalize → classify → chain       │
                 │          │          → attribute → benign? owner?       │
                 │          │          → rules → baseline → coalesce      │
                 │          ├─► LiveBuffer (last 5000, for the UI)        │
                 │          └─► EventWriter ──► SQLiteEventStore          │
                 │                                                        │
                 │  AUTH callback ─► Enforcer (in-memory decision) ──────►│ es_respond_*
                 │          └─ undecided ─► AskBroker (held and asked)    │
                 │  ServiceHandler ◄── XPC (app, CLI) / dev socket        │
                 └────────────────────────────────────────────────────────┘
       WhoRead.app (user)  ── XPC ──►  whoreadd / system extension
       whoread CLI (user/root) ─ XPC ─┘
```

## Modules

| Module | Depends on | Role | Covered by `swift test` |
|---|---|---|---|
| `WhoReadCore` | Foundation | All logic: models, path normalization, catalog trie with nested categories, process tree, agent detection, attribution, benign services, rule engine, baseline, alert coalescing, ask keys and what an answer covers, eslogger parser + prefilter, argv redaction, the sanitizer for everything shown to a person (`DisplayText`), latency monitor, enforcement state, export, alert text (en/zh), checks for state files and directories (`SafeFile`, `TrustedFile`). No EndpointSecurity; no IO besides those file checks and what callers inject. | yes |
| `WhoReadStore` | Core, SQLite3 | `EventStore` on SQLite (WAL, 0600). Creates no directories, and refuses a database file that is a link or has a second name. | yes |
| `WhoReadIPC` | Core | Codable request/response protocol; in-process client; dev Unix socket; XPC server/client and the per-connection signing requirement (`XPCPeerPolicy`, macOS). | yes (XPC itself: no) |
| `WhoReadEngine` | Core, Store, IPC | Daemon runtime: sources, pipeline, writer, enforcer, ask broker, kill-switch watcher, service handler, daemon lifecycle, data-directory checks, link inventory, unclean-stop record, process snapshot, owner resolver, staged output files, fixture sanitizer. | yes, except the native source's Endpoint Security calls (test VM only) |
| `WhoReadUIModel` | Core, IPC | App view models: snapshot fetcher, question polling and connection recovery, live feed, tab tables, menu bar state, notification planner, onboarding, rule draft, the en/zh UI string table. | yes |
| `whoreadd` | Engine | Daemon executable (dev LaunchDaemon). | through `scripts/dev/e2e-dev-socket.sh` |
| `whoread` | Engine | CLI. | yes (over the dev socket) |
| `App/` (Xcode) | UIModel, IPC | SwiftUI menu bar app. | no (built by CI and `scripts/dev/sc-build.sh app`) |
| `Extension/` (Xcode) | Engine | Endpoint Security system extension = whoreadd with the native source. | no (built only) |

The native source keeps everything that does not call Endpoint Security (mute plan, deadline miss
mode, ask budget, held messages, client gates, drain, watchdog, denial backlog, dropped-message
counts, late answers) outside its EndpointSecurity guard, and its message conversion is tested on
hand-built messages. The libraries keep Linux code paths (Glibc, no ES or XPC), but only macOS is
built and tested.

## Data files

`Data/catalog.json` (sensitive categories, prefixes, file patterns, owners), `Data/agents.json`
(AI agent recognition) and `Data/benign.json` (system services folded as noise) are the defaults
that ship; `scripts/dev/gen_catalog.py` writes them. The daemon:
- loads the defaults from the first of `--defaults DIR`, `$WHOREAD_DATA_DIR`, the bundle's
  `Contents/Resources` or `Contents/Resources/Data` (the system extension names its own), a
  `WhoReadData` folder next to the executable, and `/Library/Application Support/WhoRead/defaults/`. Running as root it reads them only where no one
  but root can change the files (no link, one name, no ACL entry that lets others write), their
  directory or a directory above it. An explicit `--defaults` that fails this stops the start;
  other candidates that fail are skipped and named in the error. A root daemon therefore refuses the
  repository's own `Data/`;
- keeps its state in `/Library/Application Support/WhoRead`: the database, the user's catalog, the
  kill-switch file, the `auth-armed` and `watchdog-stall` markers, `daemon.lock` and
  `mach-service`. It refuses to start unless only root can change that directory, the kill switch's
  directory and every directory above them (links followed; a sticky one on the way passes), and unless
  everything in the data directory is root's own: no links, no second hard link, nothing others can
  write, no ACL entry that lets others in. A directory someone else made is refused, never adopted
  or moved aside. A `flock` on `daemon.lock` keeps a second daemon (the dev LaunchDaemon and the
  system extension) off the same directory;
- keeps the user's edited catalog in `catalog.json`, next to `catalog.base.json`, the defaults it
  was made from. At start the user copy is merged with the current defaults field by field: a field
  the user left as it was takes the new default, a field the user changed is kept, new default
  categories are added, deleted ones stay deleted;
- resolves third-party owner team IDs with `codesign -dv` at start and after catalog changes, in
  memory only (`OwnerResolver`), so the user copy never freezes them;
- re-discovers home directories every 5 minutes, follows links in dotfile directories (below), and
  swaps the classifier (and ES muting, and the eslogger prefilter) only when the monitored set
  changed;
- writes the XPC service name to `mach-service` for the CLI and the app; they use it only when it is
  a root-owned regular file in directories only root can change, and their built-in name otherwise;
- marks categories whose prefixes do not exist as "not detected".

**Links.** Endpoint Security reports resolved paths, so the target of a link inside a monitored
dotfile directory (a dotfile manager's `~/.azure/config -> ~/dotfiles/azure/config`) becomes a
monitored prefix of the same category. The file keeps its own categories as well, but the link's
category lends no ownership. Only catalog paths inside a home's dot-directories are searched (app
data folders hold sandbox links back into the home, and external volumes and project roots can be
huge). Links are found:
- by a breadth-first search, 8 levels deep, at most 20,000 entries per directory and 100,000 per
  search, but at least 2,000 for every directory: at start, every 5 minutes, and at most every
  30 s after link changes were lost;
- between searches, from file events, within about 1.5 s and at any depth: a link created inside a
  searched directory (or its real path), the links in a directory moved or copied in, and a searched
  directory or a directory above it made a link. More than 64 such changes at once start a full
  search instead.

At most 4,096 links are followed per classifier (in catalog order), and at most 1,024 links that
events showed are remembered between full searches. A dangling link is followed to the path a write
through it would create, also below directories that do not exist yet (not through an existing
non-directory or a missing `..`), so that first write is monitored. A link target is never the root,
`/dev`, a home or a directory holding a home or the prefix, and a link in a user's own files never
makes a system path a category.

## Event flow

1. **Source.**
   - eslogger: subscribed to open, close, exec, fork, exit, rename, clone, copyfile, link, unlink,
     truncate, exchangedata, create, setmode, setowner, setacl, setattrlist and mount (and readdir
     when enabled). Every line first goes through an Aho–Corasick prefilter. It always passes
     lifecycle lines, multi-path events (rename, clone, copyfile, link, exchangedata) and mounts. It
     passes a create when it has a new-path destination, when its existing file starts with a
     monitored prefix, or when one of its JSON strings is exactly a proper ancestor of a prefix (a
     link planted at `~/.config`; if any ancestor is not ASCII, every create passes). It drops
     unmodified closes, and passes lines in which a JSON string value starts with a monitored prefix
     (ASCII case-insensitive, `/` or `\/`, with or without `/System/Volumes/Data`, needles
     JSON-escaped) and lines with `\u` escapes. Then the JSON is parsed. Malformed lines still
     advance the kernel-drop sequence check, which restarts with each new eslogger.
   - Native: the kernel delivers only monitored-prefix events, thanks to inverted target-path
     muting over every spelling of each prefix (catalog, on-disk/realpath, NFC and NFD, and each of
     them under the data volume's root, which homes under `/home` or made directly on the data volume
     need); ancestors are muted as literal paths. A realpath spelling is registered only if it is not
     `/dev`, a home, or a folder containing a home or the prefix, and no spelling containing a NUL is
     ever registered. MOUNT supports no target muting, so every mount is delivered. NOTIFY events
     go to an analysis queue capped at 50,000; past that they are dropped and counted
     (`whoread status`). Kernel drops are counted from `global_seq_num` gaps, and AUTH messages the
     kernel dropped from per-event-type `seq_num` gaps, as denied (fail-closed mode) or allowed
     (kill mode): nothing else is known about them. NOTIFY_CREATE records new symlinks, directories
     and nodes (regular files come through their creating NOTIFY_OPEN). A close that reports no write
     call but `was_mapped_writable` (message version 6 and later) is recorded as a write with the
     note `mapped-writable`, only for a process that opened that file for writing while the daemon
     ran (the last 4,096 such opens are remembered). At connect the source reads the client's
     default mute set (system programs macOS mutes for most AUTH events), logs it and counts it in
     `whoread status`: their accesses are recorded but can never be asked about or blocked.
     Denials are recorded from a bounded backlog that merges identical repeats past 1,000 and only
     counts past 10,000.
2. **Process events** update the `ProcessTree`. It is keyed by (pid, fork time), with images keyed
   by pidversion, which changes on exec (a node keeps its last 8). Children link to their fork-time
   parent (`original_ppid`) by node id, so reparenting to launchd and pid reuse do not break chains.
   Where a message carries `parent_audit_token` (message version 4 and later) naming that parent,
   the node seen with that exact pidversion is linked; a token naming launchd, a debugger or a later
   holder of the pid is ignored. Tombstones keep exited ancestors for late events. An unknown parent
   is resolved through libproc with a start-time check (a reused pid is rejected); a parent that
   cannot be found leaves the node unlinked: its ancestry is unknown and its chain does not reach
   launchd, which is never assumed. A chain query walks at most 64 links; past them it uses what
   each node recorded about its ancestors when it was linked (AI agents, the responsible app, the
   nearest non-platform binary, the top-most process), and the chain does not count as reaching
   launchd either. An AI agent process that execs another program stays that agent, with its team.
   - Each image carries what the kernel says about its code: the platform flag,
     `cs_validation_category` (message version 10 and later) and the code-signing flags. Apple
     trust needs a verified platform binary (PLATFORM where the category is reported); a third-party
     team or signing ID counts only for Developer ID or App Store code; code another process can
     control (get-task-allow, debugged, signed but no longer valid) is never trusted. A responsible
     token naming the process itself means no responsible process.
   - At start the tree is seeded from a libproc snapshot, which has no fork-time parent: processes
     reparented to launchd stay unlinked until their own events. The AI agent ancestry of running
     processes is saved every 5 s when it changed and at stop (at most 512 processes, 8 agents each,
     512 KiB, agents and orphans first, with the boot time) and restored right after the seed: a
     process that was an agent is one again, and an orphan gets placeholders for its parent and the
     agents above it. Restored chains carry their agents but never reach launchd.
3. **File events** are normalized (firmlink, `/private` aliases, NFC, case fold, `~` per home) and
   classified by a component trie, split on Unicode scalars. A path belongs to every category whose
   prefix holds it and whose patterns accept it, each at its most severe prefix: a key in a custom
   folder inside the SSH key folder is ssh/critical and custom/high. The deepest prefix that accepts
   the path names it (that category is listed first, and the UI shows it). Prefixes that only add
   severity (link targets, custom paths, project roots) name a path only when they are more severe;
   custom paths and project roots also win ties. File patterns refine severity; a truncated path
   gets the category's worst severity. A directory open is a readdir (dropped unless readdir is
   enabled). Writes include an open for writing or with `O_TRUNC`, a modified close, truncate,
   unlink, and permission, owner and ACL changes (chmod, chown, `chmod +a`, setattrlist with those
   attributes; a setattrlist that changes none of them is not recorded).
   - Moving or cloning a directory carries every prefix registered inside it, wherever it sits, and
     is judged by the worst file each of those categories can hold. A folder inside a project root
     is judged at the category's worst severity when it leaves the project (a temp folder, the
     Trash, a rename to an excluded name such as `node_modules` or `.git`) and at base severity when
     it stays.
   - Destinations of rename, clone and copyfile, and creates of a symlink or node, carry in what
     lands there: planting a folder or a link at a parent of monitored prefixes (`~/.config`) is a
     write to every category below it. An existing directory a rename lands on is read as well as
     written (only a swap can land on a non-empty one); with the native source, an empty directory on
     a local APFS volume counts as a plain destination.
   - A mount at or above monitored prefixes is a write to every category below it, except a mount
     on a home or above one (network, auto_home and FileVault homes are mounted there at every
     login) and on a volume's own mount point (a direct child of the volumes folder).

   Non-sensitive events are dropped here.
4. **Attribution** walks the chain leaf → root:
   - the first `.app` gives the outermost `.app` (framework-embedded helper apps excepted);
   - otherwise the first known AI agent;
   - otherwise the nearest non-platform binary;
   - otherwise the top-most process below launchd.

   The nearest agent anywhere in the chain is also recorded, as are every AI agent in the whole
   chain and whether the chain reaches launchd (ancestry known).
5. **Benign services** (Spotlight, Time Machine, iCloud/File Provider, Quick Look, XProtect, file
   system services such as fseventsd) are folded. They only count as benign when launched by
   launchd or another benign service, through a chain that reaches launchd.
6. **Rules**, evaluated per category, with one event per category (an allow for one category never
   silences another touched by the same operation):
   - an owner is an owner of the path's category, or of the category the path is named by, when that
     one is not there through a link alone and the other category is not more severe or has no
     owners of its own (a volume, a custom folder);
   - monitor-only sources evaluate rules in dry-run mode, where deny becomes "would block";
   - native NOTIFY events while AUTH is subscribed and enforcement is active are evaluated without
     consuming "allow once"; a deny rule that matches there (the access happened anyway, e.g.
     allowed once) still raises a rule alert;
   - denials arrive already decided from the AUTH path.
7. **Anomaly policy**:
   - benign → nothing;
   - blocked, asked (denied without an answer) or would block → alert; a category denied only along
     with another one, and an access the kernel denied because the answer came too late, raise none;
   - explicit allow → nothing;
   - alert rule → alert (also after an answer allowed the access);
   - owner with no AI agent in its chain and a chain that reaches launchd → nothing (an owner run
     by an agent, or started by an unknown process, alerts);
   - "trust Apple programs" covers the chain → nothing;
   - critical, and run by an AI agent, started by an unknown process or not approved by the user →
     alert;
   - a new (app, category, access) triple → alert (there is no learning period).

   With enforcement on, undecided accesses never get here as "allowed": they are held and asked
   (docs/ASK_MODE.md); an unanswered one becomes a denied event with an `ask` alert.

   The baseline records everything except benign and denied accesses. It is bounded by count: past
   100,000 entries the user did not approve, maintenance forgets the least recently seen of them
   down to 90,000. Approved entries are never forgotten, and nothing is forgotten for age; a
   forgotten entry only means its next access alerts as a first access again.
8. **Coalescing**: one alert per (app, category, lane) per 10 minutes, the lanes being passed,
   blocked and asked (questions also per set of AI agents in the whole chain, and apart for chains
   whose ancestry is unknown), so "blocked ×6" never counts reads that went through. At most 10,000
   windows are open; past that the ones that close first are dropped. Repeats bump the count. An
   escalation (e.g. first access → critical) or a new access kind (a write after reads) re-surfaces
   the alert and moves its headline path to the access that caused it; "allow once" targets that
   path. The alert text says read / wrote / read and modified, and "for the first time" when the
   triple was new.
9. **Storage**: batched every 250 ms (at most 100,000 events wait; past that the oldest are dropped
   and counted). Per-(app, category) summaries are maintained incrementally; details older than 7
   days are rolled into daily aggregates (by the daemon's local calendar day; `whoread daily`,
   `whoread export --aggregates`); history is kept for 30 days (`detail-days`, `retention-days`).

**What is shown and exported.** argv is redacted before it is stored or shown, and stored chains
keep the nearest 64 processes (docs/THREAT_MODEL.md, "Privacy"). Everything shown to a person
(notifications, the app, the CLI's tables, the log) goes through `DisplayText`: hidden characters
(controls, bidi overrides, zero-width and other invisible characters) become visible escapes, and
names are capped at 64 characters, banner paths at 160 (cut in the middle). `whoread export` writes
JSON, JSON Lines or CSV. JSON keeps values exact; the CLI writes the hidden characters
JSONEncoder leaves raw as `\u` escapes. CSV is quoted per RFC 4180, and a cell that starts with `=`,
`+`, `-`, `@`, a tab or a carriage return gets a leading apostrophe so a spreadsheet does not run it
as a formula; to a terminal, hidden characters are escaped as well. `--output FILE` is written as
`FILE.partial` with mode 0600 and renamed into place; a link or anything but a regular file at FILE
is refused.

## Enforcement path (native source)

`handleFile` (ES callback; the kernel calls the file client's handler serially):
1. Build a `FileActivity` from the `es_message_t`.
2. `Enforcer.decide`:
   - a directory listing or directory open → allow (cacheable);
   - enforcement inactive → allow;
   - classify; not sensitive → allow (cacheable);
   - chain from the tree;
   - `RuleEngine.evaluate`.

   AUTH events, subscribed only while enforcement is active: OPEN, RENAME, CLONE, COPYFILE, LINK,
   UNLINK, TRUNCATE, EXCHANGEDATA, CREATE, SETMODE, SETOWNER, SETACL, SETATTRLIST and MOUNT
   (READDIR is not subscribed: listings are never blocked). A setattrlist that changes no
   permission, owner or ACL attribute is allowed and not recorded.
3. Respond:
   - AUTH_OPEN deny → flags `0`, never cached;
   - AUTH_OPEN allow → `UINT32_MAX`, cached only when the decision is cacheable and no enforced deny
     rule denies this process anything on this file (in ask mode, only when static allow rules
     cover both read and write; allows by owner, benign service or Apple trust are never cached);
   - other AUTH events → `es_respond_auth_result`, never cached (SETMODE, SETOWNER and MOUNT
     support caching, but their cache key ignores the process chain);
   - ask (enforcement on, nothing decided): `es_retain_message`, hand the message to `AskBroker`
     with a budget (deadline − clamp(20 %, 1–5 s)) and return; the broker answers it exactly once
     (your answer, re-decided against the new rules, or deny when the budget runs out), the source
     releases it; a backstop denies at budget + headroom/2, before the deadline. A budget under
     0.5 s, no `.asks` poll in the last 5 s, 256 accesses already held, or a source that is stopping
     → deny at once (the question is still listed).
4. Record the latency of immediately answered messages, from the message's `mach_time`, against
   its `deadline` (statistics only: nothing switches enforcement off; held accesses are left out).
   es_respond failures are logged from a queue without touching the message.
5. Denials are queued for recording; NOTIFY events of allowed accesses carry the normal log.

**Deadline miss mode.** On macOS 27 and later the file client is put in fail-closed mode before
anything is subscribed (`es_set_deadline_miss_mode`, looked up at run time and read back with
`es_get_deadline_miss_mode`; `whoread status` shows the mode). A missed deadline then denies the
access instead of getting the daemon killed, and an AUTH message dropped from a full queue is denied
instead of allowed. Older systems keep the kernel's default, kill. In fail-closed mode an allow is
never sent at or after its deadline: the source reads the clock just before `es_respond` and sends a
deny instead. Such an access, like an allow `es_respond` did not deliver, is recorded as blocked with
the note `deadline-missed` (no rule, no alert) and counted in `whoread status`.

**Watchdog.** In fail-closed mode a handler stuck in one call would deny every access behind it for
as long as the daemon lives. A watchdog checks every 10 s (uptime clock, so sleep does not count)
and exits the daemon (`_exit(70)`, leaving the `watchdog-stall` marker) once one call has been
running for max(120 s, 4 × the longest AUTH deadline seen), at most 900 s. The minimum doubles with
each watchdog exit in the last hour (240 s, 480 s, then 900 s), so a wedge that comes back keeps
failing closed for longer instead of restarting the daemon every two minutes. launchd starts a fresh
daemon; the enforcement setting is untouched. The watchdog runs before macOS 27 too.

**Unclean stops.** The `auth-armed` marker exists while AUTH events are subscribed. Found at start (a
kill for a missed deadline, a watchdog exit, a crash, power loss), it is reported in
`DaemonStatus.uncleanStop`, with how many unclean stops and watchdog exits there were since the last
clean stop; enforcement stays as the user set it.

**Teardown.** ES clients are created and deleted on one thread (`whoread.es.clients`). A stop first
denies every held access, then, for each client: `es_unsubscribe_all`; a drain of what the kernel
queued (`es_sync_client` on macOS 27, looked up at run time, otherwise until the handler has been
idle for 50 ms; at most 1 s); closing the client's gate, inside which every `es_*` call made off the
client thread runs (at most 1 s); and `es_delete_client`. A client that cannot be deleted safely in
time is left to the kernel's teardown. A stop waits at most 8 s for all of it.

Rule priority: never-block system daemons > explicit deny > explicit allow > owner (no AI agent in
the chain, and the chain reaches launchd) > benign service / trusted Apple chain > ask (enforcement
on) or default allow. "Allow once" and "always allow" on a rule's block are **exceptions** on the
deny rule, so deny keeps the highest priority. An access to a file in several categories needs a
decision for each: a question names the most severe undecided one, and an allow is re-decided, so
the access stays denied, and the next category is asked, while another category is undecided.

## IPC and permissions

There is a single protocol, `IPCRequest`/`IPCResponse` (JSON). XPC carries it as one `Data` →
`Data` method; the dev socket carries it as length-prefixed frames. The protocol version
(`whoReadIPCVersion`, now 4: adds the setmode, setowner, setacl and mount operations and the deadline
miss mode in the status) is checked with a `hello` by the CLI and the app.

`XPCPeerPolicy` chooses the code-signing requirement installed on each new XPC connection: none for
root, the client requirement for other peers, and `(client) and (app)` when a look at the peer's pid
at accept time suggests the app. `setCodeSigningRequirement` makes XPC check every message against
it, so that look only picks the requirement: a wrong guess leaves the connection unprivileged or
invalidated, never privileged. A requirement that does not parse fails closed. Dev-socket peers
carry no code identity: there, only root (or a `--permissive` dev daemon) is privileged.

`ServiceHandler` accepts root and the console user only, and sorts each request into a privilege
level (see THREAT_MODEL "Protecting the guard from the guarded"):
- read (status, settings, catalog, agents, open questions): any accepted peer, questions without
  their file path and command lines unless the peer is privileged;
- recorded (events, live tail, alerts, summaries, daily totals, baseline, rules): root or the app;
- strengthen (enforcement on, a new deny or alert rule, "block from now on", denying a question,
  resume, "trust Apple programs" off): any accepted peer;
- weaken (everything else that changes something): root or the app.

Rule, settings and catalog read-modify-writes are serialized by one recursive lock in `DaemonCore`;
settings are applied in memory before they are persisted, so a kill switch works even when the disk
is full.

The app uses two XPC connections, each with its own queue and timer:
- questions: `.asks` every second, every 250 ms while any is open; the answers go here too (also
  those given on a question's alert), so a slow history read never delays them. Any `.asks` poll
  marks an answering app present for 5 s; with none, undecided accesses are denied at once instead
  of held;
- status and history: status, alerts and the live tail every second; settings, catalog, agents,
  summaries and rules every 10 s; a full poll right after any change; every other change.

`SnapshotFetcher` needs only the handshake and the status to count the daemon as reachable; every
other part is read on its own and keeps its last value when it fails. When the daemon does not serve
a connection as the app (history refused, question paths hidden), the app reopens it: at once, then
after 30 s, doubling up to 10 minutes. Turning enforcement off uses a fresh connection with a 2 s
timeout, and falls back to creating the kill-switch file with administrator rights.

## Threads

| Thread / queue | Work |
|---|---|
| ES process client handler | fork/exec/exit → tree (synchronous, in memory; message reads inside the client's gate) |
| ES file client handler | AUTH decide + respond (inside the client's gate); NOTIFY → `whoread.native.events` (bounded) |
| `whoread.native.events` | analysis of NOTIFY events |
| `whoread.native.denied` | recording denials |
| `whoread.native.report` | es_respond failure logs |
| `whoread.native.watchdog` | file handler liveness, every 10 s |
| `whoread.es.clients` | creating, muting, subscribing and deleting the ES clients |
| `whoread.ask` | budget timers, answers to held accesses |
| `whoread.ask.redact` | argv redaction of questions (off the ES callback) |
| `whoread.eslogger.reader` | read eslogger stdout, prefilter, parse, analyze |
| `whoread.eslogger.stderr` | blocking read of eslogger stderr (4 KB tail for the source error and hint) |
| `whoread.eslogger.supervisor` | eslogger restarts, with backoff |
| `whoread.writer` | SQLite batches |
| `whoread.maintenance` | every 30 s: prune tree, expire alert windows and questions, baseline prune and flush, retention (hourly), home and link re-discovery (every 5 minutes), save used "allow once"; every 5 s: save the AI agent ancestry; every second: latency check |
| `whoread.links` | links that file events showed (about 1.5 s later), full link searches after lost changes |
| `whoread.policy` | enforcement on/off observers: releasing held accesses when enforcement goes off, telling the source (AUTH subscribe/unsubscribe, ES cache clear) |
| `whoread.killswitch` | stat the kill-switch file every 200 ms |
| IPC threads | `ServiceHandler` |

Core objects (`ProcessTree`, `RuleEngine`, `Baseline`, `AlertCoalescer`, `EnforcementState`,
`LatencyMonitor`, `AskBroker`, stores) are internally locked.
