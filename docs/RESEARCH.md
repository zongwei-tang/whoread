# Research notes (M0)

> Status: the Endpoint Security facts below are verified against the **macOS 27.0 SDK** (Xcode 27.0,
> 27A266a) on macOS 27.0.1 (26A434). The raw record is
> [`research/sdk-verification-27.0.1.txt`](research/sdk-verification-27.0.1.txt), written by
> `scripts/verify-sdk.sh`; `scripts/dev/es-typecheck/check-stub.sh` checks that every declaration of
> the type-check stub has exactly the SDK's type (`--self-test` checks that the check rejects a stub
> that differs). What only a running system shows (blocking, deadlines, delivery details) is still to
> be checked on a VM with SIP disabled: see "Pending checks".

## How this was verified

The brief asks to read the EndpointSecurity headers from `xcrun --show-sdk-path` and to run
`eslogger --list-events`. The first notes were written on a Linux machine (Swift 6.1, no Xcode, no
macOS SDK), from primary or near-primary sources, quoted verbatim, with URLs, in:

- [`research/endpoint-security-api.md`](research/endpoint-security-api.md): Apple DocC JSON
  (all 1686 pages under `/documentation/endpointsecurity`, which already reflect the macOS 27
  SDK), plus Apple's own header comments from MacOSX26.5.sdk. The header text came through a
  third-party SDK mirror on GitHub; it matches the 13.3 and 15.5 SDK text. Also the
  `EndpointSecurity(7)` man page, the WWDC20 10159 and WWDC22 110345 transcripts, and Santa
  (northpolesec) for real-world usage. §15 lists what the macOS 27.0 SDK headers changed or added.
- [`research/eslogger-libproc-packaging.md`](research/eslogger-libproc-packaging.md): the
  eslogger(1) man page (identical on macOS 13 through 26), a real `--list-events` output from
  macOS 26.5.2, real eslogger JSON lines from public captures (message version 7 from 2023 and
  version 10 from macOS 26), XNU open source for libproc / `KERN_PROCARGS2` / pidversion, the
  XcodeGen ProjectSpec and source, and the Apple SystemExtensions docs.
- [`research/packaging-details.md`](research/packaging-details.md): packaging details for M6.

Then, on a Mac with Xcode 27, `scripts/verify-sdk.sh` recorded from the installed SDK the header
comment, availability and prototype of every ES function WhoRead calls or considered, the structs it
reads, numeric values compiled from the headers, Swift's view of `es_message_t`, the libproc, libbsm
and other declarations the code uses, and `eslogger --list-events`:
[`research/sdk-verification-27.0.1.txt`](research/sdk-verification-27.0.1.txt). The libraries,
`whoreadd` and `whoread` compile against that SDK (`scripts/dev/sc-build.sh`), and so do the app and
the extension (`scripts/dev/sc-build.sh app`, without Xcode). "Header" below means the macOS 27.0
SDK header unless an older one is named.

Items still marked **UNVERIFIED** are handled defensively (see below) and listed under "Pending
checks".

## Differences between the brief and the sources (sources win)

| # | Brief says | Source says | What WhoRead does |
|---|---|---|---|
| 1 | FDA deep link `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles` | `ESClient.h`: on macOS 13+ use `x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles`; the old URL is "until macOS 12" and "may stop working". | Onboarding opens the new URL and falls back to the old one if it fails to open. |
| 2 | Inverted muting: invert, `es_unmute_all_target_paths`, then mute prefixes. | `es_invert_muting` **toggles** (the 27 header calls process inversion "an involution"; Santa checks `es_muting_inverted` first). The header says to unmute all target paths *before* inverting, and that the client must have **no AUTH subscriptions** at that point. Muting applies to the real, possibly firmlinked path as `F_GETPATH` returns it, after symlink resolution, and makes no provision for hard links. | Order: unmute all target paths → invert only if `es_muting_inverted` says not inverted → check again, and abort the setup and retry unless it now reads inverted (also on `ES_MUTE_INVERTED_ERROR`) → mute prefixes → subscribe. Rule changes apply a *diff* (`es_mute_path` / `es_unmute_path`) rather than unmute-all while AUTH events are subscribed. Prefixes are registered in every byte-distinct spelling: catalog, realpath (on-disk case), NFC and NFD, and each of them again under the data volume's root (`/System/Volumes/Data`), which VFS reports for data-volume paths outside the firmlinks, such as a home under `/home`. A resolved spelling that is `/`, under `/dev`, a home, or a folder holding a home or the prefix itself is never registered. Whether ES compares mute paths byte-wise or case-insensitively is **UNVERIFIED** (VM item 10). |
| 3 | "Cover clone/copyfile/link/rename/exchangedata by source path." | With target muting inverted, a multi-target event is delivered if **ANY** of its target paths is selected (header). For RENAME, LINK, CLONE and EXCHANGEDATA the targets are source and destination; for COPYFILE the source and the new or overwritten file; for CREATE "the file that will be created or replaced". SETMODE, SETOWNER, SETACL and SETATTRLIST support target-path muting; MOUNT, FORK and EXIT do not. | Covering the source prefix is enough for delivery. Moving or cloning a *parent* of a sensitive directory (e.g. `mv ~/.config /tmp/x`) has neither path under the prefix, so ancestors are also registered as `TARGET_LITERAL` and classified (`PathClassifier.ancestors`). Every mount is delivered and judged by its mount point (row 19). |
| 4 | Cache only when the decision does not depend on the chain or time. | The ES cache is **global across all clients** and `es_clear_cache` is rate-limited (`ERR_THROTTLE`). A cache hit produces no AUTH but still produces NOTIFY. Cache keys: OPEN = (process executable *file*, file); READDIR = (process executable file, dir); SETMODE and SETOWNER = (executable, file); MOUNT = (executable, mount point). RENAME, CLONE, COPYFILE, LINK, UNLINK, TRUNCATE, EXCHANGEDATA and CREATE do not support caching, and the 27 header adds that the `cache` argument is ignored for them. That `cache=false` guarantees no caching even if another client asks for it is from WWDC20, not the header. | The key is the executable file, so a cached *allow* for `cat` would also apply to a later `cat` under an AI agent. Only AUTH_OPEN allows are ever cached, and only when no live rule covering the target depends on the chain, argv/owner status, time or use counts (`RuleDecision.cacheable`). Answers to questions are scoped by the AI agents in the chain, so what they allow is never cached; in ask mode an allow is cached only when static rules give it for reads and writes of every category (an owner's pass depends on the chain). SETMODE, SETOWNER and MOUNT are never cached. Logging comes from NOTIFY events, which the cache does not suppress. `es_clear_cache` runs on every rule or enforcement change; calls are coalesced and retried. |
| 5 | AUTH_OPEN: reply with `es_respond_flags_result` and the allowed fflags. | Header: pass `UINT32_MAX` unless you mean to deny certain flags; on a cache hit, later opens are allowed only if their flags are a subset. Whether a *non-cached* response that masks some requested flags fails the open or downgrades it is **UNVERIFIED**. `fflag` is the kernel's mask: `FREAD`/`FWRITE`, not `O_*`. | Allow → `UINT32_MAX`, cached only if the decision depends on code identity alone *and* no enforced deny rule covers this process and file for any access kind (otherwise a cached masked answer would deny later opens with no AUTH event, no log and no notification, and would outlive the kill switch). Deny → `0` with `cache=false`, so the outcome never depends on the unverified masking semantics. |
| 6 | AUTH deadline: client is terminated; behaviour per header. | Header: "the client will be killed" (since 10.15); deadlines differ per message. WWDC20: a missed deadline is an implicit **ALLOW** that is not cached. By default, AUTH messages dropped from a full queue are allowed. macOS 27 adds `es_set_deadline_miss_mode` and `es_get_deadline_miss_mode` with three modes: `KILL` = 0 (default), `FAIL_CLOSED` = 1 (deny the access, do not kill the client; AUTH messages dropped from a full queue are denied too) and `FAIL_OPEN` = 2. `es_set_deadline_max_milliseconds` can only lower a deadline (ERROR above the system default); a floor (`es_set_deadline_min_milliseconds`) is for descendants clients only. | On macOS 27 the file client sets **FAIL_CLOSED** before any subscription and reads the mode back; `whoread status` shows it (`deadline:` line). Both functions are looked up with `dlsym` and called with the raw values above, so the source builds with older SDKs and runs on macOS 14; before 27 the client stays in KILL. In fail-closed mode a late allow is a denial nothing else would record: just before `es_respond` the daemon compares `mach_absolute_time()` with the message's deadline (comparable, per the header) and sends a deny instead, and an allow whose `es_respond` result is neither SUCCESS nor `ERR_DUPLICATE_RESPONSE` counts as denied too. Such accesses are counted, and recorded as blocked with the note `deadline-missed` (no rule, no alert). AUTH messages the kernel dropped are counted by outcome from per-event-type `seq_num` gaps (message version 2+). Latency is measured from the message's `mach_time` (queueing counts) and only counted (a p99 warning); it never switches enforcement off. A handler call stuck far longer than any deadline (at least max(120 s, 4 × the longest AUTH deadline seen), doubling with each such exit in the last hour, at most 900 s) makes the daemon exit so launchd starts a fresh one; enforcement stays as set. A marker file kept while AUTH is subscribed makes the next start report an unclean stop. `es_set_deadline_max_milliseconds` is not used: it could only shorten the ask-mode budget. Ask-mode holds answer before the deadline (row 18). Pending on-device checks: item 12. |
| 7 | (not mentioned) | Headers up to 26.5: `es_delete_client` must be called from the same thread that called `es_new_client`. The 27 header replaces this (Thread Safety): every other `es_*` call (subscribe, mute, respond, retain, release, cache) is safe concurrently from any thread; `es_delete_client` is not safe concurrently with any other `es_*` call on that client, itself included, and may be called from any thread that has exclusive access; using a deleted client is undefined behaviour. `es_sync_client` (27) runs a block once every message queued in front of its marker has been handled (all blocks run if the client is destroyed); it must not be called from the client's own handler. | Clients are still created and deleted on one dedicated thread, which satisfies both rules. Before a delete: `es_unsubscribe_all`; a drain of what the kernel queued before (`es_sync_client` through `dlsym` on macOS 27; before, the handler idle for 50 ms), at most 1 s; then the client's gate closes (every `es_*` call made off the client thread, and every read of message memory by the process client, runs inside it), at most 1 s. A file client whose drain timed out, or any client with a call still inside its gate, is not deleted: the process is stopping, or a retry replaces it. |
| 8 | eslogger: no target-path filter. | Correct. `--select` is not in any Apple man page (13 through 27); third parties say it filters by the *instigating* executable path. eslogger **suppresses events from its own process group**. Raw stdout escapes `/` as `\/`. Key order changes between releases. Exec events carry the **full environment**. `schema_version` was 1 from 2023 (macOS 13.3, message v7) through macOS 26 (message v10). On macOS 27.0.1 `--list-events` lists 106 events (no root needed), including every one WhoRead uses. | No `--select`. Events: open, close, exec, fork, exit, rename, clone, copyfile, link, unlink, truncate, exchangedata, create, setmode, setowner, setacl, setattrlist, mount, and readdir when enabled. Early byte-level prefilter (Aho–Corasick, case-insensitive, matches both `/` and `\/` spellings); rename, clone, copyfile, link, exchangedata and mount lines are always parsed, and a create line also when one of its strings is exactly an ancestor of a prefix. The parser never relies on key order. `env` is never read; argv is redacted before storage. Test scripts give eslogger its own process group (`set -m`). |
| 9 | Process tree: maintain with fork/exec/exit; use `original_ppid` on reparenting. | XNU `kern_exec.c` and the header confirm that **pidversion changes on exec**, and (pid, pidversion) identifies one execution; `start_time` is fork time and survives exec. For the parent the header recommends `parent_audit_token` (message v4) over `ppid`. `responsible_audit_token` "may be the process itself" when there is no responsible process or it has exited. libproc has no fork-time parent. | Process instances are keyed by (pid, start_time) and images by pidversion. Children link to parents by internal node id, so reparenting and pid reuse cannot corrupt chains. The parent is the fork-time parent (`original_ppid`); where `parent_audit_token` names that pid, the child links to the node seen with that exact pidversion. A responsible token equal to the process itself counts as none. A process whose fork-time parent is unknown (one seen only in the start-up snapshot under launchd, or whose parent was never seen) is left unlinked: its ancestry is unknown, never launchd, so it gets no owner exemption, no Apple trust and no benign status, and a question about it says so. The AI agent ancestry of running processes is saved every 5 s and restored after a daemon restart (`kern.boottime` tells a save from an earlier boot). |
| 10 | ES needs the entitlement, root and FDA. | Confirmed. ES is a **library** (`libEndpointSecurity.tbd`), not a framework. `ERR_NOT_PERMITTED` means FDA is missing and `ERR_NOT_PRIVILEGED` means not root; `ERR_NOT_PERMITTED` is the only supported way to detect missing FDA. Exception, new in macOS 27: `es_new_descendants_client` needs neither root nor TCC, only the entitlement, and sees only the caller's own subtree. | Linked as `sdk: libEndpointSecurity.tbd`. Onboarding treats `ERR_NOT_PERMITTED` as "FDA missing". A descendants client is not used: helpers started through launchd (`open -a`, XPC services) leave the subtree. |
| 11 | `NSEndpointSecurityMachServiceName` in Info.plist. | Only documented in the `EndpointSecurity(7)` man page. Default when unset: `<teamID>.<bundleID>.xpc` (deprecated). The same page documents `NSEndpointSecurityEarlyBoot` (hold mounts and non-platform executions until the extension's first subscription) and `NSEndpointSecurityRebootRequired` (TRUE: a new version starts only at the next reboot, so an update leaves no monitoring gap). | Set explicitly to `$(DEVELOPMENT_TEAM).$(WHOREAD_EXTENSION_BUNDLE_ID).xpc`. `NSEndpointSecurityEarlyBoot` is false and `NSEndpointSecurityRebootRequired` is not set: an extension update restarts it at once, with a short gap in which no client is connected. |
| 12 | Request the ES entitlement via the App ID's **Capability Requests** tab. | Apple's ES pages point to developer.apple.com/system-extensions → "Request an Entitlement" (a contact form). The generic Capability Requests help page does not mention Endpoint Security. **UNVERIFIED** which path Apple currently uses. | `docs/DISTRIBUTION.md` (M6) describes both paths. |
| 13 | XcodeGen project. | Target types are `tool` and `system-extension`. A `target:` dependency from the app auto-creates "Embed System Extensions". XcodeGen does **not** generate `CFBundlePackageType` for system extensions. | Set to `$(PRODUCT_BUNDLE_PACKAGE_TYPE)` in `Xcode/project.yml`. For development, `scripts/dev/sc-build.sh app` assembles and signs the same bundle without Xcode. |
| 14 | Kill switch: `whoread enforcement off`. | (Design, not an Apple fact.) AI agents run as the user and can run `whoread`. | Turning enforcement **off** needs `sudo` or the signed app; turning it on does not. The file kill switch needs root too (it lives in a root-owned directory). Root may use any CLI build over XPC. Reading what the daemon recorded (events, alerts, summaries, rules, baseline, export) also needs `sudo` or the app, because it names files the daemon saw with Full Disk Access. Open questions are listed to the console user without their file path or command lines; such a user may deny a question, never allow it. |
| 15 | (not mentioned) | `es_file_t` carries `stat` (`st_mode`). The documented eslogger sample open has `fflag` 17825793 = `0x1100001`, which is `FREAD \| O_DIRECTORY \| O_CLOEXEC` (`sys/fcntl.h`: `FREAD` = 0x1, `O_DIRECTORY` = 0x100000, `O_CLOEXEC` = 0x1000000). That the kernel passes `O_DIRECTORY` through in `fflag` is inferred from that sample (**UNVERIFIED**). | A target whose `st_mode` is a directory (or, without `stat`, an `fflag` with `0x0010_0000`) opened without write intent is a directory listing: recorded only when readdir is enabled, never blocked (AUTH_READDIR is not subscribed). |
| 16 | (not mentioned) | `AUTH_CREATE` (`es_event_create_t`: `destination_type`, `destination.existing_file` or `destination.new_path {dir, filename, mode}`) does not support caching (header). A NEW_PATH notification happens only when a client denied the create. CREATE, RENAME and UNLINK "can fire multiple times for a single syscall". Whether `new_path.mode` carries the file type bits is not stated. | AUTH_CREATE answered with `es_respond_auth_result`, never cached. NOTIFY_CREATE is subscribed too: a create of a regular file is skipped (its creating NOTIFY_OPEN records it), and a NEW_PATH notification is skipped; symlinks, directories and nodes are recorded as writes. A NEW_PATH destination's type is taken from `mode` only when it has `S_IFMT` bits (**UNVERIFIED** whether it does): otherwise a symlink planted at a parent of monitored prefixes is recorded by NOTIFY_CREATE but not decided at AUTH. Repeated events show as duplicate rows; a repeated AUTH is covered by "allow once". The stub's event-type values match the 27 SDK (`check-stub.sh`). |
| 17 | (not mentioned) | Whether a copied Apple binary keeps its platform-binary flag is not stated anywhere (**UNVERIFIED**; it has the same cdhash, so it is likely still in the trust cache). Since message version 10, `es_process_t.cs_validation_category` gives the kernel's own signing category: `INVALID` 0, `PLATFORM` 1, `TESTFLIGHT` 2, `DEVELOPMENT` 3, `APP_STORE` 4, `ENTERPRISE` 5, `DEVELOPER_ID` 6, `LOCAL_SIGNING` 7, `ROSETTA` 8, `OOPJIT` 9, `NONE` 10. `codesigning_flags` uses the values of `kern/cs_blobs.h` (in the SDK's Kernel.framework): `CS_VALID` 0x1, `CS_GET_TASK_ALLOW` 0x4, `CS_DEBUGGED` 0x10000000, `CS_SIGNED` 0x20000000; per `ESMessageCore.h` a tampered page clears `CS_VALID` once it is paged in. | Apple trust (Apple programs, platform owners, benign services, never-block) needs the platform flag, category `PLATFORM` where it is reported, a root-owned system location unless a signing ID is pinned, and code no other process controls: not get-task-allow, not debugged, not signed but no longer valid. A pinned third-party team or signing ID counts only for `DEVELOPER_ID` or `APP_STORE` where the category is reported; location-only owners (Homebrew, npm, pip tools) are not gated by category. Without a category (older macOS, libproc) the flag alone counts. `es_exec_entitlements` (27) is not used: `codesigning_flags` already shows get-task-allow. |
| 18 | (not mentioned; user decision) | `es_retain_message` (11.0) lets a client answer a message after its handler returned ("out of order"); each retain needs exactly one release. Santa answers retained messages from a timer at 80 % of the deadline budget, headroom clamped to [1 s, 5 s]. That `es_respond_*` may be called from any thread is documented in the 27 header (Thread Safety); earlier headers were silent. Deadline lengths are per message and undocumented. | Ask mode holds undecided sensitive accesses this way (docs/ASK_MODE.md): retain, answer once from the broker's queue (or a backstop), release, inside the client's gate (row 7). The M5 VM script prints how long an unanswered access waits, which is the budget on that Mac. |
| 19 | (not mentioned) | SETMODE, SETOWNER, SETACL, SETATTRLIST and MOUNT have AUTH and NOTIFY variants. The first four support target-path muting; MOUNT does not (header list). `es_event_setattrlist_t` carries the `attrlist` (`commonattr`); `es_event_mount_t` carries a `statfs` (`f_mntonname`). | Subscribed on the native file client (AUTH while enforcing) and in eslogger. chmod, chown, ACL changes, and setattrlist calls that change mode, owner or ACL are recorded and decided as writes; other setattrlist calls are allowed and not recorded. A mount at or above a monitored folder is a write to every category below it (THREAT_MODEL lists the mounts that are not judged). eslogger's JSON for setattrlist and mount is **UNVERIFIED** (item 15 below). |
| 20 | (not mentioned) | Header (`es_new_client`): a new client starts with a **default mute set**. Most AUTH events of some system programs (for example those watchdogd monitors) are muted; NOTIFY events still arrive. The set may change between releases; it can be read and unmuted, which is not recommended. Mute inversion does not clear it. | Read with `es_muted_paths_events` at connect, before any mute of WhoRead's own. Program entries muted for the AUTH events WhoRead answers are logged and counted (`whoread status`, `muted:` line) and never unmuted. Their accesses are recorded through NOTIFY but can never be asked about or blocked. |
| 21 | (not mentioned) | `es_event_close_t.was_mapped_writable` (message v6): when a file was changed only through a memory mapping, `modified` is false and this flag is true. It covers the vnode's whole life and does not say whether the mapping was written. | A close with `modified` false and `was_mapped_writable` true is recorded as a possible write (note `mapped-writable`) only for a process that opened that path with `FWRITE` while the daemon ran (a shared writable mapping needs such a descriptor; at most 4096 such opens are remembered). The eslogger source does not read the flag. |
| 22 | (not mentioned) | Extended ACLs (`chmod +a`, shown by `ls -le`) can let others add, remove or rename entries, or change permissions or owner, which mode bits do not show. Observed on macOS 27.0.1: `acl_get_link_np` and `acl_get_fd_np` with `ACL_TYPE_EXTENDED` return NULL with `ENOENT` when there is no ACL; a file created in a folder with an inheritable ALLOW entry inherits it; `acl_set_fd_np(fd, acl_init(0), ACL_TYPE_EXTENDED)` removes it. `/`, `/Library` and `/Library/Logs` are root:wheel 0755, `/Library/Application Support` is root:admin 0755, none of them nor `/private`, `/private/tmp`, `/private/var/folders` or `/Users` has an extended ACL, and a home carries only `group:everyone deny delete`. | The daemon refuses to start unless only root can change its data directory, the kill-switch directory and every directory above them (owner root or the daemon's user, no group or other write bit unless sticky, no ACL ALLOW entry that lets others change them; DENY entries pass). The CLI and the app use the service name the daemon announces only under the same conditions. Exports drop the ALLOW entries a new file inherits; the extension moves aside a log folder or log file that has any. Stock permissions on macOS 14 to 26 are **UNVERIFIED** (item 23). |
| 23 | (not mentioned) | Observed with `codesign` on macOS 27.0.1: the default resource rules list nested code under `Frameworks`, `SharedFrameworks`, `PlugIns`, `Plug-ins`, `XPCServices`, `Helpers`, `MacOS` and some `Library/` folders, but not `Contents/Library/SystemExtensions`. The app's seal therefore covers the extension's files by hash only, and `codesign --verify --deep` on the app does not evaluate the extension's own signature. | `scripts/dev/sc-app.sh` verifies the extension's signature separately. Assumed to be the same for an Xcode build (not verified). |

## Facts the implementation depends on (summary)

- `es_new_client(_:_:)` (10.15). Handler receives messages serially. A retained message
  (`es_retain_message`, 11.0) may be answered out of order. Creating a client clears the cache and
  gives it the default mute set (row 20).
- `es_respond_auth_result` for every AUTH event except AUTH_OPEN, which uses
  `es_respond_flags_result`. Results: `SUCCESS` 0, `ERR_INVALID_ARGUMENT` 1, `ERR_INTERNAL` 2,
  `NOT_FOUND` 3, `ERR_DUPLICATE_RESPONSE` 4, `ERR_EVENT_TYPE` 5.
- `es_mute_path` and `es_unmute_path` (12.0) with `ES_MUTE_PATH_TYPE_TARGET_PREFIX` (2) or
  `_TARGET_LITERAL` (3) (13.0); `es_unmute_all_target_paths`, `es_invert_muting(client,
  ES_MUTE_INVERSION_TYPE_TARGET_PATH)` and `es_muting_inverted` (13.0). `es_muting_inverted` can
  return `ES_MUTE_INVERTED_ERROR`.
- Target-path muting does not apply to FORK, EXIT and MOUNT, which is one more reason the process
  lifecycle uses its own client.
- `es_subscribe`: since the 27 header, event types the running system does not know
  (≥ its `ES_EVENT_TYPE_LAST`) are silently ignored and SUCCESS is still returned, so SUCCESS is no
  proof of a subscription to an event newer than the running macOS. Every event WhoRead uses dates
  from 10.15 or 12.
- `es_mute_process(client, &audit_token)` to mute ourselves (the token comes from
  `task_info(TASK_AUDIT_TOKEN)`). Per WWDC20, ES does not send introspective AUTH events, but does
  send NOTIFY. The 27 header adds that the token must belong to a running process and that muted
  processes are unmuted when they exit.
- Event structs and field names (all checked against the SDK by `check-stub.sh`):
  `open.fflag/file`, `close.modified/target/was_mapped_writable` (v6),
  `rename.source/destination_type/destination.{existing_file|new_path{dir,filename}}`,
  `clone.source/target_dir/target_name`, `copyfile.source/target_file?/target_dir/target_name`,
  `link.source/target_dir/target_filename` (not `target_name`), `unlink.target/parent_dir`,
  `truncate.target`, `exchangedata.file1/file2`, `readdir.target`,
  `create.destination_type/destination.{existing_file|new_path{dir,filename,mode}}`,
  `setmode.target`, `setowner.target`, `setacl.target`, `setattrlist.attrlist/target`,
  `mount.statfs`, `exec.target` + `es_exec_arg*`, `fork.child`, `exit.stat`.
- `es_process_t`: `audit_token`, `ppid`, `original_ppid`, `codesigning_flags`, `is_platform_binary`,
  `cdhash` (20 bytes), `signing_id`, `team_id`, `executable`, `start_time` (v3),
  `responsible_audit_token` and `parent_audit_token` (v4), `cs_validation_category` (v10).
  `cdhash_full` (v11, the full CDHash) is not used. Version-gated fields are read only after
  checking `message->version >=` (header wording; DocC says "greater than"). Which macOS release
  sends which message version is inferred, not documented: v10 is in the 26.5 header and not in
  15.5, v11 is new in 27.
- `seq_num` (v2) counts each event type on its own and `global_seq_num` (v4) counts all of a
  client's messages; gaps are dropped messages.
- `es_exec_arg` reads data stored after the struct inside the message, so it gets a pointer into the
  original message. Swift's layout of `es_message_t` equals C's (224 bytes, `event` at offset 104).
- libproc (XNU open source): `proc_listallpids` returns a *count*, `proc_listpids` returns
  *bytes*. `PROC_PIDTBSDINFO` on other users' processes needs root.
  `PROC_PIDPATHINFO_MAXSIZE` = 4096. `PROC_PIDUNIQIDENTIFIERINFO` is not in the public headers (not
  used). `KERN_PROCARGS2` (49) sits under `__APPLE_API_UNSTABLE`; its layout (argc, exec path, NUL
  padding, argv, env) comes from XNU, not from a header. `libproc.h` itself calls its interfaces
  private and subject to change.
- `audit_token_to_pid`, `_pidversion` and `_euid` (libbsm, 10.8) are visible through `import Darwin`
  (its module map has a `libbsm` submodule); `whoreadd` links `-lbsm`.
- eslogger JSON shapes: see the fixtures in `Tests/Fixtures/eslogger/` (synthetic, modelled on real
  samples; no capture from this project yet).

## Pending checks

Done on macOS 27.0.1 with the 27.0 SDK (record in `research/sdk-verification-27.0.1.txt`):

1. Done: `scripts/verify-sdk.sh`. `fflag` is `Int32` in Swift; the target mute types are 2 and 3,
   from 13.0; the message-version gates are as listed above (also `exec.dyld_exec_path` v7,
   `script` v2, `cwd` v3, `last_fd` v4, `image_cputype` v6, `create.acl` v2, `mount.disposition` v8,
   `seq_num` v2, `thread` and `global_seq_num` v4).
2. Done: `eslogger --list-events` (106 events) contains every event the native source, the eslogger
   source and `scripts/capture-fixture.sh` use.
7. Done: libbsm's `audit_token_to_*` are visible from Swift through `import Darwin`; no C shim is
   needed.
12. Done in code: `es_set_deadline_miss_mode(client, ES_DEADLINE_MISS_MODE_FAIL_CLOSED)` (row 6).
    Still to check on a VM: that it returns SUCCESS for a system client and reads back as
    fail-closed, and a stop under fail-closed.
13. Done: every other macOS API the code uses is declared in the SDK as used:
    `NSXPCConnection.processIdentifier` / `effectiveUserIdentifier` / `setCodeSigningRequirement`
    (13.0), `SecCodeCopyGuestWithAttributes` with `kSecGuestAttributePid`,
    `SecRequirementCreateWithString`, `SecCodeCheckValidity`, `task_info(TASK_AUDIT_TOKEN)` (15),
    `LOCAL_PEERPID` (2) and `getpeereid` on the dev socket. `NSXPCConnection` has no public audit
    token property. `NSAppleScript` "do shell script … with administrator privileges" (the app's
    kill-switch fallback) and the `x-apple.systempreferences:com.apple.LoginItems-Settings.extension`
    URL cannot be checked against headers; how they behave is still to be seen on a Mac.

Still to check on the Mac or on a VM with SIP disabled (**UNVERIFIED** until then). Most of these
can run as jobs of the VM harness (`scripts/vm/README.md`):

3. Capture a real 60 s fixture (`scripts/capture-fixture.sh`, M0 step needing sudo + FDA). Stop AI
   agents first: code running as you could change the script or the `whoread` it builds while it runs.
4. On a VM with SIP disabled (M4/M5):
   - return value of a late `es_respond_*`;
   - whether a masked non-cached AUTH_OPEN fails or downgrades (WhoRead never sends one);
   - what happens to pending AUTH messages when the daemon is killed (expected: implicit allow in
     kill mode);
   - whether ad-hoc signing plus the ES entitlement is enough with SIP off, and whether an ad-hoc
     system extension without a team activates at all.
5. `codesign -dv` the owner / benign / agent apps. The daemon does this at start (in memory) for
   literal bundle and executable paths; `whoread catalog resolve-owners` shows what it
   finds. Third-party app owners without a team ID are not trusted.
6. XPC peers: that `setCodeSigningRequirement` checks every message, the first one included, by its
   audit token (the embedded CLI cannot weaken protection, the app can, and an exec or pid reuse into
   the app gains nothing); that the embedded CLI's signing identifier is `<prefix>.whoread.cli`; and
   that a Release build writes `WHOREAD_SIGNING_ANCHOR` verbatim into the extension's Info.plist (a
   mangled value fails closed: every non-root client is refused).
8. `es_exec_arg` on device: that argv comes out right (the layout is verified, item 1).
9. Catalog paths and owner install locations. On the Mac, run `whoread catalog show` and fix
   prefixes reported as not detected for apps that are installed. Owner locations taken from
   vendor documentation, not checked on a Mac: Homebrew Python's exec path (expected inside
   `Python.framework/…/Python.app/Contents/MacOS/Python`), nvm / fnm / volta / mise node paths,
   the npm Codex vendor binary (`@openai/codex/vendor/*/codex/codex`), cursor-agent
   (`~/.local/share/cursor-agent/versions/*/`), opencode, the Google Cloud SDK bundled Python,
   Safari's cryptex path (must start with `/System`), Keychain Access's location on macOS 14/15.
   A wrong path makes a tool a non-owner (more alerts), never an owner.
10. Native muting with a catalog prefix whose on-disk spelling differs in case or Unicode
    normalization (VM): confirm that muting the realpath spelling (added automatically) is what
    delivers events. Also which path ES reports for a file under an autofs or network home.
11. `O_DIRECTORY` in `AUTH_OPEN`/`NOTIFY_OPEN` `fflag` for `opendir(3)` (row 15), and whether
    `stat` is always filled in `es_file_t` for opens.
14. Native source (VM): `open(O_CREAT)` of a new file emits NOTIFY_OPEN (so skipping regular-file
    NOTIFY_CREATE loses nothing); with inverted target-path muting the kernel-drop count stays at 0
    at idle (muted events do not use up `global_seq_num`), and `seq_num` does not advance for AUTH
    results served from the cache or for muted events (the dropped-AUTH counts assume both); whether
    `open(O_RDONLY|O_TRUNC)` truncates and which events it produces; whether a relaunched eslogger
    inherits the daemon's ignored SIGINT/SIGTERM (`ps -o pid,ignored -p <pid>`; the source escalates
    to SIGKILL either way).
15. Ask mode and the newer events (VM): that `es_respond_*` on a retained message works from the
    broker's queue and the backstop thread; the real AUTH_OPEN deadline length (the M5 script prints
    the hold budget); that an app blocked in `open()` for the budget does not trip other timeouts
    badly; chmod, chown, ACL changes and a disk image mounted over a vault folder are seen and
    decided; eslogger's JSON for setattrlist (`attrlist.commonattr`) and mount
    (`statfs.f_mntonname`).
16. Teardown and recovery (VM): `es_sync_client` on a live client; whether `es_delete_client` on the
    process client waits for a handler still busy in the process tree update after a drain timeout;
    whether the system extension, not only the dev LaunchDaemon, is relaunched after the watchdog's
    `_exit(70)`.
17. Default mute set (row 20): its contents on macOS 14 and 27.
18. `was_mapped_writable` after writes through a `MAP_SHARED`, `PROT_WRITE` mapping with no
    `write(2)` (row 21).
19. Renames: the AUTH_RENAME and NOTIFY_RENAME shape for `renamex_np(RENAME_SWAP)` (XNU may
    authorize both directions), and the `stat` of an empty destination directory in AUTH_RENAME.
20. Creates at ancestors: whether `new_path.mode` carries `S_IFMT` bits for mkdir versus symlink
    (row 16); which path ES matches under inverted target muting for AUTH_CREATE and AUTH_RENAME
    destinations at an ancestor; whether AUTH_CREATE and NOTIFY_CREATE arrive at a missing ancestor
    of a monitored prefix (a dangling link's target directory).
21. Message versions sent by macOS 14, 15, 26 and 27.
22. Code identity (row 17). Check first, because `CS_VALID` now gates the never-block list: signed
    platform daemons, everything on the never-block list and Rosetta-translated processes report
    `CS_SIGNED` together with `CS_VALID`. Then: a Developer ID app reports category 6; an Xcode
    debug build reports 3 with `CS_GET_TASK_ALLOW`; Homebrew tools report 7 or 10 without it; an lldb
    attach sets `CS_DEBUGGED` in later events; the Apple daemons on the never-block list report
    `PLATFORM`; the category of an x86_64 Developer ID owner under Rosetta (`ROSETTA` would make it a
    non-owner); the category of Xcode's and the Command Line Tools' git (if not `PLATFORM`, the
    platform owner specs for them stop matching); whether a code page written through the task port
    of a non-hardened process clears `CS_VALID`; when the kernel sets `CS_INVALID_ALLOWED` (0x20,
    not used yet); whether a copied Apple binary still reports `PLATFORM`; that `parent_audit_token`
    names the parent's current pidversion, and launchd after reparenting; and that real eslogger
    JSON uses the field names `parent_audit_token`, `cs_validation_category` and
    `codesigning_flags`.
23. File system permissions (row 22): the stock owners, modes and ACLs of `/`, `/Library`,
    `/Library/Logs`, `/Library/Application Support` and `$TMPDIR` on macOS 14 to 26 and on the CI
    runners (the daemon and `scripts/install-dev-daemon.sh` refuse a directory others can change);
    and that the installed extension's bundled `Resources/Data` passes the daemon's trust check (a
    checkout built under umask 002 gives group-writable files, which it refuses).
24. VM harness (`scripts/vm`): whether root without FDA can write the system TCC.db with SIP off,
    and undo it on uninstall; whether tccd honours csreq-NULL path rows after ad-hoc re-signing;
    `kern.hv_vmm_present` and `hw.model` in a Tart guest; a second `mount_virtiofs` while the
    automount holds the tag; a root LaunchDaemon reading the share without FDA;
    `amfi_get_out_of_my_way` in Tart; Tart's `--dir tag=` syntax and the image name; the Spotlight
    state of the vanilla image; how the guest clock jumps after the host sleeps; whether
    `launchctl bootout` signals one pid or the process group; how long `sync` takes against
    launchd's 30 s exit timeout. (Whether launchd sets `TMPDIR` for root daemons and whether the
    share is mounted noexec no longer matter: the scripts depend on neither.)
