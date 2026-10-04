# Research notes (M0)

> Status: verified against Apple's published sources from a **Linux** development host. **Not yet
> verified against the SDK installed on your Mac.** Run `scripts/verify-sdk.sh` on the Mac and
> diff its output against this file (see "Pending local verification").

## How this was verified

The brief asks to read the EndpointSecurity headers from `xcrun --show-sdk-path` and to run
`eslogger --list-events`. The first notes were written on a Linux machine (Swift 6.1, no Xcode, no macOS
SDK), so neither was possible. Instead, every API fact below comes from a primary or
near-primary source, quoted verbatim, with URLs, in:

- [`research/endpoint-security-api.md`](research/endpoint-security-api.md): Apple DocC JSON
  (all 1686 pages under `/documentation/endpointsecurity`, which already reflect the macOS 27
  SDK), plus Apple's own header comments from MacOSX26.5.sdk. The header text came through a
  third-party SDK mirror on GitHub; it matches the 13.3 and 15.5 SDK text. Also the
  `EndpointSecurity(7)` man page, the WWDC20 10159 and WWDC22 110345 transcripts, and Santa
  (northpolesec) for real-world usage.
- [`research/eslogger-libproc-packaging.md`](research/eslogger-libproc-packaging.md): the
  eslogger(1) man page (identical on macOS 13 through 26), a real `--list-events` output from
  macOS 26.5.2, real eslogger JSON lines from public captures (message version 7 from 2023 and
  version 10 from macOS 26), XNU open source for libproc / `KERN_PROCARGS2` / pidversion, the
  XcodeGen ProjectSpec and source, and the Apple SystemExtensions docs.
- [`research/packaging-details.md`](research/packaging-details.md): packaging details for M6.

Nothing in the code relies on an API that is not in those notes. Items marked **UNVERIFIED**
in the notes are handled defensively (see below).

## Differences between the brief and the sources (sources win)

| # | Brief says | Source says | What WhoRead does |
|---|---|---|---|
| 1 | FDA deep link `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles` | `ESClient.h`: on macOS 13+ use `x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles`; the old URL is "until macOS 12" and "may stop working". | Onboarding opens the new URL and falls back to the old one if it fails to open. |
| 2 | Inverted muting: invert, `es_unmute_all_target_paths`, then mute prefixes. | `es_invert_muting` **toggles** (Santa checks `es_muting_inverted` first). The header says to unmute all target paths *before* inverting, and that the client must have **no AUTH subscriptions** at that point. Muting applies to the real, possibly firmlinked path as `F_GETPATH` returns it, after symlink resolution. | Order: unmute all target paths → invert only if `es_muting_inverted` says not inverted → mute prefixes → subscribe. Rule changes apply a *diff* (`es_mute_path` / `es_unmute_path`) rather than unmute-all while AUTH events are subscribed. Prefixes are registered in every byte-distinct spelling: catalog, realpath (on-disk case), NFC and NFD (a resolved `/` or `/dev/…` target is never registered). Whether ES compares mute paths byte-wise or case-insensitively is **UNVERIFIED** (VM item 10). |
| 3 | "Cover clone/copyfile/link/rename/exchangedata by source path." | With target muting inverted, a multi-target event is delivered if **ANY** of its target paths is selected (header flowchart). For RENAME, LINK, CLONE, EXCHANGEDATA and COPYFILE, the targets include source and destination. | Covering the source prefix is enough for delivery. Moving or cloning a *parent* of a sensitive directory (e.g. `mv ~/.config /tmp/x`) has neither path under the prefix, so ancestors are also registered as `TARGET_LITERAL` and classified (`PathClassifier.ancestors`). |
| 4 | Cache only when the decision does not depend on the chain or time. | The ES cache is **global across all clients**. A cache hit produces no AUTH but still produces NOTIFY. Cache keys: OPEN = (process executable *file*, file); READDIR = (process executable file, dir). RENAME, CLONE, COPYFILE, LINK, UNLINK, TRUNCATE, EXCHANGEDATA and CREATE do not support caching. Passing `cache=false` guarantees no caching even if another client asks for it. | The key is the executable file, so a cached *allow* for `cat` would also apply to a later `cat` under an AI agent. WhoRead caches only when no live rule covering the target depends on the chain, argv/owner status, time or use counts (`RuleDecision.cacheable`). Logging comes from NOTIFY events, which the cache does not suppress. `es_clear_cache` runs on every rule or enforcement change; it is rate-limited and returns `ERR_THROTTLE` when called too often, so calls are coalesced. |
| 5 | AUTH_OPEN: reply with `es_respond_flags_result` and the allowed fflags. | Header: pass `UINT32_MAX` unless you mean to deny certain flags; on a cache hit, later opens are allowed only if their flags are a subset. Whether a *non-cached* response that masks some requested flags fails the open or downgrades it is **UNVERIFIED**. `fflag` uses `FREAD`/`FWRITE`, not `O_*`. | Allow → `UINT32_MAX`, cached only if the decision depends on code identity alone *and* no enforced deny rule covers this process and file for any access kind (otherwise a cached masked answer would deny later opens with no AUTH event, no log and no notification, and would outlive the kill switch). Deny → `0` with `cache=false`, so the outcome never depends on the unverified masking semantics. |
| 6 | AUTH deadline: client is terminated; behaviour per header. | Header: "the client will be killed" (since 10.15). WWDC20: a missed deadline is an implicit **ALLOW** that is not cached. macOS 27 adds `es_set_deadline_miss_mode` (default KILL; FAIL_OPEN available). AUTH messages dropped from a full queue are allowed by default. | The callback replies synchronously from in-memory state, measures latency from the message's `mach_time` (so queueing time counts) against `deadline`, and trips the latency monitor; the trip is persisted (the enforcement setting is switched off), and a marker file kept while AUTH is subscribed leaves enforcement off after a kill. **FAIL_OPEN is not implemented yet**: the client runs in the default KILL mode. `if #available(macOS 27, *)` alone does not compile against a macOS 26 SDK, where the symbol is undeclared; it also needs a compile-time SDK guard or a `dlsym` lookup, and the raw value of `ES_DEADLINE_MISS_MODE_FAIL_OPEN` is not in the notes (**UNVERIFIED**). To do once the macOS 27 SDK is available. Pending on-device check: the return value of a late `es_respond_*`. |
| 7 | (not mentioned) | `es_delete_client` must be called from the same thread that called `es_new_client` (header only). | The native source creates and deletes its clients on one dedicated thread. |
| 8 | eslogger: no target-path filter. | Correct. `--select` is not in any Apple man page (13 through 27); third parties say it filters by the *instigating* executable path. eslogger **suppresses events from its own process group**. Raw stdout escapes `/` as `\/`. Key order changes between releases. Exec events carry the **full environment**. `schema_version` was 1 from 2023 (macOS 13.3, message v7) through macOS 26 (message v10). | No `--select`. Early byte-level prefilter (Aho–Corasick, case-insensitive, matches both `/` and `\/` spellings). The parser never relies on key order. `env` is never read; argv is redacted before storage. Test scripts give eslogger its own process group (`set -m`). |
| 9 | Process tree: maintain with fork/exec/exit; use `original_ppid` on reparenting. | XNU `kern_exec.c` and the header confirm that **pidversion changes on exec**; `start_time` is fork time and survives exec. `parent_audit_token` exists from message v4. | Process instances are keyed by (pid, start_time) and images by pidversion. Children link to parents by internal node id, so reparenting and pid reuse cannot corrupt chains. |
| 10 | ES needs the entitlement, root and FDA. | Confirmed. ES is a **library** (`libEndpointSecurity.tbd`), not a framework. `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED` is the only supported way to detect missing FDA. | Linked as `sdk: libEndpointSecurity.tbd`. Onboarding treats `ERR_NOT_PERMITTED` as "FDA missing". |
| 11 | `NSEndpointSecurityMachServiceName` in Info.plist. | Only documented in the `EndpointSecurity(7)` man page. Default when unset: `<teamID>.<bundleID>.xpc` (deprecated). | Set explicitly to `$(DEVELOPMENT_TEAM).$(WHOREAD_EXTENSION_BUNDLE_ID).xpc`. |
| 12 | Request the ES entitlement via the App ID's **Capability Requests** tab. | Apple's ES pages point to developer.apple.com/system-extensions → "Request an Entitlement" (a contact form). The generic Capability Requests help page does not mention Endpoint Security. **UNVERIFIED** which path Apple currently uses. | `docs/DISTRIBUTION.md` (M6) describes both paths. |
| 13 | XcodeGen project. | Target types are `tool` and `system-extension`. A `target:` dependency from the app auto-creates "Embed System Extensions". XcodeGen does **not** generate `CFBundlePackageType` for system extensions. | Set to `$(PRODUCT_BUNDLE_PACKAGE_TYPE)` in `Xcode/project.yml`. |
| 14 | Kill switch: `whoread enforcement off`. | (Design, not an Apple fact.) AI agents run as the user and can run `whoread`. | Turning enforcement **off** needs `sudo` or the signed app; turning it on does not. The file kill switch needs root too (it lives in a root-owned directory). Root may use any CLI build over XPC. |
| 15 | (not mentioned) | `es_file_t` carries `stat` (`st_mode`). The documented eslogger sample open has `fflag` 17825793 = `0x1100001`, which reads as `FREAD \| O_DIRECTORY \| O_CLOEXEC`; that the kernel passes `O_DIRECTORY` (`0x0010_0000`) through in `fflag` is inferred from that sample (**UNVERIFIED**). | A target whose `st_mode` is a directory (or, without `stat`, an `fflag` with `0x0010_0000`) opened without write intent is a directory listing: recorded only when readdir is enabled, never blocked. |
| 16 | (not mentioned) | `AUTH_CREATE` (`es_event_create_t`: `destination_type`, `destination.existing_file` or `destination.new_path {dir, filename, mode}`) does not support caching (header). | Subscribed for AUTH only (NOTIFY_OPEN already records creating opens); answered with `es_respond_auth_result`, never cached. |
| 17 | (not mentioned) | A copied Apple binary keeps its platform-binary flag: the flag follows the code signature (cdhash), not the path. SDK knowledge, not in the notes (**UNVERIFIED**, assumed true because the opposite assumption would fail open). | Platform owners and benign services count only in root-owned system locations, unless a signing ID is pinned. |

## Facts the implementation depends on (summary)

- `es_new_client(_:_:)` (10.15). Handler receives messages serially. A retained message
  (`es_retain_message`, 11.0) may be answered out of order. Creating a client clears the cache.
- `es_respond_auth_result` for every AUTH event except AUTH_OPEN, which uses
  `es_respond_flags_result`. Duplicate responses return `ES_RESPOND_RESULT_ERR_DUPLICATE_RESPONSE`.
- `es_mute_path(client, path, ES_MUTE_PATH_TYPE_TARGET_PREFIX | _TARGET_LITERAL)` (13.0 for target
  types), `es_unmute_all_target_paths` (13.0), `es_invert_muting(client,
  ES_MUTE_INVERSION_TYPE_TARGET_PATH)` and `es_muting_inverted` (13.0).
- Target-path muting does not apply to FORK and EXIT, which is one more reason the process
  lifecycle uses its own client.
- `es_mute_process(client, &audit_token)` to mute ourselves. ES already does not send introspective
  AUTH events, but does send NOTIFY.
- Event structs and field names: `open.fflag/file`, `close.modified/target/was_mapped_writable` (v6),
  `rename.source/destination_type/destination.{existing_file|new_path{dir,filename}}`,
  `clone.source/target_dir/target_name`, `copyfile.source/target_file?/target_dir/target_name`,
  `link.source/target_dir/target_filename` (not `target_name`), `unlink.target/parent_dir`,
  `truncate.target`, `exchangedata.file1/file2`, `readdir.target`, `exec.target` + `es_exec_arg*`,
  `fork.child`, `exit.stat`.
- `es_process_t`: `audit_token`, `ppid`, `original_ppid`, `codesigning_flags`, `is_platform_binary`,
  `cdhash` (20 bytes), `signing_id`, `team_id`, `executable`, `start_time` (v3),
  `responsible_audit_token` and `parent_audit_token` (v4). Version-gated fields are read only after
  checking `message->version >=` (header wording; DocC says "greater than").
- libproc (XNU open source): `proc_listallpids` returns a *count*, `proc_listpids` returns
  *bytes*. `PROC_PIDTBSDINFO` on other users' processes needs root.
  `PROC_PIDPATHINFO_MAXSIZE` = 4096. `PROC_PIDUNIQIDENTIFIERINFO` is private (not used).
  `KERN_PROCARGS2` layout: argc, exec path, NUL padding, argv, env.
- eslogger JSON shapes: see the fixtures in `Tests/Fixtures/eslogger/`.

## Pending local verification (on the Mac)

1. `scripts/verify-sdk.sh`: diff the SDK declarations against the table above. Look especially
   at `fflag` (`Int32` in Swift), `es_mute_path` target types, and the message-version gates.
2. `eslogger --list-events` (captured by the same script): confirm the 11 event names the
   capture uses.
3. Capture a real 60 s fixture (`scripts/capture-fixture.sh`, M0 step needing sudo + FDA).
4. On a VM with SIP disabled (M4/M5):
   - return value of a late `es_respond_*`;
   - whether a masked non-cached AUTH_OPEN fails or downgrades;
   - what happens to pending AUTH messages when the daemon is killed (expected: implicit allow);
   - whether ad-hoc signing plus the ES entitlement is enough with SIP off.
5. `codesign -dv` the owner / benign / agent apps. The daemon does this at start (in memory) for
   literal bundle and executable paths; `whoread catalog resolve-owners` shows what it
   finds. Third-party app owners without a team ID are not trusted.
6. Whether `NSXPCConnection.setCodeSigningRequirement` (macOS 13+) works against an ad-hoc
   signed dev CLI (expected: no; dev builds run without a client requirement).
7. Whether `audit_token_to_pid` / `_pidversion` / `_euid` (libbsm) are visible from Swift via
   `import EndpointSecurity`/`Darwin`. If not, add a small C shim module including
   `<bsm/libbsm.h>`. `NativeESSource` was only type-checked against a stub of the documented
   Swift API (`scripts/dev/es-typecheck`).
8. `es_exec_arg` reads data that follows the struct inside the message. `NativeESSource` passes a
   pointer into the original message (offset of `event`), never a copy. Verify on device that argv
   comes out right.
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
    delivers events.
11. `O_DIRECTORY` in `AUTH_OPEN`/`NOTIFY_OPEN` `fflag` for `opendir(3)` (row 15), and whether
    `stat` is always filled in `es_file_t` for opens.
12. With the macOS 27 SDK: `es_set_deadline_miss_mode(client, ES_DEADLINE_MISS_MODE_FAIL_OPEN)`
    (row 6), behind a compile-time SDK guard.
