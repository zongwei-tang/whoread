# Research: eslogger, libproc/sysctl, and macOS packaging facts

Gathered 2026-10-04 from public primary and secondary sources. Raw copies of every source are saved under `scratchpad/src/`, `scratchpad/src/repos/`, `scratchpad/src/xnu/`, `scratchpad/src/sdk/` and `scratchpad/src-partC/`. Text in blockquotes or code blocks is verbatim. Anything not directly supported by a fetched source is marked **UNVERIFIED**. Inferences are labelled "Inference".

Real JSON samples are in `scratchpad/eslogger-public-samples.jsonl.txt`.

Main sources used:
- **SDK headers:** https://github.com/alexey-lysiuk/macos-sdk (MacOSX13.3/14.5/15.5/26.5.sdk). Referred to below as "SDK 26.5" and so on.
- **XNU:** https://github.com/apple-oss-distributions/xnu, tag `xnu-12377.121.6`, which is the latest tag. Also tag `xnu-8792.41.9` (macOS 13 era) for comparison.

---

# Part A: eslogger

## A1. eslogger(1) man page

### Sources and how the text changed across versions
- https://keith.github.io/xcode-man-pages/eslogger.1.html is an HTML export of Xcode's man pages. The current page comes from the "Xcode 27.2 beta 2 (27B5028f)" export, commit `46d6bd5d44`, dated 2026-09-28. Page history: https://github.com/keith/xcode-man-pages/commits/main/docs/eslogger.1.html
- https://github.com/vitorgalvao/macos-man-pages has `macOS/13/man1/eslogger.1`, `/14/`, `/15/`, `/26/` and `/27/`. The 13, 14, 15 and 26 files are byte-identical (same md5). The 27 file differs only in SEE ALSO, which adds `estrace(1)`. Every version carries the date line `22 February, 2022`.
- **Surprise:** the Xcode 27.2 **beta 1** export (commit `ad6dfbc82dad5e4cd0edb8722ef780f4220781d1`, 2026-09-16) added an `--se` option. Beta 2 (`46d6bd5d4488143b1928411eb2bbaa262e712e0a`) removed it again. The beta 1 text read:
  > `--se` Restrict to the event set supported by **EndpointSecuritySE**, the reduced notify-only kernel extension used on some platforms. **--list-events** lists only that set, and requesting an event outside it fails with an error naming the unsupported events. This is the default when running against **EndpointSecuritySE**; the flag forces the same behavior elsewhere.

  (https://github.com/keith/xcode-man-pages/commit/ad6dfbc82dad5e4cd0edb8722ef780f4220781d1). Treat this as beta-only and do not rely on it.

### Verbatim text (current, matching the macOS 13 through 27 pages)

```
NAME
     eslogger – log Endpoint Security events

SYNOPSIS
     eslogger [--oslog] [--format format] [--oslog-subsystem subsystem]
              [--oslog-category category] event [...]
     eslogger --list-events

DESCRIPTION
     eslogger interfaces with Endpoint Security to log events to standard output or to the unified
     logging system.

     Like all Endpoint Security clients, eslogger must be run as super-user and requires the
     responsible process to have TCC Full Disk Access authorization. See TCC AUTHORIZATION below.
     To avoid feedback loops when filtering output using shell pipelines, eslogger automatically
     suppresses events for all processes that are part of its process group.

     eslogger is not intended to be used by applications. It is not meant provide the same
     functionality, performance and schema stability as natively interfacing with the Endpoint
     Security API does. It cannot provide the integrity protection granted to System Extensions.
     Applications should continue to interface with EndpointSecurity(7) natively.

     IMPORTANT: eslogger is NOT API in any sense. Do NOT rely on the structure or information
     emitted for ANY reason. It may change from release to release without warning.

OPTIONS
     --format format
             Log format to use. Default, and the only format currently supported, is json. See
             FORMATS below.

     --list-events
             List supported events on standard output and exit.

     --oslog
             Emit event data to the unified logging system instead of to standard output. See
             log(1) on configuring and using the unified logging system. The default subsystem and
             category are configured for oversize messages, resulting in a message size limit of
             32k. Larger messages will be truncated.

     --oslog-subsystem subsystem
             Log subsystem to use with --oslog. Default is com.apple.eslogger. Changing the
             subsystem will make the default log profile ineffective, resulting in a message size
             limit of 1k. Configuring subsystem for oversize messages is recommended when using
             --oslog-subsystem.

     --oslog-category category
             Log category to use with --oslog. Default is events. Changing the subsystem will make
             the default log profile ineffective, resulting in a message size limit of 1k.
             Configuring category for oversize messages is recommended when using
             --oslog-category. eslogger uses the main category for operational logging, such as
             fatal errors.

EVENTS
     Events are specified by their short name, such as exec or exit. Use --list-events to list the
     currently supported events by their short name. eslogger supports all notify events that
     EndpointSecurity supports. By design, eslogger does not support any auth events.

     Some fields available in native Endpoint Security API clients are not available in eslogger.
     Currently, the only such field is es_token_t state part of es_thread_state_t, which is used
     only in remote_thread_create events.

FORMATS
     The only supported format for event data is json, which is either JSON Lines, when writing to
     standard output, or JSON, when writing to the unified logging system. While no formal schema is
     provided, the data is modelled after es_message_t as provided by EndpointSecurity(7).
     Semantics, field names and optionality corresponds to the C counterparts as documented in the
     libEndpointSecurity(3) header documentation in the SDK. A schema_version is provided with every
     event. No schema stability guarantees are being made across schema_version changes. New events
     may be added without bumping schema_version. schema_version is specific to the JSON
     representation of events. schema_version is distinct from the version field, which denotes the
     message version as emitted by EndpointSecurity(7).

EXAMPLES
     Subscribe to process lifecycle events and append event data to a file:
     % sudo eslogger exec fork exit >>/tmp/proc.log

     Subscribe to screensharing events and write event data to the unified logging system with the
     default subsystem and category:
     % sudo eslogger --oslog screensharing_attach screensharing_detach

     List available events:
     % eslogger --list-events

     Postprocess the output in a shell pipeline with jq:
     % sudo eslogger exec | jq -r 'select(.process.executable.path == "/bin/zsh")|"\(.process.audit_token.pid): \(.process.executable.path) -> \(.event.exec.target.executable.path)"'

TCC AUTHORIZATION
     eslogger requires the responsible process to have been authorized for Full Disk Access. For
     running eslogger in an SSH session, enable "Allow full disk access for remote users" in System
     Preferences > Sharing > Remote Login. Running eslogger from an app, including Terminal.app or a
     third-party terminal emulator, requires the respective app to be authorized for Full Disk
     Access in System Preferences > Security & Privacy > Privacy > Full Disk Access. Running
     eslogger as a launch daemon requires eslogger itself to be authorized for Full Disk Access in
     System Preferences > Security & Privacy > Privacy > Full Disk Access. MDM servers can grant Full
     Disk Access authorization using the Privacy Preferences Policy Control payload, identified by
     payload type com.apple.TCC.configuration-profile-policy, and its service dictionary key
     SystemPolicyAllFiles.

SEE ALSO
     estrace(1), log(1), mdmclient(1), libEndpointSecurity(3), EndpointSecurity(7).
```
(Source: `macOS/13/man1/eslogger.1`, https://raw.githubusercontent.com/vitorgalvao/macos-man-pages/main/macOS/13/man1/eslogger.1. Wording is identical in the keith.github.io HTML. The `estrace(1)` SEE ALSO entry appears only in macOS 27 and Xcode 27.)

### Requirements: root, FDA, and statements from Apple
- WWDC22 session 110345 transcript (https://developer.apple.com/videos/play/wwdc2022/110345/):
  > eslogger ships with the OS and is already entitled for Endpoint Security. Like all Endpoint Security clients, eslogger must be run as superuser and requires the user to have authorized the responsible process for Full Disk Access, such as Terminal.app or SSH. eslogger is not intended to be used by applications. Its output is subject to change in software updates.

  > eslogger supports all 80 NOTIFY events that Endpoint Security supports in macOS Ventura.
- Without root you get `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED`, and without FDA you get `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`. This is restated at https://rdowd.com/de-mystifying-endpoint-security-messages/. The exact text eslogger prints to stderr on failure is **UNVERIFIED**.
- Entitlements on `/usr/bin/eslogger`, from a binary dump of the macOS 15-era build, project `EndpointSecurity-589.100.29` (https://github.com/timb-machine-mirrors/dmaynor-apple-vuln-research/blob/main/artifacts/cli-binary-map/metadata/eslogger-meta.txt): `com.apple.developer.endpoint-security.client`, `com.apple.private.endpoint-security.embeddedclient`, and `com.apple.security.iokit-user-client-class` = [`EndpointSecurityDriver`, `EndpointSecurityExternalClient`]. The same dump shows the binary links `ArgumentParserInternal.framework` and has types named `JSONEventSerialiser`, `FileWriterEventHandler`, `OSLogEventHandler` and `NSFileHandle`.

### `--select`: not documented by Apple
- **`--select` appears in no man page version**: not macOS 13, 14, 15, 26 or 27, and not the Xcode 14.0 through 27.2 beta 2 exports. Apple's binary-strings dump above is filtered and does not show it either way.
- Three independent third-party 2026 sources use it:
  - tbarabosch blog, 2026-09-18 (https://github.com/tbarabosch/tbarabosch.github.io/blob/main/_posts/2026-09-18-building-a-tiny-macos-edr.md):
    > The `--select` option narrows events to a program-path prefix:
    > `sudo /usr/bin/eslogger --select /bin/zsh exec create rename`
  - jefahnierocks/host-capability-substrate (https://github.com/jefahnierocks/host-capability-substrate/blob/main/docs/host-capability-substrate/shell-environment-research.md):
    > `eslogger --select /bin/zsh` is insufficient because it misses exec-into-shell events from non-zsh parents.

    This implies it filters on the **instigating process's executable path**, not on the exec target.
  - GenseeAI/gensee-crate endpoint-spike.rs (https://github.com/GenseeAI/gensee-crate/blob/main/crate/gensee-crate-macos/src/bin/endpoint-spike.rs) passes `--select /bin/sleep` and `--select /path/prefix` through to `/usr/bin/eslogger`:
    > exec is system-wide; prefer --select while testing to reduce background noise.
- Inference: this matches the ES "inverted muting" feature that WWDC22 describes:
  > Instead of suppressing events based on specified process, executable path, or target path, we now allow you to invert any of these three types of muting. Effectively, you can now select processes, executable paths, or target paths you are interested in…
- **UNVERIFIED:** whether `--select` exists on every macOS version, whether it matches by prefix or literal path, whether it can be repeated, and whether it ever matches target paths.

## A2. Event names (`eslogger --list-events`)

Real `--list-events` output on **macOS 26.5.2 (25F84)**, captured 2026-09-28. It contains 104 events and the source joined them with spaces (https://github.com/jlevy/fdu/blob/a59df75736f9dae8da10b81f069ecadc4f9fd681/explorations/change-sources/os-facilities/results/host_facts.txt):
```
access authentication authorization_judgement authorization_petition btm_launch_item_add btm_launch_item_remove chdir chroot clone close copyfile create cs_invalidated deleteextattr dup exchangedata exec exit fcntl file_provider_materialize file_provider_update fork fsgetpath gatekeeper_user_override get_task get_task_inspect get_task_name get_task_read getattrlist getextattr iokit_open kextload kextunload link listextattr login_login login_logout lookup lw_session_lock lw_session_login lw_session_logout lw_session_unlock mmap mount mprotect od_attribute_set od_attribute_value_add od_attribute_value_remove od_create_group od_create_user od_delete_group od_delete_user od_disable_user od_enable_user od_group_add od_group_remove od_group_set od_modify_password open openssh_login openssh_logout proc_check proc_suspend_resume profile_add profile_remove pty_close pty_grant readdir readlink remote_thread_create remount rename screensharing_attach screensharing_detach searchfs setacl setattrlist setegid seteuid setextattr setflags setgid setmode setowner setregid setreuid settime setuid signal stat su sudo tcc_modify trace truncate uipc_bind uipc_connect unlink unmount utimes write xp_malware_detected xp_malware_remediated xpc_connect
```
- **All requested spellings are confirmed present:** `open`, `close`, `exec`, `fork`, `exit`, `rename`, `clone`, `copyfile`, `link`, `unlink`, `truncate`, `exchangedata`, `readdir`, `create`. `write` is also present.
- Native output is one event name per line. The Cybereason post shows `access`, `authentication`, `btm_launch_item_add`… on separate lines. nubcoxyz/ESLogger splits `--list-events` output with `components(separatedBy: .newlines)` (https://github.com/nubcoxyz/ESLogger/blob/main/Sources/ESLogger/ESLogger.swift). `--list-events` needs no root, per the man page example and the tbarabosch post.
- Count history:
  - WWDC22 said "all 80 NOTIFY events" for Ventura.
  - Cybereason, Oct 2022, said "At the time of writing this post, eslogger supports 82 different endpoint security events, including several undocumented ones" (https://web.archive.org/web/20230316151652/https://www.cybereason.com/blog/blue-teaming-on-macos-with-eslogger).
  - macOS 26.5.2 shows 104.
- The short names are the lowercase `ES_EVENT_TYPE_NOTIFY_*` suffix. Numeric `event_type` values come from the `es_event_type_t` enum (SDK 26.5 `ESTypes.h`, which is append-only and ordered by OS release). I computed them by enumerating the enum, and they match `event_type` in every genuine sample:

| name | event_type | introduced (header comment) |
|---|---|---|
| exec | 9 | macOS 10.15 |
| open | 10 | 10.15 |
| fork | 11 | 10.15 |
| close | 12 | 10.15 |
| create | 13 | 10.15 |
| exchangedata | 14 | 10.15 |
| exit | 15 | 10.15 |
| link | 19 | 10.15 |
| rename | 25 | 10.15 |
| unlink | 32 | 10.15 |
| write | 33 | 10.15 |
| truncate | 41 | 10.15 |
| clone | 61 | 10.15.1 |
| readdir | 68 | 10.15.1 |
| copyfile | 110 | macOS 12.0 |

(https://github.com/alexey-lysiuk/macos-sdk/blob/main/MacOSX26.5.sdk/usr/include/EndpointSecurity/ESTypes.h, `typedef enum { // The following events are available beginning in macOS 10.15 ES_EVENT_TYPE_AUTH_EXEC, ...`)

## A3. Real JSON output and its structure

### Sample provenance (see `eslogger-public-samples.jsonl.txt`)
1. **Genuine single-line output, macOS 26 "Tahoe".** From germanRB-SDS/web-jia: https://github.com/germanRB-SDS/web-jia/tree/8f26a025a667ca516fe98d595c1fc6a50b323ee1/sds-dev-governance/docs/prompts-output/%5B01-5%5D/evidence (`sensor-run-stdout.jsonl` and `canary-run-stdout.jsonl`).
   - It was captured 2026-09-14, with eslogger running as a launchd job inside a Tart VM. The image is `cirruslabs/macos-tahoe-base`, per `sensor-run-*-boot.json`. The exact build is **UNVERIFIED**.
   - It contains 203 events: exec, fork, exit and unlink only.
   - Every event has `schema_version` 1 and message `version` 10.
   - The repo's own analysis reports `"stderr_bytes": 0` and that `global_seq_num` runs 0–82 with no gaps. Its write-up says: "83 eventos reales … 227.996 bytes de stdout, 0 bytes de stderr. Esquema 1, versión de mensaje 10".
2. **Pretty-printed fixtures, message version 7, July and October 2023.** From Security-Experts-Community/open-xp-rules, `packages/system/normalization_formulas/MacOS/es-logger/*/tests/raw_*.txt` at commit `93629719ff3f005456edb63f7e42dbc2caee05de` (https://github.com/Security-Experts-Community/open-xp-rules/tree/93629719ff3f005456edb63f7e42dbc2caee05de/packages/system/normalization_formulas/MacOS/es-logger).
   - The source does not state the macOS version, so it is **UNVERIFIED**. Inference: message version 7 plus the `dyld_exec_path` field means 13.3 or later, because the SDK 13.3 header documents `dyld_exec_path` as "Field available only if message version >= 7". PATH also contains `/System/Cryptexes/App/usr/bin`.
   - They appear genuine:
     - pid/pidversion and `global_seq_num` chain consistently across files. The fork has global_seq_num 2310: child pid 8012, pidversion 17713. The exec has 2311: process pid 8012, pidversion 17713, and target pid 8012, pidversion **17714**.
     - The cdhashes and stat data look realistic.
   - **Some fixtures in that folder were hand-edited**, because their `event_type` does not match the event key. Do not use them:
     - `data_exchange_between_two_files` (exchangedata, but event_type 110 with a timestamp identical to copyfile)
     - `file_provider_materialization`
     - `malware_remediated`
     - `remote_thread_create` (event_type 11)
     - `cs_invalidated`
     - `remount`
     - `setreuid`/`setregid`

     So there is **no trustworthy exchangedata sample**.
3. **Rejected as synthetic:**
   - LuD1161/agentjail `samples/exec-sample.jsonl`. Its own README says: "Sample is synthetic (sanitized) … not a live capture."
   - hoknie/vigil `exec.ndjson`, which has a fake cdhash `0f3a6c9d1e2b4a5c6d7e8f901a2b3c4d5e6f7a8b` and pidversion 4242 everywhere.
   - fish2lab/os-lab-mcp `raw.eslogger.sample`, which has pid 1001, pidversion 60001 and start_time `.000Z`.
   - rdowd.com shows an abbreviated (stats and audit tokens removed) unlink with version 10, dated 2025-12-29, and it is not valid JSON as shown.

### Top-level keys (observed)
- macOS 26, version 10, all 203 events: `action`, `action_type`, `event`, `event_type`, `global_seq_num`, `mach_time`, `process`, `schema_version`, `seq_num`, `thread`, `time`, `version`.
- The version 7 fixtures (2023) have the same set.
- **`deadline` never appears** in any observed eslogger output. Note: eslogger is notify-only. The C struct has `uint64_t deadline;`.
- `thread` = `{"thread_id": <n>}`.
- `action_type` = 1, which is `ES_ACTION_TYPE_NOTIFY`. The enum is `ES_ACTION_TYPE_AUTH, ES_ACTION_TYPE_NOTIFY` (ESTypes.h).
- `action` for exec, fork, exit, unlink, close and so on is `{"result":{"result":{"auth":0},"result_type":0}}`.
- `action` for open is `{"result":{"result":{"flags":4294967295},"result_type":1}}`. `result_type` 1 is `ES_RESULT_TYPE_FLAGS`.
- `schema_version` was **1** in every source: 2023 version 7 fixtures, the Dec 2025 rdowd version 10 excerpt, and the Sep 2026 macOS 26 version 10 capture. The nubcoxyz/ESLogger parser, from Feb 2023, has a commented-out header check: `// guard let expectedHeader = "{\"schema_version\":1,\"mach_time\":".data(using: .utf8)`.

### Timestamp formats (observed in all samples)
| field | example | format |
|---|---|---|
| `time` | `"2026-09-14T07:00:59.310882725Z"` | ISO-8601 UTC, 9 fractional digits, `Z` |
| `process.start_time` | `"2026-09-14T07:00:38.017053Z"` | 6 fractional digits (it is a `struct timeval`), `Z` |
| `stat.st_*timespec` | `"2026-08-13T02:51:55.000000000Z"` | 9 fractional digits, `Z` |

All 203 macOS 26 events matched the patterns `dddd-dd-ddTdd:dd:dd.dddddddddZ` (`time`) and `dddd-dd-ddTdd:dd:dd.ddddddZ` (`start_time`). The version 7 fixtures use the same formats.

### `process` (es_process_t)
- Keys observed in version 10 output: `audit_token`, `cdhash`, `codesigning_flags`, `cs_validation_category`, `executable`, `group_id`, `is_es_client`, `is_platform_binary`, `original_ppid`, `parent_audit_token`, `ppid`, `responsible_audit_token`, `session_id`, `signing_id`, `start_time`, `team_id`, `tty`.
- Version 7 has the same keys **minus `cs_validation_category`**, which the header gates at "message version >= 10".
- `audit_token` / `parent_audit_token` / `responsible_audit_token` = `{"asid","pidversion","ruid","euid","rgid","auid","egid","pid"}`.
  - `auid` 4294967295 appears for unset values.
- `cdhash` = 40 uppercase hex characters.
- `team_id` can be `null`.
- `tty` = `null` or an es_file object.
- `executable` = `{"path","path_truncated","stat":{st_dev, st_mode, st_nlink, st_ino, st_uid, st_gid, st_rdev, st_atimespec, st_mtimespec, st_ctimespec, st_birthtimespec, st_size, st_blocks, st_blksize, st_flags, st_gen}}`.
- Header docs (SDK 26.5 `ESMessageCore.h`, https://github.com/alexey-lysiuk/macos-sdk/blob/main/MacOSX26.5.sdk/usr/include/EndpointSecurity/ESMessageCore.h):
  > @field original_ppid Original ppid of the process.  This field stays constant even in the event this process is reparented.
  > @field start_time Process start time, i.e. time of fork creating this process.
  > @field responsible_audit_token audit token of the process responsible for this process, which may be the process itself in case there is no responsible process or the responsible process has already exited.
  > The tuple (pid, pidversion) identifies a specific process execution, and should be used to link events to the process that emitted them.  Executing an executable image in a process using the exec or posix_spawn family of syscalls increments the pidversion.  However, (pid, pidversion) is not meant to be unique across reboots or across multiple systems.

  Field version gates:
  ```c
  es_file_t *_Nullable tty;                           /* field available only if message version >= 2 */
  struct timeval start_time;                          /* field available only if message version >= 3 */
  audit_token_t responsible_audit_token;              /* field available only if message version >= 4 */
  audit_token_t parent_audit_token;                   /* field available only if message version >= 4 */
  es_cs_validation_category_t cs_validation_category; /* field available only if message version >= 10 */
  ```
  > Overlong paths are truncated at a maximum length that currently is 16K, though that number is not considered API and may change

  This explains `path_truncated`.

### Event payloads (observed JSON vs header)
- **open**: `{"open":{"fflag":17825793,"file":{path,stat,path_truncated}}}`. The header says:
  > The `fflag` field represents the mask as applied by the kernel, not as represented by typical open(2) `oflag` values … (e.g. FREAD, FWRITE instead of O_RDONLY, O_RDWR, etc...)
- **close**: `{"close":{"target":{…},"was_mapped_writable":false,"modified":false}}`. Header:
  > The `modified` flag only reflects that a file was or was not modified by filesystem syscall. If a file was only modifed though a memory mapping this flag will be false, but was_mapped_writable will be true.

  `was_mapped_writable` is "Field available only if message version >= 6".
- **rename**: `{"rename":{"source":{…},"destination_type":0,"destination":{"existing_file":{…}}}}` or `{"rename":{"destination_type":1,"destination":{"new_path":{"dir":{…},"filename":"3.txt"}},"source":{…}}}`.
  - The enum is `ES_DESTINATION_TYPE_EXISTING_FILE, ES_DESTINATION_TYPE_NEW_PATH`, so 0 means existing file and 1 means new path.
  - Header: "This event can fire multiple times for a single syscall, for example when the syscall has to be retried due to racing VFS operations."
- **exec**: keys are `args` (array of strings), `cwd` (es_file), `dyld_exec_path` (string, version 7 and later), `env` (array of `"K=V"` strings: **the full environment is emitted**), `fds` (`[{"fd":0,"fdtype":1},…]`), `image_cputype` (for example 16777223), `image_cpusubtype`, `last_fd`, `script` (null or es_file), and `target` (es_process_t). Header note:
  > The `audit_token_t` structs contained in the two different `es_process_t` structs will not be identical: the pidversion field will be updated, and the uid/gid values may be different if the new program had setuid/setgid permission bits set.

  In the samples, `start_time` of `target` equals the pre-exec `process.start_time` (time of fork).
- **fork**: `{"fork":{"child":{<es_process_t>}}}`.
- **exit**: `{"exit":{"stat":256}}`. Header: "The exit status of a process (same format as wait(2))". So 256 = exit code 1, and the macOS 26 samples show `{"stat":0}`.
- **unlink**: `{"unlink":{"target":{…},"parent_dir":{…}}}`.
- **clone**: `{"clone":{"target_dir":{…},"target_name":"splitByEvents copy.py","source":{…}}}`.
- **copyfile**: `{"copyfile":{"flags":0,"target_dir":{…},"source":{…},"target_file":null,"target_name":"floss copy.exe","mode":420}}`.
- **link**: `{"link":{"target_dir":{…},"target_filename":"…","source":{…}}}`. Note the key is `target_filename` here, while clone and copyfile use `target_name`.
- **truncate**: `{"truncate":{"target":{…}}}`.
- **create**: `{"create":{"destination_type":0,"destination":{"existing_file":{…}},"acl":null}}`. The new_path variant has `dir`, `filename` and `mode`, per the header.
- **readdir**: `{"readdir":{"target":{…}}}`.
- **write**: `{"write":{"target":{…}}}`.
- **exchangedata**: the header has `file1` and `file2`. No genuine sample was found (**UNVERIFIED** JSON).

### Schema and version changes
- `schema_version` stayed at 1 from 2023 through macOS 26 in every source found. No Apple changelog for the JSON schema exists. The man page says "No schema stability guarantees are being made across schema_version changes. New events may be added without bumping schema_version."
- **Message `version`** is the ES `es_message_t.version`. Fields gated by version, from SDK 26.5 headers:

  | version | fields |
  |---|---|
  | ≥2 | `seq_num`, exec `script`, create `acl`, process `tty` |
  | ≥3 | exec `cwd`, process `start_time` |
  | ≥4 | `thread`, `global_seq_num`, exec `last_fd`, process `responsible_audit_token` and `parent_audit_token` |
  | ≥5 | get_task* `type` |
  | ≥6 | close `was_mapped_writable`, exec `image_cputype` and `image_cpusubtype` |
  | ≥7 | exec `dyld_exec_path` |
  | ≥8 | mount/remount `disposition`, remount `remount_flags` |
  | ≥9 | signal `instigator` |
  | ≥10 | iokit_open `parent_registry_id` and `parent_path`, xp_malware_detected `detected_executable`, process `cs_validation_category` |

- Highest version each SDK documents: SDK 13.3 and 14.5 know up to 7, SDK 15.5 up to 8, SDK 26.5 up to 10. macOS 26 emitted 10 (observed). The exact version-to-OS mapping is **UNVERIFIED**.
- **Key order differs between releases.** The version 7 era starts `{"schema_version":1,"mach_time":…` (open-xp-rules fixtures, nubco comment). The macOS 26 output starts `{"schema_version":1,"action":…` and nested keys are in hash order. Do not depend on order.

## A4. Gotchas
- **Volume.**
  - Cybereason: "running eslogger for only a few minutes can result in tens of thousands of events", and one roughly 1-minute pkg install run "returned 8371 endpoint security events".
  - tbarabosch: "Events such as `open`, `write`, `stat` and directory lookups arrive in impressive quantities."
  - agentjail: `mmap`, `open`, `close`, `lookup` "easily dominate event volume".
  - In the macOS 26 capture, the maximum line was 3,864 bytes for exec/fork/exit/unlink over 4 seconds. Exec lines carry the full `env`, so they can be much larger.
- **Self-suppression.** The man page says eslogger "automatically suppresses events for all processes that are part of its process group". tbarabosch relies on this when spawning eslogger with `subprocess.Popen` without a new process group.
- **Output encoding.** Genuine stdout escapes forward slashes as `\/`, for example `"path":"\/usr\/libexec\/mobileassetd"` (GROUP 1 samples). JSON parsers handle this, but raw `grep` for paths will not match.
- **Big integers.** `st_ino` values such as `1152921500312082960` exceed 2^53, and `auid`/`flags` 4294967295 appear. Decode them as `UInt64`/`Int64`, never as Double.
- **Nulls.** `team_id`, `tty`, `script`, `copyfile.target_file` and `create.acl` are `null` in real output.
- **Preamble.** In the macOS 26 launchd run, stdout contained exactly one JSON object per line (83 events = 83 lines) and stderr was 0 bytes. No banner was observed. Whether anything is printed on startup in other modes, such as from a terminal, is **UNVERIFIED**.
- **TTY.** Not required. The macOS 26 capture ran as a launchd job, and GenseeAI and tbarabosch spawn it with a piped stdout. The man page documents running as a launch daemon, which then needs eslogger itself to have FDA.
- **SIGINT/SIGTERM.**
  - In the WWDC22 demo, Ctrl-C ends a capture ("Back in the first tab, I'm interrupting eslogger.").
  - tbarabosch sends SIGTERM and SIGKILLs after 2 s if it has not exited, as a precaution. That is not evidence of hanging.
  - nubcoxyz/ESLogger uses `process?.kill()`.
  - GenseeAI: "use --duration-seconds during piped tests so the stream closes cleanly".
  - Exit status on signal, and whether a partial line is flushed, are **UNVERIFIED**.
- **Buffering.** **UNVERIFIED**; no source states it. Inference only: the binary uses `NSFileHandle` and `FileWriterEventHandler` rather than stdio, so writes are likely not 4 KB stdio-buffered. Reader side: nubcoxyz/ESLogger had to rejoin JSON objects that were "split across more than one line" between pipe reads, so buffer until `\n`.
- **Dropped events.** Use `global_seq_num` and `seq_num` gaps, as the header documents. nubcoxyz/ESLogger implements this: `if lastGlobalSeqNum != -1 && jsonEvent.global_seq_num > lastGlobalSeqNum+1 { … kernel dropped events for us`.
- **`--oslog` truncation.** The limit is 32k with the default subsystem and category, and 1k if you change them (man page).
- **Thread state.** The man page says the only ES field missing from eslogger output is `es_thread_state_t.state`, which appears in remote_thread_create events.

---

# Part B: libproc and sysctl (XNU open source)

## B5. Declarations

**`libsyscall/wrappers/libproc/libproc.h`** at xnu-12377.121.6 (https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/libsyscall/wrappers/libproc/libproc.h). The SDK copy is at `MacOSX*.sdk/usr/include/libproc.h` and differs only in writing `macos(11.0)` instead of `macos(10.16)`.
```c
/*
 * This header file contains private interfaces to obtain process information.
 * These interfaces are subject to change in future releases.
 */
...
int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
int proc_listallpids(void * buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_4_1);
int proc_listpgrppids(pid_t pgrpid, void * buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_4_1);
int proc_listchildpids(pid_t ppid, void * buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_7, __IPHONE_4_1);
int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
int proc_name(int pid, void * buffer, uint32_t buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
int proc_pidpath(int pid, void * buffer, uint32_t  buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
int proc_pidpath_audittoken(audit_token_t *audittoken, void * buffer, uint32_t  buffersize) API_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0));
```

**Return-value semantics**, from `libsyscall/wrappers/libproc/libproc.c` (https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/libsyscall/wrappers/libproc/libproc.c):
```c
int
proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize)
{
	int retval;

	if ((type >= PROC_ALL_PIDS) || (type <= PROC_PPID_ONLY)) {
		if ((retval = __proc_info(PROC_INFO_CALL_LISTPIDS, type, typeinfo, (uint64_t)0, buffer, buffersize)) == -1) {
			return 0;
		}
	...
int
proc_listallpids(void * buffer, int buffersize)
{
	int numpids;
	numpids = proc_listpids(PROC_ALL_PIDS, (uint32_t)0, buffer, buffersize);

	if (numpids == -1) {
		return -1;
	} else {
		return numpids / sizeof(int);
	}
}
...
proc_pidpath(int pid, void * buffer, uint32_t  buffersize)
{
	int retval, len;

	if (buffersize < PROC_PIDPATHINFO_SIZE) {
		errno = ENOMEM;
		return 0;
	}
	if (buffersize > PROC_PIDPATHINFO_MAXSIZE) {
		errno = EOVERFLOW;
		return 0;
	}
	retval = __proc_info(PROC_INFO_CALL_PIDINFO, pid, PROC_PIDPATHINFO, (uint64_t)0, buffer, buffersize);
	if (retval != -1) {
		len = (int)strlen(buffer);
		return len;
	}
	return 0;
}
```
- `proc_listpids` returns **bytes** and returns 0 on error.
- `proc_listallpids` returns a **count of pids**. Because `proc_listpids` maps -1 to 0, it also returns 0 on error.
- `proc_pidinfo` returns bytes copied, or 0 on error.
- `proc_pidpath` requires a buffer of at least `PROC_PIDPATHINFO_SIZE` (1024) and at most `PROC_PIDPATHINFO_MAXSIZE` (4096).
- Kernel side (`bsd/kern/proc_info.c`): with a NULL buffer, listpids returns `((nprocs + 20) * sizeof(int))`, as in `/* if the buffer is null, return num of procs */`.

**`bsd/sys/proc_info.h`**, public and shipped in the SDK (https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/sys/proc_info.h):
```c
#define PROC_ALL_PIDS           1
#define PROC_PGRP_ONLY          2
#define PROC_TTY_ONLY           3
#define PROC_UID_ONLY           4
#define PROC_RUID_ONLY          5
#define PROC_PPID_ONLY          6
#define PROC_KDBG_ONLY          7

struct proc_bsdinfo {
	uint32_t                pbi_flags;              /* 64bit; emulated etc */
	uint32_t                pbi_status;
	uint32_t                pbi_xstatus;
	uint32_t                pbi_pid;
	uint32_t                pbi_ppid;
	uid_t                   pbi_uid;
	gid_t                   pbi_gid;
	uid_t                   pbi_ruid;
	gid_t                   pbi_rgid;
	uid_t                   pbi_svuid;
	gid_t                   pbi_svgid;
	uint32_t                rfu_1;                  /* reserved */
	char                    pbi_comm[MAXCOMLEN];
	char                    pbi_name[2 * MAXCOMLEN];  /* empty if no name is registered */
	uint32_t                pbi_nfiles;
	uint32_t                pbi_pgid;
	uint32_t                pbi_pjobc;
	uint32_t                e_tdev;                 /* controlling tty dev */
	uint32_t                e_tpgid;                /* tty process group id */
	int32_t                 pbi_nice;
	uint64_t                pbi_start_tvsec;
	uint64_t                pbi_start_tvusec;
};

/* pbi_flags values */
#define PROC_FLAG_SYSTEM        1       /*  System process */
#define PROC_FLAG_TRACED        2       /* process currently being traced, possibly by gdb */
#define PROC_FLAG_INEXIT        4       /* process is working its way in exit() */
#define PROC_FLAG_PPWAIT        8
#define PROC_FLAG_LP64          0x10    /* 64bit process */
#define PROC_FLAG_SLEADER       0x20    /* The process is the session leader */
#define PROC_FLAG_CTTY          0x40    /* process has a control tty */
#define PROC_FLAG_CONTROLT      0x80    /* Has a controlling terminal */
#define PROC_FLAG_THCWD         0x100   /* process has a thread with cwd */
...
#define PROC_FLAG_PSUGID        0x2000   /* process has set privileges since last exec */
#define PROC_FLAG_EXEC          0x4000   /* process has called exec  */

#define PROC_PIDTBSDINFO                3
#define PROC_PIDTBSDINFO_SIZE           (sizeof(struct proc_bsdinfo))
#define PROC_PIDPATHINFO                11
#define PROC_PIDPATHINFO_SIZE           (MAXPATHLEN)
#define PROC_PIDPATHINFO_MAXSIZE        (4*MAXPATHLEN)
#define PROC_PIDT_SHORTBSDINFO          13
#define PROC_PIDT_SHORTBSDINFO_SIZE     (sizeof(struct proc_bsdshortinfo))
```
SDK `sys/param.h` has `#define MAXCOMLEN 16` and `#define MAXPATHLEN PATH_MAX`. SDK `sys/syslimits.h` has `#define PATH_MAX 1024`. So `pbi_comm` is 16 bytes, `pbi_name` is 32 bytes, and `PROC_PIDPATHINFO_MAXSIZE` = 4096.

**Surprise: `PROC_PIDUNIQIDENTIFIERINFO`, `struct proc_uniqidentifierinfo` and `PROC_PIDT_BSDINFOWITHUNIQID` are NOT in the public SDK headers.** `grep` finds 0 hits in SDK 13.3, 14.5, 15.5 and 26.5 `sys/proc_info.h`.
- In current XNU they live in **`bsd/sys/proc_info_private.h`** (https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/sys/proc_info_private.h).
- In xnu-8792.41.9 (macOS 13) they were in `bsd/sys/proc_info.h` under `#ifdef PRIVATE`.
- To use them from Swift you must redeclare them yourself.

```c
struct proc_uniqidentifierinfo {
	uint8_t                 p_uuid[16];             /* UUID of the main executable */
	uint64_t                p_uniqueid;             /* 64 bit unique identifier for process */
	uint64_t                p_puniqueid;            /* unique identifier for process's parent */
	int32_t                 p_idversion;            /* pid version */
	int32_t                 p_orig_ppidversion;     /* process's original parent's pid version, doesn't change if reparented */
	uint64_t                p_reserve2;             /* reserved for future use */
	uint64_t                p_reserve3;             /* reserved for future use */
};
/* This structure is API */
_Static_assert(sizeof(struct proc_uniqidentifierinfo) == 56, "sizeof(struct proc_uniqidentifierinfo) == 56");

struct proc_bsdinfowithuniqid {
	struct proc_bsdinfo             pbsd;
	struct proc_uniqidentifierinfo  p_uniqidentifier;
};
...
/* Flavors for proc_pidinfo() */
#define PROC_PIDUNIQIDENTIFIERINFO      17
#define PROC_PIDUNIQIDENTIFIERINFO_SIZE \
	                                (sizeof(struct proc_uniqidentifierinfo))

#define PROC_PIDT_BSDINFOWITHUNIQID     18
#define PROC_PIDT_BSDINFOWITHUNIQID_SIZE \
	                                (sizeof(struct proc_bsdinfowithuniqid))
```
The macOS 13 (xnu-8792.41.9) layout has the same size and offsets, but the field after `p_idversion` was `uint32_t p_reserve2;`, followed by `uint64_t p_reserve3; uint64_t p_reserve4;`. `p_orig_ppidversion` is new.

**Permission rules** (`bsd/kern/proc_info.c`, https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/proc_info.c):
```c
	/* Certain operations don't require privileges */
	switch (flavor) {
	case PROC_PIDT_SHORTBSDINFO:
	case PROC_PIDUNIQIDENTIFIERINFO:
	case PROC_PIDPATHINFO:
	case PROC_PIDCOALITIONINFO:
	case PROC_PIDPLATFORMINFO:
		check_same_user = NO_CHECK_SAME_USER;
		break;
	default:
		check_same_user = CHECK_SAME_USER;
```
and in `proc_security_policy`:
```c
	/*
	 * Check for 'get information for processes owned by other users' privilege
	 * root has this privilege by default
	 */
```
So `PROC_PIDTBSDINFO` on another user's process needs root, or returns EPERM. `PROC_PIDPATHINFO`, `PROC_PIDT_SHORTBSDINFO` and `PROC_PIDUNIQIDENTIFIERINFO` do not need root, although the MACF/sandbox hook `mac_proc_check_proc_info` can still deny them. The fill code is:
```c
	p_uniqidinfo->p_uniqueid = proc_uniqueid(p);
	proc_getexecutableuuid(p, (unsigned char *)&p_uniqidinfo->p_uuid, sizeof(p_uniqidinfo->p_uuid));
	p_uniqidinfo->p_puniqueid = proc_puniqueid(p);
	p_uniqidinfo->p_idversion = proc_pidversion(p);
	p_uniqidinfo->p_orig_ppidversion = proc_orig_ppidversion(p);
```

## B6. KERN_PROCARGS2 layout
- SDK `sys/sysctl.h`: `#define KERN_ARGMAX 8 /* int: max arguments to exec */`, `#define KERN_PROCARGS2 49`. The MIB is `{CTL_KERN, KERN_PROCARGS2, pid}`.
- Apple's own `ps` (adv_cmds, https://github.com/apple-oss-distributions/adv_cmds/blob/main/ps/print.c, blob commit `60bc9ebf…`, latest tag `adv_cmds-237`):
```c
	/*
	 * Make a sysctl() call to get the raw argument space of the process.
	 * The layout is documented in start.s, which is part of the Csu
	 * project.  In summary, it looks like:
	 *
	 * /---------------\ 0x00000000
	 * :               :
	 * :               :
	 * |---------------|
	 * | argc          |
	 * |---------------|
	 * | arg[0]        |
	 * |---------------|
	 * :               :
	 * :               :
	 * |---------------|
	 * | arg[argc - 1] |
	 * |---------------|
	 * | 0             |
	 * |---------------|
	 * | env[0]        |
	 * |---------------|
	 * :               :
	 * :               :
	 * |---------------|
	 * | env[n]        |
	 * |---------------|
	 * | 0             |
	 * |---------------| <-- Beginning of data returned by sysctl() is here.
	 * | argc          |
	 * |---------------|
	 * | exec_path     |
	 * |:::::::::::::::|
	 * |               |
	 * | String area.  |
	 * |               |
	 * |---------------| <-- Top of stack.
	 * :               :
	 * :               :
	 * \---------------/ 0xffffffff
	 */
```
  `ps` then does `memcpy(&nargs, procargs, sizeof(nargs))`, then `/* Skip the saved exec_path. */`, then `/* Skip trailing '\0' characters. */`, then reads `nargs` NUL-terminated strings. The comment notes:
  > There is no way to deterministically know where the command arguments end and the environment strings start, which is why the '=' character is searched for as a heuristic.

  Since `ps` has the argc word, counting strings works.
- Kernel (`bsd/kern/kern_sysctl.c`, https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_sysctl.c):
  - L1323: `SYSCTL_PROC(_kern, KERN_PROCARGS2, procargs2, ...)`.
  - L1707: `/* Put processes argc as the first word in the copyout buffer */`, followed by `suword(where, argc);`.
  - About the `executable_path=` prefix:
    > When these sysctls were introduced, the first string in the strings section was just the bare path of the executable.  However, for security reasons we now prefix this string with executable_path= so it can be parsed getenv style.  To avoid binary compatability issues with exising callers of this sysctl, we strip it off here.
  - The buffer must be at most ARG_MAX: `if (where != USER_ADDR_NULL && (buflen <= 0 || buflen > ARG_MAX)) { error = EINVAL;`.
  - Other users' processes require root. `is_procargs_content_read_permitted` returns false when uid differs and `suser()` fails, which gives EINVAL.
  - **Environment variables are omitted** unless one of these holds: the target is the caller, `!cs_restricted(p)`, SIP allows unrestricted dtrace, or the caller has `com.apple.private.read-environment-variables`. Source comment: `/* Allow reading environment variables if any of the following are true: ...`.
  - Processes with `com.apple.private.no-read-procargs` return a synthetic `argc=1, exec path, NUL, NUL, argv[0]=exec path` (`sysctl_procargs_no_read`).

## B7. Does audit-token pidversion change on exec? **Yes.**
- Current XNU (`bsd/kern/kern_exec.c` L7788–7797 at xnu-12377.121.6, https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_exec.c#L7788-L7797):
```c
	/* Update the process' identity version and set the security token.
	 * Also, ensure we always see a modified identity version (rdar://129775819).
	 */
	int previous_pid_version = proc_get_ro(p)->p_idversion;
	int new_pid_version;
	do {
		new_pid_version = OSIncrementAtomic(&nextpidversion);
	} while (new_pid_version == previous_pid_version);
	proc_setpidversion(p, new_pid_version);
	task_set_uniqueid(proc_task(p));
```
- macOS 13 era (xnu-8792.41.9 `kern_exec.c` L6618–6621):
```c
	/* Update the process' identity version and set the security token */
	proc_setpidversion(p, OSIncrementAtomic(&nextpidversion));
	task_set_uniqueid(task);
	set_security_token_task_internal(p, task);
```
- The audit token carries it (`bsd/kern/kern_prot.c`, `proc_calc_audit_token`): `audit_token->val[5] = proc_getpid(p); ... audit_token->val[7] = proc_pidversion(p);`.
- Fork (`bsd/kern/kern_fork.c` L980–1001):
  - A new process gets `proc_ro_data.p_idversion = OSIncrementAtomic(&nextpidversion);` and `proc_ro_data.p_uniqueid = ++nextuniqueid;`.
  - In the exec-copy path, the identifiers are copied: `/* For exec copy of the proc, copy the PID identifiers of original proc */ ... proc_ro_data.p_uniqueid = parent_proc->p_proc_ro->p_uniqueid;`.
  - Inference: **`p_uniqueid` survives exec while pidversion changes**. pidversion comes from a global counter, so it is not simply +1: the macOS 26 sample shows deltas of 1, 3, 4, 5 … 583.
- ES header (SDK 14.5 and later) says the same thing ("Executing an executable image … increments the pidversion"). Real data confirms it:
  - open-xp-rules fork→exec: pid 8012, pidversion 17713 → 17714.
  - macOS 26 capture: `[628,1639,628,1640,…"/sbin/launchd","/usr/libexec/xpcproxy"]`.

---

# Part C: packaging facts (items 8–12)

The section below was gathered by a parallel research pass. I spot-checked these items against the saved raw sources:
- the FDA deep-link text in ESClient.h (identical in SDK 13.3 and 26.5)
- XcodeGen `system-extension`/`tool` type strings
- the `copy.destination` list without `systemExtensions`
- the automatic "Embed System Extensions" phase with `$(SYSTEM_EXTENSIONS_FOLDER_PATH)` in PBXProjGenerator.swift
- the `codeSign` default `!dependencyTarget.type.isExecutable`, where `isExecutable` includes `isSystemExtension`
- `setCodeSigningRequirement`/`setConnectionCodeSigningRequirement` `API_AVAILABLE(macos(13.0))` in the SDK 26.5 NSXPCConnection.h


Fetched 2026-10-04 (UTC). Raw sources are saved under `scratchpad/src-partC/`:
- `xcodegen-*`: XcodeGen docs and source
- `apple/*.json`: Apple DocC JSON (`apple/rendered/*.txt` holds a text rendering made by `tools/docc.py`)
- `man/`: man pages
- `sdk*.h`: SDK headers from a GitHub SDK mirror
- `web/`, `forums/`: third-party pages and forum extractions

Apple developer forum pages could not be downloaded with curl: they redirect to a "Security Verification" page. For those, the files hold WebFetch extractions. WebFetch uses a small model, so those quotes are close to verbatim but not byte-exact. Each such quote is marked "(WebFetch)".

---

## 8. XcodeGen ProjectSpec

**Versions of the sources I fetched**
- `Docs/ProjectSpec.md` came from the `master` branch. The latest commit touching that file is `24c891cb55805a5ee088912b98ee3c3d7121a92f` (2026-09-13, "Add scheme build architecture overrides (#1642)"). The repo HEAD at fetch time was `366592bc5be446b427fc8e2a21520344460f96ab`. (Sources: `gh api repos/yonaskolb/XcodeGen/commits?path=Docs/ProjectSpec.md&per_page=1`; `src-partC/xcodegen-ProjectSpec-commit.json`)
- The latest XcodeGen release is **2.46.0** (published 2026-07-16). (Source: `gh api repos/yonaskolb/XcodeGen/releases/latest`)
- A real-world spec (third-party) uses `minimumXcodeGenVersion: 2.46.0` for a system-extension target. See "Real-world reference" below.
- URL: https://raw.githubusercontent.com/yonaskolb/XcodeGen/master/Docs/ProjectSpec.md

### Target `type` values (verbatim list, "Product Type" section)
> This will provide default build settings for a certain product type. It can be any of the following:
```
- `application`
- `application.on-demand-install-capable`
- `application.messages`
- `application.watchapp`
- `application.watchapp2`
- `application.watchapp2-container`
- `app-extension`
- `app-extension.intents-service`
- `app-extension.messages`
- `app-extension.messages-sticker-pack`
- `bundle`
- `bundle.ocunit-test`
- `bundle.ui-testing`
- `bundle.unit-test`
- `extensionkit-extension`
- `framework`
- `instruments-package`
- `library.dynamic`
- `library.static`
- `framework.static`
- `tool`
- `tv-app-extension`
- `watchkit-extension`
- `watchkit2-extension`
- `xcode-extension`
- `driver-extension`
- `system-extension`
- `xpc-service`
- ``""`` (used for legacy targets)
```
- The command-line tool type string is **`tool`**. The system extension type string is **`system-extension`**, and the DriverKit type string is `driver-extension`.
- XcodeProj's enum confirms these strings. The XcodeGen type is the raw value with `com.apple.product-type.` stripped: XcodeGen's `XCProjExtensions.swift` has `rawValue.replacingOccurrences(of: "com.apple.product-type.", with: "")`. URL: https://raw.githubusercontent.com/tuist/XcodeProj/main/Sources/XcodeProj/Objects/Targets/PBXProductType.swift (file commit `76f5ae3d31c3`, 2026-08-20; latest XcodeProj release 9.17.5)
```swift
    case commandLineTool = "com.apple.product-type.tool"
    case driverExtension = "com.apple.product-type.driver-extension"
    case systemExtension = "com.apple.product-type.system-extension"
...
        case .systemExtension:
            "systemextension"
        case .driverExtension:
            "dext"
```
- XcodeGen's own test fixture uses an Endpoint Security system extension. URL: https://raw.githubusercontent.com/yonaskolb/XcodeGen/master/Tests/Fixtures/TestProject/project.yml
```yaml
  EndpointSecuritySystemExtension:
    platform: macOS
    type: system-extension
    sources:
      - EndpointSecurity Extension
    settings:
      PRODUCT_BUNDLE_IDENTIFIER: com.project.App-macOS.EndpointSecurity
      CODE_SIGN_ENTITLEMENTS: EndpointSecurity Extension/EndpointSecurity.entitlements
    scheme: {}
    dependencies:
      - sdk: libEndpointSecurity.tbd
```
  In the same fixture, the app target `App_macOS` (`type: application`) simply lists `- target: EndpointSecuritySystemExtension` under `dependencies:`.
- The fixture's entitlements file contains `com.apple.developer.endpoint-security.client` = `<true/>`. Its Info.plist contains `NSSystemExtensionUsageDescription` and `CFBundlePackageType` = `$(PRODUCT_BUNDLE_PACKAGE_TYPE)`. (Files: `src-partC/xcodegen-Tests_Fixtures_TestProject_EndpointSecurity_Extension_*`)

### Embedding a system extension: automatic "Embed System Extensions" phase
The doc's list of `copy` → `destination` values does **not** include `systemExtensions`. URL: ProjectSpec.md, "Dependency" section:
```
- **copy** - Copy Files Phase for this dependency. This only applies when `embed` is true. Must be specified as an object with the following fields:
    - [x] **destination**: **String** - Destination of the Copy Files phase. This can be one of the following values:
        - `absolutePath`
        - `productsDirectory`
        - `wrapper`
        - `executables`
        - `resources`
        - `javaResources`
        - `frameworks`
        - `sharedFrameworks`
        - `sharedSupport`
        - `plugins`
    - [ ] **subpath**: **String** - The path inside of the destination to copy the files.
```
The source enum matches that list exactly. URL: https://raw.githubusercontent.com/yonaskolb/XcodeGen/master/Sources/ProjectSpec/BuildPhaseSpec.swift
```swift
        public enum Destination: String {
            case absolutePath
            case productsDirectory
            case wrapper
            case executables
            case resources
            case javaResources
            case frameworks
            case sharedFrameworks
            case sharedSupport
            case plugins
```
You don't need a `copy` block, though. A `target:` dependency on a `system-extension` (or `driver-extension`) target is put into an auto-generated "Embed System Extensions" phase. URL: https://raw.githubusercontent.com/yonaskolb/XcodeGen/master/Sources/XcodeGenKit/PBXProjGenerator.swift
```swift
                if let copyPhase = dependency.copyPhase {
                    // custom copy takes precedence
                    ...
                } else if dependencyTarget.type.isSystemExtension {
                    // embed system extension
                    systemExtensions.append(embedFile)
...
        if !systemExtensions.isEmpty {
            let copyFilesPhase = addObject(
                // With parameters below the Xcode will show "Destination: System Extensions".
                getPBXCopyFilesBuildPhase(dstSubfolderSpec: .productsDirectory, dstPath: "$(SYSTEM_EXTENSIONS_FOLDER_PATH)", name: "Embed System Extensions", files: systemExtensions)
            )
```
`isSystemExtension` is defined in `Sources/ProjectSpec/XCProjExtensions.swift`:
```swift
    public var isSystemExtension: Bool {
        fileExtension == "dext" || fileExtension == "systemextension"
    }
```
Embed defaults to true when the depending target is an app:
```swift
        if isApp {
            // If target is an app, all dependencies should be embed (unless they're static)
            return true
```
The fixture's generated pbxproj shows the resulting phase. URL: https://raw.githubusercontent.com/yonaskolb/XcodeGen/master/Tests/Fixtures/TestProject/Project.xcodeproj/project.pbxproj
```
		DE875E9A37F7CB9C347AEFA0 /* Embed System Extensions */ = {
			isa = PBXCopyFilesBuildPhase;
			buildActionMask = 2147483647;
			dstPath = "$(SYSTEM_EXTENSIONS_FOLDER_PATH)";
			dstSubfolderSpec = 16;
			files = (
				5126CD91C2CB41C9B14B6232 /* DriverKitDriver.dext in Embed System Extensions */,
				F4D77E81B0539EA5F4F141A6 /* EndpointSecuritySystemExtension.systemextension in Embed System Extensions */,
```
`SYSTEM_EXTENSIONS_FOLDER_PATH` is an Xcode build setting. That it resolves to `Contents/Library/SystemExtensions` is UNVERIFIED from Xcode docs, but Apple requires that location (see §9).

### Dependency linking options (verbatim)
```
- [ ] **embed**: **Bool** - Whether to embed the dependency. Defaults to true for application target and false for non application targets.
- [ ] **link**: **Bool** - Whether to link the dependency. Defaults to `true` depending on the type of the dependency and the type of the target (e.g. static libraries will only link to executables by default).
- [ ] **codeSign**: **Bool** - Whether the `codeSignOnCopy` setting is applied when embedding framework. Defaults to true.
```
**The doc and the code disagree on the `codeSign` default.** The code is `codeSign: dependency.codeSign ?? !dependencyTarget.type.isExecutable` (PBXProjGenerator.swift). `isExecutable` includes `isSystemExtension`, so an embedded system extension gets **no** `CodeSignOnCopy` by default. The fixture's pbxproj shows `settings = {ATTRIBUTES = (RemoveHeadersOnCopy, ); }` on `EndpointSecuritySystemExtension.systemextension in Embed System Extensions`.

### Local Swift packages and `package:` / `product:` dependencies (verbatim)
```
### Local Package

- [x] **path**: **String** - the path to the package in local. The path must be directory with a `Package.swift`.
- [ ] **group** : **String**- Optional path that specifies the location where the package will live in your xcode project. Use `""` to specify the project root.
- [ ] **excludeFromProject** : **String**- Optional flag to exclude the package from the generated project (useful if the package is already added via xcworkspace and the project is not intended for standalone use), defaults to `false`
```
```
- `package: name` - links to a Swift Package. The name must match the name of a package defined in the top level `packages`
...
**Package dependency**
- [ ] **product**: **String** - The product to use from the package. This defaults to the package name, so is only required if a Package has multiple libraries or a library with a differing name. Use this over `products` when you want to define different linking options per product.
- [ ] **products**: **String** - A list of products to use from the package. This can be used when depending on multiple products from a package.
```
```yaml
packages:
  FooFeature:
    path: Packages/FooFeature
targets:
  App:
    dependencies:
      - package: FooFeature
        products:
          - FooDomain
          - FooUI
```
```yaml
      - package: SwiftPM
        product: SPMUtility
```

### `entitlements` and `info` (both are of type Plist)
```
- [ ] **info**: **[Plist](#plist)** - If defined, this will generate and write an `Info.plist` to the specified path and use it by setting the `INFOPLIST_FILE` build setting for every configuration, unless `INFOPLIST_FILE` is already defined in  **settings** for this configuration. The following properties are generated automatically if appropriate, the rest will have to be provided.
  - `CFBundleIdentifier`
  - `CFBundleInfoDictionaryVersion`
  - `CFBundleExecutable` **Not generated for targets of type bundle**
  - `CFBundleName`
  - `CFBundleDevelopmentRegion`
  - `CFBundleShortVersionString`
  - `CFBundleVersion`
  - `CFBundlePackageType`
- [ ] **entitlements**: **[Plist](#plist)** - If defined this will generate and write a `.entitlements` file, and use it by setting `CODE_SIGN_ENTITLEMENTS` build setting for every configuration. All properties must be provided
```
```
### Plist
Plists are created on disk on every generation of the project. They can be used as a way to define `Info.plist` or `.entitlement` files. Some `Info.plist` properties are generated automatically.

- [x] **path**: **String** - This is the path where the plist will be written to
- [x] **properties**: **[String: Any]** - This is a map of all the plist keys and values
```
```yml
targets:
  App:
    info:
      path: App/Info.plist
      properties:
        UISupportedInterfaceOrientations: [UIInterfaceOrientationPortrait]
        UILaunchStoryboardName: LaunchScreen
    entitlements:
      path: App/App.entitlements
      properties:
        com.apple.security.application-groups: group.com.app
```
**Gotcha:** XcodeGen does not auto-generate `CFBundlePackageType` for `system-extension` targets. `InfoPlistGenerator.swift` only sets it for unit/UI tests (`BNDL`), `application`/`watch2App` (`APPL`), `framework` (`FMWK`), `bundle` (`BNDL`), and `xpcService`/`appExtension` (`XPC!`); everything else hits `default: break`. Set it yourself. The fixture uses `$(PRODUCT_BUNDLE_PACKAGE_TYPE)`; the third-party spec below uses `SYSX`. URL: https://raw.githubusercontent.com/yonaskolb/XcodeGen/master/Sources/XcodeGenKit/InfoPlistGenerator.swift

XcodeGen has no `SettingPresets/Products/system-extension.yml`. The directory only contains `app-extension.intents-service.yml app-extension.messages.yml app-extension.yml bundle.ui-testing.yml bundle.unit-test.yml framework.static.yml framework.yml library.static.yml tv-app-extension.yml watchkit2-extension.yml`.

### `settings` (verbatim)
```
- [ ] **groups**: **[String]** - List of [Setting Groups](#setting-groups) to include and merge
- [ ] **configs**: **[String:[Settings](#settings)]** - Mapping of config name to a settings spec. These settings will only be applied for that config. Each key will be matched to any configs that contain the key and is case insensitive. ...
- [ ] **base**: **[String:String]** - Used to specify default settings that apply to any config
```
> Don't mix simple maps with `groups`, `base` and `configs`.
> If `groups`, `base`, `configs` are used then simple maps is silently ignored.
> Settings are merged in the following order: `groups`, `base`, `configs` (simple maps are ignored).

### Build scripts (verbatim)
```
- [ ] **preBuildScripts**: **[[Build Script](#build-script)]** - Build scripts that run *before* any other build phases
- [ ] **postCompileScripts**: **[[Build Script](#build-script)]** - Build scripts that run after the Compile Sources phase
- [ ] **postBuildScripts**: **[[Build Script](#build-script)]** - Build scripts that run *after* any other build phases
```
Each script can contain `path` or `script` (one is required), `name` (default `Run Script`), `inputFiles`, `outputFiles`, `inputFileLists`, `outputFileLists`, `shell` (default `/bin/sh`), `showEnvVars` (default `true`), `runOnlyWhenInstalling` (default `false`), `basedOnDependencyAnalysis` (default `true`), and `discoveredDependencyFile`.
> Either a **path** or **script** must be defined, the rest are optional.

### Schemes
Target `scheme` (verbatim excerpt):
> This is a convenience used to automatically generate schemes for a target based on different configs or included tests. If you want more control check out the top level [Scheme](#scheme).
```
- [x] **configVariants**: **[String]** - This generates a scheme for each entry, using configs that contain the name with debug and release variants. ...
- [ ] **testTargets**: ...
- [ ] **gatherCoverageData**: **Bool** ...
- [ ] **buildArchitectures**: **String** - ... Supported values are `matchRunDestination`, `universal`, and `useTargetSettings`. By default this is `matchRunDestination` if not set.
- [ ] **commandLineArguments**: **[String:Bool]** ...
- [ ] **environmentVariables**: ...
- [ ] **preActions** / **postActions** ...
```
(In practice `configVariants` is not required: the fixture and the real-world spec both use `scheme: {}`.)

Top-level `schemes` (verbatim):
```
- [x] ***build***: Build options
- [ ] ***run***: The run action
- [ ] ***test***: The test action
- [ ] ***profile***: The profile action
- [ ] ***analyze***: The analyze action
- [ ] ***archive***: The archive action
- [ ] ***management***: management metadata
```
```
- [x] **targets**: **[String:String]** or **[String:[String]]** - A map of target names to build and which build types they should be enabled for. The build types can be `all`, `none`, or an array of the following types:
	- `run` or `running`
	- `test` or `testing`
	- `profile` or `profiling`
	- `analyze` or `analyzing`
	- `archive` or `archiving`
```
Common action option: `config` — "If a config, or the build action itself, is not defined the first configuration found of a certain type will be used ... `debug`: run, test, analyze ... `release`: profile, archive".

### Options (verbatim)
```
- [ ] **bundleIdPrefix**: **String** - If this is specified then any target that doesn't have an `PRODUCT_BUNDLE_IDENTIFIER` (via all levels of build settings) will get an autogenerated one by combining `bundleIdPrefix` and the target name: `bundleIdPrefix.name`. The target name will be stripped of all characters that aren't alphanumerics, hyphens, or periods. Underscores will be replaced with hyphens.
- [ ] **deploymentTarget**: **[[Platform](#platform): String]** - A project wide deployment target can be specified for each platform otherwise the default SDK version in Xcode will be used. This will be overridden by any custom build settings that set the deployment target eg `IPHONEOS_DEPLOYMENT_TARGET`. Target specific deployment targets can also be set with [Target](#target).deploymentTarget.
- [ ] **minimumXcodeGenVersion**: **String** - The minimum version of XcodeGen required.
- [ ] **projectFormat**: **String** - The version of Xcode project. By default this is set to `xcode16_0`
```
```yaml
options:
  deploymentTarget:
    watchOS: "2.0"
    tvOS: "10.0"
```
CLI usage (README.md): `xcodegen generate`; "**--spec**: An optional path to a `.yml` or `.json` project spec. Defaults to `project.yml`."

### Real-world reference: third-party XcodeGen spec with an ES system extension (not authoritative)
GenseeAI/gensee-crate `macos/GenseeCrate/project.yml`, commit `2471d6df4d15` (2026-09-07). URL: https://github.com/GenseeAI/gensee-crate/blob/2471d6df4d150f14beedf7807bab6a6fd129884d/macos/GenseeCrate/project.yml (saved: `web/gh-GenseeAI_gensee-crate-project.yml`)
```yaml
    entitlements:
      path: Host/GenseeCrate.entitlements
      properties:
        com.apple.developer.system-extension.install: true
...
    dependencies:
      - target: GenseeCrateEndpointSecurity
      - sdk: SystemExtensions.framework
...
  GenseeCrateEndpointSecurity:
    type: system-extension
    platform: macOS
    info:
      path: EndpointSecurityExtension/Info.plist
      properties:
        CFBundlePackageType: SYSX
        NSEndpointSecurityMachServiceName: "$(TeamIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER).xpc"
        NSSystemExtensionUsageDescription: Gensee Crate monitors process and file activity to protect AI agent sessions.
    entitlements:
      path: EndpointSecurityExtension/GenseeCrateEndpointSecurity.entitlements
      properties:
        com.apple.developer.endpoint-security.client: true
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: ai.gensee.crate.endpoint-security
        PRODUCT_NAME: "$(PRODUCT_BUNDLE_IDENTIFIER)"
        SKIP_INSTALL: YES
    dependencies:
      - sdk: libEndpointSecurity.tbd
      - sdk: libbsm.tbd
```
(`PRODUCT_NAME: "$(PRODUCT_BUNDLE_IDENTIFIER)"` satisfies Apple's rule that the extension's filename must match its bundle identifier; see §9.)

---

## 9. Apple SystemExtensions / Endpoint Security

All Apple pages come from `https://developer.apple.com/tutorials/data/documentation/<path>.json`. Literal `(`, `)` and `:` in the path worked; no encoding was needed. Swift declarations below are copied from each page's `primaryContentSections.declarations.tokens`. Availability comes from `metadata.platforms[].introducedAt`.

### OSSystemExtensionRequest — macOS 10.15
URL: .../systemextensions/ossystemextensionrequest.json — `class OSSystemExtensionRequest`, abstract: "A request to activate or deactivate a system extension."

- `activationRequest(forExtensionWithIdentifier:queue:)`, macOS 10.15. URL: .../systemextensions/ossystemextensionrequest/activationrequest(forextensionwithidentifier:queue:).json
  ```swift
  class func activationRequest(forExtensionWithIdentifier identifier: String, queue: dispatch_queue_t) -> Self
  ```
  Parameters: "identifier: The bundle identifier of the target extension." "queue: The dispatch queue to use when calling delegate methods."
  > Create and submit an activation request whenever you want to use a given extension. If the extension is inactive, the system may need to prompt the user for approval. The request succeeds only after the user gives their approval.
  > If the extension is already active, the request succeeds in short order, without significant delay or user interaction. If you request activation of a new version of an already-active extension, the system prompts the user to resolve the conflict before proceeding.
  > An activation request may succeed, but also indicate that the extension requires a restart to become active. ...
- `deactivationRequest(forExtensionWithIdentifier:queue:)`, macOS 10.15. URL: .../ossystemextensionrequest/deactivationrequest(forextensionwithidentifier:queue:).json
  ```swift
  class func deactivationRequest(forExtensionWithIdentifier identifier: String, queue: dispatch_queue_t) -> Self
  ```
  > The system discovers existing system extensions in the `Contents/Library/SystemExtensions` directory of the main app bundle.
  > A deactivation request may require a restart before deactivating the extension. If the request succeeds but requires a restart to complete, the extension may still appear operational until the next restart.
- `propertiesRequest(forExtensionWithIdentifier:queue:)`, **macOS 12.0**: `class func propertiesRequest(forExtensionWithIdentifier identifier: String, queue: dispatch_queue_t) -> Self`
- `var delegate: (any OSSystemExtensionRequestDelegate)?` and `var identifier: String`
- `OSSystemExtensionRequest.Result`: `case completed` ("The request completed successfully.") and `case willCompleteAfterReboot` ("The request requires a restart to complete successfully.")
- `OSSystemExtensionRequest.ReplacementAction`: `case cancel` and `case replace`

### OSSystemExtensionManager — macOS 10.15
URL: .../systemextensions/ossystemextensionmanager.json
```swift
class var shared: OSSystemExtensionManager { get }
func submitRequest(_ request: OSSystemExtensionRequest)
```
> Create an instance of OSSystemExtensionRequest with the class methods on that type, and submit it to the shared instance of the extension manager with submitRequest(_:). Set the delegate on the request to receive the result of the activation or deactivation. The delegate also receives notifications if the user needs to authorize the extension or if a version conflict occurs.

### OSSystemExtensionRequestDelegate — macOS 10.15; `protocol OSSystemExtensionRequestDelegate : NSObjectProtocol`
URL: .../systemextensions/ossystemextensionrequestdelegate.json and each method page:
```swift
func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction   // macOS 10.15
func requestNeedsUserApproval(_ request: OSSystemExtensionRequest)                                                       // macOS 10.15
func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result)            // macOS 10.15
func request(_ request: OSSystemExtensionRequest, didFailWithError error: any Error)                                      // macOS 10.15
optional func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties])     // macOS 12.0
```
Which methods are required vs. optional is confirmed by the SDK header (MacOSX26.5.sdk `SystemExtensions.framework/Versions/A/Headers/SystemExtensions.h`, via the GitHub mirror `alexey-lysiuk/macos-sdk` at commit `896cd40df984`, file `src-partC/sdk26.5-SystemExtensions.h`). The protocol begins with `@required`, which covers the four 10.15 methods. `@optional` comes before `request:foundProperties:` only.

Discussion quotes:
- actionForReplacingExtension:
  > The manager calls this method when it encounters an existing extension with the same team and bundle identifiers, but with different version identifiers. It uses the CFBundleVersion and CFBundleShortVersionString identifiers to determine if the existing and new versions differ. ... If you return OSSystemExtensionRequest.ReplacementAction.cancel, the manager aborts the installation and calls request(_:didFailWithError:), with the OSSystemExtensionError.Code.requestCanceled error code.
  > If the local system has System Extension developer mode enabled, the manager always calls this method when it finds an existing installation, even if the version identifiers match.
- requestNeedsUserApproval:
  > Activating an extension may require explicit user approval to proceed. ... Activation remains pending until the user grants or denies permission, or until the app quits.
- didFinishWithResult:
  > If the request completes with the OSSystemExtensionRequest.Result.willCompleteAfterReboot result, then the extension isn't active until after the next restart. After restarting, the most recently-processed request determines the extension's state.

### "Installing System Extensions and Drivers" article
URL: .../systemextensions/installing-system-extensions-and-drivers.json
> System extensions reside inside your app's `Contents/Library/SystemExtensions` folder.

> During the activation process, the system verifies:
> - Your extension is installed in the `Contents/Library/SystemExtensions` folder of your app.
> - Your app is installed in an appropriate `Applications` directory of the system.
> - The code signature of your extension.
> - The entitlements in the code signature match the entitlements granted to your development team.
> - The identifer in your activation request matches the one in your system extension bundle.
> - The identifier isn't already in use by another system extension.

> The system automatically uninstalls any system extensions when the user deletes the corresponding app. You can also uninstall a system extension by creating a deactivation request.

> To see the system extensions installed on your system, run the `systemextensionsctl` command-line tool with the `list` option from Terminal.
> `% systemextensionsctl list`

The article's sample code:
```swift
let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: driverID,
                     queue: DispatchQueue.main)
request.delegate = self
let extensionManager = OSSystemExtensionManager.shared
extensionManager.submitRequest(request)
```

### SystemExtensions framework landing page: naming, Team ID, and notarization rules
URL: .../systemextensions.json
> To successfully activate your extension, you must adhere to the following rules:
> - The extension must match your bundle identifier, excluding file extension. For example, ... a NetworkExtension extension with bundle identifier `com.example.networkextension` must use the filename `com.example.networkextension.systemextension`.
> - You must use the same Team ID when signing the extension that you use for signing your app, unless the extension has the `com.apple.developer.system-extension.redistributable` entitlement.
> - You must either distribute your app and extension through the Mac App Store, or notarize them.

### Requirement that the app be in /Applications
Apple states this in three places:
- The Installing article: "Your app is installed in an appropriate `Applications` directory of the system." (quoted above)
- `OSSystemExtensionError.Code.unsupportedParentBundleLocation` (raw value 3). URL: .../systemextensions/ossystemextensionerror/code/unsupportedparentbundlelocation.json
  > An error code that indicates the extension's parent app isn't in a valid location for activation.
  > The expected location of a driver extension is in the `Contents/Library/SystemExtensions` directory of a macOS app. The app itself must be in one of the system's `Applications` directories.
- "Debugging and testing system extensions". URL: .../driverkit/debugging-and-testing-system-extensions.json
  > You must place all system extensions in the `Contents/Library/SystemExtensions` directory of your app bundle, and the app itself must be installed in one of the system's `Applications` directories. To allow development of your app outside of these directories, use the `systemextensionsctl` command-line tool to enable developer mode. When in developer mode, the system doesn't check the location of your system extension prior to loading it, so you can load it from anywhere in the file system. To enable developer mode, open a Terminal window and execute the following command:
  > `% systemextensionsctl developer on`
  > To turn developer mode off, open Terminal and run the same tool with `developer off` as the parameter.

  > ### Disable code-signing and notarization checks
  > System Integrity Protection (SIP) in macOS prevents unauthorized code from running on your system. Xcode doesn't notarize apps or system extensions during the normal development cycle, so disabling SIP bypasses the notarization checks that the system normally performs, and allows you to debug your code more quickly.

### OSSystemExtensionError.Code — all cases are macOS 10.15 (iOS/iPadOS/Mac Catalyst 18.4)
URL: .../systemextensions/ossystemextensionerror/code.json. Integer values come from the SDK header (sdk26.5 `SystemExtensions.h` lines 49-61).
| Swift case | ObjC constant = value | Apple abstract |
|---|---|---|
| unknown | OSSystemExtensionErrorUnknown = 1 | An error code that indicates an unknown error occurred. |
| missingEntitlement | ...MissingEntitlement = 2 | ...the system extension lacks a required entitlement. (Discussion: "The app must have the System Extension Entitlement to activate or deactivate system extensions.") |
| unsupportedParentBundleLocation | ...UnsupportedParentBundleLocation = 3 | ...the extension's parent app isn't in a valid location for activation. |
| extensionNotFound | ...ExtensionNotFound = 4 | ...the manager can't find the system extension. |
| extensionMissingIdentifier | ...ExtensionMissingIdentifier = 5 | ...the extension identifier is missing. |
| duplicateExtensionIdentifer (sic) | ...DuplicateExtensionIdentifer = 6 | ...the extension identifier duplicates an existing identifier. |
| unknownExtensionCategory | ...UnknownExtensionCategory = 7 | ...can't recognize the extension's category identifier. |
| codeSignatureInvalid | ...CodeSignatureInvalid = 8 | ...the extension's signature is invalid. |
| validationFailed | ...ValidationFailed = 9 | ...the manager can't validate the extension. |
| forbiddenBySystemPolicy | ...ForbiddenBySystemPolicy = 10 | ...the system policy prohibits activating the system extension. |
| requestCanceled | ...RequestCanceled = 11 | ...the system extension manager request was canceled. |
| requestSuperseded | ...RequestSuperseded = 12 | ...failed because the system already has a pending request for the same identifier. |
| authorizationRequired | ...AuthorizationRequired = 13 | ...the system was unable to obtain the proper authorization. |

### Entitlements
- **`com.apple.developer.system-extension.install`** — "System Extension Entitlement", macOS 10.15. `details.value` = `{"baseType": "boolean"}`. URL: .../bundleresources/entitlements/com.apple.developer.system-extension.install.json
  > A Boolean value that indicates whether your app has permission to activate or deactivate system extensions.
  > To add this entitlement to your app, enable the System Extension capability in Xcode. Add this entitlement for all system extension types, including DriverKit extensions.

  The value is a Boolean `true`. Apple does not document a string value such as "systemextension-install".
- **`com.apple.developer.endpoint-security.client`** — macOS 10.15, boolean. URL: .../bundleresources/entitlements/com.apple.developer.endpoint-security.client.json
  > The entitlement required to monitor system events for potentially malicious activity.
  > You must request this entitlement from Apple. For information about how to request the entitlement, see System Extensions and DriverKit.
  > If your app or extension lacks this requirement, es_new_client(_:_:) fails with the result ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED.
- **`com.apple.developer.system-extension.redistributable`** — boolean:
  > This extension allows a distributing app to have a different team ID than the one associated with the system extension. If this entitlement isn't present, the team ID of the app and system extension must match.
- `es_new_client(_:_:)`, macOS 10.15. URL: .../endpointsecurity/es_new_client(_:_:).json
  ```swift
  func es_new_client(_ client: UnsafeMutablePointer<OpaquePointer?>, _ handler: @escaping es_handler_block_t) -> es_new_client_result_t
  ```
  > To create a client, your app must have the `com.apple.developer.endpoint-security.client` entitlement. The user also needs to approve your app with Transparency, Consent, and Control (TCC) mechanisms. The user does this in the Security and Privacy pane of System Preferences, by adding the app to Full Disk Access.

  Result codes:
  - `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`: "The caller isn't properly entitled to connect to Endpoint Security."
  - `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`: "The caller isn't permitted to connect to Endpoint Security." / "This error indicates the app lacks Transparency, Consent, and Control (TCC) approval from the user."
  - `ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED`: "The caller isn't running as root."

### Info.plist keys
- **NSSystemExtensionUsageDescriptionKey**. URL: .../systemextensions/nssystemextensionusagedescriptionkey.json
  > A message that tells the user why the app is trying to install a system extension bundle.
  > This key is required for all system extensions except DriverKit extensions, and must be in the extension's `Info.plist` file. Failure to include this key results in an error at activation time.

  The literal plist key string `NSSystemExtensionUsageDescription` comes from XcodeGen's fixture and the third-party spec. Apple's page only names the constant.
- **NSEndpointSecurityMachServiceName**. Apple's DocC has **no** page for it: `.../bundleresources/information-property-list/nsendpointsecuritymachservicename.json` returns 404, and it isn't listed in `endpointsecurity.json` or `information-property-list.json`. Apple documents it in the **EndpointSecurity(7) man page** shipped in the SDK (`MacOSX26.5.sdk/usr/share/man/man7/EndpointSecurity.7`, via the mirror; file `src-partC/man/sdk26.5-EndpointSecurity.7`):
  ```
  If the ES client is a system extension, the following optional keys can be set in the bundle's Info.plist:
  ...
  .It Ar NSEndpointSecurityMachServiceName
  Type: String
  .Pp
  If set, this string will be the name of the MachService which can be used for XPC between the ES extension and its app.
  If not set, a default mach service (name: <teamID>.<bundleID>.xpc) will be provided but its usage is deprecated.
  ```
  The same man page also documents `NSEndpointSecurityEarlyBoot` (Boolean) and `NSEndpointSecurityRebootRequired` (Boolean).

  Apple DTS on the forums (WebFetch), https://developer.apple.com/forums/thread/713744 (Sep 2022):
  > Specifically to do this in your ES sysex: 1. Edit its `Info.plist` to list the name in the `NSEndpointSecurityMachServiceName` property. 2. On start, set up a listener for that name using `NSXPCListener`.

  > I recommend that you do the following: * Add your Team ID as a prefix. * Add a suffix to distinguish this from your sysex, so something like `.xpc-qqq`.

  > On the sysex side, call `-[NSXPCListener initWithMachServiceName:]` ... Then, still on the client side call `-[NSXPCConnection initWithMachServiceName:options:]`, passing in the endpoint name and `NSXPCConnectionPrivileged`.

### systemextensionsctl
Man page systemextensionsctl(8), page dated "October 30, 2023". Source: https://keith.github.io/xcode-man-pages/systemextensionsctl.8.html (mirror HEAD `46d6bd5d`, "Xcode 27.2 beta 2 (27B5028f)"). Verbatim:
```
SYNOPSIS
    systemextensionsctl developer [on | off]
    systemextensionsctl list
    systemextensionsctl reset
...
Users should not run systemextensionsctl under most circumstances; this utility is intended for software developers.
  developer [on | off]
  Turn developer mode on and off. When the computer examines a new system extension, it performs a version check to see if it is the same as a system extension that is already installed. When developer mode is on, this version check is skipped.
  list
  List the system extensions and their state. States include:
      activated enabled            Available for use
      activated waiting for user   Waiting for user approval via System Settings
      activated disabled           Available but currently disabled by the user, can be enabled using System Settings
      terminated waiting for uninstall on reboot   Will be removed at the next computer restart
  reset
  Forcibly reset system extensions. This removes all system extensions and clears related state.
```
- **`uninstall` is not in the man page.** It does appear in the tool's own usage output. Third-party captures:
  - https://derflounder.wordpress.com/2020/09/01/uninstalling-macos-system-extensions/ :
    ```
    systemextensionsctl: usage:
    	systemextensionsctl developer [on|off]
    	systemextensionsctl list [category]
    	systemextensionsctl reset  - reset all System Extensions state
    	systemextensionsctl uninstall  ; can also accept '-' for teamID
    ```
  - A newer capture (2025) that also shows `gc`: https://gist.github.com/joshuataylor/bcbb9d8b80c83d3f188195a61ef60e4e
    ```
    systemextensionsctl uninstall <teamID> <bundleID>; teamID can also be '-' (for matching empty Team ID)
    systemextensionsctl gc  - garbage collect orphaned system extension(s)
    ```
- **`uninstall` requires SIP to be disabled.** Several captures of the tool's message agree:
  - graham pugh, 2021: https://grahamrpugh.com/2021/04/06/delete-system-extension-command-line.html
  - verityj, 2023: https://verityj.github.io/2023/06/12/extensions.html
  - Apple DTS, Jan 2025 (WebFetch): https://developer.apple.com/forums/thread/773002
  - GitHub issue on macOS 26, 2026-09-17: https://github.com/daseinlabs/parsec/issues/34

  The message is:
  ```
  At this time, this tool cannot be used if System Integrity Protection is enabled.
  This limitation will be removed in the near future.
  Please remember to re-enable System Integrity Protection!
  ```
  derflounder adds: "Note: As of September 1, 2020, running the systemextensionsctl uninstall command requires System Integrity Protection (SIP) to be disabled."
- **Whether `developer on` requires SIP disabled:** neither Apple's docs nor the man page say so. Third-party sources disagree:
  - Saying SIP is required:
    - dognotdog/ptpwebcam README: "`systemextensionsctl developer on` but for that to work we need to disable SIP as of MacOS 13"
    - obscuravpn-client README lists "Disable system integrity protection" before `systemextensionsctl developer on`
  - Not mentioning SIP: denoland/clawpatrol README uses `sudo systemextensionsctl developer on    # one-time, allows Apple Dev sysexts`
- Apple's System Extensions page (https://developer.apple.com/system-extensions/):
  > If you plan to deploy drivers built with DriverKit, allow other developers to use your system extensions, or use the EndpointSecurity API, you'll need to request an entitlement from Apple.
  > While your request is in review, you can test system extensions on your Mac by temporarily turning off System Integrity Protection.

---

## 10. Notarization (notarytool, stapler) and Developer ID

### "Customizing the notarization workflow"
URL: https://developer.apple.com/tutorials/data/documentation/security/customizing-the-notarization-workflow.json (verbatim code blocks). **Apple's listings have no trailing `\`.** In a shell, either put everything on one line or add backslashes.
```sh
% xcrun notarytool submit OvernightTextEditor_11.6.8.zip
                   --keychain-profile "notarytool-password"
                   --wait
                   --webhook "https://example.com/notarization"
```
```sh
% xcrun notarytool store-credentials "notarytool-password"
               --apple-id "<AppleID>"
               --team-id <DeveloperTeamID>
               --password <secret_2FA_password>
```
```sh
% xcrun notarytool log 2efe2717-52ef-43a5-96dc-0797e4ca1041 --keychain-profile "notarytool-password" developer_log.json
```
```sh
% xcrun stapler staple "Overnight TextEditor.app"
```
```sh
/usr/bin/ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"
```
Apple's text:
> Because you can't upload the `.app` bundle directly to the notary service, you'll need to create a compressed archive containing the app

> The notary service accepts disk images (UDIF format), signed flat installer packages, and ZIP archives.

> Use the `wait` flag to tell `notarytool` to exit only after the Notary service finishes processing the submission.

> You can add the `apple-id` and `password` options to supply your App Store Connect credentials. Because App Store Connect requires two-factor authentication (2FA) on all accounts, you must create an app-specific password for `notarytool`

> While you can notarize a ZIP archive, you can't staple to it directly. Instead, run `stapler` against each item that you added to the archive. Then create a new ZIP file containing the stapled items for distribution.

> The `altool` command has been deprecated, and the Apple notary service no longer supports `altool` from November 1, 2023.

### notarytool(1) man page
Source: https://keith.github.io/xcode-man-pages/notarytool.1.html (page date "April 28th, 2022"). Synopsis (verbatim tokens):
```
notarytool submit file-path { -k key-path -d key-id [-i issuer] | --apple-id apple-id [--password app-specific-password] --team-id team-id | -p profile-name [--keychain keychain-path] } [--wait --no-s3-acceleration --force]
notarytool store-credentials profile-name { -k key-path -d key-id [-i issuer] | --apple-id apple-id [--password app-specific-password] --team-id team-id } [--no-validate] [--keychain keychain-path | --sync]
```
> -p, --keychain-profile profile-name  Authenticate using credentials stored in the Keychain by notarytool. Use the profile name that you previously provided via the store-credentials command.

> [--password app-specific-password] App-specific password for your Apple ID. You will be given a secure prompt on the command line if Apple ID and Team ID are provided but the --password option is not specified.

> store-credentials ... Save authentication credentials for the Apple notary service to the default login keychain. ... --validate, --no-validate ... The default is --validate.

> --wait, --no-wait Rather than exiting after a successful upload, begin waiting for your submission to complete. The default is --no-wait.

Man page examples:
```
notarytool store-credentials MyGreatCompany-ASP --apple-id mygreataccount@example.com --team-id K36BKF7T3D
notarytool submit MyDiskImage.dmg -p MyGreatCompany --wait
notarytool log d0d37a38-dc80-4603-bca9-80705a49cbbd -p MyGreatCompany ~/Desktop/developer_log.json
```
> notarytool submit works only with UDIF disk images, signed "flat" installer packages, and zip files.

The `wait` subcommand returns once the service responds with a status of "Accepted", "Invalid", "Rejected", or if a fatal error occurs.

### stapler(1)
Source: https://keith.github.io/xcode-man-pages/stapler.1.html
```
stapler staple [-q] [-v] path
stapler validate [-q] [-v] path
```
> Stapling does not invalidate the code signature and must be run after an executable or archive has been code-signed and notarized with Developer ID. Code-signing a supported file format invalidates any stapled tickets, so stapler staple must be run again if this occurs.

> stapler works only with UDIF disk images, signed "flat" installer packages, and certain code-signed executable bundles such as ".app".

> stapler requires internet access to retrieve tickets when stapling or validating.

### Developer ID requirements
Source: "Notarizing macOS software before distribution", https://developer.apple.com/tutorials/data/documentation/security/notarizing-macos-software-before-distribution.json
> - Use a "Developer ID" application, kernel extension, system extension, or installer certificate for your code-signing signature. (Don't use a Mac Distribution, ad hoc, Apple Developer, or local development certificate.)
> - Enable the Hardened Runtime capability for your app and command line targets ...
> - Include a secure timestamp with your code-signing signature. ...
> - Don't include the `com.apple.security.get-task-allow` entitlement with the value set to any variation of `true`.

> Beginning in macOS 10.15, all software built after June 1, 2019, and distributed with Developer ID must be notarized.

Source: "Resolving common notarization issues" (…/security/resolving-common-notarization-issues.json):
> When code signing items like Mach-O files, disk images, bundles, apps, command line tools, photos, and so on, sign with a Developer ID Application certificate.

> be sure to add a secure timestamp by adding the `timestamp` option to your `OTHER_CODE_SIGN_FLAGS` build setting, or by using the option directly with the `codesign` utility if you sign manually

> add the following option to the `OTHER_CODE_SIGN_FLAGS` build setting: `--options=runtime`

```sh
% codesign -vvv --deep --strict /path/to/binary/or/bundle
% spctl -vvv --assess --type exec /path/to/application
```

### Provisioning profiles are needed for restricted entitlements under Developer ID
Source: TN3125, https://developer.apple.com/tutorials/data/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles.json
> A macOS app can claim certain entitlements without them being authorized by a provisioning profile. These *unrestricted entitlements* include: `com.apple.security.get-task-allow`, `com.apple.security.application-groups`, Those used to enable and configure the App Sandbox, Those used to configure the Hardened Runtime

> In contrast, *restricted entitlements* must be authorized by a provisioning profile.

> macOS supports provisioning profiles for both App Store and Developer ID distribution. Some entitlements are not supported by Developer ID profiles.

> macOS expects to find the profile at `MyApp.app/Contents/embedded.provisionprofile`.

> In this document the term *app* refers to a main executable packaged in a bundle structure. This encompasses apps, app extensions, App Clips, system extensions, and XPC Services.

> Developer ID profiles, which have an expiration date far in the future.

Source: "Signing a daemon with a restricted entitlement", https://developer.apple.com/tutorials/data/documentation/xcode/signing-a-daemon-with-a-restricted-entitlement.json
> the Endpoint Security API is usable from a daemon but requires that the daemon has the com.apple.developer.endpoint-security.client entitlement, and that it's authorized by a provisioning profile.
> If the API you're using supports system extensions, avoid this issue by switching from a daemon to a system extension. System extensions readily support provisioning profiles, and Xcode automatically creates and embeds the profile in that case.

The same page also says: "follow the instructions on Provisioning with managed capabilities to add the Endpoint Security additional capability to your App ID."

Source: Apple Developer Account Help, "Supported capabilities (macOS)", https://developer.apple.com/help/account/reference/supported-capabilities-macos. Table columns are ADP | Developer ID | Apple Developer:
```
System Extension   | ✓ | ✓ | (none)
Network extensions | ✓ | ✓ | (none)
Hardened runtime   | ✓ | ✓ | ✓
App groups         | ✓ | ✓ | ✓
```
Endpoint Security is **not** listed in that table. It is a managed or additional capability that needs Apple approval: "Managed capabilities require approval from Apple to use." (https://developer.apple.com/help/account/reference/provisioning-with-managed-capabilities)

Contrast with Network Extension: Developer ID uses suffixed entitlement values ("…when signed with a Developer ID profile"), such as `content-filter-provider-systemextension`, `packet-tunnel-provider-systemextension`, `app-proxy-provider-systemextension` and `dns-proxy-systemextension`. (…/bundleresources/entitlements/com.apple.developer.networking.networkextension.json) Apple's docs show no such suffix for ES or system-extension.install; both are plain booleans.

---

## 11. NSXPCConnection and NSXPCListener

URLs are under `https://developer.apple.com/tutorials/data/documentation/foundation/...` (literal parentheses and colons worked).

| API | Swift declaration (verbatim) | macOS introducedAt |
|---|---|---|
| NSXPCConnection.setCodeSigningRequirement(_:) | `func setCodeSigningRequirement(_ requirement: String)` | **13.0** (macOS only) |
| NSXPCListener.setConnectionCodeSigningRequirement(_:) | `func setConnectionCodeSigningRequirement(_ requirement: String)` | **13.0** (macOS only) |
| NSXPCConnection.init(machServiceName:options:) | `init(machServiceName name: String, options: NSXPCConnection.Options = [])` | 10.8 |
| NSXPCConnection.Options.privileged | `static var privileged: NSXPCConnection.Options { get }` | 10.8 (iOS 6.0, Mac Catalyst 13.1, tvOS 9.0, visionOS 1.0, watchOS 2.0) |
| NSXPCListener.init(machServiceName:) | `init(machServiceName name: String)` | 10.8 |

The SDK header (`sdk26.5-NSXPCConnection.h`) confirms:
```objc
- (void)setCodeSigningRequirement:(NSString *)requirement API_AVAILABLE(macos(13.0)) API_UNAVAILABLE(ios, tvos, watchos);
- (void)setConnectionCodeSigningRequirement:(NSString *)requirement API_AVAILABLE(macos(13.0)) API_UNAVAILABLE(ios, tvos, watchos);
    NSXPCConnectionPrivileged = (1 << 12UL)
```
Doc text:
- setCodeSigningRequirement:
  > Use this method to enforce a code-signing requirement on the peer process of an XPC connection. ... Calling this method with a malformed `requirement` results in a fatal error in Swift, or throws an exception in Objective-C. If new messages don't match the requirement, the connection becomes invalidated.
  > Call this method before calling resume(), since it's an XPC error to call this method more than once.

  Example: `c.setCodeSigningRequirement("entitlement [com.example.testentitlement] exists")`
- setConnectionCodeSigningRequirement (from the header comment):
  > Sets the code signing requirement for new connections. If the requirement is malformed, an exception is thrown. If new peer connections do not match the requirement, the incoming connection is automatically rejected before consulting the delegate.
  > This method will only work on `anonymousListener` or `initWithMachServiceName` listener instances. Use on other types of listeners will result in an assertion failure.
- init(machServiceName:options:):
  > If the connection is being made to a process that is running in a privileged Mach bootstrap context (for example, a daemon started by a `launchd` property list in `/Library/LaunchDaemons`), then pass the NSXPCConnection option.

  The doc's link text is truncated in the JSON. The header says "use the NSXPCConnectionPrivileged option".
- Options.privileged:
  > Use this option if connecting to a service in the privileged Mach bootstrap (for example, a daemon with a `launchd.plist` in `/Library/LaunchDaemons)`.
- NSXPCListener `delegate` is `@property (nullable, weak) id <NSXPCListenerDelegate> delegate;` (header). It is weak, so keep a strong reference to the delegate. The forum thread above shows this exact bug.

---

## 12. Full Disk Access deep link

**Primary Apple source:** the Endpoint Security SDK header `EndpointSecurity/ESClient.h`. The text is identical in MacOSX13.3, 14.5, 15.5 and 26.5 SDKs (files `src-partC/sdk{13.3,14.5,15.5,26.5}-ESClient.h`, from the GitHub mirror alexey-lysiuk/macos-sdk at commit `896cd40df984`):
```
 * @note The only supported way to check if an application is properly TCC authorized for Full Disk Access
 *       is to call es_new_client and handling ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED in a way appropriate
 *       to your application.  Most applications will want to ask the user for TCC authorization when
 *       es_new_client returns ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED.
 *       To direct the user to the Full Disk Access section in System Settings, applications can use the following URLs:
 *       `x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles` (macOS 13 and later)
 *       `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles` (until macOS 12)
 *       Applications are advised to use the new URL in macOS 13 as the old one may stop working in a future release.
```
- **Apple-recommended on macOS 13+:** `x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles`
- **Legacy, officially "until macOS 12":** `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles`. Apple warns it "may stop working in a future release".

Third-party sources:
- bvanpeski/SystemPreferences, `macos_preferencepanes-Ventura.md`, "How to open every macOS System Settings Section (macOS 13+)", "as of macOS Sonoma 14.2" (commit `f291dc30`, 2024-01-27). URL: https://github.com/bvanpeski/SystemPreferences/blob/main/macos_preferencepanes-Ventura.md
  > * **Full Disk Access:** `open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"`

  and, for the primary pane, `open x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension` vs `open x-apple.systempreferences:com.apple.preference.security` (legacy).
  > macOS Ventura and newer operating systems use a new extension framework but still support some older prefpane calls. Who knows how long those will continue to work

- derflounder, 2022-10-25, Ventura. Lists both `com.apple.preference.security` and `com.apple.settings.PrivacySecurity.extension` for "Open Privacy & Security". It has no FDA anchor. https://derflounder.wordpress.com/2022/10/25/opening-macos-venturas-system-settings-to-desired-locations-via-the-command-line/
- Code in actively maintained projects. Dates are the last commit touching the file.
  - Using the **legacy** URL:
    - objective-see/BlockBlock (2026-04-13)
    - Brandon7CC/mac-monitor ESManager.swift (2025-09-30; opened on `.notPermitted`)
    - IBM/mac-ibm-migration-tool (2026-03-16)
    - mactools-app/MacTools (2026-08-29)
    - canyonroad/agentsh (2026-04-03; it also uses `...?Privacy_EndpointSecurity` for the ES extensions pane)
    - tmc/macgo (2026-02-17, with fallback)
    - eddmann/ClaudeMeter (2026-05-19, with fallback)
  - Using the **new** URL:
    - objective-see/AuRevoir (2026-04-09). Uses `if (@available(macOS 13.0, *))` → new URL, else legacy.
    - HarfangLab/endpoint-sec Rust crate (2026-03-30). Mirrors the ESClient.h note.
    - strongdm/leash (2025-10-21)
  - Trying the new URL first, then legacy: lobehub (2026-08-01), xopcai (2026-05-25), viticci/remctl (2026-09-04)
  - sweetrb/apple-notes-mcp TECHNICAL_NOTES.md (2026-10-03):
    > Apple documents the Full Disk Access URL in `EndpointSecurity/ESClient.h` ... (checked on macOS 27.2, 2026-09-24)

    This is about related anchors, not FDA specifically.

---

## UNVERIFIED (could not confirm from a fetched primary source)
1. Whether `systemextensionsctl developer on` itself requires SIP to be disabled (on any macOS version). Apple docs and the man page don't say so. Third-party READMEs conflict.
2. That `systemextensionsctl uninstall` still requires SIP disabled on the *latest* macOS. Third-party evidence goes up to macOS 26 (GitHub issue, 2026-09-17), but there is no Apple documentation. The man page doesn't document `uninstall` (or `gc`) at all.
3. That the legacy URL `com.apple.preference.security?Privacy_AllFiles` still works on macOS 14, 15, 26 or 27. Apple only says "until macOS 12" and warns it may stop working. Third-party code still uses it and I found no report of breakage, but nothing confirms it directly. The new `com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles` is Apple-documented for "macOS 13 and later" in SDK headers up to 26.5. Actual behaviour on 15, 26 and 27 was not tested.
4. The exact value of the Xcode build setting `SYSTEM_EXTENSIONS_FOLDER_PATH` (presumably `$(CONTENTS_FOLDER_PATH)/Library/SystemExtensions`). Not found in a fetched Apple doc.
5. `CFBundlePackageType` = `SYSX` for system extensions. Seen only in a third-party spec, not in an Apple doc.
6. The raw string value of the `NSSystemExtensionUsageDescriptionKey` constant (`NSSystemExtensionUsageDescription`). Seen only in XcodeGen's fixture and the third-party spec.
7. Forum quotes (threads 713744 and 773002) are WebFetch model extractions, not byte-exact. curl was blocked by Apple's human-verification redirect.
8. Whether Developer ID provisioning profiles actually support the Endpoint Security managed capability. TN3125 says "Some entitlements are not supported by Developer ID profiles". The macOS capability table lists System Extension as Developer ID-supported but doesn't list Endpoint Security. Real-world Developer ID-distributed ES products imply it works (e.g. objective-see TaskExplorer README: "The extension's Endpoint Security entitlement requires a provisioning profile"), but no Apple page states it.

---

# Consolidated UNVERIFIED list (Parts A and B; Part C's own list is directly above)

1. **`eslogger --select`.** No Apple documentation exists. Its existence and semantics come only from 2026 third-party sources (program-path prefix, matched against the instigating process's executable). Unconfirmed: prefix vs literal matching, whether it can be repeated, and which macOS versions support it.
2. **Exact stderr/stdout text eslogger prints on errors** (missing root or missing FDA), and its exit codes, including the exit status after SIGINT or SIGTERM.
3. **eslogger stdout buffering behaviour.** The binary uses NSFileHandle, which suggests per-write output, but this is an inference only.
4. **Whether eslogger prints anything before the first JSON line in interactive or terminal use.** Only a launchd run on macOS 26 is evidenced, and it printed no preamble.
5. **The exact macOS build behind the open-xp-rules fixtures.** Message version 7 means 13.3 or later, by inference.
6. **The exact mapping of ES message `version` to macOS release.** Only "SDK 13.3/14.5 document up to 7, 15.5 up to 8, 26.5 up to 10", plus observed version 10 on macOS 26.
7. **A genuine exchangedata JSON sample.** The only public one is hand-edited.
8. **Whether `schema_version` was ever anything other than 1.** No counter-example was found.
9. **The `--se` option.** It appeared in Xcode 27.2 beta 1 man page only and was removed in beta 2. Behaviour is unknown.
