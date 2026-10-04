# Threat model

WhoRead answers "which process, started by whom, opened or modified which sensitive file, and
when", and optionally blocks it. This page lists what it can and cannot see or stop. The macOS
facts behind it are cited in [`RESEARCH.md`](RESEARCH.md).

## What WhoRead sees

- **Opens** of monitored files, with read/write intent (`FREAD`/`FWRITE`).
- **Closes that modified a file**.
- **rename, clone, copyfile, link, unlink, truncate, exchangedata** (and readdir if enabled) whose
  source or destination is monitored. Endpoint Security delivers a multi-path event if *any* of
  its paths is selected.
- **Moves or clones of a parent directory** of a monitored prefix, e.g. `mv ~/.config /tmp/x`.
  Ancestors are registered as literal target paths and classified as accesses to the categories
  below them.
- **The process**: pid, executable, signing ID, team ID, cdhash, platform-binary flag, argv
  (redacted), its full parent chain, and the attributed responsible app or AI agent.

## What WhoRead does not see

| Gap | Why | Consequence / mitigation |
|---|---|---|
| **Which bytes were read** | Endpoint Security has no per-`read(2)` event; only open/close (and mmap). | WhoRead says "Zoom opened `id_ed25519` for reading", not what it read. |
| **File handles opened before WhoRead started** | No new open event is generated for an already-open descriptor. | A process that opened a key before the daemon started can keep reading it unseen. Starting at boot (system extension) narrows the window. |
| **`.env` (etc.) anywhere on disk** | Inverted target-path muting is prefix-based; there is no "any path ending in `.env`" rule. | Only inside the **project roots** you configure are `.env*`, `*.pem` and `*.key` matched (at any depth). Elsewhere they are not monitored. |
| **Pre-existing hard links outside the monitored prefixes** | ES reports one of a file's hard-link paths; muting applies to that path (header note on `es_mute_path`). | Creating *new* hard links out of a monitored directory is seen, and denied when enforcing. A link that existed before is a blind spot. |
| **Content leaving after a legitimate read** | Out of scope (no network monitoring in v1). | `ssh` reading your key and sending it to a host you typed is "owner behaviour". |
| **Indirect access through a long-running helper** | Attribution follows the process tree. | If an agent asks an already running process (an editor extension host, a database server, an `ssh-agent`) to read a file, the access is charged to that process, not to the agent. |
| **Processes detached from their ancestry** | `open -a`, `launchctl submit` or XPC services are started by launchd, not by the requester. | Such processes have no agent in their chain, so agent-chain rules do not apply to them. Their *own* identity rules (signing ID, non-owner) still apply. |
| **Volumes and paths you did not configure** | The catalog decides what is monitored. | Edit the catalog (Settings → Monitored paths) or add a custom category. |

## Attackers WhoRead does not stop

- **Root-level malware** can stop the dev LaunchDaemon, edit the database or settings, or remove
  the kill-switch file. It can also delete the TCC grant when SIP is off. The system extension
  form is harder to stop than a LaunchDaemon, but it is not a security boundary against root.
- **Code running as you can read what you can read** unless an enforcing rule blocks it. Monitor
  mode only reports.
- **Weak owner identities.** Owners are matched as follows:
  - Apple platform binaries: name, location *and* the kernel's platform flag. Strong.
  - Signed apps: bundle path plus team ID, once `whoread catalog resolve-owners` has filled the
    team IDs from `codesign -dv`. Strong.
  - Homebrew / unsigned tools: path only, and interpreted tools by argv (e.g.
    `python3 /opt/homebrew/bin/aws`). **Weak.** Anything that can write to `/opt/homebrew` can
    pose as such an owner. The catalog marks these specs as unverified.
- **AI-agent detection is heuristic.** It uses executable names, paths, bundle names and argv
  (`Data/agents.json`). A renamed or repackaged agent is not recognised until the file is updated.

## Protecting the guard from the guarded

AI agents run as you, so WhoRead must not let them switch it off:

- **Weakening changes** need **root** (`sudo whoread …`) or the **signed WhoRead app**:
  - enforcement off, pause;
  - allow rules and exceptions;
  - editing or deleting rules;
  - settings and catalog;
  - restarting learning.

  The daemon checks the XPC peer's euid. It recognises the app by code signature (team-pinned
  requirement), not by name. An agent can run the `whoread` CLI, but it cannot turn the guard off
  without your password.
- **Strengthening changes** (enforcement on, new block/alert rules, "block from now on", ignore,
  mark read) are open to the console user.
- **Other users** on the same Mac cannot read your history: non-root peers must be the console
  user.
- **Development builds** are ad-hoc signed. The app requirement is then only an identifier and
  can be spoofed. Use Developer ID builds for real protection.
- Every enforcement change, rule change and alert action is logged with the peer pid and uid.

## Enforcement safety

- **Fail-open.** Internal errors and unknown events are allowed. Rule loading failures disable
  enforcement. If the daemon hangs past an AUTH deadline, macOS kills the client and the pending
  operation is implicitly allowed.
- **Decisions are made in memory on the ES callback** (classifier, process tree, rules). Logging
  and notifications happen afterwards on queues. No disk IO, no XPC, no UI on the callback path.
- **Never blocked** (hard-coded, by name *and* platform flag): launchd, kernel_task,
  WindowServer, loginwindow, securityd, trustd, opendirectoryd, syspolicyd, tccd, the mds/mdworker
  family, backupd, installd, softwareupdated, endpointsecurityd, and the daemon itself.
- **Platform binaries** are only blocked by rules that name them explicitly, rules that opt in,
  or AI-agent-chain rules.
- **Latency guard.** Every AUTH response time is recorded. A missed deadline, or p99 over the
  threshold (default 50 ms), turns enforcement off automatically until you turn it on again.
- **Three kill switches**, each effective at once:
  - `sudo whoread enforcement off`;
  - the UI switch, which falls back to an administrator prompt if the daemon refuses;
  - the file `/Library/Application Support/WhoRead/disable-enforcement`, polled every 200 ms.

  Every change also clears the ES result cache.
- **Caching.** The ES cache is global and keyed on the *executable file*. WhoRead lets ES cache
  only decisions that depend on code identity alone. With an agent-chain, "allow once" or owner
  rule in play, a cached allow for `cat` would also let a later `cat` under an agent through, so
  those decisions are never cached.

## Privacy

- File contents are never read: only paths and process metadata.
- argv is redacted before storage and display (tokens, passwords, `Authorization:` headers,
  high-entropy strings). eslogger's exec environment is never parsed.
- The database is in `/Library/Application Support/WhoRead/`, root-owned, mode 0600. The app does
  not open it; it asks the daemon over XPC.
- No network access, telemetry, crash reporting, auto-update or LLM calls.

## eslogger backend caveats

- Apple states eslogger's output is "NOT API". The parser reads `schema_version`, ignores
  unknown fields, never depends on key order, and keeps fixtures per shape. It counts lines from
  unknown schema versions and reports them in `whoread status`.
- eslogger cannot block (NOTIFY only) and suppresses events from its own process group.
- It receives every event on the system and filters in user space, so it costs more CPU than the
  native client's inverted muting. That is fine for development and monitor-only use.
