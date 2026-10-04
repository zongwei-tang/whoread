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
- **Directory listings** only when readdir is enabled (off by default). Opening a directory only
  lists it, so it counts as readdir, not as a read of the category.
- **Moves or clones of a parent directory** of a monitored prefix, e.g. `mv ~/.config /tmp/x`.
  Ancestors are registered as literal target paths, and the move is recorded as an access to
  *every* category below them (gh, gcloud, git credentials…), each at the worst severity a file
  of that category can have. Moving a folder inside a project root carries its `.env`/`*.pem`
  files and is recorded in the project-secrets category.
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
| **Volumes and paths you did not configure** | The catalog decides what is monitored. | Edit the catalog (Settings → Monitored paths, or `sudo whoread catalog add-path`) or add a custom category. A path rule on an unmonitored path adds that path to the Custom category automatically. |
| **iTerm2 session logs** | They go to a folder you choose per profile (Profiles → Session → Automatically log). | Add that folder as a custom path. The catalog only covers iTerm2's saved window state. |
| **Changes made only through a writable memory mapping** | The close event's `modified` flag is not set for writes through `mmap`. | The open with write intent (`FWRITE`) is still recorded. |
| **Events the kernel dropped** | Under heavy load ES can drop NOTIFY events (eslogger reports sequence gaps). | `whoread status` shows the drop count. AUTH events are never dropped: the kernel waits for an answer. |

## Attackers WhoRead does not stop

- **Root-level malware** can stop the dev LaunchDaemon, edit the database or settings, or remove
  the kill-switch file. It can also delete the TCC grant when SIP is off. The system extension
  form is harder to stop than a LaunchDaemon, but it is not a security boundary against root.
- **Code running as you can read what you can read** unless an enforcing rule blocks it. Monitor
  mode only reports.
- **Weak owner identities.** An owner is a process expected to read a category (ssh for SSH keys).
  Owners raise no alert on their own, so how they are recognised matters:
  - Apple platform binaries: location *and* the kernel's platform flag, and the location must be
    root-owned (`/System`, `/usr/bin`, `/usr/sbin`, `/usr/libexec`, `/bin`, `/sbin`,
    `/Library/Apple`). A copied Apple binary keeps its platform flag, so `/usr/local/bin/ssh` or
    `~/x/Keychain Access.app` is not an owner. Apple apps count only under `/System`. Strong.
  - Signed third-party apps: bundle path plus team ID. The daemon reads the team IDs of the apps
    installed on this Mac with `codesign -dv` at start and after catalog changes (kept in memory,
    never written to your catalog; `sudo whoread catalog resolve-owners` shows them). An owner
    spec that lists glob paths is never pinned to one signing ID, so other members still match.
    An app whose team ID is not known is **not** an owner, so it raises alerts instead of passing
    silently. Strong.
  - Homebrew, npm, pyenv and other tools in user-writable places (`/opt/homebrew` belongs to the
    user, as do `/usr/local` on Intel Homebrew Macs and everything under `~`): anchored install
    paths only, and for scripts both the interpreter's location and the script it runs
    (`python3 /opt/homebrew/bin/aws`; only the script position counts, not any argument).
    **Weak.** Any process running as you can write there and pose as such an owner. These owners
    only keep honest tools quiet; enforcing rules are what stop a hostile process.
  - Names alone never make an owner. Shells, `curl` and `git` are not owners of shell history,
    `.netrc` or SSH keys: they read on behalf of whoever runs them (an agent's
    `zsh -c 'fc -l'`, `curl -T ~/.netrc …`, `git diff --no-index /dev/null ~/.ssh/id_ed25519`).
  - Each AI agent owns only its own transcripts: Claude Code reading Codex's sessions alerts.
  - Install paths in the default catalog come from vendor documentation and have not all been
    checked on a Mac yet (see RESEARCH.md). A path that is wrong makes the tool a non-owner, which
    means more alerts, never fewer.
- **AI-agent detection is heuristic.** It uses executable names, paths, bundle names and argv
  (`Data/agents.json`). A renamed or repackaged agent is not recognised until the file is updated.

## Protecting the guard from the guarded

AI agents run as you, so WhoRead must not let them switch it off:

- **Weakening changes** need **root** (`sudo whoread …`) or the **signed WhoRead app**:
  - enforcement off, pause;
  - allow rules and exceptions ("allow once", "always allow");
  - ignore, keep blocking and mark read (they silence an alert);
  - editing or deleting rules;
  - settings and catalog;
  - restarting learning.

  The daemon checks the peer's euid. It recognises the app by code signature (team-pinned
  requirement), not by name. An agent can run the `whoread` CLI, but it can neither turn the
  guard off nor dismiss the alert about its own access without your password.
- **Strengthening changes** (enforcement on, new block/alert rules, "block from now on", unpause)
  are open to the console user. An unprivileged "block from now on" adds the rule but leaves the
  alert open. Rules are size-limited (512 rules, bounded fields), so a client cannot slow down
  rule evaluation on the AUTH path.
- **Root may use any `whoread` build** over XPC (root can create the kill-switch file anyway);
  other clients must satisfy the client code-signing requirement.
- **Unknown peers are refused.** A non-root peer must be the console user, and both must be known.
- **Shared Macs.** The daemon records every user's accesses in one database. Whoever is at the
  console can read all of it (not only their own); other non-root users cannot connect. Do not
  rely on WhoRead to keep one user's history from another user who logs in at the console.
- **Development builds.** An extension built without a team drops both requirements: any local
  client may connect, no app is recognised, and every weakening change needs sudo. The dev
  LaunchDaemon recognises the app only when both `WHOREAD_CLIENT_REQUIREMENT` and
  `WHOREAD_APP_REQUIREMENT` are set (`--app-requirement` alone has no effect and is logged as an
  error). Use Developer ID builds for real protection.
- Every enforcement change, rule change, alert action and mark-read is logged with the peer pid
  and uid in `/Library/Logs/WhoRead/extension.log` (system extension) or `whoreadd.log` (dev
  daemon), root-only (0600 in a 0700 directory). Log lines are sanitized: file and process names
  cannot forge extra lines.
- **One daemon per data directory.** A lock file stops the dev LaunchDaemon and the system
  extension from running at the same time (the kill switches would reach only one of them).

## Enforcement safety

- **Fail-open.** Internal errors and unknown events are allowed. If the stored rules cannot be
  read, enforcement stays off and the rules are not overwritten with the templates (only root or
  the app may replace them). If the daemon hangs past an AUTH deadline, macOS kills the client
  and the pending operation is implicitly allowed. WhoRead runs in the default deadline mode;
  the macOS 27 fail-open mode is not used yet (RESEARCH.md).
- **Death while enforcing leaves enforcement off.** While AUTH events are subscribed, a marker file
  exists. If the next start finds it (the kernel killed the daemon for a missed deadline, or it
  crashed, or the Mac lost power), enforcement stays off until you turn it on again. That is
  fail-open by design.
- **Decisions are made in memory on the ES callback** (classifier, process tree, rules). Logging
  and notifications happen afterwards on queues. No disk IO, no XPC, no UI on the callback path.
- **Never blocked** (hard-coded, by name *and* platform flag): launchd, kernel_task,
  WindowServer, loginwindow, securityd, trustd, opendirectoryd, syspolicyd, tccd, the mds/mdworker
  family, backupd, installd, softwareupdated, endpointsecurityd, and the daemon itself.
- **Platform binaries** are only blocked by rules that name them explicitly, rules that opt in,
  or AI-agent-chain rules.
- **Directory listings are never blocked**, even by a deny rule: they reveal names only, and
  blocking them breaks `ls`, Finder and shells. Creating a new file inside a protected directory
  is blocked (AUTH_CREATE), opening or moving one is blocked (AUTH_OPEN, rename, clone, link…).
- **Owners under an agent.** The "block AI agents from critical files" template blocks every
  process under an agent, owners included (`ssh` run by an agent is still the agent): the brief's
  priority is deny > allow > owner. Rules made by "block from now on" exempt the category's
  owners, so blocking the terminal an alert was charged to does not break your own `ssh`/`git`.
- **Exceptions are narrow.** "Allow once" covers the path, category and access kind that was
  blocked, and only chains with the same AI agents the alert showed; it expires after 10 minutes
  or one use. "Always allow" is scoped the same way minus the path. A used "allow once" stays used
  across restarts. Unsigned binaries are pinned to their cdhash in these rules, and a deny on a
  pinned cdhash follows the code to any path.
- **Latency guard.** Every AUTH response time is recorded, from the event's own timestamp (so time
  spent queued counts). A missed deadline, or p99 over the threshold (default 50 ms), turns
  enforcement off automatically; the setting itself is switched off, so it stays off across
  restarts until you turn it on again (`whoread enforcement on` or the UI switch).
- **Three kill switches**, each effective at once:
  - `sudo whoread enforcement off`;
  - the UI switch, which falls back to an administrator prompt if the daemon refuses;
  - the file `/Library/Application Support/WhoRead/disable-enforcement`, polled every 200 ms.

  Every change also clears the ES result cache.
- **Caching.** The ES cache is global and keyed on the *executable file*. WhoRead lets ES cache
  only allows that depend on code identity alone and that no enforced deny rule could narrow.
  With an agent-chain, "allow once" or owner rule in play, a cached allow for `cat` would also
  let a later `cat` under an agent through, so those decisions are never cached. An AUTH_OPEN
  allow grants all requested flags; denials are never cached.

## Privacy

- File contents are never read: only paths and process metadata.
- argv is redacted before storage and display: tokens and passwords in flags and `key=value`,
  credentials in URLs (`https://user:token@host`, `?access_token=`), `Authorization:`/cookie
  headers, tool-specific password options (`sshpass -p`, `mysql -p…`, `redis-cli -a`,
  `security -w`, `openssl -pass pass:`…), well-known token formats and high-entropy strings —
  also inside `sh -c "<command>"` strings, which is how AI agents run commands. File paths are
  kept. Stored parent chains are capped at the nearest 64 processes. eslogger's exec environment
  is never parsed.
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
