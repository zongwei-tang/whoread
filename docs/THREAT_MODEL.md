# Threat model

WhoRead answers "which process, started by whom, opened or modified which sensitive file, and
when", and optionally blocks it. This page lists what it can and cannot see or stop. The macOS
facts behind it are cited in [`RESEARCH.md`](RESEARCH.md).

## What WhoRead sees

- **Opens** of monitored files, with read/write intent (`FREAD`/`FWRITE`). An open with `O_TRUNC`
  counts as a write whatever its access mode (it can empty a file opened read-only).
- **Closes that modified a file**. With the native backend (message version 6 and later), a close
  that reports no write call but a writable mapping, by a process that opened that file for writing
  while the daemon ran, is recorded as a write with the note `mapped-writable` ("possibly modified
  through a writable mapping"; nothing tells whether the mapping was written to).
- **rename, clone, copyfile, link, unlink, truncate, exchangedata** (and readdir if enabled) whose
  source or destination is monitored. Endpoint Security delivers a multi-path event if *any* of
  its paths is selected. A rename onto an existing directory may be a swap (`renamex_np` with
  `RENAME_SWAP`, which ES does not flag) that moves that directory and its contents to the source
  path, so it is judged as reading and writing everything the directory can hold. With the native
  backend, a rename onto an *empty* directory on a local APFS volume is judged as a write only. A
  swap onto an existing *file* is seen only as a write of that file, since every atomic save looks
  the same (whether the kernel also authorizes the reverse direction is not verified on a Mac yet).
- **Permission, owner and ACL changes** of monitored files (chmod, chown, `chmod +a`, and
  setattrlist with those attributes): recorded and decided as writes. `chmod 644` on a key exposes
  it to the other users of the Mac without any open.
- **Mounts** on a monitored path or on a parent of monitored paths: recorded and decided as a write
  to every category below the mount point. Two kinds are not judged: a mount on a home or on anything
  above a home (network, auto_home and FileVault homes are mounted there at every login), and a mount
  on a volume's own mount point (a direct child of the volumes folder, where every disk, image and
  share arrives). A mount over a monitored path inside a volume is still judged.
- **New symlinks, directories and device nodes** created inside a monitored directory (e.g.
  `ln -s … ~/.ssh/authorized_keys`). New regular files are recorded through their creating open.
- **Directory listings** only when readdir is enabled (off by default). Opening a directory only
  lists it, so it counts as readdir, not as a read of the category.
- **Moves, clones and copies of a parent directory** of a monitored prefix, e.g.
  `mv ~/.config /tmp/x`. Ancestors are registered as literal target paths, and the move is recorded
  as an access to *every* category below them (gh, gcloud, git credentials…), each at the worst
  severity a file of that category can have, wherever the moved folder itself sits (a home on an
  external volume, a cloud folder holding a project root or a link target). The other way round,
  planting a parent (a folder or link renamed or cloned onto `~/.config`, or a symlink created
  there) is recorded and decided as a write to every category below it.
- **Project folders.** Inside the project roots you configure, `.env*`, `*.pem` and `*.key` are
  matched at any depth. A folder moved out of the project (to a temp folder or the Trash, or renamed
  to an excluded name such as `node_modules` or `.git`) is judged by the worst file it can carry; a
  folder moved within the project keeps the category's base severity. A folder moved or cloned into
  a project root is a project-secrets write.
- **Nested categories.** A path belongs to every category whose prefix holds it and whose patterns
  accept it: a key in a custom folder inside the SSH key folder is in the ssh category and in the
  custom one, so the rules of both cover it, and a rule or an answer about one never decides the
  other. The deepest prefix names the path (that is the category the UI shows), except that link
  targets, custom paths and project roots name it only when they are more severe (custom paths and
  project roots also win ties). Each category gets its own event and alert.
- **The process**: pid, executable, signing ID, team ID, cdhash, platform-binary flag, the kernel's
  signing category and code-signing flags (where Endpoint Security reports them), argv (redacted),
  its full parent chain, and the attributed responsible app or AI agent.
- **Other spellings of a path.** The native backend registers each monitored path as the catalog
  spells it, in both Unicode normal forms when it is not ASCII, as it is spelled on disk, and under
  the data volume root (`/System/Volumes/Data`), so homes under `/home` (autofs) and homes created
  directly on the data volume are covered too.
- **Links.** A file reached through a symlink is judged at least as strictly as its real location:
  a link adds its category to the file, and the file keeps its own. Links from
  prefixes in a home or under `/Volumes` are followed only to targets that are also in a home or
  under `/Volumes`: a dotfile linked into `/nix/store` or `/opt` is not monitored at its target.
  A link's category lends no ownership: owners of a category a file reaches only through a link are
  not owners of the file's other categories (a folder of yours linked into a cloud CLI's config
  folder does not make that CLI an owner of what the folder holds). So when a dotfile directory is
  itself a link into a cloud folder or onto an external volume, its own tools (ssh for its folder)
  are asked once about the cloud-storage or volumes category. A link to a broad folder of
  yours also adds its category to the files there that have a category of their own, so their
  owners are asked about it too. Path rules also match the link targets the classifier followed (up
  to 8 per prefix); allow path rules never follow links.
- **Link discovery.** Links in the dotfile directories directly under a home are found by a search
  (breadth first, 8 levels deep, at most 20,000 entries per directory and 100,000 per search, but at
  least 2,000 for every directory) at start and every 5 minutes. Between searches, links that file
  events show are followed within about 1.5 s, at any depth: a link created, replaced or removed
  inside a dotfile directory or its real path, the links in a directory moved or copied in, and a
  dotfile directory or a directory above it made a link. More than 64 link changes at once start a
  full search, at most every 30 s. One classifier follows at most 4,096 links, in catalog order, and
  at most 1,024 links found from events are remembered between full searches. A dangling link's
  target is monitored before it exists, so the first write through it is decided, also below
  directories that do not exist yet, except through an existing non-directory or a missing `..`
  (those wait for the 5-minute search). Not followed: links inside a directory that a followed link
  leads to, and links past the caps above. A directory swapped into a dotfile directory by a rename
  swap reported from the dotfile side is searched only at the next full search.

## What WhoRead does not see

| Gap | Why | Consequence / mitigation |
|---|---|---|
| **Which bytes were read** | Endpoint Security has no per-`read(2)` event; only open/close (and mmap). | WhoRead says "Zoom opened `id_ed25519` for reading", not what it read. |
| **File handles opened before WhoRead started** | No new open event is generated for an already-open descriptor. | A process that opened a key before the daemon started can keep reading it unseen. Starting at boot (system extension) narrows the window. |
| **`.env` (etc.) anywhere on disk** | Inverted target-path muting is prefix-based; there is no "any path ending in `.env`" rule. | Only inside the **project roots** you configure are `.env*`, `*.pem` and `*.key` matched (at any depth). Elsewhere they are not monitored. |
| **Pre-existing hard links outside the monitored prefixes** | ES reports one of a file's hard-link paths; muting applies to that path (header note on `es_mute_path`). | Creating *new* hard links out of a monitored directory is seen, and denied when enforcing. A link that existed before is a blind spot. |
| **Content leaving after a legitimate read** | Out of scope (no network monitoring in v1). | `ssh` reading your key and sending it to a host you typed is "owner behaviour". |
| **Indirect access through a long-running helper** | Attribution follows the process tree. | If an agent asks an already running process (an editor extension host, a database server, an `ssh-agent`) to read a file, the access is charged to that process, not to the agent. |
| **Processes detached from their ancestry** | `open -a`, `launchctl submit` or XPC services are started by launchd, not by the requester. A traced process is judged by its fork-time parent, not by its debugger. | Such processes have no agent in their chain, so agent-chain rules do not apply to them; neither do they to code an agent injects through a debugger it attached to another process. Their *own* identity rules (signing ID, non-owner) still apply. |
| **Unknown ancestry** | A parent that was never seen (the process client runs behind the file client, events were dropped, a process was reparented after its parent exited) leaves the chain unknown, never "started by launchd". After a daemon restart, libproc has no fork-time parent, so a running process whose parent is launchd counts as unknown until it produces an event of its own. | Such a chain may hide an AI agent, so it gets no owner exemption, Apple trust or benign status, and an answer given for a known chain does not cover it: in ask mode it is asked (ASK_MODE.md). Programs in windows opened before a restart (Terminal → zsh → ssh) are asked until Terminal itself shows up in an event (opening a new tab is enough). Outside ask mode, agent-chain deny rules do not apply to it, since the agent cannot be known; a critical access by it still alerts. The AI agents of running processes are kept across restarts ("Restarts lose some ancestry", below). |
| **Volumes and paths you did not configure** | The catalog decides what is monitored. | Edit the catalog (Settings → Monitored paths, or `sudo whoread catalog add-path`) or add a custom category. A path rule on an unmonitored path adds that path to the Custom category automatically; without sudo or the app this only works for paths that really resolve (symlinks followed) inside your home or under `/Volumes`. A catalog edit that would stop monitoring an enabled path rule, or add a whole disk, home or folder of homes, is refused. A path rule placed *above* monitored prefixes (a rule on `~/Documents` while only `~/Documents/secret` is monitored) only filters what is monitored below it. |
| **iTerm2 session logs** | They go to a folder you choose per profile (Profiles → Session → Automatically log). | Add that folder as a custom path. The catalog only covers iTerm2's saved window state. |
| **Changes made only through a writable memory mapping** | The close event's `modified` flag is not set for writes through `mmap`. Endpoint Security's `was_mapped_writable` flag only says that something mapped the file writable during its life. | The open with write intent (`FWRITE`) is recorded. With the native backend, the close by a process that opened the file for writing is recorded as a possible write (`mapped-writable`, above). Not when that process opened the file before the daemon started, renamed it before closing it, or was among more than 4,096 writable opens tracked since; writes through a mapping after its descriptor is closed are not seen. The eslogger backend does not read the flag. |
| **Events the kernel dropped** | Under heavy load ES can drop messages (sequence gaps). On macOS 27 the native file client runs in fail-closed mode: an AUTH message dropped from a full queue is *denied*. Before macOS 27 (kill mode) it is *allowed*. | `whoread status` shows the kernel drop count (eslogger and native, from sequence gaps), the native analysis-queue drops, and for the native file client the dropped AUTH messages by outcome (from per-event-type sequence gaps); the app shows them in the menu bar and in Settings. Nothing is known about a dropped message (no process, no path), so it is counted, never recorded as an event. The counts assume that AUTH results served from the ES cache and muted events do not advance the sequence numbers; that is not verified on a Mac yet. |
| **Answers that reach the kernel too late** | In fail-closed mode (macOS 27) the kernel denies an access whose answer comes at or after its deadline, and no later event shows it. | The daemon reads the clock just before `es_respond` and sends a deny instead of a late allow; an allow `es_respond` did not deliver counts too. Every such access is counted in `whoread status`; one to a sensitive file is also recorded as blocked with the note `deadline-missed` (no rule, no alert). A very short window remains between the clock check and the kernel handling the answer. |
| **Programs in the Endpoint Security default mute set** | A new ES client starts with some system programs (those watchdogd monitors, for example) muted for most AUTH events. Inverting target muting does not clear this, and Apple advises against unmuting it. | Their accesses still arrive as NOTIFY events and are recorded, but can never be asked about or blocked. The daemon logs the list at connect, and `whoread status` shows how many program paths are muted (`muted:` line). The list may change between macOS releases. |
| **Saving a directory package in a monitored folder** | NSFileManager's `replaceItemAt` (document safe saves) swaps the new package in with `RENAME_SWAP`. ES reports no rename flags, so this is the same event as moving the old package out. | It is judged as a read of everything the folder's category can hold (in a project root: its most severe key pattern), so such saves are asked about. A plain rename onto an *empty* directory on a local APFS volume is judged as a write only (native backend). |
| **A link planted at a parent of monitored paths, when its create event does not say its type** | WhoRead judges a new *link* at a parent of monitored paths (`ln -s … ~/.config`), not a new directory there (tools create `~/.config` all the time). Whether ES's AUTH_CREATE always carries the file type is not verified on a Mac. | Where it does not, such a link is not decided at AUTH; the NOTIFY event records it afterwards. |
| **Paths spelled in another case** | Inverted target muting compares paths byte for byte. | WhoRead registers the catalog spelling, both Unicode normal forms and the spelling on disk. That ES reports the on-disk spelling whatever case a program typed is expected, but not verified on a Mac yet. |
| **chflags, utimes and extended attributes** | Not subscribed. | Flag, timestamp and extended-attribute changes of monitored files are neither recorded nor decided. |

## Attackers WhoRead does not stop

- **Root-level malware** can stop the dev LaunchDaemon, edit the database or settings, or remove
  the kill-switch file. It can also delete the TCC grant when SIP is off. The system extension
  form is harder to stop than a LaunchDaemon, but it is not a security boundary against root.
- **Code running as you can read what you can read** unless enforcement is on. With enforcement
  off (or the eslogger backend), WhoRead only records and alerts.
- **Load still opens gaps.** WhoRead never switches enforcement off by itself. Before macOS 27 the
  kernel does two things it cannot change: an AUTH message dropped from a full client queue is
  *allowed*, and a client that misses a deadline is killed (that access is allowed) and restarted by
  launchd. On macOS 27 the file client runs in fail-closed mode: both are denied instead, and the
  daemon lives. A handler stuck in one call is exited by the daemon's watchdog after at least 120 s
  (longer after recent watchdog exits, up to 900 s); accesses in the restart gap are allowed and not
  recorded. A process running as you that floods monitored files can provoke drops either way. If
  restarts repeat, Endpoint Security may refuse new connections; only the manual kill switches stop
  that loop.
- **"Allow all Apple programs" trusts Apple's shells and interpreters too.** With the setting on, a
  chain made only of Apple programs in system locations (e.g. `Terminal → zsh → python3`, or a user
  LaunchAgent that has launchd start `/bin/cat`) is never asked, unless an AI agent is in it. A
  third-party app in the chain (`Zoom → sh → cat`) still asks. Off by default.
- **Answers are per app, not per program.** "Always allow" for Terminal covers every program you run
  in Terminal without an AI agent, for that category and access (the cdhash pin applies only when an
  unsigned binary is charged to itself). Answers pinned to a team ID are not gated by signing
  category or controllability (a question has no signing category to scope by, and gating would ask
  forever about your own debug builds), so an "always allow" for an app also covers a debugged or
  development build of it.
- **Agent scoping follows the process tree.** An agent that gets launchd to start something for it
  (`open -a`, `osascript` telling Terminal to run a command, `launchctl submit`) breaks the chain; the
  started process is judged without the agent. An AI agent process that execs another program stays
  that agent, with its team, whatever the new program is: a copy of `cat` named after another agent,
  or an unsigned program run under the agent's name, cannot shed it. So an agent that really starts
  another agent *in place* (exec, not a child) is shown and scoped as the first agent, and the second
  agent's own rules do not apply to that process. A fork-time copy of an agent that execs a shell is
  a program the agent started, not the agent.
- **Restarts lose some ancestry.** The daemon saves the AI agent ancestry of running processes every
  5 s when it changed, and at stop: for each process its pid and start time, its agent identity, its
  parent, and up to 8 agents above it; at most 512 processes and 512 KiB, agents and processes whose
  parent has exited first, then the others, oldest first. After a restart a process that was an agent
  is one again, with its saved team, and an orphan whose parent is gone is linked below placeholders
  for that parent and its agents (or below the agent itself while it still runs). Placeholders are
  never found by pid and never make a chain reach launchd: the restored chain carries the agents and
  no trust. A save from an earlier boot is ignored (where the boot time cannot be read, pid and
  start time decide alone). Processes not saved (past those limits, or
  started within 5 s before a crash) come back with unknown ancestry, which fails closed (see
  "Unknown ancestry" above).
- **Weak owner identities.** An owner is a process expected to read a category (ssh for SSH keys).
  Owners raise no alert on their own, and only count with a known chain and no AI agent in it, so
  how they are recognised matters:
  - Apple platform binaries: location *and* the kernel's platform flag, and the location must be
    root-owned (`/System`, `/usr/bin`, `/usr/sbin`, `/usr/libexec`, `/bin`, `/sbin`,
    `/Library/Apple`, `/Library/Developer/CommandLineTools`; never the data volume spelling
    `/System/Volumes/Data/…`). A copied Apple binary keeps its platform flag, so
    `/usr/local/bin/ssh` or `~/x/Keychain Access.app` is not an owner. Apple apps count only under
    `/System`. Where Endpoint Security reports the kernel's signing category (message version 10,
    macOS 26 and later) it must be PLATFORM. Code that another process controls (its code-signing
    flags show get-task-allow or debugged) or that is signed but no longer valid (it ran a page its
    signature does not cover) is never an owner, never an Apple program for "trust Apple programs",
    never a benign service and never on the never-block list. Strong.
  - Signed third-party apps: bundle path plus team ID. The daemon reads the team IDs of the apps
    installed on this Mac with `codesign -dv` at start and after catalog changes (kept in memory,
    never written to your catalog; `sudo whoread catalog resolve-owners` shows them). An owner
    spec that lists glob paths is never pinned to one signing ID, so other members still match.
    An app whose team ID is not known is **not** an owner, so it raises alerts instead of passing
    silently. The team ID counts only for code the kernel validated as Developer ID or App Store: a
    development (Xcode debug), TestFlight, enterprise, local or ad hoc build with the same team ID is
    not an owner. Without a reported category (older macOS) the team ID alone counts. Strong. (Which
    category an Intel app reports under Rosetta is not verified on a Mac yet; if it is not Developer
    ID, such an app is not an owner and is asked.)
  - Homebrew, npm, pyenv and other tools in user-writable places (`/opt/homebrew` belongs to the
    user, as do `/usr/local` on Intel Homebrew Macs and everything under `~`): anchored install
    paths only, and for scripts both the interpreter's location and the script it runs
    (`python3 /opt/homebrew/bin/aws`; only the script position counts, not any argument). Not gated
    by signing category, since the honest tool is ad hoc signed too: a local or ad hoc binary
    written to the same path is an owner. A debugged or get-task-allow process is still not one; a
    tool you once attached a debugger to stays a non-owner until it restarts.
    **Weak.** Any process running as you can write there and pose as such an owner. These owners
    only keep honest tools quiet; enforcing rules are what stop a hostile process.
  - Names alone never make an owner. Shells, `curl` and `git` are not owners of shell history,
    `.netrc` or SSH keys: they read on behalf of whoever runs them (an agent's
    `zsh -c 'fc -l'`, `curl -T ~/.netrc …`, `git diff --no-index /dev/null ~/.ssh/id_ed25519`).
  - Each AI agent owns only its own transcripts: Claude Code reading Codex's sessions alerts.
  - Install paths in the default catalog come from vendor documentation and have not all been
    checked on a Mac yet (see RESEARCH.md). A path that is wrong makes the tool a non-owner, which
    means more alerts, never fewer.
- **Injection into a running third-party owner without the hardened runtime.** A process with
  debugging rights can write into another process through its task port without ptrace. Code pages
  written that way clear the process's "valid" signing flag once executed (unless the kernel kills
  it), and such a process is no longer trusted (not verified on a Mac yet). Injection that leaves the
  code pages valid is not detected. Requiring the hardened runtime for team-pinned owners would close
  this; it is not done.
- **AI-agent detection is heuristic.** It uses executable names, paths, bundle names and argv
  (`Data/agents.json`). A renamed or repackaged agent is not recognised until the file is updated.

## Protecting the guard from the guarded

AI agents run as you, so WhoRead must not let them switch it off, or read through it what they
could not read themselves:

- **Weakening changes** need **root** (`sudo whoread …`) or the **signed WhoRead app**:
  - enforcement off, pause;
  - allow rules and exceptions ("allow once", "always allow");
  - ignore, keep blocking and mark read (they silence an alert);
  - editing, deleting or replacing rules;
  - settings and catalog (turning "trust Apple programs" *off* is open to the console user: only
    that one setting is changed, on the live settings);
  - answering a question with "allow once", "always allow" or "allow all Apple programs";
  - `whoread baseline restart-learning` (it forgets every access you did not approve, so they
    alert as first accesses again).

  Denying a question (once or always) is open to the console user, so an agent can see questions
  and deny them, but never allow them. Turning enforcement on is open to the console user too: with
  no app answering, every undecided access is then denied at once (a nuisance an agent could cause,
  not a way in). An agent can run the `whoread` CLI, but it can neither turn the guard off nor
  dismiss the alert about its own access without your password.
- **Reading what the daemon recorded** needs root or the signed app too: events, the live tail,
  alerts, app, file and agent summaries, daily totals, the baseline, rules and exports. These name
  files the daemon saw with Full Disk Access (Mail, Messages, iCloud Drive and other folders a
  process running as you may not be able to read; benign-service accesses are stored with full
  paths too) and keep command lines. The console user (an AI agent too) gets status, settings, the
  catalog and the agent list (its own configuration, or public data), open questions without their
  file path and command lines, deny answers and the strengthening changes below.
- **The app is recognised by its XPC connection, never by a pid.** When a connection arrives, a look
  at the peer's pid only chooses which code-signing requirement the daemon installs on it: "(client
  requirement) and (app requirement)" for what looks like the app, the client requirement
  otherwise. XPC then checks every message against that requirement, by the audit token the message
  carries, and invalidates the connection when one does not match (documented in
  `NSXPCConnection.h`; not yet checked on a Mac). A wrong guess leaves a connection
  invalidated or unprivileged, never privileged. The genuine app on a connection wrongly taken for a
  client reads no history and shows a limited view; questions travel on a connection of their own,
  and the app reopens a refused connection (ASK_MODE.md). The app's "enforcement off" opens a fresh
  connection, so the kill path is unaffected.
- **Which code may connect.** The client requirement admits only the CLI (`<prefix>.whoread.cli`)
  and the app (`<prefix>.whoread`) of the team, not every program the team signed. Release builds
  (any configuration but Debug) pin Developer ID (the Developer ID CA intermediate and a Developer ID
  Application leaf) and refuse code that carries the `com.apple.security.get-task-allow`,
  `com.apple.security.cs.disable-library-validation` or
  `com.apple.security.cs.allow-dyld-environment-variables` entitlement, any of which would let code
  running as you drive the app. A requirement that does not parse fails closed: a bad client
  requirement refuses every non-root peer, and a bad app requirement (or one that no longer parses
  combined with the client one) means the app is never recognised; both are logged.
- **Strengthening changes** (enforcement on, new block/alert rules, "block from now on", unpause)
  are open to the console user. An unprivileged "block from now on" adds the rule but leaves the
  alert open. Rules are size-limited (512 rules, 256 exceptions per rule, bounded fields), and the
  process chain a decision walks is capped (64 links, plus the few ancestors each process records
  past them), so no client and no process tree, however deep, can slow down rule evaluation on the
  AUTH path without bound.
- **Root may use any `whoread` build** over XPC (root can create the kill-switch file anyway);
  other clients must satisfy the client code-signing requirement.
- **Unknown peers are refused.** A non-root peer must be the console user, and both must be known.
- **Shared Macs.** The daemon records every user's accesses in one database. Whoever is at the
  console can read all of it (not only their own) with sudo or the app; without, only status,
  configuration and questions without paths. Other non-root users cannot connect. Do not rely on
  WhoRead to keep one user's history from another user who logs in at the console.
- **Development builds.** An extension built without a team drops both requirements: any local
  client may connect, no app is recognised, and every weakening change and every read of recorded
  history needs sudo. The Debug configuration of the extension recognises Apple Development
  (debuggable) builds as the app and logs a warning saying so; a Debug app cannot connect to a
  Release extension. The dev LaunchDaemon recognises the app only when both
  `WHOREAD_CLIENT_REQUIREMENT` and `WHOREAD_APP_REQUIREMENT` are set (`--app-requirement` alone has
  no effect and is logged as an error), and logs the same warning when the app requirement does not
  pin Developer ID. Use Developer ID builds for real protection.
- **The daemon's own directories.** The daemon refuses to start unless only root can change its data
  directory (rules, database, catalog copy, auth-armed marker), the kill switch's directory and every
  directory above them, links followed. A directory on the way must belong to root (or the daemon's
  user), must not be writable by group or others unless it is sticky, and may carry no ACL entry
  that lets others add, remove or rename entries or change its permissions or owner (deny entries,
  such as a home's "everyone deny delete", pass). The data directory itself must be a real directory
  owned by root with no ACL entry granting anyone anything, and every entry in it, `defaults/`
  included, must be root's, not a symbolic link, not a file with a second hard link, and neither
  writable by others nor opened to them by an ACL. An existing directory that fails is never adopted
  or changed: the error names it and the fix (move it aside so a fresh one is created, or remove the
  ACL). The database is refused when it is a link, not a regular file, or has a second hard link.
- **What clients and the root daemon read from disk.** The CLI and the app take the daemon's service
  name from the `mach-service` file in the data directory only when that file is a root-owned regular
  file with one name that others cannot change, in a directory that passes the checks above;
  otherwise the CLI uses its built-in name and says why, and the app uses its Info.plist name. A
  daemon running as root (the system extension too) reads its default catalog, agent list and benign
  list only under the same conditions: an explicit `--defaults` directory that fails stops the start.
  The extension's bundled data must therefore not be writable by group or others (a build made under
  umask 002 would be refused).
- **Logs.** Every enforcement change, rule change, answer, alert action and mark-read is logged with
  the peer pid and uid in `/Library/Logs/WhoRead/extension.log` (system extension) or `whoreadd.log`
  (dev daemon), root-only (0600 in a 0700 directory). The extension opens the directory and the file
  without following links: a link, another user's directory or file, a group- or other-writable
  directory, one with an ACL that lets others in, or a hard-linked log file is moved aside to
  `<name>.untrusted-<time>-<random>`, and a fresh one is made; if no safe log can be had, the reason
  goes to the unified log (subsystem `com.whoread.extension`). The dev daemon's log is reopened by
  launchd by path, so it stays private only while `/Library/Logs` stays root-only: the install script
  refuses to install otherwise, and the daemon logs an error when its log is not root-only. Log lines
  go through the same sanitizer as everything shown to a person (Privacy, below), so file and process
  names cannot forge extra lines.
- **Minted apps.** Every distinct unsigned program path is an app of its own, so a process can create
  new (app, category, access) triples at will. The baseline of known triples is bounded by count only:
  at most 100,000 entries you did not approve; beyond that, maintenance forgets the least recently
  seen of them down to 90,000. Entries are never forgotten for age, so a known access does not alert
  as a first access again after the retention period, and approvals are never forgotten. A forgotten
  entry only means its next access alerts as a first access again; the baseline never decides an
  access. Open alert windows (10,000) and open questions (1,024) are bounded too, and `whoread
  baseline` returns the newest 10,000 entries.
- **One daemon per data directory.** A lock file stops the dev LaunchDaemon and the system
  extension from running at the same time (the kill switches would reach only one of them).

## Enforcement safety

- **Ask mode (fail-closed for undecided sensitive accesses).** With enforcement on, an access to a
  monitored file that no rule, owner (with a known chain and no AI agent), benign service or "trust
  Apple programs" decides is held and you are asked (docs/ASK_MODE.md). If you do not answer before
  the access's deadline budget, if no app has polled questions in the last 5 seconds (app not
  running), or if more than 256 accesses are already waiting, it is **denied**. Your answer is saved
  as a rule.
- **Deadlines.** On macOS 27 and later the file client runs in fail-closed deadline mode: an access
  not answered by its deadline, or an AUTH message the kernel drops from a full queue, is denied, and
  the daemon is not killed. Before macOS 27 (kill mode, the only one there) a daemon that hangs past
  an AUTH deadline is killed by macOS and the pending operation is allowed. `whoread status` shows
  the mode in force (docs/ASK_MODE.md, "Holding an access").
- **Fail-open elsewhere.** Internal errors and unknown events on every other path are allowed, so
  a WhoRead bug cannot lock up the Mac. If the stored rules cannot be read, enforcement stays off
  (with no rules every access would be asked, and answers could not be saved), and single-rule
  changes are refused for everyone (one would rewrite the table from an empty list). Only an
  explicit replacement by root or the app (`sudo whoread rules replace --json-file F --confirm`)
  overwrites them, and it first copies every old row, readable or not, into the `rules_backup` table
  of `whoread.sqlite`.
- **Never switched off automatically.** Slow answers and missed deadlines are counted and shown, not
  acted on. While AUTH events are subscribed a marker file exists; if the next start finds it (before
  macOS 27 the kernel killed the daemon for a missed deadline; a crash; a power loss), or finds the
  marker the watchdog leaves when it exits a daemon whose event handler is stuck, enforcement stays
  as you set it and `whoread status` and the app report the unclean stop, with how many there were
  since the last clean stop. Turning enforcement off (any kill switch) releases every held access as
  allowed.
- **Decisions are made in memory on the ES callback** (classifier, process tree, rules). Logging
  and notifications happen afterwards on queues. No disk IO, no XPC, no UI on the callback path.
- **Never blocked** (hard-coded, by name, platform flag *and* root-owned location, so a renamed
  copy of an Apple binary is not exempt; where the kernel reports the signing category it must be
  PLATFORM, and the program must not be controllable, as for owners above): launchd, kernel_task,
  WindowServer, loginwindow, securityd, trustd, opendirectoryd, syspolicyd, tccd, the Spotlight
  family (mds…, mdworker, mdworker_shared, mdsync, corespotlightd), backupd and backupd-helper,
  installd, softwareupdated, endpointsecurityd, and the daemon itself.
- **Platform binaries** are exempt only from "anything that isn't an expected owner" rules that do
  not opt in (`includePlatformBinaries`). Rules that name them, AI-agent-chain rules and app rules
  (including "block from now on") cover everything the app runs, platform binaries included.
- **Directory listings are never blocked**, even by a deny rule: they reveal names only, and
  blocking them breaks `ls`, Finder and shells. Creating a new file inside a protected directory
  is blocked (AUTH_CREATE), opening or moving one is blocked (AUTH_OPEN, rename, clone, link…), and
  so are permission, owner and ACL changes and mounts there.
- **Owners under an agent.** The "block AI agents from critical files" template blocks every
  process under an agent, owners included (`ssh` run by an agent is still the agent): the priority
  is deny > allow > owner. Rules made by "block from now on" exempt the category's owners, so
  blocking the terminal an alert was charged to does not break your own `ssh`/`git`.
- **Exceptions are narrow.** "Allow once" on a rule's block covers the path, category and access
  kind that was blocked, and only chains with the same AI agents the alert showed (and only known
  chains, unless the alert's was unknown); it expires after 10 minutes or one use. "Always allow"
  is scoped the same way minus the path, and also saves the app × category × access answer rule (so
  that app is not asked about other files of the category). A used "allow once" stays used across
  clean restarts; after a crash or SIGKILL, a use from the last 30 seconds may come back until the
  exception expires. Unsigned binaries are pinned to their cdhash in these rules; a deny on a
  pinned cdhash follows the code to any path and into chains charged to another app. A "block from
  now on" rule for an AI agent applies wherever that agent is in the chain.
- **Latency is measured, never acted on.** Every immediately answered AUTH response is timed from
  the event's own timestamp (held questions are excluded). p99 over the threshold (default 50 ms)
  for 3 consecutive checks logs a warning at most once a minute; deadline misses are counted.
- **Held accesses are answered exactly once.** The message is retained, answered by the user's answer
  or the budget timer, and released; a backstop denies it before the kernel deadline if nothing else
  did; before the ES clients are deleted every held access is denied. A held access the answer allows
  is re-decided against the new rules first, so an answer about one category never lets through an
  operation that also touches another undecided category.
- **Denial floods** are recorded from a bounded backlog: past 1,000 pending, identical repeats
  (same process instance, operation, targets and rule) are merged; past 10,000 the rest are only
  counted in `whoread status`. Every one of them is still denied.
- **Three kill switches**, each effective at once:
  - `sudo whoread enforcement off`;
  - the UI switch, which falls back to an administrator prompt if the daemon refuses;
  - the file `/Library/Application Support/WhoRead/disable-enforcement`, polled every 200 ms.

  Every change also clears the ES result cache.
- **Caching.** The ES cache is global and keyed on the *executable file* and the target. WhoRead
  lets ES cache only allows that depend on code identity alone and that no enforced deny rule could
  narrow: with an agent-chain, "allow once", answer or owner rule in play, a cached allow for `cat`
  would also let a later `cat` under an agent through. With enforcement on, a sensitive open is
  cached only when static allow rules cover both read and write on every category it touches, since
  an AUTH_OPEN allow grants all flags; allows by owner, benign service or Apple trust are never
  cached. Only opens are cached at all (mode, owner and mount changes could be, but their cache key
  ignores the chain), and denials never are.

## Privacy

- File contents are never read: only paths and process metadata.
- argv is redacted before storage and display.
  - Covered:
    - tokens and passwords in flags, `key=value` and `key:value` (also in comma lists such as
      `user:bob,password:…`);
    - credentials in URLs (`https://user:token@host`, also with `/`, `@`, `'`, `;` or `&` in the
      password, and `?access_token=`, `&sig=`);
    - `Authorization:`/cookie headers;
    - tool-specific password options (`sshpass -p`, `mysql -p…`, `redis-cli -a`, `security -w`,
      `openssl -pass pass:`, `ldap* -w` also attached, `ldappasswd -a/-s`, `smbclient -U user%…`,
      `lftp -u user,…`, `useradd/usermod -p`, `cypher-shell -p`…);
    - passwords given as plain arguments (`htpasswd -b`, `htdbm`, `mosquitto_passwd`,
      `rabbitmqctl add_user`, `dscl -passwd`, `networksetup`, `openssl passwd`, redis `AUTH`,
      `sqlplus user/pw`, `neo4j-admin set-initial-password`);
    - SQL that sets, inserts or hashes a password (`ALTER USER … PASSWORD`, `IDENTIFIED BY`,
      `SET PASSWORD`, `INSERT … (password) VALUES`, `PASSWORD('…')`, `crypt('…')`, Cypher
      `SET PASSWORD FROM … TO …`, `sp_addlogin`, `sp_password`), and SQL that connects with one
      (`CONNECT user/pw` where sqlplus, rman or dgmgrl runs);
    - calls such as `db.auth('u', 'pw')` and `auth=('u', 'pw')`;
    - what an expect script `send`s;
    - well-known token formats and high-entropy strings.
  - Also read in these places: inside `sh -c "<command>"` strings, which is how AI agents run
    commands; in commands run through `docker exec`, `kubectl exec` or `ssh`; in heredocs a shell
    reads as its script (`bash <<EOF`, `ssh host <<EOF`); with no space around `;`, `&&` or `|`;
    with a redirect attached to a word (`-pPW>FILE`, `'…'>FILE`).
  - What a command line writes is file contents and is redacted; the redirect's target is kept. This
    covers echo, printf or yes words sent to a file or a pipe (also from loops, groups, functions,
    process substitutions or after `exec > FILE`), heredoc bodies written to a file or read as a
    secret (`--password-stdin`, `sudo -S`, `chpasswd`), here-strings, and the literal values of
    variables, loop words, `printf -v` values and function or `sh -c` arguments that such data uses.
    The price is evidence: `echo x > /tmp/f` is stored as `echo ‹redacted› > /tmp/f`, and inside a
    group whose output goes to a file everything echoed is taken as written. The command a child
    process actually runs is still recorded in its own argv, so detection does not depend on it.
  - Kept: file paths, including the patterns and paths of searches (`grep`, `rg`, `git grep`), and
    the account `sysadminctl -resetPasswordFor` names. Replacement text of `sed -i` and `perl -pi` is
    kept on purpose, so that ordinary code edits stay readable.
  - Stored parent chains are capped at the nearest 64 processes (the AI agents of the whole chain are
    kept with every event). eslogger's exec environment is never parsed.
- Everything shown to a person (notification banners, the menu, the Alerts tab, the app's tables
  and inspector, the CLI's tables, tail, events, asks and alerts, error messages, and the log) goes
  through one sanitizer. C0/C1 controls, DEL, bidi overrides and isolates, zero-width and other
  format characters, U+2028/U+2029, private-use and other default-ignorable characters become
  visible `\u{…}` escapes (the emoji presentation selectors stay). Runs of spaces in a name show as
  one space; names are capped at 64 characters and banner paths at 160, cut in the middle so the
  file name stays visible. `--json` output and JSON/JSONL exports write those characters as `\u`
  escapes, so they stay valid JSON and decode to the exact values. CSV has no lossless escape:
  written to a terminal, hidden characters are escaped; written to a file or a pipe the cells are
  exact, except that a cell starting with `=`, `+`, `-`, `@`, a tab or a carriage return gets a
  leading apostrophe so that a spreadsheet does not run it as a formula (in every CSV output).
- Recorded history, benign-service accesses with full paths included, is served only to root and
  the signed app (see "Protecting the guard from the guarded").
- The database is in `/Library/Application Support/WhoRead/`, root-owned, mode 0600. The app does
  not open it; it asks the daemon over XPC.
- `whoread export --output FILE` and `whoread catalog export --output FILE` write `FILE` with mode
  0600 whatever the umask and without inherited ACL entries, through `FILE.partial` renamed at the
  end. They refuse a `FILE` that is a link (even a dangling one), a directory or another
  non-regular file, and an existing `FILE.partial`. Under sudo, a file written into a folder owned
  by the user who ran sudo is given to that user; otherwise root keeps it. For another mode, export
  to standard output and redirect it.
- No network access, telemetry, crash reporting, auto-update or LLM calls.

## eslogger backend caveats

- Apple states eslogger's output is "NOT API". The parser reads `schema_version`, ignores
  unknown fields, never depends on key order, and keeps fixtures per shape. It counts lines from
  unknown schema versions and reports them in `whoread status`.
- eslogger cannot block (NOTIFY only) and suppresses events from its own process group. Nothing is
  asked with it: first accesses are alerted instead (docs/ASK_MODE.md).
- It does not report the writable-mapping flag of a close, and a rename onto an empty directory is
  recorded as a read of the category's worst file (the native backend checks emptiness).
- It receives every event on the system and filters in user space, so it costs more CPU than the
  native client's inverted muting. That is fine for development and monitor-only use.
