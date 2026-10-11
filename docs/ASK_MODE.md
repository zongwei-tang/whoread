# Ask mode

While enforcement is on, the first time a program touches a sensitive file and nothing has decided
that access yet, WhoRead holds the access and asks you. Your answer is saved as a rule, so you are
asked once per app × category × access (× AI agents in the chain). An access you do not answer in
time is denied.

Enforcement is never switched off automatically.

## What is asked, what is not

For an access to a monitored file (every category, every severity), with enforcement active:

| Order | Case | Result |
|---|---|---|
| 1 | Directory listing / directory open | allowed (never blocked) |
| 2 | Never-block system daemons (name, platform flag and root-owned system location; where Endpoint Security reports the kernel's signing category it must be PLATFORM, and no other process may control the program) | allowed |
| 3 | An enforced deny rule matches (exceptions carve out, and count as answers) | denied |
| 4 | Allow rules cover every requested access kind on every touched category (your earlier answers are allow rules) | allowed |
| 5 | The process is an owner of the category, **no AI agent is in its chain, and its chain is known** (it reaches launchd) | allowed |
| 6 | The chain is a benign system service (Spotlight, Time Machine, iCloud, Quick Look, XProtect, file system services such as fseventsd), started by launchd or by other benign services, and the chain is known | allowed |
| 7 | "Trust Apple programs" is on, and the leaf **and every ancestor up to launchd** are Apple programs in system locations (checked as in row 2), each seen in an event and not only in the process snapshot taken at start, with no AI agent | allowed |
| 8 | Anything else | **asked** |

Details:
- A question names one category: the most severe one still undecided (ties: the first), and the
  access kinds requested on it. A read approval does not answer a write.
- A file can belong to several categories (nested prefixes: a custom folder inside a credential
  folder, a project root inside a cloud folder, a folder reached through a link). Each needs its own
  decision. An allow on the first question is re-decided before the access goes through: while
  another category is still undecided, the access is denied, an `ask` alert for that category
  appears at once (answerable in the Alerts tab), and the program's next attempt asks about it.
- Owners also count through the category a file is named by (its deepest prefix): an owner of that
  category is an owner of the file's other categories when those are not more severe, or have no
  owners of their own (an external volume, a custom folder, project secrets). Never when the file is
  in the naming category only through a link.
- An owner pinned by team or signing ID counts only for code the kernel validated as Developer ID or
  App Store (where it reports the signing category), and never for code another process controls
  (get-task-allow, debugged, or signed but no longer valid). Owners pinned only by location
  (Homebrew, npm, pip tools) are not gated by signing category; see THREAT_MODEL.md.
- A chain that does not reach launchd may hide an AI agent: its starter was never seen, its parent
  exited before WhoRead saw it, it was cut at 64 links, or it was restored after a daemon restart.
  Such a chain gets no owner exemption, no benign status and no Apple trust, so it is asked.
- A path allow rule that matches only because the target is an ancestor directory (moving the parent
  of a protected folder) does not answer for it.
- An "allow once" exception on a deny rule is not used up by an access that ends up asked.
- Alert rules and dry-run deny rules do not decide anything; they still alert, also after an answer
  covers the access (an answer only answers the question).
- Questions are never cached by Endpoint Security. An allow is cached only when static allow rules
  (no AI-agent scope, no expiry, nothing that depends on the chain) cover both read and write on
  every touched category, because an ES-cached open allow covers later opens whatever their flags.
  Answers carry an agent scope, so the accesses they decide are never cached; neither are allows by
  owner, benign service or Apple trust. Only opens are ever cached: mode, owner and mount changes
  could be, but their cache key ignores the process chain.

With enforcement off, or with the eslogger backend (which cannot hold or block), nothing can be
held. A first access is then recorded and alerted at once, with the same answers: "always allow"
saves the same allow rule, "block from now on" a deny rule, "allow all Apple programs" the setting.
With the setting on, all-Apple chains raise no alert either. An owner stays silent only with a known
chain and no AI agent: a critical access by a program whose starter is unknown, or by a program an
AI agent runs inside an approved app, alerts even though that app was approved.

## Holding an access

Endpoint Security gives every AUTH message a deadline (Mach absolute time, per message; its length
is not documented and must be measured on a Mac: `scripts/vm/acceptance-m5.sh` measures how long an
unanswered access waits). What the kernel does at the deadline depends on the macOS version:

- **macOS 27 and later:** the native source sets the file client's deadline miss mode to
  fail-closed before it subscribes to anything, and reads it back (`whoread status`, line
  `deadline:`). An access not answered by its deadline is denied and the daemon keeps running; an
  AUTH message the kernel drops from a full queue is denied too.
- **Before macOS 27** (kill mode, the only one there): a client that misses a deadline is killed by
  the kernel and the access is allowed; AUTH messages dropped from a full queue are allowed.

Either way an access is held only for a **budget**, so that WhoRead answers it itself:

- remaining = deadline − now;
- headroom = 20 % of remaining, clamped to [1 s, 5 s] (the pattern Santa uses);
- budget = remaining − headroom; no positive budget → not held.

The native source retains the message (`es_retain_message`), returns from the callback at once and
gives the broker a closure that answers the message exactly once and releases it:

- you answer in time → your answer; an "allow" is first re-decided against the rules the answer
  just saved, so an operation that also touches another undecided category (`cp ~/.ssh/id_x
  ~/.aws/credentials`) is denied and asks about that category when the program retries;
- the budget runs out → **deny** (not cached), and the question stays open for a later answer;
- the budget is under 0.5 s, 256 accesses are already held, or nobody polled `.asks` in the last
  5 s → **deny at once** (the question is still listed);
- a backstop in the source denies at budget + headroom/2 if nothing else answered (always before
  the deadline);
- before the source deletes its ES clients (stop, setup failure) every held access is denied, and
  nothing is held while no client exists;
- turning enforcement off (any kill switch) releases every held access as allowed and drops the open
  questions; their `ask` alerts stay answerable.

**Late answers.** In fail-closed mode an allow that reaches the kernel at or after the deadline is a
denial that no later event shows. The source reads the clock just before it answers and sends a
deny instead of a late allow; an allow that `es_respond` did not deliver counts the same. Every such
access is counted in `whoread status`, and one to a sensitive file is recorded as blocked with the
note `deadline-missed` (no rule, no alert: nothing you could answer would have changed it). Before
macOS 27 a late answer is sent as decided; the kernel has killed the daemon and allowed the access by
then.

Accesses with the same key (`AskKey`: responsible app or agent, category, access kinds, AI agents
in the chain, and whether the chain is known) share one question; answering it answers all of them.
A later access with the same key while the question is open waits for the same answer (no new
notification). Unanswered questions are forgotten an hour after their last attempt; at most 1024 are
kept (the oldest that hold nothing are dropped first). The `.asks` reply lists at most 200, those
holding an access first (earliest deadline first) when it is cut; the app then withdraws no banners.
Question ids never repeat across daemon restarts, so an answer to an old banner cannot land on a new
question.

Building a question on the ES callback is memory copies only; its argv is redacted on a queue of its
own, so the command lines appear a moment after the question.

Held accesses are excluded from the latency statistics.

## Answers

| Answer | Saved as | Needs |
|---|---|---|
| Allow once | allow rule for 10 minutes (it replaces an earlier one of the same scope; expired ones are pruned) | root or the signed app |
| Always allow | permanent allow rule | root or the signed app |
| Allow all Apple programs (offered only for all-Apple chains without an AI agent) | setting `trustApplePrograms = true` | root or the signed app |
| Deny | nothing (the accesses held for this question are denied) | console user |
| Always deny | enforced deny rule for that app or agent on the whole category, read and write, in every chain, platform binaries included (owners exempt); it also denies every open question of that app × category | console user |

An answer that allows also releases the accesses held for every other open question it covers.

Allow rules made from answers have the subject = the app or agent (pinned to its team ID when it has
one, and to its cdhash when it is an unsigned binary charged to itself), target = the category,
access = the asked kinds, `chainAgents` = the AI agents in the chain (`[]` = none),
`coversUnknownAncestry` (below), template `ask-answer`. `chainAgents` means "only those agents, or
none": an approval for Terminal (`[]`) never covers Claude Code running inside Terminal, and an
approval given while Claude Code was in the chain does not cover Codex. Answers are per app, not
per program: "always allow" for Terminal covers what you run in Terminal without an agent.

Answers also record whether the chain was known. A chain that does not reach launchd may hide an AI
agent (see "Details" above). Its question says "started by an unknown process, possibly an AI
agent", and `whoread asks` shows "unknown starter"; known and unknown chains of the same app get
separate questions. An answer given for a known chain never covers a chain of unknown ancestry. One
given for an unknown chain covers both, and its rule carries `coversUnknownAncestry = true`: the Rules
tab adds "(also when who started the program is unknown)", `whoread rules` adds "(also unknown
starter)". Rules saved without the field have the narrower scope. The wording appears for every chain
that does not reach launchd, including chains restored after a daemon restart (whose agent is known
and shown) and chains cut at 64 links. An app older than the daemon does not show it; an answer
given there still covers unknown starters. Answers given in the Alerts tab are scoped by the AI
agents of the whole chain, which every event keeps, not only by the 64 links stored with it.

An AI agent runs as you and can run `whoread`. It sees questions without their file path ("(path
hidden: run with sudo to see it)") and without command lines; it still sees who is asking (the
process, the executables of its chain, the responsible app), which any process of the same user can
see with `ps` while they run. It can deny questions (and, by polling them, make accesses wait for
their budget instead of being denied at once), but allowing needs your password or the signed app.
Turning "trust Apple programs" off is open to the console user.

Answer rules count toward the 512-rule limit. At the limit an allow answer changes nothing and the
question stays open; "always allow" on a rule's block saves nothing either, not even the exception.
If saving fails (disk full) the rule still applies in memory and the held accesses are released; the
error says the answer was applied but not saved. If the answer applied but its alerts could not be
marked as handled, the error says that instead.

Answering an `ask` alert in the Alerts tab, or an alert from monitor-only mode, is the same as
answering the question; "deny" there denies the accesses held for every open question the same allow
would cover. A block that no rule caused is a question nobody answered in time: "allow once" on it
saves the app × category answer rule for 10 minutes, as on the question. On an alert of a **rule's**
block, "allow once" adds only a narrow exception to that rule (that path, that category and access,
the same AI agents, one use, 10 minutes) and no answer rule; "always allow" there adds the permanent
exception (without the path) and also the app × category answer rule.

## No automatic switch-off

- Slow answers and missed deadlines never turn enforcement off. Deadline misses are counted; p99
  over `latencyP99ThresholdMs` for 3 consecutive checks logs a warning at most once a minute.
- If the daemon stops while AUTH is subscribed (before macOS 27 the kernel killed it for a missed
  deadline; a crash; a power loss), or its watchdog exited it with the event handler stuck (also
  reported when the daemon only monitored: file events were lost then), the next start keeps
  enforcement as you set it and reports the unclean stop (`DaemonStatus.uncleanStop`, kept until the
  next clean stop). Every unclean stop since the last clean one is counted in that report, with the
  first and last time and the number of watchdog exits. The app says "The monitor stopped
  unexpectedly (…). Enforcement stays as you set it."
- The watchdog (native source, every macOS version) looks every 10 s, on the uptime clock (it pauses
  while the Mac sleeps; idle time never counts). When one call of the file client's event handler has
  been running for at least max(120 s, 4 × the longest AUTH deadline seen), capped at 900 s, it logs
  one line, leaves a marker for the next start and exits the daemon, so launchd starts a fresh one.
  The enforcement setting is untouched. Accesses in the restart gap are allowed and not recorded, as
  for any restart.
- One automatic "off" remains on purpose: if the stored rules cannot be read at start, enforcement
  stays off until they load or are replaced (with no rules everything would be asked, and answers
  could not be saved).
- The three manual kill switches still work: `sudo whoread enforcement off`, the app switch, the
  file `/Library/Application Support/WhoRead/disable-enforcement`. They run on queues of their own,
  so they do not depend on the event handler.

Risk you accept with this:
- Before macOS 27, if a bug makes the daemon miss deadlines repeatedly, the kernel kills it each
  time (allowing that access), launchd restarts it, and Endpoint Security may eventually refuse new
  connections. Under a flood the kernel also allows AUTH messages it drops from a full queue.
- On macOS 27 (fail-closed) a missed deadline or a dropped AUTH message is denied and the daemon is
  not killed. A handler stuck in one call denies every access behind it until the watchdog exits the
  daemon. Its wait doubles with each watchdog exit in the last hour (240 s, 480 s, then 900 s), so a
  wedge that comes back keeps failing closed for longer between restarts instead of restarting every
  two minutes.
- Either way only the manual kill switches stop such a loop.

## In the app and the CLI

- There is no learning period: `learningDays` is 0 by default (a stored old default of 7 becomes 0).
  Set above 0 (`whoread settings set learning-days N`), it keeps first-access alerts quiet for that
  many days and never changes what is asked. The menu bar never shows "Learning" (`whoread status`
  can, while enforcement is off): it shows "Enforcing" while enforcement is on,
  unless the source is in error or monitoring is paused. Pausing does not stop holding, asking or
  denying; only the kill switches do.
- The app posts one notification per question (whatever the notification settings say, since an
  unanswered question denies). The banner shows, in this order: the AI agents in the chain, the
  headline, where the program really is and who signed it (`Program: <path> (<signer>)`, the signer
  being Apple, Apple-signed outside the system folders, a developer team, not signed by an
  identified developer, or not known), what allowing covers, and the chain. The coverage line names
  the app, not only the program: "Allow once (10 min) and Always allow cover: Terminal (any program
  run in it) reading SSH keys, only when the chain has no AI agent". An AI agent outside an app reads
  "(any program it runs)", a program outside any app "(and the Apple programs it starts)". A banner
  sent before the path or the names could be read is replaced once, quietly, when they can. Allow
  buttons on a banner need the Mac unlocked.
- Deny buttons say what the rule spares: "Always deny Terminal (any program run in it, except
  expected owners) any access to SSH keys", and on an alert "Block Terminal (…, except expected
  owners) from SSH keys from now on", because ssh run in Terminal keeps reading SSH keys.
- Open questions are listed in the menu bar (those holding an access first) and the Alerts tab, with
  the same identity and coverage lines. Questions and answers use an XPC connection of their own:
  `.asks` is read every second, every 250 ms while a question is open. The other connection reads
  status, alerts and the live tail every second, and settings, catalog, summaries and rules every
  10 s. A slow or refused history read never delays or hides a question, and the app
  reopens a connection the daemon did not take for the signed app (at once, then after 30 s,
  doubling up to 10 minutes).
- When the daemon does not take the app for the signed WhoRead app (an ad hoc or development build),
  the app shows "Limited view": it still lists questions (without path or command lines), can deny
  them, add block rules, and read status, settings, catalog and the agent list; alerts, the live
  feed, history and rules show the last data read, with the `sudo whoread …` command that shows them.
  When the daemon cannot be reached at all, no limited view is shown, since no questions arrive
  either.
- Settings has "Trust all Apple programs (not when started by an AI agent)"; saving other settings
  never changes it. The Rules tab shows an answer's agent scope and keeps it when you edit the rule.
- `whoread asks` lists questions with a PROGRAM column (the real path) next to the app name, and
  after the table, for each question, what allowing covers ("#ID allow-once / allow cover: …"). Paths
  are shown only with sudo. `whoread ask ID allow-once|allow|deny|block|trust-apple` answers
  (allowing needs sudo); `whoread settings set trust-apple on|off`; `whoread rules` shows the agent
  scope and expiry of answer rules; `whoread alerts` prints a `Program:` line under each open alert.
