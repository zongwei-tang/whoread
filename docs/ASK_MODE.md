# Ask mode

Ask mode replaces the learning period. While enforcement is on, the first time a program touches
a sensitive file and nothing has decided that access yet, WhoRead holds the access and asks you.
Your answer is saved as a rule, so you are asked once per app × category × access (× AI agents in
the chain).

Enforcement is never switched off automatically.

## What is asked, what is not

For an access to a monitored file (every category, every severity), with enforcement active:

| Order | Case | Result |
|---|---|---|
| 1 | Directory listing / directory open | allowed (never blocked) |
| 2 | Never-block system daemons (name + platform flag + root-owned location) | allowed |
| 3 | An enforced deny rule matches (exceptions carve out, and count as answers) | denied |
| 4 | Allow rules cover every requested access kind on every touched category (your earlier answers are allow rules) | allowed |
| 5 | The process is an owner of the category **and no AI agent is in its chain** | allowed |
| 6 | The chain is a benign system service (Spotlight, Time Machine, iCloud, Quick Look, XProtect) | allowed |
| 7 | "Trust Apple programs" is on, and the leaf **and every ancestor up to launchd** are Apple programs in system locations, with no AI agent | allowed |
| 8 | Anything else | **asked** |

Details:
- A question names one category: the most severe one still undecided (ties: the first), and the
  access kinds requested on it. A read approval does not answer a write.
- A path allow rule that matches only because the target is an ancestor directory (moving the parent
  of a protected folder) does not answer for it.
- An "allow once" exception on a deny rule is not used up by an access that ends up asked.
- Alert rules and dry-run deny rules do not decide anything; they still alert, also after an answer
  covers the access (an answer only answers the question).
- Questions are never cached by Endpoint Security. Allows in ask mode are cached only when static
  allow rules cover both read and write (an ES-cached open allow covers later opens whatever their
  flags); allows by owner, benign service or Apple trust are never cached.

With enforcement off, or with the eslogger backend (which cannot hold or block), nothing can be
held. A first access is then recorded and alerted at once (no learning period), with the same
answers: "always allow" saves the same allow rule, "block from now on" a deny rule, "allow all Apple
programs" the setting. With the setting on, all-Apple chains raise no first-access alert either.

## Holding an access

Endpoint Security gives every AUTH message a deadline (Mach absolute time, per message; its length
is not documented and must be measured on a Mac: the M5 VM script prints it). Missing it gets the
daemon killed by the kernel, and the access is allowed. So an access is held only for a **budget**:

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

Accesses with the same key (`AskKey`: responsible app or agent, category, access kinds, AI agents
in the chain) share one question; answering it answers all of them. A later access with the same key
while the question is open waits for the same answer (no new notification). Unanswered questions
are forgotten an hour after their last attempt; at most 1024 are kept (the oldest that hold nothing
are dropped first). The `.asks` reply lists at most 200, those holding an access first when it is
cut; the app then withdraws no banners. Question ids never repeat across daemon restarts, so an
answer to an old banner cannot land on a new question.

Building a question on the ES callback is memory copies only; its argv is redacted on the broker's
queue, so it appears a moment after the question.

Held accesses are excluded from the latency statistics.

## Answers

| Answer | Saved as | Needs |
|---|---|---|
| Allow once | allow rule for 10 minutes (expired ones are pruned) | root or the signed app |
| Always allow | permanent allow rule | root or the signed app |
| Allow all Apple programs (offered only for all-Apple chains without an AI agent) | setting `trustApplePrograms = true` | root or the signed app |
| Deny | nothing (this access and the other held ones are denied) | console user |
| Always deny | enforced deny rule for that app or agent on the whole category, read and write, in every chain, platform binaries included (owners exempt); it also denies every open question of that app × category | console user |

Allow rules made from answers have the subject = the app or agent (cdhash-pinned for an unsigned
binary charged to itself), target = the category, access = the asked kinds, `chainAgents` = the AI
agents in the chain (`[]` = none), template `ask-answer`. `chainAgents` means "only those agents, or
none": an approval for Terminal (`[]`) never covers Claude Code running inside Terminal, and an
approval given while Claude Code was in the chain does not cover Codex. Answers are per app, not
per program: "always allow" for Terminal covers what you run in Terminal without an agent.

An AI agent runs as you and can run `whoread`: it can see questions and deny them (and, by polling
questions, make accesses wait for their budget instead of being denied at once), but allowing needs
your password or the signed app. Turning "trust Apple programs" off is open to the console user.

Answer rules count toward the 512-rule limit; at the limit an allow answer fails and the question
stays open. If saving fails (disk full) the rule still applies in memory and the held accesses are
released; the error is reported.

Answering an `ask` alert in the Alerts tab, or an alert from monitor-only mode, is the same as
answering the question. On an alert of a **rule's** block, "allow once" adds only the narrow
exception (that path, that access, one use, 10 minutes); "always allow" there adds the permanent
exception and also the app × category answer rule.

## No automatic switch-off

- Slow answers and missed deadlines never turn enforcement off. Deadline misses are counted; p99
  over `latencyP99ThresholdMs` for 3 consecutive checks logs a warning at most once a minute.
- If the daemon stops while AUTH is subscribed (the kernel killed it for a missed deadline, a crash,
  power loss), the next start keeps enforcement as you set it and reports the unclean stop
  (`DaemonStatus.uncleanStop`, kept until the next clean stop).
- One automatic "off" remains on purpose: if the stored rules cannot be read at start, enforcement
  stays off until they load or are replaced (with no rules everything would be asked, and answers
  could not be saved).
- The three manual kill switches still work: `sudo whoread enforcement off`, the app switch, the
  file `/Library/Application Support/WhoRead/disable-enforcement`.

Risk you accept with this: if a bug makes the daemon miss deadlines repeatedly, the kernel kills it
each time, launchd restarts it, and Endpoint Security may eventually refuse new connections. Only the
manual kill switches stop that loop. Under a flood the kernel also allows AUTH messages it drops
from a full queue (default deadline mode; the fail-closed mode needs macOS 27).

## What changes for the user

- No learning period. `learningDays` defaults to 0 (a stored old default of 7 is migrated to 0); the
  menu bar never shows "Learning". It shows "Enforcing" while enforcement is on, unless the source
  is in error or monitoring is paused. Pausing does not stop holding, asking or denying; only the
  kill switches do.
- The app posts one notification per question (whatever the notification settings say, since an
  unanswered question denies), naming the AI agents in the chain; open questions are listed in the
  menu bar (those holding an access first) and the Alerts tab. While questions are open it polls
  `.asks` every 250 ms (status, alerts and the live tail stay at 1 s). Allow buttons on a banner need
  the Mac unlocked.
- Settings has "Trust all Apple programs (not when started by an AI agent)"; saving other settings
  never changes it. The Rules tab shows an answer's agent scope and keeps it when you edit the rule.
- `whoread asks` lists questions; `whoread ask ID allow-once|allow|deny|block|trust-apple` answers
  (allowing needs sudo); `whoread settings set trust-apple on|off`; `whoread rules` shows the agent
  scope and expiry of answer rules.
