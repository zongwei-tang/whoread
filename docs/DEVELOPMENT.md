# Development

Everything that needs `sudo`, System Settings, SIP, a VM or an Apple account is marked **(manual)**.

## Hosts

| Host | What runs there |
|---|---|
| Any Mac, and CI (GitHub's macOS 15, 26 and 27 runners: `macos-15`, `macos-latest`, `xcode-27`) | `swift build`, `swift test` (Core, Store, IPC, Engine, UI models), the daemon with the replay source, the CLI over the dev socket, `scripts/dev/e2e-dev-socket.sh`, Xcode builds of every target |
| Your Mac | the app, the **eslogger** backend (monitor only) |
| macOS VM, SIP disabled | the **native** Endpoint Security client, AUTH/enforcement (M4/M5), driven from the host by `scripts/vm/` ([README](../scripts/vm/README.md)). **Never** on your main Mac. |

The libraries keep Linux code paths (no Endpoint Security, no XPC), but nothing builds or tests
them on Linux.

## Build and test

```bash
scripts/test-core.sh                 # swift build --build-tests + swift test
swift build -c release               # whoreadd, whoread
.build/release/whoread replay Tests/Fixtures/eslogger/schema-v1-msgv10/scenario.jsonl --home /Users/alice --defaults Data
scripts/dev/e2e-dev-socket.sh        # daemon + fake eslogger + CLI, no root needed
scripts/ci/run-ci.sh REPORT.txt      # every check CI runs, with a plain-text report
```
Run `replay` (and any `whoreadd` you start by hand) as yourself: a daemon running as root reads
default data only from directories only root can change, so it refuses the repository's `Data/`.

`scripts/ci/run-ci.sh` is what CI runs: `swift build` and `swift test`, the dev-socket e2e,
XcodeGen and `xcodebuild` of every target (ad hoc), `shellcheck -S warning` and `bash -n` over
`scripts/`, the ES stub check, the VM harness self-test, the app bundle test,
`eslogger --list-events` and, on CI only (passwordless sudo), `scripts/ci/install-acceptance.sh`: a
real install with `scripts/install.sh`, the CLI and the app against the installed daemon, the M2
acceptance where the runner lets eslogger run, then `scripts/uninstall.sh --purge` and a check that
nothing is left. The workflow runs on GitHub's hosted macOS runners for pushes to `main` and `dev`,
only while the repository is public; GitHub retired its macOS 14 image on 2026-11-02, so macOS 14
is no longer tested there.

Inside a file-system sandbox that allows writes only to `$TMPDIR` and the repository (some editor
and agent sandboxes do), SwiftPM and `xcodebuild` fail; build with plain `swiftc` instead:
```bash
scripts/dev/sc-build.sh build                   # libraries, whoreadd, whoread into .build-sc/debug
scripts/dev/sc-build.sh test [FILTER]           # and the four test bundles (FILTER: WhoReadCoreTests.AnalyzerTests/testX)
scripts/dev/sc-build.sh app                     # .build-sc/debug/WhoRead.app with the CLI and the extension, ad hoc signed
WHOREAD_ENTITLED=1 scripts/dev/sc-build.sh app  # the same with the restricted entitlements, in .build-sc/debug/entitled
scripts/dev/sc-app-test.sh [--unit]             # tests of the app mode and the xcconfig resolver
```
- Nothing in `.build-sc/debug` itself carries an entitlement: AMFI kills an ad hoc binary that claims
  a restricted one on a Mac with SIP on. A plain build strips one an earlier entitled build left
  there. The `entitled` copies are for the SIP-disabled VM only.
- The app mode signs inside-out with the hardened runtime and verifies the result (plists,
  identifiers, signatures, entitlements, linked libraries); it never launches anything. `actool`
  cannot run inside such a sandbox, so the asset catalog is then skipped.
- These are debug builds (`-Onone`, host architecture only): timings measured with them are
  debug numbers.
- Tests that bind a Unix socket skip themselves where the sandbox forbids it; they run on CI or an
  unsandboxed Mac.

Xcode (Mac):
```bash
brew install xcodegen
cp Xcode/Local.xcconfig.example Xcode/Local.xcconfig   # set DEVELOPMENT_TEAM, BUNDLE_ID_PREFIX
scripts/build.sh                      # generates Xcode/WhoRead.xcodeproj and builds all targets
```
Products land in `build/DerivedData/Build/Products/Debug/`; the app embeds the CLI as
`WhoRead.app/Contents/Helpers/whoread`. Without a team, `build.sh` signs ad hoc and drops all
entitlements (restricted ones need a provisioning profile, so the binaries would not launch).
Such an app runs against the dev daemon but cannot install the system extension.

With a team, `whoreadd` and the embedded extension claim the Endpoint Security entitlement, so
automatic signing fails until Apple has granted that capability to the team (DISTRIBUTION.md §2).
Until then build with `WHOREAD_NO_ES=1 scripts/build.sh`: every target is team-signed without
entitlements, with the same limits as the no-team build.

Regenerating data and fixtures:
```bash
python3 scripts/dev/gen_catalog.py    # Data/catalog.json, agents.json, benign.json
python3 scripts/dev/gen_fixtures.py   # Tests/Fixtures/eslogger/*/scenario.jsonl
```

Other checks:
```bash
scripts/verify-sdk.sh [OUTPUT]                        # the SDK's view of every ES, libproc and libbsm symbol used (no root)
scripts/dev/es-typecheck/check-stub.sh [--self-test]  # the Linux ES stub against the real SDK
scripts/vm/selftest.sh                                # the VM job harness, without a VM
scripts/dev/secret-scan.py [--worktree]               # keys, tokens and local paths before publishing
```
`check-stub.sh` needs the macOS 27 SDK (Xcode 27) and skips with exit 0 on older ones. It requires
every stub declaration to have exactly the SDK's type and every constant its value; `--self-test`
checks that each of its one-declaration mutations is rejected (run it after changing
`gen_stub_checks.py`).

## The test vault

All automated tests read and write only `~/WhoReadTestVault/`, never real credentials.
```bash
scripts/create-test-vault.sh          # fake keys/credentials (throwaway ed25519 key, AWS example creds)
```

## M0 on the Mac (manual)

1. `scripts/verify-sdk.sh`: records the local SDK declarations and `eslogger --list-events`
   into `docs/research/sdk-verification-<ver>.txt`. No sudo.
2. Full Disk Access for your terminal: System Settings → Privacy & Security → Full Disk Access →
   enable Terminal (or iTerm).
3. Stop AI agents and anything else running as you, and do not run this from an agent's session.
   Code running as you cannot open the raw capture, but it could edit the script while it runs or
   replace the `whoread` it builds, and so receive the raw stream under your `sudo` ticket. Then run
   `scripts/capture-fixture.sh`. It:
   - builds this checkout's `whoread` (`swift build -c release --product whoread`), never one
     found on `PATH`;
   - records 60 s of eslogger (asks for sudo once) with the event list the daemon uses, while
     exercising the test vault;
   - keeps the raw capture (every file the Mac opened, and the environment of every exec) in a
     fresh root-only directory under `/private/tmp`, and removes it on every exit (`KEEP_RAW=1`
     keeps it, still root-only, and prints how to remove it);
   - sanitizes it into `Tests/Fixtures/eslogger/captured/macos-<ver>/capture.jsonl`: the vault
     events of the script's own processes (and of Apple programs that name nothing but system and
     vault paths), a small sample of events on the system volume, the home and user name rewritten,
     exec environments dropped.

   Review the fixture before committing it.

## M2: eslogger dev daemon on the Mac (manual)

```bash
swift build -c release
sudo scripts/install-dev-daemon.sh eslogger
```
The script builds nothing: it installs `whoreadd` and `whoread` from `--bin DIR` (or
`WHOREAD_BIN`), else from the first of `.build/release`, `.build/debug` and `.build-sc/debug` that
holds both. It changes nothing and names the fix when the data directory or its `defaults/`, or
`/usr/local`, is a link, not root's, writable by group or others, or has an ACL allow entry, and when
someone other than root could add, remove or rename entries in `/Library/Logs`. It never follows or
adopts what someone else left at the log: at `/Library/Logs/WhoRead` and its `whoreadd.log`, a link,
another user's entry, one others can write or with an ACL allow entry, a log with a second name, or a log
others could read (an earlier install's 0644) is renamed aside to `<name>.untrusted-<time>-<pid>-<n>`,
and a 0700 directory with a 0600 log takes its place.

Then:
1. System Settings → Privacy & Security → Full Disk Access → **+** → ⌘⇧G →
   `/usr/local/libexec/whoreadd` → enable it.
2. Restart the daemon and run the acceptance script as root (its probes still run as you):
   ```bash
   sudo launchctl kickstart -k system/com.whoread.daemon
   sudo scripts/acceptance-m2.sh
   ```
   Reading the recorded accesses needs root (or the signed app), so the script stops when it is not
   root. It needs `jq` (part of macOS 15 and later; on 14: `brew install jq`). `sudo` drops
   Homebrew's folders from `PATH`; to include the node probe, run
   `sudo env PATH="$PATH" scripts/acceptance-m2.sh`. Each probe's recorded chain must be the script's
   real ancestry as `ps` shows it: up to launchd, or up to a process that was already running when
   the daemon started and whose parent is launchd now (a Terminal window opened before), with the
   ancestry above it marked unknown (THREAT_MODEL.md, "Unknown ancestry").
3. Owner apps are pinned to the team IDs `codesign -dv` reports for the apps installed here. The
   daemon does this in memory at every start and after catalog changes (unresolved third-party
   apps are not owners, so they alert). To see what it finds:
   ```bash
   sudo whoread catalog resolve-owners
   ```
   Nothing is written. After installing an owner app, restart the daemon
   (`sudo launchctl kickstart -k system/com.whoread.daemon`).

Logs: `/Library/Logs/WhoRead/whoreadd.log`, root only (`sudo tail -f …`): it holds alert
headlines and process chains of every user. Remove with
`sudo scripts/uninstall-dev-daemon.sh [--purge]`.

`install-dev-daemon.sh` refuses to run while the WhoRead system extension is active: only one
daemon may use `/Library/Application Support/WhoRead`. For the same reason
`uninstall-dev-daemon.sh --purge` removes nothing while the extension is active.

If eslogger reports NOT_PERMITTED although whoreadd has FDA, also add `/usr/bin/eslogger` to Full
Disk Access. Which process TCC treats as responsible for a LaunchDaemon's child is unverified
(see RESEARCH.md).

## M3: the signed app against the dev daemon (manual)

The app may read the recorded history and weaken protection (Settings, rules, Pause, Allow once /
Always allow, Ignore, Mark read) only when the daemon recognises its code signature. The dev
daemon does that only when it is given both requirements, and a client requirement also rejects the
ad-hoc `swift build` CLI, so install the team-signed products of the same Xcode build:
```bash
WHOREAD_NO_ES=1 scripts/build.sh      # needs DEVELOPMENT_TEAM in Xcode/Local.xcconfig
P="$PWD/build/DerivedData/Build/Products/Debug"
TEAM=ABCDE12345 PREFIX=com.yourname   # the values from Xcode/Local.xcconfig
sudo WHOREAD_BIN="$P" \
  WHOREAD_CLIENT_REQUIREMENT="(identifier \"$PREFIX.whoread.cli\" or identifier \"$PREFIX.whoread\") and anchor apple generic and certificate leaf[subject.OU] = \"$TEAM\"" \
  WHOREAD_APP_REQUIREMENT="identifier \"$PREFIX.whoread\" and anchor apple generic and certificate leaf[subject.OU] = \"$TEAM\"" \
  scripts/install-dev-daemon.sh eslogger
open "$P/WhoRead.app"
```
- The script checks that `$P/whoread` satisfies the client requirement and refuses
  `WHOREAD_APP_REQUIREMENT` without `WHOREAD_CLIENT_REQUIREMENT` (it would have no effect).
- Write comments in a requirement as `/* … */`. A `//` or `#` comment, or a trailing `;`, parses
  on its own but breaks the `(client) and (app)` requirement the app's connection gets: the daemon
  logs an error at start and never recognises the app.
- The daemon logs a warning that the app requirement does not pin Developer ID. Development builds
  carry get-task-allow, so code running as you could drive such an app: this setup is for
  development only.
- `WHOREAD_NO_ES=1` is needed until the team has the Endpoint Security capability (see "Build and
  test"); the app does not need the extension for M3.
- It re-signs `whoreadd` ad hoc without entitlements for the eslogger source (the ES
  entitlement of the Xcode build needs a provisioning profile). Full Disk Access is probably tied
  to that signature (UNVERIFIED): if eslogger reports NOT_PERMITTED after a reinstall, grant it
  again.
- An app the daemon does not recognise (ad hoc, unsigned, or no requirements given) gets a limited
  view: status, settings, catalog, the agent list and the open questions without their file paths
  or command lines. It can deny questions and add block rules; the history tabs say they cannot be
  shown there, and every weakening action is refused (use `sudo whoread …` for those). For UI work
  without signing, start a dev daemon with `whoreadd run --permissive` (development only: every
  local peer may do anything).

## M4/M5: test VM with SIP disabled (manual)

Blocking (AUTH) is only ever tested in a macOS VM with SIP disabled. The VM is driven from the host
by a small job runner over the folder Tart shares with it: no ssh, no network, nothing is built in
the VM. Set it up once as [scripts/vm/README.md](../scripts/vm/README.md) describes (create the Tart
VM, disable SIP, share the repository, install the runner), then, on the host:
```bash
scripts/dev/sc-build.sh build                                        # the VM installs the host's build
scripts/vm/vmjob.sh run provision scripts/vm/provision.sh -- native  # native dev daemon, FDA, test vault
scripts/vm/vmjob.sh run m2 scripts/acceptance-m2.sh                  # M4: the M2 records with the native source
scripts/vm/vmjob.sh run overhead scripts/vm/measure-overhead.sh      # M4: overhead on unmonitored paths
scripts/vm/vmjob.sh run m5 scripts/vm/acceptance-m5.sh -- --stop-test
```
- `acceptance-m2.sh` should produce the same records as on the host.
- M5 checks a deny rule and attempts to get around it, other spellings, permission, owner, ACL and
  mount changes, truncate and swaps, the AI agent template, the latencies and the deadline miss
  mode (fail-closed on macOS 27 and later, kill before), the three kill switches, the daemon killed
  with SIGKILL (launchd restarts it still enforcing, with `uncleanStop` set in `whoread status`:
  enforcement is never switched off automatically), and ask mode: an undecided access is denied at
  once while no app polls, held and let through by an answer while something polls, and denied when
  its hold budget runs out.
- `--stop-test` also freezes the daemon (SIGSTOP) during an AUTH request: before macOS 27 the
  kernel kills it at the deadline and allows the access; in fail-closed mode the access is denied
  at the deadline and the daemon lives.
- Note the latencies, the hold budget and the stop-test behaviour M5 prints with the test results.
- M5 leaves enforcement as it found it. While it runs, the WhoRead app must not be open in the VM:
  it would answer questions.

## System extension in development (manual)

- Uninstall the dev LaunchDaemon first (`sudo scripts/uninstall-dev-daemon.sh`), in the VM too
  after M4/M5. Only one daemon may use `/Library/Application Support/WhoRead`; a second one
  refuses to start.
- Without a team, `WHOREAD_ENTITLED=1 scripts/dev/sc-build.sh app` builds an ad hoc bundle with the
  restricted entitlements for the SIP-disabled VM. Its Mach service name starts with "." (no team),
  so that app talks to the dev daemon, not to the extension; whether a team-less, ad hoc system
  extension activates at all is UNVERIFIED.
- The app must be launched from `/Applications`. Alternatively, run `systemextensionsctl developer
  on`, which third-party reports say needs SIP off on macOS 13+.
- Approve the extension in System Settings → General → Login Items & Extensions, then give it
  Full Disk Access.
- CLI: `sudo ln -sf /Applications/WhoRead.app/Contents/Helpers/whoread /usr/local/bin/whoread`.
  The extension accepts only clients signed by your team.
- The Debug configuration of the extension is the development path: it recognises any build of the
  app signed by the team, Apple Development builds included (debuggable). Release, and any
  configuration but Debug, pins Developer ID and refuses code with get-task-allow, disabled library
  validation or DYLD environment variables; a Debug app cannot even connect to a Release extension.
- An extension built without a team cannot pin its requirements to a team, so it drops them:
  any local client may connect, no app is recognised, and weakening needs `sudo`.
- The extension runs as root, so it reads its bundled `Contents/Resources/Data` only when no one but
  root can change those files and the directories above them, and refuses to start otherwise (which
  leaves nothing monitored). A checkout or copy made under umask 002 keeps group-writable files:
  build with umask 022, or `chmod go-w` the bundled `Data`. Whether macOS keeps the bundle's modes
  when it installs the extension is UNVERIFIED.
- Log: `/Library/Logs/WhoRead/extension.log` (root only). A link, another user's file, a file with a
  second name or with an ACL allow entry at that path is moved aside, never followed; when no safe log
  file can be had, the extension says why in the unified log (subsystem `com.whoread.extension`).
- `systemextensionsctl list` shows its state. `systemextensionsctl uninstall <team> <bundle>`
  needs SIP off.

## Conventions

- No third-party dependencies. The package uses only Foundation, SQLite3 and (macOS)
  EndpointSecurity, libbsm and Security; the app adds SwiftUI, AppKit, UserNotifications and
  SystemExtensions.
- Every change comes with tests, and the full suite passes before it is merged into `main`.
- Shell scripts pass `shellcheck -S warning` (CI checks it).
- Development happens on `dev`; `main` only receives tested releases.
