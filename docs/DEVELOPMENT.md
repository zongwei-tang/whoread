# Development

Everything that needs `sudo`, System Settings, SIP, a VM or an Apple account is marked **(manual)**.

## Hosts

| Host | What runs there |
|---|---|
| Any (Linux CI, Linux, Mac) | `swift build`, `swift test` (Core, Store, IPC, Engine, UI models), the daemon with the replay source, CLI over the dev socket, `scripts/dev/e2e-dev-socket.sh` |
| Your Mac | Xcode builds, the app, the **eslogger** backend (monitor only) |
| macOS VM, SIP disabled | the **native** Endpoint Security client, AUTH/enforcement (M4/M5). **Never** on your main Mac. |

## Build and test

```bash
scripts/test-core.sh                 # swift build + swift test
swift build -c release               # whoreadd, whoread
.build/release/whoread replay Tests/Fixtures/eslogger/schema-v1-msgv10/scenario.jsonl --home /Users/alice --defaults Data
scripts/dev/e2e-dev-socket.sh        # daemon + fake eslogger + CLI, no root needed
```

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
automatic signing fails until Apple has granted that capability to the team (requested at M6,
DISTRIBUTION.md §2). Until then build with `WHOREAD_NO_ES=1 scripts/build.sh`: every target is
team-signed without entitlements, with the same limits as the no-team build.

Regenerating data and fixtures:
```bash
python3 scripts/dev/gen_catalog.py    # Data/catalog.json, agents.json, benign.json
python3 scripts/dev/gen_fixtures.py   # Tests/Fixtures/eslogger/*/scenario.jsonl
```

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
3. `scripts/capture-fixture.sh`: 60 s of eslogger (asks for sudo once), sanitized into
   `Tests/Fixtures/eslogger/captured/macos-<ver>/capture.jsonl`. Review it before committing.

## M2: eslogger dev daemon on the Mac (manual)

```bash
swift build -c release
sudo scripts/install-dev-daemon.sh eslogger
```
Then:
1. System Settings → Privacy & Security → Full Disk Access → **+** → ⌘⇧G →
   `/usr/local/libexec/whoreadd` → enable it.
2. Restart the daemon and run the acceptance script:
   ```bash
   sudo launchctl kickstart -k system/com.whoread.daemon
   scripts/acceptance-m2.sh
   ```
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

The app may weaken protection (Settings, rules, Pause, Allow once / Always allow, Ignore, Mark
read) only when the daemon recognises its code signature. The dev daemon does that only when it is
given both requirements, and a client requirement also rejects the ad-hoc `swift build` CLI, so
install the team-signed products of the same Xcode build:
```bash
WHOREAD_NO_ES=1 scripts/build.sh      # needs DEVELOPMENT_TEAM in Xcode/Local.xcconfig
P="$PWD/build/DerivedData/Build/Products/Debug"
TEAM=ABCDE12345 PREFIX=com.yourname   # the values from Xcode/Local.xcconfig
sudo WHOREAD_BIN="$P" \
  WHOREAD_CLIENT_REQUIREMENT="anchor apple generic and certificate leaf[subject.OU] = \"$TEAM\"" \
  WHOREAD_APP_REQUIREMENT="identifier \"$PREFIX.whoread\" and anchor apple generic and certificate leaf[subject.OU] = \"$TEAM\"" \
  scripts/install-dev-daemon.sh eslogger
open "$P/WhoRead.app"
```
- The script checks that `$P/whoread` satisfies the client requirement and refuses
  `WHOREAD_APP_REQUIREMENT` without `WHOREAD_CLIENT_REQUIREMENT` (it would have no effect).
- `WHOREAD_NO_ES=1` is needed until the team has the Endpoint Security capability (see "Build and
  test"); the app does not need the extension for M3.
- It re-signs `whoreadd` ad hoc without entitlements for the eslogger source (the ES
  entitlement of the Xcode build needs a provisioning profile). Full Disk Access is probably tied
  to that signature (UNVERIFIED): if eslogger reports NOT_PERMITTED after a reinstall, grant it
  again.
- Without the requirements (or with an ad-hoc app), the app can read everything but every
  weakening action is refused; use `sudo whoread …` for those.

## M4/M5: test VM with SIP disabled (manual)

1. Create a macOS VM.
   - **Tart**:
     ```bash
     brew install cirruslabs/cli/tart
     tart clone ghcr.io/cirruslabs/macos-sequoia-base:latest whoread-vm
     tart run whoread-vm
     ```
   - **UTM**: create a macOS VM from an IPSW.
2. Disable SIP inside the VM: shut it down and boot it into recovery (Tart:
   `tart run --recovery whoread-vm`; UTM: hold the power button / choose Options). Open Terminal
   from the Utilities menu and run:
   ```
   csrutil disable
   ```
   Reboot, and check with `csrutil status`.
3. In the VM: install Xcode command line tools (or Xcode), clone the repo,
   `scripts/create-test-vault.sh`, then:
   ```bash
   swift build -c release
   sudo scripts/install-dev-daemon.sh native
   ```
   This ad-hoc signs whoreadd with the ES entitlement. Whether ad-hoc signing is enough with SIP
   off is UNVERIFIED; if `es_new_client` returns NOT_ENTITLED, sign with your development
   certificate, or add `amfi_get_out_of_my_way=1` to the VM's boot-args (VM only).
4. Full Disk Access for `/usr/local/libexec/whoreadd` in the VM, then
   `sudo launchctl kickstart -k system/com.whoread.daemon`.
5. M4:
   ```bash
   scripts/acceptance-m2.sh
   scripts/vm/measure-overhead.sh
   ```
   `acceptance-m2.sh` should produce the same records as on the host.
6. M5:
   ```bash
   scripts/vm/acceptance-m5.sh [--stop-test]
   ```
   Record the latencies, the ask-mode hold budget it prints and the pending-AUTH behaviour in
   docs/STATUS.md. The SIGKILL step expects enforcement still on after launchd restarts the daemon,
   with `uncleanStop` set in `whoread status` (enforcement is never switched off automatically).

## System extension in development (manual)

- Uninstall the dev LaunchDaemon first (`sudo scripts/uninstall-dev-daemon.sh`), in the VM too
  after M4/M5. Only one daemon may use `/Library/Application Support/WhoRead`; a second one
  refuses to start.
- The app must be launched from `/Applications`. Alternatively, run `systemextensionsctl developer
  on`, which third-party reports say needs SIP off on macOS 13+.
- Approve the extension in System Settings → General → Login Items & Extensions, then give it
  Full Disk Access.
- CLI: `sudo ln -sf /Applications/WhoRead.app/Contents/Helpers/whoread /usr/local/bin/whoread`.
  The extension accepts only clients signed by your team.
- Log: `/Library/Logs/WhoRead/extension.log` (root only).
- An extension built without a team cannot pin its requirements to a team, so it drops them:
  any local client may connect, no app is recognised, and weakening needs `sudo`.
- `systemextensionsctl list` shows its state. `systemextensionsctl uninstall <team> <bundle>`
  needs SIP off.

## Conventions

- No third-party dependencies in the core. The package uses only Foundation, SQLite3 and (macOS)
  EndpointSecurity, Security and SystemExtensions.
- Code written on a non-Mac host that has not been compiled yet carries a `NOT YET COMPILED`
  comment at the top and a `[~]` in docs/STATUS.md until it has been compiled on a Mac.
- Each milestone ends with tests passing, an updated docs/STATUS.md and a commit.
