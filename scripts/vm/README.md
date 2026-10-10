# Test VM harness

Blocking (Endpoint Security AUTH events) is only ever tested in a macOS virtual machine with SIP
disabled, never on your Mac. This folder lets the host (also a sandboxed shell, without
ssh and without network) drive that VM through the folder Tart shares with it:

- **in the VM** a small runner (`runner/runner.sh`, installed once) picks up job scripts from
  `<repo>/.vm/jobs/`, runs each once as root with a timeout, and writes the output and exit code to
  `<repo>/.vm/results/`; it also writes `<repo>/.vm/heartbeat` (guest time, macOS version, SIP
  status) every 5 seconds;
- **on the host** `vmjob.sh` queues a job, streams its output and exits with its exit code. It never
  uses `sudo`.

`.vm/` is gitignored. The runner runs whatever appears in the shared folder as root, so it belongs in
the throwaway test VM only: `runner/install.sh`, `provision.sh`, `tcc-fda.sh`, `acceptance-m5.sh`
and `measure-overhead.sh` refuse to run outside a VM.

## One-time setup

The VM is `whoread-vm`, cloned from `ghcr.io/cirruslabs/macos-golden-gate-vanilla:latest` (user
`admin`, password `admin`, automatic login). It has no Xcode and no Command Line Tools; everything
here works with what macOS itself ships (bash, jq, perl, sqlite3, codesign, mdutil).

0. **Create the VM (once).** On the host, in Terminal:
   ```
   brew install cirruslabs/cli/tart
   tart clone ghcr.io/cirruslabs/macos-golden-gate-vanilla:latest whoread-vm
   ```
1. **Disable SIP in the VM (once).** On the host: `tart run --recovery whoread-vm`. In the VM window
   choose Options → Continue (sign in as admin / admin if asked), then in the menu bar Utilities →
   Terminal, and type:
   ```
   csrutil disable
   ```
   Confirm with `y` and the admin password, then Apple menu → Shut Down.
2. **Start the VM with the repository shared** (on the host, in Terminal, from the repository's main
   folder: the one that holds `.worktrees/`, not a worktree; leave it running):
   ```
   tart run --dir=whoread:"$PWD" whoread-vm
   ```
3. **Mount the share at a fixed place.** In the VM, open Terminal (⌘-Space, type Terminal) and type:
   ```
   mkdir -p /Users/admin/wr && mount_virtiofs com.apple.virtio-fs.automount /Users/admin/wr
   ```
   Check: `ls /Users/admin/wr/whoread/scripts/vm/runner` lists `install.sh`.
   - If `mount_virtiofs` fails, macOS has already mounted the shared folder on its own and holds it.
     In a Finder window's sidebar, under Locations, click the eject button next to that shared
     folder volume (the one that is not one of the VM's disks), then type the command again.
   - If it reports missing permission, type it again with `sudo ` in front of `mount_virtiofs`.
4. **Install the runner** (in the VM's Terminal):
   ```
   sudo bash /Users/admin/wr/whoread/scripts/vm/runner/install.sh
   ```
   The last line starts with `OK:`. If the VM asks whether bash or whoread-vmrunner.sh may access
   files, click Allow. Normally it installs a root LaunchDaemon. If that cannot read the share
   (privacy protection), it grants the runner Full Disk Access through the TCC database (SIP is off)
   and, failing that, falls back to a LaunchAgent in the admin session that runs each job as root
   through a sudoers rule for the runner alone. It records the TCC rows it writes; rerunning it
   (safe) or `uninstall.sh` puts them back as they were.
5. **Check from the host:**
   ```
   scripts/vm/vmjob.sh ping
   ```
   prints `VM runner alive` and the heartbeat (`sip: System Integrity Protection status: disabled.`).

After a VM restart the runner mounts the share at `/Users/admin/wr` by itself. If `vmjob.sh ping`
then finds no fresh heartbeat, macOS mounted the shared folder first: eject it as in step 3; the
runner retries every 10 seconds.

After a change to `scripts/vm/runner/` (a pull, another branch), run step 4 again: the VM runs the
copy `install.sh` made, not the file in the share. `vmjob.sh` queues nothing for a runner older than
itself; `run` and `ping` then exit with 69 and say so.

Optional, UNVERIFIED Tart syntax: if `tart run --help` documents a `tag=` option for `--dir`,
`--dir=whoread:"$PWD":tag=whoread` gives the share its own tag,
which macOS does not mount on its own; then mount it in step 3 with `mount_virtiofs whoread
/Users/admin/wr`. The runner tries the tag `whoread` first and `com.apple.virtio-fs.automount`
second.

## A test round (on the host, no sudo)

```
scripts/dev/sc-build.sh build                                        # host build into .build-sc/debug
scripts/vm/vmjob.sh run provision scripts/vm/provision.sh -- native  # last line: PROVISIONED: …
scripts/vm/vmjob.sh run m2 scripts/acceptance-m2.sh                  # M2/M4 records with the native source
scripts/vm/vmjob.sh run overhead scripts/vm/measure-overhead.sh      # M4 overhead
scripts/vm/vmjob.sh run m5 scripts/vm/acceptance-m5.sh -- --stop-test
```

Run them from the checkout you want to test: a worktree under `.worktrees/` is inside the shared
folder, so its own build and scripts are used. `provision.sh` installs that checkout's
`.build-sc/debug/whoreadd` and `whoread` with `scripts/install-dev-daemon.sh --bin`, signs the
installed whoreadd ad hoc with the Endpoint Security entitlement (the build in `.build-sc/debug`
never carries one), grants it Full Disk Access by writing the VM's TCC
database (`tcc-fda.sh`, which detects the table's columns at run time), creates
`/Users/admin/WhoReadTestVault` as admin, reports Spotlight's indexing state, and reports the
daemon's status. `-- eslogger` provisions the monitor-only source instead.

- The jobs run as root, so the acceptance scripts read the recorded history as root (reading it
  needs root or the signed app) and make every vault access as admin (`sudo -u admin`; Spotlight's
  import through `launchctl asuser`).
- `acceptance-m5.sh` leaves enforcement as it found it. While it runs, the WhoRead app must not be
  open in the VM: it answers questions, and M5 checks that an unanswered question is denied at once
  when no app polls.
- `measure-overhead.sh` warns when Spotlight is busy (its numbers are then noisy).

Other useful jobs:
```
scripts/vm/vmjob.sh shell 'whoread status'
scripts/vm/vmjob.sh shell 'tail -n 50 /Library/Logs/WhoRead/whoreadd.log'
scripts/vm/vmjob.sh list                       # queued, running and recent jobs
scripts/vm/vmjob.sh result ID [--wait]         # output and exit code of an earlier job
```

## If provisioning reports a problem

- **Full Disk Access could not be granted automatically**, or the daemon reports NOT_PERMITTED. In
  the VM: System Settings → Privacy & Security → Full Disk Access → **+** → ⌘⇧G →
  `/usr/local/libexec/whoreadd` → Open → switch it on. Then provision again. A grant made there is
  tied to the signature of that build: after every new build, select whoreadd in that list, remove
  it with **−**, and add it again as above. (The automatic grant writes a row without a code
  requirement, which should survive re-signing; UNVERIFIED on macOS 27, as is whether root may
  write the TCC database with SIP off. The daemon's status, which provision prints, is the real
  test.)
- **AMFI refuses the ad hoc Endpoint Security entitlement** (the daemon is killed at launch or the
  log says NOT_ENTITLED). `scripts/vm/vmjob.sh run provision scripts/vm/provision.sh -- native
  --amfi-boot-arg` sets `amfi_get_out_of_my_way=1` in the VM's boot-args and restarts the VM after a
  minute; when `vmjob.sh ping` answers again (eject the automatic share mount if it does not, see
  above), provision once more. Whether a Tart VM accepts that boot-arg is UNVERIFIED; if `nvram`
  refuses, the job says so.
- **Spotlight indexing disabled** (provision prints `mdutil -s /`): the Spotlight check of
  `acceptance-m2.sh` then reports INCOMPLETE. To test it, switch indexing on with
  `scripts/vm/vmjob.sh shell 'mdutil -i on /'`, wait until `measure-overhead.sh` no longer reports
  Spotlight as busy, and run `acceptance-m2.sh` again.

## Jobs

- A job carries a copy of the script as it was when `vmjob.sh` queued it; in the VM that copy runs
  from a folder only root can read, so editing the script afterwards (also while the job waits or
  runs) changes nothing. A script inside the shared folder runs with `$0` its path there, so paths
  relative to `$0` work; the other files it uses are read from the share when it uses them. Any
  other script, and `shell` commands, start in the shared folder. Arguments go after `--`.
- Scripts run with `/bin/bash`: one whose `#!` line names another interpreter, or options
  (`#!/bin/bash -e`; use `set -e` in the script instead), is refused (exit code 64), as is one
  holding a line `WHOREAD_VM_END_OF_SCRIPT` (it ends the copy).
- Jobs run as root, one at a time, in their checkout, with a clean environment: `PATH` includes
  `/usr/local/bin`, `WHOREAD_LANG=en`, `WHOREAD_TEST_USER=admin`, `WHOREAD_VM_SHARE` (the shared
  folder in the VM) and `WHOREAD_VM_REPO` (the checkout). Accesses to the test vault must run as the
  test user (`sudo -u "$WHOREAD_TEST_USER"`): the acceptance scripts do that when they run as root.
- Timeout: `--timeout N`, else a `# timeout: N` line among the script's first 20 lines, else 900 s.
  At the timeout the job's process group and every descendant get SIGTERM, 10 s later SIGKILL; exit
  code 124. Only time the VM runs counts: while the Mac sleeps the VM is paused, and the jump of
  its clock on waking uses up neither the job's timeout nor the time `vmjob.sh` waits.
- A job is renamed out of `jobs/` before it starts, so it never runs twice, also across runner or VM
  restarts. If the runner is stopped while a job runs (the VM shuts down, `install.sh` runs again),
  it stops the job and records it as interrupted (exit code 125); a job that had just ended keeps
  its own exit code. Neither is run again. If the job is still running when the next runner starts
  (a runner killed outright leaves the job's process group behind), that runner stops it first,
  identified by pid and start time, so it cannot overlap with the next job.
- If the heartbeat stops, `vmjob.sh` gives up instead of waiting out the timeout (exit code 69): a
  job the runner has not taken yet is withdrawn and never runs; for a running one, look later with
  `vmjob.sh result ID --wait`.
- The shared directory is the main checkout (also when `vmjob.sh` runs from a worktree);
  `WHOREAD_VM_HOST_DIR` overrides it.
- `selftest.sh` checks all of this on the host without a VM (runner in test mode, fake daemon for
  `acceptance-m2.sh`, TCC schemas of several macOS releases).

## Troubleshooting

- `vmjob.sh ping` finds no heartbeat: the runner is not installed, or the share is not mounted at
  `/Users/admin/wr`. In the VM: `sudo tail -n 30 /var/log/whoread-vmrunner.log` and
  `cat /var/run/whoread-vmrunner.state`.
- State `mount-failed` (often after a VM restart): macOS mounted the shared folder on its own first.
  Eject it in Finder (step 3); the runner mounts the share within 10 seconds.
- LaunchAgent fallback: the log is `/tmp/whoread-vmrunner-agent.log`; it needs admin logged in
  (automatic login is on in the image).
- `measure-overhead.sh` stops the daemon while it measures. If that job was killed outright, start
  the daemon again: `scripts/vm/vmjob.sh shell 'launchctl bootstrap system /Library/LaunchDaemons/com.whoread.daemon.plist'`.
- Remove the runner: `sudo bash /Users/admin/wr/whoread/scripts/vm/runner/uninstall.sh` (in the VM).
  It also puts back the TCC rows `install.sh` wrote; the last line starts with `OK:` or `FAILED:`.
