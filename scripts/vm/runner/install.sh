#!/bin/bash
# Installs the WhoRead VM job runner (scripts/vm/runner/runner.sh) IN THE TEST VM, never on your
# main Mac: the runner runs whatever the host puts into the shared folder, as root. Run once in the
# VM, after mounting the shared repository at /Users/admin/wr (scripts/vm/README.md):
#   sudo bash /Users/admin/wr/whoread/scripts/vm/runner/install.sh
# Rerunning replaces the installation. The last line starts with "OK:" or "FAILED:".
#
# Normal case: a root LaunchDaemon (com.whoread.vmrunner) that mounts the share itself after a
# reboot. If it cannot read the share (privacy protection of the mount), the script grants Full
# Disk Access to the runner through the TCC database (SIP is off in the VM) and retries; if that
# does not help either, it falls back to a LaunchAgent in the test user's GUI session that runs each
# job as root through a sudoers rule for the runner alone. What it changes in the TCC database is
# recorded, and uninstall.sh (or the next install) puts those rows back as they were.
# Settings: WHOREAD_VM_USER (default: the user who ran sudo, else admin), WHOREAD_VM_MOUNT (default
# <that user's home>/wr), WHOREAD_VM_TAGS (default "whoread com.apple.virtio-fs.automount").
set -uo pipefail
fail() { echo "FAILED: $*"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "FAILED: run it with sudo"; exit 77; }
# The runner executes what appears in a shared folder as root: only ever in a throwaway VM. A VM:
# the hypervisor flag, or the model name of an Apple silicon VM (VirtualMac2,1).
is_vm() {
  [ "$(sysctl -n kern.hv_vmm_present 2>/dev/null)" = 1 ] && return 0
  case "$(sysctl -n hw.model 2>/dev/null)" in VirtualMac*) return 0 ;; esac
  return 1
}
is_vm || fail "this Mac is not a virtual machine (kern.hv_vmm_present is not 1, hw.model is $(sysctl -n hw.model 2>/dev/null)). The runner is only for the test VM."
HERE="$(cd "$(dirname "$0")" && pwd)"
VM_USER="${WHOREAD_VM_USER:-${SUDO_USER:-admin}}"
[ "$VM_USER" = root ] && VM_USER=admin
case "$VM_USER" in ''|*[!A-Za-z0-9_.-]*) fail "unexpected user name: $VM_USER" ;; esac
VM_UID=$(id -u "$VM_USER" 2>/dev/null) || fail "no user $VM_USER in this VM"
VM_HOME=$(dscl . -read "/Users/$VM_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
[ -n "$VM_HOME" ] || VM_HOME="/Users/$VM_USER"
MOUNT="${WHOREAD_VM_MOUNT:-$VM_HOME/wr}"
TAGS="${WHOREAD_VM_TAGS:-whoread com.apple.virtio-fs.automount}"

RUNNER=/usr/local/libexec/whoread-vmrunner.sh
CONF=/usr/local/etc/whoread-vmrunner.conf
LABEL=com.whoread.vmrunner
DAEMON_PLIST="/Library/LaunchDaemons/$LABEL.plist"
AGENT_LABEL=com.whoread.vmrunner.agent
AGENT_PLIST="/Library/LaunchAgents/$AGENT_LABEL.plist"
SUDOERS=/etc/sudoers.d/whoread-vmrunner
TCC_RECORD=/usr/local/etc/whoread-vmrunner.tcc
DAEMON_STATE=/var/run/whoread-vmrunner.state
AGENT_STATE=/tmp/whoread-vmrunner-agent.state
DAEMON_LOG=/var/log/whoread-vmrunner.log
AGENT_LOG=/tmp/whoread-vmrunner-agent.log

# launchctl bootout can return before the old runner has exited (stopping a running job takes it up
# to 10 s), and bootstrapping the label again while it is still there fails.
wait_gone() { # SERVICE-TARGET
  for _ in $(seq 80); do launchctl print "$1" >/dev/null 2>&1 || return 0; sleep 0.5; done
  return 1
}

# Whatever an earlier install left, in either mode.
launchctl bootout "system/$LABEL" 2>/dev/null
launchctl bootout "gui/$VM_UID/$AGENT_LABEL" 2>/dev/null
wait_gone "system/$LABEL" || fail "the runner $LABEL from an earlier install does not stop"
wait_gone "gui/$VM_UID/$AGENT_LABEL" || fail "the runner $AGENT_LABEL from an earlier install does not stop"
rm -f "$DAEMON_PLIST" "$AGENT_PLIST" "$SUDOERS" "$DAEMON_STATE" "$AGENT_STATE"
if [ -f "$TCC_RECORD" ]; then
  bash "$HERE/../tcc-fda.sh" --undo "$TCC_RECORD" \
    || fail "could not put back the Full Disk Access rows an earlier install changed ($TCC_RECORD)"
fi

install -d -m 755 -o root -g wheel /usr/local/libexec /usr/local/etc || fail "cannot create /usr/local/libexec"
install -m 755 -o root -g wheel "$HERE/runner.sh" "$RUNNER" || fail "cannot install $RUNNER"
printf 'VM_USER=%s\nMOUNT=%s\nTAGS=%s\nBEAT_EVERY=5\n' "$VM_USER" "$MOUNT" "$TAGS" > "$CONF" || fail "cannot write $CONF"
chown root:wheel "$CONF"
chmod 644 "$CONF"

# plist LABEL MODE LOG PATH [extra XML]
write_plist() {
  cat > "$4" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- WhoRead VM job runner (test VM only). Installed by scripts/vm/runner/install.sh. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$1</string>
	<key>ProgramArguments</key>
	<array>
		<string>$RUNNER</string>
		<string>$2</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>StandardOutPath</key>
	<string>$3</string>
	<key>StandardErrorPath</key>
	<string>$3</string>
	<key>ExitTimeOut</key>
	<integer>30</integer>
${5:-}
</dict>
</plist>
PLIST
  chown root:wheel "$4" && chmod 644 "$4" && plutil -lint "$4" >/dev/null
}

# wait_state FILE SECONDS: waits for "ok"; prints the last state seen.
wait_state() {
  local s=""
  for _ in $(seq "$2"); do
    s=$(cat "$1" 2>/dev/null)
    [ "$s" = ok ] && break
    sleep 1
  done
  echo "${s:-not started}"
}

show_log() { echo "--- last lines of $1:"; tail -n 15 "$1" 2>/dev/null; }

start_daemon() {
  rm -f "$DAEMON_STATE"
  launchctl bootstrap system "$DAEMON_PLIST" 2>/dev/null || launchctl kickstart -k "system/$LABEL"
}

write_plist "$LABEL" daemon "$DAEMON_LOG" "$DAEMON_PLIST" $'\t<key>KeepAlive</key>\n\t<true/>' \
  || fail "generated $DAEMON_PLIST is not a valid plist"
start_daemon
state=$(wait_state "$DAEMON_STATE" 30)

case "$state" in
  share-unreadable|share-unwritable|repo-missing)
    echo "The root runner cannot use the share ($state); granting Full Disk Access to it and retrying."
    if ( umask 077; bash "$HERE/../tcc-fda.sh" --record "$TCC_RECORD" "$RUNNER" /bin/bash ); then
      launchctl bootout "system/$LABEL" 2>/dev/null
      wait_gone "system/$LABEL" || fail "the runner $LABEL does not stop"
      start_daemon
      state=$(wait_state "$DAEMON_STATE" 30)
    fi ;;
esac

case "$state" in
  ok)
    grep -q '^mode: daemon' "$MOUNT/whoread/.vm/heartbeat" "$MOUNT/.vm/heartbeat" 2>/dev/null \
      || fail "the runner reports ok but no heartbeat appeared under $MOUNT"
    echo "OK: WhoRead VM runner installed as root LaunchDaemon $LABEL; share mounted at $MOUNT; log $DAEMON_LOG. On the host: scripts/vm/vmjob.sh ping"
    exit 0 ;;
  mount-failed)
    show_log "$DAEMON_LOG"
    echo "The runner stays installed and retries every 10 s. To let it mount the share, unmount the"
    echo "default shared-folder mount in this VM (or restart the VM with tart run --dir=whoread:<repo>:tag=whoread)."
    fail "the share could not be mounted at $MOUNT (see scripts/vm/README.md, step 3)" ;;
  share-unreadable|share-unwritable|repo-missing) ;;
  *)
    show_log "$DAEMON_LOG"
    fail "the runner did not start (state: $state)" ;;
esac

# Fallback: a LaunchAgent in the GUI session of $VM_USER (auto-login), jobs as root through sudo.
echo "The root runner still cannot use the share ($state); switching to a LaunchAgent for $VM_USER."
show_log "$DAEMON_LOG"
launchctl bootout "system/$LABEL" 2>/dev/null
wait_gone "system/$LABEL" || fail "the runner $LABEL does not stop"
rm -f "$DAEMON_PLIST"
launchctl print "gui/$VM_UID" >/dev/null 2>&1 \
  || fail "$VM_USER is not logged in to the VM's desktop (enable automatic login and log in), then rerun"
# Passwordless sudo for this one program only: it runs jobs from the share as root.
printf '%s ALL=(root) NOPASSWD: %s\n' "$VM_USER" "$RUNNER" > "$SUDOERS.tmp"
chmod 440 "$SUDOERS.tmp"
chown root:wheel "$SUDOERS.tmp"
visudo -cf "$SUDOERS.tmp" >/dev/null || { rm -f "$SUDOERS.tmp"; fail "the sudoers rule did not validate"; }
mv -f "$SUDOERS.tmp" "$SUDOERS"
write_plist "$AGENT_LABEL" agent "$AGENT_LOG" "$AGENT_PLIST" \
  $'\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n\t<key>LimitLoadToSessionType</key>\n\t<string>Aqua</string>' \
  || fail "generated $AGENT_PLIST is not a valid plist"
launchctl bootstrap "gui/$VM_UID" "$AGENT_PLIST" || fail "launchctl bootstrap gui/$VM_UID $AGENT_PLIST failed"
echo "If the VM shows a dialog asking whether bash or whoread-vmrunner.sh may access files, click Allow."
state=$(wait_state "$AGENT_STATE" 90)
if [ "$state" = ok ]; then
  echo "OK: WhoRead VM runner installed as LaunchAgent $AGENT_LABEL for $VM_USER (jobs run as root through sudo); log $AGENT_LOG. On the host: scripts/vm/vmjob.sh ping"
  exit 0
fi
show_log "$AGENT_LOG"
[ "$state" = repo-missing ] \
  && fail "something is mounted at $MOUNT, but neither $MOUNT/whoread nor $MOUNT holds the repository: start the VM with tart run --dir=whoread:<the repository> (scripts/vm/README.md, step 2)"
fail "the LaunchAgent runner cannot use the share either (state: $state); see scripts/vm/README.md, Troubleshooting"
