#!/bin/bash
# Removes the WhoRead VM job runner from the test VM (whichever mode install.sh chose). In the VM:
#   sudo bash /Users/admin/wr/whoread/scripts/vm/runner/uninstall.sh
# Puts back the Full Disk Access rows install.sh changed in the TCC database. Leaves the share
# mounted and <repo>/.vm (job results) in place. The last line starts with "OK:" or "FAILED:".
# WHOREAD_VM_RUNNER_TEST=1 (scripts/vm/selftest.sh on the host): no root; every system path lies
# under WHOREAD_VM_RUNNER_TEST_ROOT, the TCC database included, and launchctl is
# WHOREAD_VM_RUNNER_TEST_LAUNCHCTL (a stand-in; none: the runner counts as not loaded).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
R=""
LAUNCHCTL=launchctl
if [ -n "${WHOREAD_VM_RUNNER_TEST:-}" ]; then
  R="${WHOREAD_VM_RUNNER_TEST_ROOT:?WHOREAD_VM_RUNNER_TEST_ROOT must name the stand-in root}"
  LAUNCHCTL="${WHOREAD_VM_RUNNER_TEST_LAUNCHCTL:-}"
else
  [ "$(id -u)" -eq 0 ] || { echo "run it with sudo" >&2; exit 77; }
fi
lc() { [ -n "$LAUNCHCTL" ] || return 1; "$LAUNCHCTL" "$@"; }
VM_USER="${WHOREAD_VM_USER:-${SUDO_USER:-admin}}"
[ "$VM_USER" = root ] && VM_USER=admin
VM_UID=$(id -u "$VM_USER" 2>/dev/null || echo 501)
TCC_RECORD="$R/usr/local/etc/whoread-vmrunner.tcc"

# launchctl bootout returns before the runner has exited: it first stops a running job (up to 10 s)
# and records its result in the share, for which it may still need the access put back below.
wait_gone() { # SERVICE-TARGET
  for _ in $(seq 80); do lc print "$1" >/dev/null 2>&1 || return 0; sleep 0.5; done
  return 1
}
lc bootout system/com.whoread.vmrunner 2>/dev/null
lc bootout "gui/$VM_UID/com.whoread.vmrunner.agent" 2>/dev/null
for target in system/com.whoread.vmrunner "gui/$VM_UID/com.whoread.vmrunner.agent"; do
  wait_gone "$target" || { echo "FAILED: the runner $target does not stop; nothing removed, run this again"; exit 1; }
done
rm -f "$R/Library/LaunchDaemons/com.whoread.vmrunner.plist" "$R/Library/LaunchAgents/com.whoread.vmrunner.agent.plist" \
  "$R/etc/sudoers.d/whoread-vmrunner" "$R/usr/local/libexec/whoread-vmrunner.sh" "$R/usr/local/etc/whoread-vmrunner.conf" \
  "$R/var/run/whoread-vmrunner.state" "$R/tmp/whoread-vmrunner-agent.state"
if [ -f "$TCC_RECORD" ]; then
  TCC=(bash "$HERE/../tcc-fda.sh")
  [ -z "$R" ] || TCC+=(--db "$R/Library/Application Support/com.apple.TCC/TCC.db")
  if ! "${TCC[@]}" --undo "$TCC_RECORD"; then
    echo "FAILED: the runner is removed, but the Full Disk Access rows install.sh changed could not be put back; they are listed in $TCC_RECORD"
    exit 1
  fi
fi
echo "OK: WhoRead VM runner removed (logs kept: /var/log/whoread-vmrunner.log, /tmp/whoread-vmrunner-agent.log)"
