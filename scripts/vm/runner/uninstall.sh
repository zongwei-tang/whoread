#!/bin/bash
# Removes the WhoRead VM job runner from the test VM (whichever mode install.sh chose). In the VM:
#   sudo bash /Users/admin/wr/whoread/scripts/vm/runner/uninstall.sh
# Leaves the share mounted and <repo>/.vm (job results) in place.
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run it with sudo" >&2; exit 77; }
VM_USER="${WHOREAD_VM_USER:-${SUDO_USER:-admin}}"
[ "$VM_USER" = root ] && VM_USER=admin
VM_UID=$(id -u "$VM_USER" 2>/dev/null || echo 501)
launchctl bootout system/com.whoread.vmrunner 2>/dev/null
launchctl bootout "gui/$VM_UID/com.whoread.vmrunner.agent" 2>/dev/null
rm -f /Library/LaunchDaemons/com.whoread.vmrunner.plist /Library/LaunchAgents/com.whoread.vmrunner.agent.plist \
  /etc/sudoers.d/whoread-vmrunner /usr/local/libexec/whoread-vmrunner.sh /usr/local/etc/whoread-vmrunner.conf \
  /var/run/whoread-vmrunner.state /tmp/whoread-vmrunner-agent.state
echo "OK: WhoRead VM runner removed (logs kept: /var/log/whoread-vmrunner.log, /tmp/whoread-vmrunner-agent.log)"
