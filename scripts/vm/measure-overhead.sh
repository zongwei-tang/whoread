#!/bin/bash
# timeout: 900
# M4: CPU overhead of the native monitor on UNmonitored paths (inverted muting should make it
# near zero). ONLY in the test VM (it stops and restarts the daemon), with the native dev daemon
# installed; from the host as a runner job:
#   scripts/vm/vmjob.sh run overhead scripts/vm/measure-overhead.sh [-- N]
# (or in the VM: sudo scripts/vm/measure-overhead.sh [N]). Compares the daemon's CPU time and the
# workload's wall time during a burst of opens outside every monitored prefix. Needs jq (macOS 15+).
# If the job is killed outright while the daemon is stopped, restart it from the host with
#   scripts/vm/vmjob.sh shell 'launchctl bootstrap system /Library/LaunchDaemons/com.whoread.daemon.plist'
set -euo pipefail
N="${1:-30000}"
# A VM: the hypervisor flag, or the model name of an Apple silicon VM (VirtualMac2,1).
is_vm() {
  [ "$(sysctl -n kern.hv_vmm_present 2>/dev/null)" = 1 ] && return 0
  case "$(sysctl -n hw.model 2>/dev/null)" in VirtualMac*) return 0 ;; esac
  return 1
}
if ! is_vm && [ -z "${WHOREAD_SKIP_VM_CHECK:-}" ]; then
  echo "This Mac does not look like a VM (kern.hv_vmm_present is not 1). Run it in the test VM only;" >&2
  echo "if this really is one, rerun with WHOREAD_SKIP_VM_CHECK=1." >&2
  exit 1
fi
command -v jq >/dev/null || { echo "jq is missing (part of macOS 15 and later)"; exit 1; }
pgrep -x whoreadd >/dev/null || { echo "whoreadd not running"; exit 1; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/whoread-overhead.XXXXXX")"
# Restart the daemon and remove the work files however the script ends (also on SIGTERM from the
# runner's timeout: the trap turns it into a normal exit, which runs the EXIT trap).
STOPPED=""
trap '[ -n "$STOPPED" ] && sudo launchctl bootstrap system /Library/LaunchDaemons/com.whoread.daemon.plist; rm -rf "$WORK"' EXIT
trap 'exit 130' INT TERM HUP
for i in $(seq 200); do head -c 4096 /dev/urandom > "$WORK/f$i"; done
workload() { for _ in $(seq $((N / 200))); do cat "$WORK"/f* > /dev/null; done; }
cpu() { ps -o cputime= -p "$(pgrep -x whoreadd | head -1)" | awk -F'[:.]' '{print ($1*60+$2)+$3/100}'; }
# One clock for both runs (BSD date has no %N).
now() { jq -n 'now'; }
round() { jq -n "($1) * 1000 | round / 1000"; }
# Spotlight indexing (or anything else busy) makes both runs noisy: say so next to the numbers.
busy() {
  local spot
  spot=$(ps -A -o %cpu= -o comm= | awk '{ n = $2; sub(/.*\//, "", n) } n ~ /^(mds|mds_stores|mdworker.*)$/ { s += $1 } END { printf "%.0f", s }') || spot=0
  echo "load average $(sysctl -n vm.loadavg 2>/dev/null | tr -d '{}' | awk '{print $1}'), Spotlight processes ${spot}% CPU"
  [ "${spot:-0}" -lt 20 ] || echo "WARNING: Spotlight is busy (indexing?); these numbers are noisy. Rerun once it has settled."
}
busy
workload   # warm-up: both measured runs then find the files in the cache
c0=$(cpu); s=$(now)
workload
e=$(now); c1=$(cpu)
echo "monitor running : $N opens in $(round "$e - $s") s, whoreadd CPU +$(round "$c1 - $c0") s"
sudo launchctl bootout system /Library/LaunchDaemons/com.whoread.daemon.plist
STOPPED=1
s=$(now); workload; e=$(now)
echo "monitor stopped : $N opens in $(round "$e - $s") s"
busy
echo "Done: compare the CPU time and the duration with the monitor running and stopped."
