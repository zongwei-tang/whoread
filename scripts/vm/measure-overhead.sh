#!/bin/bash
# M4: CPU overhead of the native monitor on UNmonitored paths (inverted muting should make it
# near zero). Run in the VM with the native dev daemon installed. Compares the daemon's CPU time
# and the workload's wall time during a burst of opens outside every monitored prefix.
set -euo pipefail
N="${1:-30000}"
WORK="$(mktemp -d)"
for i in $(seq 200); do head -c 4096 /dev/urandom > "$WORK/f$i"; done
workload() { for _ in $(seq $((N / 200))); do cat "$WORK"/f* > /dev/null; done; }
cpu() { ps -o cputime= -p "$(pgrep -x whoreadd | head -1)" | awk -F'[:.]' '{print ($1*60+$2)+$3/100}'; }
# One clock for both runs (BSD date has no %N).
now() { python3 -c 'import time;print(time.time())'; }
pgrep -x whoreadd >/dev/null || { echo "whoreadd not running"; exit 1; }
# Restart the daemon and remove the work files however the script ends.
STOPPED=""
trap '[ -n "$STOPPED" ] && sudo launchctl bootstrap system /Library/LaunchDaemons/com.whoread.daemon.plist; rm -rf "$WORK"' EXIT
c0=$(cpu); s=$(now)
workload
e=$(now); c1=$(cpu)
echo "monitor running : $N opens in $(python3 -c "print(round($e-$s,2))") s, whoreadd CPU +$(python3 -c "print(round($c1-$c0,3))") s"
sudo launchctl bootout system /Library/LaunchDaemons/com.whoread.daemon.plist
STOPPED=1
s=$(now); workload; e=$(now)
echo "monitor stopped : $N opens in $(python3 -c "print(round($e-$s,2))") s"
echo "Copy these numbers into docs/STATUS.md (M4)."
