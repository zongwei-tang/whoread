#!/bin/bash
# M5 acceptance — ONLY inside a macOS VM with SIP disabled, never on your main Mac.
# Prerequisites in the VM:
#   swift build -c release && sudo scripts/install-dev-daemon.sh native
#   Full Disk Access for /usr/local/libexec/whoreadd, scripts/create-test-vault.sh
# Usage: sudo -v; scripts/vm/acceptance-m5.sh [--stop-test]
set -uo pipefail
set -m
if [ "$(csrutil status 2>/dev/null | grep -c disabled)" = "0" ]; then
  echo "SIP looks enabled. This script is for a SIP-disabled test VM only." >&2
  exit 1
fi
VAULT="$HOME/WhoReadTestVault"
KEY="$VAULT/ssh/id_ed25519"
CREDS="$VAULT/aws/credentials"
WR="${WHOREAD:-whoread}"
PASS=0; FAIL=0
ok()  { echo "PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
denied() { "$@" >/dev/null 2>"$TMPDIR/err"; local rc=$?; [ $rc -ne 0 ] && grep -qi "not permitted" "$TMPDIR/err"; }
allowed() { "$@" >/dev/null 2>&1; }

sudo -v || exit 1
"$WR" status | grep -q "source:.*native" || { echo "daemon is not running the native source"; exit 1; }

RULE=$(mktemp)
cat > "$RULE" <<JSON
{"id":"m5-deny-vault","name":"M5: block non-owners from the test vault","enabled":true,"enforce":true,
 "target":{"category":"test-vault"},"subject":{"type":"anyNonOwner"},"access":"read","action":"deny",
 "includePlatformBinaries":true}
JSON
sudo "$WR" rules add --json-file "$RULE" >/dev/null
"$WR" enforcement on >/dev/null
sleep 0.5

echo "== deny rule"
denied /bin/cat "$KEY" && ok "cat of the test key → Operation not permitted" || bad "cat was not denied"
allowed /usr/bin/ssh-keygen -y -f "$KEY" && ok "ssh-keygen -y -f (owner) still works" || bad "owner ssh-keygen was blocked"

echo "== bypass attempts"
rm -f "$TMPDIR"/m5-*
denied /bin/cp -c "$KEY" "$TMPDIR/m5-clone" && ok "clone (cp -c) denied" || bad "clone not denied"
denied /bin/cp "$KEY" "$TMPDIR/m5-copy" && ok "copy (cp) denied" || bad "copy not denied"
denied /usr/bin/python3 -c "import shutil; shutil.copyfile('$KEY', '$TMPDIR/m5-py')" && ok "copyfile via python denied" || bad "python copy not denied"
denied /bin/mv "$KEY" "$TMPDIR/m5-moved" && ok "rename out (mv) denied" || bad "rename not denied"
denied /bin/ln "$KEY" "$TMPDIR/m5-link" && ok "hard link denied" || bad "hard link not denied"
[ -f "$KEY" ] && ok "key still in place" || bad "key moved!"

echo "== AI agent chain rule"
sudo "$WR" rules disable m5-deny-vault >/dev/null
sudo "$WR" rules enforce template.block-agents-critical >/dev/null
sleep 0.3
allowed /bin/cat "$CREDS" && ok "plain cat allowed (no agent in chain)" || bad "plain cat denied"
# argv[0] "claude" makes this shell look like Claude Code to the agent rules (agents.json).
if bash -c "exec -a claude /bin/bash -c 'cat \"$CREDS\"'" >/dev/null 2>"$TMPDIR/err"; then
  bad "cat under an AI agent chain was allowed"
else
  grep -qi "not permitted" "$TMPDIR/err" && ok "cat under an AI agent chain denied" || bad "agent-chain cat failed for another reason: $(cat "$TMPDIR/err")"
fi
if bash -c "exec -a claude /bin/bash -c '/usr/bin/ssh-keygen -y -f \"$KEY\"'" >/dev/null 2>&1; then
  ok "owner (ssh-keygen) under agent chain allowed (exceptOwners)"
else
  bad "owner under agent chain denied"
fi
sudo "$WR" rules disable template.block-agents-critical >/dev/null
sudo "$WR" rules enable m5-deny-vault >/dev/null
sleep 0.3

echo "== kill switches (each must take effect immediately)"
t() { python3 -c 'import time; print(time.time())'; }
first_allowed() { local s; s=$(t); for _ in $(seq 100); do allowed /bin/cat "$KEY" && { python3 -c "print(round($(t)-$s,3))"; return 0; }; sleep 0.02; done; echo "timeout"; return 1; }
first_denied()  { local s; s=$(t); for _ in $(seq 100); do denied /bin/cat "$KEY" && { python3 -c "print(round($(t)-$s,3))"; return 0; }; sleep 0.02; done; echo "timeout"; return 1; }
denied /bin/cat "$KEY" || bad "precondition: not denied"
sudo "$WR" enforcement off >/dev/null; d=$(first_allowed) && ok "CLI 'enforcement off' took effect in ${d}s" || bad "CLI kill switch: $d"
"$WR" enforcement on >/dev/null; d=$(first_denied) && ok "re-enabled in ${d}s" || bad "re-enable: $d"
sudo "$WR" kill-switch engage >/dev/null; d=$(first_allowed) && ok "kill-switch file took effect in ${d}s" || bad "file kill switch: $d"
sudo "$WR" kill-switch release >/dev/null; d=$(first_denied) && ok "file released in ${d}s" || bad "file release: $d"
echo "MANUAL  UI switch: open the WhoRead menu, turn Enforcement off, then run: cat $KEY  (must succeed at once)"

echo "== daemon killed"
( for i in $(seq 200); do /bin/cat "$KEY" >/dev/null 2>&1 && echo ok || echo denied; sleep 0.01; done ) > "$TMPDIR/m5-loop" &
LOOP=$!
sleep 0.5
sudo launchctl kill SIGKILL system/com.whoread.daemon
wait $LOOP
echo "  loop results while the daemon was SIGKILLed: $(sort "$TMPDIR/m5-loop" | uniq -c | tr '\n' ' ')"
for _ in $(seq 50); do "$WR" status >/dev/null 2>&1 && break; sleep 0.2; done
"$WR" status >/dev/null 2>&1 && ok "launchd restarted the daemon" || bad "daemon did not come back"
uptime >/dev/null && ok "system responsive"

if [ "${1:-}" = "--stop-test" ]; then
  echo "== daemon stopped (SIGSTOP): what happens to a pending AUTH?"
  PID=$(pgrep -x whoreadd | head -1)
  sudo kill -STOP "$PID"
  s=$(t); /bin/cat "$KEY" >/dev/null 2>"$TMPDIR/err"; rc=$?; e=$(t)
  echo "  cat returned rc=$rc after $(python3 -c "print(round($e-$s,2))") s: $(cat "$TMPDIR/err")"
  sudo kill -CONT "$PID" 2>/dev/null || true
  sleep 2
  "$WR" status | head -3
  echo "  (record this in docs/STATUS.md: expected per WWDC20 — client killed at the deadline, implicit allow)"
fi

echo "== latency"
"$WR" status --json | python3 -c '
import json,sys; s=json.load(sys.stdin)["latency"]
print("  AUTH responses: %d, p50 %.0f µs, p99 %.0f µs, max %.0f µs, deadline misses %d" % (s["totalResponses"], s["p50Micros"], s["p99Micros"], s["maxMicros"], s["deadlineMisses"]))'

sudo "$WR" rules delete m5-deny-vault >/dev/null
rm -f "$RULE" "$TMPDIR"/m5-*
echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
