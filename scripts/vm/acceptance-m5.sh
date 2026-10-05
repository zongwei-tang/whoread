#!/bin/bash
# M5 acceptance — ONLY inside a macOS VM with SIP disabled, never on your main Mac.
# Prerequisites in the VM:
#   swift build -c release && sudo scripts/install-dev-daemon.sh native
#   Full Disk Access for /usr/local/libexec/whoreadd, scripts/create-test-vault.sh
#   Command Line Tools (cc) for the copyfile(2) helper
# Usage: sudo -v; scripts/vm/acceptance-m5.sh [--stop-test]
set -uo pipefail
set -m
# A custom SIP configuration also prints "...: disabled" lines; only full "status: disabled." counts.
if ! csrutil status 2>/dev/null | grep -q 'status: disabled\.'; then
  echo "SIP is not fully disabled. This script is for a SIP-disabled test VM only." >&2
  exit 1
fi
if [ "$(sysctl -n kern.hv_vmm_present 2>/dev/null)" = "0" ] && [ -z "${WHOREAD_SKIP_VM_CHECK:-}" ]; then
  echo "This Mac does not look like a VM (kern.hv_vmm_present = 0). Never run this on your main Mac." >&2
  echo "If this really is a test VM, rerun with WHOREAD_SKIP_VM_CHECK=1." >&2
  exit 1
fi
VAULT="$HOME/WhoReadTestVault"
KEY="$VAULT/ssh/id_ed25519"
CREDS="$VAULT/aws/credentials"
WR="${WHOREAD:-whoread}"
TMPDIR="${TMPDIR:-/tmp}"
PASS=0; FAIL=0
ok()  { echo "PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
denied() { "$@" >/dev/null 2>"$TMPDIR/err"; local rc=$?; [ $rc -ne 0 ] && grep -qi "not permitted" "$TMPDIR/err"; }
allowed() { "$@" >/dev/null 2>&1; }

sudo -v || exit 1
"$WR" status | grep -q "source:.*native" || { echo "daemon is not running the native source"; exit 1; }

# Whatever happens, leave no enforcing test rule, stopped daemon or moved key behind.
RULE=""; KILL_SWITCH=""; STOPPED_PID=""
cleanup() {
  [ -n "$STOPPED_PID" ] && sudo kill -CONT "$STOPPED_PID" 2>/dev/null
  [ -n "$KILL_SWITCH" ] && sudo "$WR" kill-switch release >/dev/null 2>&1
  # Back to the template's defaults (disabled, dry run), so a later "enable" does not block.
  sudo "$WR" rules dry-run template.block-agents-critical >/dev/null 2>&1
  sudo "$WR" rules disable template.block-agents-critical >/dev/null 2>&1
  sudo "$WR" rules delete m5-deny-vault >/dev/null 2>&1
  [ -f "$TMPDIR/m5-moved" ] && [ ! -e "$KEY" ] && /bin/mv "$TMPDIR/m5-moved" "$KEY"
  rm -f ${RULE:+"$RULE"} "$TMPDIR"/m5-* "$VAULT/ssh/m5-new"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# Left over from an interrupted run, it would turn the AUTH_CREATE check below into an open.
rm -f "$VAULT/ssh/m5-new"
RULE=$(mktemp)
cat > "$RULE" <<JSON
{"id":"m5-deny-vault","name":"M5: block non-owners from the test vault","enabled":true,"enforce":true,
 "target":{"category":"test-vault"},"subject":{"type":"anyNonOwner"},"access":"any","action":"deny",
 "includePlatformBinaries":true}
JSON
sudo "$WR" rules add --json-file "$RULE" >/dev/null
"$WR" enforcement on >/dev/null
sleep 0.5

echo "== deny rule"
denied /bin/cat "$KEY" && ok "cat of the test key → Operation not permitted" || bad "cat was not denied"
allowed /usr/bin/ssh-keygen -y -f "$KEY" && ok "ssh-keygen -y -f (owner) still works" || bad "owner ssh-keygen was blocked"
allowed /bin/ls "$VAULT/ssh" && ok "listing the vault still works (listings are never blocked)" || bad "ls of the vault was blocked"
denied /usr/bin/touch "$VAULT/ssh/m5-new" && ok "new file in the vault denied (AUTH_CREATE)" || bad "creating a file in the vault was not denied"

echo "== bypass attempts"
rm -f "$TMPDIR"/m5-*
denied /bin/cp -c "$KEY" "$TMPDIR/m5-clone" && ok "clone (cp -c) denied" || bad "clone not denied"
denied /bin/cp "$KEY" "$TMPDIR/m5-copy" && ok "copy (cp) denied" || bad "copy not denied"
denied /usr/bin/python3 -c "import shutil; shutil.copyfile('$KEY', '$TMPDIR/m5-py')" && ok "copy via python (open path) denied" || bad "python copy not denied"
# cp and shutil open(2) the source, so they only exercise AUTH_OPEN. The copyfile(2) syscall (no
# libc wrapper) fires AUTH_COPYFILE and no open event. Its MAC check runs before the filesystem's,
# so anything but EPERM (ENOTSUP included) means it was allowed.
cat > "$TMPDIR/m5-cf.c" <<'C'
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
int main(int c, char **v) { if (c != 3 || syscall(SYS_copyfile, v[1], v[2], 0600, 0) != 0) { perror("copyfile"); return 1; } return 0; }
C
if cc -w -o "$TMPDIR/m5-cf" "$TMPDIR/m5-cf.c" 2>"$TMPDIR/err"; then
  denied "$TMPDIR/m5-cf" "$KEY" "$TMPDIR/m5-sys" && ok "copyfile(2) syscall denied (AUTH_COPYFILE)" || bad "copyfile(2) not denied: $(cat "$TMPDIR/err")"
else
  bad "cannot build the copyfile(2) helper (xcode-select --install): $(cat "$TMPDIR/err")"
fi
denied /bin/mv "$KEY" "$TMPDIR/m5-moved" && ok "rename out (mv) denied" || bad "rename not denied"
[ -f "$TMPDIR/m5-moved" ] && /bin/mv "$TMPDIR/m5-moved" "$KEY"   # put it back for the next checks
denied /bin/ln "$KEY" "$TMPDIR/m5-link" && ok "hard link denied" || bad "hard link not denied"
[ -f "$KEY" ] && ok "key still in place" || bad "key moved!"

echo "== AI agent chain rule"
sudo "$WR" rules disable m5-deny-vault >/dev/null
sudo "$WR" rules enforce template.block-agents-critical >/dev/null
sleep 0.3
allowed /bin/cat "$CREDS" && ok "plain cat allowed (no agent in chain)" || bad "plain cat denied"
# argv[0] "claude" makes this shell look like Claude Code (agents.json argv0Names). The command must
# not be the last one in the -c string, otherwise bash execs it in place and the 'claude' ancestor
# disappears from the chain.
as_agent() { ( exec -a claude /bin/bash -c '"$@"; rc=$?; exit $rc' claude "$@" ); }
if as_agent /bin/cat "$CREDS" >/dev/null 2>"$TMPDIR/err"; then
  bad "cat under an AI agent chain was allowed"
else
  grep -qi "not permitted" "$TMPDIR/err" && ok "cat under an AI agent chain denied" || bad "agent-chain cat failed for another reason: $(cat "$TMPDIR/err")"
fi
# The template blocks owners too when an agent started them (deny > allow > owner, brief §5).
if as_agent /usr/bin/ssh-keygen -y -f "$KEY" >/dev/null 2>&1; then
  bad "owner (ssh-keygen) under an agent chain was allowed (the template does not exempt owners)"
else
  ok "owner (ssh-keygen) under an agent chain denied"
fi
sudo "$WR" rules disable template.block-agents-critical >/dev/null
sudo "$WR" rules enable m5-deny-vault >/dev/null
sleep 0.3

# Now, not at the end: "enforcement on" below starts a new latency window, and the daemon
# restarted after the SIGKILL starts with an empty one. The checks above are only a few dozen
# AUTH responses; a burst of denied opens (denials are never cached) gives p99 enough samples.
for _ in $(seq 200); do /bin/cat "$KEY" >/dev/null 2>&1; done
echo "== latency"
"$WR" status --json | python3 -c '
import json,sys; s=json.load(sys.stdin)["latency"]
print("  AUTH responses: %d (%d in the window), p50 %.0f µs, p99 %.0f µs, max %.0f µs, deadline misses %d" % (s["totalResponses"], s["samples"], s["p50Micros"], s["p99Micros"], s["maxMicros"], s["deadlineMisses"]))'
active=$("$WR" status --json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("enforcementActive"))')
[ "$active" = "True" ] && ok "enforcement still on after the burst (never switched off automatically)" \
  || bad "enforcement went off after the burst"

echo "== kill switches (each must take effect immediately)"
t() { python3 -c 'import time; print(time.time())'; }
first_allowed() { local s; s=$(t); for _ in $(seq 100); do allowed /bin/cat "$KEY" && { python3 -c "print(round($(t)-$s,3))"; return 0; }; sleep 0.02; done; echo "timeout"; return 1; }
first_denied()  { local s; s=$(t); for _ in $(seq 100); do denied /bin/cat "$KEY" && { python3 -c "print(round($(t)-$s,3))"; return 0; }; sleep 0.02; done; echo "timeout"; return 1; }
denied /bin/cat "$KEY" || bad "precondition: not denied"
sudo "$WR" enforcement off >/dev/null; d=$(first_allowed) && ok "CLI 'enforcement off' took effect in ${d}s" || bad "CLI kill switch: $d"
"$WR" enforcement on >/dev/null; d=$(first_denied) && ok "re-enabled in ${d}s" || bad "re-enable: $d"
KILL_SWITCH=1
sudo "$WR" kill-switch engage >/dev/null; d=$(first_allowed) && ok "kill-switch file took effect in ${d}s" || bad "file kill switch: $d"
sudo "$WR" kill-switch release >/dev/null; d=$(first_denied) && ok "file released in ${d}s" || bad "file release: $d"
KILL_SWITCH=""
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
# The auth-armed marker outlived the SIGKILL: enforcement is never switched off automatically, so
# the new instance keeps enforcing and only reports the unclean stop.
enforcement_state() { "$WR" status --json | python3 -c '
import json,sys; s=json.load(sys.stdin)
print("on" if s["enforcementActive"] else "off", s.get("uncleanStop") or "(no unclean-stop note)")'; }
st=$(enforcement_state)
case "$st" in
  "on "*"while enforcing"*) ok "restart kept enforcing and reported the unclean stop: ${st#on }" ;;
  *) bad "after the SIGKILL, expected enforcement on with an unclean-stop note, got: $st" ;;
esac
d=$(first_denied) && ok "cat denied again after the restart (in ${d}s)" || bad "cat not denied after the restart: $d"

echo "== ask mode"
sudo "$WR" rules disable m5-deny-vault >/dev/null
sleep 0.3
# Nobody polls questions (no app in the VM): an undecided access is denied at once.
s=$(t); denied /bin/cat "$CREDS"; rc=$?; e=$(t)
[ $rc -eq 0 ] && ok "undecided read denied at once with no answering app ($(python3 -c "print(round($e-$s,2))") s)" \
  || bad "undecided read was not denied"
# A stand-in for the app: polling questions makes the daemon hold accesses and wait for an answer.
( while :; do "$WR" asks --json >/dev/null 2>&1; sleep 1; done ) &
POLL=$!
sleep 1.5
( s=$(t); /bin/cat "$CREDS" >/dev/null 2>&1; rc=$?; echo "rc=$rc after $(python3 -c "print(round($(t)-$s,2))") s" ) > "$TMPDIR/m5-ask" &
HELD=$!
sleep 1
id=$("$WR" asks --json | python3 -c 'import json,sys; a=json.load(sys.stdin); print(a[0]["id"] if a else "")')
[ -n "$id" ] && ok "question #$id listed while cat waits" || bad "no question listed"
[ -n "$id" ] && { sudo "$WR" ask "$id" allow-once >/dev/null && ok "answered: allow once" || bad "answering failed"; }
wait $HELD
r=$(cat "$TMPDIR/m5-ask")
case "$r" in rc=0*) ok "the held cat went through after the answer: $r" ;; *) bad "held cat after the answer: $r" ;; esac
# Unanswered: the access waits for its budget and is then denied. The time it waits is the deadline
# budget on this Mac (deadline minus 20 %, headroom clamped to 1-5 s): record it in docs/STATUS.md.
s=$(t); ( echo x >> "$VAULT/ssh/m5-new" ) 2>/dev/null; rc=$?; e=$(t)
[ $rc -ne 0 ] && ok "unanswered write denied after $(python3 -c "print(round($e-$s,2))") s (the hold budget)" \
  || bad "unanswered write went through"
kill $POLL 2>/dev/null; wait $POLL 2>/dev/null
sudo "$WR" rules enable m5-deny-vault >/dev/null
sleep 0.3

if [ "${1:-}" = "--stop-test" ]; then
  echo "== daemon stopped (SIGSTOP): what happens to a pending AUTH?"
  # Enforcement stays on across the restart; make sure, then wait until a read is denied again.
  "$WR" enforcement on >/dev/null
  if ! d=$(first_denied); then
    bad "stop-test: enforcement did not come back after 'enforcement on': $d"
  else
    PID=$(pgrep -x whoreadd | head -1)
    STOPPED_PID="$PID"
    sudo kill -STOP "$PID"
    s=$(t); /bin/cat "$KEY" >/dev/null 2>"$TMPDIR/err"; rc=$?; e=$(t)
    echo "  cat returned rc=$rc after $(python3 -c "print(round($e-$s,2))") s: $(cat "$TMPDIR/err")"
    sudo kill -CONT "$PID" 2>/dev/null || true
    STOPPED_PID=""
    sleep 2
    # Killed at the deadline: launchd restarts it, possibly after its respawn throttle.
    for _ in $(seq 150); do "$WR" status >/dev/null 2>&1 && break; sleep 0.2; done
    NEW_PID=$(pgrep -x whoreadd | head -1)
    if [ -n "$NEW_PID" ] && [ "$NEW_PID" = "$PID" ]; then
      echo "  the daemon survived the stop (pid $PID); enforcement: $(enforcement_state)"
    else
      echo "  the daemon was killed (pid $PID, now ${NEW_PID:-not running}); enforcement: $(enforcement_state)"
    fi
    echo "  (record this in docs/STATUS.md: expected per WWDC20 — client killed at the deadline, implicit allow)"
  fi
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
