#!/bin/bash
# timeout: 900
# M5 acceptance — ONLY inside a macOS VM with SIP disabled, never on your main Mac. From the host,
# as a job of the VM runner (scripts/vm/README.md):
#   scripts/vm/vmjob.sh run m5 scripts/vm/acceptance-m5.sh [-- --stop-test]
# or in the VM itself: sudo -v; scripts/vm/acceptance-m5.sh [--stop-test]
# Prerequisites in the VM: scripts/vm/provision.sh (native dev daemon with Full Disk Access, test
# vault), jq (part of macOS 15 and later). The copyfile(2) probe uses cc when the Command Line Tools
# are installed, else perl's syscall().
# Run as root (a VM job), every probe runs as the test user ($WHOREAD_TEST_USER, through sudo -u),
# whose home holds the vault; rules, enforcement and the daemon are handled as root.
set -uo pipefail
set -m
# A custom SIP configuration also prints "...: disabled" lines; only full "status: disabled." counts.
if ! csrutil status 2>/dev/null | grep -q 'status: disabled\.'; then
  echo "SIP is not fully disabled. This script is for a SIP-disabled test VM only." >&2
  exit 1
fi
# A VM: the hypervisor flag, or the model name of an Apple silicon VM (VirtualMac2,1).
is_vm() {
  [ "$(sysctl -n kern.hv_vmm_present 2>/dev/null)" = 1 ] && return 0
  case "$(sysctl -n hw.model 2>/dev/null)" in VirtualMac*) return 0 ;; esac
  return 1
}
if ! is_vm && [ -z "${WHOREAD_SKIP_VM_CHECK:-}" ]; then
  echo "This Mac does not look like a VM (kern.hv_vmm_present is not 1, hw.model is $(sysctl -n hw.model 2>/dev/null)). Never run this on your main Mac." >&2
  echo "If this really is a test VM, rerun with WHOREAD_SKIP_VM_CHECK=1." >&2
  exit 1
fi
command -v jq >/dev/null || { echo "jq is missing (part of macOS 15 and later)" >&2; exit 1; }
AS=()
if [ "$(id -u)" -eq 0 ]; then
  TEST_USER="${WHOREAD_TEST_USER:-${SUDO_USER:-}}"
  case "$TEST_USER" in ''|root) echo "running as root: set WHOREAD_TEST_USER to the user whose test vault to probe" >&2; exit 1 ;; esac
  USER_HOME=$(dscl . -read "/Users/$TEST_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
  [ -n "$USER_HOME" ] || { echo "no home directory for $TEST_USER" >&2; exit 1; }
  AS=(sudo -n -u "$TEST_USER" --)
else
  USER_HOME="$HOME"
fi
VAULT="$USER_HOME/WhoReadTestVault"
KEY="$VAULT/ssh/id_ed25519"
CREDS="$VAULT/aws/credentials"
# Canaries for the coverage checks (truncate, swap, chmod…): a check that fails never damages the key.
CANARY="$VAULT/ssh/m5-canary"
SWAPDIR="$VAULT/m5-swap"
WR="${WHOREAD:-whoread}"
TMPDIR="${TMPDIR:-/tmp}"
WORK=""
PASS=0; FAIL=0
ok()  { echo "PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
as_user() { ${AS[@]+"${AS[@]}"} "$@"; }
denied() { as_user "$@" >/dev/null 2>"$TMPDIR/err"; local rc=$?; [ $rc -ne 0 ] && grep -qi "not permitted" "$TMPDIR/err"; }
allowed() { as_user "$@" >/dev/null 2>&1; }
# denied, for a command that brings its own sudo (not the test user's: theirs may want a password).
denied_as_is() { "$@" >/dev/null 2>"$TMPDIR/err"; local rc=$?; [ $rc -ne 0 ] && grep -qi "not permitted" "$TMPDIR/err"; }
# Without the Command Line Tools, cc and /usr/bin/python3 are stubs that ask to install them.
HAVE_CLT=""
xcode-select -p >/dev/null 2>&1 && HAVE_CLT=1

sudo -v || exit 1
"$WR" status | grep -q "source:.*native" || { echo "daemon is not running the native source"; exit 1; }
[ -f "$KEY" ] || { echo "no test vault in $USER_HOME (scripts/create-test-vault.sh)"; exit 1; }

# Whatever happens, leave no enforcing test rule, stopped daemon or moved key behind, and
# enforcement as it was: a later job (acceptance-m2.sh, measure-overhead.sh) must not find it on
# with nothing answering questions. Quick: the VM runner kills a timed-out job 10 s after SIGTERM.
ENFORCEMENT_BEFORE=$("$WR" status --json 2>/dev/null | jq -r '.enforcementEnabled')
RULE=""; ALLOW_RULE=""; KILL_SWITCH=""; STOPPED_PID=""; SWAP=()
cleanup() {
  [ -n "$STOPPED_PID" ] && sudo kill -CONT "$STOPPED_PID" 2>/dev/null
  [ -n "$KILL_SWITCH" ] && sudo "$WR" kill-switch release >/dev/null 2>&1
  # Enforcement off before anything goes back into the vault: under the deny rule, or in ask mode
  # once the test rules are gone (nothing answers questions here), putting the key back and
  # removing m5-new would be denied.
  sudo "$WR" enforcement off >/dev/null 2>&1
  # Back to the template's defaults (disabled, dry run), so a later "enable" does not block.
  sudo "$WR" rules dry-run template.block-agents-critical >/dev/null 2>&1
  sudo "$WR" rules disable template.block-agents-critical >/dev/null 2>&1
  sudo "$WR" rules delete m5-deny-vault >/dev/null 2>&1
  for r in m5-cov-canary-read m5-cov-canary-write m5-cov-swap-write m5-cov-swap-read; do
    sudo "$WR" rules delete "$r" >/dev/null 2>&1
  done
  sudo "$WR" rules delete m5-allow-vault-read >/dev/null 2>&1
  [ -f "$TMPDIR/m5-moved" ] && [ ! -e "$KEY" ] && /bin/mv "$TMPDIR/m5-moved" "$KEY"
  # A swap that went through left the vault folder's content in the decoy: swap it back. Before the
  # m5-* files go: the C helper is one of them.
  [ -f "$TMPDIR/m5-decoy/secret" ] && [ ${#SWAP[@]} -gt 0 ] && "${SWAP[@]}" "$TMPDIR/m5-decoy" "$SWAPDIR"
  [ -d "$TMPDIR/m5-decoy" ] && { rm -f "$TMPDIR/m5-decoy"/*; rmdir "$TMPDIR/m5-decoy"; }
  rm -f ${RULE:+"$RULE"} ${ALLOW_RULE:+"$ALLOW_RULE"} "$TMPDIR"/m5-* "$VAULT/ssh/m5-new"
  [ -n "$WORK" ] && { rm -f "$WORK/err"; rmdir "$WORK" 2>/dev/null; }
  # As the script found it; unknown counts as off (the state scripts/vm/provision.sh leaves).
  [ "$ENFORCEMENT_BEFORE" = true ] && sudo "$WR" enforcement on >/dev/null 2>&1
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# Run as root, the probes (the test user) write their copies, links and the moved key into TMPDIR. A
# root-only TMPDIR would fail them with EACCES on the destination before Endpoint Security is asked
# (rename, link, copyfile), so a working denial would be reported as missing: use a folder of the
# test user's own.
if [ ${#AS[@]} -gt 0 ]; then
  WORK=$(mktemp -d /tmp/whoread-m5.XXXXXX) && chown "$TEST_USER" "$WORK" \
    || { echo "cannot create a work folder for $TEST_USER in /tmp" >&2; exit 1; }
  TMPDIR="$WORK"
fi

# Left over from an interrupted run, it would turn the AUTH_CREATE check below into an open. Removed
# with enforcement off (in ask mode it would be denied); the deny rule below switches it on.
sudo "$WR" enforcement off >/dev/null 2>&1
rm -f "$VAULT/ssh/m5-new"
# The canaries are (re)written with enforcement off too: with it on, an undecided write to the vault
# is asked and, with no app answering, denied. Run as root, they are handed to the test user, whose
# probes read and change them: on a file of root's, the kernel's own EACCES (read) or EPERM (chmod)
# would come before Endpoint Security is asked, a false FAIL or a false PASS.
printf 'canary\n' > "$CANARY" && chmod 600 "$CANARY" && chmod -N "$CANARY" 2>/dev/null
mkdir -p "$SWAPDIR" && printf 'inside\n' > "$SWAPDIR/secret"
if [ ${#AS[@]} -gt 0 ]; then chown -R "$TEST_USER" "$CANARY" "$SWAPDIR"; fi
RULE=$(mktemp "$TMPDIR/whoread-m5-rule.XXXXXX")
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
if [ -n "$HAVE_CLT" ]; then
  denied /usr/bin/python3 -c "import shutil; shutil.copyfile('$KEY', '$TMPDIR/m5-py')" && ok "copy via python (open path) denied" || bad "python copy not denied"
elif [ -x /usr/bin/perl ]; then
  denied /usr/bin/perl -MFile::Copy -e 'copy($ARGV[0], $ARGV[1]) or die "copy: $!\n"' "$KEY" "$TMPDIR/m5-pl" && ok "copy via perl (open path) denied" || bad "perl copy not denied: $(cat "$TMPDIR/err")"
else
  bad "cannot test a copy by an interpreter: neither python3 (Command Line Tools) nor perl"
fi
# cp and shutil open(2) the source, so they only exercise AUTH_OPEN. The copyfile(2) syscall (no
# libc wrapper) fires AUTH_COPYFILE and no open event. Its MAC check runs before the filesystem's,
# so anything but EPERM (ENOTSUP included) means it was allowed.
cat > "$TMPDIR/m5-cf.c" <<'C'
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
int main(int c, char **v) { if (c != 3 || syscall(SYS_copyfile, v[1], v[2], 0600, 0) != 0) { perror("copyfile"); return 1; } return 0; }
C
COPYFILE=()
if [ -n "$HAVE_CLT" ] && cc -w -o "$TMPDIR/m5-cf" "$TMPDIR/m5-cf.c" 2>"$TMPDIR/err"; then
  COPYFILE=("$TMPDIR/m5-cf")
elif [ -x /usr/bin/perl ]; then
  # 227 is SYS_copyfile (sys/syscall.h); perl passes the strings as pointers, like the C helper.
  COPYFILE=(/usr/bin/perl -e 'syscall(227, $ARGV[0], $ARGV[1], 0600, 0) == 0 or die "copyfile: $!\n"')
fi
if [ ${#COPYFILE[@]} -gt 0 ]; then
  denied "${COPYFILE[@]}" "$KEY" "$TMPDIR/m5-sys" && ok "copyfile(2) syscall denied (AUTH_COPYFILE)" || bad "copyfile(2) not denied: $(cat "$TMPDIR/err")"
else
  bad "no way to issue copyfile(2): neither the Command Line Tools (cc) nor perl"
fi
denied /bin/mv "$KEY" "$TMPDIR/m5-moved" && ok "rename out (mv) denied" || bad "rename not denied"
# The rename went through: put the key back for the next checks, with enforcement off for that
# moment (the deny rule would refuse the rename into the vault).
if [ -f "$TMPDIR/m5-moved" ]; then
  sudo "$WR" enforcement off >/dev/null; /bin/mv "$TMPDIR/m5-moved" "$KEY"; "$WR" enforcement on >/dev/null
fi
denied /bin/ln "$KEY" "$TMPDIR/m5-link" && ok "hard link denied" || bad "hard link not denied"
[ -f "$KEY" ] && ok "key still in place" || bad "key moved!"

echo "== coverage: other spellings, permission and namespace changes (deny rule on the vault)"
# files-4: the data volume's spelling of a firmlinked path must be selected too.
if [ -e "/System/Volumes/Data$CANARY" ]; then
  denied /bin/cat "/System/Volumes/Data$CANARY" && ok "open through /System/Volumes/Data… denied" \
    || bad "open through the /System/Volumes/Data spelling was not denied (files-4)"
fi
# macos-5: muting compares bytes; is an open through a different-case spelling delivered (RESEARCH item 10)?
CASED="${CANARY/WhoReadTestVault/WHOREADTESTVAULT}"
if [ -e "$CASED" ]; then
  denied /bin/cat "$CASED" && ok "open through a different-case spelling denied (case variants are delivered)" \
    || bad "open through a different-case spelling was NOT denied: case variants are not delivered (macos-5)"
else
  echo "SKIP  case variants: the volume is case-sensitive"
fi
# files-10: permission, ACL and owner changes are AUTH events now.
denied /bin/chmod 644 "$CANARY" && ok "chmod of a vault file denied (AUTH_SETMODE)" \
  || { bad "chmod of a vault file was not denied"; chmod 600 "$CANARY"; }
denied /bin/chmod +a "everyone allow read" "$CANARY" && ok "chmod +a of a vault file denied (AUTH_SETACL)" \
  || { bad "chmod +a of a vault file was not denied"; chmod -N "$CANARY"; }
# chown needs root: sudo, not through the test user (whose own sudo may want a password), and to the
# canary's present owner and group (the test user's), so a chown that goes through changes nothing.
denied_as_is sudo /usr/sbin/chown "$(stat -f %u:%g "$CANARY")" "$CANARY" && ok "chown of a vault file denied (AUTH_SETOWNER)" \
  || bad "chown of a vault file was not denied"
# A disk image mounted over a vault folder (AUTH_MOUNT). hdiutil fails in its own words, also for
# reasons that have nothing to do with WhoRead, so a PASS needs the denied mount event as well.
# The image is handed to the test user, who attaches it; its name matches m5-*, so the cleanup
# removes it.
if hdiutil create -quiet -size 1m -fs HFS+ -volname m5 "$TMPDIR/m5-disk.dmg" 2>/dev/null; then
  if [ ${#AS[@]} -gt 0 ]; then chown "$TEST_USER" "$TMPDIR/m5-disk.dmg"; fi
  as_user hdiutil attach -quiet -nobrowse -mountpoint "$SWAPDIR" "$TMPDIR/m5-disk.dmg" >/dev/null 2>"$TMPDIR/err"
  # Mounted = the folder now sits on another device. `mount` may print the mount point under the data
  # volume's root instead of $SWAPDIR, which a text match would miss (and leave the image attached).
  if [ "$(stat -f %d "$SWAPDIR")" != "$(stat -f %d "$VAULT")" ]; then
    bad "a disk image was mounted over a vault folder (AUTH_MOUNT not denied)"
    hdiutil detach -quiet "$SWAPDIR"
  else
    sleep 1   # denials are stored in batches
    # Reading the recorded history needs root (or the signed app): sudo, as root a no-op.
    if sudo "$WR" events --denied --since 2m --json \
         | jq -e --arg p "$SWAPDIR" 'any(.[]; .operation == "mount" and .path == $p)' >/dev/null; then
      ok "mount over a vault folder denied (AUTH_MOUNT, recorded)"
    else
      echo "INCONCLUSIVE  mount over a vault folder failed, but no denied mount event was recorded: $(tr '\n' ' ' < "$TMPDIR/err")"
    fi
  fi
else
  echo "SKIP  mount over a vault folder: hdiutil could not create a disk image"
fi

echo "== coverage: truncate and swap (read and write decided apart)"
# Path rules that tell reads from writes, so that a check passes only if the access kind is right:
# the canary may be read but not written, the swap folder written but not read.
sudo "$WR" rules disable m5-deny-vault >/dev/null
cat > "$RULE" <<JSON
[{"id":"m5-cov-canary-read","enabled":true,"enforce":true,"target":{"pathPrefix":"$CANARY"},
  "subject":{"type":"anyNonOwner"},"access":"read","action":"allow","includePlatformBinaries":true},
 {"id":"m5-cov-canary-write","enabled":true,"enforce":true,"target":{"pathPrefix":"$CANARY"},
  "subject":{"type":"anyNonOwner"},"access":"write","action":"deny","includePlatformBinaries":true},
 {"id":"m5-cov-swap-write","enabled":true,"enforce":true,"target":{"pathPrefix":"$SWAPDIR"},
  "subject":{"type":"anyNonOwner"},"access":"write","action":"allow","includePlatformBinaries":true},
 {"id":"m5-cov-swap-read","enabled":true,"enforce":true,"target":{"pathPrefix":"$SWAPDIR"},
  "subject":{"type":"anyNonOwner"},"access":"read","action":"deny","includePlatformBinaries":true}]
JSON
sudo "$WR" rules add --json-file "$RULE" >/dev/null
sleep 0.3
allowed /bin/cat "$CANARY" && ok "precondition: the canary may be read" || bad "precondition: reading the canary was denied"
# files-8: open(O_RDONLY|O_TRUNC) empties the file without FWRITE: it is a write.
TRUNC=()
if [ -n "$HAVE_CLT" ]; then
  TRUNC=(/usr/bin/python3 -c "import os, sys; os.open(sys.argv[1], os.O_RDONLY | os.O_TRUNC)")
elif [ -x /usr/bin/perl ]; then
  TRUNC=(/usr/bin/perl -MFcntl -e 'sysopen(my $f, $ARGV[0], O_RDONLY | O_TRUNC) or die "open: $!\n"')
fi
if [ ${#TRUNC[@]} -gt 0 ]; then
  denied "${TRUNC[@]}" "$CANARY" && ok "open(O_RDONLY|O_TRUNC) denied as a write" \
    || bad "open(O_RDONLY|O_TRUNC) was not denied (files-8): $(cat "$TMPDIR/err")"
else
  bad "no way to issue open(O_RDONLY|O_TRUNC): neither python3 (Command Line Tools) nor perl"
fi
[ -s "$CANARY" ] && ok "canary not truncated" || bad "canary was truncated by a read-only open (files-8)"
# files-5: renamex_np(RENAME_SWAP) onto an existing vault folder moves the folder out (a read of it).
# The decoy is the test user's: swapping two folders needs write access to both.
as_user /bin/mkdir -p "$TMPDIR/m5-decoy"
cat > "$TMPDIR/m5-swap.c" <<'C'
#include <stdio.h>
int main(int c, char **v) { if (c != 3 || renamex_np(v[1], v[2], RENAME_SWAP) != 0) { perror("renamex_np"); return 1; } return 0; }
C
if [ -n "$HAVE_CLT" ] && cc -w -o "$TMPDIR/m5-swap" "$TMPDIR/m5-swap.c" 2>"$TMPDIR/err"; then
  SWAP=("$TMPDIR/m5-swap")
elif [ -x /usr/bin/perl ]; then
  # renamex_np(a, b, f) is renameatx_np(AT_FDCWD, a, AT_FDCWD, b, f): 488 is SYS_renameatx_np
  # (sys/syscall.h), -2 AT_FDCWD (sys/fcntl.h), 2 RENAME_SWAP (sys/stdio.h).
  SWAP=(/usr/bin/perl -e 'syscall(488, -2, $ARGV[0], -2, $ARGV[1], 2) == 0 or die "renamex_np: $!\n"')
fi
if [ ${#SWAP[@]} -gt 0 ]; then
  if denied "${SWAP[@]}" "$TMPDIR/m5-decoy" "$SWAPDIR"; then
    ok "RENAME_SWAP onto a vault folder denied (the folder counts as read)"
  else
    bad "RENAME_SWAP onto a vault folder was not denied (files-5): $(cat "$TMPDIR/err")"
    [ -f "$TMPDIR/m5-decoy/secret" ] && "${SWAP[@]}" "$TMPDIR/m5-decoy" "$SWAPDIR"
  fi
else
  bad "no way to issue renamex_np(RENAME_SWAP): neither the Command Line Tools (cc) nor perl"
fi
for r in m5-cov-canary-read m5-cov-canary-write m5-cov-swap-write m5-cov-swap-read; do sudo "$WR" rules delete "$r" >/dev/null; done
sudo "$WR" rules enable m5-deny-vault >/dev/null
sleep 0.3

echo "== AI agent chain rule"
sudo "$WR" rules disable m5-deny-vault >/dev/null
# In ask mode an undecided read is denied at once here (nothing answers questions in the VM), so a
# plain cat would be denied with or without the template. An allow rule decides it instead: then
# only the template separates the two chains, and the agent-chain denial shows that deny beats allow.
ALLOW_RULE=$(mktemp "$TMPDIR/whoread-m5-rule.XXXXXX")
cat > "$ALLOW_RULE" <<JSON
{"id":"m5-allow-vault-read","name":"M5: allow reading the test vault","enabled":true,"enforce":true,
 "target":{"category":"test-vault"},"subject":{"type":"anyNonOwner"},"access":"read","action":"allow",
 "includePlatformBinaries":true}
JSON
sudo "$WR" rules add --json-file "$ALLOW_RULE" >/dev/null || bad "could not add the allow rule"
sudo "$WR" rules enforce template.block-agents-critical >/dev/null
sleep 0.3
allowed /bin/cat "$CREDS" && ok "plain cat allowed (no agent in chain)" || bad "plain cat denied"
# argv[0] "claude" makes this shell look like Claude Code (agents.json argv0Names). The command must
# not be the last one in the -c string, otherwise bash execs it in place and the 'claude' ancestor
# disappears from the chain.
# As root, the probe runs as the test user below the 'claude' shell (claude → sudo → probe).
as_agent() { ( exec -a claude /bin/bash -c '"$@"; rc=$?; exit $rc' claude ${AS[@]+"${AS[@]}"} "$@" ); }
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
sudo "$WR" rules delete m5-allow-vault-read >/dev/null || bad "could not delete the allow rule"
sudo "$WR" rules enable m5-deny-vault >/dev/null
sleep 0.3

# Now, not at the end: "enforcement on" below starts a new latency window, and the daemon
# restarted after the SIGKILL starts with an empty one. The checks above are only a few dozen
# AUTH responses; a burst of denied opens (denials are never cached) gives p99 enough samples.
for _ in $(seq 200); do as_user /bin/cat "$KEY" >/dev/null 2>&1; done
echo "== latency"
"$WR" status --json | jq -r '.latency | "  AUTH responses: \(.totalResponses) (\(.samples) in the window), p50 \(.p50Micros | round) µs, p99 \(.p99Micros | round) µs, max \(.maxMicros | round) µs, deadline misses \(.deadlineMisses)"'
# macOS 27 and later: the file client runs in ES_DEADLINE_MISS_MODE_FAIL_CLOSED (a missed deadline
# or a message dropped from a full queue is denied, the daemon is not killed); before 27, kill.
dmode=$("$WR" status --json | jq -r '.sourceDeadlineMissMode // ""')
major=$(sw_vers -productVersion | cut -d. -f1)
if [ "$major" -ge 27 ]; then
  [ "$dmode" = "fail-closed" ] && ok "AUTH deadline miss mode: fail-closed" || bad "AUTH deadline miss mode on macOS $major: '$dmode' (expected fail-closed)"
else
  [ "$dmode" = "kill" ] && ok "AUTH deadline miss mode: kill (macOS $major has no other)" || bad "AUTH deadline miss mode: '$dmode' (expected kill)"
fi
active=$("$WR" status --json | jq -r '.enforcementActive')
[ "$active" = "true" ] && ok "enforcement still on after the burst (never switched off automatically)" \
  || bad "enforcement went off after the burst"

echo "== kill switches (each must take effect immediately)"
t() { jq -n 'now'; }
since() { jq -n "($(t) - $1) * 1000 | round / 1000"; }   # seconds since T, 3 decimals
first_allowed() { local s; s=$(t); for _ in $(seq 100); do allowed /bin/cat "$KEY" && { since "$s"; return 0; }; sleep 0.02; done; echo "timeout"; return 1; }
first_denied()  { local s; s=$(t); for _ in $(seq 100); do denied /bin/cat "$KEY" && { since "$s"; return 0; }; sleep 0.02; done; echo "timeout"; return 1; }
denied /bin/cat "$KEY" || bad "precondition: not denied"
sudo "$WR" enforcement off >/dev/null; d=$(first_allowed) && ok "CLI 'enforcement off' took effect in ${d}s" || bad "CLI kill switch: $d"
"$WR" enforcement on >/dev/null; d=$(first_denied) && ok "re-enabled in ${d}s" || bad "re-enable: $d"
KILL_SWITCH=1
sudo "$WR" kill-switch engage >/dev/null; d=$(first_allowed) && ok "kill-switch file took effect in ${d}s" || bad "file kill switch: $d"
sudo "$WR" kill-switch release >/dev/null; d=$(first_denied) && ok "file released in ${d}s" || bad "file release: $d"
KILL_SWITCH=""
echo "MANUAL  UI switch: open the WhoRead menu, turn Enforcement off, then run: cat $KEY  (must succeed at once)"

echo "== daemon killed"
( for _ in $(seq 200); do as_user /bin/cat "$KEY" >/dev/null 2>&1 && echo ok || echo denied; sleep 0.01; done ) > "$TMPDIR/m5-loop" &
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
enforcement_state() { "$WR" status --json | jq -r '"\(if .enforcementActive then "on" else "off" end) \(if (.uncleanStop // "") == "" then "(no unclean-stop note)" else .uncleanStop end)"'; }
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
[ $rc -eq 0 ] && ok "undecided read denied at once with no answering app ($(jq -n "($e - $s) * 100 | round / 100") s)" \
  || bad "undecided read was not denied"
# A stand-in for the app: polling questions makes the daemon hold accesses and wait for an answer.
( while :; do "$WR" asks --json >/dev/null 2>&1; sleep 1; done ) &
POLL=$!
sleep 1.5
( s=$(t); as_user /bin/cat "$CREDS" >/dev/null 2>&1; rc=$?; echo "rc=$rc after $(jq -n "($(t) - $s) * 100 | round / 100") s" ) > "$TMPDIR/m5-ask" &
HELD=$!
sleep 1
# The question that holds this cat: other questions can be open (the first denied-at-once read
# above, or whatever else in the VM touched a sensitive file meanwhile).
id=$("$WR" asks --json | jq -r '[.[] | select(.key.categoryID == "test-vault" and .holding > 0
                                              and ((.path // "") | endswith("WhoReadTestVault/aws/credentials")))]
                                 | if length > 0 then .[0].id else "" end')
[ -n "$id" ] && ok "question #$id listed while cat waits" || bad "no question holding the cat of $CREDS: $("$WR" asks 2>&1 | head -n 12)"
[ -n "$id" ] && { sudo "$WR" ask "$id" allow-once >/dev/null && ok "answered: allow once" || bad "answering failed"; }
wait $HELD
r=$(cat "$TMPDIR/m5-ask")
case "$r" in rc=0*) ok "the held cat went through after the answer: $r" ;; *) bad "held cat after the answer: $r" ;; esac
# Unanswered: the access waits for its budget and is then denied. The time it waits is the deadline
# budget on this Mac (deadline minus 20 %, headroom clamped to 1-5 s).
s=$(t); as_user /bin/sh -c 'echo x >> "$1"' sh "$VAULT/ssh/m5-new" 2>/dev/null; rc=$?; e=$(t)
[ $rc -ne 0 ] && ok "unanswered write denied after $(jq -n "($e - $s) * 100 | round / 100") s (the hold budget)" \
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
    s=$(t); as_user /bin/cat "$KEY" >/dev/null 2>"$TMPDIR/err"; rc=$?; e=$(t)
    echo "  cat returned rc=$rc after $(jq -n "($e - $s) * 100 | round / 100") s: $(cat "$TMPDIR/err")"
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
    echo "  (expected before macOS 27 (kill mode, WWDC20): client killed at the deadline,"
    echo "   implicit allow; macOS 27 and later (fail-closed): the cat denied at the deadline, the daemon not killed)"
  fi
fi

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
