#!/bin/bash
# M0: captures ~60 s of eslogger output on this Mac while exercising the test vault.
#
# Needs: sudo, and Full Disk Access for the app running this script (Terminal / iTerm).
# The raw capture contains every file your Mac opened for a minute and the full environment of
# every exec, root's and other users' processes included (tokens included). Only root can read it:
# root creates a fresh 0700 directory under /private/tmp (sticky, so nobody else can rename or
# replace it), eslogger's output is opened there by root, and the sanitizer reads it through
# `sudo cat`. The directory is removed on every exit (success, error, Ctrl-C) unless KEEP_RAW=1,
# which leaves it there, still root-only, and prints its path. Root never opens, changes or removes
# anything in this user-writable repository, and only runs absolute paths.
# Same-user code (an AI agent included) cannot open the raw capture, but it can read the sanitized
# fixture, and it could edit this script while it runs or replace the whoread it builds (which is fed
# the raw capture): stop such agents first. Only the sanitized subset is meant to be committed;
# review it first.
#
# Process groups matter: eslogger suppresses events from its own process group, so job control is
# enabled (set -m) to give the background eslogger its own group, separate from the test commands.
set -euo pipefail
set -m
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTDIR="$ROOT/Tests/Fixtures/eslogger/captured"
OS="$(sw_vers -productVersion)"
VAULT="$HOME/WhoReadTestVault"
DURATION="${DURATION:-60}"
TMPDIR="${TMPDIR:-/tmp}"

# The sanitizer first: a failed build must not leave a capture behind. Always this checkout's, built from
# the same source as this script: an installed whoread (the app's CLI on PATH, say) may be older, and an
# older one takes --capture-pid for an unknown switch and silently applies its own, leakier rules.
(cd "$ROOT" && swift build -c release --product whoread >/dev/null) || { echo "building whoread failed" >&2; exit 1; }
WR="$ROOT/.build/release/whoread"

# The vault exercised below, whatever WHOREAD_TEST_VAULT says.
WHOREAD_TEST_VAULT="$VAULT" "$ROOT/scripts/create-test-vault.sh" >/dev/null
sudo -v

RAWDIR=
ESPID=
SCRATCH=
# Interrupt only our own eslogger (its process group, thanks to set -m).
stop_es() {
  [ -n "$ESPID" ] || return 0
  sudo /bin/kill -INT -- "-$ESPID" 2>/dev/null || sudo /bin/kill -INT "$ESPID" 2>/dev/null || true
  wait "$ESPID" 2>/dev/null || true
  ESPID=
}
# On any exit: never leave a root eslogger streaming, nor the raw capture behind.
cleanup() {
  local rc=$?
  stop_es
  if [ -n "$SCRATCH" ]; then rm -f "$SCRATCH/clone" "$SCRATCH/link"; rmdir "$SCRATCH" 2>/dev/null || true; fi
  [ -n "$RAWDIR" ] || return 0
  if [ "${KEEP_RAW:-0}" = 1 ]; then
    echo "Raw capture kept, readable only by root: $RAWDIR (remove it with: sudo rm $RAWDIR/raw.jsonl $RAWDIR/eslogger.stderr && sudo rmdir $RAWDIR)" >&2
  elif sudo /bin/rm -f "$RAWDIR/raw.jsonl" "$RAWDIR/eslogger.stderr" && sudo /bin/rmdir "$RAWDIR"; then
    [ "$rc" = 0 ] || echo "capture-fixture.sh failed (exit $rc); the raw capture was removed" >&2
  else
    echo "Could not remove the raw capture in $RAWDIR (root-only): remove it with sudo" >&2
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

RAWDIR="$(sudo /usr/bin/mktemp -d /private/tmp/whoread-capture.XXXXXXXX)"
# Clone and link targets: a fresh directory, never fixed names in a shared one.
SCRATCH="$(mktemp -d "$TMPDIR/whoread-capture-test.XXXXXX")"
echo "Capturing $DURATION s of eslogger output into $RAWDIR (root-only)"
# Root opens the output files, inside its own directory. The events are EsloggerSource.eventNames(readdir: false).
sudo /bin/sh -c 'umask 077; out="$1"; err="$2"; shift 2; exec "$@" > "$out" 2> "$err"' sh "$RAWDIR/raw.jsonl" "$RAWDIR/eslogger.stderr" \
  /usr/bin/eslogger open close exec fork exit rename clone copyfile link unlink truncate exchangedata create setmode setowner setacl setattrlist mount &
ESPID=$!
sleep 3
ps -p "$ESPID" >/dev/null || { echo "eslogger exited early (Full Disk Access for this terminal?): $(sudo /bin/cat "$RAWDIR/eslogger.stderr")" >&2; exit 1; }

# Exercise the vault the same way the M2 acceptance test does.
cat "$VAULT/ssh/id_ed25519" > /dev/null
/usr/bin/python3 -c "open('$VAULT/aws/credentials').read()" || true
if command -v node >/dev/null; then node -e "require('fs').readFileSync('$VAULT/ssh/id_ed25519')"; fi
( cat "$VAULT/aws/credentials" > /dev/null & ) ; sleep 1
cp -c "$VAULT/aws/credentials" "$SCRATCH/clone" 2>/dev/null || cp "$VAULT/aws/credentials" "$SCRATCH/clone"
ln "$VAULT/notes/todo.txt" "$SCRATCH/link" 2>/dev/null || true
mv "$VAULT/notes/old.txt" "$VAULT/notes/old-renamed.txt" && mv "$VAULT/notes/old-renamed.txt" "$VAULT/notes/old.txt"
# Whatever was left at this name (a link, say) is not written through.
rm -f "$VAULT/notes/truncate-me.txt"
: > "$VAULT/notes/truncate-me.txt"; echo x >> "$VAULT/notes/truncate-me.txt"
rm -f "$SCRATCH/clone" "$SCRATCH/link" "$VAULT/notes/truncate-me.txt"
# The creates the parser records (a regular file's create comes with its creating open): a symlink and a directory.
rm -f "$VAULT/notes/link-me"
ln -s todo.txt "$VAULT/notes/link-me" && rm -f "$VAULT/notes/link-me"
rmdir "$VAULT/notes/dir-me" 2>/dev/null || true
mkdir "$VAULT/notes/dir-me" && rmdir "$VAULT/notes/dir-me"
mdls "$VAULT/notes/todo.txt" > /dev/null 2>&1 || true

REMAIN=$(( DURATION - 3 - 2 ))
[ "$REMAIN" -gt 0 ] && sleep "$REMAIN"
stop_es
echo "Raw capture: $(sudo /usr/bin/wc -l "$RAWDIR/raw.jsonl" | awk '{print $1}') lines, $(sudo /usr/bin/du -h "$RAWDIR/raw.jsonl" | cut -f1)." \
  "stderr: $(sudo /usr/bin/wc -c "$RAWDIR/eslogger.stderr" | awk '{print $1}') bytes"
sudo /bin/test -s "$RAWDIR/raw.jsonl" || { echo "eslogger captured nothing: $(sudo /bin/cat "$RAWDIR/eslogger.stderr")" >&2; exit 1; }

SAN="$OUTDIR/macos-$OS"
mkdir -p "$SAN"
# Only the vault events of this script's own processes (and of Apple's programs) are kept.
sudo /bin/cat "$RAWDIR/raw.jsonl" | "$WR" fixture sanitize --home "$HOME" --input /dev/stdin --output "$SAN/capture.jsonl" \
  --vault "$VAULT" --capture-pid "$$" --sample 40
echo "Sanitized fixture: $SAN/capture.jsonl  (review it, then commit it)"
