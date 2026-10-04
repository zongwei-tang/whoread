#!/bin/bash
# M0: captures ~60 s of eslogger output on this Mac while exercising the test vault.
#
# Needs: sudo, and Full Disk Access for the app running this script (Terminal / iTerm).
# The raw capture contains every file your Mac opened for a minute and the full environment of
# every exec (tokens included). It is written 0600 to Tests/Fixtures/eslogger/captured/raw/
# (gitignored) and deleted after sanitizing unless KEEP_RAW=1. Only the sanitized subset is meant
# to be committed.
#
# Process groups matter: eslogger suppresses events from its own process group, so job control is
# enabled (set -m) to give the background eslogger its own group, separate from the test commands.
set -euo pipefail
set -m
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTDIR="$ROOT/Tests/Fixtures/eslogger/captured"
RAW="$OUTDIR/raw"
mkdir -p "$RAW"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OS="$(sw_vers -productVersion)"
OUT="$RAW/eslogger-$OS-$STAMP.jsonl"
VAULT="$HOME/WhoReadTestVault"
DURATION="${DURATION:-60}"
TMPDIR="${TMPDIR:-/tmp}"

"$ROOT/scripts/create-test-vault.sh" >/dev/null
sudo -v
echo "Capturing $DURATION s of eslogger output to $OUT"
sudo /usr/bin/eslogger open close exec fork exit rename clone copyfile link unlink truncate > "$OUT" 2> "$OUT.stderr" &
ESPID=$!
# Never leave a root eslogger streaming into the repo: stop it on any exit (error, Ctrl-C).
stop_es() { sudo kill -INT -- "-$ESPID" 2>/dev/null || sudo kill -INT "$ESPID" 2>/dev/null || true; wait "$ESPID" 2>/dev/null || true; }
trap stop_es EXIT
trap 'exit 130' INT TERM HUP
sleep 3
ps -p "$ESPID" >/dev/null || { echo "eslogger exited early (Full Disk Access for this terminal?): $(cat "$OUT.stderr")" >&2; exit 1; }

# Exercise the vault the same way the M2 acceptance test does.
cat "$VAULT/ssh/id_ed25519" > /dev/null
/usr/bin/python3 -c "open('$VAULT/aws/credentials').read()" || true
if command -v node >/dev/null; then node -e "require('fs').readFileSync('$VAULT/ssh/id_ed25519')"; fi
( cat "$VAULT/aws/credentials" > /dev/null & ) ; sleep 1
cp -c "$VAULT/aws/credentials" "$TMPDIR/whoread-clone-test" 2>/dev/null || cp "$VAULT/aws/credentials" "$TMPDIR/whoread-clone-test"
ln "$VAULT/notes/todo.txt" "$TMPDIR/whoread-link-test" 2>/dev/null || true
mv "$VAULT/notes/old.txt" "$VAULT/notes/old-renamed.txt" && mv "$VAULT/notes/old-renamed.txt" "$VAULT/notes/old.txt"
: > "$VAULT/notes/truncate-me.txt"; echo x >> "$VAULT/notes/truncate-me.txt"
rm -f "$TMPDIR/whoread-clone-test" "$TMPDIR/whoread-link-test" "$VAULT/notes/truncate-me.txt"
mdls "$VAULT/notes/todo.txt" > /dev/null 2>&1 || true

REMAIN=$(( DURATION - 3 - 2 ))
[ "$REMAIN" -gt 0 ] && sleep "$REMAIN"
# Interrupt only our own eslogger (its process group, thanks to set -m).
stop_es
trap - EXIT INT TERM HUP
sudo chown "$(id -u):$(id -g)" "$OUT" "$OUT.stderr"
echo "Raw capture: $(wc -l < "$OUT") lines, $(du -h "$OUT" | cut -f1). stderr: $(wc -c < "$OUT.stderr") bytes"
[ -s "$OUT" ] || { echo "eslogger captured nothing: $(cat "$OUT.stderr")" >&2; exit 1; }

if [ -x "$ROOT/build/whoread" ] || command -v whoread >/dev/null; then
  WR="$(command -v whoread || echo "$ROOT/build/whoread")"
else
  (cd "$ROOT" && swift build -c release --product whoread >/dev/null) && WR="$ROOT/.build/release/whoread"
fi
SAN="$OUTDIR/macos-$OS"
mkdir -p "$SAN"
"$WR" fixture sanitize --home "$HOME" --input "$OUT" --output "$SAN/capture.jsonl" --vault "$VAULT" --sample 40
[ "${KEEP_RAW:-0}" = 1 ] || rm -f "$OUT" "$OUT.stderr"
echo "Sanitized fixture: $SAN/capture.jsonl  (review it, then commit it)"
