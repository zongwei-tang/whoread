#!/bin/bash
# End-to-end smoke test on any host (no root, no macOS): whoreadd with a fake eslogger that
# replays a fixture, queried by the whoread CLI over the dev Unix socket.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
swift build >/dev/null
BIN="$ROOT/.build/debug"
TMP="$(mktemp -d)"
trap 'kill ${DPID:-} 2>/dev/null || true; rm -rf "$TMP"' EXIT
FIXTURE="${1:-$ROOT/Tests/Fixtures/eslogger/schema-v1-msgv10/scenario.jsonl}"
cat > "$TMP/eslogger" <<SH
#!/bin/sh
cat "$FIXTURE"
exec sleep 600
SH
chmod +x "$TMP/eslogger"
"$BIN/whoreadd" run --source eslogger --eslogger "$TMP/eslogger" --data-dir "$TMP/data" --defaults "$ROOT/Data" \
  --home /Users/alice --dev-socket "$TMP/s.sock" --kill-switch "$TMP/data/disable-enforcement" --no-seed --permissive \
  2> "$TMP/daemon.log" &
DPID=$!
for _ in $(seq 50); do [ -S "$TMP/s.sock" ] && break; sleep 0.1; done
W() { "$BIN/whoread" --socket "$TMP/s.sock" "$@"; }
sleep 0.5
echo "== status";  W status
echo "== events --agents-only"; W events --agents-only
echo "== alerts"; W alerts
echo "== apps"; W apps
echo "== files"; W files
echo "== agents"; W agents
echo "== export csv (first 3 lines)"; W export --format csv | head -3
echo "== rules"; W rules
echo "== enforcement on (replay/eslogger cannot enforce)"; W enforcement on
echo "== kill switch"; "$BIN/whoread" kill-switch engage --path "$TMP/data/disable-enforcement"
# The watcher polls every 200 ms; the daemon must report the file, not just print the line.
seen=""
for _ in $(seq 20); do W status | grep "kill switch:" | grep -q "PRESENT" && { seen=1; break; }; sleep 0.1; done
W status | grep "kill switch:"
[ -n "$seen" ] || { echo "FAIL: the daemon did not observe the kill-switch file" >&2; cat "$TMP/daemon.log" >&2; exit 1; }
echo "== daemon log"; cat "$TMP/daemon.log"
