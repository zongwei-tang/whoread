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
# The checks below match the English output.
export WHOREAD_LANG=en
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
fail() { echo "FAIL: $*" >&2; cat "$TMP/daemon.log" >&2; exit 1; }

echo "== settings set language (zh means zh-Hans; an unknown value is refused, not 'system')"
W settings set language zh | grep -q '"zh-Hans"' || fail "language zh was not stored as zh-Hans"
if W settings set language english 2>/dev/null; then fail "language english was accepted"; fi
W settings | grep -q '"zh-Hans"' || fail "a refused language value changed the setting"

echo "== status: no learning period, enforcement never switched off automatically"
# Captured first: a failing `W status` must stop the script, not pass for "no match".
st=$(W status)
if grep -qiE "learning|trip" <<< "$st"; then fail "status still mentions learning or a latency trip"; fi

echo "== asks (ask mode; eslogger cannot hold an access, so nothing is waiting)"
W asks | tee "$TMP/asks.out"
grep -q "No questions waiting" "$TMP/asks.out" || fail "asks did not report an empty list"
[ "$(W asks --json | tr -d '[:space:]')" = "[]" ] || fail "asks --json is not an empty list"
rc=0; W ask 999999 deny 2> "$TMP/err" || rc=$?
cat "$TMP/err"
[ "$rc" = 1 ] && grep -q "notFound" "$TMP/err" || fail "answering an unknown question: rc $rc"
if W ask 999999 maybe 2>/dev/null; then fail "an unknown answer was accepted"; fi

echo "== settings set trust-apple on|off (round trip)"
W settings set trust-apple on | grep -Eq '"trustApplePrograms" *: *true' || fail "trust-apple on was not stored"
W status | grep -q "trust Apple:  on" || fail "status does not show trust-apple on"
W settings set trust-apple off | grep -Eq '"trustApplePrograms" *: *false' || fail "trust-apple off was not stored"
W settings | grep -Eq '"trustApplePrograms" *: *false' || fail "trust-apple off did not persist"
st=$(W status)
if grep -q "trust Apple" <<< "$st"; then fail "status still shows trust-apple after turning it off"; fi

echo "== catalog add-path refuses a home or a folder above one (or the whole disk), however spelled"
for p in /Users/alice /Users/alice/ /users/ALICE /Users /System/Volumes/Data/Users/alice /System/Volumes/Data/; do
  if W catalog add-path custom "$p" 2>/dev/null; then fail "add-path $p was accepted"; fi
done
W catalog add-path custom "/Users/alice/Tax Docs"
# Unquoted, the path is two words: refused instead of adding /Users/alice/Tax.
if W catalog add-path custom /Users/alice/Tax Docs 2>/dev/null; then fail "a stray positional was ignored"; fi
W catalog export --output "$TMP/catalog.json" && W catalog import "$TMP/catalog.json"
if command -v python3 >/dev/null; then
  python3 - "$TMP/catalog.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
next(x for x in c["categories"] if x["id"] == "custom")["paths"].append("/Users/alice")
json.dump(c, open(sys.argv[1], "w"))
PY
  if W catalog import "$TMP/catalog.json" 2>/dev/null; then fail "import of a catalog that monitors a whole home was accepted"; fi
fi

if command -v python3 >/dev/null; then
  echo "== export pages past undecodable rows"
  # Copies of the fixture's rows past the 5000-event export page, then one undecodable body
  # inside the first page and more than a whole page of them later on.
  expected=$(python3 - "$TMP/data/whoread.sqlite" <<'PY'
import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1], timeout=10)
cols = [r[1] for r in db.execute("PRAGMA table_info(events)")]
rows = db.execute("SELECT * FROM events ORDER BY id").fetchall()
body, first = cols.index("body"), max(r[0] for r in rows) + 1
copies = []
for i in range(13000):
    r = list(rows[i % len(rows)])
    r[0] = first + i
    b = json.loads(r[body]); b["id"] = r[0]; r[body] = json.dumps(b).encode()
    copies.append(r)
db.executemany("INSERT INTO events(%s) VALUES(%s)" % (",".join(cols), ",".join("?" * len(cols))), copies)
db.execute("UPDATE events SET body = X'7b7d' WHERE id = ? OR id BETWEEN ? AND ?", (first + 100, first + 6000, first + 11999))
db.commit()
print(db.execute("SELECT COUNT(*) FROM events WHERE benign = 0 AND body != X'7b7d'").fetchone()[0])
PY
)
  got=$(W export --format jsonl 2> "$TMP/export.err" | wc -l | tr -d ' ')
  cat "$TMP/export.err"
  [ "$got" = "$expected" ] || fail "export wrote $got of $expected decodable events"
  grep -q "could not decode" "$TMP/export.err" || fail "export did not report the undecodable rows"
fi

echo "== no daemon vs. a refusal the daemon answered"
rc=0; "$BIN/whoread" --socket "$TMP/missing.sock" status 2> "$TMP/err" || rc=$?
cat "$TMP/err"
[ "$rc" = 69 ] && grep -q "cannot reach" "$TMP/err" || fail "no daemon: rc $rc"
kill "$DPID"; wait "$DPID" 2>/dev/null || true
# Without --permissive a non-root peer is refused, and the suggested sudo command must paste back
# as the same arguments.
"$BIN/whoreadd" run --source eslogger --eslogger "$TMP/eslogger" --data-dir "$TMP/strict" --defaults "$ROOT/Data" \
  --home /Users/alice --dev-socket "$TMP/s2.sock" --kill-switch "$TMP/strict/disable-enforcement" --no-seed \
  2>> "$TMP/daemon.log" &
DPID=$!
for _ in $(seq 50); do [ -S "$TMP/s2.sock" ] && break; sleep 0.1; done
rc=0; "$BIN/whoread" --socket "$TMP/s2.sock" catalog add-path custom "/Users/alice/Tax Docs" 2> "$TMP/err" || rc=$?
cat "$TMP/err"
[ "$rc" = 77 ] && ! grep -q "cannot reach" "$TMP/err" || fail "non-root catalog change: rc $rc"
grep -qF "sudo whoread --socket $TMP/s2.sock catalog add-path custom '/Users/alice/Tax Docs'" "$TMP/err" \
  || fail "the sudo hint lost the quoting"
# Allowing a question needs root or the app. (On Linux /dev/console is root's, so the daemon refuses
# every non-root peer; AskCLITests checks the wording the console user gets.)
rc=0; "$BIN/whoread" --socket "$TMP/s2.sock" ask 1 allow 2> "$TMP/err" || rc=$?
cat "$TMP/err"
[ "$rc" = 77 ] && grep -qF "sudo whoread --socket $TMP/s2.sock ask 1 allow" "$TMP/err" || fail "non-root ask allow: rc $rc"
rc=0; "$BIN/whoread" --socket "$TMP/s2.sock" settings set trust-apple on 2> "$TMP/err" || rc=$?
[ "$rc" = 77 ] || fail "non-root trust-apple on: rc $rc"

echo "== daemon log"; cat "$TMP/daemon.log"
