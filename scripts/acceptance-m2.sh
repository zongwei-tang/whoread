#!/bin/bash
# M2 acceptance on the Mac (host, monitor only). Prerequisites:
#   - dev LaunchDaemon installed with the eslogger source and Full Disk Access granted
#   - scripts/create-test-vault.sh has been run
# Only ~/WhoReadTestVault is read. Each probe runs in its own process group (set -m), separate
# from the daemon's, so eslogger does not suppress it.
set -uo pipefail
set -m
VAULT="$HOME/WhoReadTestVault"
WR="${WHOREAD:-whoread}"
PASS=0; FAIL=0; INCOMPLETE=""
ok()   { echo "PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
python3_bin="/usr/bin/python3"
node_bin="$(command -v node || true)"

"$WR" status >/dev/null || { echo "daemon not reachable (is it installed and running?)"; exit 1; }
[ -f "$VAULT/ssh/id_ed25519" ] || { echo "run scripts/create-test-vault.sh first"; exit 1; }

probe() { # name, expected leaf name, command...
  local name="$1" leaf="$2"; shift 2
  local start; start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local t0; t0=$(python3 -c 'import time; print(time.time())')
  "$@" >/dev/null 2>&1
  # The chain must be complete: rooted at launchd (pid 1) with this script ($$) above the leaf.
  local found="" result=""
  for _ in $(seq 40); do
    result=$("$WR" events --since "$start" --json 2>/dev/null | python3 -c '
import json,sys
leaf, me = sys.argv[1], int(sys.argv[2])
wrong = ""
for e in json.load(sys.stdin):
    ch = e["chain"]
    if not (ch and ch[-1]["name"].lower().startswith(leaf) and "WhoReadTestVault" in e["path"]):
        continue
    text = " → ".join("%s(%d)" % (c["name"], c["pid"]) for c in ch)
    if ch[0]["pid"] == 1 and any(c["pid"] == me for c in ch[:-1]):
        print("ok " + text); break
    wrong = "wrong " + text
else:
    print(wrong)
' "$leaf" "$$")
    case "$result" in ok\ *) found="${result#ok }"; break ;; esac
    sleep 0.05
  done
  local dt; dt=$(python3 -c "import time; print(round(time.time()-$t0,2))")
  if [ -n "$found" ] && python3 -c "import sys; sys.exit(0 if $dt <= 2.0 else 1)"; then
    ok "$name recorded in ${dt}s, chain: $found"
  elif [ -n "$found" ]; then
    bad "$name recorded but took ${dt}s (> 2 s): $found"
  elif [ -n "$result" ]; then
    bad "$name recorded with a wrong parent chain (expected launchd(1) … bash($$) … $leaf): ${result#wrong }"
  else
    bad "$name not recorded within 2 s"
  fi
}

probe "cat reads fake private key"       cat     /bin/cat "$VAULT/ssh/id_ed25519"
probe "python3 reads fake credentials"   python  "$python3_bin" -c "open('$VAULT/aws/credentials').read()"
if [ -n "$node_bin" ]; then
  probe "node reads fake private key"    node    "$node_bin" -e "require('fs').readFileSync('$VAULT/ssh/id_ed25519')"
else
  echo "SKIP  node not installed"
fi

# Spotlight: modify a vault file and wait for mdworker to index it (folded by default).
echo "spotlight $(date)" >> "$VAULT/notes/spotlight.txt"
mdimport "$VAULT/notes/spotlight.txt" >/dev/null 2>&1 || true
folded=""
for _ in $(seq 60); do
  folded=$("$WR" events --since 2m --all --json | python3 -c '
import json,sys
ev=json.load(sys.stdin)
print("yes" if any(e.get("benignServiceID")=="spotlight" for e in ev) else "")')
  [ -n "$folded" ] && break
  sleep 1
done
if [ -n "$folded" ]; then
  hidden=$("$WR" events --since 2m --json | python3 -c 'import json,sys; print(sum(1 for e in json.load(sys.stdin) if e.get("benignServiceID")))')
  [ "$hidden" = "0" ] && ok "Spotlight read recorded and folded (hidden without --all)" || bad "Spotlight read visible without --all"
else
  # An M2 acceptance item: not verified means not accepted.
  echo "INCOMPLETE  no Spotlight read seen within 60 s (indexing off for this folder, or benign.json no longer matches mdworker)"
  INCOMPLETE=1
fi

# CLI query and export.
"$WR" events --since 5m --category test-vault >/dev/null && ok "CLI query" || bad "CLI query"
tmp=$(mktemp -d)
"$WR" export --format json --since 5m --output "$tmp/e.json" && python3 -c "import json; json.load(open('$tmp/e.json'))" && ok "export JSON" || bad "export JSON"
"$WR" export --format csv --since 5m --output "$tmp/e.csv" && head -1 "$tmp/e.csv" | grep -q '^id,time,operation' && ok "export CSV" || bad "export CSV"
rm -rf "$tmp"
echo
echo "$PASS passed, $FAIL failed${INCOMPLETE:+, Spotlight folding NOT verified}"
[ "$FAIL" -eq 0 ] && [ -z "$INCOMPLETE" ]
