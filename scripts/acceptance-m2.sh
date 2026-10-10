#!/bin/bash
# timeout: 600
# M2 acceptance (monitor only); in the test VM with the native source it is the M4 check. Run as
# root, either way:
#   sudo scripts/acceptance-m2.sh                            on your Mac (the probes run as you)
#   scripts/vm/vmjob.sh run m2 scripts/acceptance-m2.sh      in the VM, as a runner job
# Reading the recorded accesses (whoread events/export) needs root or the signed app, so the script
# queries the daemon as root and stops before any query when it is not root. The probes run as the
# test user, whose home holds the vault: $WHOREAD_TEST_USER (set for VM jobs), else the user who ran
# sudo.
# Prerequisites:
#   - dev LaunchDaemon installed and Full Disk Access granted (in the VM: scripts/vm/provision.sh)
#   - scripts/create-test-vault.sh has been run (in the VM provision.sh does it for the test user)
#   - jq (part of macOS 15 and later; on 14: brew install jq)
# Only the test vault is read. Each probe runs in its own process group (set -m), separate from the
# daemon's, so eslogger does not suppress it. No Python needed: the VM has no Command Line Tools, so
# perl stands in for the python3 probe.
set -uo pipefail
set -m
WR="${WHOREAD:-whoread}"
PASS=0; FAIL=0; INCOMPLETE=""
ok()   { echo "PASS  $*"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
if [ "$(id -u)" -ne 0 ]; then
  echo "run it as root: sudo $0 (the probes still run as $(id -un)). Reading the recorded accesses needs"
  echo "root or the signed WhoRead app, and the daemon refuses everyone else."
  exit 1
fi
command -v jq >/dev/null || { echo "jq is missing (part of macOS 15 and later; on 14: brew install jq)"; exit 1; }
TEST_USER="${WHOREAD_TEST_USER:-${SUDO_USER:-}}"
case "$TEST_USER" in ''|root) echo "running as root: set WHOREAD_TEST_USER to the user whose test vault to probe, or run it with sudo as that user"; exit 1 ;; esac
USER_HOME=$(dscl . -read "/Users/$TEST_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
[ -n "$USER_HOME" ] || { echo "no home directory for $TEST_USER"; exit 1; }
VAULT="$USER_HOME/WhoReadTestVault"
# Every access to the vault runs as the test user; every daemon query as root, the script itself.
as_user() { sudo -n -u "$TEST_USER" -- "$@"; }
# In the test user's login session (as root through launchctl asuser): Spotlight's importer is per
# session, and the runner's jobs start outside every session.
as_session_user() { launchctl asuser "$(id -u "$TEST_USER")" sudo -n -u "$TEST_USER" -- "$@"; }
now() { jq -n 'now'; }
node_bin="$(command -v node || true)"

"$WR" status >/dev/null || { echo "daemon not reachable (is it installed and running?)"; exit 1; }
[ -f "$VAULT/ssh/id_ed25519" ] || { echo "run scripts/create-test-vault.sh first (for the user whose home is $USER_HOME)"; exit 1; }
# Every check below reads the recorded accesses. A refusal must not turn into "not recorded".
if ! err=$("$WR" events --since 1m --json 2>&1 >/dev/null); then
  echo "cannot read the recorded accesses: ${err:-whoread events failed}"
  exit 1
fi

probe() { # name, expected leaf name, command...
  local name="$1" leaf="$2"; shift 2
  local start; start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local t0; t0=$(now)
  as_user "$@" >/dev/null 2>&1
  # The chain must be complete: rooted at launchd (pid 1) with this script ($$) above the leaf.
  local found="" result=""
  for _ in $(seq 40); do
    result=$("$WR" events --since "$start" --json 2>/dev/null | jq -r --arg leaf "$leaf" --argjson me "$$" '
      [ .[] | select(((.chain // []) | length) > 0
                     and ((.chain[-1].name // "") | ascii_downcase | startswith($leaf))
                     and ((.path // "") | contains("WhoReadTestVault")))
            | { text: ([.chain[] | "\(.name)(\(.pid))"] | join(" → ")),
                good: (.chain[0].pid == 1 and any(.chain[:-1][]; .pid == $me)) } ] as $m
      | ($m | map(select(.good)) | first) as $ok
      | if $ok then "ok " + $ok.text elif ($m | length) > 0 then "wrong " + ($m | last).text else "" end')
    case "$result" in ok\ *) found="${result#ok }"; break ;; esac
    sleep 0.05
  done
  local dt; dt=$(jq -n "($(now) - $t0) * 100 | round / 100")
  if [ -n "$found" ] && [ "$(jq -n "$dt <= 2.0")" = true ]; then
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
# Without the Command Line Tools /usr/bin/python3 is only a stub that asks to install them.
if xcode-select -p >/dev/null 2>&1 && [ -x /usr/bin/python3 ]; then
  probe "python3 reads fake credentials" python  /usr/bin/python3 -c "open('$VAULT/aws/credentials').read()"
elif [ -x /usr/bin/perl ]; then
  echo "SKIP  python3 (no Command Line Tools); perl reads instead"
  probe "perl reads fake credentials"    perl    /usr/bin/perl -e 'open(my $f, "<", $ARGV[0]) or die "$!\n"; my @l = <$f>;' "$VAULT/aws/credentials"
else
  echo "SKIP  python3 and perl not available"
fi
if [ -n "$node_bin" ]; then
  probe "node reads fake private key"    node    "$node_bin" -e "require('fs').readFileSync('$VAULT/ssh/id_ed25519')"
else
  # sudo sets its own PATH, without Homebrew's folder.
  echo "SKIP  node not found on PATH (by hand, to include it: sudo env PATH=\"\$PATH\" $0)"
fi

# Spotlight: modify a vault file and wait for mdworker to index it (folded by default).
as_user /bin/sh -c 'echo "spotlight $(date)" >> "$1"' sh "$VAULT/notes/spotlight.txt"
as_session_user mdimport "$VAULT/notes/spotlight.txt" >/dev/null 2>&1 || true
folded=""
for _ in $(seq 60); do
  folded=$("$WR" events --since 2m --all --json | jq -r 'if any(.[]; .benignServiceID == "spotlight") then "yes" else "" end')
  [ -n "$folded" ] && break
  sleep 1
done
if [ -n "$folded" ]; then
  hidden=$("$WR" events --since 2m --json | jq '[.[] | select((.benignServiceID // "") != "")] | length')
  [ "$hidden" = "0" ] && ok "Spotlight read recorded and folded (hidden without --all)" || bad "Spotlight read visible without --all"
else
  # An M2 acceptance item: not verified means not accepted.
  echo "INCOMPLETE  no Spotlight read seen within 60 s (indexing off for this folder, or benign.json no longer matches mdworker)"
  echo "            Spotlight indexing here: $(mdutil -s / 2>&1 | tr -s ' \t\n' ' ')"
  INCOMPLETE=1
fi

# CLI query and export.
"$WR" events --since 5m --category test-vault >/dev/null && ok "CLI query" || bad "CLI query"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/whoread-m2.XXXXXX")
"$WR" export --format json --since 5m --output "$tmp/e.json" && jq empty "$tmp/e.json" && ok "export JSON" || bad "export JSON"
"$WR" export --format csv --since 5m --output "$tmp/e.csv" && head -1 "$tmp/e.csv" | grep -q '^id,time,operation' && ok "export CSV" || bad "export CSV"
rm -rf "$tmp"
echo
echo "$PASS passed, $FAIL failed${INCOMPLETE:+, Spotlight folding NOT verified}"
[ "$FAIL" -eq 0 ] && [ -z "$INCOMPLETE" ]
