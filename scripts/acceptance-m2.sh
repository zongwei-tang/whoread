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
# Only the test vault is read, and the NFD probe's own folder in the test user's home (created and
# removed by the probe, and its project root added and removed again). Each probe runs in its own
# process group (set -m), separate from the daemon's, so eslogger does not suppress it. No Python
# needed: the VM has no Command Line Tools, so perl stands in for the python3 probe, and the NFD and
# mmap probes, which need python3, are skipped.
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
# Without the Command Line Tools /usr/bin/python3 is only a stub that asks to install them.
has_python3() { xcode-select -p >/dev/null 2>&1 && [ -x /usr/bin/python3 ]; }
node_bin="$(command -v node || true)"

"$WR" status >/dev/null || { echo "daemon not reachable (is it installed and running?)"; exit 1; }
[ -f "$VAULT/ssh/id_ed25519" ] || { echo "run scripts/create-test-vault.sh first (for the user whose home is $USER_HOME)"; exit 1; }
# Every check below reads the recorded accesses. A refusal must not turn into "not recorded".
if ! err=$("$WR" events --since 1m --json 2>&1 >/dev/null); then
  echo "cannot read the recorded accesses: ${err:-whoread events failed}"
  exit 1
fi

# This script's real ancestry from ps, itself ($$) first, up to launchd (pid 1), as a JSON array: what
# the chain recorded above each probe must be.
ancestry() {
  local p=$$ out="" n=0
  while [ -n "$p" ] && [ "$n" -lt 256 ]; do
    out="${out:+$out,}$p"
    [ "$p" -le 1 ] && break
    p=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')
    n=$((n + 1))
  done
  echo "[$out]"
}
REAL=$(ancestry)

probe() { # [--op OPERATION] name, expected leaf name, file in the vault it reads (or its absolute path), command...
  # --op: only an event of that operation counts (a close is only ever recorded as a write).
  local op=""
  if [ "$1" = --op ]; then op="$2"; shift 2; fi
  local name="$1" leaf="$2" file="$3"; shift 3
  # A recorded path is canonical (NFC, no /System/Volumes/Data): an absolute one is given that way.
  case "$file" in /*) ;; *) file="/WhoReadTestVault/$file" ;; esac
  local start; start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  as_user "$@" >/dev/null 2>&1
  # Latency is counted from the end of the command: an interpreter that takes a second to start
  # (python3 on a loaded machine) says nothing about how fast the access was recorded.
  local t0; t0=$(now)
  # Above the probe, the chain must be this script's real ancestry ($REAL): all the way to launchd, or
  # up to a process that was already running when the daemon started and whose parent is launchd now.
  # libproc has no fork-time parent for such a process, so the daemon marks the ancestry above it
  # unknown (ancestryKnown false; docs/THREAT_MODEL.md, "Unknown ancestry") instead of guessing
  # launchd. Only events on the probed file count: --since has whole seconds, and the vault was
  # written (by cat, among others) just before.
  local found="" result=""
  for _ in $(seq 40); do
    result=$("$WR" events --since "$start" --json 2>/dev/null | jq -r --arg leaf "$leaf" --arg file "$file" --arg op "$op" \
        --argjson me "$$" --argjson real "$REAL" '
      def verdict:
        (.chain | map(.pid)) as $c
        | ($c | index($me)) as $i
        | if $i == null then "this script (\($me)) is not in it"
          else ($c[0:$i + 1] | reverse) as $up
            | ($real[$up | length]) as $above
            | if $up != $real[0:($up | length)] then
                "above this script it is not the ancestry ps shows: \($real | reverse | map(tostring) | join(" → "))"
              elif $c[0] == 1 then (if .ancestryKnown == false then "it reaches launchd but is marked unknown" else "ok" end)
              elif $above == 1 and .ancestryKnown == false then "unknown"
              elif $above == 1 then "it stops below launchd but is not marked unknown"
              else "it stops at pid \($c[0]), whose parent \($above) is not launchd"
              end
          end;
      [ .[] | select(((.chain // []) | length) > 0
                     and ((.chain[-1].name // "") | ascii_downcase | startswith($leaf))
                     and ((.path // "") | endswith($file))
                     and ($op == "" or .operation == $op))
            | { text: ([.chain[] | "\(.name)(\(.pid))"] | join(" → ")), why: verdict } ] as $m
      | ($m | map(select(.why == "ok" or .why == "unknown")) | first) as $ok
      | (($m | map(select(.why | startswith("this script") | not)) | first) // $m[0]) as $near
      | if $ok then "\($ok.why) \($ok.text)"
        elif $near then "wrong \($near.text): \($near.why)"
        else "" end')
    case "$result" in ok\ *|unknown\ *) found="$result"; break ;; esac
    sleep 0.05
  done
  local dt; dt=$(jq -n "($(now) - $t0) * 100 | round / 100")
  local chain="${found#* }"
  case "$found" in
    unknown\ *) chain="$chain (the ancestry above ${chain%% *} is unknown: it was running before the daemon started)" ;;
  esac
  if [ -n "$found" ] && [ "$(jq -n "$dt <= 2.0")" = true ]; then
    ok "$name recorded in ${dt}s, chain: $chain"
  elif [ -n "$found" ]; then
    bad "$name recorded but took ${dt}s (> 2 s): $chain"
  elif [ -n "$result" ]; then
    bad "$name recorded with a wrong parent chain: ${result#wrong }"
  else
    bad "$name not recorded within 2 s"
  fi
}

probe "cat reads fake private key"       cat     ssh/id_ed25519   /bin/cat "$VAULT/ssh/id_ed25519"
# Without the Command Line Tools /usr/bin/python3 is only a stub that asks to install them.
if xcode-select -p >/dev/null 2>&1 && [ -x /usr/bin/python3 ]; then
  probe "python3 reads fake credentials" python  aws/credentials  /usr/bin/python3 -c "open('$VAULT/aws/credentials').read()"
elif [ -x /usr/bin/perl ]; then
  echo "SKIP  python3 (no Command Line Tools); perl reads instead"
  probe "perl reads fake credentials"    perl    aws/credentials  /usr/bin/perl -e 'open(my $f, "<", $ARGV[0]) or die "$!\n"; my @l = <$f>;' "$VAULT/aws/credentials"
else
  echo "SKIP  python3 and perl not available"
fi
if [ -n "$node_bin" ]; then
  probe "node reads fake private key"    node    ssh/id_ed25519   "$node_bin" -e "require('fs').readFileSync('$VAULT/ssh/id_ed25519')"
else
  # sudo sets its own PATH, without Homebrew's folder.
  echo "SKIP  node not found on PATH (by hand, to include it: sudo env PATH=\"\$PATH\" $0)"
fi

# NFD: a project root with a non-ASCII name, added in NFC and created on disk in NFD (as Finder may),
# and a .env read in it. Outside the vault: the vault's own prefix would let every line in it through
# the eslogger prefilter, so here only the root's spellings can. データ has no case and one voiced
# kana, so the prefilter matches it by its exact spellings, NFC and NFD (Café would go by its ASCII
# fragment instead, for its é). python3 makes the NFD name and checks that the disk keeps it.
NFD_ROOT=""; NFD_DIR=""; NFD_ADDED=""
nfd_cleanup() {
  if [ -n "$NFD_ADDED" ]; then
    "$WR" settings set project-root-remove "$NFD_ROOT" >/dev/null || bad "NFD: could not remove the project root $NFD_ROOT"
    NFD_ADDED=""
  fi
  case "$NFD_DIR" in "$USER_HOME"/WhoReadProbe-*) as_user /bin/rm -rf -- "$NFD_DIR" ;; esac
  NFD_DIR=""
}
trap nfd_cleanup EXIT
if has_python3; then
  # The two spellings come back marked: the python3 stub can print to stderr too.
  out=$(as_user /usr/bin/python3 -c '
import os, shutil, sys, unicodedata
nfc = os.path.join(sys.argv[1], "WhoReadProbe-" + "".join(map(chr, (0x30C7, 0x30FC, 0x30BF))))
nfd = unicodedata.normalize("NFD", nfc)
shutil.rmtree(nfd, ignore_errors=True)
os.mkdir(nfd)
if os.path.basename(nfd) not in os.listdir(sys.argv[1]):
    shutil.rmtree(nfd)
    sys.exit("the file system did not keep the NFD name")
with open(os.path.join(nfd, ".env"), "w") as f:
    f.write("WHOREAD_PROBE=not-a-secret\n")
print("nfc=" + nfc)
print("nfd=" + nfd)' "$USER_HOME" 2>&1)
  NFD_ROOT=$(sed -n 's/^nfc=//p' <<< "$out")
  NFD_DIR=$(sed -n 's/^nfd=//p' <<< "$out")
  if [ -z "$NFD_ROOT" ] || [ -z "$NFD_DIR" ]; then
    bad "NFD: could not create the probe folder in $USER_HOME: $out"
  elif ! err=$("$WR" settings set project-root-add "$NFD_ROOT" 2>&1 >/dev/null); then
    bad "NFD: could not add the project root $NFD_ROOT: $err"
  else
    NFD_ADDED=1
    probe "cat reads .env in a project root named in NFD" cat "$NFD_ROOT/.env" /bin/cat "$NFD_DIR/.env"
  fi
  nfd_cleanup
else
  echo "SKIP  NFD project root (no Command Line Tools: python3 makes the NFD name)"
fi

# mmap: python3 changes a vault file only through a shared writable mapping, with no write call, so its
# close reports modified false and was_mapped_writable true. That close must be recorded (a close is
# recorded only as a write); the read-write open before it does not count.
if has_python3; then
  as_user /bin/sh -c 'echo "mmap $(date)" > "$1"' sh "$VAULT/notes/mmap.txt"
  probe --op close "python3 writes fake notes through mmap" python notes/mmap.txt /usr/bin/python3 -c '
import mmap, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
m = mmap.mmap(fd, 0)
m[0:4] = b"MMAP"
m.flush()
m.close()
os.close(fd)' "$VAULT/notes/mmap.txt"
else
  echo "SKIP  mmap write (no Command Line Tools: python3 makes the mapping)"
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
