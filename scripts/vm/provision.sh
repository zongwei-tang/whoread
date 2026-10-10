#!/bin/bash
# timeout: 600
# Provisions the SIP-disabled test VM: creates the test vault as the VM's test user, grants the dev
# daemon Full Disk Access, installs the host-built daemon and CLI, and reports what works. Runs IN
# THE VM as root, as a job of the VM runner (scripts/vm/README.md); it refuses to run outside a VM.
# On the host:
#   scripts/dev/sc-build.sh build
#   scripts/vm/vmjob.sh run provision scripts/vm/provision.sh [-- native|eslogger [--amfi-boot-arg]]
# native (default): the Endpoint Security client, ad hoc signed with the ES entitlement (only works
# with SIP off). eslogger: monitor only, through /usr/bin/eslogger.
# --amfi-boot-arg: if AMFI refuses the ad hoc ES entitlement, set amfi_get_out_of_my_way=1 in the
# VM's boot-args and restart the VM in a minute; provision again once the runner is back.
# WHOREAD_BIN: directory with the prebuilt whoreadd and whoread (default: the first of
# <checkout>/.build-sc/debug, .build/release, .build/debug that has both). Nothing is built here: the
# VM has no Xcode.
set -uo pipefail
SOURCE="${1:-native}"
case "$SOURCE" in native|eslogger) ;; *) echo "usage: $0 [native|eslogger] [--amfi-boot-arg]" >&2; exit 64 ;; esac
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_USER="${WHOREAD_TEST_USER:-${SUDO_USER:-admin}}"
WR=/usr/local/bin/whoread
LOG=/Library/Logs/WhoRead/whoreadd.log
PROBLEMS=0
step()    { echo; echo "== $*"; }
problem() { echo "PROBLEM: $*"; PROBLEMS=$((PROBLEMS + 1)); }

[ "$(id -u)" -eq 0 ] || { echo "run it as root, as a VM job (scripts/vm/vmjob.sh)" >&2; exit 77; }
# A VM: the hypervisor flag, or the model name of an Apple silicon VM (VirtualMac2,1).
is_vm() {
  [ "$(sysctl -n kern.hv_vmm_present 2>/dev/null)" = 1 ] && return 0
  case "$(sysctl -n hw.model 2>/dev/null)" in VirtualMac*) return 0 ;; esac
  return 1
}
is_vm || { echo "not a VM (kern.hv_vmm_present is not 1, hw.model is $(sysctl -n hw.model 2>/dev/null)): refusing" >&2; exit 1; }
SIP=$(csrutil status 2>/dev/null | head -n 1)
echo "macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion)), $(uname -m); $SIP"

if [ "${2:-}" = --amfi-boot-arg ]; then
  step "AMFI boot-arg"
  current=$(nvram boot-args 2>/dev/null | cut -f 2-)
  case "$current" in
    *amfi_get_out_of_my_way=1*) echo "already set: $current" ;;
    *)
      nvram boot-args="${current:+$current }amfi_get_out_of_my_way=1" || { echo "nvram refused the boot-arg (SIP off and permissive security needed)"; exit 1; }
      echo "boot-args now: $(nvram boot-args 2>/dev/null | cut -f 2-)"
      shutdown -r +1 >/dev/null 2>&1 &
      echo "The VM restarts in about a minute. Provision again when 'scripts/vm/vmjob.sh ping' answers."
      exit 0 ;;
  esac
fi

case "$SIP" in
  *"status: disabled."*) ;;
  *) [ "$SOURCE" = native ] && { echo "SIP is not fully disabled in this VM: the native source cannot run (scripts/vm/README.md, step 1)"; exit 1; } ;;
esac
command -v jq >/dev/null || { echo "jq is missing (part of macOS 15 and later)"; exit 1; }

step "binaries"
BIN="${WHOREAD_BIN:-}"
if [ -z "$BIN" ]; then
  for d in "$ROOT/.build-sc/debug" "$ROOT/.build/release" "$ROOT/.build/debug"; do
    [ -x "$d/whoreadd" ] && [ -x "$d/whoread" ] && { BIN="$d"; break; }
  done
fi
[ -n "$BIN" ] || { echo "no whoreadd/whoread under $ROOT/.build-sc/debug: build on the host first (scripts/dev/sc-build.sh build)"; exit 1; }
echo "from $BIN (built $(stat -f '%Sm' -t '%Y-%m-%d %H:%M' "$BIN/whoreadd"))"
# Checked and installed from a copy on the VM's own disk: one snapshot of the two binaries even if
# the host rebuilds meanwhile, and nothing is executed from the shared folder (whether the virtiofs
# mount allows that is not verified).
STAGE=$(mktemp -d /tmp/whoread-bin.XXXXXX) || { echo "cannot create a temporary folder"; exit 1; }
trap 'rm -f "$STAGE/whoreadd" "$STAGE/whoread"; rmdir "$STAGE" 2>/dev/null' EXIT
cp "$BIN/whoreadd" "$BIN/whoread" "$STAGE/" || { echo "cannot copy whoreadd and whoread from $BIN"; exit 1; }
BIN="$STAGE"
version=$("$BIN/whoread" version 2>&1) || { echo "the host-built whoread does not run in this VM: $version"; exit 1; }
echo "whoread: $version"

HOME_DIR=$(dscl . -read "/Users/$TEST_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
[ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ] || { echo "no home directory for the test user $TEST_USER"; exit 1; }

step "previous daemon"
if [ -x "$WR" ] && "$WR" status >/dev/null 2>&1; then
  # A test that was interrupted can leave enforcement on; the vault must be writable below.
  "$WR" enforcement off >/dev/null 2>&1 && echo "running; enforcement switched off for provisioning" \
    || echo "running; could not switch enforcement off"
else
  echo "none running"
fi

step "test vault as $TEST_USER"
# The script reaches the user's shell on stdin, so the user needs no access to the share.
if sudo -n -u "$TEST_USER" -H /bin/bash -s < "$ROOT/scripts/create-test-vault.sh"; then :
else problem "creating the test vault in $HOME_DIR failed"
fi

step "Spotlight"
# acceptance-m2.sh checks that Spotlight's reads of the vault are recorded and folded; with indexing
# off (some VM images turn it off) that check cannot pass. Not changed here: switching it on starts
# a full index, which skews the overhead and latency numbers until it settles (README).
mdutil -s / 2>&1 | sed 's/^/  /'

step "Full Disk Access"
FDA_PATHS=(/usr/local/libexec/whoreadd)
[ "$SOURCE" = eslogger ] && FDA_PATHS+=(/usr/bin/eslogger)
# Granted by path before the binary is installed: the row carries no code requirement, so the ad hoc
# re-signing below (and at every provisioning) should keep it (UNVERIFIED; see tcc-fda.sh). Whether
# it took effect shows below: the source runs, or reports NOT_PERMITTED.
if bash "$ROOT/scripts/vm/tcc-fda.sh" "${FDA_PATHS[@]}"; then FDA=yes
else
  FDA=no
  problem "Full Disk Access could not be granted through the TCC database. In the VM: System Settings → Privacy & Security → Full Disk Access → + → ⌘⇧G → ${FDA_PATHS[*]} → switch on; then provision again. A grant made there is tied to this build's signature: after every new build remove whoreadd from the list (−) and add it again"
fi

step "install the dev daemon ($SOURCE)"
# It boots the daemon out and in again, with Full Disk Access already granted above: no restart
# afterwards (killing the new daemon while it sets up its client could leave an unclean-stop note
# that a later M5 check would then read).
if WHOREAD_BIN="$BIN" /bin/bash "$ROOT/scripts/install-dev-daemon.sh" "$SOURCE"; then :
else
  problem "install-dev-daemon.sh failed"
  # If only its final bootstrap failed (the label was still loaded), a restart runs the new binary.
  launchctl kickstart -k system/com.whoread.daemon >/dev/null 2>&1
fi
codesign -d --entitlements - /usr/local/libexec/whoreadd 2>/dev/null | grep -q endpoint-security \
  && echo "whoreadd is signed with the Endpoint Security entitlement" \
  || { [ "$SOURCE" = native ] && problem "whoreadd carries no Endpoint Security entitlement"; }

step "daemon"
reachable=""
for _ in $(seq 60); do "$WR" status >/dev/null 2>&1 && { reachable=1; break; }; sleep 0.5; done
if [ -z "$reachable" ]; then
  problem "the daemon does not answer"
  launchctl print system/com.whoread.daemon 2>/dev/null | grep -E '^[[:space:]]*(state|pid|last exit code|last exit reason)' | sed 's/^/  /'
  echo "  log:"; tail -n 20 "$LOG" 2>/dev/null | sed 's/^/    /'
  echo "If launchd shows the daemon killed at launch (code signing) or the log says NOT_ENTITLED, AMFI"
  echo "refuses the ad hoc entitlement: provision with -- native --amfi-boot-arg (restarts the VM)."
else
  for _ in $(seq 30); do
    [ "$("$WR" status --json 2>/dev/null | jq -r '.sourceRunning')" = true ] && break
    sleep 0.5
  done
  st=$("$WR" status --json 2>/dev/null)
  jq -r '"source: \(.source), running: \(.sourceRunning), can enforce: \(.sourceCanEnforce), enforcement active: \(.enforcementActive)",
         "error: \(.sourceError // "none")", "hint: \(.sourceHint // "none")",
         "monitored homes: \(.homeDirectories | join(", "))"' <<< "$st"
  [ "$(jq -r '.sourceRunning' <<< "$st")" = true ] || {
    problem "the $SOURCE source is not running"
    echo "  log:"; tail -n 20 "$LOG" 2>/dev/null | sed 's/^/    /'
    case "$(jq -r '.sourceError // ""' <<< "$st")" in
      *ENTITLED*|*ntitle*) echo "AMFI refuses the ad hoc entitlement: provision with -- native --amfi-boot-arg (restarts the VM)." ;;
      *PERMITTED*|*ermitted*) echo "Full Disk Access is missing or not yet seen by TCC. In the VM: System Settings → Privacy & Security → Full Disk Access → + → ⌘⇧G → /usr/local/libexec/whoreadd → switch on (if it is already listed: remove it with − and add it again), then provision again." ;;
    esac
  }
  [ "$SOURCE" = native ] && [ "$(jq -r '.sourceCanEnforce' <<< "$st")" != true ] && problem "the native source cannot enforce"
  # A known starting point for the jobs that follow: enforcement off (acceptance-m5.sh switches it
  # on itself). It can be on here when the data directory kept it from an earlier daemon.
  if [ "$(jq -r '.enforcementEnabled' <<< "$st")" = true ]; then
    "$WR" enforcement off >/dev/null 2>&1 && echo "enforcement was on (kept from an earlier run); switched off" \
      || problem "enforcement is on and could not be switched off"
  fi
  jq -e --arg h "$HOME_DIR" 'any(.homeDirectories[]; . == $h)' <<< "$st" >/dev/null \
    || problem "the daemon does not monitor $HOME_DIR (where the test vault is)"
  echo; "$WR" status
fi

echo
if [ "$PROBLEMS" -eq 0 ]; then
  echo "PROVISIONED: $SOURCE source running, Full Disk Access through TCC: $FDA, test vault $HOME_DIR/WhoReadTestVault"
else
  echo "PROVISION INCOMPLETE: $PROBLEMS problem(s), see PROBLEM lines above"
  exit 1
fi
