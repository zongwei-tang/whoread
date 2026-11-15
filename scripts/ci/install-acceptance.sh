#!/bin/bash
# CI only: installs WhoRead with scripts/install.sh on a GitHub macOS runner (passwordless sudo) and
# checks that the installed pieces work together through the real launchd and XPC: the daemon runs,
# the pinned CLI and app reach it, the recorded history needs root or the app, a re-signed copy of
# the CLI is refused, and, where the runner lets eslogger run, the M2 acceptance
# (scripts/acceptance-m2.sh on the test vault). Then it uninstalls and checks that nothing is left.
#
# Never run it on your own Mac: it replaces, then removes, an installed WhoRead and its history.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
if [ "${CI:-}" != true ] && [ "${WHOREAD_CI_INSTALL:-}" != 1 ]; then
  echo "CI only: it replaces and removes an installed WhoRead (WHOREAD_CI_INSTALL=1 runs it anyway)"
  exit 64
fi
sudo -n true 2>/dev/null || { echo "needs passwordless sudo"; exit 1; }
PASS=0; FAIL=0; SKIP=0
ok()   { echo "PASS  $*"; PASS=$((PASS + 1)); }
bad()  { echo "FAIL  $*"; FAIL=$((FAIL + 1)); }
skip() { echo "SKIP  $*"; SKIP=$((SKIP + 1)); }
indent() { sed 's/^/      /'; }
T="$(mktemp -d "${TMPDIR:-/tmp}/wr-install.XXXXXX")"
WR=/usr/local/bin/whoread
APP=/Applications/WhoRead.app
APPBIN="$APP/Contents/MacOS/WhoRead"

echo "== install (scripts/install.sh --no-wait --no-open)"
if "$ROOT/scripts/install.sh" --no-wait --no-open > "$T/install.log" 2>&1; then
  ok "scripts/install.sh"
else
  bad "scripts/install.sh failed"
fi
tail -25 "$T/install.log" | indent

if sudo launchctl print system/com.whoread.daemon > "$T/launchd.txt" 2>&1 && grep -q 'state = running' "$T/launchd.txt"; then
  ok "launchd runs com.whoread.daemon"
else
  bad "the launchd job is not running"
  head -30 "$T/launchd.txt" | indent
  sudo tail -30 /Library/Logs/WhoRead/whoreadd.log 2>/dev/null | indent
fi
if [ -L "$WR" ] && [ "$(readlink "$WR")" = "$APP/Contents/Helpers/whoread" ]; then
  ok "/usr/local/bin/whoread links to the CLI in the app"
else
  bad "/usr/local/bin/whoread is not the link into the app"
fi
if [ "$(stat -f %u "$APP")" = 0 ] && ! find "$APP" -perm -g+w -o -perm -o+w | grep -q .; then
  ok "the app is owned by root and writable by no one else"
else
  bad "the app in /Applications can be changed by others"
fi

echo "== the CLI and the app over XPC"
if out="$("$WR" status 2>&1)"; then ok "the user's CLI reaches the daemon"; else bad "whoread status as the user failed"; fi
printf '%s\n' "$out" | indent
if out="$("$WR" events --limit 1 2>&1)"; then
  bad "the user's CLI could read the recorded history"
else
  case "$out" in
    *"needs root"*) ok "the user's CLI may not read the recorded history (needs sudo)" ;;
    *) bad "whoread events as the user failed for another reason: $out" ;;
  esac
fi
if out="$(sudo "$WR" events --limit 1 --json 2>&1)"; then ok "sudo whoread events"; else bad "sudo whoread events: $out"; fi
if out="$("$APPBIN" --self-check 2>&1)"; then rc=0; else rc=$?; fi
printf '%s\n' "$out" | indent
[ "$rc" -eq 0 ] && ok "app self-check: reachable and recognised as the WhoRead app" || bad "app self-check exited $rc"
cp "$APP/Contents/Helpers/whoread" "$T/other-cli"
codesign --force --sign - --identifier com.example.other "$T/other-cli" 2>/dev/null
if out="$("$T/other-cli" status 2>&1)"; then
  bad "a re-signed copy of the CLI was served: $out"
else
  ok "a re-signed copy of the CLI is refused"
fi

echo "== monitoring (eslogger)"
if "$WR" status --json 2>/dev/null | grep -Eq '"sourceRunning" *: *true'; then
  ok "eslogger runs under the daemon"
  "$ROOT/scripts/create-test-vault.sh" > /dev/null 2>&1 || true
  sudo "$ROOT/scripts/acceptance-m2.sh" > "$T/m2.log" 2>&1
  indent < "$T/m2.log" | tail -30
  passed="$(sed -n -E 's/^([0-9]+) passed, ([0-9]+) failed.*/\1 \2/p' "$T/m2.log" | tail -1)"
  if [ -z "$passed" ]; then
    bad "acceptance-m2 did not finish"
  elif [ "${passed#* }" != 0 ]; then
    bad "acceptance-m2: ${passed#* } failed"
  else
    ok "acceptance-m2: ${passed% *} passed"
    grep -q '^INCOMPLETE' "$T/m2.log" && skip "Spotlight folding not seen on this runner"
  fi
else
  skip "eslogger does not run on this runner (no Full Disk Access for the daemon):"
  "$WR" status 2>&1 | grep -E 'source:|hint:' | indent
fi

echo "== uninstall"
if sudo "$ROOT/scripts/uninstall-dev-daemon.sh" --purge > "$T/uninstall.log" 2>&1; then ok "uninstall-dev-daemon.sh --purge"; else bad "uninstall failed"; fi
indent < "$T/uninstall.log"
if sudo launchctl print system/com.whoread.daemon > /dev/null 2>&1; then bad "the launchd job is still loaded"; else ok "launchd job removed"; fi
for p in "$APP" "$WR" /usr/local/libexec/whoreadd "/Library/Application Support/WhoRead" \
         /Library/LaunchDaemons/com.whoread.daemon.plist /Library/Logs/WhoRead; do
  if [ -e "$p" ] || [ -L "$p" ]; then bad "left behind: $p"; else ok "removed: $p"; fi
done
rm -rf "$T"
echo "$PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
