#!/bin/bash
# Installs the development LaunchDaemon (needs sudo). Run on your Mac after building:
#   swift build -c release        (or scripts/build.sh for signed Xcode builds, see below)
#   sudo scripts/install-dev-daemon.sh [eslogger|native]
#
# Then grant Full Disk Access to /usr/local/libexec/whoreadd (System Settings → Privacy & Security
# → Full Disk Access → + → ⌘⇧G → /usr/local/libexec/whoreadd) and restart it:
#   sudo launchctl kickstart -k system/com.whoread.daemon
#
# "native" (Endpoint Security) only in a VM with SIP disabled.
#
# To let the signed WhoRead app weaken protection (Settings, rules, Allow once…), pass both
# requirements and install the team-signed CLI from the same Xcode build (docs/DEVELOPMENT.md):
#   WHOREAD_BIN=<Xcode products dir>
#   WHOREAD_CLIENT_REQUIREMENT='anchor apple generic and certificate leaf[subject.OU] = "TEAMID"'
#   WHOREAD_APP_REQUIREMENT='identifier "<prefix>.whoread" and anchor apple generic and certificate leaf[subject.OU] = "TEAMID"'
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 77; }
SOURCE="${1:-eslogger}"
case "$SOURCE" in
  eslogger|native) ;;
  *) echo "usage: $0 [eslogger|native]" >&2; exit 64 ;;
esac
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -n "${WHOREAD_BIN:-}" ]; then
  BIN="$WHOREAD_BIN"
else
  BIN="$ROOT/.build/release"
  [ -x "$BIN/whoreadd" ] || BIN="$ROOT/.build/debug"
fi
[ -x "$BIN/whoreadd" ] && [ -x "$BIN/whoread" ] || { echo "no whoreadd/whoread in $BIN: build first (swift build -c release)" >&2; exit 1; }
CLIENT_REQ="${WHOREAD_CLIENT_REQUIREMENT:-}"
APP_REQ="${WHOREAD_APP_REQUIREMENT:-}"
# Without a client requirement no peer counts as verified code, so the app requirement would
# silently do nothing.
if [ -n "$APP_REQ" ] && [ -z "$CLIENT_REQ" ]; then
  echo "WHOREAD_APP_REQUIREMENT has no effect without WHOREAD_CLIENT_REQUIREMENT; set both" >&2
  exit 64
fi
# The daemon refuses every client that does not satisfy the requirement, including this CLI.
if [ -n "$CLIENT_REQ" ] && ! codesign --verify -R="$CLIENT_REQ" "$BIN/whoread" 2>/dev/null; then
  echo "$BIN/whoread does not satisfy WHOREAD_CLIENT_REQUIREMENT, so the daemon would refuse it." >&2
  echo "Use the team-signed products of scripts/build.sh as WHOREAD_BIN." >&2
  exit 1
fi
# Only one daemon may use the data directory: the system extension would fight this one.
if systemextensionsctl list 2>/dev/null | grep -F '.whoread.extension' | grep -q '\[activated'; then
  echo "The WhoRead system extension is installed; remove it before installing the dev daemon:" >&2
  echo "  scripts/release/uninstall.sh   (in a SIP-disabled VM: systemextensionsctl uninstall <team> <bundle id>)" >&2
  exit 1
fi
DATA="/Library/Application Support/WhoRead"
PLIST=/Library/LaunchDaemons/com.whoread.daemon.plist
LOGS=/Library/Logs/WhoRead

launchctl bootout system "$PLIST" 2>/dev/null || true
install -d -m 755 -o root -g wheel /usr/local/libexec /usr/local/bin "$DATA" "$DATA/defaults"
# The log carries alert headlines and process chains of every user: root only. Pre-create the
# file, and fix the modes an earlier install (755/644) left behind.
install -d -o root -g wheel "$LOGS"
( umask 077; : >> "$LOGS/whoreadd.log" )
chown root:wheel "$LOGS/whoreadd.log"
chmod 700 "$LOGS"
chmod 600 "$LOGS/whoreadd.log"
install -m 755 -o root -g wheel "$BIN/whoreadd" /usr/local/libexec/whoreadd
install -m 755 -o root -g wheel "$BIN/whoread" /usr/local/bin/whoread
install -m 644 -o root -g wheel "$ROOT/Data/catalog.json" "$ROOT/Data/agents.json" "$ROOT/Data/benign.json" "$DATA/defaults/"
if [ "$SOURCE" = "native" ]; then
  # The ES entitlement is required even with SIP off; sign ad hoc with it.
  codesign --force --sign - --entitlements "$ROOT/Extension/whoreadd.entitlements" /usr/local/libexec/whoreadd
else
  # eslogger needs no entitlement. Strip the restricted one an Xcode build carries: without a
  # provisioning profile AMFI would refuse to launch it on a normal Mac.
  codesign --force --sign - /usr/local/libexec/whoreadd
fi

ARGS=()
[ -n "$CLIENT_REQ" ] && ARGS+=(--client-requirement "$CLIENT_REQ")
[ -n "$APP_REQ" ] && ARGS+=(--app-requirement "$APP_REQ")
xml_escape() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
while IFS= read -r line; do
  case "$line" in
    *__EXTRA_ARGS__*)
      for a in ${ARGS[@]+"${ARGS[@]}"}; do printf '\t\t<string>%s</string>\n' "$(xml_escape "$a")"; done ;;
    *) printf '%s\n' "${line//__SOURCE__/$SOURCE}" ;;
  esac
done < "$ROOT/packaging/com.whoread.daemon.plist" > "$PLIST"
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
plutil -lint "$PLIST" >/dev/null || { echo "generated $PLIST is not a valid plist" >&2; exit 1; }
launchctl bootstrap system "$PLIST"
echo "Installed. Logs (root only): $LOGS/whoreadd.log"
echo "Now grant Full Disk Access to /usr/local/libexec/whoreadd, then: sudo launchctl kickstart -k system/com.whoread.daemon"
echo "Owner team IDs are read from codesign at every daemon start; to see them: sudo whoread catalog resolve-owners"
