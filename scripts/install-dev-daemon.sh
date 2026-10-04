#!/bin/bash
# Installs the development LaunchDaemon (needs sudo). Run on your Mac after building:
#   swift build -c release        (or scripts/build.sh for signed Xcode builds)
#   sudo scripts/install-dev-daemon.sh [eslogger|native]
#
# Then grant Full Disk Access to /usr/local/libexec/whoreadd (System Settings → Privacy & Security
# → Full Disk Access → + → ⌘⇧G → /usr/local/libexec/whoreadd) and restart it:
#   sudo launchctl kickstart -k system/com.whoread.daemon
#
# "native" (Endpoint Security) only in a VM with SIP disabled.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 77; }
SOURCE="${1:-eslogger}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${WHOREAD_BIN:-$ROOT/.build/release}"
[ -x "$BIN/whoreadd" ] || BIN="$ROOT/.build/debug"
[ -x "$BIN/whoreadd" ] || { echo "build first: swift build -c release" >&2; exit 1; }
DATA="/Library/Application Support/WhoRead"
PLIST=/Library/LaunchDaemons/com.whoread.daemon.plist

launchctl bootout system "$PLIST" 2>/dev/null || true
install -d -m 755 -o root -g wheel /usr/local/libexec /usr/local/bin "$DATA" "$DATA/defaults" /Library/Logs/WhoRead
install -m 755 -o root -g wheel "$BIN/whoreadd" /usr/local/libexec/whoreadd
install -m 755 -o root -g wheel "$BIN/whoread" /usr/local/bin/whoread
install -m 644 -o root -g wheel "$ROOT/Data/catalog.json" "$ROOT/Data/agents.json" "$ROOT/Data/benign.json" "$DATA/defaults/"
if [ "$SOURCE" = "native" ]; then
  # The ES entitlement is required even with SIP off; sign ad hoc with it.
  codesign --force --sign - --entitlements "$ROOT/Extension/whoreadd.entitlements" /usr/local/libexec/whoreadd
fi
EXTRA=""
if [ -n "${WHOREAD_APP_REQUIREMENT:-}" ]; then
  EXTRA="<string>--app-requirement</string><string>${WHOREAD_APP_REQUIREMENT}</string>"
fi
sed -e "s|__SOURCE__|$SOURCE|" -e "s|__EXTRA_ARGS__|$EXTRA|" "$ROOT/packaging/com.whoread.daemon.plist" > "$PLIST"
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
launchctl bootstrap system "$PLIST"
echo "Installed. Logs: /Library/Logs/WhoRead/whoreadd.log"
echo "Now grant Full Disk Access to /usr/local/libexec/whoreadd, then: sudo launchctl kickstart -k system/com.whoread.daemon"
