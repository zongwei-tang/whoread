#!/bin/bash
# Removes the development LaunchDaemon, and the menu bar app and CLI link that scripts/install.sh
# (install-dev-daemon.sh --app) installed. Keeps the database unless --purge.
#   sudo scripts/uninstall-dev-daemon.sh [--purge]
# A release (team-signed, with its system extension) is left alone: scripts/release/uninstall.sh
# removes that.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 77; }
PURGE=0
case "${1:-}" in
  "") ;;
  --purge) PURGE=1 ;;
  *) echo "usage: $0 [--purge]" >&2; exit 64 ;;
esac
DATA="/Library/Application Support/WhoRead"
APP=/Applications/WhoRead.app
CLI=/usr/local/bin/whoread
# Written by install-dev-daemon.sh --app: the app in /Applications is the one it installed.
MARKER="$DATA/dev-installed-app"
EXT_ACTIVE=0
if systemextensionsctl list 2>/dev/null | grep -F '.whoread.extension' | grep -q '\[activated'; then EXT_ACTIVE=1; fi
# The data directory then belongs to the system extension: purging it would pull it from under it.
if [ "$PURGE" = 1 ] && [ "$EXT_ACTIVE" = 1 ]; then
  echo "The WhoRead system extension is active and uses $DATA; nothing removed." >&2
  echo "Run without --purge to remove only the dev daemon, or remove the extension first (scripts/release/uninstall.sh)." >&2
  exit 1
fi
launchctl bootout system /Library/LaunchDaemons/com.whoread.daemon.plist 2>/dev/null || true
# whoread-uninstall: this script, as WhoRead.pkg installs it (bash has it open already).
rm -f /Library/LaunchDaemons/com.whoread.daemon.plist /usr/local/libexec/whoreadd /usr/local/libexec/whoread-uninstall

# The app install-dev-daemon.sh --app installed (its marker, or an ad-hoc signature, which no release
# has), never while a system extension, which lives in a release app, is active.
app_ours() {
  [ -d "$APP" ] && [ ! -L "$APP" ] && [ "$EXT_ACTIVE" = 0 ] || return 1
  case "$(plutil -extract CFBundleIdentifier raw -o - "$APP/Contents/Info.plist" 2>/dev/null)" in
    *.whoread) ;;
    *) return 1 ;;
  esac
  [ -f "$MARKER" ] && [ ! -L "$MARKER" ] && return 0
  codesign -dv "$APP" 2>&1 | grep -qx 'Signature=adhoc'
}
REMOVED_APP=0
if app_ours; then
  pkill -x WhoRead 2>/dev/null || true
  # Moved into root's own folder first: nothing is deleted through a path others can change.
  stage="$(mktemp -d /private/tmp/whoread-app.XXXXXX)"
  mv "$APP" "$stage/removed.app"
  rm -rf "$stage"
  REMOVED_APP=1
fi
rm -f "$MARKER"
# The CLI: a dev copy goes, and so does a link into an app that is gone; a link into a release
# app stays (DISTRIBUTION.md §5).
if [ -L "$CLI" ]; then
  case "$(readlink "$CLI")" in
    "$APP"/*) [ -e "$CLI" ] || rm -f "$CLI" ;;
    *) rm -f "$CLI" ;;
  esac
elif [ -e "$CLI" ]; then
  rm -f "$CLI"
fi

what="daemon"
[ "$REMOVED_APP" = 0 ] || what="daemon, app"
if [ "$PURGE" = 1 ]; then
  rm -rf "$DATA" /Library/Logs/WhoRead
  echo "removed $what, data and logs"
else
  echo "removed $what (data kept in $DATA; --purge to delete)"
fi
