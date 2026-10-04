#!/bin/bash
# Removes WhoRead: deactivates the system extension (macOS asks for confirmation), removes the
# app, the `whoread` link, the dev LaunchDaemon if present, and — with --purge — all recorded data.
# Nothing is removed unless the extension is really gone: an enforcing extension without its app
# would leave no UI to turn it off.
set -euo pipefail
APP="/Applications/WhoRead.app"
DATA="/Library/Application Support/WhoRead"
KILL_SWITCH="$DATA/disable-enforcement"

# "[activated enabled|waiting for user|disabled]" all count as installed (systemextensionsctl(8)).
extension_id() { /usr/libexec/PlistBuddy -c 'Print :WhoReadExtensionBundleID' "$APP/Contents/Info.plist" 2>/dev/null; }
extension_active() { systemextensionsctl list 2>/dev/null | grep -F "$1" | grep -q '\[activated'; }

# Force enforcement off first, so nothing stays blocked whatever happens next.
CREATED_KILL_SWITCH=""
if [ -d "$DATA" ] && [ ! -e "$KILL_SWITCH" ]; then
  sudo touch "$KILL_SWITCH" && CREATED_KILL_SWITCH=1
fi
pkill -x WhoRead 2>/dev/null || true

if [ -d "$APP" ]; then
  EXT="$(extension_id || true)"
  if [ -n "$EXT" ] && extension_active "$EXT"; then
    echo "Deactivating the system extension (approve the prompt)…"
    if ! "$APP/Contents/MacOS/WhoRead" --uninstall-extension || extension_active "$EXT"; then
      echo "Deactivation failed or was cancelled; $APP was kept so you can retry." >&2
      [ -e "$KILL_SWITCH" ] && echo "Enforcement stays off while $KILL_SWITCH exists (sudo rm it to undo)." >&2
      exit 1
    fi
  fi
fi
# Any WhoRead extension still active (the app was moved or deleted, or installed another one):
# nothing here can deactivate it, so keep the kill switch, the app and the data.
if extension_active '.whoread.extension'; then
  if [ -d "$APP" ]; then
    echo "A WhoRead system extension that $APP does not manage is still active; deactivate it from the app that installed it, then rerun." >&2
  else
    echo "The WhoRead system extension is still active but $APP is missing; put the app back in /Applications and rerun." >&2
  fi
  [ -e "$KILL_SWITCH" ] && echo "Enforcement stays off while $KILL_SWITCH exists (sudo rm it to undo)." >&2
  exit 1
fi

if [ -f /Library/LaunchDaemons/com.whoread.daemon.plist ]; then
  sudo launchctl bootout system /Library/LaunchDaemons/com.whoread.daemon.plist 2>/dev/null || true
  sudo rm -f /Library/LaunchDaemons/com.whoread.daemon.plist /usr/local/libexec/whoreadd /usr/local/bin/whoread
fi
# The release CLI is a link into the app (DISTRIBUTION.md §5); leave any other whoread alone.
case "$(readlink /usr/local/bin/whoread 2>/dev/null || true)" in
  "$APP"/*) sudo rm -f /usr/local/bin/whoread ;;
esac
sudo rm -rf "$APP"
if [ "${1:-}" = "--purge" ]; then
  sudo rm -rf "$DATA" /Library/Logs/WhoRead
  echo "WhoRead and its data removed."
else
  [ -n "$CREATED_KILL_SWITCH" ] && sudo rm -f "$KILL_SWITCH"
  echo "WhoRead removed. History kept in $DATA (run with --purge to delete)."
fi
