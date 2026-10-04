#!/bin/bash
# Removes WhoRead: deactivates the system extension (macOS asks for confirmation), removes the
# app, the dev LaunchDaemon if present, and — with --purge — all recorded data.
set -euo pipefail
APP="/Applications/WhoRead.app"
if [ -d "$APP" ]; then
  echo "Deactivating the system extension (approve the prompt)…"
  "$APP/Contents/MacOS/WhoRead" --uninstall-extension || true
fi
if [ -f /Library/LaunchDaemons/com.whoread.daemon.plist ]; then
  sudo launchctl bootout system /Library/LaunchDaemons/com.whoread.daemon.plist 2>/dev/null || true
  sudo rm -f /Library/LaunchDaemons/com.whoread.daemon.plist /usr/local/libexec/whoreadd /usr/local/bin/whoread
fi
sudo rm -rf "$APP"
if [ "${1:-}" = "--purge" ]; then
  sudo rm -rf "/Library/Application Support/WhoRead" /Library/Logs/WhoRead
  echo "WhoRead and its data removed."
else
  echo "WhoRead removed. History kept in /Library/Application Support/WhoRead (run with --purge to delete)."
fi
