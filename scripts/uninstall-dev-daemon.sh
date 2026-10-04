#!/bin/bash
# Removes the development LaunchDaemon. Keeps the database unless --purge.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 77; }
launchctl bootout system /Library/LaunchDaemons/com.whoread.daemon.plist 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.whoread.daemon.plist /usr/local/libexec/whoreadd /usr/local/bin/whoread
if [ "${1:-}" = "--purge" ]; then
  rm -rf "/Library/Application Support/WhoRead" /Library/Logs/WhoRead
  echo "removed daemon, data and logs"
else
  echo "removed daemon (data kept in /Library/Application Support/WhoRead; --purge to delete)"
fi
