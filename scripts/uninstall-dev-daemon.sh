#!/bin/bash
# Removes the development LaunchDaemon. Keeps the database unless --purge.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 77; }
# The data directory then belongs to the system extension: purging it would pull it from under it.
if [ "${1:-}" = "--purge" ] && systemextensionsctl list 2>/dev/null | grep -F '.whoread.extension' | grep -q '\[activated'; then
  echo "The WhoRead system extension is active and uses /Library/Application Support/WhoRead; nothing removed." >&2
  echo "Run without --purge to remove only the dev daemon, or remove the extension first (scripts/release/uninstall.sh)." >&2
  exit 1
fi
launchctl bootout system /Library/LaunchDaemons/com.whoread.daemon.plist 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.whoread.daemon.plist /usr/local/libexec/whoreadd
# The release CLI is a link into the app (DISTRIBUTION.md §5); only the dev copy goes.
case "$(readlink /usr/local/bin/whoread 2>/dev/null || true)" in
  /Applications/WhoRead.app/*) ;;
  *) rm -f /usr/local/bin/whoread ;;
esac
if [ "${1:-}" = "--purge" ]; then
  rm -rf "/Library/Application Support/WhoRead" /Library/Logs/WhoRead
  echo "removed daemon, data and logs"
else
  echo "removed daemon (data kept in /Library/Application Support/WhoRead; --purge to delete)"
fi
