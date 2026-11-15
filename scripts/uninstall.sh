#!/bin/bash
# Removes what scripts/install.sh installed: the background service, the `whoread` command and the
# menu bar app. The recorded history is kept unless you pass --purge.
#
#   scripts/uninstall.sh [--purge]     run it as yourself, not with sudo
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
case "${1:-}" in
  ""|--purge) ;;
  -h|--help) sed -n '2,5p' "$0" | sed -E 's/^# ?//'; exit 0 ;;
  *) echo "usage: $0 [--purge]" >&2; exit 64 ;;
esac
ZH=0
case "$(defaults read -g AppleLanguages 2>/dev/null | sed -n '2p')" in *zh*) ZH=1 ;; esac
say() { if [ "$ZH" = 1 ]; then printf '%s\n' "$2"; else printf '%s\n' "$1"; fi; }
if [ "$(id -u)" -eq 0 ]; then
  say "Run it as yourself, without sudo: scripts/uninstall.sh (it asks for your password)." \
    "请直接运行，不要加 sudo：scripts/uninstall.sh（它会问你的密码）。" >&2
  exit 64
fi
APPBIN=/Applications/WhoRead.app/Contents/MacOS/WhoRead
# The app registered itself to open at login; take that back while it is still there.
if [ -x "$APPBIN" ]; then "$APPBIN" --unregister-login-item >/dev/null 2>&1 || true; fi
pkill -x WhoRead 2>/dev/null || true
sudo "$ROOT/scripts/uninstall-dev-daemon.sh" "$@"
say "WhoRead is removed. You can also remove whoreadd from System Settings > Privacy & Security > Full Disk Access (select it, click -)." \
  "WhoRead 已经卸载。你还可以在「系统设置 > 隐私与安全性 > 完全磁盘访问权限」里选中 whoreadd，点 - 把它移除。"
