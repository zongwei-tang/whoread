#!/bin/bash
# Installs WhoRead on this Mac: builds it as you, installs the background service, the `whoread`
# command and the menu bar app (macOS asks for your password once), helps you switch on Full Disk
# Access for the background service, checks that the pieces talk to each other, and starts the app.
# This is monitor-only mode: WhoRead records and alerts. Blocking needs a signed release.
#
#   scripts/install.sh            run it as yourself, not with sudo
#
# Run it again after updating the code. A rebuilt WhoRead is a different program to macOS, so Full
# Disk Access may have to be switched on again; the script says when.
# Options: --no-wait  do not open System Settings or wait for Full Disk Access (CI)
#          --no-open  do not start the menu bar app (CI)
# To remove WhoRead: scripts/uninstall.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WAIT=1
OPEN=1
for a in "$@"; do
  case "$a" in
    --no-wait) WAIT=0 ;;
    --no-open) OPEN=0 ;;
    -h|--help) sed -n '2,14p' "$0" | sed -E 's/^# ?//'; exit 0 ;;
    *) echo "usage: $0 [--no-wait] [--no-open]" >&2; exit 64 ;;
  esac
done

# Chinese when it is the first language in System Settings.
ZH=0
case "$(defaults read -g AppleLanguages 2>/dev/null | sed -n '2p')" in *zh*) ZH=1 ;; esac
say() { if [ "$ZH" = 1 ]; then printf '%s\n' "$2"; else printf '%s\n' "$1"; fi; }
die() { say "$1" "$2" >&2; exit 1; }

[ "$(id -u)" -ne 0 ] || die "Run it as yourself, without sudo: scripts/install.sh (it asks for your password when it needs it)." \
  "请直接运行，不要加 sudo：scripts/install.sh（需要密码时它会问你）。"
[ "$(uname -s)" = Darwin ] || die "WhoRead runs on macOS only." "WhoRead 只能在 macOS 上运行。"
major="$(sw_vers -productVersion | cut -d. -f1)"
[ "$major" -ge 14 ] || die "WhoRead needs macOS 14 or later." "WhoRead 需要 macOS 14 或更新的版本。"
xcrun --show-sdk-platform-path >/dev/null 2>&1 || die \
  "Building WhoRead needs Xcode (free in the App Store). Install it, open it once, then run this again." \
  "编译 WhoRead 需要 Xcode（App Store 免费下载）。装好后打开一次，再重新运行本脚本。"

B="$ROOT/.build-sc/release"
LOG="$ROOT/.build-sc/install-build.log"
mkdir -p "$ROOT/.build-sc"
say "Building WhoRead (a minute or two)..." "正在编译 WhoRead（一两分钟）……"
if ! WHOREAD_CONFIG=release "$ROOT/scripts/dev/sc-build.sh" app > "$LOG" 2>&1; then
  tail -25 "$LOG" >&2
  die "The build failed. Full log: $LOG" "编译失败。完整日志：$LOG"
fi

# The running app is replaced: quit it first.
pkill -x WhoRead 2>/dev/null || true

say "Installing. macOS asks for your password: the background service runs as root." \
  "正在安装。macOS 会问你的登录密码：后台服务需要以 root 身份运行。"
sudo "$ROOT/scripts/install-dev-daemon.sh" eslogger --bin "$B" --app "$B/WhoRead.app"

WR=/usr/local/bin/whoread
APPBIN=/Applications/WhoRead.app/Contents/MacOS/WhoRead
reachable() { "$WR" status >/dev/null 2>&1; }
running() { "$WR" status --json 2>/dev/null | grep -Eq '"sourceRunning" *: *true'; }

for _ in $(seq 60); do reachable && break; sleep 0.5; done
reachable || die "The background service does not answer. Its log: sudo tail -50 /Library/Logs/WhoRead/whoreadd.log" \
  "后台服务没有响应。日志在：sudo tail -50 /Library/Logs/WhoRead/whoreadd.log"

# eslogger starts within a few seconds when Full Disk Access is already on (a reinstall of the same build).
for _ in $(seq 10); do running && break; sleep 1; done
if ! running && [ "$WAIT" = 1 ]; then
  printf '%s' /usr/local/libexec/whoreadd | pbcopy 2>/dev/null || true
  open "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles" 2>/dev/null \
    || open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null || true
  echo
  say "One more step: let WhoRead's background service see file accesses (Full Disk Access)." \
    "最后一步：允许 WhoRead 的后台服务看到文件访问（完全磁盘访问权限）。"
  say "System Settings is open at Privacy & Security > Full Disk Access:" \
    "「系统设置」已经打开到「隐私与安全性 > 完全磁盘访问权限」："
  say "  0. If whoreadd is in the list already (from an earlier install), select it and click - first." \
    "  0. 如果列表里已经有 whoreadd（以前装过），先选中它，点 - 删掉。"
  say "  1. Click + under the list (enter your password if asked)." \
    "  1. 点列表下面的 +（如果要求，输入密码）。"
  say "  2. Press Command-Shift-G, paste with Command-V (the path /usr/local/libexec/whoreadd is copied), press Return, click Open." \
    "  2. 按 Command-Shift-G，用 Command-V 粘贴（路径 /usr/local/libexec/whoreadd 已经复制好了），按回车，再点「打开」。"
  say "  3. Make sure the switch next to whoreadd is on." \
    "  3. 确认 whoreadd 旁边的开关是打开的。"
  say "Waiting for it (this window continues by itself)..." "等待中（打开后这里会自动继续）……"
  start=$SECONDS
  kicked=$SECONDS
  hinted=0
  until running; do
    if [ $((SECONDS - start)) -ge 900 ]; then
      die "Still no Full Disk Access after 15 minutes. Switch it on, then run scripts/install.sh again." \
        "15 分钟后仍然没有完全磁盘访问权限。打开开关后，再运行一次 scripts/install.sh。"
    fi
    # eslogger(1) asks for Full Disk Access of the responsible process, the daemon; should macOS want
    # it for eslogger itself (as for an eslogger run as its own launch daemon), adding it helps.
    if [ "$hinted" = 0 ] && [ $((SECONDS - start)) -ge 75 ]; then
      say "If whoreadd is switched on already, add /usr/bin/eslogger the same way and switch it on too." \
        "如果 whoreadd 的开关已经打开，请用同样的方法再添加 /usr/bin/eslogger，并打开它的开关。"
      hinted=1
    fi
    # A restart makes the service try again at once; by itself it retries less often.
    if [ $((SECONDS - kicked)) -ge 15 ] && sudo -n true 2>/dev/null; then
      sudo -n launchctl kickstart -k system/com.whoread.daemon >/dev/null 2>&1 || true
      kicked=$SECONDS
      for _ in $(seq 20); do reachable && break; sleep 0.5; done
    fi
    sleep 2
  done
  say "Full Disk Access is on." "完全磁盘访问权限已经打开。"
fi

# The app's own check: it reaches the service and is recognised as the WhoRead app.
if check="$("$APPBIN" --self-check 2>&1)"; then rc=0; else rc=$?; fi
printf '%s\n' "$check" | sed 's/^/  /'
[ "$rc" -eq 0 ] || die "The menu bar app could not use the background service (see above). Run scripts/install.sh again." \
  "菜单栏 App 无法使用后台服务（见上面的信息）。请再运行一次 scripts/install.sh。"

# Live check: a read of a fake file in WhoRead's test vault (a built-in category for fake secrets,
# ~/WhoReadTestVault) must show up in the recorded history within a few seconds.
if running && [ "$WAIT" = 1 ]; then
  vault="$HOME/WhoReadTestVault"
  probe="$vault/notes/install-check.txt"
  if [ ! -L "$vault" ] && [ ! -L "$vault/notes" ] && [ ! -L "$probe" ] && mkdir -p "$vault/notes" 2>/dev/null \
     && echo "WhoRead install check: not a secret" > "$probe" 2>/dev/null; then
    sleep 1
    /bin/cat "$probe" > /dev/null
    found=0
    for _ in $(seq 20); do
      if sudo "$WR" events --since 2m --category test-vault --json 2>/dev/null | grep -q 'install-check\.txt'; then
        found=1; break
      fi
      sleep 0.5
    done
    if [ "$found" = 1 ]; then
      say "Live check passed: reading a fake test file was recorded, with the program that did it." \
        "实时检查通过：读取一个假的测试文件已经被记录下来，包括是哪个程序读的。"
    else
      say "Live check: reading a fake test file was not recorded within 10 seconds. Run whoread status to see why." \
        "实时检查：10 秒内没有记录到对假测试文件的读取。请运行 whoread status 查看原因。"
    fi
  fi
fi

[ "$OPEN" = 0 ] || open /Applications/WhoRead.app || true
echo
if running; then
  say "Done. WhoRead records which programs open your sensitive files, and which app or AI agent started them." \
    "装好了。WhoRead 会记录哪些程序打开了你的敏感文件，以及是哪个 App 或 AI agent 启动了它们。"
else
  say "Installed, but monitoring has not started: Full Disk Access is still off (see above)." \
    "已经安装，但监控还没有开始：完全磁盘访问权限还没有打开（见上文）。"
fi
say "The menu bar icon shows alerts; allow notifications when macOS asks. In Terminal: whoread status, sudo whoread events --since 1h" \
  "菜单栏图标会显示提醒；macOS 询问时请允许通知。终端里可以用：whoread status、sudo whoread events --since 1h"
say "Programs that were already open when WhoRead started (Terminal, editors, AI agents) are marked \"started by an unknown process\" until they are reopened, since WhoRead did not see who started them; in Terminal a new tab is enough. This happens again whenever the WhoRead service restarts (an update, a reinstall)." \
  "WhoRead 启动前就开着的程序（终端、编辑器、AI agent）会被标成「不知道是谁启动的」，直到重新打开它们，因为 WhoRead 没看到是谁启动了它们；终端只要新开一个标签页就行。以后 WhoRead 的后台服务每次重启（更新、重装）都会这样。"
say "Blocking needs a signed release, which is not available yet. To remove WhoRead: scripts/uninstall.sh" \
  "拦截功能需要签名的正式版，目前还没有。卸载：scripts/uninstall.sh"
