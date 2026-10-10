#!/bin/bash
# Installs the development LaunchDaemon (needs sudo). Run on your Mac after building:
#   swift build -c release        (or scripts/build.sh for signed Xcode builds, see below)
#   sudo scripts/install-dev-daemon.sh [eslogger|native] [--bin DIR]
#
# Nothing is built here: it installs whoreadd and whoread from --bin DIR (or WHOREAD_BIN=DIR), else
# from the first of .build/release, .build/debug, .build-sc/debug that has both. The test VM has no
# Xcode and installs the host's build this way (scripts/vm/provision.sh).
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

# Prints why PATH (a link at PATH is not followed) could be changed by someone other than UID, and
# succeeds; fails when only UID can change it. Any ACL ALLOW entry counts (mode bits do not show
# one); DENY entries, like a home's "everyone deny delete", only take rights away.
untrusted_reason() {  # PATH UID
  local owner mode
  owner="$(stat -f %u "$1")"
  mode="$(stat -f %Lp "$1")"
  if [ "$owner" != "$2" ]; then echo "is owned by uid $owner"
  elif (( 8#$mode & 8#022 )); then echo "is writable by group or others (mode $mode)"
  elif [[ "$(ls -led "$1")" == *$'\n'*' allow '* ]]; then echo "has an access control list that lets others in"
  else return 1
  fi
}

# Prints why someone other than UID and root could add, remove or rename entries in DIR, and succeeds;
# fails when no one else can. A sticky bit does not help (others could still make an entry first). An
# ACL entry counts only when it allows such a change: one that lets others list or read does not.
entries_untrusted_reason() {  # DIR UID
  local owner mode line
  if [ -L "$1" ] || [ ! -d "$1" ]; then echo "is a symbolic link or not a directory"; return 0; fi
  owner="$(stat -f %u "$1")"
  mode="$(stat -f %Lp "$1")"
  if [ "$owner" != "$2" ] && [ "$owner" != 0 ]; then echo "is owned by uid $owner"; return 0; fi
  if (( 8#$mode & 8#022 )); then echo "is writable by group or others (mode $mode)"; return 0; fi
  while IFS= read -r line; do
    case "$line" in *' allow '*) ;; *) continue ;; esac
    case ",${line##* allow }," in
      *,add_file,*|*,add_subdirectory,*|*,delete_child,*|*,delete,*|*,write,*|*,append,*|*,writesecurity,*|*,chown,*)
        echo "has an access control list that lets others add, remove or rename its entries"
        return 0 ;;
    esac
  done < <(ls -led "$1")
  return 1
}

# Fails, saying why, when someone other than UID and root could add, remove or rename entries in DIR,
# the folder that holds the log directory: they could swap that directory for a link after the checks
# in private_log, and launchd opens the log by path at every start.
require_private_parent() {  # DIR UID
  local reason
  reason="$(entries_untrusted_reason "$1" "$2")" || return 0
  echo "refusing to set up the log: $1 $reason. Only root may be able to change it: check it, then sudo chown root:wheel it, sudo chmod go-w it and remove its ACL entries (sudo chmod -N)" >&2
  return 1
}

# Renames PATH to PATH.untrusted-<time>-<pid>-<n>, never following or deleting it, and says why.
move_aside() {  # PATH REASON
  local to n=0
  while :; do
    to="$1.untrusted-$(date +%s)-$$-$n"
    [ -e "$to" ] || [ -L "$to" ] || break
    n=$((n + 1))
  done
  mv "$1" "$to"
  echo "$1 $2: moved aside to $to" >&2
}

# Makes DIR a directory only OWNER can enter (0700) holding NAME as OWNER's alone (0600), for launchd
# to append the daemon's output to (alert headlines and process chains of every user). Nothing someone
# else left there is followed or adopted, as the system extension does with its own log (macos-3):
# - nothing at all is done when others can change entries in DIR's parent (require_private_parent);
# - at DIR, a link or non-directory, another user's directory, or one others can write or that has an
#   ACL ALLOW entry is moved aside first;
# - then, with nobody else able to change DIR, the same goes for NAME, for a NAME that is not a regular
#   file or has more than one name (chown and chmod would change that other file too), and for one
#   others could read: chmod closes its path, not the descriptors opened before, and launchd would go
#   on appending to that very file.
# An existing log that passes is kept, with its content. Both lose their whole ACL: one made fresh
# takes ALLOW entries from an inheritable ACL above it, which its mode does not show.
private_log() {  # DIR NAME OWNER GROUP
  local dir="$1" file="$1/$2" owner="$3" group="$4" uid reason
  uid="$(id -u "$owner")"
  require_private_parent "$(dirname "$dir")" "$uid" || return 1
  if [ -L "$dir" ] || { [ -e "$dir" ] && [ ! -d "$dir" ]; }; then
    move_aside "$dir" "is a symbolic link or not a directory"
  elif [ -d "$dir" ] && reason="$(untrusted_reason "$dir" "$uid")"; then
    move_aside "$dir" "$reason"
  fi
  [ -d "$dir" ] || mkdir -m 700 "$dir"
  chown -h "$owner:$group" "$dir"
  chmod -h 700 "$dir"
  chmod -h -N "$dir"
  if [ -L "$file" ] || { [ -e "$file" ] && [ ! -f "$file" ]; }; then
    move_aside "$file" "is a symbolic link or not a regular file"
  elif [ -e "$file" ] && reason="$(untrusted_reason "$file" "$uid")"; then
    move_aside "$file" "$reason"
  elif [ -e "$file" ] && [ "$(stat -f %l "$file")" != 1 ]; then
    move_aside "$file" "has $(stat -f %l "$file") hard links"
  elif [ -e "$file" ] && (( 8#$(stat -f %Lp "$file") & 8#044 )); then
    move_aside "$file" "was readable by others (mode $(stat -f %Lp "$file")), who may still hold it open"
  fi
  [ -e "$file" ] || install -m 600 -o "$owner" -g "$group" /dev/null "$file"
  chown -h "$owner:$group" "$file"
  chmod -h 600 "$file"
  chmod -h -N "$file"
}

# Fails, saying why, unless each existing DIR is a real directory that only UID can change. Used where
# the daemon's own check would refuse it at start (the data directory), and where launchd starts the
# daemon from as root (/usr/local): `install -d` would chown and chmod whatever a link there points to,
# and the files copied next would land in it.
require_trusted_dirs() {  # UID FIX DIR...
  local uid="$1" fix="$2" dir reason
  shift 2
  for dir in "$@"; do
    if [ -L "$dir" ] || { [ -e "$dir" ] && [ ! -d "$dir" ]; }; then reason="is a symbolic link or not a directory"
    elif [ -d "$dir" ] && reason="$(untrusted_reason "$dir" "$uid")"; then :
    else continue
    fi
    echo "refusing to install: $dir $reason. Only root may be able to change it: $fix" >&2
    return 1
  done
}

# Sourced (by the tests): define the functions above, do nothing else. `return` works only there.
if (return 0 2>/dev/null); then return 0; fi

[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 77; }
usage() { echo "usage: $0 [eslogger|native] [--bin DIR]" >&2; exit 64; }
SOURCE=eslogger
BIN="${WHOREAD_BIN:-}"
while [ $# -gt 0 ]; do
  case "$1" in
    eslogger|native) SOURCE="$1"; shift ;;
    --bin) [ $# -ge 2 ] || usage; BIN="$2"; shift 2 ;;
    *) usage ;;
  esac
done
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ -z "$BIN" ]; then
  for d in "$ROOT/.build/release" "$ROOT/.build/debug" "$ROOT/.build-sc/debug"; do
    if [ -x "$d/whoreadd" ] && [ -x "$d/whoread" ]; then BIN="$d"; break; fi
  done
  BIN="${BIN:-$ROOT/.build/release}"
fi
[ -x "$BIN/whoreadd" ] && [ -x "$BIN/whoread" ] || { echo "no whoreadd/whoread in $BIN: build first (swift build -c release)" >&2; exit 1; }
# Prebuilt binaries from another Mac (the VM installs the host's build): fail here, not in launchd.
"$BIN/whoread" version >/dev/null 2>&1 || { echo "$BIN/whoread does not run on this Mac (architecture or macOS version?)" >&2; exit 1; }
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

# Like the daemon at start (macos-4): a data directory someone else could have changed is refused,
# never adopted (install -d would chown it) or moved aside (that would drop the user's rules).
require_trusted_dirs 0 "check it, then move it aside (sudo mv it to a new name) so a fresh one is created; whoever made it may have left rules, a catalog or links in it" \
  "$DATA" "$DATA/defaults"
# launchd runs whoreadd from /usr/local/libexec as root: whoever could rename entries in /usr/local
# could put their own program there.
require_trusted_dirs 0 "check it, then sudo chown root:wheel it, sudo chmod go-w it and remove its ACL entries (sudo chmod -N)" /usr/local
# The log's folder (private_log checks it again): refused here, the running daemon is left alone.
require_private_parent "$(dirname "$LOGS")" 0

launchctl bootout system "$PLIST" 2>/dev/null || true
# bootout can return before the old daemon has exited; bootstrapping the label again while it is
# still there fails (the VM's provisioning reinstalls over a running daemon).
for _ in $(seq 60); do launchctl print system/com.whoread.daemon >/dev/null 2>&1 || break; sleep 0.5; done
install -d -m 755 -o root -g wheel /usr/local/libexec /usr/local/bin "$DATA" "$DATA/defaults"
require_trusted_dirs 0 "check it, then remove its ACL entries (sudo chmod -N)" /usr/local/libexec /usr/local/bin
# The log carries alert headlines and process chains of every user: root only. A link or another
# user's file there is moved aside, never followed, and so is an earlier install's 0644 log (others
# may still hold it open); a 0755 directory is kept and closed to others.
private_log "$LOGS" whoreadd.log root wheel
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
