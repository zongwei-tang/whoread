#!/bin/bash
# Grants Full Disk Access (TCC service kTCCServiceSystemPolicyAllFiles) to executables by path, by
# writing the system TCC database directly. ONLY for the SIP-disabled test VM: with SIP on the
# database cannot be written, and this must never run on your main Mac. Run as root:
#   scripts/vm/tcc-fda.sh /usr/local/libexec/whoreadd [PATH...]
# The access table's columns change between macOS releases, so the row is built from the columns
# this release has. A required column it does not know stops it (exit 3); then grant by hand:
# System Settings → Privacy & Security → Full Disk Access → + → ⌘⇧G → the path → Open → switch on.
# UNVERIFIED on macOS 27: that root without Full Disk Access may write this database once SIP is off
# (GitHub's macOS runner images do it that way), and that tccd honours a row without a code
# requirement (csreq NULL) for an ad hoc signed binary, also after it is re-signed. The real test is
# whether the daemon's Endpoint Security client starts (scripts/vm/provision.sh reports it).
#
# --db FILE: write FILE instead of the system database and leave tccd alone (scripts/vm/selftest.sh).
# --record FILE: before a row is written, append to FILE how to undo it: a path that had no row loses
#   it again, a row that was there comes back exactly as it was (scripts/vm/runner/install.sh).
# --undo FILE: undo what FILE records, newest first, then delete FILE (scripts/vm/runner/uninstall.sh).
set -euo pipefail
DB="/Library/Application Support/com.apple.TCC/TCC.db"
SYSTEM=1
RECORD=""
UNDO=""
usage() { echo "usage: $0 [--db FILE] [--record FILE] PATH... | $0 [--db FILE] --undo FILE" >&2; exit 64; }
while [ $# -gt 0 ]; do
  case "$1" in
    --db) [ $# -ge 2 ] || usage; DB="$2"; SYSTEM=""; shift 2 ;;
    --record) [ $# -ge 2 ] || usage; RECORD="$2"; shift 2 ;;
    --undo) [ $# -ge 2 ] || usage; UNDO="$2"; shift 2 ;;
    -*) usage ;;
    *) break ;;
  esac
done
if [ -n "$UNDO" ]; then
  [ $# -eq 0 ] && [ -z "$RECORD" ] || usage
else
  [ $# -gt 0 ] || usage
fi
SERVICE=kTCCServiceSystemPolicyAllFiles
if [ -n "$SYSTEM" ]; then
  [ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 77; }
  # A VM: the hypervisor flag, or the model name of an Apple silicon VM (VirtualMac2,1).
  [ "$(sysctl -n kern.hv_vmm_present 2>/dev/null)" = "1" ] || case "$(sysctl -n hw.model 2>/dev/null)" in VirtualMac*) ;; *) false ;; esac \
    || { echo "not a VM: refusing to touch TCC here" >&2; exit 1; }
  csrutil status 2>/dev/null | grep -q 'status: disabled\.' || { echo "SIP is on: the TCC database cannot be written" >&2; exit 1; }
fi
[ -f "$DB" ] || { echo "no TCC database at $DB" >&2; exit 1; }
q() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/''/g")"; }
sql() { sqlite3 -cmd ".timeout 5000" "$DB" "$1"; }
# tccd keeps decisions in memory; restart it so the changed rows count now.
restart_tccd() {
  [ -z "$SYSTEM" ] || launchctl kickstart -k system/com.apple.tccd.system >/dev/null 2>&1 || killall tccd 2>/dev/null || true
}

if [ -n "$UNDO" ]; then
  [ -f "$UNDO" ] || { echo "nothing to undo: no $UNDO"; exit 0; }
  # One statement list per line (text and blobs in hex, so no line breaks), the newest line first.
  sed -n '1!G;h;$p' "$UNDO" | while IFS= read -r stmt; do
    [ -z "$stmt" ] || sql "$stmt"
  done
  rm -f "$UNDO"
  restart_tccd
  echo "Full Disk Access rows put back as they were before (from $UNDO)"
  exit 0
fi

cols=$(sql "SELECT name || '|' || \"notnull\" || '|' || (dflt_value IS NOT NULL) FROM pragma_table_info('access');") \
  || { echo "cannot read the access table of $DB" >&2; exit 1; }
[ -n "$cols" ] || { echo "$DB has no access table" >&2; exit 1; }
case $'\n'"$cols" in
  *$'\nauth_value|'*) GRANTED="auth_value = 2" ;;   # macOS 11 and later
  *$'\nallowed|'*)    GRANTED="allowed = 1" ;;      # macOS 10.15 and earlier
  *) echo "the access table has neither auth_value nor allowed: unknown schema, grant by hand" >&2; exit 3 ;;
esac
# The row a grant replaces (INSERT OR REPLACE): same service, client and client type, and the same
# indirect object where the table has that column (part of its primary key).
INDIRECT=""
case $'\n'"$cols" in *$'\nindirect_object_identifier|'*) INDIRECT=" AND indirect_object_identifier = 'UNUSED'" ;; esac

# undo_line PATH : one line of SQL that deletes the row a grant to PATH writes and puts back the row
# it replaces, if there was one, exactly (every value rendered by SQLite, text and blobs in hex).
undo_line() {
  local names="" values="" name n old
  while IFS='|' read -r name _ _; do
    names="${names:+$names, }\"$name\""
    values="${values:+$values || ', ' || }CASE typeof(\"$name\") WHEN 'null' THEN 'NULL'"
    values="$values WHEN 'text' THEN 'CAST(X''' || hex(\"$name\") || ''' AS TEXT)'"
    values="$values WHEN 'blob' THEN 'X''' || hex(\"$name\") || '''' ELSE quote(\"$name\") END"
  done <<< "$cols"
  n=$(sql "SELECT count(*) FROM access WHERE service = $(q "$SERVICE") AND client = $(q "$1") AND client_type = 1$INDIRECT;")
  [ "$n" -le 1 ] || { echo "$n rows for $1 where one was expected; nothing changed" >&2; return 1; }
  old=$(sql "SELECT ' INSERT INTO access ($(printf '%s' "$names" | sed "s/'/''/g")) VALUES (' || $values || ');'
             FROM access WHERE service = $(q "$SERVICE") AND client = $(q "$1") AND client_type = 1$INDIRECT;")
  sql "SELECT 'DELETE FROM access WHERE service = CAST(X''' || hex($(q "$SERVICE")) || ''' AS TEXT)'
              || ' AND client = CAST(X''' || hex($(q "$1")) || ''' AS TEXT) AND client_type = 1'
              || $(q "$INDIRECT") || ';' || $(q "$old");"
}

rc=0
for path in "$@"; do
  case "$path" in /*) ;; *) echo "not an absolute path: $path" >&2; exit 64 ;; esac
  names=""; values=""
  while IFS='|' read -r name notnull hasdefault; do
    case "$name" in
      service)                    v=$(q "$SERVICE") ;;
      client)                     v=$(q "$path") ;;
      client_type)                v=1 ;;          # 1: the client is an absolute path, not a bundle id
      auth_value)                 v=2 ;;          # 2: allowed
      auth_reason)                v=4 ;;          # 4: set by system policy (as image builders do)
      auth_version)               v=1 ;;
      allowed|prompt_count)       v=1 ;;
      indirect_object_identifier) v=$(q UNUSED) ;;
      flags)                      v=0 ;;
      boot_uuid)                  v=$(q UNUSED) ;;
      last_modified|last_reminded) v="CAST(strftime('%s','now') AS INTEGER)" ;;
      *)
        # csreq, policy_id, pid… stay NULL or take their default: no code requirement, so a later
        # ad hoc re-signing of the same path keeps the grant.
        if [ "$notnull" = "1" ] && [ "$hasdefault" = "0" ]; then
          echo "the access table has a required column this script does not know: $name; grant by hand" >&2
          exit 3
        fi
        continue ;;
    esac
    names="${names:+$names, }$name"; values="${values:+$values, }$v"
  done <<< "$cols"
  if [ -n "$RECORD" ]; then
    line=$(undo_line "$path") || exit 1
    printf '%s\n' "$line" >> "$RECORD" || { echo "cannot write $RECORD" >&2; exit 1; }
  fi
  sql "INSERT OR REPLACE INTO access ($names) VALUES ($values);"
  n=$(sql "SELECT count(*) FROM access WHERE service = $(q "$SERVICE") AND client = $(q "$path") AND client_type = 1 AND $GRANTED;")
  if [ "$n" = "1" ]; then echo "Full Disk Access granted: $path"
  else echo "Full Disk Access NOT stored for $path" >&2; rc=1; fi
done

restart_tccd
exit $rc
