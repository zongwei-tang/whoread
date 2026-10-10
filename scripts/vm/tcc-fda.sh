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
set -euo pipefail
DB="/Library/Application Support/com.apple.TCC/TCC.db"
SYSTEM=1
if [ "${1:-}" = "--db" ]; then DB="${2:?--db FILE}"; SYSTEM=""; shift 2; fi
[ $# -gt 0 ] || { echo "usage: $0 [--db FILE] PATH..." >&2; exit 64; }
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

cols=$(sql "SELECT name || '|' || \"notnull\" || '|' || (dflt_value IS NOT NULL) FROM pragma_table_info('access');") \
  || { echo "cannot read the access table of $DB" >&2; exit 1; }
[ -n "$cols" ] || { echo "$DB has no access table" >&2; exit 1; }
case $'\n'"$cols" in
  *$'\nauth_value|'*) GRANTED="auth_value = 2" ;;   # macOS 11 and later
  *$'\nallowed|'*)    GRANTED="allowed = 1" ;;      # macOS 10.15 and earlier
  *) echo "the access table has neither auth_value nor allowed: unknown schema, grant by hand" >&2; exit 3 ;;
esac

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
  sql "INSERT OR REPLACE INTO access ($names) VALUES ($values);"
  n=$(sql "SELECT count(*) FROM access WHERE service = $(q "$SERVICE") AND client = $(q "$path") AND client_type = 1 AND $GRANTED;")
  if [ "$n" = "1" ]; then echo "Full Disk Access granted: $path"
  else echo "Full Disk Access NOT stored for $path" >&2; rc=1; fi
done

if [ -n "$SYSTEM" ]; then
  # tccd keeps decisions in memory; restart it so the new rows count now.
  launchctl kickstart -k system/com.apple.tccd.system >/dev/null 2>&1 || killall tccd 2>/dev/null || true
fi
exit $rc
