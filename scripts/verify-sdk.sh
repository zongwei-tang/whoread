#!/bin/bash
# Records the local SDK's view of every Endpoint Security, libproc and libbsm symbol WhoRead uses
# (prototypes with availability and header notes, the structs it reads, numeric enum values compiled
# from the headers, Swift's layout of es_message_t), the other macOS APIs docs/RESEARCH.md lists, and
# `eslogger --list-events`, so the notes and the es-typecheck stub can be checked against the headers
# instead of memory or web docs. Header paths are printed relative to the SDK.
#
# Every step runs even when another one fails (no Xcode, a sandbox, no eslogger): a step that cannot
# run records why, and everything else is still written. Nothing here needs root and nothing
# subscribes to Endpoint Security (`eslogger --list-events` only prints event names).
#
# Usage: scripts/verify-sdk.sh [OUTPUT]  (default docs/research/sdk-verification-<macOS version>.txt)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MACOS="$(sw_vers -productVersion 2>/dev/null || echo unknown)"
OUT="${1:-$ROOT/docs/research/sdk-verification-$MACOS.txt}"
SDK="$(xcrun --show-sdk-path 2>/dev/null || true)"
INC="$SDK/usr/include"
ES="$INC/EndpointSecurity"
FW="$SDK/System/Library/Frameworks"
# Without a scratch directory every compile step below would write to "/values.c" and the like.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/verify-sdk.XXXXXX")" || { echo "verify-sdk.sh: mktemp failed" >&2; exit 1; }
cleanup() { find "$WORK" -delete 2>/dev/null || true; }
trap cleanup EXIT

# Header paths relative to the SDK, so the output does not depend on where Xcode is installed, and
# scratch paths (compiler errors) relative to the scratch directory, which may sit under $HOME.
rel() {
  local args=(-e "s#$WORK/##g")
  if [ -n "$SDK" ]; then args+=(-e "s#$SDK/##g"); fi
  sed "${args[@]}"
}

# hits GREP_ARGS... : grep -n hits (at most 40 lines), or NOT FOUND. The output is captured first, so
# a long hit list cannot be cut into a false NOT FOUND by head closing the pipe.
hits() {
  local out
  out="$(grep -Hn "$@" 2>/dev/null)"
  if [ -n "$out" ]; then printf '%s\n' "$out" | head -n 40 | rel; else echo "NOT FOUND"; fi
}

# decl SYMBOL : the header comment, availability and prototype of an ES function (OS_EXPORT to ';').
decl() {
  local out
  out="$(awk -v sym="$1" '
    /^[ \t]*\/\*/ { cbuf = ""; incomment = 1 }
    incomment { cbuf = cbuf FILENAME ":" FNR ": " $0 "\n"; if ($0 ~ /\*\//) incomment = 0; next }
    /^OS_EXPORT/ { buf = ""; collecting = 1 }
    collecting {
      buf = buf FILENAME ":" FNR ": " $0 "\n"
      if ($0 ~ /;/) {
        if (buf ~ ("[^A-Za-z0-9_]" sym "[ \t]*\\(")) printf "%s%s", cbuf, buf
        collecting = 0; buf = ""; cbuf = ""
      }
    }' "$ES"/*.h 2>/dev/null)"
  if [ -n "$out" ]; then printf '%s\n' "$out" | rel; else echo "NOT FOUND"; fi
}

# types NAME... : the typedef struct/union of each name, as declared.
types() {
  local name out
  for name in "$@"; do
    out="$(awk -v name="$name" '
      /^typedef (struct|union)/ { buf = ""; on = 1 }
      on { buf = buf $0 "\n" }
      on && $0 ~ ("^} *" name ";") { printf "%s", buf; on = 0 }
      on && /^} *[A-Za-z0-9_]+;/ { on = 0 }' "$ES"/*.h 2>/dev/null)"
    echo "### $name"
    if [ -n "$out" ]; then printf '%s\n' "$out"; else echo "NOT FOUND"; fi
  done
}

# enumerators NAME... : the enumerator names of the given typedef enums in ESTypes.h.
enumerators() {
  local name
  for name in "$@"; do
    awk -v name="$name" '
      /^typedef enum/ { n = 0; on = 1; next }
      on && /^}/ { if ($0 ~ ("^} *" name "( |;)")) for (i = 0; i < n; i++) print e[i]; on = 0; next }
      on && match($0, /^[ \t]*ES_[A-Z0-9_]+/) { v = substr($0, RSTART, RLENGTH); gsub(/[ \t]/, "", v); e[n++] = v }
    ' "$ES/ESTypes.h" 2>/dev/null
  done
}

section() { printf '\n## %s\n' "$1"; }

{
  echo "# WhoRead SDK verification (scripts/verify-sdk.sh)"
  echo "# macOS: $MACOS ($(sw_vers -buildVersion 2>/dev/null || echo '?'))"
  echo "# Xcode: $(xcodebuild -version 2>/dev/null | tr '\n' ' ' || true)"
  echo "# SDK: $(xcrun --show-sdk-version 2>/dev/null || echo 'unavailable') ($(basename "${SDK:-none}"))"
  echo "# swiftc: $(xcrun swiftc --version 2>/dev/null | head -n 1 || true)"
  echo "# clang: $(xcrun clang --version 2>/dev/null | head -n 1 || true)"
  if [ -z "$SDK" ] || [ ! -d "$ES" ]; then
    echo "# NO SDK: xcrun --show-sdk-path failed or has no EndpointSecurity headers; header sections are empty."
  fi
  echo "# EndpointSecurity headers: $(cd "$ES" 2>/dev/null && ls | tr '\n' ' ')"

  section "ES functions WhoRead calls (header comment, availability, prototype)"
  for sym in es_new_client es_delete_client es_subscribe es_unsubscribe es_unsubscribe_all es_respond_auth_result \
             es_respond_flags_result es_retain_message es_release_message es_clear_cache es_mute_process es_mute_path \
             es_unmute_path es_unmute_all_target_paths es_invert_muting es_muting_inverted es_exec_arg_count es_exec_arg; do
    echo; echo "### $sym"; decl "$sym"
  done

  section "ES functions WhoRead does not call yet (macOS 12-27)"
  for sym in es_set_deadline_miss_mode es_get_deadline_miss_mode es_set_deadline_max_milliseconds \
             es_get_deadline_max_milliseconds es_set_deadline_min_milliseconds es_get_deadline_min_milliseconds \
             es_new_descendants_client es_sync_client es_exec_entitlements es_muted_paths_events es_release_muted_paths \
             es_mute_path_events es_mute_process_events es_unmute_all_paths es_exec_env_count es_exec_fd_count; do
    echo; echo "### $sym"; decl "$sym"
  done

  section "Header notes"
  for t in "Cache key" "does not support caching" "ANY target path" "ALL paths" "deadline" "Thread Safety" \
           "safe to call" "default mute set" "hard\") links" "can fire multiple times" "message version >=" \
           "version >=" "Available in msg versions"; do
    echo; echo "### grep: $t"; hits -F "$t" "$ES"/*.h
  done

  section "Structs WhoRead reads"
  types es_string_token_t es_token_t es_file_t es_process_t es_thread_t es_message_t es_event_open_t \
        es_event_close_t es_event_rename_t es_event_clone_t es_event_copyfile_t es_event_link_t es_event_unlink_t \
        es_event_truncate_t es_event_exchangedata_t es_event_readdir_t es_event_create_t es_event_exec_t \
        es_event_fork_t es_event_exit_t es_muted_path_t es_muted_paths_t es_events_t

  section "Numeric values, compiled from the headers"
  {
    echo '#include <EndpointSecurity/EndpointSecurity.h>'
    echo '#include <libproc.h>'
    echo '#include <sys/fcntl.h>'
    echo '#include <sys/un.h>'
    echo '#include <sys/sysctl.h>'
    echo '#include <mach/task_info.h>'
    echo '#include <stddef.h>'
    echo '#include <stdio.h>'
    echo '#define P(x) printf("%-48s %lld\n", #x, (long long)(x))'
    echo 'int main(void) {'
    enumerators es_event_type_t es_action_type_t es_destination_type_t es_auth_result_t es_result_type_t es_return_t \
      es_respond_result_t es_new_client_result_t es_clear_cache_result_t es_mute_path_type_t es_mute_inversion_type_t \
      es_mute_inverted_return_t es_cs_validation_category_t es_deadline_miss_mode_t | sed 's/.*/  P(&);/'
    for m in FREAD FWRITE O_CREAT O_TRUNC O_EVTONLY O_DIRECTORY O_SYMLINK O_CLOEXEC PROC_PIDTBSDINFO PROC_PIDPATHINFO \
             PROC_PIDPATHINFO_MAXSIZE MAXPATHLEN TASK_AUDIT_TOKEN KERN_PROCARGS2 LOCAL_PEERCRED LOCAL_PEERPID \
             LOCAL_PEERTOKEN; do
      echo "  P($m);"
    done
    for f in "sizeof(es_message_t)" "offsetof(es_message_t, event)" "offsetof(es_message_t, global_seq_num)" \
             "sizeof(es_process_t)" "offsetof(es_process_t, cs_validation_category)" \
             "offsetof(es_process_t, cdhash_full)" "sizeof(es_file_t)" "sizeof(es_event_exec_t)"; do
      echo "  P($f);"
    done
    echo '  return 0;'
    echo '}'
  } > "$WORK/values.c"
  if xcrun clang -isysroot "$SDK" -fno-modules -o "$WORK/values" "$WORK/values.c" > "$WORK/clang.log" 2>&1; then
    "$WORK/values" || echo "(the values program failed)"
  else
    echo "UNAVAILABLE: clang could not compile the values program:"; head -n 20 "$WORK/clang.log" | rel
  fi

  section "Swift's view of es_message_t (must equal the C layout above: es_exec_arg reads past the struct)"
  cat > "$WORK/layout.swift" <<'EOF'
import EndpointSecurity
print("MemoryLayout<es_message_t>.size", MemoryLayout<es_message_t>.size)
print("MemoryLayout<es_message_t>.offset(of: \\.event)", MemoryLayout<es_message_t>.offset(of: \es_message_t.event) ?? -1)
print("MemoryLayout<es_message_t>.offset(of: \\.global_seq_num)", MemoryLayout<es_message_t>.offset(of: \es_message_t.global_seq_num) ?? -1)
print("MemoryLayout<es_process_t>.size", MemoryLayout<es_process_t>.size)
print("MemoryLayout<es_file_t>.size", MemoryLayout<es_file_t>.size)
EOF
  if xcrun swiftc -sdk "$SDK" -module-cache-path "$WORK/mc" -o "$WORK/layout" "$WORK/layout.swift" > "$WORK/swiftc.log" 2>&1; then
    "$WORK/layout" || echo "(the layout program failed)"
  else
    echo "UNAVAILABLE: swiftc could not compile the layout program:"; head -n 20 "$WORK/swiftc.log" | rel
  fi

  section "libproc, sys/proc_info.h, sysctl, libbsm"
  echo "### libproc.h prototypes"; hits -E "^int[[:space:]]+(proc_listallpids|proc_listpids|proc_pidinfo|proc_pidpath|proc_pidpath_audittoken|proc_name)[[:space:]]*\(" "$INC/libproc.h"
  echo "### libproc.h status"; hits -F "private interfaces" "$INC/libproc.h"
  echo "### proc_info.h flavors"; hits -E "define (PROC_PIDTBSDINFO|PROC_PIDT_SHORTBSDINFO|PROC_PIDPATHINFO|PROC_PIDUNIQIDENTIFIERINFO)" "$INC/sys/proc_info.h"
  echo "### PROC_PIDUNIQIDENTIFIERINFO (absent = not public)"; hits -F "PROC_PIDUNIQIDENTIFIERINFO" "$INC/sys/proc_info.h" "$INC/libproc.h"
  echo "### KERN_PROCARGS2"; hits -B1 -A1 -F "KERN_PROCARGS2" "$INC/sys/sysctl.h"
  echo "### libbsm audit token accessors"; hits -B2 -E "^(pid_t|int|uid_t)[[:space:]]+audit_token_to_(pid|pidversion|euid)[[:space:]]*\(" "$INC/bsm/libbsm.h"
  echo "### Darwin module map: libbsm"; hits -A2 -F "module libbsm" "$INC/Darwin.modulemap"

  section "Other APIs docs/RESEARCH.md lists (pending item 13)"
  echo "### NSXPCConnection"; hits -E "processIdentifier|effectiveUserIdentifier|auditSessionIdentifier|setCodeSigningRequirement|auditToken" "$FW/Foundation.framework/Headers/NSXPCConnection.h"
  echo "### SecCode"; hits -E "SecCodeCopyGuestWithAttributes\(|kSecGuestAttributePid|kSecGuestAttributeAudit[^A-Za-z]|SecCodeCheckValidity\(" "$FW/Security.framework/Headers/SecCode.h"
  echo "### SecRequirement"; hits -E "SecRequirementCreateWithString\(" "$FW/Security.framework/Headers/SecRequirement.h"
  echo "### task_info"; hits -E "TASK_AUDIT_TOKEN" "$INC/mach/task_info.h"
  echo "### sys/un.h peer options"; hits -E "LOCAL_PEER(CRED|PID|EPID|TOKEN|UUID)" "$INC/sys/un.h"
  echo "### getpeereid"; hits -E "getpeereid" "$INC/unistd.h"
  echo "### libraries"; (cd "$SDK/usr/lib" 2>/dev/null && ls libEndpointSecurity.tbd libbsm.tbd) || echo "NOT FOUND"

  section "eslogger --list-events"
  if EV="$(eslogger --list-events 2>&1)"; then
    echo "$(printf '%s\n' "$EV" | grep -c .) events"
    printf '%s\n' "$EV"
  else
    echo "UNAVAILABLE: eslogger --list-events failed: $EV"
  fi
} > "$OUT" 2>&1
echo "Wrote $OUT"
