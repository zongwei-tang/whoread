#!/bin/bash
# Run on the Mac (first step): records the local SDK's view of every EndpointSecurity / libproc
# symbol WhoRead uses, plus `eslogger --list-events`, so docs/RESEARCH.md can be checked against
# the headers instead of memory or web docs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/docs/research/sdk-verification-$(sw_vers -productVersion).txt"
SDK="$(xcrun --show-sdk-path)"
ES="$SDK/usr/include/EndpointSecurity"
{
  echo "# SDK: $SDK"
  echo "# macOS: $(sw_vers -productVersion) ($(sw_vers -buildVersion)); Xcode: $(xcodebuild -version | tr '\n' ' ')"
  echo
  for sym in es_new_client es_delete_client es_subscribe es_unsubscribe es_respond_auth_result es_respond_flags_result \
             es_retain_message es_release_message es_clear_cache es_mute_process es_mute_path es_unmute_path \
             es_unmute_all_target_paths es_invert_muting es_muting_inverted es_exec_arg_count es_exec_arg \
             es_set_deadline_miss_mode; do
    echo "## $sym"
    grep -n -B2 -A3 "\b$sym\b *(" "$ES"/*.h | head -40 || echo "NOT FOUND"
    echo
  done
  for t in ES_MUTE_PATH_TYPE_TARGET_PREFIX ES_MUTE_INVERSION_TYPE_TARGET_PATH ES_EVENT_TYPE_AUTH_COPYFILE \
           ES_EVENT_TYPE_NOTIFY_CLOSE "Cache key" "does not support caching" "deadline" "ANY target path" "ALL paths"; do
    echo "## grep: $t"
    grep -n "$t" "$ES"/*.h | head -30 || echo "NOT FOUND"
    echo
  done
  echo "## es_process_t / es_message_t / event structs"
  for s in es_process_t es_message_t es_event_open_t es_event_close_t es_event_rename_t es_event_clone_t \
           es_event_copyfile_t es_event_link_t es_event_unlink_t es_event_truncate_t es_event_exchangedata_t es_event_exec_t; do
    awk "/} $s;/{f=0} f; /typedef struct/{buf=\"\"} {buf=buf\"\\n\"\$0} /} $s;/{print buf}" "$ES"/*.h | tail -40
  done
  echo
  echo "## libproc"
  grep -n -E "proc_listallpids|proc_pidinfo|proc_pidpath|PROC_PIDTBSDINFO|PROC_PIDPATHINFO_MAXSIZE" "$SDK/usr/include/libproc.h" "$SDK/usr/include/sys/proc_info.h" | head -20
  echo
  echo "## eslogger --list-events"
  eslogger --list-events
} > "$OUT" 2>&1
echo "Wrote $OUT"
