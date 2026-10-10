#!/bin/bash
# Host side of the WhoRead VM job runner (scripts/vm/runner/): runs scripts as root inside the
# SIP-disabled test VM through the folder tart shares with it, without ssh or network. Never uses
# sudo on this Mac.
#   scripts/vm/vmjob.sh ping                             is the runner in the VM alive?
#   scripts/vm/vmjob.sh run NAME SCRIPT [--timeout N] [-- ARG...]
#                                                        run SCRIPT in the VM, print its output as it
#                                                        comes, exit with its exit code
#   scripts/vm/vmjob.sh shell 'COMMAND' [--timeout N]    the same for a one-line command
#   scripts/vm/vmjob.sh result ID [--wait]               output and exit code of an earlier job
#   scripts/vm/vmjob.sh list                             queued, running and recent jobs
# Exit codes besides the job's own: 124 the job timed out in the VM, 125 interrupted by a runner or
# VM restart, 69 the runner is not responding (a job it had not taken yet is withdrawn and never
# runs) or is older than this script (nothing is queued: install it again in the VM, README step 4),
# 70 gave up waiting (a job still queued is withdrawn and never runs; a running one may still
# finish: result ID --wait), 64 usage. A job gets its timeout plus 120 s from its start (not from
# when it was queued) before vmjob gives up; WHOREAD_VMJOB_GRACE sets another margin than 120 s.
# Only time this Mac is awake counts: a jump of the clock (after sleep) does not use up these limits.
#
# Every job runs a private copy of SCRIPT: its text as it was when vmjob queued the job, which the
# job carries (editing SCRIPT afterwards, also while it waits or runs, changes nothing). A SCRIPT
# inside the shared directory runs with $0 its path there, so paths relative to $0 work (other files
# it uses come from the share as they are then); BASH_SOURCE is the private copy. Either way it runs
# with /bin/bash: a script whose #! line names another interpreter, or options, is refused. The
# timeout is --timeout N, else a "# timeout: N" line among the script's first 20 lines, else 900 s.
# In the VM a job starts in the checkout it came from (the shared directory for other scripts) with:
#   WHOREAD_VM_SHARE   the shared directory as the VM sees it
#   WHOREAD_VM_REPO    the checkout the script came from (a worktree under the share works too)
#   WHOREAD_TEST_USER  the VM's test user (admin): run vault accesses as this user
# WHOREAD_VM_HOST_DIR: the directory shared with the VM (tart run --dir=whoread:DIR); default: the
# main checkout of this repository. Results stay in DIR/.vm (gitignored).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"
DEFAULT_TIMEOUT=900
END_OF_SCRIPT=WHOREAD_VM_END_OF_SCRIPT
# The oldest runner (its heartbeat's "runner:" line) that runs the job files written here: version 1
# ran a job file where it lies in the share, and the copy of the script a job makes goes next to it.
NEED_RUNNER=2
GRACE="${WHOREAD_VMJOB_GRACE:-120}"
case "$GRACE" in ""|*[!0-9]*) echo "vmjob: WHOREAD_VMJOB_GRACE must be a number of seconds" >&2; exit 64 ;; esac

die() { echo "vmjob: $*" >&2; exit "${2:-1}"; }
usage() { sed -n '5,18p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 64; }

# CLOCK: seconds of waiting so far. It follows the wall clock while that moves plausibly; tick is
# called about once a second, and a step backwards or of more than MAX_STEP seconds (this Mac slept,
# and the VM with it, or the clock was set) counts as one second.
CLOCK=0
WALL_LAST=""
MAX_STEP=30
tick() {
  local now step
  now=$(date +%s)
  if [ -n "$WALL_LAST" ]; then
    step=$((now - WALL_LAST))
    if [ "$step" -lt 0 ] || [ "$step" -gt "$MAX_STEP" ]; then step=1; fi
    CLOCK=$((CLOCK + step))
  fi
  WALL_LAST=$now
}

# The shared directory: the main checkout, also when this script runs from a worktree under it.
host_dir() {
  local common
  if [ -n "${WHOREAD_VM_HOST_DIR:-}" ]; then
    (cd "$WHOREAD_VM_HOST_DIR" && pwd -P) || die "WHOREAD_VM_HOST_DIR is not a directory: $WHOREAD_VM_HOST_DIR"
    return
  fi
  common=$(git -C "$HERE" rev-parse --git-common-dir 2>/dev/null) || die "not in a git checkout; set WHOREAD_VM_HOST_DIR"
  case "$common" in /*) ;; *) common="$HERE/$common" ;; esac
  (cd "$common/.." && pwd -P)
}
HOST_DIR=$(host_dir) || exit 1
VMDIR="$HOST_DIR/.vm"
HB="$VMDIR/heartbeat"

# A fresh heartbeat by the host's clock, or else one that changes within 15 s.
alive() {
  local m now first cur
  [ -f "$HB" ] || { echo "vmjob: no heartbeat in $VMDIR: the runner is not installed in the VM, or the share is not mounted there (scripts/vm/README.md)" >&2; return 1; }
  m=$(stat -f %m "$HB" 2>/dev/null || echo 0)
  now=$(date +%s)
  [ "${1:-}" != strict ] && [ $((now - m)) -ge 0 ] && [ $((now - m)) -le 20 ] && return 0
  first=$(cat "$HB" 2>/dev/null)
  for _ in $(seq 30); do
    sleep 0.5
    cur=$(cat "$HB" 2>/dev/null)
    [ -n "$cur" ] && [ "$cur" != "$first" ] && return 0
  done
  echo "vmjob: the runner in the VM is not responding: its heartbeat has not changed for 15 s (file age $((now - m)) s). Last heartbeat:" >&2
  sed 's/^/  /' "$HB" >&2
  return 1
}

# The runner that writes the heartbeat is NEED_RUNNER or newer. The VM runs the copy install.sh
# made, so a change to scripts/vm/runner/ reaches it only when install.sh runs again: the install.sh
# of this checkout (a worktree's can be newer than the main checkout's), as the VM sees it.
runner_current() {
  local v install=/Users/admin/wr/whoread/scripts/vm/runner/install.sh
  v=$(sed -n 's/^runner:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' "$HB" 2>/dev/null | head -n 1)
  [ "${v:-0}" -ge "$NEED_RUNNER" ] && return 0
  case "$HERE" in "$HOST_DIR"/*) install="/Users/admin/wr/whoread/${HERE#"$HOST_DIR"/}/runner/install.sh" ;; esac
  echo "vmjob: the runner in the VM is version ${v:-unknown}, older than these scripts (they need $NEED_RUNNER). Install it again: in the VM, sudo bash $(printf '%q' "$install") (scripts/vm/README.md, step 4)" >&2
  return 1
}

cmd_ping() {
  alive strict || exit 69
  echo "VM runner alive ($VMDIR)"
  sed 's/^/  /' "$HB"
  runner_current || exit 69
}

OFFSET=0
# Prints what was appended to FILE since the last call.
show_new() {
  local size
  size=$(wc -c < "$1" 2>/dev/null | tr -d ' ')
  [ -n "$size" ] || return 0
  if [ "$size" -gt "$OFFSET" ]; then
    tail -c +$((OFFSET + 1)) "$1" | head -c $((size - OFFSET))
    OFFSET=$size
  fi
}

# Takes a job back if the runner has not claimed it yet. The rename and the runner's claim (also a
# rename) cannot both succeed, so a withdrawn job never starts.
withdraw() {
  mv "$VMDIR/jobs/$1.sh" "$VMDIR/jobs/$1.sh.withdrawn" 2>/dev/null
}

# wait_result ID LIMIT_SECONDS: streams ID.out, returns the job's exit code. LIMIT counts from the
# job's start: time spent queued behind other jobs is not the job's (a job still queued after LIMIT
# is taken back, 70). Gives up (69) when the runner's heartbeat stops changing: after 30 s for a job
# still queued (taken back), after 120 s for a running one (it may still finish: result ID --wait).
# A job that is neither queued nor running and has no result (withdrawn, or no such job): 70 at once.
wait_result() {
  local id="$1" limit="$2" res="$VMDIR/results/$1" start now rc seen changed cur started=""
  tick
  start=$CLOCK
  seen=$(cat "$HB" 2>/dev/null)
  changed=$start
  while :; do
    [ -f "$res.out" ] && show_new "$res.out"
    if [ -f "$res.status" ]; then
      # The status is written after the output's last line; give a lagging share a moment.
      for _ in $(seq 20); do
        tail -n 1 "$res.out" 2>/dev/null | grep -qE "^\[vm\] job $id: (exit|interrupted|could not)" && break
        sleep 0.25
      done
      [ -f "$res.out" ] && show_new "$res.out"
      rc=""
      for _ in $(seq 20); do
        rc=$(tr -dc '0-9' < "$res.status" 2>/dev/null)
        [ -n "$rc" ] && break
        sleep 0.25
      done
      [ -n "$rc" ] || rc=1
      return $((rc > 255 ? 255 : rc))
    fi
    tick
    now=$CLOCK
    cur=$(cat "$HB" 2>/dev/null)
    if [ "$cur" != "$seen" ]; then seen=$cur; changed=$now; fi
    # A job moves jobs/ → running/ → (status written) → done/; checked in this order, it cannot slip
    # past unseen.
    if [ -f "$VMDIR/jobs/$id.sh" ]; then
      if [ $((now - changed)) -ge 30 ] && withdraw "$id"; then
        echo "vmjob: the runner did not take job $id (heartbeat unchanged for $((now - changed)) s); withdrawn, it will not run. Check: $0 ping" >&2
        return 69
      fi
      if [ $((now - start)) -ge "$limit" ] && withdraw "$id"; then
        echo "vmjob: job $id was still queued after $((now - start)) s (the runner is busy with other jobs: $0 list); withdrawn, it will not run" >&2
        return 70
      fi
    elif [ -f "$VMDIR/running/$id.sh" ]; then
      [ -n "$started" ] || { started=1; start=$now; }
      if [ $((now - changed)) -ge 120 ]; then
        echo "vmjob: the runner stopped responding while job $id runs (heartbeat unchanged for $((now - changed)) s); later: $0 result $id --wait" >&2
        return 69
      fi
      if [ $((now - start)) -ge "$limit" ]; then
        echo "vmjob: gave up waiting after ${limit}s; the job may still finish: $0 result $id --wait" >&2
        return 70
      fi
    elif [ ! -f "$res.status" ]; then
      if [ -f "$VMDIR/jobs/$id.sh.withdrawn" ]; then echo "vmjob: job $id was withdrawn and never ran" >&2
      else echo "vmjob: no job $id in $VMDIR (not queued, not running, no result)" >&2
      fi
      return 70
    fi
    sleep 1
  done
}

# timeout from a "# timeout: N" header line, if any
header_timeout() {
  head -n 20 "$1" | sed -n 's/^#[[:space:]]*timeout:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' | head -n 1
}

cmd_run() {
  local name="${1:-}" script="${2:-}" timeout="" abs rel repo repo_rel id job
  [ -n "$name" ] && [ -n "$script" ] || usage
  shift 2
  while [ $# -gt 0 ]; do
    case "$1" in
      --timeout) timeout="${2:-}"; shift 2 || usage ;;
      --) shift; break ;;
      *) die "unexpected argument: $1 (script arguments go after --)" 64 ;;
    esac
  done
  case "$timeout" in '') ;; *[!0-9]*|0) die "--timeout needs a positive number of seconds" 64 ;; esac
  [ -f "$script" ] || die "no such script: $script" 64
  # The VM runs the copy with /bin/bash (`. COPY` for a script in the share, which keeps $0): a #!
  # line naming another interpreter, or options (#!/bin/bash -e), would silently not apply there.
  case "$(head -n 1 "$script")" in
    '#!'*)
      case "$(head -n 1 "$script" | tr -s ' \t' '  ' | sed 's/ $//')" in
        '#!/bin/bash'|'#! /bin/bash'|'#!/bin/sh'|'#! /bin/sh'|\
        '#!/usr/bin/env bash'|'#! /usr/bin/env bash'|'#!/usr/bin/env sh'|'#! /usr/bin/env sh') ;;
        *) die "$script starts with $(head -n 1 "$script"): jobs run with /bin/bash only, without options (use set -e and the like in the script)" 64 ;;
      esac ;;
  esac
  name=$(printf '%s' "$name" | tr -c 'A-Za-z0-9._-' '_')
  abs="$(cd "$(dirname "$script")" && pwd -P)/$(basename "$script")"
  # The job carries the script's text up to this line (a here-document).
  ! grep -qxF "$END_OF_SCRIPT" "$abs" || die "$script contains a line $END_OF_SCRIPT, which ends the copy a job carries" 64
  [ -n "$timeout" ] || timeout=$(header_timeout "$abs")
  [ -n "$timeout" ] || timeout=$DEFAULT_TIMEOUT
  alive || exit 69
  runner_current || exit 69
  mkdir -p "$VMDIR/jobs" "$VMDIR/results" || die "cannot create $VMDIR"
  id="$(date +%Y%m%d-%H%M%S)-$name-$$"
  job="$VMDIR/jobs/$id.sh"
  {
    echo '#!/bin/bash'
    echo "# timeout: $timeout"
    echo "# whoread-vm job $id, submitted $(date -u +%Y-%m-%dT%H:%M:%SZ), with a copy of $(printf '%q' "$abs")"
    case "$abs" in
      "$HOST_DIR"/*)
        rel="${abs#"$HOST_DIR"/}"
        repo=$(git -C "$(dirname "$abs")" rev-parse --show-toplevel 2>/dev/null) && repo=$(cd "$repo" && pwd -P) || repo="$HOST_DIR"
        case "$repo" in "$HOST_DIR"/*) repo_rel="/${repo#"$HOST_DIR"/}" ;; *) repo_rel="" ;; esac
        # shellcheck disable=SC2016  # expanded in the VM
        printf 'export WHOREAD_VM_REPO="$WHOREAD_VM_SHARE"%s\n' "$(printf '%q' "$repo_rel")" ;;
      *)
        rel=""
        # shellcheck disable=SC2016  # expanded in the VM
        echo 'export WHOREAD_VM_REPO="$WHOREAD_VM_SHARE"' ;;
    esac
    # shellcheck disable=SC2016  # expanded in the VM
    echo 'cd "$WHOREAD_VM_REPO" || exit 1'
    # The runner runs this file from a private folder; the copy of the script goes there too, under
    # its own name (error messages name it), and never into the share.
    # shellcheck disable=SC2016  # expanded in the VM
    printf 'script="$(dirname "$0")/script/"%s\n' "$(printf '%q' "$(basename "$abs")")"
    # shellcheck disable=SC2016  # expanded in the VM
    printf 'mkdir "$(dirname "$script")" && cat > "$script" <<%s || exit 125\n' "'$END_OF_SCRIPT'"
    cat "$abs"
    [ -z "$(tail -c 1 "$abs")" ] || echo
    echo "$END_OF_SCRIPT"
    if [ -n "$rel" ]; then
      # Sourced from bash -c, so $0 is the script's path in the share; the copy's path is part of
      # the command (not an argument), so the script's arguments stay its own.
      # shellcheck disable=SC2016  # expanded in the VM
      printf 'exec /bin/bash -c ". $(printf %%q "$script")" "$WHOREAD_VM_SHARE"/%s' "$(printf '%q' "$rel")"
    else
      # shellcheck disable=SC2016  # expanded in the VM
      printf 'exec /bin/bash "$script"'
    fi
    for a in "$@"; do printf ' %q' "$a"; done
    echo
  } > "$job.tmp" || die "cannot write $job.tmp"
  mv -f "$job.tmp" "$job" || die "cannot queue $job"
  echo "vmjob: queued $id (timeout ${timeout}s)" >&2
  wait_result "$id" $((timeout + GRACE))
}

cmd_shell() {
  local command="${1:-}" tmp rc
  [ -n "$command" ] || usage
  shift
  tmp=$(mktemp "${TMPDIR:-/tmp}/vmjob-shell.XXXXXX") || die "mktemp failed"
  printf '%s\n' "$command" > "$tmp"
  cmd_run shell "$tmp" "$@"
  rc=$?
  rm -f "$tmp"
  return $rc
}

cmd_result() {
  local id="${1:-}" res
  [ -n "$id" ] || usage
  case "$id" in *[!A-Za-z0-9._-]*) die "bad job id: $id" 64 ;; esac
  res="$VMDIR/results/$id"
  if [ "${2:-}" = --wait ]; then wait_result "$id" 86400; return; fi
  if [ -f "$res.status" ]; then wait_result "$id" 0; return; fi
  [ -f "$res.out" ] && cat "$res.out"
  if [ -f "$VMDIR/jobs/$id.sh" ]; then echo "vmjob: $id is queued" >&2
  elif [ -f "$VMDIR/running/$id.sh" ]; then echo "vmjob: $id is running" >&2
  elif [ -f "$VMDIR/jobs/$id.sh.withdrawn" ]; then echo "vmjob: $id was withdrawn and never ran" >&2
  else echo "vmjob: no job $id" >&2
  fi
  return 70
}

cmd_list() {
  local f id
  for f in "$VMDIR/jobs/"*.sh; do [ -f "$f" ] && echo "queued   $(basename "$f" .sh)"; done
  for f in "$VMDIR/running/"*.sh; do [ -f "$f" ] && echo "running  $(basename "$f" .sh)"; done
  for f in "$VMDIR/results/"*.status; do
    [ -f "$f" ] || continue
    id=$(basename "$f" .status)
    printf 'exit %-4s %s\n' "$(tr -dc '0-9' < "$f")" "$id"
  done | tail -n 20
}

cmd="${1:-}"
[ $# -gt 0 ] && shift
case "$cmd" in
  ping) cmd_ping ;;
  run) cmd_run "$@" ;;
  shell) cmd_shell "$@" ;;
  result) cmd_result "$@" ;;
  list) cmd_list ;;
  *) usage ;;
esac
