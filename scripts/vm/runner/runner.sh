#!/bin/bash
# WhoRead VM job runner. Lets the host drive the SIP-disabled test VM through the
# shared folder, without ssh or network. Runs IN THE VM only; scripts/vm/runner/install.sh copies
# it to /usr/local/libexec/whoread-vmrunner.sh and starts it with launchd. Modes:
#   daemon            root LaunchDaemon com.whoread.vmrunner (the normal case)
#   agent             LaunchAgent in the test user's GUI session, the fallback when a root daemon
#                     cannot read the share; every job then runs as root through
#                     `sudo -n /usr/local/libexec/whoread-vmrunner.sh exec-job ID`
#   mount             (root) mount the share unless it is mounted
#   exec-job ID       (root) run one claimed job (used by agent mode)
#   stop-job ID       (root) stop what is left of a job whose runner died (used by agent mode)
#
# Protocol, in <shared repository>/.vm/ (the host side is scripts/vm/vmjob.sh):
#   jobs/ID.sh          queued by the host (written as ID.sh.tmp, then renamed)
#   running/ID.sh       claimed: renamed out of jobs/ before it starts, so it never runs twice
#   running/ID.pid      while it runs: the pid of its process group leader and that process's start
#                       time, so a restarted runner can stop a job its predecessor left running
#   done/ID.sh          finished, or interrupted by a runner restart (never run again)
#   results/ID.out      stdout + stderr, written while the job runs; the last line starts "[vm] job ID:"
#   results/ID.status   exit code, written after the last line of ID.out (124: timed out,
#                       125: interrupted or could not run)
#   heartbeat           rewritten every few seconds: guest time, macOS version, SIP status, jobs
# A job runs as root, in its own process group, with a timeout: 900 s, or N from a "# timeout: N"
# line among its first 20 lines. On timeout it gets SIGTERM, 10 s later SIGKILL.
#
# Settings come from /usr/local/etc/whoread-vmrunner.conf (KEY=VALUE lines, written by install.sh):
#   VM_USER  the VM's test user (default admin)    MOUNT  where the share is mounted (default
#   /Users/admin/wr)    TAGS  virtiofs tags to try, in order    BEAT_EVERY  heartbeat seconds
# WHOREAD_VM_RUNNER_TEST=1 (scripts/vm/selftest.sh on the host): no mounting, no root, no sudo;
# WHOREAD_VM_RUNNER_TEST_PATH is then put in front of PATH (stand-ins for tools a sandbox refuses).
set -uo pipefail
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
RUNNER_VERSION=1
MODE="${1:-}"
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
CONF="${WHOREAD_VM_RUNNER_CONF:-/usr/local/etc/whoread-vmrunner.conf}"
TEST_MODE="${WHOREAD_VM_RUNNER_TEST:-}"
[ -n "$TEST_MODE" ] && [ -n "${WHOREAD_VM_RUNNER_TEST_PATH:-}" ] && PATH="$WHOREAD_VM_RUNNER_TEST_PATH:$PATH"
VM_USER=admin
MOUNT=/Users/admin/wr
TAGS="whoread com.apple.virtio-fs.automount"
BEAT_EVERY=5
DEFAULT_TIMEOUT=900
if [ -f "$CONF" ]; then
  while IFS='=' read -r key value; do
    case "$key" in
      VM_USER) VM_USER="$value" ;;
      MOUNT) MOUNT="$value" ;;
      TAGS) TAGS="$value" ;;
      BEAT_EVERY) BEAT_EVERY="$value" ;;
    esac
  done < "$CONF"
fi
case "$MODE" in
  daemon) STATE=/var/run/whoread-vmrunner.state ;;
  *) STATE=/tmp/whoread-vmrunner-agent.state ;;
esac
STATE="${WHOREAD_VM_RUNNER_STATE:-$STATE}"
SHARE=""
LAST_BEAT=0
CURRENT=""
# A stop request (SIGTERM...) that arrives while a job is being started waits until the job's pid
# is known and recorded, so the job is never left running unseen.
STARTING=""
STOP_PENDING=""
# The heartbeat names the mode the host sees: a job that agent mode runs as root is still "agent".
case "$MODE" in exec-job|stop-job) BEAT_MODE=agent ;; *) BEAT_MODE="$MODE" ;; esac

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [$MODE] $*"; }

# Records the runner's state for install.sh (ok, mount-failed, share-unreadable, ...); logs changes.
set_state() {
  [ "$(cat "$STATE" 2>/dev/null)" = "$1" ] && return 0
  printf '%s\n' "$1" > "$STATE" 2>/dev/null
  log "state: $1${2:+ ($2)}"
}

# Something is mounted on MOUNT: the mount table lists it (which needs no access to the share: a
# privacy-protected mount can refuse even stat), or it is on another device than its parent.
is_mounted() {
  [ -n "$TEST_MODE" ] && return 0
  mount 2>/dev/null | grep -qF " on $MOUNT (" && return 0
  local a b
  a=$(stat -f %d "$MOUNT" 2>/dev/null) || return 1
  b=$(stat -f %d "$MOUNT/.." 2>/dev/null) || return 1
  [ "$a" != "$b" ]
}

# Root only. Mounts the first tag that works; the default tag fails while the guest's automount
# holds it (README: unmount the default shared-folder mount, or share with tag=whoread).
do_mount() {
  is_mounted && return 0
  if [ ! -d "$MOUNT" ]; then
    mkdir -p "$MOUNT" && chown "$VM_USER" "$MOUNT" 2>/dev/null
  fi
  local tag err=""
  for tag in $TAGS; do
    if err=$(mount_virtiofs "$tag" "$MOUNT" 2>&1); then
      log "mounted virtiofs tag $tag at $MOUNT"
      return 0
    fi
    MOUNT_ERROR="$tag: $err"
  done
  return 1
}

# The repository inside the mount: <mount>/whoread for a named share (tart run --dir=whoread:PATH),
# <mount> itself for an unnamed one.
find_share() {
  if [ -f "$MOUNT/whoread/Package.swift" ]; then SHARE="$MOUNT/whoread"
  elif [ -f "$MOUNT/Package.swift" ]; then SHARE="$MOUNT"
  else SHARE=""; return 1
  fi
}

# Writes the heartbeat at most every BEAT_EVERY seconds ("force": now). Fails only when a write
# was due and did not succeed.
beat() {
  local now hb f running=""
  now=$(date +%s)
  if [ "${1:-}" != force ] && [ $((now - LAST_BEAT)) -lt "$BEAT_EVERY" ]; then return 0; fi
  hb="$SHARE/.vm/heartbeat"
  for f in "$SHARE/.vm/running/"*.sh; do
    [ -f "$f" ] && running="$running $(basename "$f" .sh)"
  done
  {
    echo "time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "epoch: $now"
    echo "mode: $BEAT_MODE"
    echo "user: $(id -un)"
    echo "host: $(hostname 2>/dev/null)"
    echo "macos: $(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null))"
    echo "sip: $(csrutil status 2>/dev/null | head -n 1)"
    echo "vm: kern.hv_vmm_present=$(sysctl -n kern.hv_vmm_present 2>/dev/null)"
    echo "share: $SHARE"
    echo "running:${running:- none}"
    echo "runner: $RUNNER_VERSION"
  } > "$hb.tmp.$$" 2>/dev/null && mv -f "$hb.tmp.$$" "$hb" 2>/dev/null || return 1
  LAST_BEAT=$now
}

# Mounted, repository visible and readable, .vm writable. Sets SHARE.
ensure_share() {
  if ! is_mounted; then
    MOUNT_ERROR=""
    if [ "$MODE" = daemon ]; then do_mount
    else sudo -n "$SELF" mount >/dev/null 2>&1
    fi || { set_state mount-failed "${MOUNT_ERROR:-sudo -n $SELF mount failed}"; return 1; }
  fi
  if ! ls "$MOUNT" >/dev/null 2>&1; then set_state share-unreadable "cannot list $MOUNT"; return 1; fi
  if ! find_share; then set_state repo-missing "no Package.swift in $MOUNT/whoread or $MOUNT"; return 1; fi
  if ! head -c 1 "$SHARE/Package.swift" >/dev/null 2>&1; then set_state share-unreadable "cannot read $SHARE/Package.swift"; return 1; fi
  if ! mkdir -p "$SHARE/.vm/jobs" "$SHARE/.vm/running" "$SHARE/.vm/done" "$SHARE/.vm/results" 2>/dev/null || ! beat; then
    set_state share-unwritable "cannot write $SHARE/.vm"; return 1
  fi
  set_state ok "share $SHARE"
}

job_timeout() {
  local t
  t=$(head -n 20 "$1" 2>/dev/null | sed -n 's/^#[[:space:]]*timeout:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' | head -n 1)
  [ -n "$t" ] && [ "$t" -gt 0 ] 2>/dev/null || t=$DEFAULT_TIMEOUT
  echo "$t"
}

descendants() {
  local c
  for c in $(pgrep -P "$1" 2>/dev/null); do echo "$c"; descendants "$c"; done
}

# SIGTERM to the job's process group and every descendant (some put themselves in their own
# group, e.g. the acceptance scripts' probes), SIGKILL to whatever is left after 10 s.
stop_tree() {
  local pg="$1" kids p
  kids=$(descendants "$pg")
  kill -TERM -- "-$pg" 2>/dev/null
  for p in $kids; do kill -TERM "$p" 2>/dev/null; done
  for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 -- "-$pg" 2>/dev/null || break; sleep 1; done
  kill -KILL -- "-$pg" 2>/dev/null
  for p in $kids; do kill -KILL "$p" 2>/dev/null; done
}

# Start time of a process ("" if it is gone or ps cannot tell).
start_of() {
  LC_ALL=C ps -o lstart= -p "$1" 2>/dev/null | tr -s ' ' | sed 's/^ //; s/ $//'
}

# The leader of a job a dead runner left behind, if that very process still runs: same pid AND same
# start time. Pids are reused (after a VM restart at once), also by launchd jobs, which lead their
# own process groups: without the start time, "kill -- -PID" could hit loginwindow or whoreadd.
orphan_leader() {
  local f="$SHARE/.vm/running/$1.pid" pid start now
  [ -f "$f" ] || return 1
  read -r pid start < "$f" || true
  case "$pid" in ''|*[!0-9]*) return 1 ;; esac
  [ -n "$start" ] || return 1
  now=$(start_of "$pid")
  [ -n "$now" ] && [ "$now" = "$start" ] || return 1
  echo "$pid"
}

stop_orphan() {
  local pid
  pid=$(orphan_leader "$1") || return 0
  log "job $1: still running although its runner stopped (pid $pid); stopping it"
  stop_tree "$pid"
}

# Appends the last line to ID.out, then writes ID.status (renamed into place: the host reads a
# complete file or none).
finish() {
  local res="$SHARE/.vm/results/$1"
  printf '%s\n' "$3" >> "$res.out"
  sync
  printf '%s\n' "$2" > "$res.status.tmp" && mv -f "$res.status.tmp" "$res.status"
}

# Runs running/ID.sh as root and records the result.
exec_job() {
  local id="$1" job out timeout start deadline pid rc timed_out="" home=/var/root
  job="$SHARE/.vm/running/$id.sh"
  out="$SHARE/.vm/results/$id.out"
  timeout=$(job_timeout "$job")
  start=$(date +%s)
  deadline=$((start + timeout))
  [ -n "$TEST_MODE" ] && home="$HOME"
  log "job $id: start (timeout ${timeout}s)"
  echo "[vm] job $id: started $(date -u +%Y-%m-%dT%H:%M:%SZ) as $(id -un) on macOS $(sw_vers -productVersion 2>/dev/null), timeout ${timeout}s" > "$out"
  # Job control gives the job its own process group (killed as a whole on timeout) and leaves
  # SIGINT at its default: a plain background job would ignore it, and so would every probe.
  STARTING=1
  set -m
  ( cd "$SHARE" && exec env -i PATH="$PATH" HOME="$home" USER="$(id -un)" LOGNAME="$(id -un)" SHELL=/bin/bash \
      LANG=en_US.UTF-8 WHOREAD_LANG=en ${TMPDIR:+TMPDIR="$TMPDIR"} \
      WHOREAD_VM_SHARE="$SHARE" WHOREAD_VM_JOB="$id" WHOREAD_VM_USER="$VM_USER" WHOREAD_TEST_USER="$VM_USER" \
      /bin/bash "$job" ) >> "$out" 2>&1 < /dev/null &
  pid=$!
  set +m
  CURRENT=$pid
  printf '%s %s\n' "$pid" "$(start_of "$pid")" > "$SHARE/.vm/running/$id.pid"
  STARTING=""
  [ -n "$STOP_PENDING" ] && on_term
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      timed_out=1
      log "job $id: timed out after ${timeout}s"
      stop_tree "$pid"
      break
    fi
    beat
    sleep 1
  done
  wait "$pid"; rc=$?
  CURRENT=""
  rm -f "$SHARE/.vm/running/$id.pid"
  [ -n "$timed_out" ] && rc=124
  finish "$id" "$rc" "[vm] job $id: exit $rc after $(( $(date +%s) - start ))s${timed_out:+ (timed out after ${timeout}s and killed)}"
  log "job $id: exit $rc"
  return "$rc"
}

# A job left in running/ belongs to a runner that died (or a VM that restarted): it is not run
# again, only marked interrupted. If it is still running (a runner killed with SIGKILL leaves the
# job's own process group behind), it is stopped first, so it cannot overlap with the next job.
recover_interrupted() {
  local f id
  for f in "$SHARE/.vm/running/"*.sh; do
    [ -f "$f" ] || continue
    id=$(basename "$f" .sh)
    if [ -f "$SHARE/.vm/running/$id.pid" ]; then
      if [ "$MODE" = agent ] && [ -z "$TEST_MODE" ]; then sudo -n "$SELF" stop-job "$id"
      else stop_orphan "$id"
      fi
      rm -f "$SHARE/.vm/running/$id.pid"
    fi
    [ -e "$SHARE/.vm/results/$id.status" ] \
      || finish "$id" 125 "[vm] job $id: interrupted (the runner or the VM restarted while it ran); not run again"
    mv -f "$f" "$SHARE/.vm/done/$id.sh"
    log "job $id: was running when the runner stopped; marked interrupted"
  done
}

take_job() {
  local f="$1" id
  id=$(basename "$f" .sh)
  case "$id" in
    ''|.*|*[!A-Za-z0-9._-]*) log "ignoring a job with an unexpected name: $id"; mv -f "$f" "$f.rejected" 2>/dev/null; return ;;
  esac
  # The claim: once renamed out of jobs/, no later scan (of this or a restarted runner) starts it.
  mv "$f" "$SHARE/.vm/running/$id.sh" 2>/dev/null || { log "job $id: cannot claim it"; return; }
  if [ -e "$SHARE/.vm/results/$id.status" ]; then
    log "job $id: already has a result; not run again"
  elif [ "$MODE" = agent ] && [ -z "$TEST_MODE" ]; then
    sudo -n "$SELF" exec-job "$id"
  else
    exec_job "$id"
  fi
  [ -e "$SHARE/.vm/results/$id.status" ] \
    || finish "$id" 125 "[vm] job $id: could not be run (agent mode: is sudo set up? see the runner log)"
  mv -f "$SHARE/.vm/running/$id.sh" "$SHARE/.vm/done/$id.sh" 2>/dev/null
}

on_signal() {
  if [ -n "$STARTING" ]; then STOP_PENDING=1; else on_term; fi
}

on_term() {
  [ -n "$CURRENT" ] && stop_tree "$CURRENT"
  log "stopped"
  exit 143
}

main_loop() {
  local recovered="" f
  log "runner $RUNNER_VERSION starting as $(id -un): mount $MOUNT, tags $TAGS"
  set_state starting
  while :; do
    if ! ensure_share; then
      recovered=""
      sleep 10
      continue
    fi
    if [ -z "$recovered" ]; then recover_interrupted; recovered=1; fi
    for f in "$SHARE/.vm/jobs/"*.sh; do
      [ -f "$f" ] || continue
      take_job "$f"
      beat force
    done
    sleep 1
  done
}

need_root() {
  [ -n "$TEST_MODE" ] || [ "$(id -u)" -eq 0 ] || { echo "$MODE: run as root" >&2; exit 77; }
}

# The runner executes whatever appears in a shared folder as root: only ever in the test VM (the
# hypervisor flag, or the model name of an Apple silicon VM, VirtualMac2,1), as install.sh checks.
is_vm() {
  [ "$(sysctl -n kern.hv_vmm_present 2>/dev/null)" = 1 ] && return 0
  case "$(sysctl -n hw.model 2>/dev/null)" in VirtualMac*) return 0 ;; esac
  return 1
}
case "$MODE" in
  daemon|agent|mount|exec-job|stop-job)
    [ -n "$TEST_MODE" ] || is_vm || { echo "$MODE: this Mac is not a virtual machine; the runner only runs in the test VM" >&2; exit 78; } ;;
esac

trap on_signal TERM INT HUP
case "$MODE" in
  daemon)
    need_root
    main_loop ;;
  agent)
    # Installed for all GUI sessions (/Library/LaunchAgents); only the test user's one runs jobs.
    [ "$(id -un)" = "$VM_USER" ] || exit 0
    main_loop ;;
  mount)
    need_root
    MOUNT_ERROR=""
    do_mount || { echo "mount failed: $MOUNT_ERROR" >&2; exit 1; } ;;
  exec-job)
    need_root
    id="${2:-}"
    case "$id" in ''|.*|*[!A-Za-z0-9._-]*) echo "bad job id" >&2; exit 64 ;; esac
    find_share || { echo "no repository under $MOUNT" >&2; exit 1; }
    [ -f "$SHARE/.vm/running/$id.sh" ] || { echo "job $id is not claimed" >&2; exit 1; }
    exec_job "$id" ;;
  stop-job)
    need_root
    id="${2:-}"
    case "$id" in ''|.*|*[!A-Za-z0-9._-]*) echo "bad job id" >&2; exit 64 ;; esac
    find_share || { echo "no repository under $MOUNT" >&2; exit 1; }
    stop_orphan "$id" ;;
  *)
    echo "usage: $0 daemon|agent|mount|exec-job ID|stop-job ID" >&2
    exit 64 ;;
esac
