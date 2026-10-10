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
#   running/ID.dir      while it runs: its private folder (below), for the same restarted runner
#   done/ID.sh          finished, or interrupted by a runner restart (never run again)
#   results/ID.out      stdout + stderr, written while the job runs; the last line starts "[vm] job ID:"
#   results/ID.status   exit code, written after the last line of ID.out (124: timed out,
#                       125: interrupted or could not run)
#   heartbeat           rewritten every few seconds: guest time, macOS version, SIP status, jobs
# A job runs as root, in its own process group, with a timeout: 900 s, or N from a "# timeout: N"
# line among its first 20 lines. On timeout it gets SIGTERM, 10 s later SIGKILL. Timeouts count the
# time the VM runs: when the host sleeps, the VM is paused and its clock jumps ahead on waking, and
# that jump is not the job's time (tick). A job runs from a private copy of its job file, made when
# it starts in a folder only root can read (bash reads a script while it runs it, so a change to the
# file in the share would otherwise reach a running job); the folder is removed when the job ends
# (by the next runner if this one is killed outright). A runner that is stopped (SIGTERM) stops its
# job and records its result before it exits: the job's own exit code if it had already ended,
# else 125.
#
# Settings come from /usr/local/etc/whoread-vmrunner.conf (KEY=VALUE lines, written by install.sh):
#   VM_USER  the VM's test user (default admin)    MOUNT  where the share is mounted (default
#   /Users/admin/wr)    TAGS  virtiofs tags to try, in order    BEAT_EVERY  heartbeat seconds
# WHOREAD_VM_RUNNER_TEST=1 (scripts/vm/selftest.sh on the host): no mounting, no root, no sudo;
# WHOREAD_VM_RUNNER_TEST_PATH is then put in front of PATH (stand-ins for tools a sandbox refuses).
set -uo pipefail
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
# In the heartbeat; vmjob.sh queues jobs only for a runner as new as the job files it writes.
# 2: every job runs from a private copy (exec_job), which job files from vmjob.sh rely on.
RUNNER_VERSION=2
MODE="${1:-}"
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
CONF="${WHOREAD_VM_RUNNER_CONF:-/usr/local/etc/whoread-vmrunner.conf}"
TEST_MODE="${WHOREAD_VM_RUNNER_TEST:-}"
[ -n "$TEST_MODE" ] && [ -n "${WHOREAD_VM_RUNNER_TEST_PATH:-}" ] && PATH="$WHOREAD_VM_RUNNER_TEST_PATH:$PATH"
# Where jobs get their private folders (exec_job).
TMPROOT="${TMPDIR:-/tmp}"
TMPROOT="${TMPROOT%/}"
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
LAST_BEAT=""
# The job this process started and has not recorded yet: pid of its process group leader, id, start
# (CLOCK), timeout, and whether the runner timed it out or stopped it.
JOB_PID=""
JOB_ID=""
JOB_START=0
JOB_TIMEOUT=0
JOB_TIMED_OUT=""
JOB_STOPPED=""
# The private folder that holds the copy the job runs from (mktemp -d; see exec_job).
JOB_DIR=""
# A stop request (SIGTERM...) that arrives while a job is being started, or while its result is
# being recorded, waits until that is done: the job is never left running unseen, and its result
# is never lost.
DEFER=""
STOP_PENDING=""
# The heartbeat names the mode the host sees: a job that agent mode runs as root is still "agent".
case "$MODE" in exec-job|stop-job) BEAT_MODE=agent ;; *) BEAT_MODE="$MODE" ;; esac

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [$MODE] $*"; }

# CLOCK: seconds this runner has been running, for timeouts and the heartbeat interval. It follows
# the wall clock while that moves plausibly, but the guest's clock jumps: the VM is paused while the
# host sleeps and its clock is set ahead on waking (or back, when it was ahead). tick is called about
# once a second; a step backwards or of more than MAX_STEP seconds counts as one second.
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
  local hb f running=""
  tick
  if [ "${1:-}" != force ] && [ -n "$LAST_BEAT" ] && [ $((CLOCK - LAST_BEAT)) -lt "$BEAT_EVERY" ]; then return 0; fi
  hb="$SHARE/.vm/heartbeat"
  for f in "$SHARE/.vm/running/"*.sh; do
    [ -f "$f" ] && running="$running $(basename "$f" .sh)"
  done
  {
    echo "time: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "epoch: $(date +%s)"
    echo "uptime: $CLOCK"
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
  LAST_BEAT=$CLOCK
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
  local pid d=""
  if pid=$(orphan_leader "$1"); then
    log "job $1: still running although its runner stopped (pid $pid); stopping it"
    stop_tree "$pid"
  fi
  # Its private folder, which the dead runner did not remove.
  [ -f "$SHARE/.vm/running/$1.dir" ] && read -r d < "$SHARE/.vm/running/$1.dir"
  if is_job_dir "$d"; then rm -rf -- "$d"; fi
  rm -f "$SHARE/.vm/running/$1.dir"
}

# Appends the last line to ID.out, then writes ID.status (renamed into place: the host reads a
# complete file or none).
finish() {
  local res="$SHARE/.vm/results/$1"
  printf '%s\n' "$3" >> "$res.out"
  sync
  printf '%s\n' "$2" > "$res.status.tmp" && mv -f "$res.status.tmp" "$res.status"
}

# is_job_dir PATH : PATH has the form of a job's private folder (exec_job makes it with mktemp -d).
# running/ID.dir names it for a later runner, and the share is the host's to write: nothing else is
# ever removed through it.
is_job_dir() {
  local s="${1#"$TMPROOT"/whoread-vmjob.}"
  [ "$s" != "$1" ] && [ ${#s} -eq 6 ] && case "$s" in *[!A-Za-z0-9]*) false ;; esac
}

# drop_job_dir : removes the private folder of the job this process started, and its record.
drop_job_dir() {
  if is_job_dir "$JOB_DIR"; then rm -rf -- "$JOB_DIR"; fi
  [ -z "$JOB_ID" ] || rm -f "$SHARE/.vm/running/$JOB_ID.dir"
  JOB_DIR=""
}

# end_job : records the result of the job this process started, which has ended or was stopped,
# and forgets the job. Returns the recorded exit code.
end_job() {
  local rc
  # wait returns early when a trapped signal arrives; the job is reaped only when it really returned.
  while :; do
    wait "$JOB_PID"; rc=$?
    kill -0 "$JOB_PID" 2>/dev/null || break
  done
  rm -f "$SHARE/.vm/running/$JOB_ID.pid"
  drop_job_dir
  tick
  if [ -n "$JOB_TIMED_OUT" ]; then
    rc=124
    finish "$JOB_ID" "$rc" "[vm] job $JOB_ID: exit $rc after $((CLOCK - JOB_START))s (timed out after ${JOB_TIMEOUT}s and killed)"
  elif [ -n "$JOB_STOPPED" ]; then
    rc=125
    finish "$JOB_ID" "$rc" "[vm] job $JOB_ID: interrupted after $((CLOCK - JOB_START))s (the runner was stopped while it ran); not run again"
  else
    finish "$JOB_ID" "$rc" "[vm] job $JOB_ID: exit $rc after $((CLOCK - JOB_START))s"
  fi
  log "job $JOB_ID: exit $rc"
  JOB_PID=""
  return "$rc"
}

# Runs a private copy of running/ID.sh as root and records the result.
exec_job() {
  local id="$1" job out copy timeout pid rc home=/var/root
  job="$SHARE/.vm/running/$id.sh"
  out="$SHARE/.vm/results/$id.out"
  tick
  [ -n "$TEST_MODE" ] && home="$HOME"
  DEFER=1
  JOB_ID=$id
  # The copy the job runs from: in a new folder only this user (root) can read, and read once from
  # the share. The timeout comes from the same copy. running/ID.dir names the folder, so that the
  # next runner removes it if this one is killed outright.
  JOB_DIR=$(mktemp -d "$TMPROOT/whoread-vmjob.XXXXXX") || JOB_DIR=""
  [ -z "$JOB_DIR" ] || printf '%s\n' "$JOB_DIR" > "$SHARE/.vm/running/$id.dir"
  copy="$JOB_DIR/$id.sh"
  if [ -z "$JOB_DIR" ] || ! cp "$job" "$copy" 2>/dev/null; then
    drop_job_dir
    log "job $id: cannot copy it to a private folder"
    finish "$id" 125 "[vm] job $id: could not be run: no private copy of $job could be made"
    DEFER=""
    [ -n "$STOP_PENDING" ] && on_term
    return 125
  fi
  timeout=$(job_timeout "$copy")
  log "job $id: start (timeout ${timeout}s)"
  echo "[vm] job $id: started $(date -u +%Y-%m-%dT%H:%M:%SZ) as $(id -un) on macOS $(sw_vers -productVersion 2>/dev/null), timeout ${timeout}s" > "$out"
  # Job control gives the job its own process group (killed as a whole on timeout) and leaves
  # SIGINT at its default: a plain background job would ignore it, and so would every probe.
  set -m
  ( cd "$SHARE" && exec env -i PATH="$PATH" HOME="$home" USER="$(id -un)" LOGNAME="$(id -un)" SHELL=/bin/bash \
      LANG=en_US.UTF-8 WHOREAD_LANG=en ${TMPDIR:+TMPDIR="$TMPDIR"} \
      WHOREAD_VM_SHARE="$SHARE" WHOREAD_VM_JOB="$id" WHOREAD_VM_USER="$VM_USER" WHOREAD_TEST_USER="$VM_USER" \
      /bin/bash "$copy" ) >> "$out" 2>&1 < /dev/null &
  pid=$!
  set +m
  JOB_PID=$pid JOB_ID=$id JOB_START=$CLOCK JOB_TIMEOUT=$timeout JOB_TIMED_OUT="" JOB_STOPPED=""
  printf '%s %s\n' "$pid" "$(start_of "$pid")" > "$SHARE/.vm/running/$id.pid"
  DEFER=""
  [ -n "$STOP_PENDING" ] && on_term
  while kill -0 "$pid" 2>/dev/null; do
    tick
    if [ $((CLOCK - JOB_START)) -ge "$timeout" ]; then
      JOB_TIMED_OUT=1
      log "job $id: timed out after ${timeout}s"
      stop_tree "$pid"
      break
    fi
    beat
    sleep 1
  done
  DEFER=1
  end_job; rc=$?
  DEFER=""
  [ -n "$STOP_PENDING" ] && on_term
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
    if [ -f "$SHARE/.vm/running/$id.pid" ] || [ -f "$SHARE/.vm/running/$id.dir" ]; then
      if [ "$MODE" = agent ] && [ -z "$TEST_MODE" ]; then sudo -n "$SELF" stop-job "$id"
      else stop_orphan "$id"
      fi
      rm -f "$SHARE/.vm/running/$id.pid" "$SHARE/.vm/running/$id.dir"
    fi
    if [ -e "$SHARE/.vm/results/$id.status" ]; then
      log "job $id: its result was recorded when the runner stopped"
    else
      finish "$id" 125 "[vm] job $id: interrupted (the runner or the VM restarted while it ran); not run again"
      log "job $id: was running when the runner stopped; marked interrupted"
    fi
    mv -f "$f" "$SHARE/.vm/done/$id.sh"
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
  if [ -n "$DEFER" ]; then STOP_PENDING=1; else on_term; fi
}

# Stops the job this process runs, if any, and records its result before exiting: the job may have
# ended just before (the loop in exec_job sees that up to a second later), then its own exit code
# counts; else it is stopped and recorded as interrupted (125).
on_term() {
  DEFER=1
  if [ -n "$JOB_PID" ]; then
    # Also when a timeout was stopping it: this signal cut that short.
    if kill -0 "$JOB_PID" 2>/dev/null; then
      [ -n "$JOB_TIMED_OUT" ] || JOB_STOPPED=1
      log "job $JOB_ID: stopping it, the runner is being stopped"
      stop_tree "$JOB_PID"
    fi
    end_job
    mv -f "$SHARE/.vm/running/$JOB_ID.sh" "$SHARE/.vm/done/$JOB_ID.sh" 2>/dev/null
  fi
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
