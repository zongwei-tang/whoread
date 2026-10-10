#!/bin/bash
# Self-test of the VM job harness on any Mac, without a VM, root or network: runs
# scripts/vm/runner/runner.sh in test mode (no mounting, no sudo) against a temporary "share" and
# drives it with scripts/vm/vmjob.sh; checks scripts/vm/tcc-fda.sh against the TCC schemas of
# several macOS releases; and checks that every script the VM runs parses.
# Usage: scripts/vm/selftest.sh        (about a minute; leaves its files in a mktemp directory)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d "${TMPDIR:-/tmp}/whoread-vm-selftest.XXXXXX")" || exit 1
T="$(cd "$T" && pwd -P)"
SHARE="$T/share/whoread"          # the shared directory; the "VM" mounts $T/share
mkdir -p "$SHARE/wt/scripts"
: > "$SHARE/Package.swift"
printf 'VM_USER=%s\nMOUNT=%s\nBEAT_EVERY=1\n' "$(id -un)" "$T/share" > "$T/runner.conf"
PASS=0; FAIL=0
ok()  { echo "PASS  $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $*"; FAIL=$((FAIL+1)); }

RUNNER_PID=""
start_runner() { # MODE
  rm -f "$T/state"
  WHOREAD_VM_RUNNER_TEST=1 WHOREAD_VM_RUNNER_CONF="$T/runner.conf" WHOREAD_VM_RUNNER_STATE="$T/state" \
    bash "$ROOT/scripts/vm/runner/runner.sh" "$1" >> "$T/runner.log" 2>&1 &
  RUNNER_PID=$!
  for _ in $(seq 50); do [ "$(cat "$T/state" 2>/dev/null)" = ok ] && return 0; sleep 0.2; done
  return 1
}
stop_runner() {
  [ -n "$RUNNER_PID" ] || return 0
  kill -TERM "$RUNNER_PID" 2>/dev/null
  wait "$RUNNER_PID" 2>/dev/null
  RUNNER_PID=""
}
trap stop_runner EXIT
VMJOB() { WHOREAD_VM_HOST_DIR="$SHARE" bash "$ROOT/scripts/vm/vmjob.sh" "$@"; }
last_id() { (cd "$SHARE/.vm/results" && ls -t ./*.status 2>/dev/null | head -n 1 | sed 's|^\./||; s|\.status$||'); }
started_count() { grep -c '^\[vm\] job .*: started' "$SHARE/.vm/results/$1.out" 2>/dev/null; }

echo "== syntax"
for f in "$ROOT"/scripts/vm/*.sh "$ROOT"/scripts/vm/runner/*.sh "$ROOT/scripts/install-dev-daemon.sh" \
         "$ROOT/scripts/uninstall-dev-daemon.sh" "$ROOT/scripts/acceptance-m2.sh" "$ROOT/scripts/create-test-vault.sh"; do
  bash -n "$f" && ok "bash -n ${f#"$ROOT"/}" || bad "bash -n ${f#"$ROOT"/}"
done

echo "== runner (daemon mode, test)"
start_runner daemon && ok "runner up, state ok" || { bad "runner did not reach state ok"; cat "$T/runner.log"; exit 1; }
out=$(VMJOB ping) && ok "ping" || bad "ping failed: $out"
grep -q '^mode: daemon' "$SHARE/.vm/heartbeat" && ok "heartbeat names the mode" || bad "heartbeat: $(cat "$SHARE/.vm/heartbeat")"

cat > "$T/outside.sh" <<'SH'
#!/bin/bash
echo "hello from job"
echo "share=$WHOREAD_VM_SHARE repo=$WHOREAD_VM_REPO"
echo "pwd=$(pwd -P)"
echo "args=$#|$1|$2"
echo "testuser=$WHOREAD_TEST_USER"
echo "zero=$0"
exit 3
SH
out=$(VMJOB run copy "$T/outside.sh" -- "a b" "c'd" 2>"$T/err"); rc=$?
[ $rc -eq 3 ] && ok "copied script: exit code passed through" || bad "copied script: rc $rc ($(cat "$T/err"))"
grep -q '^hello from job$' <<< "$out" && ok "copied script: output streamed" || bad "copied script output: $out"
grep -q "^args=2|a b|c'd$" <<< "$out" && ok "copied script: arguments kept" || bad "copied script args: $out"
grep -q "^pwd=$SHARE$" <<< "$out" && ok "copied script: starts in the share" || bad "copied script pwd: $out"
zero=$(sed -n 's/^zero=//p' <<< "$out")
case "$zero" in
  */script/outside.sh) [ ! -e "$zero" ] && [ "${zero#"$SHARE"/}" = "$zero" ] \
    && ok "copied script: runs from a private copy outside the share, removed after the job" \
    || bad "copied script: private copy $zero left behind or in the share" ;;
  *) bad "copied script: \$0 is $zero, not its private copy" ;;
esac
grep -q "^testuser=$(id -un)$" <<< "$out" && ok "WHOREAD_TEST_USER set" || bad "test user: $out"
grep -q '^\[vm\] job .*: exit 3 after' <<< "$out" && ok "final [vm] line" || bad "no final line: $out"
COPY_ID=$(last_id)

# In place: a script under the share runs from there (a nested checkout stands in for a worktree).
git init -q "$SHARE" 2>/dev/null; git init -q "$SHARE/wt" 2>/dev/null
cat > "$SHARE/wt/scripts/inside.sh" <<'SH'
#!/bin/bash
# timeout: 50
echo "zero=$0"
echo "repo=$WHOREAD_VM_REPO pwd=$(pwd -P)"
echo "dir=$(cd "$(dirname "$0")/.." && pwd -P)"
echo "arg=$1"
SH
out=$(VMJOB run inside "$SHARE/wt/scripts/inside.sh" -- "x y" 2>"$T/err"); rc=$?
[ $rc -eq 0 ] && ok "in-place script: exit 0" || bad "in-place script rc $rc: $(cat "$T/err")"
grep -q "^zero=$SHARE/wt/scripts/inside.sh$" <<< "$out" && ok "in-place script: \$0 is its path in the share" || bad "in-place \$0: $out"
grep -q "^repo=$SHARE/wt pwd=$SHARE/wt$" <<< "$out" && ok "in-place script: WHOREAD_VM_REPO and cwd are its checkout" || bad "in-place repo: $out"
grep -q "^arg=x y$" <<< "$out" && ok "in-place script: argument kept" || bad "in-place arg: $out"
grep -q "timeout 50s" <<< "$out" && ok "timeout header honoured" || bad "timeout header: $out"

echo "== timeouts"
printf '#!/bin/bash\n# timeout: 2\necho going to sleep\nsleep 60\necho not reached\n' > "$T/slow.sh"
s=$(date +%s); out=$(VMJOB run slow "$T/slow.sh" 2>"$T/err"); rc=$?; e=$(date +%s)
[ $rc -eq 124 ] && ok "header timeout: exit 124 after $((e - s)) s" || bad "header timeout: rc $rc after $((e - s)) s: $out"
[ $((e - s)) -lt 20 ] && ok "killed promptly" || bad "took $((e - s)) s"
grep -q 'not reached' <<< "$out" && bad "the job went on after the timeout" || ok "job stopped at the timeout"
printf '#!/bin/bash\nsleep 60\n' > "$T/slow2.sh"
out=$(VMJOB run slow2 "$T/slow2.sh" --timeout 2 2>"$T/err"); rc=$?
[ $rc -eq 124 ] && ok "--timeout overrides the default" || bad "--timeout: rc $rc"

echo "== shell"
out=$(VMJOB shell 'echo shell-ok; exit 7' 2>"$T/err"); rc=$?
[ $rc -eq 7 ] && grep -q '^shell-ok$' <<< "$out" && ok "shell one-liner" || bad "shell: rc $rc: $out"

echo "== jobs queued behind another job"
# vmjob gives a job its timeout + grace from its start, not from when it was queued; a job still
# queued after that is withdrawn (exit 70) and never runs. The second job waits about 12 s for the
# first and then runs about 12 s: within its 20 s from its start, not from when it was queued.
printf '#!/bin/bash\necho first\nsleep 12\n' > "$T/first.sh"
VMJOB run first "$T/first.sh" > "$T/first.out" 2>&1 &
FIRST=$!
for _ in $(seq 50); do grep -qx 'first' "$SHARE/.vm/results/"*-first-*.out 2>/dev/null && break; sleep 0.2; done
printf '#!/bin/bash\n# timeout: 20\nsleep 12\necho second ran\nexit 4\n' > "$T/second.sh"
printf '#!/bin/bash\ntouch "%s/third-ran"\n' "$T" > "$T/third.sh"
WHOREAD_VMJOB_GRACE=0 VMJOB run third "$T/third.sh" --timeout 1 > "$T/third.out" 2>&1 &
THIRD=$!
s=$(date +%s); out=$(WHOREAD_VMJOB_GRACE=0 VMJOB run second "$T/second.sh" 2>"$T/err"); rc=$?; e=$(date +%s)
[ $rc -eq 4 ] && grep -q '^second ran$' <<< "$out" \
  && ok "a job queued behind another gets its whole time from its start ($((e - s)) s in all, limit 20 s)" \
  || bad "queued job: rc $rc after $((e - s)) s: $out $(cat "$T/err")"
wait $THIRD; rc=$?
[ $rc -eq 70 ] && grep -q 'still queued' "$T/third.out" && ok "a job still queued after its limit is withdrawn (exit 70)" \
  || bad "queued past its limit: rc $rc: $(cat "$T/third.out")"
wait $FIRST
sleep 2
[ ! -e "$T/third-ran" ] && ok "the withdrawn job never ran" || bad "the withdrawn job ran"
s=$(date +%s); out=$(VMJOB result 20000101-000000-nosuch-1 --wait 2>&1); rc=$?; e=$(date +%s)
[ $rc -eq 70 ] && [ $((e - s)) -lt 5 ] && grep -q 'no job' <<< "$out" && ok "result --wait of an unknown job: 70 at once" \
  || bad "result --wait of an unknown job: rc $rc after $((e - s)) s: $out"

echo "== a job never runs twice"
cp "$SHARE/.vm/done/$COPY_ID.sh" "$SHARE/.vm/jobs/$COPY_ID.sh"
for _ in $(seq 30); do [ -f "$SHARE/.vm/jobs/$COPY_ID.sh" ] || break; sleep 0.2; done
sleep 1
[ ! -f "$SHARE/.vm/jobs/$COPY_ID.sh" ] && ok "requeued finished job taken out of the queue" || bad "requeued job still queued"
[ "$(started_count "$COPY_ID")" = 1 ] && ok "requeued finished job not run again" || bad "requeued job ran again"
out=$(VMJOB result "$COPY_ID"); rc=$?
[ $rc -eq 3 ] && grep -q '^hello from job$' <<< "$out" && ok "result ID: output and exit code" || bad "result: rc $rc"

echo "== bad job names are ignored"
printf '#!/bin/bash\ntouch "%s/ran"\n' "$T" > "$SHARE/.vm/jobs/bad name.sh"
sleep 3
[ ! -e "$T/ran" ] && [ -f "$SHARE/.vm/jobs/bad name.sh.rejected" ] && ok "bad name rejected, not run" || bad "bad name handling"

# wait_for FILE_GLOB LINE : until a file matching the glob holds LINE (10 s at most).
wait_for() {
  for _ in $(seq 50); do
    # shellcheck disable=SC2086  # the glob is meant to expand
    grep -qx "$2" $1 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}
# with_runner PATH_DIR : restarts the runner with stand-ins from PATH_DIR in front of its PATH.
with_runner() {
  stop_runner
  WHOREAD_VM_RUNNER_TEST_PATH="$1" start_runner daemon
}

echo "== clock jumps (host sleep) do not use up a job's time"
# A stand-in date adds the offset in $T/clock-offset to the epoch seconds; everything else is the
# real date. After the host slept, the VM's clock jumps ahead by the time it was paused.
mkdir -p "$T/clockbin"
cat > "$T/clockbin/date" <<SH
#!/bin/bash
off=\$(cat "$T/clock-offset" 2>/dev/null); off=\${off:-0}
if [ "\$#" -eq 1 ] && [ "\$1" = +%s ]; then echo \$(( \$(/bin/date +%s) + off )); else exec /bin/date "\$@"; fi
SH
chmod +x "$T/clockbin/date"
echo 0 > "$T/clock-offset"
with_runner "$T/clockbin" || bad "runner did not start with the date stand-in"
printf '#!/bin/bash\n# timeout: 30\necho begin\n/bin/sleep 4\necho done\n' > "$T/jump.sh"
VMJOB run jump "$T/jump.sh" > "$T/jump.out" 2>&1 &
WAITER=$!
wait_for "$SHARE/.vm/results/*-jump-*.out" begin || bad "jump job did not start"
echo 100000 > "$T/clock-offset"
wait $WAITER; rc=$?
[ $rc -eq 0 ] && grep -qx done "$T/jump.out" \
  && ok "a forward jump of the VM's clock does not time a running job out" || bad "forward clock jump: rc $rc: $(cat "$T/jump.out")"
# Backwards (the clock was ahead and is set right): the heartbeat must go on.
echo -100000 > "$T/clock-offset"
sleep 2
out=$(VMJOB ping 2>&1); rc=$?
[ $rc -eq 0 ] && ok "a backward jump of the VM's clock does not stop the heartbeat" || bad "backward clock jump: ping rc $rc: $out"
echo 0 > "$T/clock-offset"
with_runner "" || bad "runner did not restart"
# vmjob on the host: its clock jumps as well when the Mac wakes up; the job is still running.
printf '#!/bin/bash\n# timeout: 4\necho begin\n/bin/sleep 3\necho done\n' > "$T/hjump.sh"
PATH="$T/clockbin:$PATH" WHOREAD_VMJOB_GRACE=30 VMJOB run hjump "$T/hjump.sh" > "$T/hjump.out" 2>&1 &
WAITER=$!
wait_for "$SHARE/.vm/results/*-hjump-*.out" begin || bad "hjump job did not start"
echo 100000 > "$T/clock-offset"
wait $WAITER; rc=$?
echo 0 > "$T/clock-offset"
[ $rc -eq 0 ] && grep -qx done "$T/hjump.out" \
  && ok "a jump of the host's clock does not make vmjob give up on a running job" || bad "host clock jump: rc $rc: $(cat "$T/hjump.out")"

echo "== a runner stopped right after its job ended records the job's exit code"
# A stand-in sleep makes the runner's one-second waits last 3 s while $T/slow-sleep exists, so the
# job ends, and the stop request arrives, while the runner has not looked yet.
mkdir -p "$T/sleepbin"
printf '#!/bin/bash\nif [ -e "%s/slow-sleep" ] && [ "$1" = 1 ]; then exec /bin/sleep 3; fi\nexec /bin/sleep "$@"\n' "$T" > "$T/sleepbin/sleep"
chmod +x "$T/sleepbin/sleep"
rm -f "$T/slow-sleep" "$T/release"
with_runner "$T/sleepbin" || bad "runner did not start with the sleep stand-in"
printf '#!/bin/bash\necho waiting\nwhile [ ! -e "%s/release" ]; do /bin/sleep 0.1; done\nexit 5\n' "$T" > "$T/ends.sh"
VMJOB run ends "$T/ends.sh" > "$T/ends.out" 2>&1 &
WAITER=$!
wait_for "$SHARE/.vm/results/*-ends-*.out" waiting || bad "ends job did not start"
ENDS_ID=$(basename "$(ls "$SHARE/.vm/running/"*-ends-*.sh 2>/dev/null | head -n 1)" .sh)
: > "$T/slow-sleep"
/bin/sleep 2.5
: > "$T/release"
/bin/sleep 0.3
stop_runner
rm -f "$T/slow-sleep"
[ "$(cat "$SHARE/.vm/results/$ENDS_ID.status" 2>/dev/null)" = 5 ] \
  && ok "the stopped runner recorded the job's own exit code (5)" \
  || bad "status after the runner stopped: '$(cat "$SHARE/.vm/results/$ENDS_ID.status" 2>/dev/null)': $(tail -n 3 "$T/runner.log")"
tail -n 1 "$SHARE/.vm/results/$ENDS_ID.out" 2>/dev/null | grep -q "^\[vm\] job $ENDS_ID: exit 5 after" \
  && ok "its last line says exit 5" || bad "last line: $(tail -n 1 "$SHARE/.vm/results/$ENDS_ID.out" 2>/dev/null)"
start_runner daemon >/dev/null || bad "runner did not restart"
wait $WAITER; rc=$?
[ $rc -eq 5 ] && ok "vmjob reports exit 5" || bad "vmjob after the runner stopped: rc $rc: $(cat "$T/ends.out")"
[ "$(cat "$SHARE/.vm/results/$ENDS_ID.status" 2>/dev/null)" = 5 ] && [ -f "$SHARE/.vm/done/$ENDS_ID.sh" ] \
  && ok "the next runner keeps that result" || bad "result changed by the next runner"

echo "== a running job is not changed by edits in the share"
# The job file, as the runner sees it in the share.
printf '#!/bin/bash\necho first\n/bin/sleep 2\necho second\n' > "$SHARE/.vm/jobs/edited-job.sh"
wait_for "$SHARE/.vm/results/edited-job.out" first || bad "edited-job did not start"
echo 'echo appended to the job file' >> "$SHARE/.vm/running/edited-job.sh"
for _ in $(seq 50); do [ -f "$SHARE/.vm/results/edited-job.status" ] && break; sleep 0.2; done
grep -qx second "$SHARE/.vm/results/edited-job.out" && ! grep -q appended "$SHARE/.vm/results/edited-job.out" \
  && ok "the runner runs a private copy of a job file, made when the job starts" || bad "edited job file: $(cat "$SHARE/.vm/results/edited-job.out")"
# A script that runs from the share (its checkout), edited by the host while it runs.
printf '#!/bin/bash\necho "zero=$0 line=$LINENO source=${BASH_SOURCE[0]}"\necho first\n/bin/sleep 2\necho second\n' > "$SHARE/wt/scripts/edited.sh"
VMJOB run edited "$SHARE/wt/scripts/edited.sh" > "$T/edited.out" 2>&1 &
WAITER=$!
wait_for "$SHARE/.vm/results/*-edited-*.out" first || bad "edited script did not start"
echo 'echo appended to the script' >> "$SHARE/wt/scripts/edited.sh"
wait $WAITER; rc=$?
[ $rc -eq 0 ] && grep -qx second "$T/edited.out" && ! grep -q appended "$T/edited.out" \
  && ok "an in-place script edited while it runs: the job goes on with its copy" || bad "edited in-place script: rc $rc: $(cat "$T/edited.out")"
grep -q "^zero=$SHARE/wt/scripts/edited.sh line=2 source=" "$T/edited.out" \
  && ok "in-place script: \$0 is its path in the share, line numbers are the script's" || bad "in-place \$0/LINENO: $(cat "$T/edited.out")"
src=$(sed -n 's/^zero=.* line=[0-9]* source=//p' "$T/edited.out")
case "$src" in
  */script/edited.sh) [ ! -e "$src" ] && [ "${src#"$SHARE"/}" = "$src" ] \
    && ok "in-place script: runs from a private copy outside the share, removed after the job" \
    || bad "in-place script: private copy $src left behind or in the share" ;;
  *) bad "in-place script: BASH_SOURCE is $src, not its private copy" ;;
esac

echo "== a job runs its script as it was when it was queued"
# The runner is busy with another job while the queued script is edited (git checkout, an editor).
rm -f "$T/unblock"
printf '#!/bin/bash\necho blocking\nwhile [ ! -e "%s/unblock" ]; do /bin/sleep 0.1; done\n' "$T" > "$T/blocker.sh"
VMJOB run blocker "$T/blocker.sh" > "$T/blocker.out" 2>&1 &
BLOCKER=$!
wait_for "$SHARE/.vm/results/*-blocker-*.out" blocking || bad "blocker job did not start"
printf '#!/bin/bash\necho queued text\n' > "$SHARE/wt/scripts/later.sh"
VMJOB run later "$SHARE/wt/scripts/later.sh" > "$T/later.out" 2>&1 &
WAITER=$!
for _ in $(seq 50); do ls "$SHARE/.vm/jobs/"*-later-*.sh >/dev/null 2>&1 && break; sleep 0.2; done
printf '#!/bin/bash\necho edited text\n' > "$SHARE/wt/scripts/later.sh"
: > "$T/unblock"
wait $BLOCKER
wait $WAITER; rc=$?
[ $rc -eq 0 ] && grep -qx 'queued text' "$T/later.out" && ! grep -q 'edited text' "$T/later.out" \
  && ok "an in-place script edited while its job waits: the queued text runs" || bad "script edited while queued: rc $rc: $(cat "$T/later.out")"
# The copy ends where the script ends, also without a final newline, and only there.
printf '#!/bin/bash\necho one\necho "last line"' > "$SHARE/wt/scripts/nonl.sh"
out=$(VMJOB run nonl "$SHARE/wt/scripts/nonl.sh" 2>&1); rc=$?
[ $rc -eq 0 ] && grep -qx 'last line' <<< "$out" && ok "a script without a final newline runs to its last line" || bad "script without a final newline: rc $rc: $out"
printf '#!/bin/bash\necho before\nWHOREAD_VM_END_OF_SCRIPT\necho after\n' > "$T/marker.sh"
out=$(VMJOB run marker "$T/marker.sh" 2>&1); rc=$?
[ $rc -eq 64 ] && ! ls "$SHARE/.vm/jobs/"*-marker-* >/dev/null 2>&1 && ! ls "$SHARE/.vm/results/"*-marker-* >/dev/null 2>&1 \
  && ok "a script holding the line that ends a job's copy is refused (64), nothing queued" || bad "script with the end marker: rc $rc: $out"

echo "== scripts for another interpreter, or with interpreter options, are refused"
printf '#!/usr/bin/perl\nprint "perl ran\\n";\n' > "$T/perl.sh"
out=$(VMJOB run perl "$T/perl.sh" 2>&1); rc=$?
[ $rc -eq 64 ] && ! ls "$SHARE/.vm/jobs/"*-perl-* >/dev/null 2>&1 && ! ls "$SHARE/.vm/results/"*-perl-* >/dev/null 2>&1 \
  && ok "a #!/usr/bin/perl script is refused (64), nothing queued" || bad "perl script: rc $rc: $out"
# A script in the share runs as `. COPY`: -e from the #! line would silently not apply.
printf '#!/bin/bash -e\nfalse\necho went on\n' > "$T/opts.sh"
out=$(VMJOB run opts "$T/opts.sh" 2>&1); rc=$?
[ $rc -eq 64 ] && ! ls "$SHARE/.vm/jobs/"*-opts-* >/dev/null 2>&1 && ! ls "$SHARE/.vm/results/"*-opts-* >/dev/null 2>&1 \
  && ok "a #!/bin/bash -e script is refused (64), nothing queued" || bad "script with interpreter options: rc $rc: $out"
printf '#!/bin/sh\necho sh-ok\n' > "$T/sh.sh"
out=$(VMJOB run sh "$T/sh.sh" 2>&1); rc=$?
[ $rc -eq 0 ] && grep -qx sh-ok <<< "$out" && ok "a #!/bin/sh script runs" || bad "sh script: rc $rc: $out"
printf '#!/usr/bin/env bash \necho env-ok\n' > "$T/env.sh"
out=$(VMJOB run env "$T/env.sh" 2>&1); rc=$?
[ $rc -eq 0 ] && grep -qx env-ok <<< "$out" && ok "a #!/usr/bin/env bash script runs" || bad "env bash script: rc $rc: $out"

echo "== runner restart while a job runs"
printf '#!/bin/bash\necho long job\nsleep 60\n' > "$T/long.sh"
VMJOB run long "$T/long.sh" > "$T/long.out" 2>&1 &
WAITER=$!
# Started, not only claimed: a job stopped between its claim and its start never runs at all.
for _ in $(seq 50); do grep -qx 'long job' "$SHARE/.vm/results/"*-long-*.out 2>/dev/null && break; sleep 0.2; done
LONG_ID=$(basename "$(ls "$SHARE/.vm/running/"*-long-*.sh 2>/dev/null | head -n 1)" .sh)
[ -n "$LONG_ID" ] && ok "long job running" || bad "long job did not start"
stop_runner
start_runner daemon && ok "runner restarted" || bad "runner did not restart"
wait $WAITER; rc=$?
[ $rc -eq 125 ] && ok "interrupted job reported (exit 125)" || bad "interrupted job: rc $rc: $(cat "$T/long.out")"
[ "$(started_count "$LONG_ID")" = 1 ] && ok "interrupted job not run again" || bad "interrupted job ran again"
[ -f "$SHARE/.vm/done/$LONG_ID.sh" ] && ok "interrupted job moved to done/" || bad "interrupted job not in done/"

echo "== runner killed outright while a job runs"
# SIGKILL leaves the job's own process group running; the next runner must stop it, so it cannot
# overlap with the next job, and must leave alone an unrelated process that got a recorded pid.
if ! ps -o lstart= -p $$ >/dev/null 2>&1; then
  # A sandbox may refuse ps; then a stand-in reports a fixed start time per live pid.
  echo "(ps is not permitted here: a stand-in reports process start times)"
  mkdir -p "$T/fakebin"
  cat > "$T/fakebin/ps" <<'SH'
#!/bin/bash
pid=""; while [ $# -gt 0 ]; do [ "$1" = -p ] && pid="$2"; shift; done
[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || exit 1
echo "Thu Jan  1 00:00:00 2026 pid$pid"
SH
  chmod +x "$T/fakebin/ps"
  export WHOREAD_VM_RUNNER_TEST_PATH="$T/fakebin"
  stop_runner
  start_runner daemon >/dev/null || bad "runner did not restart with the ps stand-in"
fi
printf '#!/bin/bash\necho orphan job\nsleep 60\necho not reached\n' > "$T/orphan.sh"
VMJOB run orphan "$T/orphan.sh" > "$T/orphan.out" 2>&1 &
WAITER=$!
for _ in $(seq 50); do
  grep -qx 'orphan job' "$SHARE/.vm/results/"*-orphan-*.out 2>/dev/null && ls "$SHARE/.vm/running/"*-orphan-*.pid >/dev/null 2>&1 && break
  sleep 0.2
done
ORPHAN_ID=$(basename "$(ls "$SHARE/.vm/running/"*-orphan-*.sh 2>/dev/null | head -n 1)" .sh)
JOBPID=""
[ -n "$ORPHAN_ID" ] && read -r JOBPID _ < "$SHARE/.vm/running/$ORPHAN_ID.pid"
[ -n "$JOBPID" ] && ok "running job recorded its pid and start time" || bad "no pid file for the running job"
ORPHAN_DIR=""
[ -n "$ORPHAN_ID" ] && read -r ORPHAN_DIR < "$SHARE/.vm/running/$ORPHAN_ID.dir"
[ -n "$ORPHAN_DIR" ] && [ -f "$ORPHAN_DIR/$ORPHAN_ID.sh" ] && ok "running job recorded its private folder" \
  || bad "no private folder recorded for the running job: '$ORPHAN_DIR'"
kill -KILL "$RUNNER_PID"; wait "$RUNNER_PID" 2>/dev/null; RUNNER_PID=""
sleep 1
[ -n "$JOBPID" ] && kill -0 "$JOBPID" 2>/dev/null && ok "the job outlives its runner's SIGKILL (own process group)" || bad "job $JOBPID not running after the runner's SIGKILL"
# A decoy: a process group leader whose pid is recorded for another job, with another start time.
set -m; sleep 60 & DECOY=$!; set +m
cp "$T/orphan.sh" "$SHARE/.vm/running/decoy-job.sh"
echo "$DECOY Mon Jan  1 00:00:00 2001" > "$SHARE/.vm/running/decoy-job.pid"
# ... and a recorded private folder that is not one: never removed.
mkdir -p "$T/keep-me"
echo "$T/keep-me" > "$SHARE/.vm/running/decoy-job.dir"
start_runner daemon && ok "runner restarted after SIGKILL" || bad "runner did not restart after SIGKILL"
for _ in $(seq 50); do kill -0 "$JOBPID" 2>/dev/null || break; sleep 0.2; done
[ -n "$JOBPID" ] && ! kill -0 "$JOBPID" 2>/dev/null && ok "the restarted runner stopped the orphaned job" || bad "orphaned job $JOBPID still running"
kill -0 "$DECOY" 2>/dev/null && ok "an unrelated process holding a recorded pid is left alone" || bad "the decoy $DECOY was killed"
{ kill "$DECOY"; wait "$DECOY"; } 2>/dev/null
wait $WAITER; rc=$?
[ $rc -eq 125 ] && ok "orphaned job reported interrupted (exit 125)" || bad "orphaned job: rc $rc: $(cat "$T/orphan.out")"
# The runner recovers leftover jobs one after the other: the decoy may be marked a moment after the orphan.
for _ in $(seq 150); do [ -f "$SHARE/.vm/results/decoy-job.status" ] && break; sleep 0.2; done
[ "$(cat "$SHARE/.vm/results/decoy-job.status" 2>/dev/null)" = 125 ] && ok "decoy job marked interrupted" || bad "decoy job status"
[ -n "$ORPHAN_DIR" ] && [ ! -e "$ORPHAN_DIR" ] && ok "the restarted runner removed the orphaned job's private folder" \
  || bad "the orphaned job's private folder is left: $ORPHAN_DIR"
[ -d "$T/keep-me" ] && [ ! -e "$SHARE/.vm/running/decoy-job.dir" ] && ok "a recorded folder of another form is left alone" \
  || bad "the folder recorded for the decoy was removed, or its record kept"
sleep 1
grep -q 'not reached' "$SHARE/.vm/results/$ORPHAN_ID.out" && bad "the orphaned job went on" || ok "the orphaned job did not go on"
[ ! -e "$SHARE/.vm/running/$ORPHAN_ID.pid" ] && [ -f "$SHARE/.vm/done/$ORPHAN_ID.sh" ] && ok "orphaned job cleaned up into done/" || bad "orphan leftovers in running/"

echo "== agent mode (test: no sudo)"
stop_runner
start_runner agent && ok "agent runner up" || bad "agent runner did not start"
out=$(VMJOB shell 'echo agent-ok' 2>"$T/err"); rc=$?
[ $rc -eq 0 ] && grep -q '^agent-ok$' <<< "$out" && ok "job through the agent runner" || bad "agent job: rc $rc: $out"
grep -q '^mode: agent' "$SHARE/.vm/heartbeat" && ok "heartbeat says agent" || bad "agent heartbeat"

echo "== ping fails when the runner is gone"
stop_runner
s=$(date +%s); VMJOB ping >/dev/null 2>&1; rc=$?; e=$(date +%s)
[ $rc -eq 69 ] && ok "ping: 69 after $((e - s)) s with no runner" || bad "ping without runner: rc $rc"
# The heartbeat is still young, so run queues the job; with the heartbeat frozen it must take the
# job back instead of waiting out the timeout, and the job must never start later.
s=$(date +%s); out=$(VMJOB run nope "$T/outside.sh" 2>&1); rc=$?; e=$(date +%s)
[ $rc -eq 69 ] && [ $((e - s)) -lt 60 ] && ok "run gives up after $((e - s)) s when the runner is gone" || bad "run without runner: rc $rc after $((e - s)) s: $out"
NOPE=$(cd "$SHARE/.vm/jobs" && ls ./*-nope-*.sh.withdrawn 2>/dev/null | head -n 1 | sed 's|^\./||; s|\.sh\.withdrawn$||')
[ -n "$NOPE" ] && ok "unclaimed job withdrawn" || bad "no withdrawn job: $(ls "$SHARE/.vm/jobs")"
start_runner daemon >/dev/null
sleep 3
[ ! -e "$SHARE/.vm/results/$NOPE.out" ] && ok "withdrawn job never runs" || bad "withdrawn job ran"
out=$(VMJOB result "$NOPE" 2>&1); [ $? -eq 70 ] && grep -q withdrawn <<< "$out" && ok "result reports the withdrawal" || bad "result of withdrawn: $out"
stop_runner

echo "== a runner older than vmjob.sh gets no jobs"
# The VM keeps running the runner install.sh copied until install.sh runs again. Version 1 ran a
# job file where it lies in the share, so the copy of the script a job makes would land next to it
# (and every later job would fail): vmjob must queue nothing for it and say how to update it. A
# stand-in heartbeat, rewritten every half second, says runner: 1.
OLDSHARE="$T/oldshare"
mkdir -p "$OLDSHARE/.vm"
( while :; do
    printf 'mode: daemon\nbeat: %s\nrunner: 1\n' "$RANDOM" > "$OLDSHARE/.vm/heartbeat.tmp"
    mv -f "$OLDSHARE/.vm/heartbeat.tmp" "$OLDSHARE/.vm/heartbeat"
    /bin/sleep 0.5
  done ) &
OLDBEAT=$!
OLDVMJOB() { WHOREAD_VM_HOST_DIR="$OLDSHARE" bash "$ROOT/scripts/vm/vmjob.sh" "$@"; }
out=$(OLDVMJOB ping 2>&1); rc=$?
[ $rc -eq 69 ] && grep -q 'runner/install.sh' <<< "$out" \
  && ok "ping reports a runner older than vmjob.sh (69, install it again)" || bad "ping with a version 1 runner: rc $rc: $out"
out=$(WHOREAD_VMJOB_GRACE=0 OLDVMJOB run old "$T/outside.sh" --timeout 1 2>&1); rc=$?
[ $rc -eq 69 ] && grep -q 'runner/install.sh' <<< "$out" && [ -z "$(ls -A "$OLDSHARE/.vm/jobs" 2>/dev/null)" ] \
  && ok "run queues nothing for a runner older than vmjob.sh (69, install it again)" \
  || bad "run with a version 1 runner: rc $rc: $out; queued: $(ls -A "$OLDSHARE/.vm/jobs" 2>/dev/null)"
kill "$OLDBEAT"; wait "$OLDBEAT" 2>/dev/null
grep -q '^runner: [2-9]' "$SHARE/.vm/heartbeat" && ok "the runner's heartbeat names a version vmjob.sh accepts" \
  || bad "runner heartbeat: $(grep '^runner:' "$SHARE/.vm/heartbeat")"

echo "== TCC grant (scripts/vm/tcc-fda.sh --db)"
TCC="$ROOT/scripts/vm/tcc-fda.sh"
# macOS 14+ (also 11-13 without the last four columns)
sqlite3 "$T/tcc-new.db" "CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL, csreq BLOB, policy_id INTEGER, indirect_object_identifier_type INTEGER, indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED', indirect_object_code_identity BLOB, flags INTEGER, last_modified INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)), pid INTEGER, pid_version INTEGER, boot_uuid TEXT NOT NULL DEFAULT 'UNUSED', last_reminded INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)), PRIMARY KEY (service, client, client_type, indirect_object_identifier));"
# macOS 10.15
sqlite3 "$T/tcc-old.db" "CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, allowed INTEGER NOT NULL, prompt_count INTEGER NOT NULL, csreq BLOB, policy_id INTEGER, indirect_object_identifier_type INTEGER, indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED', indirect_object_code_identity BLOB, flags INTEGER, last_modified INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)), PRIMARY KEY (service, client, client_type, indirect_object_identifier));"
# a future release with a required column nobody knows yet
sqlite3 "$T/tcc-future.db" "CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL, auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL, mystery INTEGER NOT NULL, PRIMARY KEY (service, client, client_type));"
bash "$TCC" --db "$T/tcc-new.db" /usr/local/libexec/whoreadd "/opt/it's" >/dev/null && bash "$TCC" --db "$T/tcc-new.db" /usr/local/libexec/whoreadd >/dev/null \
  && [ "$(sqlite3 "$T/tcc-new.db" "SELECT count(*) FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND client_type=1 AND auth_value=2 AND csreq IS NULL;")" = 2 ] \
  && ok "current schema: granted, quoted, idempotent" || bad "current schema: $(sqlite3 "$T/tcc-new.db" 'SELECT * FROM access;')"
bash "$TCC" --db "$T/tcc-old.db" /usr/bin/eslogger >/dev/null \
  && [ "$(sqlite3 "$T/tcc-old.db" "SELECT allowed FROM access WHERE client='/usr/bin/eslogger';")" = 1 ] \
  && ok "10.15 schema: granted through 'allowed'" || bad "old schema"
bash "$TCC" --db "$T/tcc-future.db" /usr/local/libexec/whoreadd >/dev/null 2>&1; rc=$?
[ $rc -eq 3 ] && [ "$(sqlite3 "$T/tcc-future.db" 'SELECT count(*) FROM access;')" = 0 ] \
  && ok "unknown required column: refused (exit 3), nothing written" || bad "unknown schema: rc $rc"
bash "$TCC" --db "$T/tcc-new.db" relative/path >/dev/null 2>&1 && bad "relative path accepted" || ok "relative path refused"

echo "== TCC grants are recorded and put back (tcc-fda.sh --record / --undo, runner/uninstall.sh)"
# tcc_db FILE : the macOS 14+ access table with rows install.sh must leave as it found them: an
# earlier /bin/bash row unlike what a grant writes (denied, a code requirement holding a NUL and a
# quote byte, a text value with a quote, its own times) and another service's row for it.
tcc_db() {
  sqlite3 "$1" "$(sqlite3 "$T/tcc-new.db" .schema)"
  sqlite3 "$1" "INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version, csreq, policy_id,
      indirect_object_identifier, flags, last_modified, boot_uuid, last_reminded) VALUES ('kTCCServiceSystemPolicyAllFiles',
      '/bin/bash', 1, 0, 2, 1, X'FADE0C0000002700', NULL, 'UNUSED', 7, 1234, 'it''s', 99);
    INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version)
      VALUES ('kTCCServiceAccessibility', '/bin/bash', 1, 2, 4, 1);"
}
# every row, every value as an SQL literal (text and blobs told apart), in a fixed order
tcc_rows() { sqlite3 -cmd '.mode quote' "$1" 'SELECT * FROM access ORDER BY service, client, client_type;'; }
RUNNER_PATH=/usr/local/libexec/whoread-vmrunner.sh
tcc_db "$T/tcc-undo.db"
before=$(tcc_rows "$T/tcc-undo.db")
bash "$TCC" --db "$T/tcc-undo.db" --record "$T/tcc.record" "$RUNNER_PATH" /bin/bash "/opt/it's" >/dev/null \
  && bash "$TCC" --db "$T/tcc-undo.db" --record "$T/tcc.record" /bin/bash >/dev/null \
  && [ "$(sqlite3 "$T/tcc-undo.db" "SELECT count(*) FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;")" = 3 ] \
  && ok "grants with --record written" || bad "grants with --record: $(tcc_rows "$T/tcc-undo.db")"
out=$(bash "$TCC" --db "$T/tcc-undo.db" --undo "$T/tcc.record" 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$(tcc_rows "$T/tcc-undo.db")" = "$before" ] \
  && ok "--undo removes the granted rows and puts back the earlier one exactly (also after two grants)" \
  || bad "--undo: rc $rc: $out; before: $before; after: $(tcc_rows "$T/tcc-undo.db")"
[ ! -e "$T/tcc.record" ] && ok "--undo deletes the record when done" || bad "record left after a successful undo"
out=$(bash "$TCC" --db "$T/tcc-undo.db" --undo "$T/tcc.record" 2>&1); rc=$?
[ $rc -eq 0 ] && [ "$(tcc_rows "$T/tcc-undo.db")" = "$before" ] && ok "--undo without a record changes nothing" || bad "--undo without a record: rc $rc: $out"
echo 'DELETE FROM no_such_table;' > "$T/tcc.record"
bash "$TCC" --db "$T/tcc-undo.db" --undo "$T/tcc.record" >/dev/null 2>&1; rc=$?
[ $rc -ne 0 ] && [ -f "$T/tcc.record" ] && ok "a record that cannot be applied is kept (exit $rc)" || bad "broken record: rc $rc, record $(ls "$T/tcc.record" 2>&1)"

# uninstall.sh in test mode: every system path under a stand-in root, the TCC database included.
VR="$T/vmroot"
VR_TCC="$VR/Library/Application Support/com.apple.TCC/TCC.db"
VR_FILES=("$VR/Library/LaunchDaemons/com.whoread.vmrunner.plist" "$VR/Library/LaunchAgents/com.whoread.vmrunner.agent.plist"
          "$VR/etc/sudoers.d/whoread-vmrunner" "$VR/usr/local/libexec/whoread-vmrunner.sh" "$VR/usr/local/etc/whoread-vmrunner.conf"
          "$VR/var/run/whoread-vmrunner.state" "$VR/tmp/whoread-vmrunner-agent.state")
vr_files() { local f; for f in "${VR_FILES[@]}"; do mkdir -p "$(dirname "$f")"; : > "$f"; done; }
vr_left() { local f; for f in "${VR_FILES[@]}"; do [ -e "$f" ] && echo "${f#"$VR"}"; done; }
UNINSTALL() { WHOREAD_VM_RUNNER_TEST=1 WHOREAD_VM_RUNNER_TEST_ROOT="$VR" WHOREAD_VM_USER="$(id -un)" \
  WHOREAD_VM_RUNNER_TEST_LAUNCHCTL="${LAUNCHCTL_STANDIN:-}" bash "$ROOT/scripts/vm/runner/uninstall.sh"; }
vr_files
mkdir -p "$(dirname "$VR_TCC")"
tcc_db "$VR_TCC"
before=$(tcc_rows "$VR_TCC")
( umask 077; bash "$TCC" --db "$VR_TCC" --record "$VR/usr/local/etc/whoread-vmrunner.tcc" "$RUNNER_PATH" /bin/bash >/dev/null ) \
  || bad "uninstall setup: grant failed"
out=$(UNINSTALL 2>&1); rc=$?
[ $rc -eq 0 ] && grep -q '^OK: WhoRead VM runner removed' <<< "$out" && [ -z "$(vr_left)" ] \
  && ok "uninstall.sh removes the runner's files" || bad "uninstall.sh: rc $rc: $out; left: $(vr_left)"
[ "$(tcc_rows "$VR_TCC")" = "$before" ] && [ ! -e "$VR/usr/local/etc/whoread-vmrunner.tcc" ] \
  && ok "uninstall.sh puts back the Full Disk Access rows install.sh changed" || bad "uninstall.sh TCC rows: $(tcc_rows "$VR_TCC")"
vr_files
echo 'DELETE FROM no_such_table;' > "$VR/usr/local/etc/whoread-vmrunner.tcc"
out=$(UNINSTALL 2>&1); rc=$?
[ $rc -eq 1 ] && grep -q '^FAILED: ' <<< "$out" && [ -f "$VR/usr/local/etc/whoread-vmrunner.tcc" ] && [ -z "$(vr_left)" ] \
  && ok "uninstall.sh reports rows it could not put back (FAILED, record kept)" || bad "uninstall.sh with a broken record: rc $rc: $out"
# launchctl bootout returns while the runner still stops its job and records the result: the
# access it may need for that stays until the runner is gone.
rm -f "$VR/usr/local/etc/whoread-vmrunner.tcc"
mkdir -p "$T/lcbin"
cat > "$T/lcbin/launchctl" <<SH
#!/bin/bash
case "\$1" in
  bootout) exit 0 ;;
  print) [ "\$2" = system/com.whoread.vmrunner ] && [ -e "$T/runner-loaded" ] ;;
  *) exit 1 ;;
esac
SH
chmod +x "$T/lcbin/launchctl"
vr_files
tcc_db_reset() { rm -f "$VR_TCC"; tcc_db "$VR_TCC"; }
tcc_db_reset
before=$(tcc_rows "$VR_TCC")
( umask 077; bash "$TCC" --db "$VR_TCC" --record "$VR/usr/local/etc/whoread-vmrunner.tcc" "$RUNNER_PATH" /bin/bash >/dev/null ) \
  || bad "uninstall setup: grant failed"
granted=$(tcc_rows "$VR_TCC")
: > "$T/runner-loaded"
LAUNCHCTL_STANDIN="$T/lcbin/launchctl" UNINSTALL > "$T/uninstall.out" 2>&1 &
UNINSTALLER=$!
/bin/sleep 2
[ "$(tcc_rows "$VR_TCC")" = "$granted" ] && [ -f "$VR/usr/local/etc/whoread-vmrunner.tcc" ] && [ -f "$VR/usr/local/libexec/whoread-vmrunner.sh" ] \
  && ok "uninstall.sh changes nothing while the runner is still stopping" || bad "uninstall.sh went on while the runner ran: left $(vr_left)"
rm -f "$T/runner-loaded"
wait $UNINSTALLER; rc=$?
[ $rc -eq 0 ] && [ -z "$(vr_left)" ] && [ "$(tcc_rows "$VR_TCC")" = "$before" ] \
  && ok "uninstall.sh goes on once the runner is gone" || bad "uninstall.sh after the runner stopped: rc $rc: $(cat "$T/uninstall.out")"

echo "== acceptance-m2.sh against a fake daemon (JSON handling without Python)"
# The fake whoread reports, for every probe leaf, an access whose chain is launchd → the acceptance
# script (its pid is in $T/m2.pid) → the leaf; with FAKE_CHAIN=wrong the script is missing from it.
# It logs every call as "root ..." or, when it runs through the sudo stand-in, "user ...", and
# refuses a history query from the test user as the daemon does.
# Stand-ins in $T/m2root let the script run "as root" here: id -u says 0, dscl gives the test user
# the fake home, sudo -n -u USER -- runs the command as this user (marked as the test user's), and
# launchctl asuser runs it in place.
mkdir -p "$T/m2home/WhoReadTestVault/ssh" "$T/m2home/WhoReadTestVault/aws" "$T/m2home/WhoReadTestVault/notes" "$T/m2bin" "$T/m2root"
echo fake > "$T/m2home/WhoReadTestVault/ssh/id_ed25519"
echo fake > "$T/m2home/WhoReadTestVault/aws/credentials"
printf '#!/bin/sh\nexit 0\n' > "$T/m2bin/mdimport"
printf '#!/bin/bash\nif [ "$#" -eq 1 ] && [ "$1" = -u ]; then echo 0; else exec /usr/bin/id "$@"; fi\n' > "$T/m2root/id"
printf '#!/bin/bash\necho "NFSHomeDirectory: $FAKE_HOME"\n' > "$T/m2root/dscl"
printf '#!/bin/bash\necho "sudo $*" >> "$FAKE_SUDO_LOG"\n[ "$1" = -n ] && [ "$2" = -u ] && [ "$4" = -- ] || exit 1\nshift 4\nFAKE_AS_USER=1 exec "$@"\n' > "$T/m2root/sudo"
printf '#!/bin/bash\n[ "$1" = asuser ] || exit 1\nshift 2\nexec "$@"\n' > "$T/m2root/launchctl"
cat > "$T/m2bin/whoread" <<'SH'
#!/bin/bash
if [ -n "${FAKE_AS_USER:-}" ]; then echo "user $*"; else echo "root $*"; fi >> "$FAKE_LOG"
case "$1" in
  events|export)
    if [ -n "${FAKE_REFUSE:-}" ] || [ -n "${FAKE_AS_USER:-}" ]; then
      echo "whoread: reading recorded accesses, alerts and rules needs root: run it with sudo, or use the WhoRead app" >&2
      exit 1
    fi ;;
esac
me=$(cat "$FAKE_PID_FILE")
[ "${FAKE_CHAIN:-}" = wrong ] && me=4242
ev() { printf '{"path":"%s/WhoReadTestVault/x","chain":[{"name":"launchd","pid":1},{"name":"bash","pid":%s},{"name":"%s","pid":999}]%s}' "$HOME" "$me" "$1" "${2:-}"; }
case "$1" in
  status) echo "  source:       native running" ;;
  events)
    case " $* " in
      *" --category "*) echo '[]' ;;
      *" --all "*) echo "[$(ev cat),$(ev Python),$(ev perl5.34),$(ev node),$(ev mdworker ',"benignServiceID":"spotlight"')]" ;;
      *) echo "[$(ev cat),$(ev Python),$(ev perl5.34),$(ev node)]" ;;
    esac ;;
  export)
    while [ $# -gt 0 ]; do case "$1" in --format) f=$2; shift ;; --output) o=$2; shift ;; esac; shift; done
    if [ "$f" = csv ]; then echo "id,time,operation,path" > "$o"; else echo '[]' > "$o"; fi ;;
  *) exit 1 ;;
esac
SH
chmod +x "$T/m2bin/whoread" "$T/m2bin/mdimport" "$T/m2root/"*
ME=$(id -un)
# m2 STANDINS_DIR|"" VAR=VALUE... : acceptance-m2.sh with the fake daemon (and the root stand-ins);
# neither SUDO_USER nor WHOREAD_TEST_USER unless given.
m2() {
  local root="$1"; shift
  : > "$T/m2.calls"; : > "$T/m2.sudo"
  env -u SUDO_USER -u WHOREAD_TEST_USER HOME="$T/m2home" PATH="${root:+$root:}$T/m2bin:$PATH" WHOREAD="$T/m2bin/whoread" \
    FAKE_PID_FILE="$T/m2.pid" FAKE_HOME="$T/m2home" FAKE_LOG="$T/m2.calls" FAKE_SUDO_LOG="$T/m2.sudo" "$@" \
    bash -c 'echo $$ > "$FAKE_PID_FILE"; exec bash "$0"' "$ROOT/scripts/acceptance-m2.sh"
}
# m2_root_queries : every history query ran, as root, and none as the test user.
m2_root_queries() {
  grep -q '^root events ' "$T/m2.calls" && grep -q '^root export --format json ' "$T/m2.calls" \
    && grep -q '^root export --format csv ' "$T/m2.calls" && ! grep -q '^user ' "$T/m2.calls"
}
# m2_user_probes : every vault access went through sudo -n -u <test user>.
m2_user_probes() {
  grep -q "^sudo -n -u $ME -- /bin/cat " "$T/m2.sudo" && grep -q "^sudo -n -u $ME -- /bin/sh -c " "$T/m2.sudo" \
    && grep -q "^sudo -n -u $ME -- mdimport " "$T/m2.sudo"
}
for how in "SUDO_USER=$ME" "WHOREAD_TEST_USER=$ME"; do
  out=$(m2 "$T/m2root" "$how"); rc=$?
  [ $rc -eq 0 ] && grep -q ' 0 failed' <<< "$out" && grep -q '^PASS  cat reads fake private key recorded in' <<< "$out" \
    && grep -q '^PASS  Spotlight read recorded and folded' <<< "$out" && grep -q '^PASS  export CSV' <<< "$out" \
    && ok "acceptance-m2 as root ($how) passes against a matching fake" || bad "acceptance-m2 (root, $how): rc $rc: $out"
  m2_root_queries && ok "  every history query as root ($how)" || bad "history queries ($how): $(cat "$T/m2.calls")"
  m2_user_probes && ok "  every vault access as the test user ($how)" || bad "vault accesses ($how): $(cat "$T/m2.sudo")"
done
out=$(m2 ""); rc=$?
[ $rc -ne 0 ] && grep -q "^run it as root: sudo .*acceptance-m2.sh (the probes still run as $ME)" <<< "$out" && [ ! -s "$T/m2.calls" ] \
  && ok "acceptance-m2 without root stops before asking the daemon anything" || bad "acceptance-m2 (not root): rc $rc: $out; calls: $(cat "$T/m2.calls")"
out=$(m2 "$T/m2root"); rc=$?
[ $rc -ne 0 ] && grep -q '^running as root: set WHOREAD_TEST_USER' <<< "$out" && [ ! -s "$T/m2.calls" ] && [ ! -s "$T/m2.sudo" ] \
  && ok "acceptance-m2 as root without a test user stops before anything" || bad "acceptance-m2 (root, no user): rc $rc: $out"
out=$(m2 "$T/m2root" "SUDO_USER=$ME" FAKE_CHAIN=wrong); rc=$?
[ $rc -ne 0 ] && grep -q '^FAIL  cat reads fake private key recorded with a wrong parent chain' <<< "$out" \
  && ok "acceptance-m2 reports a chain without the script" || bad "acceptance-m2 (fake, wrong chain): rc $rc: $out"
out=$(m2 "$T/m2root" "SUDO_USER=$ME" FAKE_REFUSE=1); rc=$?
[ $rc -ne 0 ] && grep -q '^cannot read the recorded accesses: whoread: reading recorded accesses' <<< "$out" \
  && ! grep -q 'not recorded' <<< "$out" && [ ! -s "$T/m2.sudo" ] \
  && ok "acceptance-m2 stops with the daemon's refusal instead of reporting accesses as not recorded" \
  || bad "acceptance-m2 (history refused): rc $rc: $out"

echo
echo "$PASS passed, $FAIL failed (files: $T)"
[ "$FAIL" -eq 0 ]
