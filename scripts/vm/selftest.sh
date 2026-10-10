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
exit 3
SH
out=$(VMJOB run copy "$T/outside.sh" -- "a b" "c'd" 2>"$T/err"); rc=$?
[ $rc -eq 3 ] && ok "copied script: exit code passed through" || bad "copied script: rc $rc ($(cat "$T/err"))"
grep -q '^hello from job$' <<< "$out" && ok "copied script: output streamed" || bad "copied script output: $out"
grep -q "^args=2|a b|c'd$" <<< "$out" && ok "copied script: arguments kept" || bad "copied script args: $out"
grep -q "^pwd=$SHARE$" <<< "$out" && ok "copied script: starts in the share" || bad "copied script pwd: $out"
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
# queued after that is withdrawn (exit 70) and never runs.
printf '#!/bin/bash\necho first\nsleep 4\n' > "$T/first.sh"
VMJOB run first "$T/first.sh" > "$T/first.out" 2>&1 &
FIRST=$!
for _ in $(seq 50); do grep -qx 'first' "$SHARE/.vm/results/"*-first-*.out 2>/dev/null && break; sleep 0.2; done
printf '#!/bin/bash\n# timeout: 8\nsleep 5\necho second ran\nexit 4\n' > "$T/second.sh"
printf '#!/bin/bash\ntouch "%s/third-ran"\n' "$T" > "$T/third.sh"
WHOREAD_VMJOB_GRACE=0 VMJOB run third "$T/third.sh" --timeout 1 > "$T/third.out" 2>&1 &
THIRD=$!
s=$(date +%s); out=$(WHOREAD_VMJOB_GRACE=0 VMJOB run second "$T/second.sh" 2>"$T/err"); rc=$?; e=$(date +%s)
[ $rc -eq 4 ] && grep -q '^second ran$' <<< "$out" \
  && ok "a job queued behind another gets its whole time from its start ($((e - s)) s in all, limit 8 s)" \
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
kill -KILL "$RUNNER_PID"; wait "$RUNNER_PID" 2>/dev/null; RUNNER_PID=""
sleep 1
[ -n "$JOBPID" ] && kill -0 "$JOBPID" 2>/dev/null && ok "the job outlives its runner's SIGKILL (own process group)" || bad "job $JOBPID not running after the runner's SIGKILL"
# A decoy: a process group leader whose pid is recorded for another job, with another start time.
set -m; sleep 60 & DECOY=$!; set +m
cp "$T/orphan.sh" "$SHARE/.vm/running/decoy-job.sh"
echo "$DECOY Mon Jan  1 00:00:00 2001" > "$SHARE/.vm/running/decoy-job.pid"
start_runner daemon && ok "runner restarted after SIGKILL" || bad "runner did not restart after SIGKILL"
for _ in $(seq 50); do kill -0 "$JOBPID" 2>/dev/null || break; sleep 0.2; done
[ -n "$JOBPID" ] && ! kill -0 "$JOBPID" 2>/dev/null && ok "the restarted runner stopped the orphaned job" || bad "orphaned job $JOBPID still running"
kill -0 "$DECOY" 2>/dev/null && ok "an unrelated process holding a recorded pid is left alone" || bad "the decoy $DECOY was killed"
{ kill "$DECOY"; wait "$DECOY"; } 2>/dev/null
wait $WAITER; rc=$?
[ $rc -eq 125 ] && ok "orphaned job reported interrupted (exit 125)" || bad "orphaned job: rc $rc: $(cat "$T/orphan.out")"
[ "$(cat "$SHARE/.vm/results/decoy-job.status" 2>/dev/null)" = 125 ] && ok "decoy job marked interrupted" || bad "decoy job status"
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

echo "== acceptance-m2.sh against a fake daemon (JSON handling without Python)"
# The fake whoread reports, for every probe leaf, an access whose chain is launchd → the acceptance
# script (its pid is in $T/m2.pid) → the leaf; with FAKE_CHAIN=wrong the script is missing from it.
mkdir -p "$T/m2home/WhoReadTestVault/ssh" "$T/m2home/WhoReadTestVault/aws" "$T/m2home/WhoReadTestVault/notes" "$T/m2bin"
echo fake > "$T/m2home/WhoReadTestVault/ssh/id_ed25519"
echo fake > "$T/m2home/WhoReadTestVault/aws/credentials"
printf '#!/bin/sh\nexit 0\n' > "$T/m2bin/mdimport"
cat > "$T/m2bin/whoread" <<'SH'
#!/bin/bash
if [ -n "${FAKE_REFUSE:-}" ] && [ "$1" = events ]; then
  echo "whoread: reading recorded accesses, alerts and rules needs root: run it with sudo, or use the WhoRead app" >&2
  exit 1
fi
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
chmod +x "$T/m2bin/whoread" "$T/m2bin/mdimport"
m2() { env HOME="$T/m2home" PATH="$T/m2bin:$PATH" WHOREAD="$T/m2bin/whoread" FAKE_PID_FILE="$T/m2.pid" "$@" \
  bash -c 'echo $$ > "$FAKE_PID_FILE"; exec bash "$0"' "$ROOT/scripts/acceptance-m2.sh"; }
out=$(m2); rc=$?
[ $rc -eq 0 ] && grep -q ' 0 failed' <<< "$out" && grep -q '^PASS  cat reads fake private key recorded in' <<< "$out" \
  && grep -q '^PASS  Spotlight read recorded and folded' <<< "$out" && grep -q '^PASS  export CSV' <<< "$out" \
  && ok "acceptance-m2 passes against a matching fake" || bad "acceptance-m2 (fake, matching): rc $rc: $out"
out=$(m2 FAKE_CHAIN=wrong); rc=$?
[ $rc -ne 0 ] && grep -q '^FAIL  cat reads fake private key recorded with a wrong parent chain' <<< "$out" \
  && ok "acceptance-m2 reports a chain without the script" || bad "acceptance-m2 (fake, wrong chain): rc $rc: $out"
out=$(m2 FAKE_REFUSE=1); rc=$?
[ $rc -ne 0 ] && grep -q '^cannot read the recorded accesses: whoread: reading recorded accesses' <<< "$out" \
  && grep -q 'needs root (or the signed WhoRead app): run sudo ' <<< "$out" && ! grep -q 'not recorded' <<< "$out" \
  && ok "acceptance-m2 stops with the daemon's refusal instead of reporting accesses as not recorded" \
  || bad "acceptance-m2 (history refused): rc $rc: $out"

echo
echo "$PASS passed, $FAIL failed (files: $T)"
[ "$FAIL" -eq 0 ]
