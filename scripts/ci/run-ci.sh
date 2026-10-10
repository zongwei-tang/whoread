#!/bin/bash
# CI driver (GitHub Actions macOS runners, or any Mac without a sandbox): runs every check that does
# not need root, Endpoint Security or a VM, and writes a plain-text report.
#
# Usage: scripts/ci/run-ci.sh REPORT_FILE
# Each stage runs even when an earlier one failed; the exit status is non-zero if any stage failed.
# The report holds, per stage, the outcome and the lines that matter (errors, failed tests, summary),
# never environment values.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REPORT="${1:?usage: run-ci.sh REPORT_FILE}"
LOGS="$ROOT/build/ci-logs"
mkdir -p "$LOGS"
cd "$ROOT"
FAILED=0
: > "$REPORT"
{
  echo "# WhoRead CI report"
  echo "commit: $(git rev-parse HEAD 2>/dev/null)"
  echo "runner: macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion)), $(uname -m)"
  echo "xcode: $(xcodebuild -version 2>/dev/null | tr '\n' ' ')"
  echo "swift: $(swift --version 2>&1 | head -1)"
  echo
} >> "$REPORT"

# stage NAME FILTER_REGEX COMMAND... : runs COMMAND with output to a log; records outcome and the
# matching lines (capped) in the report.
stage() {
  local name="$1" filter="$2"; shift 2
  local log="$LOGS/$name.log" start end rc
  start=$(date +%s)
  "$@" > "$log" 2>&1
  rc=$?
  end=$(date +%s)
  if [ $rc -eq 0 ]; then echo "## $name: PASS ($((end - start)) s)" >> "$REPORT"
  else echo "## $name: FAIL (exit $rc, $((end - start)) s)" >> "$REPORT"; FAILED=1; fi
  {
    grep -E "$filter" "$log" | grep -v '^ *|' | awk '!seen[$0]++' | head -150
    if [ $rc -ne 0 ]; then echo "--- last 40 lines"; tail -40 "$log"; fi
    echo
  } >> "$REPORT"
}

ERR='error:|warning:|Executed [0-9]+ tests|failed \(|FAILED|BUILD (SUCCEEDED|FAILED)|\*\* .* \*\*'

stage swift-build "$ERR" swift build --build-tests
stage swift-test "error:|Executed [0-9]+ tests|failed \(|skipped|Test Suite 'All tests'" swift test
stage e2e-dev-socket "error|FAIL|ok$|^== " scripts/dev/e2e-dev-socket.sh

if ! command -v xcodegen >/dev/null || ! command -v shellcheck >/dev/null; then
  stage brew-tools "Error|error" brew install xcodegen shellcheck
fi
stage xcodegen "error|Created project|Generated" scripts/xcodegen.sh
stage xcode-build "$ERR" scripts/build.sh Debug
stage shellcheck "SC[0-9]+|error" bash -c 'find scripts -name "*.sh" -print0 | xargs -0 shellcheck -S warning'
stage bash-syntax "syntax|error" bash -c 'for f in $(find scripts -name "*.sh"); do bash -n "$f" || exit 1; done'
# Monitor-only facts the runner can show without Full Disk Access (listing events needs no root).
stage eslogger-events "." eslogger --list-events

{
  echo "OVERALL: $([ $FAILED -eq 0 ] && echo PASS || echo FAIL)"
} >> "$REPORT"
exit $FAILED
