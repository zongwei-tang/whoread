#!/bin/bash
# CI only: builds WhoRead.pkg with scripts/release/make-pkg.sh (signed and notarized when the signing
# secrets are set, see docs/DISTRIBUTION.md), then installs it with installer(8), checks it and removes
# it with its own uninstaller (scripts/ci/install-acceptance.sh with WHOREAD_CI_PKG). Writes a report.
#
# Usage: scripts/ci/package-ci.sh REPORT_FILE OUT_DIR
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REPORT="${1:?usage: package-ci.sh REPORT_FILE OUT_DIR}"
OUT="${2:?usage: package-ci.sh REPORT_FILE OUT_DIR}"
LOGS="$ROOT/build/ci-logs"
mkdir -p "$LOGS" "$OUT"
FAILED=0
{
  echo "# WhoRead package report"
  echo "commit: $(git -C "$ROOT" rev-parse HEAD 2>/dev/null)"
  echo "runner: macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion)), $(uname -m)"
  echo "signing: $([ -n "${WHOREAD_SIGN_APP:-}" ] && echo 'Developer ID' || echo 'none (ad hoc)')"
  echo "notarization: $([ -n "${WHOREAD_NOTARY_KEY:-}" ] && echo yes || echo no)"
  echo
} > "$REPORT"

stage() {  # NAME FILTER COMMAND...
  local name="$1" filter="$2" log="$LOGS/$1.log" rc start
  shift 2
  start=$(date +%s)
  "$@" > "$log" 2>&1
  rc=$?
  if [ $rc -eq 0 ]; then echo "## $name: PASS ($(( $(date +%s) - start )) s)" >> "$REPORT"
  else echo "## $name: FAIL (exit $rc, $(( $(date +%s) - start )) s)" >> "$REPORT"; FAILED=1; fi
  {
    grep -E "$filter" "$log" | head -150
    [ $rc -eq 0 ] || { echo "--- last 40 lines"; tail -40 "$log"; }
    echo
  } >> "$REPORT"
  return $rc
}

if stage make-pkg "^== |^Package:|error|Accepted|Invalid|rejected|accepted|source=|^notarization:|\"status\"|^earlier submissions|^  (createdDate|id|status):" "$ROOT/scripts/release/make-pkg.sh" "$OUT"; then
  PKG="$(find "$OUT" -maxdepth 1 -name 'WhoRead-*.pkg' | head -1)"
  WHOREAD_CI_PKG="$PKG" stage pkg-acceptance "^(PASS|FAIL|SKIP|INCOMPLETE)|passed,|^      " \
    bash "$ROOT/scripts/ci/install-acceptance.sh"
fi
echo "OVERALL: $([ $FAILED -eq 0 ] && echo PASS || echo FAIL)" >> "$REPORT"
exit $FAILED
