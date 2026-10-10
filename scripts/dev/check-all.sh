#!/bin/bash
# Everything that can be verified without a Mac: unit tests, ES stub type-check, XcodeGen spec
# generation (if xcodegen is installed) and the cross-process dev-socket e2e.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
echo "== swift test"; swift test 2>&1 | grep -E "error:|failed \(|Executed [0-9]+ tests" | tail -2
echo "== ES stub type-check"; (cd scripts/dev/es-typecheck && swift build 2>&1 | grep -E "error|Build complete")
if command -v xcodegen >/dev/null || [ -x "$HOME/.local/bin/xcodegen" ]; then
  XG="$(command -v xcodegen || echo "$HOME/.local/bin/xcodegen")"
  TMP="$(mktemp -d)"
  echo "== xcodegen"; (cd Xcode && "$XG" generate --spec project.yml --project "$TMP" | tail -1)
  rm -rf "$TMP"
fi
echo "== e2e over the dev socket"; scripts/dev/e2e-dev-socket.sh >/dev/null && echo "e2e ok"
