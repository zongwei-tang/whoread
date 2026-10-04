#!/bin/bash
# Builds every Xcode target. Usage: scripts/build.sh [Debug|Release]
set -euo pipefail
CONFIG="${1:-Debug}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"$ROOT/scripts/xcodegen.sh"
cd "$ROOT/Xcode"
EXTRA=()
if ! grep -qs '^DEVELOPMENT_TEAM *= *[A-Z0-9]' Local.xcconfig; then
  # No team: sign ad hoc and without entitlements. The restricted ones (system-extension.install,
  # endpoint-security.client) need a provisioning profile, and AMFI refuses to launch an ad-hoc
  # binary that claims them. The app then runs against the dev daemon but cannot install the
  # extension; install-dev-daemon.sh re-signs whoreadd with the ES entitlement for the VM.
  EXTRA+=(CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= PROVISIONING_PROFILE_SPECIFIER= CODE_SIGN_ENTITLEMENTS=)
fi
for scheme in whoread whoreadd WhoRead; do
  xcodebuild -project WhoRead.xcodeproj -scheme "$scheme" -configuration "$CONFIG" \
    -derivedDataPath "$ROOT/build/DerivedData" ${EXTRA[@]+"${EXTRA[@]}"} build | tail -n 3
done
echo "Products: $ROOT/build/DerivedData/Build/Products/$CONFIG"
