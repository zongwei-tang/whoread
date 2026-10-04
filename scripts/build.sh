#!/bin/bash
# Builds every Xcode target. Usage: scripts/build.sh [Debug|Release]
set -euo pipefail
CONFIG="${1:-Debug}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
"$ROOT/scripts/xcodegen.sh"
cd "$ROOT/Xcode"
EXTRA=()
if ! grep -qs '^DEVELOPMENT_TEAM *= *[A-Z0-9]' Local.xcconfig; then
  # No team: sign ad hoc so local builds still run (system extension activation will not work).
  EXTRA+=(CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM= PROVISIONING_PROFILE_SPECIFIER=)
fi
for scheme in whoread whoreadd WhoRead; do
  xcodebuild -project WhoRead.xcodeproj -scheme "$scheme" -configuration "$CONFIG" \
    -derivedDataPath "$ROOT/build/DerivedData" "${EXTRA[@]}" build | tail -n 3
done
echo "Products: $ROOT/build/DerivedData/Build/Products/$CONFIG"
