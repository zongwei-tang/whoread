#!/bin/bash
# Generates Xcode/WhoRead.xcodeproj from Xcode/project.yml. Requires XcodeGen (brew install xcodegen).
set -euo pipefail
cd "$(dirname "$0")/../Xcode"
command -v xcodegen >/dev/null || { echo "xcodegen not found: brew install xcodegen" >&2; exit 1; }
[ -f Local.xcconfig ] || echo "note: Xcode/Local.xcconfig missing; building with BUNDLE_ID_PREFIX=com.example and no team (ad-hoc)." >&2
xcodegen generate --spec project.yml
