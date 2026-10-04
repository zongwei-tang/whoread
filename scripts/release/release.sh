#!/bin/bash
# Archive → export (Developer ID) → notarize → staple → DMG.
#
# One-time setup (see docs/DISTRIBUTION.md):
#   - Xcode/Local.xcconfig with DEVELOPMENT_TEAM and BUNDLE_ID_PREFIX
#   - scripts/release/ExportOptions.plist (from the template) with your Developer ID profiles
#   - xcrun notarytool store-credentials whoread-notary --apple-id <id> --team-id <TEAM>
# Usage: scripts/release/release.sh [notary-profile]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROFILE="${1:-whoread-notary}"
OUT="$ROOT/build/release"
rm -rf "$OUT"; mkdir -p "$OUT"
[ -f "$ROOT/scripts/release/ExportOptions.plist" ] || { echo "create scripts/release/ExportOptions.plist from the template" >&2; exit 1; }

"$ROOT/scripts/xcodegen.sh"
xcodebuild -project "$ROOT/Xcode/WhoRead.xcodeproj" -scheme WhoRead -configuration Release \
  -archivePath "$OUT/WhoRead.xcarchive" archive
xcodebuild -exportArchive -archivePath "$OUT/WhoRead.xcarchive" \
  -exportOptionsPlist "$ROOT/scripts/release/ExportOptions.plist" -exportPath "$OUT/export"
APP="$OUT/export/WhoRead.app"

# Sanity checks before uploading.
codesign --verify --deep --strict --verbose=2 "$APP"
EXT="$(echo "$APP/Contents/Library/SystemExtensions/"*.systemextension)"
codesign -d --entitlements :- "$EXT" | grep -q endpoint-security.client \
  || { echo "system extension lacks the ES entitlement" >&2; exit 1; }
# The extension only talks to code that satisfies its requirements: the embedded CLI and the app.
requirement() { /usr/libexec/PlistBuddy -c "Print :$1" "$EXT/Contents/Info.plist"; }
[ -x "$APP/Contents/Helpers/whoread" ] || { echo "app lacks Contents/Helpers/whoread" >&2; exit 1; }
codesign --verify -R="$(requirement WhoReadClientRequirement)" "$APP/Contents/Helpers/whoread" \
  || { echo "embedded whoread does not satisfy WhoReadClientRequirement" >&2; exit 1; }
codesign --verify -R="$(requirement WhoReadAppRequirement)" "$APP" \
  || { echo "the app does not satisfy WhoReadAppRequirement" >&2; exit 1; }

/usr/bin/ditto -c -k --keepParent "$APP" "$OUT/WhoRead.zip"
xcrun notarytool submit "$OUT/WhoRead.zip" --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$APP"
xcrun stapler validate "$APP"

hdiutil create -volname WhoRead -srcfolder "$APP" -ov -format UDZO "$OUT/WhoRead.dmg"
codesign --sign "Developer ID Application" "$OUT/WhoRead.dmg"
xcrun notarytool submit "$OUT/WhoRead.dmg" --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$OUT/WhoRead.dmg"
echo "Release: $OUT/WhoRead.dmg"
