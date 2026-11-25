#!/bin/bash
# Builds WhoRead.pkg: a double-click installer for monitor-only mode (eslogger). It installs what
# scripts/install.sh installs (the background service, the menu bar app, the `whoread` command) and an
# uninstaller, /usr/local/libexec/whoread-uninstall. Full Disk Access still has to be switched on by
# hand: no installer can do that.
#
#   scripts/release/make-pkg.sh OUT_DIR
#
# Unsigned (ad hoc) unless these are set; CI sets them from the repository's secrets:
#   WHOREAD_SIGN_APP   a "Developer ID Application: …" identity in the keychain (signs the code)
#   WHOREAD_SIGN_PKG   a "Developer ID Installer: …" identity (signs the package)
#   WHOREAD_KEYCHAIN   the keychain that holds them (optional)
# and, to notarize and staple the signed package:
#   WHOREAD_NOTARY_KEY (path to the App Store Connect API key .p8), WHOREAD_NOTARY_KEY_ID, WHOREAD_NOTARY_ISSUER
#   WHOREAD_NOTARY_TIMEOUT  how long to wait for Apple (notarytool's --timeout, default 30m). A team's first
#                           submissions can sit "In Progress" for an hour or more; CI waits longer.
#
# The package carries no payload: everything travels in its scripts folder, and postinstall runs
# scripts/install-dev-daemon.sh on it, so a package install and scripts/install.sh install the same way
# (with the same checks). Nothing is relocated by Installer, and nothing is left in a temporary place.
# Signed with a Developer ID, the daemon keeps its identity across updates, so Full Disk Access stays on.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:?usage: make-pkg.sh OUT_DIR}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
APP_ID="${WHOREAD_SIGN_APP:-}"
PKG_ID="${WHOREAD_SIGN_PKG:-}"
KC=()
[ -z "${WHOREAD_KEYCHAIN:-}" ] || KC=(--keychain "$WHOREAD_KEYCHAIN")
if { [ -n "$APP_ID" ] && [ -z "$PKG_ID" ]; } || { [ -z "$APP_ID" ] && [ -n "$PKG_ID" ]; }; then
  echo "set both WHOREAD_SIGN_APP and WHOREAD_SIGN_PKG, or neither" >&2; exit 64
fi

echo "== build"
WHOREAD_CONFIG=release "$ROOT/scripts/dev/sc-build.sh" app
B="$ROOT/.build-sc/release"
VERSION="$("$B/whoread" version | awk '{print $2}')"
[ -n "$VERSION" ] || { echo "could not read the version from whoread version" >&2; exit 1; }
BUILD="$(git -C "$ROOT" rev-list --count HEAD 2>/dev/null || echo 0)"
ARCH="$(uname -m)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/whoread-pkg.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
S="$WORK/scripts"
mkdir -p "$S/bin" "$S/scripts" "$S/Data" "$S/packaging"
ditto "$B/WhoRead.app" "$S/WhoRead.app"
# Monitor-only: the Endpoint Security extension needs Apple's entitlement, which this build has not.
rm -rf "$S/WhoRead.app/Contents/Library/SystemExtensions"
rmdir "$S/WhoRead.app/Contents/Library" 2>/dev/null || true
cp "$B/whoreadd" "$B/whoread" "$S/bin/"
cp "$ROOT/scripts/install-dev-daemon.sh" "$ROOT/scripts/uninstall-dev-daemon.sh" "$S/scripts/"
cp "$ROOT/Data/catalog.json" "$ROOT/Data/agents.json" "$ROOT/Data/benign.json" "$S/Data/"
cp "$ROOT/packaging/com.whoread.daemon.plist" "$S/packaging/"
cp "$ROOT/packaging/pkg/preinstall" "$ROOT/packaging/pkg/postinstall" "$S/"
chmod 755 "$S/preinstall" "$S/postinstall" "$S/scripts/"*.sh

echo "== sign (${APP_ID:-ad hoc})"
# No entitlements anywhere: the app's system-extension one and the daemon's Endpoint Security one need
# provisioning profiles, without which macOS refuses to start the program. eslogger needs neither.
sign() {  # PATH
  if [ -n "$APP_ID" ]; then
    codesign --force --options runtime --timestamp --sign "$APP_ID" ${KC[@]+"${KC[@]}"} \
      --preserve-metadata=identifier "$1"
  else
    codesign --force --options runtime --sign - --preserve-metadata=identifier "$1"
  fi
}
sign "$S/bin/whoreadd"
sign "$S/bin/whoread"
sign "$S/WhoRead.app/Contents/Helpers/whoread"
sign "$S/WhoRead.app"
for p in "$S/bin/whoreadd" "$S/bin/whoread" "$S/WhoRead.app"; do
  codesign --verify --deep --strict "$p"
  if codesign -d --entitlements - --xml "$p" 2>/dev/null | grep -q '<key>'; then
    echo "$p still has entitlements" >&2; exit 1
  fi
done

echo "== package"
pkgbuild --nopayload --scripts "$S" --identifier com.whoread.pkg --version "$VERSION.$BUILD" \
  "$WORK/whoread-component.pkg"
RES="$WORK/resources"
cp -R "$ROOT/packaging/pkg/resources" "$RES"
sed -e "s/__VERSION__/$VERSION/g" -e "s/__ARCH__/$ARCH/g" "$ROOT/packaging/pkg/distribution.xml" > "$WORK/distribution.xml"
PKG="$OUT/WhoRead-$VERSION-$ARCH.pkg"
rm -f "$PKG"
if [ -n "$PKG_ID" ]; then
  productbuild --distribution "$WORK/distribution.xml" --package-path "$WORK" --resources "$RES" \
    --sign "$PKG_ID" ${KC[@]+"${KC[@]}"} --timestamp "$PKG"
  pkgutil --check-signature "$PKG"
else
  productbuild --distribution "$WORK/distribution.xml" --package-path "$WORK" --resources "$RES" "$PKG"
fi

if [ -n "$PKG_ID" ] && [ -n "${WHOREAD_NOTARY_KEY:-}" ]; then
  echo "== notarize"
  xcrun notarytool submit "$PKG" --key "$WHOREAD_NOTARY_KEY" --key-id "${WHOREAD_NOTARY_KEY_ID:?}" \
    --issuer "${WHOREAD_NOTARY_ISSUER:?}" --wait --timeout "${WHOREAD_NOTARY_TIMEOUT:-30m}" \
    --output-format json > "$WORK/notary.json" || true   # a timeout exits non-zero; the status below decides
  cat "$WORK/notary.json"; echo
  status="$(plutil -extract status raw -o - "$WORK/notary.json" 2>/dev/null || true)"
  id="$(plutil -extract id raw -o - "$WORK/notary.json" 2>/dev/null || true)"
  if [ "$status" != Accepted ]; then
    echo "notarization: ${status:-no status} (submission ${id:-?})" >&2
    [ -z "$id" ] || xcrun notarytool log "$id" --key "$WHOREAD_NOTARY_KEY" --key-id "$WHOREAD_NOTARY_KEY_ID" \
      --issuer "$WHOREAD_NOTARY_ISSUER" >&2 || true
    exit 1
  fi
  xcrun stapler staple "$PKG"
  xcrun stapler validate "$PKG"
  spctl --assess --type install --verbose=2 "$PKG"
fi
echo "Package: $PKG"
