#!/bin/bash
# Tests for scripts/dev/xcconfig.sh and `scripts/dev/sc-build.sh app` (scripts/dev/sc-app.sh).
# Usage: scripts/dev/sc-app-test.sh [--unit]
#   --unit  only the xcconfig resolver and the verification helpers (seconds); otherwise also
#           builds, re-signs and inspects .build-sc/debug/WhoRead.app three times (default,
#           WHOREAD_ENTITLED=1, default again), leaving the default (no entitlements) form behind.
#           Never launches anything.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
X="$ROOT/scripts/dev/xcconfig.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/sc-app-test.XXXXXX")"
cleanup() { rm -f "$T"/*; rmdir "$T"; }
trap cleanup EXIT
FAILS=0

# check DESC EXPECTED ACTUAL
check() {
  if [ "$2" = "$3" ]; then echo "ok   $1"
  else echo "FAIL $1"; echo "     expected: $2"; echo "     actual:   $3"; FAILS=$((FAILS + 1)); fi
}
# refuses DESC COMMAND... : COMMAND must fail.
refuses() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "FAIL $desc: succeeded"; FAILS=$((FAILS + 1)); else echo "ok   $desc"; fi
}

echo "== xcconfig.sh"
cp "$ROOT/Xcode/Shared.xcconfig" "$T/Shared.xcconfig"
prefix="$("$X" "$T/Shared.xcconfig" get BUNDLE_ID_PREFIX)"
check "shared: extension id derives from the prefix" "$prefix.whoread.extension" \
  "$("$X" "$T/Shared.xcconfig" get WHOREAD_EXTENSION_BUNDLE_ID)"
check "shared: no team gives a Mach service starting with '.'" ".$prefix.whoread.extension.xpc" \
  "$("$X" "$T/Shared.xcconfig" get WHOREAD_MACH_SERVICE)"
# Local.xcconfig is included at the end of Shared.xcconfig, after the settings that refer to it.
printf 'BUNDLE_ID_PREFIX = com.acme\nDEVELOPMENT_TEAM = ABCDE12345 // team\n' > "$T/Local.xcconfig"
check "local: prefix reaches the extension id (resolved lazily)" "com.acme.whoread.extension" \
  "$("$X" "$T/Shared.xcconfig" get WHOREAD_EXTENSION_BUNDLE_ID)"
check "local: team and prefix reach the Mach service" "ABCDE12345.com.acme.whoread.extension.xpc" \
  "$("$X" "$T/Shared.xcconfig" get WHOREAD_MACH_SERVICE)"
check "-D overrides the files" "org.x.whoread.extension" \
  "$("$X" -D BUNDLE_ID_PREFIX=org.x "$T/Shared.xcconfig" get WHOREAD_EXTENSION_BUNDLE_ID)"
check "-D values are resolved too" "com.acme.whoread" \
  "$("$X" -D 'PRODUCT_BUNDLE_IDENTIFIER=$(BUNDLE_ID_PREFIX).whoread' "$T/Shared.xcconfig" get PRODUCT_BUNDLE_IDENTIFIER)"

cat > "$T/syntax.xcconfig" <<'EOF'
// comment line
   A = one   // trailing comment
B=${A}-$(A)
	C = say "hi" & <b>
EMPTY =
#include? "missing-optional.xcconfig"
EOF
check "comments, white space, \${} and \$() references" "one-one" "$("$X" "$T/syntax.xcconfig" get B)"
check "quotes are kept" 'say "hi" & <b>' "$("$X" "$T/syntax.xcconfig" get C)"
check "empty value" "" "$("$X" "$T/syntax.xcconfig" get EMPTY)"
printf '<string>$(C)</string>\n<string>$(B) &amp; $(EMPTY)x</string>\n' > "$T/template.plist"
check "expand --xml escapes values, not the template" \
  "$(printf '%s\n' '<string>say "hi" &amp; &lt;b&gt;</string>' '<string>one-one &amp; x</string>')" \
  "$("$X" "$T/syntax.xcconfig" expand --xml < "$T/template.plist")"
check "expand without --xml" '<string>say "hi" & <b></string>' \
  "$("$X" "$T/syntax.xcconfig" expand < "$T/template.plist" | head -1)"

refuses "undefined setting" "$X" "$T/syntax.xcconfig" get NOPE
printf 'A = $(NOPE)\n' > "$T/undef.xcconfig"
refuses "reference to an undefined setting" "$X" "$T/undef.xcconfig" get A
printf '<string>$(NOPE)</string>\n' > "$T/undef.plist"
refuses "template reference to an undefined setting" sh -c '"$1" "$2" expand < "$3"' _ "$X" "$T/syntax.xcconfig" "$T/undef.plist"
printf 'A = $(B)\nB = $(A)\n' > "$T/cycle.xcconfig"
refuses "reference cycle" "$X" "$T/cycle.xcconfig" get A
printf '#include "missing.xcconfig"\n' > "$T/inc.xcconfig"
refuses "missing mandatory #include" "$X" "$T/inc.xcconfig" get A
printf 'A[sdk=macosx*] = x\n' > "$T/cond.xcconfig"
refuses "conditional setting (unsupported)" "$X" "$T/cond.xcconfig" get A
printf 'A = $(inherited) x\n' > "$T/inh.xcconfig"
refuses "\$(inherited) (unsupported)" "$X" "$T/inh.xcconfig" get A
printf 'A = x\nB = $(A:lower)\n' > "$T/op.xcconfig"
refuses "operators (unsupported)" "$X" "$T/op.xcconfig" get B
# An unsupported reference before a supported one is refused too, not passed through.
printf 'A = x\nB = y\nC = $(A:lower)$(B)\nD = $(FOO_$(B))\nE = ${A:upper}-$(B)\n' > "$T/op2.xcconfig"
refuses "operator followed by a reference (unsupported)" "$X" "$T/op2.xcconfig" get C
refuses "nested reference (unsupported)" "$X" "$T/op2.xcconfig" get D
refuses "\${} operator followed by a reference (unsupported)" "$X" "$T/op2.xcconfig" get E
printf '<string>$(A:lower)</string>\n' > "$T/op.plist"
refuses "template: operator (unsupported)" sh -c '"$1" "$2" expand < "$3"' _ "$X" "$T/op2.xcconfig" "$T/op.plist"
printf '<string>$(A:lower) $(B)</string>\n' > "$T/op2.plist"
refuses "template: operator followed by a reference (unsupported)" sh -c '"$1" "$2" expand < "$3"' _ "$X" "$T/op2.xcconfig" "$T/op2.plist"

echo "== sc-app.sh verification helpers"
# sc_app FUNCTION ARGS... : one function of sc-app.sh, in a shell like sc-build.sh's.
# XC_FILE replaces Xcode/Shared.xcconfig.
sc_app() {
  ROOT="$ROOT" XC_FILE="${XC_FILE:-}" bash -c 'set -euo pipefail
    OUT="$ROOT/.build-sc/debug" MC= SDK= PLAT= PLUGINS= TARGET=arm64-apple-macosx14.0 JOBS=1
    . "$ROOT/scripts/dev/sc-app.sh"
    [ -z "$XC_FILE" ] || XCCONFIG="$XC_FILE"
    show_settings() { app_settings >/dev/null; printf "%s\n" "$PREFIX" "$EXT_ID" "$MACH"; }
    ext_plist() { app_settings >/dev/null; xc "${EXT_DEFS[@]}" "$XCCONFIG" expand --xml < "$ROOT/Extension/Info.plist"; }
    "$@"' _ "$@"
}
# $T/Local.xcconfig (above) sets a team: an ad-hoc bundle must not claim it.
check "ad hoc: the team in Local.xcconfig is not used, its prefix is" \
  "$(printf '%s\n' com.acme com.acme.whoread.extension .com.acme.whoread.extension.xpc)" \
  "$(XC_FILE="$T/Shared.xcconfig" sc_app show_settings)"
check "ad hoc: the extension's client and app requirements name no team" "2" \
  "$(XC_FILE="$T/Shared.xcconfig" sc_app ext_plist | grep -cF 'leaf[subject.OU] = ""')"
printf 'int x(void) { return 1; }\n' > "$T/x.c"
printf 'int x(void);\nint main(void) { return x(); }\n' > "$T/uses-x.c"
printf 'int main(void) { return 0; }\n' > "$T/plain.c"
xcrun clang -dynamiclib -install_name @rpath/libx.dylib -o "$T/libx.dylib" "$T/x.c" 2>/dev/null
xcrun clang -o "$T/uses-x" "$T/uses-x.c" "$T/libx.dylib" 2>/dev/null
xcrun clang -o "$T/plain" "$T/plain.c" 2>/dev/null
refuses "check_links: a library outside the OS" sc_app check_links "$T/uses-x"
if sc_app check_links "$T/plain" >/dev/null 2>&1; then echo "ok   check_links: only libSystem"
else echo "FAIL check_links: only libSystem"; FAILS=$((FAILS + 1)); fi
refuses "check_signature: linker signature has no hardened runtime" sc_app check_signature "$T/plain" ""
codesign --force --sign - --options runtime "$T/plain" 2>/dev/null
if sc_app check_signature "$T/plain" "" >/dev/null 2>&1; then echo "ok   check_signature: runtime, no entitlements"
else echo "FAIL check_signature: runtime, no entitlements"; FAILS=$((FAILS + 1)); fi
codesign --force --sign - --options runtime --entitlements "$ROOT/Extension/whoreadd.entitlements" "$T/plain" 2>/dev/null
refuses "check_signature: unexpected entitlements" sc_app check_signature "$T/plain" ""
refuses "check_signature: different entitlements" sc_app check_signature "$T/plain" "$ROOT/App/WhoRead.entitlements"
if sc_app check_signature "$T/plain" "$ROOT/Extension/whoreadd.entitlements" >/dev/null 2>&1; then
  echo "ok   check_signature: expected entitlements"
else echo "FAIL check_signature: expected entitlements"; FAILS=$((FAILS + 1)); fi

if [ "${1:-}" = "--unit" ]; then
  echo "== $FAILS failure(s)"
  [ "$FAILS" -eq 0 ]
  exit
fi

OUT="$ROOT/.build-sc/debug"
APP="$OUT/WhoRead.app"
XC="$ROOT/Xcode/Shared.xcconfig"
prefix="$("$X" "$XC" get BUNDLE_ID_PREFIX)"
ext_id="$("$X" "$XC" get WHOREAD_EXTENSION_BUNDLE_ID)"
EXT="Contents/Library/SystemExtensions/$ext_id.systemextension"

# entitlements PATH : the signed entitlements as XML ("" when none).
entitlements() {
  local e
  e="$(codesign -d --entitlements - --xml "$1" 2>/dev/null || true)"
  [ -z "$e" ] || printf '%s' "$e" | plutil -convert xml1 -o - -
}
xml() { plutil -convert xml1 -o - "$1"; }
# layout : every path in the bundle, relative, sorted.
layout() { (cd "$APP" && find . -mindepth 1 | sed 's|^\./||' | LC_ALL=C sort); }

echo "== sc-build.sh app (default)"
"$ROOT/scripts/dev/sc-build.sh" app > "$T/build.log" 2>&1 || { tail -20 "$T/build.log"; echo "FAIL app mode"; exit 1; }
echo "ok   app mode builds and verifies"

# The layout the sources call for (Assets.car only where actool can run).
{
  printf '%s\n' Contents Contents/Info.plist Contents/PkgInfo Contents/MacOS Contents/MacOS/WhoRead \
    Contents/Helpers Contents/Helpers/whoread Contents/Resources Contents/_CodeSignature \
    Contents/_CodeSignature/CodeResources Contents/Library Contents/Library/SystemExtensions \
    "$EXT" "$EXT/Contents" "$EXT/Contents/Info.plist" "$EXT/Contents/MacOS" "$EXT/Contents/MacOS/$ext_id" \
    "$EXT/Contents/Resources" "$EXT/Contents/_CodeSignature" "$EXT/Contents/_CodeSignature/CodeResources"
  # Xcode copies the ../Data folder reference under its on-disk name, not the display name
  # WhoReadData that project.yml gives it (see Extension/main.swift).
  for base in Contents/Resources "$EXT/Contents/Resources"; do
    echo "$base/Data"
    (cd "$ROOT/Data" && find . -mindepth 1 -name '.*' -prune -o -print) | sed "s|^\./|$base/Data/|"
  done
  for d in "$ROOT"/App/Resources/*.lproj; do
    (cd "$(dirname "$d")" && find "$(basename "$d")" -name '.*' -prune -o -print) | sed 's|^|Contents/Resources/|'
  done
  for d in "$ROOT"/Extension/*.lproj; do
    (cd "$(dirname "$d")" && find "$(basename "$d")" -name '.*' -prune -o -print) | sed "s|^|$EXT/Contents/Resources/|"
  done
  [ ! -e "$APP/Contents/Resources/Assets.car" ] || echo Contents/Resources/Assets.car
} | LC_ALL=C sort > "$T/expected-layout"
check "bundle layout" "$(cat "$T/expected-layout")" "$(layout)"

ap="$APP/Contents/Info.plist"
ep="$APP/$EXT/Contents/Info.plist"
v() { plutil -extract "$2" raw -o - "$1" 2>/dev/null || echo "<missing>"; }
check "app CFBundleIdentifier" "$prefix.whoread" "$(v "$ap" CFBundleIdentifier)"
check "app CFBundleExecutable" "WhoRead" "$(v "$ap" CFBundleExecutable)"
check "app LSUIElement" "true" "$(v "$ap" LSUIElement)"
check "app WhoReadExtensionBundleID" "$ext_id" "$(v "$ap" WhoReadExtensionBundleID)"
check "app and extension Mach service" "$(v "$ep" NSEndpointSecurityMachServiceName)" "$(v "$ap" WhoReadMachServiceName)"
check "extension CFBundlePackageType" "SYSX" "$(v "$ep" CFBundlePackageType)"
check "extension CFBundleExecutable" "$ext_id" "$(v "$ep" CFBundleExecutable)"
check "extension NSEndpointSecurityEarlyBoot" "false" "$(v "$ep" NSEndpointSecurityEarlyBoot)"
check "PkgInfo" "APPL????" "$(cat "$APP/Contents/PkgInfo")"
check "helper signing identifier" "Identifier=$prefix.whoread.cli" \
  "$(codesign -dv "$APP/Contents/Helpers/whoread" 2>&1 | grep '^Identifier=')"
check "whoreadd signing identifier" "Identifier=$prefix.whoread.daemon" \
  "$(codesign -dv "$OUT/whoreadd" 2>&1 | grep '^Identifier=')"
for p in "$APP" "$APP/$EXT" "$APP/Contents/Helpers/whoread" "$OUT/whoreadd"; do
  check "no entitlements: ${p#"$OUT"/}" "" "$(entitlements "$p")"
done

# The embedded CLI finds the bundle's defaults by itself: for Contents/Helpers/whoread,
# DefaultData.searchDirectories looks in Contents/Resources/Data (never Resources/WhoReadData).
# The same binary outside the bundle tells whether other defaults installed on this Mac (the dev
# daemon's) would answer instead, which would make the check prove nothing.
fixture="$ROOT/Tests/Fixtures/eslogger/schema-v1-msgv10/scenario.jsonl"
cp "$APP/Contents/Helpers/whoread" "$T/whoread-bare"
if env -u WHOREAD_DATA_DIR "$T/whoread-bare" replay "$fixture" --home /Users/alice >/dev/null 2>&1; then
  echo "skip embedded CLI finds the bundled defaults: defaults outside the bundle answer on this Mac"
elif env -u WHOREAD_DATA_DIR "$APP/Contents/Helpers/whoread" replay "$fixture" --home /Users/alice > "$T/replay.log" 2>&1; then
  echo "ok   embedded CLI finds the bundled defaults"
else
  echo "FAIL embedded CLI finds the bundled defaults"; sed 's/^/     /' "$T/replay.log" | head -5; FAILS=$((FAILS + 1))
fi

# Leftovers from an earlier run are removed and the result still verifies.
mkdir -p "$APP/Contents/Resources/old.lproj" "$APP/$EXT/Contents/Resources/WhoReadData/sub"
: > "$APP/Contents/Resources/old.lproj/InfoPlist.strings"
: > "$APP/$EXT/Contents/Resources/WhoReadData/sub/removed.json"
: > "$APP/Contents/MacOS/WhoRead.sc-tmp"
echo "== sc-build.sh app (WHOREAD_ENTITLED=1, with leftovers in the bundle)"
WHOREAD_ENTITLED=1 "$ROOT/scripts/dev/sc-build.sh" app > "$T/build.log" 2>&1 \
  || { tail -20 "$T/build.log"; echo "FAIL entitled app mode"; exit 1; }
echo "ok   entitled app mode builds and verifies"
check "leftovers removed" "$(cat "$T/expected-layout")" "$(layout)"
check "entitlements: app" "$(xml "$ROOT/App/WhoRead.entitlements")" "$(entitlements "$APP")"
check "entitlements: extension" "$(xml "$ROOT/Extension/WhoReadExtension.entitlements")" "$(entitlements "$APP/$EXT")"
check "entitlements: whoreadd" "$(xml "$ROOT/Extension/whoreadd.entitlements")" "$(entitlements "$OUT/whoreadd")"
check "entitlements: helper (none)" "" "$(entitlements "$APP/Contents/Helpers/whoread")"

echo "== sc-build.sh app (default again)"
"$ROOT/scripts/dev/sc-build.sh" app > "$T/build.log" 2>&1 || { tail -20 "$T/build.log"; echo "FAIL app mode"; exit 1; }
for p in "$APP" "$APP/$EXT" "$APP/Contents/Helpers/whoread" "$OUT/whoreadd"; do
  check "entitlements dropped again: ${p#"$OUT"/}" "" "$(entitlements "$p")"
done
refuses "WHOREAD_ENTITLED other than 0/1" env WHOREAD_ENTITLED=yes "$ROOT/scripts/dev/sc-build.sh" app

echo "== $FAILS failure(s)"
[ "$FAILS" -eq 0 ]
