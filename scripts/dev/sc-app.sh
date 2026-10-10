# shellcheck shell=bash disable=SC2154
# `scripts/dev/sc-build.sh app`: assembles a runnable WhoRead.app with plain swiftc, without Xcode,
# for sandboxed hosts and the test VM. Sourced by sc-build.sh after `build` (uses its ROOT, OUT,
# SWIFTC, SDK, PLAT, PLUGINS, TARGET, MC, JOBS, SYSLIBS, stale and sources).
#
# Mirrors the Xcode targets in Xcode/project.yml:
#   .build-sc/debug/WhoRead.app
#     Contents/Info.plist                    App/Info.plist with the $(...) settings substituted
#     Contents/MacOS/WhoRead                 App/Sources, linked with WhoReadUIModel/IPC/Core
#     Contents/Resources/                    App/Resources/*.lproj, Data, Assets.car when actool
#                                            works (it does not inside a sandbox)
#     Contents/Helpers/whoread               the CLI (not Contents/MacOS: on a case-insensitive
#                                            volume "whoread" is the app's own executable)
#     Contents/Library/SystemExtensions/<WHOREAD_EXTENSION_BUNDLE_ID>.systemextension
#                                            Extension/main.swift linked with WhoReadEngine,
#                                            Extension/Info.plist (CFBundlePackageType SYSX), Data,
#                                            Extension/*.lproj
# Data keeps its on-disk name, as Xcode copies a folder reference (project.yml's `name:
# WhoReadData` is only the display name). The embedded CLI looks for its defaults in
# Contents/Resources/Data and nowhere else in the bundle (DefaultData.searchDirectories); the
# extension accepts Resources/Data or Resources/WhoReadData (Extension/main.swift).
#   .build-sc/debug/whoreadd                 re-signed like the app (below)
#   .build-sc/debug/entitled/{WhoRead.app,whoreadd}
#                                            the same, with the restricted entitlements
#                                            (WHOREAD_ENTITLED=1, below)
# Settings come from Xcode/Shared.xcconfig plus the optional Xcode/Local.xcconfig it includes
# (scripts/dev/xcconfig.sh), MARKETING_VERSION / CURRENT_PROJECT_VERSION from project.yml, and
# DEVELOPMENT_TEAM is always empty (see xc below).
#
# Signing is ad hoc, inside-out, with the hardened runtime. By default nothing carries an
# entitlement: AMFI refuses to launch an ad-hoc binary that claims a restricted one, so this is the
# form that starts on a normal Mac with SIP on (the app then talks to the dev daemon and cannot
# install the extension). WHOREAD_ENTITLED=1 builds the bundle and a copy of whoreadd in
# .build-sc/debug/entitled instead and signs the extension, whoreadd and the app there with
# Extension/WhoReadExtension.entitlements, Extension/whoreadd.entitlements and
# App/WhoRead.entitlements: only for a VM with SIP disabled. The products in .build-sc/debug itself
# never carry an entitlement, whichever mode ran last (sc-build.sh's build checks it too).
#
# Re-running updates the bundle in place: every file is written as a new file (replacing a signed
# Mach-O in place can get its next launch killed through the kernel's cached signature), anything
# in the bundle this run did not write (a resource removed from the sources, old signatures) is
# deleted one file at a time, and everything is signed again.
# The result is verified: plutil -lint on every generated plist and .strings file, no unexpanded
# setting, matching identifiers between app and extension, codesign --verify --deep --strict, the
# entitlements each piece carries, and otool -L showing only system libraries. Never launched here.

APPBIN="$OUT/app-bin"
# Where this run puts the bundle and the signed whoreadd (app_bundle: $OUT/entitled when entitled).
APPDIR="$OUT/WhoRead.app"
DAEMON="$OUT/whoreadd"
XCCONFIG="$ROOT/Xcode/Shared.xcconfig"
# Swift flags of the Xcode targets: as COMMON, minus the package-only -enable-testing and
# -DSWIFT_PACKAGE, plus the platform's macro plugins (SwiftUI, Foundation), loaded in process.
APPFLAGS=(-target "$TARGET" -sdk "$SDK" -module-cache-path "$MC" -swift-version 5 -Onone -g -DDEBUG
          -I "$OUT" -L "$OUT" -j"$JOBS" -plugin-path "$PLUGINS"
          -plugin-path "$PLAT/Developer/usr/lib/swift/host/plugins")
if [ -n "${WHOREAD_SWIFTFLAGS:-}" ]; then
  read -r -a APPEXTRA <<< "$WHOREAD_SWIFTFLAGS"
  APPFLAGS+=("${APPEXTRA[@]}")
fi

app_die() { echo "sc-build.sh app: $*" >&2; exit 1; }

# app_exes : the app and extension executables, linked outside the bundle (-g leaves a .dSYM next
# to each, which must not end up in the signed bundle).
app_exes() {
  local srcs=() f
  mkdir -p "$APPBIN"
  while IFS= read -r f; do srcs+=("$f"); done < <(sources "$ROOT/App/Sources")
  if stale "$APPBIN/WhoRead" "${srcs[@]}" "$OUT/libWhoReadUIModel.a" "$OUT/libWhoReadIPC.a" "$OUT/libWhoReadCore.a"; then
    echo "== WhoRead.app executable"
    "$SWIFTC" "${APPFLAGS[@]}" -parse-as-library -module-name WhoRead -o "$APPBIN/WhoRead" "${srcs[@]}" \
      -lWhoReadUIModel -lWhoReadIPC -lWhoReadCore
  fi
  srcs=()
  while IFS= read -r f; do srcs+=("$f"); done < <(sources "$ROOT/Extension")
  if stale "$APPBIN/WhoReadExtension" "${srcs[@]}" "$OUT"/lib*.a; then
    echo "== system extension executable"
    "$SWIFTC" "${APPFLAGS[@]}" -module-name WhoReadExtension -o "$APPBIN/WhoReadExtension" "${srcs[@]}" \
      -lWhoReadEngine -lWhoReadStore -lWhoReadIPC -lWhoReadCore "${SYSLIBS[@]}"
  fi
}

# yml_setting NAME : a project-level build setting from Xcode/project.yml (must occur exactly once).
yml_setting() {
  local v
  v="$(sed -n -E "s/^[[:space:]]+$1:[[:space:]]*\"?([^\"]*)\"?[[:space:]]*\$/\\1/p" "$ROOT/Xcode/project.yml")"
  [ -n "$v" ] && [ "$(printf '%s\n' "$v" | wc -l)" -eq 1 ] || app_die "Xcode/project.yml: expected one $1"
  printf '%s\n' "$v"
}

# xc ARGS... : scripts/dev/xcconfig.sh with the project's own settings. An ad-hoc signature has no
# team, so DEVELOPMENT_TEAM is empty whatever Local.xcconfig says, as in scripts/build.sh's ad-hoc
# build: a team there would pin the extension's client and app requirements to that team (which no
# ad-hoc peer satisfies, so the extension would refuse this very app and CLI) and point the app at
# a Mach service only a team-signed extension publishes.
xc() {
  local defs=(-D "MARKETING_VERSION=$MARKETING_VERSION" -D "CURRENT_PROJECT_VERSION=$CURRENT_PROJECT_VERSION"
              -D DEVELOPMENT_LANGUAGE=en -D DEVELOPMENT_TEAM=
              # The Debug value from Xcode/project.yml: these bundles are ad hoc development builds; only a
              # Release build pins Developer ID.
              -D "WHOREAD_SIGNING_ANCHOR=anchor apple generic")
  "$ROOT/scripts/dev/xcconfig.sh" "${defs[@]}" "$@"
}

# app_settings : PREFIX, EXT_ID, MACH, MINOS, MARKETING_VERSION and CURRENT_PROJECT_VERSION.
app_settings() {
  local team
  MINOS="${TARGET##*-macosx}"
  MARKETING_VERSION="$(yml_setting MARKETING_VERSION)"
  CURRENT_PROJECT_VERSION="$(yml_setting CURRENT_PROJECT_VERSION)"
  PREFIX="$(xc "$XCCONFIG" get BUNDLE_ID_PREFIX)"
  EXT_ID="$(xc "$XCCONFIG" get WHOREAD_EXTENSION_BUNDLE_ID)"
  MACH="$(xc "$XCCONFIG" get WHOREAD_MACH_SERVICE)"
  # Bundle identifiers: letters, digits, '-' and '.'; the extension's is also a path component.
  [[ "$PREFIX" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || app_die "bad BUNDLE_ID_PREFIX '$PREFIX'"
  [[ "$EXT_ID" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || app_die "bad WHOREAD_EXTENSION_BUNDLE_ID '$EXT_ID'"
  team="$("$ROOT/scripts/dev/xcconfig.sh" "$XCCONFIG" get DEVELOPMENT_TEAM)"
  if [ -n "$team" ]; then
    echo "   DEVELOPMENT_TEAM $team not used: signed ad hoc (scripts/build.sh signs with the team)"
  fi
}

# The settings Xcode derives per target (project.yml targets.*.settings and the product type).
APP_DEFS=(-D PRODUCT_NAME=WhoRead -D 'EXECUTABLE_NAME=$(PRODUCT_NAME)'
          -D 'PRODUCT_BUNDLE_IDENTIFIER=$(BUNDLE_ID_PREFIX).whoread')
EXT_DEFS=(-D 'PRODUCT_NAME=$(WHOREAD_EXTENSION_BUNDLE_ID)' -D 'EXECUTABLE_NAME=$(PRODUCT_NAME)'
          -D 'PRODUCT_BUNDLE_IDENTIFIER=$(WHOREAD_EXTENSION_BUNDLE_ID)' -D PRODUCT_BUNDLE_PACKAGE_TYPE=SYSX)

EXPECTED=$'\n'

# record REL : REL (relative to the bundle) belongs to this run's bundle.
record() { EXPECTED+="$1"$'\n'; }

# put SRC REL : copies SRC to the bundle as a new file, without extended attributes. A temporary
# file left by an interrupted run is removed first: cp into an existing file keeps that file's mode.
put() {
  local dst="$APPDIR/$2"
  mkdir -p "$(dirname "$dst")"
  rm -f "$dst.sc-tmp"
  cp -X "$1" "$dst.sc-tmp"
  mv -f "$dst.sc-tmp" "$dst"
  record "$2"
}

# put_tree SRC_DIR REL_DIR : every file under SRC_DIR (dot files skipped, as Xcode's copy does).
put_tree() {
  local f
  while IFS= read -r f; do
    put "$f" "$2/${f#"$1"/}"
  done < <(find "$1" -mindepth 1 -name '.*' -prune -o -type f -print | LC_ALL=C sort)
}

# info_plist TEMPLATE REL DEFS... : the template with its settings substituted.
info_plist() {
  local template="$1" rel="$2" dst="$APPDIR/$2"
  shift 2
  mkdir -p "$(dirname "$dst")"
  rm -f "$dst.sc-tmp"
  xc "$@" "$XCCONFIG" expand --xml < "$template" > "$dst.sc-tmp"
  mv -f "$dst.sc-tmp" "$dst"
  plutil -lint -s "$dst" || app_die "$dst is not a valid plist"
  if grep -qF -e '$(' -e '${' "$dst"; then app_die "$dst has an unexpanded setting"; fi
  # Added by Xcode's Info.plist processing.
  plutil -replace CFBundleSupportedPlatforms -json '["MacOSX"]' "$dst"
  plutil -extract LSMinimumSystemVersion raw -o - "$dst" >/dev/null 2>&1 \
    || plutil -replace LSMinimumSystemVersion -string "$MINOS" "$dst"
  record "$rel"
}

# key PLIST KEY : one Info.plist value ("" when absent).
key() { plutil -extract "$2" raw -o - "$1" 2>/dev/null || true; }

# assets : Assets.car and the icon keys of App/Resources/Assets.xcassets, when actool can run.
# Inside a sandbox it cannot (it writes scratch files to the per-user temporary directory), and the
# AppIcon set has no images yet, so skipping it loses nothing today.
assets() {
  local work="$APPBIN/assets" v k
  mkdir -p "$work"
  rm -f "$work/Assets.car" "$work/partial.plist"
  if xcrun actool --compile "$work" --platform macosx --minimum-deployment-target "$MINOS" \
      --app-icon AppIcon --output-partial-info-plist "$work/partial.plist" --errors --warnings \
      "$ROOT/App/Resources/Assets.xcassets" > "$work/actool.log" 2>&1; then
    if [ -f "$work/Assets.car" ]; then put "$work/Assets.car" Contents/Resources/Assets.car; fi
    for k in CFBundleIconFile CFBundleIconName; do
      if v="$(plutil -extract "$k" raw -o - "$work/partial.plist" 2>/dev/null)"; then
        plutil -replace "$k" -string "$v" "$APPDIR/Contents/Info.plist"
      fi
    done
    ASSETS="compiled"
  else
    ASSETS="skipped (actool failed, see $work/actool.log)"
  fi
}

# prune : deletes, one file at a time, whatever is in the bundle that this run did not write.
prune() {
  local p rel
  while IFS= read -r p; do
    rel="${p#"$APPDIR"/}"
    case "$EXPECTED" in *$'\n'"$rel"$'\n'*) continue ;; esac
    if [ -d "$p" ] && [ ! -L "$p" ]; then
      case "$EXPECTED" in *$'\n'"$rel"/*) continue ;; esac
      rmdir "$p"
    else
      rm -f "$p"
    fi
  done < <(find "$APPDIR" -mindepth 1 -depth)
}

# sign PATH IDENTIFIER|"" ENTITLEMENTS|"" : ad hoc, hardened runtime, replacing any signature.
sign() {
  local args=(--force --sign - --options runtime)
  [ -n "$2" ] && args+=(--identifier "$2")
  [ -n "$3" ] && args+=(--entitlements "$3")
  codesign "${args[@]}" "$1" 2>&1 | grep -v 'replacing existing signature' || true
  codesign --verify --strict "$1" || app_die "signing $1 failed"
}

# sign_copy SRC DST IDENTIFIER ENTITLEMENTS|"" : DST becomes a new file, a copy of SRC signed as
# sign does (SRC may be DST: replacing a signed Mach-O in place can get its next launch killed).
sign_copy() {
  rm -f "$2.sc-tmp"
  cp -X "$1" "$2.sc-tmp"
  sign "$2.sc-tmp" "$3" "$4"
  mv -f "$2.sc-tmp" "$2"
}

# check_signature PATH ENTITLEMENTS|"" : hardened runtime, and exactly these entitlements.
check_signature() {
  local info got want
  info="$(codesign -d --verbose=2 "$1" 2>&1)" || app_die "$1: not signed"
  case "$info" in *"flags=0x"*"runtime"*) ;; *) app_die "$1: no hardened runtime" ;; esac
  got="$(codesign -d --entitlements - --xml "$1" 2>/dev/null || true)"
  if [ -z "$2" ]; then
    [ -z "$got" ] || app_die "$1 carries entitlements it must not have: $got"
  else
    got="$(printf '%s' "$got" | plutil -convert xml1 -o - -- -)"
    want="$(plutil -convert xml1 -o - "$2")"
    [ "$got" = "$want" ] || app_die "$1: entitlements differ from $2"
  fi
}

# check_links MACHO : every library it loads is part of the OS.
check_links() {
  local out line n=0
  out="$(otool -L "$1" 2>/dev/null)" || app_die "otool -L $1 failed"
  while IFS= read -r line; do
    case "$line" in
      *:) continue ;;
    esac
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%% (compatibility*}"
    case "$line" in
      /usr/lib/*|/System/Library/*) n=$((n + 1)) ;;
      *) app_die "$1 loads a library outside the OS: $line" ;;
    esac
  done <<< "$out"
  [ "$n" -gt 0 ] || app_die "otool -L $1 listed no libraries"
}

app_bundle() {
  local exe ext_dir ext_exe ent f d
  case "${WHOREAD_ENTITLED:-0}" in
    0|1) ent="${WHOREAD_ENTITLED:-0}" ;;
    *) app_die "WHOREAD_ENTITLED must be 0 or 1" ;;
  esac

  if [ "$ent" = 1 ]; then
    APPDIR="$OUT/entitled/WhoRead.app"
    DAEMON="$OUT/entitled/whoreadd"
  fi

  app_exes
  echo "== WhoRead.app bundle"
  app_settings
  mkdir -p "$APPDIR"

  exe="$(xc "${APP_DEFS[@]}" "$XCCONFIG" get EXECUTABLE_NAME)"
  info_plist "$ROOT/App/Info.plist" Contents/Info.plist "${APP_DEFS[@]}"
  rm -f "$APPDIR/Contents/PkgInfo.sc-tmp"
  printf 'APPL????' > "$APPDIR/Contents/PkgInfo.sc-tmp"
  mv -f "$APPDIR/Contents/PkgInfo.sc-tmp" "$APPDIR/Contents/PkgInfo"
  record Contents/PkgInfo
  put "$APPBIN/WhoRead" "Contents/MacOS/$exe"
  for f in "$ROOT"/App/Resources/*.lproj; do put_tree "$f" "Contents/Resources/$(basename "$f")"; done
  put_tree "$ROOT/Data" Contents/Resources/Data
  assets
  put "$OUT/whoread" Contents/Helpers/whoread

  ext_dir="Contents/Library/SystemExtensions/$EXT_ID.systemextension"
  ext_exe="$(xc "${EXT_DEFS[@]}" "$XCCONFIG" get EXECUTABLE_NAME)"
  info_plist "$ROOT/Extension/Info.plist" "$ext_dir/Contents/Info.plist" "${EXT_DEFS[@]}"
  put "$APPBIN/WhoReadExtension" "$ext_dir/Contents/MacOS/$ext_exe"
  for f in "$ROOT"/Extension/*.lproj; do put_tree "$f" "$ext_dir/Contents/Resources/$(basename "$f")"; done
  put_tree "$ROOT/Data" "$ext_dir/Contents/Resources/Data"

  prune

  local app_ent="" ext_ent="" daemon_ent=""
  if [ "$ent" = 1 ]; then
    app_ent="$ROOT/App/WhoRead.entitlements"
    ext_ent="$ROOT/Extension/WhoReadExtension.entitlements"
    daemon_ent="$ROOT/Extension/whoreadd.entitlements"
  fi
  sign "$APPDIR/Contents/Helpers/whoread" "$PREFIX.whoread.cli" ""
  sign "$APPDIR/$ext_dir" "" "$ext_ent"
  sign "$APPDIR" "" "$app_ent"
  sign_copy "$OUT/whoreadd" "$DAEMON" "$PREFIX.whoread.daemon" "$daemon_ent"

  # Verification.
  local app_plist="$APPDIR/Contents/Info.plist" ext_plist="$APPDIR/$ext_dir/Contents/Info.plist"
  while IFS= read -r f; do
    plutil -lint -s "$f" || app_die "$f is not a valid strings file"
  done < <(find "$APPDIR" -name '*.strings' -type f)
  [ "$(key "$app_plist" CFBundleIdentifier)" = "$PREFIX.whoread" ] || app_die "app CFBundleIdentifier"
  [ "$(key "$app_plist" CFBundlePackageType)" = APPL ] || app_die "app CFBundlePackageType"
  [ "$(key "$app_plist" LSUIElement)" = true ] || app_die "app LSUIElement"
  [ "$(key "$app_plist" CFBundleShortVersionString)" = "$MARKETING_VERSION" ] || app_die "app version"
  [ "$(key "$app_plist" CFBundleVersion)" = "$CURRENT_PROJECT_VERSION" ] || app_die "app build number"
  [ "$(key "$app_plist" LSMinimumSystemVersion)" = "$MINOS" ] || app_die "app LSMinimumSystemVersion"
  [ "$(key "$ext_plist" CFBundleIdentifier)" = "$EXT_ID" ] || app_die "extension CFBundleIdentifier"
  [ "$(key "$ext_plist" CFBundlePackageType)" = SYSX ] || app_die "extension CFBundlePackageType"
  [ "$(key "$ext_plist" LSMinimumSystemVersion)" = "$MINOS" ] || app_die "extension LSMinimumSystemVersion"
  [ "$(key "$app_plist" WhoReadExtensionBundleID)" = "$EXT_ID" ] || app_die "app WhoReadExtensionBundleID"
  [ "$(key "$app_plist" WhoReadMachServiceName)" = "$MACH" ] || app_die "app WhoReadMachServiceName"
  [ "$(key "$ext_plist" NSEndpointSecurityMachServiceName)" = "$MACH" ] || app_die "extension Mach service"
  # Team-less requirements, which Extension/main.swift drops (a team would lock out this app).
  for f in WhoReadClientRequirement WhoReadAppRequirement; do
    case "$(key "$ext_plist" "$f")" in
      *'leaf[subject.OU] = ""'*) ;;
      *) app_die "extension $f names a team, which no ad-hoc signature satisfies" ;;
    esac
  done
  [ -x "$APPDIR/Contents/MacOS/$(key "$app_plist" CFBundleExecutable)" ] || app_die "app CFBundleExecutable"
  [ -x "$APPDIR/$ext_dir/Contents/MacOS/$(key "$ext_plist" CFBundleExecutable)" ] || app_die "extension CFBundleExecutable"
  # The defaults (DefaultData) where the embedded CLI and the extension look for them.
  for f in catalog.json agents.json benign.json; do
    for d in "$APPDIR/Contents/Resources/Data" "$APPDIR/$ext_dir/Contents/Resources/Data"; do
      [ -f "$d/$f" ] || app_die "bundled defaults: no $d/$f"
    done
  done
  # codesign's default resource rules do not list Contents/Library/SystemExtensions as a place for
  # nested code: the app's seal covers the extension's files by hash only, and --deep on the app
  # does not evaluate the extension's own signature. Verify that separately.
  for f in "$APPDIR" "$APPDIR/$ext_dir"; do
    if ! codesign --verify --deep --strict --verbose=1 "$f" 2>&1 | sed 's/^/   /'; then
      app_die "codesign --verify --deep --strict $f failed"
    fi
  done
  check_signature "$APPDIR" "$app_ent"
  check_signature "$APPDIR/$ext_dir" "$ext_ent"
  check_signature "$APPDIR/Contents/Helpers/whoread" ""
  check_signature "$DAEMON" "$daemon_ent"
  for f in "$APPDIR/Contents/MacOS/$exe" "$APPDIR/Contents/Helpers/whoread" \
           "$APPDIR/$ext_dir/Contents/MacOS/$ext_exe" "$DAEMON"; do
    check_links "$f"
  done

  echo "   $APPDIR"
  echo "   app $PREFIX.whoread, extension $EXT_ID, Mach service $MACH"
  if [ "$ent" = 1 ]; then
    echo "   signed ad hoc WITH the restricted entitlements: runs only where SIP is disabled"
    echo "   (kept in $OUT/entitled; the products in $OUT carry no entitlement)"
  else
    echo "   signed ad hoc without entitlements (WHOREAD_ENTITLED=1 builds a copy with them in"
    echo "   $OUT/entitled, for a SIP-disabled VM)"
  fi
  echo "   verified: plists, codesign --verify --deep --strict, entitlements, otool -L (OS libraries only)"
  echo "   asset catalog: $ASSETS"
  echo "   whoreadd signed: $DAEMON"
}
