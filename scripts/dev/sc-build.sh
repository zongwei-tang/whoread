#!/bin/bash
# Builds and tests the Swift package with plain swiftc, without SwiftPM or xcodebuild.
#
# Why: SwiftPM and xcodebuild write their intermediate files atomically through Foundation, which
# inside a file-system sandbox puts the temporary copy in the per-user item-replacement directory
# (/var/folders/.../T/TemporaryItems). A sandbox that only allows writes to $TMPDIR and the
# repository (as some editor and CI sandboxes do) makes every such write fail with EPERM. swiftc itself writes
# next to its outputs, so this script works there. Outside such a sandbox `swift build` / `swift
# test` remain the normal way.
#
# Usage: scripts/dev/sc-build.sh [build|test|all] [XCTest filter]
#   build  libraries + whoreadd + whoread               (default)
#   test   build, then build and run the four test bundles (optional filter, e.g. WhoReadCoreTests
#          or WhoReadCoreTests.AnalyzerTests/testX)
# Products: .build-sc/debug/{whoreadd,whoread,lib*.a,*.swiftmodule,*.xctest}
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MODE="${1:-build}"
FILTER="${2:-}"
OUT="$ROOT/.build-sc/debug"
MC="$ROOT/.build-sc/ModuleCache"
mkdir -p "$OUT" "$MC"
SDK="$(xcrun --show-sdk-path)"
PLAT="$(xcrun --show-sdk-platform-path)"
SWIFTC="$(xcrun -f swiftc)"
# Load macro plugins (Observation, _SwiftifyImport) in process: the external swift-plugin-server
# fails inside a sandbox.
PLUGINS="$(dirname "$SWIFTC")/../lib/swift/host/plugins"
TARGET="$(uname -m)-apple-macosx14.0"
JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 8)"
COMMON=(-target "$TARGET" -sdk "$SDK" -module-cache-path "$MC" -swift-version 5 -Onone -g
        -enable-testing -DDEBUG -DSWIFT_PACKAGE -I "$OUT" -L "$OUT" -j"$JOBS" -plugin-path "$PLUGINS"
        ${WHOREAD_SWIFTFLAGS:-})
XCT=(-F "$PLAT/Developer/Library/Frameworks" -I "$PLAT/Developer/usr/lib" -L "$PLAT/Developer/usr/lib")
RPATH=(-Xlinker -rpath -Xlinker "$PLAT/Developer/Library/Frameworks" -Xlinker -rpath -Xlinker "$PLAT/Developer/usr/lib")
SYSLIBS=(-lsqlite3 -lEndpointSecurity -lbsm)

# newer OUTPUT INPUT... : true when OUTPUT is missing or older than any input file.
stale() {
  local out="$1"; shift
  [ -e "$out" ] || return 0
  local f
  for f in "$@"; do [ "$f" -nt "$out" ] && return 0; done
  return 1
}

sources() { find "$@" -name '*.swift' -type f | LC_ALL=C sort; }

# lib NAME DEP... : static library + module for Sources/NAME.
lib() {
  local name="$1"; shift
  local srcs deps=() d
  while IFS= read -r f; do srcs+=("$f"); done < <(sources "$ROOT/Sources/$name")
  for d in "$@"; do deps+=("$OUT/lib$d.a"); done
  if stale "$OUT/lib$name.a" "${srcs[@]}" ${deps[@]+"${deps[@]}"}; then
    echo "== $name"
    "$SWIFTC" "${COMMON[@]}" -parse-as-library -module-name "$name" \
      -emit-module -emit-module-path "$OUT/$name.swiftmodule" \
      -emit-library -static -o "$OUT/lib$name.a" "${srcs[@]}"
  fi
}

# exe NAME : executable from Sources/NAME linked against every library.
exe() {
  local name="$1" srcs=()
  while IFS= read -r f; do srcs+=("$f"); done < <(sources "$ROOT/Sources/$name")
  if stale "$OUT/$name" "${srcs[@]}" "$OUT"/lib*.a; then
    echo "== $name"
    "$SWIFTC" "${COMMON[@]}" -module-name "$name" -o "$OUT/$name" "${srcs[@]}" \
      -lWhoReadEngine -lWhoReadStore -lWhoReadIPC -lWhoReadUIModel -lWhoReadCore "${SYSLIBS[@]}"
  fi
}

# testbundle NAME : Tests/NAME as an .xctest bundle.
testbundle() {
  local name="$1" srcs=() b="$OUT/$1.xctest"
  while IFS= read -r f; do srcs+=("$f"); done < <(sources "$ROOT/Tests/$name")
  mkdir -p "$b/Contents/MacOS"
  if stale "$b/Contents/MacOS/$name" "${srcs[@]}" "$OUT"/lib*.a; then
    echo "== $name"
    cat > "$b/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>$name</string>
<key>CFBundleIdentifier</key><string>com.whoread.tests.$name</string>
<key>CFBundleName</key><string>$name</string>
<key>CFBundlePackageType</key><string>BNDL</string>
</dict></plist>
EOF
    "$SWIFTC" "${COMMON[@]}" "${XCT[@]}" -parse-as-library -module-name "$name" \
      -Xlinker -bundle -o "$b/Contents/MacOS/$name" "${srcs[@]}" \
      -lWhoReadEngine -lWhoReadStore -lWhoReadIPC -lWhoReadUIModel -lWhoReadCore "${SYSLIBS[@]}" \
      -framework XCTest "${RPATH[@]}"
  fi
}

build() {
  lib WhoReadCore
  lib WhoReadStore WhoReadCore
  lib WhoReadIPC WhoReadCore
  lib WhoReadEngine WhoReadCore WhoReadStore WhoReadIPC
  lib WhoReadUIModel WhoReadCore WhoReadIPC
  exe whoreadd
  exe whoread
}

runtests() {
  local t rc=0
  # Inside a sandbox that forbids binding sockets, the few dev-socket tests skip themselves.
  export WHOREAD_ALLOW_SOCKET_SKIP=1
  for t in WhoReadCoreTests WhoReadStoreTests WhoReadEngineTests WhoReadUIModelTests; do
    testbundle "$t"
  done
  for t in WhoReadCoreTests WhoReadStoreTests WhoReadEngineTests WhoReadUIModelTests; do
    if [ -n "$FILTER" ] && [[ "$FILTER" != "$t"* ]]; then continue; fi
    echo "== run $t"
    if [ -n "$FILTER" ] && [ "$FILTER" != "$t" ]; then
      xcrun xctest -XCTest "${FILTER#*.}" "$OUT/$t.xctest" || rc=1
    else
      xcrun xctest "$OUT/$t.xctest" || rc=1
    fi
  done
  return $rc
}

case "$MODE" in
  build) build ;;
  test|all) build; runtests ;;
  *) echo "usage: $0 [build|test|all] [filter]" >&2; exit 2 ;;
esac
