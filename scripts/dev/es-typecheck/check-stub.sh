#!/bin/bash
# Checks the Linux-only EndpointSecurity stub (Sources/EndpointSecurity/Stub.swift) against the real
# SDK on a Mac: gen_stub_checks.py turns every stub declaration into Swift that requires the SDK's
# declaration to have exactly the stub's type (not merely a convertible one); that program is
# compiled against the SDK (for macOS 14, the deployment target, so missing @available annotations
# fail too) and run, which compares every ALL_CAPS constant's raw value. Exit 0 when the stub matches.
#
# The stub mirrors the macOS 27 SDK. With an older SDK (no macOS 27 declarations) the check is
# skipped with a note and exit 0.
#
# Usage: scripts/dev/es-typecheck/check-stub.sh [--print | --self-test]
#   --print      show the generated Swift
#   --self-test  check that the check itself rejects a stub that differs from the SDK in one
#                declaration (each mutation below); exit 0 when every one is rejected
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
STUB="$HERE/Sources/EndpointSecurity/Stub.swift"
GEN="$HERE/gen_stub_checks.py"

if [ "${1:-}" = "--print" ]; then
  python3 "$GEN" "$STUB"
  exit 0
fi

SDK="$(xcrun --show-sdk-path 2>/dev/null || true)"
VER="$(xcrun --show-sdk-version 2>/dev/null || true)"
if [ -z "$SDK" ] || ! [[ "${VER%%.*}" =~ ^[0-9]+$ ]]; then
  echo "check-stub.sh: no macOS SDK (xcrun --show-sdk-path / --show-sdk-version failed); needs Xcode" >&2
  exit 1
fi
if [ "${VER%%.*}" -lt 27 ]; then
  echo "skipped: the stub mirrors the macOS 27 SDK, this SDK is $VER"
  exit 0
fi

TMPBASE="${TMPDIR:-/tmp}"
WORK="$(mktemp -d "$TMPBASE/es-stub-check.XXXXXX")"
# Kept between runs (module builds are slow).
MC="$TMPBASE/es-stub-check-module-cache"
cleanup() { find "$WORK" -delete 2>/dev/null || true; }
trap cleanup EXIT

# check STUB_FILE NAME: generate, compile and run the check for one stub; its exit status.
check() {
  python3 "$GEN" "$1" > "$WORK/$2.swift" &&
    xcrun swiftc -sdk "$SDK" -target "$(uname -m)-apple-macosx14.0" -swift-version 5 -module-cache-path "$MC" \
      -module-name StubCheck -o "$WORK/$2" "$WORK/$2.swift" -lEndpointSecurity -lbsm &&
    "$WORK/$2"
}

if [ "${1:-}" != "--self-test" ]; then
  echo "SDK $VER: $SDK"
  check "$STUB" main
  exit $?
fi

# Each mutation (name, old, new) replaces one exact piece of the stub, which must occur once. The
# first six were accepted by the earlier convertibility-only check: a stub stricter or looser than
# the SDK in a way an implicit conversion hides.
mkdir "$WORK/mut"
python3 - "$STUB" "$WORK/mut" <<'EOF'
import sys
MUTATIONS = [
    ("param const pointer", "es_subscribe(_ client: OpaquePointer, _ events: UnsafePointer<", "es_subscribe(_ client: OpaquePointer, _ events: UnsafeMutablePointer<"),
    ("param nullability", "es_delete_client(_ client: OpaquePointer?)", "es_delete_client(_ client: OpaquePointer)"),
    ("result optionality", "_ index: UInt32) -> es_string_token_t {", "_ index: UInt32) -> es_string_token_t? {"),
    ("implicitly unwrapped field", "public var length: Int; public var data: UnsafePointer<CChar>!", "public var length: Int; public var data: UnsafePointer<CChar>"),
    ("const message pointer", "es_retain_message(_ msg: UnsafePointer<", "es_retain_message(_ msg: UnsafeMutablePointer<"),
    ("const path pointer", "es_mute_path(_ client: OpaquePointer, _ path: UnsafePointer<CChar>", "es_mute_path(_ client: OpaquePointer, _ path: UnsafeMutablePointer<CChar>"),
    ("field nullability", "public var executable: UnsafeMutablePointer<es_file_t>\n", "public var executable: UnsafeMutablePointer<es_file_t>?\n"),
    ("field type", "public var fflag: Int32", "public var fflag: UInt32"),
    ("field name", "target_filename: es_string_token_t", "target_name: es_string_token_t"),
    ("handler block type", "es_handler_block_t = (OpaquePointer, ", "es_handler_block_t = (OpaquePointer?, "),
    ("missing availability", "@available(macOS 27.0, *)\npublic func es_sync_client", "public func es_sync_client"),
    ("raw value", "ES_EVENT_TYPE_AUTH_TRUNCATE: es_event_type_t { .init(40) }", "ES_EVENT_TYPE_AUTH_TRUNCATE: es_event_type_t { .init(50) }"),
]
stub = open(sys.argv[1], encoding="utf-8").read()
for k, (name, old, new) in enumerate(MUTATIONS):
    if stub.count(old) != 1:
        sys.exit("self-test: mutation %r no longer matches the stub exactly once; update it" % name)
    with open("%s/%02d %s.swift" % (sys.argv[2], k, name), "w", encoding="utf-8") as f:
        f.write(stub.replace(old, new))
EOF
fails=0
for m in "$WORK"/mut/*.swift; do
  name="$(basename "$m" .swift)"
  if check "$m" mutant > "$WORK/mutant.log" 2>&1; then
    echo "NOT REJECTED: $name"
    fails=$((fails + 1))
  else
    echo "rejected: $name: $(grep -m 1 -E 'error:|MISMATCH' "$WORK/mutant.log" | sed 's#^.*/mutant\.swift:#mutant.swift:#')"
  fi
done
echo "self-test: $(find "$WORK/mut" -name '*.swift' | wc -l | tr -d ' ') mutations, $fails not rejected"
[ "$fails" -eq 0 ]
