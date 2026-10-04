#!/bin/bash
# Runs the SwiftPM test suite (Core, Store, Engine). Works on macOS and Linux.
set -euo pipefail
cd "$(dirname "$0")/.."
swift build --build-tests "$@"
swift test "$@"
