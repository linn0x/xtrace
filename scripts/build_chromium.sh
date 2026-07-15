#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPOT_TOOLS="$ROOT/depot_tools"
SRC="$ROOT/chromium/src"
NINJA_BIN="${NINJA_BIN:-$(command -v ninja || true)}"

if [[ ! -d "$SRC/out/XTrace" ]]; then
  echo "Build directory not found. Run scripts/gn_gen_xtrace.sh first." >&2
  exit 1
fi

if [[ -z "$NINJA_BIN" ]]; then
  echo "ninja not found. Install ninja or set NINJA_BIN=/path/to/ninja." >&2
  exit 1
fi

export PATH="$DEPOT_TOOLS/python-bin:$DEPOT_TOOLS:$PATH"
unset GOROOT GOTOOLDIR

python3 - <<'PY'
import sys

if sys.version_info < (3, 10):
    raise SystemExit("Chromium build requires python3 >= 3.10; depot_tools/python-bin was not selected")
PY

if ! xcodebuild -version >/dev/null 2>&1 &&
  [[ -d /Applications/Xcode.app/Contents/Developer ]]; then
  export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
fi

cd "$SRC"
"$NINJA_BIN" -C out/XTrace chrome
