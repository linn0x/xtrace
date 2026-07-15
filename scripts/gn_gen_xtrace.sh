#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPOT_TOOLS="$ROOT/depot_tools"
SRC="$ROOT/chromium/src"

if [[ ! -d "$SRC" ]]; then
  echo "Chromium source not found at $SRC. Run scripts/bootstrap_chromium.sh first." >&2
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

gn gen out/XTrace --args='
is_debug=true
is_component_build=true
symbol_level=1
blink_symbol_level=1
treat_warnings_as_errors=false
use_siso=false
use_reclient=false
proprietary_codecs=true
ffmpeg_branding="Chrome"
rtc_use_h264=true
'

echo "Generated Chromium build files at $SRC/out/XTrace"
