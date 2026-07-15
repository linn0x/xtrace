#!/usr/bin/env bash
# One-click: generate + build a RELEASE, non-debug XTrace Chromium.
#
# The debug+component build (out/XTrace) is great for hacking on the C++/patch
# but runs JS/rendering ~an order of magnitude slower, so heavy SPAs can
# appear to "white-screen" while they crawl through startup. This builds a
# release flavour into a SEPARATE out dir so your debug build stays intact.
#
# The XTrace patches are applied to the source tree, not per-out-dir, so this
# build is still fully instrumented.
#
# Usage:   scripts/build_xtrace_release.sh
# Override out dir: OUT_DIR=out/XTrace-fast scripts/build_xtrace_release.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPOT_TOOLS="$ROOT/depot_tools"
SRC="$ROOT/chromium/src"
OUT_DIR="${OUT_DIR:-out/XTrace-release}"
NINJA_BIN="${NINJA_BIN:-$(command -v ninja || echo "$DEPOT_TOOLS/ninja")}"

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

# Release args. Only is_debug/is_component_build differ from gn_gen_xtrace.sh;
# codecs are kept so media-heavy sites render realistically. Flip
# is_component_build=true if you want faster incremental relinks.
gn gen "$OUT_DIR" --args='
is_debug=false
is_component_build=false
symbol_level=1
blink_symbol_level=1
treat_warnings_as_errors=false
use_siso=false
use_reclient=false
proprietary_codecs=true
ffmpeg_branding="Chrome"
rtc_use_h264=true
'

echo "==> gn gen done: $SRC/$OUT_DIR"
echo "==> building (this takes a while on a first release build)…"
"$NINJA_BIN" -C "$OUT_DIR" chrome

APP="$SRC/$OUT_DIR/Chromium.app"
echo
echo "==> Done. Release XTrace build: $APP"
echo "    Run a real page with it, e.g.:"
echo
echo "    cd xtrace-launcher && PYTHONPATH=. python3 -m xtrace_launcher run \\"
echo "      --chromium $APP \\"
echo "      --url 'https://example.com/' \\"
echo "      --log-dir ../logs/release-smoke --xtrace-categories fingerprint \\"
echo "      --xtrace-capture-values summary --xtrace-capture-assets summary"
