#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPOT_TOOLS="$ROOT/depot_tools"
SRC="$ROOT/chromium/src"
OUT_DIR="${OUT_DIR:-out/XTrace}"
NINJA_BIN="${NINJA_BIN:-$(command -v ninja || true)}"
DRY_RUN=0
DIAGNOSE_ONLY=0

usage() {
  cat <<'EOF'
Usage: scripts/relink_chromium_runtime.sh [--dry-run] [--diagnose-only] [OUT_DIR]

Relink the minimal Chromium runtime chain used by XTrace native hooks:
  Chromium.app -> Chromium Framework -> out/XTrace/libchrome_dll.dylib

This intentionally avoids the full "chrome" target. If ninja reports missing
deps for libchrome_dll.dylib, the current out dir is incomplete and ninja must
rebuild those missing objects before it can relink.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --diagnose-only)
      DIAGNOSE_ONLY=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      OUT_DIR="$1"
      shift
      ;;
  esac
done

if [[ ! -d "$SRC/$OUT_DIR" ]]; then
  echo "Build directory not found: $SRC/$OUT_DIR" >&2
  echo "Run scripts/gn_gen_xtrace.sh first, or pass an existing OUT_DIR." >&2
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

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '+'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

cd "$SRC"

echo "Runtime load path:"
echo "  Chromium.app -> Chromium Framework -> $OUT_DIR/libchrome_dll.dylib"
echo
echo "Ninja missing deps diagnostic for libchrome_dll.dylib:"
"$NINJA_BIN" -C "$OUT_DIR" -n -d explain libchrome_dll.dylib 2>&1 | sed -n '1,120p'

if [[ "$DIAGNOSE_ONLY" -eq 1 ]]; then
  exit 0
fi

run "$NINJA_BIN" -C "$OUT_DIR" \
  libchrome_dll.dylib \
  "obj/chrome/chrome_framework_shared_library/Chromium Framework" \
  Chromium.app

run codesign --force --deep --sign - "$OUT_DIR/Chromium.app"
run codesign --verify --deep --strict --verbose=2 "$OUT_DIR/Chromium.app"
