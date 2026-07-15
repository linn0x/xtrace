#!/usr/bin/env bash
set -euo pipefail

# Applies the XTrace native patches onto a checked-out Chromium tree.
#   patches/0001-xtrace-native-logger.patch -> chromium/src        (Blink/Chrome/content)
#   patches/0002-xtrace-v8-vmp-hooks.patch  -> chromium/src/v8     (V8 builtins/runtime)
#
# Run scripts/bootstrap_chromium.sh first so the tree is synced to the pinned
# Chromium revision recorded in docs/chromium-build.md. The patches only apply
# cleanly against that revision.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/chromium/src"
PATCH_NATIVE="$ROOT/patches/0001-xtrace-native-logger.patch"
PATCH_V8="$ROOT/patches/0002-xtrace-v8-vmp-hooks.patch"

ensure_git_tree() {
  local tree="$1" label="$2"
  local top
  if ! top="$(git -C "$tree" rev-parse --show-toplevel 2>/dev/null)"; then
    echo "$label source not found at $tree. Run scripts/bootstrap_chromium.sh first." >&2
    exit 1
  fi
  if [[ "$(cd "$top" && pwd -P)" != "$(cd "$tree" && pwd -P)" ]]; then
    echo "$label source at $tree is not a standalone Git checkout. Run scripts/bootstrap_chromium.sh first." >&2
    exit 1
  fi
}

ensure_patch() {
  local patch="$1"
  if [[ ! -f "$patch" ]]; then
    echo "Patch file not found: $patch" >&2
    exit 1
  fi
}

preflight_one() {
  local tree="$1" patch="$2"
  if git -C "$tree" apply --check "$patch" 2>/dev/null; then
    echo "apply"
  elif git -C "$tree" apply --reverse --check "$patch" 2>/dev/null; then
    echo "applied"
  elif git -C "$tree" apply --3way --check "$patch" 2>/dev/null; then
    echo "merge"
  else
    echo "Patch cannot be applied to $tree: $patch" >&2
    git -C "$tree" apply --3way --check "$patch" >&2 || true
    exit 1
  fi
}

apply_one() {
  local tree="$1" patch="$2" mode="$3"
  echo "Applying $(basename "$patch") -> $tree"
  case "$mode" in
    apply)
      git -C "$tree" apply "$patch"
      ;;
    applied)
      echo "  already applied; skipping"
      ;;
    merge)
      echo "  clean apply failed; retrying with 3-way merge" >&2
      git -C "$tree" apply --3way "$patch"
      ;;
    *)
      echo "Internal error: unknown patch mode '$mode' for $patch" >&2
      exit 1
      ;;
  esac
}

ensure_git_tree "$SRC" "Chromium"
ensure_git_tree "$SRC/v8" "V8"
ensure_patch "$PATCH_NATIVE"
ensure_patch "$PATCH_V8"

NATIVE_MODE="$(preflight_one "$SRC" "$PATCH_NATIVE")"
V8_MODE="$(preflight_one "$SRC/v8" "$PATCH_V8")"

apply_one "$SRC" "$PATCH_NATIVE" "$NATIVE_MODE"
apply_one "$SRC/v8" "$PATCH_V8" "$V8_MODE"

echo "Patches applied. Next: scripts/gn_gen_xtrace.sh && scripts/build_chromium.sh"
