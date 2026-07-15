#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPOT_TOOLS="$ROOT/depot_tools"
CHROMIUM_ROOT="$ROOT/chromium"
# Base revision the XTrace patches were generated against. The patches only
# apply cleanly against this exact revision (see docs/chromium-build.md).
CHROMIUM_REVISION="${CHROMIUM_REVISION:-73088b4e50b1dc69eaa0bdb14a8e4592813174fd}"

if ! xcode-select -p >/dev/null 2>&1; then
  echo "Xcode command line tools are not selected. Run: xcode-select --install" >&2
  exit 1
fi

if [[ ! -d "$DEPOT_TOOLS/.git" ]]; then
  git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git "$DEPOT_TOOLS"
else
  git -C "$DEPOT_TOOLS" pull --ff-only
fi

export PATH="$DEPOT_TOOLS:$PATH"
mkdir -p "$CHROMIUM_ROOT"
cd "$CHROMIUM_ROOT"

if ! git -C src rev-parse --git-dir >/dev/null 2>&1; then
  if [[ -e src ]]; then
    echo "Existing path is not a Chromium Git checkout: $CHROMIUM_ROOT/src" >&2
    exit 1
  fi
  fetch --nohooks chromium
fi

cd "$CHROMIUM_ROOT/src"
# Pin to the exact revision the patches target, then sync DEPS (incl. V8) to match.
git fetch --tags origin
git checkout --detach "$CHROMIUM_REVISION"
gclient sync -D --revision "src@$CHROMIUM_REVISION"
gclient runhooks

echo "Chromium source is ready at $CHROMIUM_ROOT/src (pinned to $CHROMIUM_REVISION)"
echo "Next: scripts/apply_patches.sh"
