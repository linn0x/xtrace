#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUI_DIR="$ROOT/xtrace-gui"
ELECTRON_APP="$GUI_DIR/node_modules/electron/dist/Electron.app"

if [[ ! -d "$ELECTRON_APP" ]]; then
  echo "Electron.app not found: $ELECTRON_APP" >&2
  echo "Run: cd $GUI_DIR && npm install" >&2
  exit 1
fi

if [[ "${1:-}" == "--restart" ]]; then
  pgrep -f "Electron.app/Contents/MacOS/Electron $GUI_DIR" |
    xargs -r kill 2>/dev/null || true
  sleep 1
elif pgrep -f "Electron.app/Contents/MacOS/Electron $GUI_DIR" >/dev/null; then
  echo "XTrace GUI is already running."
  exit 0
fi

open -n "$ELECTRON_APP" --args "$GUI_DIR"
echo "XTrace GUI launch requested."
