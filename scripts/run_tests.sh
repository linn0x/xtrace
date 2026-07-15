#!/usr/bin/env bash
# Run every repository test suite with a supported Python interpreter.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIN_MAJOR=3
MIN_MINOR=10

is_supported_python() {
  "$1" -c "import sys; raise SystemExit(not sys.version_info >= ($MIN_MAJOR, $MIN_MINOR))" \
    >/dev/null 2>&1
}

if [[ -n "${PYTHON_BIN:-}" ]]; then
  if ! is_supported_python "$PYTHON_BIN"; then
    echo "PYTHON_BIN must point to Python ${MIN_MAJOR}.${MIN_MINOR} or newer: $PYTHON_BIN" >&2
    exit 2
  fi
  PYTHON="$PYTHON_BIN"
else
  PYTHON=""
  for candidate in python3 python python3.14 python3.13 python3.12 python3.11 python3.10; do
    if command -v "$candidate" >/dev/null 2>&1 && is_supported_python "$candidate"; then
      PYTHON="$(command -v "$candidate")"
      break
    fi
  done
  if [[ -z "$PYTHON" ]]; then
    echo "Python ${MIN_MAJOR}.${MIN_MINOR}+ is required. Set PYTHON_BIN to its executable." >&2
    exit 2
  fi
fi

echo "Using $($PYTHON --version) at $PYTHON"
cd "$ROOT"
PYTHONDONTWRITEBYTECODE=1 "$PYTHON" -m unittest discover -s tests -v
(
  cd xtrace-launcher
  PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. "$PYTHON" -m unittest discover -s tests -v
)
npm --prefix xtrace-gui test
