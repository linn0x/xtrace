#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHROMIUM="${CHROMIUM:-$ROOT_DIR/chromium/src/out/XTrace/Chromium.app}"
TARGET_URL="${1:-${TARGET_URL:-}}"
LOG_DIR="${LOG_DIR:-$ROOT_DIR/logs/generic-vmp}"
CAPTURE_SECONDS="${CAPTURE_SECONDS:-35}"
VIRTUAL_TIME_BUDGET="${VIRTUAL_TIME_BUDGET:-15000}"
TIMESTAMP="$(date -u +%Y%m%d_%H%M%S)"
SUMMARY_PATH="$LOG_DIR/vmp_summary_$TIMESTAMP.json"
SOURCE_SNIPPETS_PATH="$LOG_DIR/vmp_sources_$TIMESTAMP.json"

if [[ -z "$TARGET_URL" ]]; then
  echo "TARGET_URL or first positional URL is required" >&2
  exit 2
fi

mkdir -p "$LOG_DIR"

PYTHONPATH="$ROOT_DIR/xtrace-launcher" python3 -m xtrace_launcher run \
  --chromium "$CHROMIUM" \
  --url "$TARGET_URL" \
  --log-dir "$LOG_DIR" \
  --xtrace-categories reverse,fingerprint \
  --xtrace-capture-values full \
  --xtrace-capture-assets summary \
  --capture-seconds "$CAPTURE_SECONDS" \
  --extra-arg=--headless=new \
  --extra-arg=--disable-gpu \
  --extra-arg=--mute-audio \
  --extra-arg=--window-size=1365,900 \
  --extra-arg=--lang=en-US \
  --extra-arg=--virtual-time-budget="$VIRTUAL_TIME_BUDGET"

TRACE_PATH="$(ls -t "$LOG_DIR"/trace_*.ndjson | head -1)"
python3 "$ROOT_DIR/scripts/analyze_vmp_trace.py" \
  "$TRACE_PATH" \
  --profile generic-vmp \
  --json-output "$SUMMARY_PATH" \
  --source-snippets-output "$SOURCE_SNIPPETS_PATH"
