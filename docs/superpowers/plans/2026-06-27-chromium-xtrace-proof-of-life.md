# Chromium XTrace Proof Of Life Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first macOS Chromium XTrace proof of life: repeatable Chromium checkout/build helpers, a CLI launcher, a local fingerprint smoke page, a trace validator, and a minimal native Blink patch that writes NDJSON events for Canvas and Crypto APIs.

**Architecture:** The first milestone uses native Blink instrumentation and a temporary renderer-side NDJSON writer controlled by `XTRACE_ENABLE=1` and `XTRACE_FILE=/absolute/path.ndjson`. This proves C++-level tracing quickly before the later browser-process/Mojo writer replaces direct renderer file writes. The CLI launcher owns per-run profile/log paths and starts the patched Chromium with the required environment.

**Tech Stack:** macOS, Chromium/depot_tools/GN/Ninja, C++ in Blink, Python 3 standard library, POSIX shell.

---

## Scope

This plan implements Milestones 1, 3, 5, and part of 6 from the design spec. It also prepares Milestone 2 by adding build scripts, but the actual Chromium checkout and build may take hours and can fail on local Xcode/network/disk conditions.

This plan intentionally does not implement the final Mojo/browser-process writer or GUI. Those should be separate follow-up plans after this proof of life emits native events.

## File Structure

- Create `/path/to/xtrace/scripts/bootstrap_chromium.sh`: install or update `depot_tools`, fetch Chromium, and run hooks.
- Create `/path/to/xtrace/scripts/gn_gen_xtrace.sh`: generate `out/XTrace` build files.
- Create `/path/to/xtrace/scripts/build_chromium.sh`: build `chrome`.
- Modify `/path/to/xtrace/.gitignore`: ignore `depot_tools/`, runtime profiles, and generated trace files.
- Create `/path/to/xtrace/xtrace-launcher/xtrace_launcher/cli.py`: CLI launcher and command builder.
- Create `/path/to/xtrace/xtrace-launcher/xtrace_launcher/__init__.py`: package marker and version.
- Create `/path/to/xtrace/xtrace-launcher/xtrace_launcher/__main__.py`: `python -m xtrace_launcher` entrypoint.
- Create `/path/to/xtrace/xtrace-launcher/tests/test_cli.py`: unit tests for launcher path and command behavior.
- Create `/path/to/xtrace/test-pages/fingerprint-smoke.html`: local page that calls the traced APIs.
- Create `/path/to/xtrace/scripts/serve_test_page.py`: local static test server.
- Create `/path/to/xtrace/scripts/validate_trace.py`: NDJSON parser and expected API checker.
- Create `/path/to/xtrace/tests/test_validate_trace.py`: unit tests for validator behavior.
- Create in Chromium checkout `/path/to/xtrace/chromium/src/third_party/blink/renderer/platform/xtrace/xtrace_logger.h`: temporary native logger API.
- Create in Chromium checkout `/path/to/xtrace/chromium/src/third_party/blink/renderer/platform/xtrace/xtrace_logger.cc`: temporary environment-controlled NDJSON writer.
- Modify in Chromium checkout `/path/to/xtrace/chromium/src/third_party/blink/renderer/platform/BUILD.gn`: add XTrace logger to Blink platform target.
- Modify in Chromium checkout `/path/to/xtrace/chromium/src/third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc`: log `fillText` and `getImageData`.
- Modify in Chromium checkout `/path/to/xtrace/chromium/src/third_party/blink/renderer/core/html/canvas/html_canvas_element.cc`: log `toDataURL`.
- Modify in Chromium checkout `/path/to/xtrace/chromium/src/third_party/blink/renderer/modules/crypto/crypto.cc`: log `getRandomValues`.
- Create `/path/to/xtrace/patches/0001-xtrace-native-logger.patch`: exported Chromium patch after compile succeeds.
- Create `/path/to/xtrace/docs/chromium-build.md`: exact build and smoke-test notes from this run.

---

### Task 1: Build Helper Scripts

**Files:**
- Modify: `/path/to/xtrace/.gitignore`
- Create: `/path/to/xtrace/scripts/bootstrap_chromium.sh`
- Create: `/path/to/xtrace/scripts/gn_gen_xtrace.sh`
- Create: `/path/to/xtrace/scripts/build_chromium.sh`

- [ ] **Step 1: Extend `.gitignore`**

Set `/path/to/xtrace/.gitignore` to:

```gitignore
chromium/
depot_tools/
logs/
profiles/
*.log
*.ndjson
*.tmp
.DS_Store
out/
node_modules/
__pycache__/
.pytest_cache/
```

- [ ] **Step 2: Create Chromium bootstrap script**

Create `/path/to/xtrace/scripts/bootstrap_chromium.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPOT_TOOLS="$ROOT/depot_tools"
CHROMIUM_ROOT="$ROOT/chromium"

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

if [[ ! -d src/.git ]]; then
  fetch --nohooks chromium
fi

cd "$CHROMIUM_ROOT/src"
gclient runhooks

echo "Chromium source is ready at $CHROMIUM_ROOT/src"
```

- [ ] **Step 3: Create GN generation script**

Create `/path/to/xtrace/scripts/gn_gen_xtrace.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPOT_TOOLS="$ROOT/depot_tools"
SRC="$ROOT/chromium/src"

if [[ ! -d "$SRC" ]]; then
  echo "Chromium source not found at $SRC. Run scripts/bootstrap_chromium.sh first." >&2
  exit 1
fi

export PATH="$DEPOT_TOOLS:$PATH"
cd "$SRC"

gn gen out/XTrace --args='
is_debug=true
is_component_build=true
symbol_level=1
blink_symbol_level=1
treat_warnings_as_errors=false
'

echo "Generated Chromium build files at $SRC/out/XTrace"
```

- [ ] **Step 4: Create Chromium build script**

Create `/path/to/xtrace/scripts/build_chromium.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPOT_TOOLS="$ROOT/depot_tools"
SRC="$ROOT/chromium/src"

if [[ ! -d "$SRC/out/XTrace" ]]; then
  echo "Build directory not found. Run scripts/gn_gen_xtrace.sh first." >&2
  exit 1
fi

export PATH="$DEPOT_TOOLS:$PATH"
cd "$SRC"
autoninja -C out/XTrace chrome
```

- [ ] **Step 5: Make scripts executable**

Run:

```bash
chmod +x /path/to/xtrace/scripts/bootstrap_chromium.sh \
  /path/to/xtrace/scripts/gn_gen_xtrace.sh \
  /path/to/xtrace/scripts/build_chromium.sh
```

Expected: command exits with status 0.

- [ ] **Step 6: Syntax-check shell scripts**

Run:

```bash
bash -n /path/to/xtrace/scripts/bootstrap_chromium.sh
bash -n /path/to/xtrace/scripts/gn_gen_xtrace.sh
bash -n /path/to/xtrace/scripts/build_chromium.sh
```

Expected: all commands exit with status 0 and print no syntax errors.

- [ ] **Step 7: Commit build helper scripts**

Run:

```bash
cd /path/to/xtrace
git add .gitignore scripts/bootstrap_chromium.sh scripts/gn_gen_xtrace.sh scripts/build_chromium.sh
git commit -m "chore: add Chromium build helpers"
```

Expected: commit succeeds.

---

### Task 2: CLI Launcher

**Files:**
- Create: `/path/to/xtrace/xtrace-launcher/xtrace_launcher/__init__.py`
- Create: `/path/to/xtrace/xtrace-launcher/xtrace_launcher/__main__.py`
- Create: `/path/to/xtrace/xtrace-launcher/xtrace_launcher/cli.py`
- Create: `/path/to/xtrace/xtrace-launcher/tests/test_cli.py`

- [ ] **Step 1: Create failing launcher tests**

Create `/path/to/xtrace/xtrace-launcher/tests/test_cli.py`:

```python
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from xtrace_launcher.cli import build_chromium_command, make_log_path, resolve_chromium_executable


class LauncherTests(unittest.TestCase):
    def test_make_log_path_uses_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            now = datetime(2026, 6, 27, 12, 34, 56, tzinfo=timezone.utc)
            path = make_log_path(Path(tmp), now=now)
            self.assertEqual(path.name, "trace_20260627_123456.ndjson")
            self.assertEqual(path.parent, Path(tmp))

    def test_resolve_chromium_app_executable(self):
        app = Path("/tmp/Chromium.app")
        expected = app / "Contents" / "MacOS" / "Chromium"
        self.assertEqual(resolve_chromium_executable(app), expected)

    def test_build_command_sets_xtrace_flags_and_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            chromium = Path("/tmp/Chromium.app")
            log_dir = Path(tmp)
            now = datetime(2026, 6, 27, 12, 34, 56, tzinfo=timezone.utc)
            command, env, log_path, profile_path = build_chromium_command(
                chromium=chromium,
                url="http://127.0.0.1:8000/fingerprint-smoke.html",
                log_dir=log_dir,
                now=now,
            )

            self.assertEqual(command[0], "/tmp/Chromium.app/Contents/MacOS/Chromium")
            self.assertIn("--xtrace-enable", command)
            self.assertIn(f"--xtrace-file={log_path}", command)
            self.assertIn(f"--user-data-dir={profile_path}", command)
            self.assertEqual(command[-1], "http://127.0.0.1:8000/fingerprint-smoke.html")
            self.assertEqual(env["XTRACE_ENABLE"], "1")
            self.assertEqual(env["XTRACE_FILE"], os.fspath(log_path))
            self.assertTrue(profile_path.name.startswith("profile_20260627_123456"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run launcher tests and verify failure**

Run:

```bash
cd /path/to/xtrace/xtrace-launcher
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'xtrace_launcher'`.

- [ ] **Step 3: Create launcher package marker**

Create `/path/to/xtrace/xtrace-launcher/xtrace_launcher/__init__.py`:

```python
__version__ = "0.1.0"
```

- [ ] **Step 4: Create launcher CLI implementation**

Create `/path/to/xtrace/xtrace-launcher/xtrace_launcher/cli.py`:

```python
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def make_log_path(log_dir: Path, now: datetime | None = None) -> Path:
    timestamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%d_%H%M%S")
    return log_dir / f"trace_{timestamp}.ndjson"


def resolve_chromium_executable(chromium: Path) -> Path:
    if chromium.suffix == ".app":
        return chromium / "Contents" / "MacOS" / "Chromium"
    return chromium


def build_chromium_command(
    *,
    chromium: Path,
    url: str,
    log_dir: Path,
    now: datetime | None = None,
    extra_args: Iterable[str] = (),
) -> tuple[list[str], dict[str, str], Path, Path]:
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%d_%H%M%S")
    log_path = make_log_path(log_dir, now=now)
    profile_path = log_dir / "profiles" / f"profile_{timestamp}"
    profile_path.mkdir(parents=True, exist_ok=True)

    executable = resolve_chromium_executable(chromium)
    command = [
        os.fspath(executable),
        "--xtrace-enable",
        f"--xtrace-file={log_path}",
        f"--user-data-dir={profile_path}",
        "--no-first-run",
        "--no-default-browser-check",
        *list(extra_args),
        url,
    ]

    env = os.environ.copy()
    env["XTRACE_ENABLE"] = "1"
    env["XTRACE_FILE"] = os.fspath(log_path)
    return command, env, log_path, profile_path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="xtrace-launcher")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="start a patched Chromium with XTrace enabled")
    run.add_argument("--chromium", required=True, type=Path, help="path to Chromium.app or Chromium executable")
    run.add_argument("--url", required=True, help="URL to open")
    run.add_argument("--log-dir", required=True, type=Path, help="directory for NDJSON logs")
    run.add_argument("--extra-arg", action="append", default=[], help="extra Chromium argument; may be repeated")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "run":
        command, env, log_path, profile_path = build_chromium_command(
            chromium=args.chromium,
            url=args.url,
            log_dir=args.log_dir,
            extra_args=args.extra_arg,
        )
        executable = Path(command[0])
        if not executable.exists():
            print(f"Chromium executable not found: {executable}", file=sys.stderr)
            return 2
        print(f"XTrace log: {log_path}")
        print(f"XTrace profile: {profile_path}")
        process = subprocess.Popen(command, env=env)
        return process.wait()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Create module entrypoint**

Create `/path/to/xtrace/xtrace-launcher/xtrace_launcher/__main__.py`:

```python
from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 6: Run launcher tests and verify pass**

Run:

```bash
cd /path/to/xtrace/xtrace-launcher
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

Expected: 3 tests pass.

- [ ] **Step 7: Commit CLI launcher**

Run:

```bash
cd /path/to/xtrace
git add xtrace-launcher
git commit -m "feat: add XTrace CLI launcher"
```

Expected: commit succeeds.

---

### Task 3: Smoke Page And Trace Validator

**Files:**
- Create: `/path/to/xtrace/test-pages/fingerprint-smoke.html`
- Create: `/path/to/xtrace/scripts/serve_test_page.py`
- Create: `/path/to/xtrace/scripts/validate_trace.py`
- Create: `/path/to/xtrace/tests/test_validate_trace.py`

- [ ] **Step 1: Create failing validator tests**

Create `/path/to/xtrace/tests/test_validate_trace.py`:

```python
import tempfile
import unittest
from pathlib import Path

from scripts.validate_trace import TraceValidationError, load_events, validate_trace


class ValidateTraceTests(unittest.TestCase):
    def test_load_events_rejects_malformed_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.ndjson"
            path.write_text('{"api":"CanvasRenderingContext2D.fillText"}\nnot-json\n', encoding="utf-8")
            with self.assertRaises(TraceValidationError) as ctx:
                load_events(path)
            self.assertIn("line 2", str(ctx.exception))

    def test_validate_trace_finds_expected_apis(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(
                    [
                        '{"t":"call","api":"CanvasRenderingContext2D.fillText","args":[]}',
                        '{"t":"call","api":"CanvasRenderingContext2D.getImageData","args":[]}',
                        '{"t":"call","api":"HTMLCanvasElement.toDataURL","args":[]}',
                        '{"t":"call","api":"Crypto.getRandomValues","args":[]}',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            validate_trace(
                path,
                expected=[
                    "CanvasRenderingContext2D.fillText",
                    "CanvasRenderingContext2D.getImageData",
                    "HTMLCanvasElement.toDataURL",
                    "Crypto.getRandomValues",
                ],
            )

    def test_validate_trace_reports_missing_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text('{"t":"call","api":"Crypto.getRandomValues","args":[]}\n', encoding="utf-8")
            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(path, expected=["CanvasRenderingContext2D.fillText"])
            self.assertIn("Missing expected APIs", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run validator tests and verify failure**

Run:

```bash
cd /path/to/xtrace
python3 -m unittest discover -s tests -v
```

Expected: FAIL with `ModuleNotFoundError` or import failure for `scripts.validate_trace`.

- [ ] **Step 3: Create test page**

Create `/path/to/xtrace/test-pages/fingerprint-smoke.html`:

```html
<!doctype html>
<meta charset="utf-8">
<title>XTrace Fingerprint Smoke</title>
<canvas id="c" width="240" height="80"></canvas>
<pre id="out"></pre>
<script>
const out = document.getElementById("out");
const canvas = document.getElementById("c");
const ctx = canvas.getContext("2d");

ctx.font = "18px sans-serif";
ctx.fillStyle = "#123456";
ctx.fillText("XTrace canvas smoke", 8, 32);
const imageData = ctx.getImageData(0, 0, 32, 32);
const dataUrl = canvas.toDataURL("image/png");

const random = new Uint8Array(16);
crypto.getRandomValues(random);

out.textContent = JSON.stringify({
  imageDataLength: imageData.data.length,
  dataUrlPrefix: dataUrl.slice(0, 22),
  randomBytes: Array.from(random).length
}, null, 2);
</script>
```

- [ ] **Step 4: Create local test server**

Create `/path/to/xtrace/scripts/serve_test_page.py`:

```python
from __future__ import annotations

import argparse
import functools
import http.server
import socketserver
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "test-pages",
    )
    args = parser.parse_args()

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=args.directory)
    with socketserver.TCPServer(("127.0.0.1", args.port), handler) as server:
        print(f"Serving {args.directory} at http://127.0.0.1:{args.port}/")
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Create trace validator implementation**

Create `/path/to/xtrace/scripts/validate_trace.py`:

```python
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable


DEFAULT_EXPECTED_APIS = [
    "CanvasRenderingContext2D.fillText",
    "CanvasRenderingContext2D.getImageData",
    "HTMLCanvasElement.toDataURL",
    "Crypto.getRandomValues",
]


class TraceValidationError(Exception):
    pass


def load_events(path: Path) -> list[dict]:
    events: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                event = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise TraceValidationError(f"Malformed JSON on line {line_number}: {exc}") from exc
            if not isinstance(event, dict):
                raise TraceValidationError(f"Expected object on line {line_number}")
            events.append(event)
    if not events:
        raise TraceValidationError(f"No events found in {path}")
    return events


def validate_trace(path: Path, expected: Iterable[str] = DEFAULT_EXPECTED_APIS) -> None:
    events = load_events(path)
    seen = {event.get("api") for event in events}
    missing = [api for api in expected if api not in seen]
    if missing:
        raise TraceValidationError("Missing expected APIs: " + ", ".join(missing))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path)
    parser.add_argument("--expect", action="append", default=[])
    args = parser.parse_args(argv)

    expected = args.expect or DEFAULT_EXPECTED_APIS
    try:
        validate_trace(args.trace, expected=expected)
    except TraceValidationError as exc:
        print(f"FAIL: {exc}")
        return 1
    print(f"PASS: {args.trace}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 6: Run validator tests and verify pass**

Run:

```bash
cd /path/to/xtrace
python3 -m unittest discover -s tests -v
```

Expected: 3 tests pass.

- [ ] **Step 7: Syntax-check server script**

Run:

```bash
python3 -m py_compile /path/to/xtrace/scripts/serve_test_page.py
python3 -m py_compile /path/to/xtrace/scripts/validate_trace.py
```

Expected: both commands exit with status 0.

- [ ] **Step 8: Commit smoke page and validator**

Run:

```bash
cd /path/to/xtrace
git add scripts/serve_test_page.py scripts/validate_trace.py test-pages/fingerprint-smoke.html tests/test_validate_trace.py
git commit -m "test: add trace smoke page and validator"
```

Expected: commit succeeds.

---

### Task 4: Fetch Chromium And Verify Patch Targets

**Files:**
- Uses: `/path/to/xtrace/scripts/bootstrap_chromium.sh`
- Uses: `/path/to/xtrace/scripts/gn_gen_xtrace.sh`
- Reads: `/path/to/xtrace/chromium/src/third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc`
- Reads: `/path/to/xtrace/chromium/src/third_party/blink/renderer/core/html/canvas/html_canvas_element.cc`
- Reads: `/path/to/xtrace/chromium/src/third_party/blink/renderer/modules/crypto/crypto.cc`
- Reads: `/path/to/xtrace/chromium/src/third_party/blink/renderer/platform/BUILD.gn`

- [ ] **Step 1: Fetch Chromium source**

Run:

```bash
/path/to/xtrace/scripts/bootstrap_chromium.sh
```

Expected: `/path/to/xtrace/chromium/src/.git` exists and `gclient runhooks` completes. If network fails, rerun the same command after connectivity is restored.

- [ ] **Step 2: Verify current Chromium revision**

Run:

```bash
git -C /path/to/xtrace/chromium/src rev-parse HEAD
```

Expected: prints a Chromium commit hash. Save this hash for `/path/to/xtrace/docs/chromium-build.md` in Task 8.

- [ ] **Step 3: Verify patch target functions still exist**

Run:

```bash
rg -n "BaseRenderingContext2D::fillText|BaseRenderingContext2D::getImageData" \
  /path/to/xtrace/chromium/src/third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc
rg -n "HTMLCanvasElement::toDataURL" \
  /path/to/xtrace/chromium/src/third_party/blink/renderer/core/html/canvas/html_canvas_element.cc
rg -n "Crypto::getRandomValues" \
  /path/to/xtrace/chromium/src/third_party/blink/renderer/modules/crypto/crypto.cc
rg -n "component\\(\"platform\"\\)|sources = \\[" \
  /path/to/xtrace/chromium/src/third_party/blink/renderer/platform/BUILD.gn
```

Expected: each `rg` command prints at least one match.

- [ ] **Step 4: Generate build files before patching**

Run:

```bash
/path/to/xtrace/scripts/gn_gen_xtrace.sh
```

Expected: `/path/to/xtrace/chromium/src/out/XTrace/build.ninja` exists.

- [ ] **Step 5: Commit current non-Chromium state**

Run:

```bash
cd /path/to/xtrace
git status --short
```

Expected: no tracked project changes from the Chromium checkout because `chromium/` is ignored.

---

### Task 5: Native Blink Logger Patch

**Files:**
- Create: `/path/to/xtrace/chromium/src/third_party/blink/renderer/platform/xtrace/xtrace_logger.h`
- Create: `/path/to/xtrace/chromium/src/third_party/blink/renderer/platform/xtrace/xtrace_logger.cc`
- Modify: `/path/to/xtrace/chromium/src/third_party/blink/renderer/platform/BUILD.gn`
- Modify: `/path/to/xtrace/chromium/src/third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc`
- Modify: `/path/to/xtrace/chromium/src/third_party/blink/renderer/core/html/canvas/html_canvas_element.cc`
- Modify: `/path/to/xtrace/chromium/src/third_party/blink/renderer/modules/crypto/crypto.cc`

- [ ] **Step 1: Create XTrace logger directory**

Run:

```bash
mkdir -p /path/to/xtrace/chromium/src/third_party/blink/renderer/platform/xtrace
```

Expected: command exits with status 0.

- [ ] **Step 2: Create XTrace logger header**

Create `/path/to/xtrace/chromium/src/third_party/blink/renderer/platform/xtrace/xtrace_logger.h`:

```cpp
// Copyright 2026 The XTrace Authors
// Use of this source code is governed by a BSD-style license that can be
// found in Chromium's LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_PLATFORM_XTRACE_XTRACE_LOGGER_H_
#define THIRD_PARTY_BLINK_RENDERER_PLATFORM_XTRACE_XTRACE_LOGGER_H_

#include "third_party/blink/renderer/platform/platform_export.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class PLATFORM_EXPORT XTraceLogger {
 public:
  static bool Enabled();
  static void LogCall(const char* api, const String& args_json);
  static String QuoteJson(const String& value);
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_PLATFORM_XTRACE_XTRACE_LOGGER_H_
```

- [ ] **Step 3: Create XTrace logger implementation**

Create `/path/to/xtrace/chromium/src/third_party/blink/renderer/platform/xtrace/xtrace_logger.cc`:

```cpp
// Copyright 2026 The XTrace Authors
// Use of this source code is governed by a BSD-style license that can be
// found in Chromium's LICENSE file.

#include "third_party/blink/renderer/platform/xtrace/xtrace_logger.h"

#include <memory>
#include <string>

#include "base/environment.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/process/process_handle.h"
#include "base/strings/string_number_conversions.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"

namespace blink {

namespace {

bool ReadTraceFilePath(base::FilePath* path) {
  std::unique_ptr<base::Environment> env = base::Environment::Create();
  std::string enabled;
  if (!env->GetVar("XTRACE_ENABLE", &enabled) || enabled != "1") {
    return false;
  }

  std::string trace_file;
  if (!env->GetVar("XTRACE_FILE", &trace_file) || trace_file.empty()) {
    return false;
  }

  *path = base::FilePath::FromUTF8Unsafe(trace_file);
  return true;
}

std::string EscapeJsonUtf8(const std::string& input) {
  std::string escaped;
  escaped.reserve(input.size() + 8);
  for (unsigned char c : input) {
    switch (c) {
      case '"':
        escaped += "\\\"";
        break;
      case '\\':
        escaped += "\\\\";
        break;
      case '\b':
        escaped += "\\b";
        break;
      case '\f':
        escaped += "\\f";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        if (c < 0x20) {
          escaped += "\\u00";
          const char* hex = "0123456789abcdef";
          escaped.push_back(hex[(c >> 4) & 0x0f]);
          escaped.push_back(hex[c & 0x0f]);
        } else {
          escaped.push_back(static_cast<char>(c));
        }
    }
  }
  return escaped;
}

}  // namespace

bool XTraceLogger::Enabled() {
  base::FilePath trace_file;
  return ReadTraceFilePath(&trace_file);
}

String XTraceLogger::QuoteJson(const String& value) {
  return String::FromUTF8("\"" + EscapeJsonUtf8(value.Utf8()) + "\"");
}

void XTraceLogger::LogCall(const char* api, const String& args_json) {
  base::FilePath trace_file;
  if (!ReadTraceFilePath(&trace_file)) {
    return;
  }

  const int64_t ts = base::Time::Now().InMillisecondsSinceUnixEpoch() * 1000;
  std::string line;
  line.reserve(256 + args_json.length());
  line += "{\"t\":\"call\"";
  line += ",\"ts\":" + base::NumberToString(ts);
  line += ",\"pid\":" + base::NumberToString(base::GetCurrentProcId());
  line += ",\"tid\":" + base::NumberToString(base::PlatformThread::CurrentId().raw());
  line += ",\"api\":\"";
  line += EscapeJsonUtf8(api);
  line += "\"";
  line += ",\"args\":";
  line += args_json.Utf8();
  line += ",\"stack\":[]";
  line += "}\n";

  base::AppendToFile(trace_file, line);
}

}  // namespace blink
```

- [ ] **Step 4: Add logger files to Blink platform build**

Edit `/path/to/xtrace/chromium/src/third_party/blink/renderer/platform/BUILD.gn` inside the `component("platform")` `sources = [` list. Add these entries in lexical order near the other platform subdirectories:

```gn
    "xtrace/xtrace_logger.cc",
    "xtrace/xtrace_logger.h",
```

Run:

```bash
rg -n "xtrace_logger" /path/to/xtrace/chromium/src/third_party/blink/renderer/platform/BUILD.gn
```

Expected: both new file names are printed.

- [ ] **Step 5: Instrument Canvas 2D**

Edit `/path/to/xtrace/chromium/src/third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc`.

Add this include near the other Blink platform includes:

```cpp
#include "third_party/blink/renderer/platform/xtrace/xtrace_logger.h"
```

In `BaseRenderingContext2D::getImageData(double sx, double sy, double sw, double sh, ExceptionState& exception_state)`, add this as the first statement:

```cpp
  XTraceLogger::LogCall(
      "CanvasRenderingContext2D.getImageData",
      String::Format("[%.17g,%.17g,%.17g,%.17g]", sx, sy, sw, sh));
```

In `BaseRenderingContext2D::getImageData(double sx, double sy, double sw, double sh, const ImageDataSettings* image_data_settings, ExceptionState& exception_state)`, add this as the first statement:

```cpp
  XTraceLogger::LogCall(
      "CanvasRenderingContext2D.getImageData",
      String::Format("[%.17g,%.17g,%.17g,%.17g]", sx, sy, sw, sh));
```

In `BaseRenderingContext2D::fillText(const String& text, double x, double y)`, add this as the first statement:

```cpp
  XTraceLogger::LogCall(
      "CanvasRenderingContext2D.fillText",
      String::Format("[%s,%.17g,%.17g]",
                     XTraceLogger::QuoteJson(text).Utf8().c_str(), x, y));
```

In `BaseRenderingContext2D::fillText(const String& text, double x, double y, double max_width)`, add this as the first statement:

```cpp
  XTraceLogger::LogCall(
      "CanvasRenderingContext2D.fillText",
      String::Format("[%s,%.17g,%.17g,%.17g]",
                     XTraceLogger::QuoteJson(text).Utf8().c_str(), x, y,
                     max_width));
```

Run:

```bash
rg -n "XTraceLogger" /path/to/xtrace/chromium/src/third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc
```

Expected: the include and four call sites are printed.

- [ ] **Step 6: Instrument canvas export**

Edit `/path/to/xtrace/chromium/src/third_party/blink/renderer/core/html/canvas/html_canvas_element.cc`.

Add this include near the other Blink platform includes:

```cpp
#include "third_party/blink/renderer/platform/xtrace/xtrace_logger.h"
```

In `HTMLCanvasElement::toDataURL(const String& mime_type, const ScriptValue& quality_argument, ExceptionState& exception_state) const`, add this as the first statement:

```cpp
  XTraceLogger::LogCall("HTMLCanvasElement.toDataURL",
                        String::Format("[%s]",
                                       XTraceLogger::QuoteJson(mime_type)
                                           .Utf8()
                                           .c_str()));
```

Run:

```bash
rg -n "XTraceLogger" /path/to/xtrace/chromium/src/third_party/blink/renderer/core/html/canvas/html_canvas_element.cc
```

Expected: the include and call site are printed.

- [ ] **Step 7: Instrument Crypto**

Edit `/path/to/xtrace/chromium/src/third_party/blink/renderer/modules/crypto/crypto.cc`.

Add this include near the other Blink platform includes:

```cpp
#include "third_party/blink/renderer/platform/xtrace/xtrace_logger.h"
```

In `Crypto::getRandomValues(NotShared<DOMArrayBufferView> array, ExceptionState& exception_state)`, add this immediately after `DCHECK(array);`:

```cpp
  XTraceLogger::LogCall(
      "Crypto.getRandomValues",
      String::Format("[\"%s\",%zu]", array->TypeName(), array->byteLength()));
```

Run:

```bash
rg -n "XTraceLogger" /path/to/xtrace/chromium/src/third_party/blink/renderer/modules/crypto/crypto.cc
```

Expected: the include and call site are printed.

- [ ] **Step 8: Format changed Chromium files**

Run:

```bash
cd /path/to/xtrace/chromium/src
git cl format --js --full third_party/blink/renderer/platform/xtrace/xtrace_logger.h \
  third_party/blink/renderer/platform/xtrace/xtrace_logger.cc \
  third_party/blink/renderer/platform/BUILD.gn \
  third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc \
  third_party/blink/renderer/core/html/canvas/html_canvas_element.cc \
  third_party/blink/renderer/modules/crypto/crypto.cc
```

Expected: command exits with status 0. If `git cl format` is unavailable, run:

```bash
cd /path/to/xtrace/chromium/src
git clang-format -- third_party/blink/renderer/platform/xtrace/xtrace_logger.h \
  third_party/blink/renderer/platform/xtrace/xtrace_logger.cc \
  third_party/blink/renderer/platform/BUILD.gn \
  third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc \
  third_party/blink/renderer/core/html/canvas/html_canvas_element.cc \
  third_party/blink/renderer/modules/crypto/crypto.cc
```

Expected: fallback formatting command exits with status 0.

---

### Task 6: Build Patched Chromium

**Files:**
- Uses: `/path/to/xtrace/scripts/build_chromium.sh`
- Uses: `/path/to/xtrace/chromium/src/out/XTrace`

- [ ] **Step 1: Regenerate build files after patch**

Run:

```bash
/path/to/xtrace/scripts/gn_gen_xtrace.sh
```

Expected: GN generation exits with status 0.

- [ ] **Step 2: Build patched Chromium**

Run:

```bash
/path/to/xtrace/scripts/build_chromium.sh
```

Expected: `autoninja` exits with status 0 and `/path/to/xtrace/chromium/src/out/XTrace/Chromium.app` exists.

- [ ] **Step 3: If the build fails, capture the exact first compiler error**

Run:

```bash
cd /path/to/xtrace/chromium/src
autoninja -C out/XTrace chrome 2>&1 | tee /path/to/xtrace/logs/chromium-build-failure.log
```

Expected if the build fails: `/path/to/xtrace/logs/chromium-build-failure.log` contains the compiler error. Fix only the first XTrace-related compiler error, then rerun Task 6 Step 2.

- [ ] **Step 4: Confirm the patched files are the only local Chromium source changes**

Run:

```bash
cd /path/to/xtrace/chromium/src
git status --short
```

Expected: output lists only the six XTrace patch files from Task 5.

---

### Task 7: Smoke Test Native Trace Output

**Files:**
- Uses: `/path/to/xtrace/test-pages/fingerprint-smoke.html`
- Uses: `/path/to/xtrace/scripts/serve_test_page.py`
- Uses: `/path/to/xtrace/xtrace-launcher/xtrace_launcher/cli.py`
- Uses: `/path/to/xtrace/scripts/validate_trace.py`
- Writes: `/path/to/xtrace/logs/trace_*.ndjson`

- [ ] **Step 1: Start local test server**

Run in one terminal:

```bash
cd /path/to/xtrace
python3 scripts/serve_test_page.py --port 8765
```

Expected: prints `Serving /path/to/xtrace/test-pages at http://127.0.0.1:8765/` and keeps running.

- [ ] **Step 2: Launch patched Chromium through XTrace launcher**

Run in another terminal:

```bash
cd /path/to/xtrace/xtrace-launcher
PYTHONPATH=. python3 -m xtrace_launcher run \
  --chromium /path/to/xtrace/chromium/src/out/XTrace/Chromium.app \
  --url http://127.0.0.1:8765/fingerprint-smoke.html \
  --log-dir /path/to/xtrace/logs
```

Expected: launcher prints `XTrace log: /path/to/xtrace/logs/trace_<timestamp>.ndjson`. After the page loads, close Chromium manually so the launcher exits.

- [ ] **Step 3: Inspect the newest trace**

Run:

```bash
latest="$(ls -t /path/to/xtrace/logs/trace_*.ndjson | head -1)"
wc -l "$latest"
sed -n '1,20p' "$latest"
```

Expected: at least four lines and visible `api` values for Canvas and Crypto calls.

- [ ] **Step 4: Validate expected events**

Run:

```bash
latest="\$(ls -t /path/to/xtrace/logs/trace_*.ndjson | head -1)"
python3 /path/to/xtrace/scripts/validate_trace.py "\$latest"
```

Expected: `PASS: /path/to/xtrace/logs/trace_<timestamp>.ndjson`.

- [ ] **Step 5: Confirm no trace is written when disabled**

Run:

```bash
rm -f /path/to/xtrace/logs/disabled.ndjson
XTRACE_ENABLE=0 XTRACE_FILE=/path/to/xtrace/logs/disabled.ndjson \
  /path/to/xtrace/chromium/src/out/XTrace/Chromium.app/Contents/MacOS/Chromium \
  --user-data-dir=/path/to/xtrace/logs/profile_disabled \
  --no-first-run \
  --no-default-browser-check \
  http://127.0.0.1:8765/fingerprint-smoke.html
test ! -s /path/to/xtrace/logs/disabled.ndjson
```

Expected: after closing Chromium, `test ! -s ...` exits with status 0.

---

### Task 8: Export Patch And Document Evidence

**Files:**
- Create: `/path/to/xtrace/patches/0001-xtrace-native-logger.patch`
- Create: `/path/to/xtrace/docs/chromium-build.md`
- Modify: `/path/to/xtrace/README.md`

- [ ] **Step 1: Export Chromium patch**

Run:

```bash
cd /path/to/xtrace/chromium/src
git diff -- third_party/blink/renderer/platform/xtrace/xtrace_logger.h \
  third_party/blink/renderer/platform/xtrace/xtrace_logger.cc \
  third_party/blink/renderer/platform/BUILD.gn \
  third_party/blink/renderer/modules/canvas/canvas2d/base_rendering_context_2d.cc \
  third_party/blink/renderer/core/html/canvas/html_canvas_element.cc \
  third_party/blink/renderer/modules/crypto/crypto.cc \
  > /path/to/xtrace/patches/0001-xtrace-native-logger.patch
```

Expected: patch file exists and is non-empty.

- [ ] **Step 2: Create build evidence document from actual command output**

Run:

```bash
revision="$(git -C /path/to/xtrace/chromium/src rev-parse HEAD)"
latest="$(ls -t /path/to/xtrace/logs/trace_*.ndjson | head -1)"
validator_output="$(python3 /path/to/xtrace/scripts/validate_trace.py "$latest")"

cat > /path/to/xtrace/docs/chromium-build.md <<EOF
# Chromium Build Notes

## Chromium Revision

$revision

## Build Commands

\`\`\`bash
/path/to/xtrace/scripts/bootstrap_chromium.sh
/path/to/xtrace/scripts/gn_gen_xtrace.sh
/path/to/xtrace/scripts/build_chromium.sh
\`\`\`

## Smoke Test Commands

\`\`\`bash
cd /path/to/xtrace
python3 scripts/serve_test_page.py --port 8765
\`\`\`

\`\`\`bash
cd /path/to/xtrace/xtrace-launcher
PYTHONPATH=. python3 -m xtrace_launcher run \
  --chromium /path/to/xtrace/chromium/src/out/XTrace/Chromium.app \
  --url http://127.0.0.1:8765/fingerprint-smoke.html \
  --log-dir /path/to/xtrace/logs
\`\`\`

\`\`\`bash
latest="\$(ls -t /path/to/xtrace/logs/trace_*.ndjson | head -1)"
python3 /path/to/xtrace/scripts/validate_trace.py "\$latest"
\`\`\`

## Observed Result

$validator_output
EOF
```

Expected: `/path/to/xtrace/docs/chromium-build.md` contains the Chromium revision and validator output from this run.

- [ ] **Step 3: Update README status**

Modify `/path/to/xtrace/README.md` to:

```markdown
# XTrace

XTrace is a macOS-focused Chromium native tracing experiment for authorized fingerprint research and defensive JavaScript analysis.

The intended direction is close to RuyiTrace: native browser instrumentation, NDJSON runtime logs, and a launcher that starts a patched browser with a clean profile.

Current status: Chromium proof-of-life plan is ready. The first implementation target is native Blink logging for Canvas and Crypto calls.

## Documents

- Design: `docs/superpowers/specs/2026-06-27-chromium-xtrace-design.md`
- Implementation plan: `docs/superpowers/plans/2026-06-27-chromium-xtrace-proof-of-life.md`
- Build notes: `docs/chromium-build.md`
```

- [ ] **Step 4: Run local tests again**

Run:

```bash
cd /path/to/xtrace
python3 -m unittest discover -s tests -v
cd /path/to/xtrace/xtrace-launcher
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

Expected: all Python tests pass.

- [ ] **Step 5: Commit project-side implementation artifacts**

Run:

```bash
cd /path/to/xtrace
git add README.md docs/chromium-build.md patches/0001-xtrace-native-logger.patch
git commit -m "docs: record Chromium XTrace proof of life"
```

Expected: commit succeeds.

---

## Self-Review Checklist

- Spec coverage: This plan covers project skeleton, build helpers, test page, launcher, first native trace events, NDJSON validation, and patch export. It intentionally leaves Mojo/browser-process logging, GUI, and wider API coverage for follow-up plans.
- Placeholder scan: The plan avoids static evidence placeholders by generating `/path/to/xtrace/docs/chromium-build.md` from live command output in Task 8.
- Type consistency: Launcher functions return `(command, env, log_path, profile_path)` and tests assert that same tuple shape. Validator raises `TraceValidationError` consistently. C++ instrumentation uses `XTraceLogger::LogCall` and `XTraceLogger::QuoteJson` as defined in the logger header.
