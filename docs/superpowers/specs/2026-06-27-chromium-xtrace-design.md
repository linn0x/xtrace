# Chromium XTrace Design

## Goal

Build a macOS research tool that is as close as practical to RuyiTrace, but based on Chromium instead of Firefox. XTrace should collect browser runtime fingerprint API activity from native Chromium/Blink code paths, emit NDJSON logs, and provide a controlled launcher for repeatable security research and defensive analysis.

This project is for authorized academic research, security education, and defensive analysis. It must not include functionality whose purpose is to bypass a site's terms, evade production risk controls, or generate stealth fingerprint spoofing payloads.

## Non-Goals

- No JavaScript hook based tracer as the primary implementation.
- No automated bypass, account abuse, CAPTCHA bypass, or platform-specific evasion workflow.
- No full GUI in the first milestone.
- No claim of complete fingerprint API coverage in the first milestone.
- No attempt to upstream patches to Chromium during the first milestone.

## Repository Layout

```text
/path/to/xtrace/
├── chromium/                 # Chromium checkout, not committed
├── patches/                  # Patch files and patch notes
├── scripts/                  # Bootstrap, build, run, and packaging helpers
├── xtrace-launcher/          # First launcher implementation, CLI-first
├── logs/                     # Local NDJSON output, ignored by git
├── test-pages/               # Local pages that exercise traced APIs
└── docs/                     # Design, usage, and build notes
```

## Architecture

XTrace has three main parts:

1. A patched Chromium build.
2. A browser-process NDJSON logger.
3. A launcher that starts the patched Chromium with a clean profile and trace environment.

The long-term architecture should send renderer-side trace events to the browser process through Chromium IPC/Mojo, and the browser process should be the single writer for NDJSON logs. This avoids unsafe direct file writes from sandboxed renderer processes and keeps event ordering, file rotation, and flushing centralized.

For the first proof of life, a narrower patch is acceptable if it proves native Blink instrumentation and NDJSON output quickly. Any temporary direct-write path must be documented as temporary and replaced before broad API coverage work.

## Runtime Controls

XTrace should be disabled by default. It is enabled only when Chromium is launched with explicit flags or environment variables.

Initial controls:

```text
--xtrace-enable
--xtrace-file=/absolute/path/to/trace.ndjson
--xtrace-limit=1000000
--user-data-dir=/absolute/path/to/profile
```

The launcher may also set environment variables for convenience:

```text
XTRACE_ENABLE=1
XTRACE_FILE=/absolute/path/to/trace.ndjson
XTRACE_LIMIT=1000000
```

Chromium command-line switches are preferred for the production implementation because they fit Chromium's existing configuration style.

## Event Format

Every event is one NDJSON line.

```json
{"t":"call","ts":1780000000000,"pid":12345,"tid":259,"frame":"https://example.test/","api":"CanvasRenderingContext2D.fillText","args":["BrowserLeaks.com",4,17],"stack":[{"file":"https://example.test/fp.js","line":42,"col":17}]}
```

Required fields:

- `t`: event type, initially `call` or `get`.
- `ts`: monotonic or wall-clock timestamp in microseconds.
- `pid`: process id.
- `tid`: thread id when available.
- `frame`: current frame URL when available.
- `api`: stable API name.
- `args`: JSON-safe argument material. The raw local producer keeps full values by default; truncation requires an explicit cap and must be marked in schema metadata.
- `stack`: best-effort JavaScript stack locations.

The logger must tolerate missing frame URLs and missing stacks. Missing context should not crash the browser.

## First API Coverage

Milestone 1 should prove the pipeline with a small set of high-signal APIs:

- `CanvasRenderingContext2D.fillText`
- `CanvasRenderingContext2D.getImageData`
- `HTMLCanvasElement.toDataURL`
- `SubtleCrypto` or `Crypto.getRandomValues`, whichever is quicker to locate and patch cleanly
- One low-risk getter from `Navigator` or `Screen`

Milestone 2 can add:

- `WebGLRenderingContext.getParameter`
- `WebGLRenderingContext.readPixels`
- `WebGL2RenderingContext` mirrors
- `AudioContext`
- `OfflineAudioContext`
- `RTCPeerConnection`
- Additional `Navigator` and `Screen` getters

## Build Strategy

Use Chromium's official macOS source build flow:

1. Install Xcode and required command-line tools.
2. Install and configure `depot_tools`.
3. Fetch Chromium source into `/path/to/xtrace/chromium`.
4. Generate build files with `gn gen`.
5. Build with `autoninja -C out/XTrace chrome`.

The build directory should not be committed. Local scripts should make the setup repeatable, but should not hide important Chromium errors.

Suggested GN args for early development:

```text
is_debug=true
symbol_level=1
is_component_build=true
blink_symbol_level=1
```

Release-like packaging can come later after the instrumentation points stabilize.

## Launcher

The first launcher is a CLI tool, not Electron.

Example:

```bash
xtrace-launcher run \
  --chromium /path/to/xtrace/chromium/src/out/XTrace/Chromium.app \
  --url https://example.test/ \
  --log-dir /path/to/xtrace/logs
```

Responsibilities:

- Create a per-run profile directory.
- Create a timestamped NDJSON log path.
- Start patched Chromium with XTrace flags.
- Print the log path.
- Preserve logs after Chromium exits.

GUI work can come after the native trace pipeline is proven.

## Testing

Milestone tests:

- A local HTML page in `test-pages/` that calls the traced APIs.
- A launcher smoke test that starts Chromium against that page.
- A log validator that confirms each expected API produced at least one NDJSON event.
- A malformed-output check that every line parses as JSON.

Manual verification is acceptable for the first Chromium build because full Chromium builds are slow, but the final milestone result must include exact commands and observed log evidence.

## Safety And Scope Controls

- Logs are local-only by default.
- No automatic upload of traces.
- No generated spoofing or bypass code.
- AI prompt templates may summarize API usage and call sites, but should avoid producing evasion instructions for a live third-party target.
- Documentation should tell users to run only against systems they own, test, or are authorized to analyze.

## Open Risks

- Chromium checkout and build are large and slow.
- Native instrumentation locations may move across Chromium versions.
- JavaScript stack extraction from native code can be partial or expensive.
- Renderer sandboxing makes direct file output undesirable.
- Broad API coverage requires careful review to avoid browser crashes.

## Milestones

1. Project skeleton, documented build flow, and local test page.
2. Chromium checkout and successful unmodified macOS build.
3. First native trace event emitted from one Blink API.
4. Browser-process NDJSON writer or documented temporary writer.
5. CLI launcher smoke test with a timestamped trace file.
6. First API coverage set and log validator.
7. Packaging notes and next-step backlog for GUI and broader coverage.
