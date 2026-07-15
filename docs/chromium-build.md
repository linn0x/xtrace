# Chromium Build

How to build the patched XTrace Chromium from a clean checkout. All commands run from the repository root.

## Prerequisites

- macOS with **full Xcode** installed at `/Applications/Xcode.app` (Command Line Tools alone are not enough for the Metal toolchain).
- ~**100 GB** free disk for the Chromium checkout + build output.
- Time: a clean build takes **several hours** (~5h on the reference machine; incremental rebuilds are seconds to minutes).
- `depot_tools` and the Chromium tree are fetched into `depot_tools/` and `chromium/` (both git-ignored). `ninja` is used from depot_tools.

If Xcode's global developer dir still points at Command Line Tools, prefix build commands with `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer` (the scripts also auto-detect it). Optionally set it globally: `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer`.

The Metal toolchain may need a one-time download:

```bash
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -downloadComponent MetalToolchain
```

## Pinned Chromium revision

The patches apply cleanly **only** against this revision:

```
73088b4e50b1dc69eaa0bdb14a8e4592813174fd
```

`scripts/bootstrap_chromium.sh` pins to it automatically (override with the `CHROMIUM_REVISION` env var if you know what you're doing). V8 is synced to the matching DEPS revision by `gclient sync`.

## Build steps

```bash
# 1. Fetch depot_tools + Chromium and sync to the pinned revision (incl. V8)
scripts/bootstrap_chromium.sh

# 2. Apply the XTrace patches
#    0001-xtrace-native-logger.patch -> chromium/src      (Blink / chrome / content)
#    0002-xtrace-v8-vmp-hooks.patch  -> chromium/src/v8   (V8 builtins / runtime)
scripts/apply_patches.sh

# 3. Generate build files
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/gn_gen_xtrace.sh

# 4. Build
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/build_chromium.sh
```

Result: `chromium/src/out/XTrace/Chromium.app`.

### Build args

`scripts/gn_gen_xtrace.sh` uses a debug, component build with light symbols, warnings-as-errors off, and Siso/Reclient disabled. It also enables common web video codecs so media-heavy sites smoke-test realistically (otherwise modern MP4 playback fails with `DEMUXER_ERROR_NO_SUPPORTED_STREAMS`):

```
proprietary_codecs=true
ffmpeg_branding="Chrome"
rtc_use_h264=true
```

The build scripts `unset GOROOT GOTOOLDIR` before invoking Chromium tools so Dawn uses its bundled Go toolchain instead of a user-managed Go install.

## Run and validate

Serve the local test page and launch the patched browser (see the top-level `README.md` for the full launcher/validator flags):

```bash
python3 scripts/serve_test_page.py --port 8765

cd xtrace-launcher
PYTHONPATH=. python3 -m xtrace_launcher run \
  --chromium ../chromium/src/out/XTrace/Chromium.app \
  --url http://127.0.0.1:8765/fingerprint-smoke.html \
  --log-dir ../logs
```

Validate the newest trace:

```bash
latest="$(ls -t logs/trace_*.ndjson | head -1)"
python3 scripts/validate_trace.py --schema-version 1 "$latest"
```

For reverse/VMP smoke traces, require the expected VMP analysis families explicitly (see `README.md` for the full flag set and what each check enforces).

## Instrumented surface (reference)

The patches keep renderer sandboxing enabled: Blink hooks serialize NDJSON in the renderer, send it to `blink.mojom.XTraceHost` over process-scoped Mojo IPC, and the browser process owns the trace file. (An earlier renderer-side writer failed under sandboxing with `FILE_ERROR_ACCESS_DENIED`; the browser-process sink replaced it.) Renderer XTrace Mojo remotes are bound per thread/sequence so worker fetch instrumentation doesn't trip Mojo's sequence checker on worker-heavy sites.

Collection surfaces (schema v1):

- **Network:** `fetch`, `XMLHttpRequest.open/send/setRequestHeader/status/responseText`, WebSocket constructor/connect/send/message/close
- **Storage / cookies:** `Storage.getItem/setItem/removeItem/clear/key`, `Document.cookie.get/set`
- **Dynamic code:** `eval`, `new Function`, `setTimeout.string`, `setInterval.string`, `HTMLScriptElement.src.set`, `HTMLScriptElement.inserted`
- **VMP families:** base64/text-codec/byte-buffer (ArrayBuffer/DataView/TypedArray), dynamic dispatch (`Object.keys`, `Reflect.*`, Map/Set tables, Proxy traps), integer bitwise/shift (via the Ignition bytecode handler path plus V8 feedback/baseline/Torque coverage), hash/crypto (`SubtleCrypto.digest/sign/importKey`), anti-debug timing (`debugger`, timing gates), and source/native-code probes (`Function.prototype.toString`)
- **URL/query:** `URL.*`/`URLSearchParams.*` hooks carry local `url_object_id`/`search_params_id` and `before_serialized`/`serialized` state so reports can group object-level causality and preserve final query material before request construction

`Reflect.apply` / `Function.prototype.call/apply` are report-recognized dynamic-dispatch indicators but their direct arm64 builtin hook is disabled — smoke testing showed renderer crashes; a safer future version should hook via cross-architecture CSA/Torque or at the call site.

The analyzer groups these into VMP families, hotspots, and `analysis_points` (`vmp_string_decoder`, `vmp_dynamic_dispatch`, `vmp_proxy_trap`, `vmp_hash_or_signature_pipeline`, `vmp_int_bitwise_pipeline`, `vmp_anti_debug_timing_gate`, `vmp_source_integrity_probe`, etc.) and, for signature investigations, into per-flow timelines linking unsigned URL construction to signed request material. See `scripts/analyze_vmp_trace.py` and `scripts/validate_trace.py` for the authoritative list.

## Verification

```bash
# All repository tests (Python 3.10+ is selected automatically, then GUI)
scripts/run_tests.sh

# Chromium tree sanity (from chromium/src, after applying patches)
git -C chromium/src diff --check
```
