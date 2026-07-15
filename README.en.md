<div align="center">

# 🔬 XTrace

### A general-purpose runtime tracer for JavaScript VM protection (JSVMP) & obfuscation analysis

*Patch Chromium once. Load any page. Watch the obfuscated runtime — API calls, stacks, values, crypto material, and JSVMP hook families — stream out as clean, structured NDJSON.*

[![release](https://img.shields.io/badge/release-v1.0.0-brightgreen)](https://github.com/linn0x/xtrace/releases)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![platform](https://img.shields.io/badge/platform-macOS-lightgrey)]()
[![engine](https://img.shields.io/badge/engine-Chromium%20%2B%20V8-orange)]()

[中文](README.md) · **English**

</div>

---

## What is XTrace?

Modern anti-analysis code hides behind **JavaScript VM protections (JSVMP)** and heavy obfuscation: custom bytecode interpreters, dynamic dispatch, proxy traps, string machines, and anti-debug timers. Reading the minified source tells you almost nothing — the logic only reveals itself *at runtime*.

XTrace is a **native tracing toolkit built into a patched Chromium/V8**. It instruments Blink and V8 so that a *normal page load* — no debugger stepping, no source patching of the target — emits a faithful **schema v1 NDJSON** log of everything the protected code actually does. You get a data-flow record of the obfuscated runtime that you can validate, diff, and analyze offline.

It is deliberately **site-neutral and general**: the same tooling works on any obfuscated JS or JSVMP surface, from a local smoke page to an arbitrary URL you're authorized to study.

> ⚖️ **Authorized use only.** XTrace is for security research, deobfuscation study, and defensive analysis on systems and content you are authorized to test. It is **not** a scraping toolkit, **not** an anti-bot bypass product, and it does **not** generate bypass code or signatures. You are responsible for complying with applicable law and terms of service.

---

## Why XTrace

- 🧩 **Sees through JSVMP** — V8 runtime hooks surface interpreter behavior that source-level tools can't: dynamic dispatch, proxy traps, byte buffers, string codecs, and more.
- 🎯 **Nine JSVMP-oriented hook families** — every capture can be validated to prove real evidence (values, refs, results) exists for each family, not just names.
- 🔐 **Crypto material in the clear** — captures digest/AES/HMAC inputs *and outputs*, including CryptoJS-style `charCodeAt` hashing and the WASM boundary, clock-aligned into one trace.
- 📏 **Structured & verifiable** — stable **schema v1 NDJSON** with a strict validator: reject truncated values, opaque refs, or evidence-free family hits.
- 🧬 **Optional causal schema v2** — `--xtrace-causality=sync` adds renderer-thread synchronous causal identity (`call_id` / `parent_id` / `depth`): a script `evaluate` becomes a paired call/return and other records become its children. Preserves every schema v1 field; off by default.
- 🕵️ **Data-flow reports, not magic** — the signing-analysis pipeline reduces a request-signing flow to **inputs → operators → output** as an auditable report.
- 🖥️ **Browser owns the trace** — renderer sandboxing stays *on*; events cross `blink.mojom.XTraceHost` (Mojo IPC) and the browser process writes the file.
- 🧪 **Batteries-included harness** — self-contained smoke pages for obfuscation / reverse / VMP surfaces, plus a Python CLI and an Electron workbench.

### JSVMP hook families

`base64` · `text_codec` · `byte_buffer` · `dynamic_dispatch` · `proxy_trap` · `hash_crypto` · `int_bitwise` · `anti_debug_timing` · `source_probe`

---

## How it works

```
        ┌──────────────────────────────────────────────┐
        │  Patched Chromium.app  (built from patches/)   │
        │                                                │
        │   Renderer (sandboxed)         Browser proc.   │
        │   ┌─────────────────┐          ┌────────────┐  │
   any  │   │ Blink + V8 hooks │──Mojo──▶ │ owns trace │──┼──▶  trace.ndjson
  page ─┼──▶│ schema v1 NDJSON │  IPC     │   file     │  │     (schema v1)
        │   └─────────────────┘          └────────────┘  │
        └──────────────────────────────────────────────┘
                                                   │
              xtrace-launcher (CLI)  ┌─────────────┴─────────────┐
              xtrace-gui (Electron)  │ validate · analyze · diff │
                                     └───────────────────────────┘
```

**Compatibility fields:** `t`, `api`, `args`, `stack`, `pid`, `tid`.
**Extended fields:** `event_id`, `session_id`, `seq`, `wall_time_us`, `mono_time_us`, `category`, `phase`, `frame_url`, `origin`, `result`, `error`, `truncated`.

See [`docs/runtime-trace-plan.md`](docs/runtime-trace-plan.md) and [`docs/trace-schema-v1.md`](docs/trace-schema-v1.md).

---

## Quick start

```bash
# 0. Prereqs: Python 3.10+ (stdlib only), current Node/npm for the workbench.
#    Run the full local suite anytime with:  scripts/run_tests.sh

# 1. Fetch depot_tools + Chromium (pinned revision the patches target)
scripts/bootstrap_chromium.sh

# 2. Apply patches (0001/0003/0004 → chromium/src, 0002 → chromium/src/v8)
scripts/apply_patches.sh

# 3. Build the patched browser
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/gn_gen_xtrace.sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/build_chromium.sh
# → chromium/src/out/XTrace/Chromium.app
```

> 🛠️ **Build prerequisites:** macOS with full Xcode (not only Command Line Tools), on the order of **~100 GB** free disk, and several hours for a clean Chromium build. XTrace ships as **patches + build scripts**, not a Chromium checkout — `chromium/` and `depot_tools/` are gitignored and created on your machine only. Details and pinned revision: [`docs/chromium-build.md`](docs/chromium-build.md).

### Capture a trace

```bash
# Serve the local harness pages
python3 scripts/serve_test_page.py --port 8765

# Capture with the patched browser
cd xtrace-launcher
PYTHONPATH=. python3 -m xtrace_launcher run \
  --chromium ../chromium/src/out/XTrace/Chromium.app \
  --url http://127.0.0.1:8765/reverse-smoke.html \
  --log-dir ../logs \
  --xtrace-categories reverse,fingerprint \
  --xtrace-capture-values full \
  --xtrace-capture-assets full \
  --capture-seconds 60 \
  --validate-after-exit
```

> Add `--xtrace-causality=sync` to emit a **schema v2 causal trace** (validate with `--schema-version 2`); the default stays schema v1.

More self-contained pages under [`test-pages/`](test-pages/): `obfuscation-smoke.html`, `fingerprint-smoke.html`, `json-parse-smoke.html`, `causality-smoke.html`, and worker/fetch variants.

---

## Validate & analyze

### Strictly validate a JSVMP-oriented trace

```bash
python3 scripts/validate_trace.py \
  --profile reverse \
  --schema-version 1 \
  --expect SubtleCrypto.importKey \
  --expect SubtleCrypto.sign \
  --require-vmp-family base64 \
  --require-vmp-family text_codec \
  --require-vmp-family byte_buffer \
  --require-vmp-family dynamic_dispatch \
  --require-vmp-family proxy_trap \
  --require-vmp-family hash_crypto \
  --require-vmp-family int_bitwise \
  --require-vmp-family anti_debug_timing \
  --require-vmp-family source_probe \
  --require-complete-values \
  --require-material-refs \
  --require-vmp-family-evidence \
  logs/your-capture.ndjson
```

| Flag | Meaning |
|------|---------|
| `--require-vmp-family NAME` | Fail if that JSVMP-oriented family never appears |
| `--require-vmp-family-evidence` | Family hits must carry real value/ref/result evidence, not names-only |
| `--require-complete-values` | Reject truncated/preview/redacted value evidence |
| `--require-material-refs` | Reject length-only or opaque refs without raw material |

Strict launcher preset for generic VMP captures (defaults to `--profile generic-vmp --strict-capture`):

```bash
cd xtrace-launcher
PYTHONPATH=. python3 -m xtrace_launcher validate ../logs/your-capture.ndjson
```

### Analyze (generic VMP profile)

```bash
python3 scripts/analyze_vmp_trace.py \
  path/to/trace.ndjson \
  --profile generic-vmp \
  --json-output logs/vmp_summary.json

# Against an arbitrary URL you supply and are authorized to study:
scripts/run_generic_vmp_readonly.sh 'https://example.invalid/your-page'
```

Optional parameter-materialization checks (any name you care about, not product-specific):

```bash
python3 scripts/validate_trace.py \
  path/to/trace.ndjson \
  --require-signature-param-materialization SOME_PARAM
```

### Signing-analysis pipeline (inputs → operators → output)

An auditable, site-neutral workflow that reduces a request-signing flow to a **data-flow report** using the native trace plus patch-free injected API hooks. `--inject-api-hooks` folds JS-level plaintext I/O (TextEncoder, `crypto.subtle.*` inputs *and* outputs, JSON, btoa, the WASM boundary, and `String.scan` for CryptoJS-style hashing) into the same NDJSON, clock-aligned to the native trace. It is a **report, not a token generator** — see [`docs/sign-analysis-recipe.md`](docs/sign-analysis-recipe.md).

---

## Electron workbench

```bash
cd xtrace-gui
npm install
npm start
```

Pick Chromium, URL, and log directory; start/stop capture; list NDJSON files; live-tail with category/API filters.

---

## Trace data & privacy

Traces default to **full fidelity** so obfuscation and JSVMP reconstruction stay faithful — headers, cookies, tokens, and body material may appear in the clear when capture flags allow it.

- Stored under `logs/` (**gitignored**); keep them on your machine.
- 🚫 **Do not publish raw `.ndjson` without review.**
- Export-time redaction is planned ([`docs/trace-log-improvements.md`](docs/trace-log-improvements.md)).

---

## Repository layout

```
patches/           # 0001 native logger, 0002 V8 JSVMP hooks, 0003/0004 causal schema v2
scripts/           # bootstrap, build, serve, validate, analyze, sign_pipeline
xtrace-launcher/   # Python CLI: run patched Chromium, capture NDJSON
xtrace-gui/        # Electron capture + review workbench
test-pages/        # local smoke HTML/JS (obfuscation / reverse / VMP surfaces)
docs/              # design, schema, build notes
tests/             # unit tests for scripts / analyzer
```

**Not shipped in the public package:** full Chromium trees, build outputs, raw traces under `logs/`, and any local stress material under `local/` (gitignored).

### Incremental relink (advanced)

If the ninja graph is unhealthy but object files are intact, `scripts/solink_xtrace_dylibs.py` can recompile the XTrace-touched units and solink `libv8.dylib` / `libchrome_dll.dylib` without a full `chrome` rebuild. Prefer a normal ninja build when the graph is healthy.

---

## Documentation

| Document | What's inside |
|----------|---------------|
| [`docs/superpowers/specs/2026-06-27-chromium-xtrace-design.md`](docs/superpowers/specs/2026-06-27-chromium-xtrace-design.md) | Design |
| [`docs/superpowers/plans/2026-06-27-chromium-xtrace-proof-of-life.md`](docs/superpowers/plans/2026-06-27-chromium-xtrace-proof-of-life.md) | Implementation plan |
| [`docs/chromium-build.md`](docs/chromium-build.md) | Build notes, pinned revision, GN args, troubleshooting |
| [`docs/trace-schema-v1.md`](docs/trace-schema-v1.md) | Trace schema |
| [`docs/trace-schema-v2.md`](docs/trace-schema-v2.md) | Causal schema v2 (`--xtrace-causality=sync` opt-in) |
| [`docs/sign-analysis-recipe.md`](docs/sign-analysis-recipe.md) | Signing-analysis recipe |
| [`docs/trace-log-improvements.md`](docs/trace-log-improvements.md) | Trace-log improvements |
| [`docs/runtime-trace-plan.md`](docs/runtime-trace-plan.md) | Runtime-trace roadmap |

### Patches

- `patches/0001-xtrace-native-logger.patch` → `chromium/src` (Blink / browser network logging)
- `patches/0002-xtrace-v8-vmp-hooks.patch` → `chromium/src/v8` (JSVMP-oriented runtime hooks)
- `patches/0003-xtrace-schema-v2-renderer.patch` → `chromium/src` (renderer sync causal identity, opt-in)
- `patches/0004-xtrace-schema-v2-browser.patch` → `chromium/src` (marks network-boundary records external)

---

## License

**MIT** — see [`LICENSE`](LICENSE). Patched Chromium / Blink / V8 portions remain under The Chromium Authors' BSD 3-Clause license; see the Chromium and V8 upstream `LICENSE` files.
