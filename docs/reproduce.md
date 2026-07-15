# Reproducing an XTrace result

Two independent paths. **Path A** verifies the whole analysis toolchain on any
machine in seconds, no Chromium build. **Path B** reproduces a real capture on a
built browser (macOS, heavy).

---

## Path A — verify the toolchain (any OS, no build)

The launcher, validator, analyzer, sign_pipeline, and GUI logic all run against
synthetic fixtures — no patched browser needed. This is what CI runs on every
push (`.github/workflows/ci.yml`).

```bash
scripts/run_tests.sh          # Python unittest x2 + the GUI node --test suite
```

Validate the committed **golden trace** — a known-good schema v2 capture — to
confirm your validator agrees before you build anything:

```bash
python3 scripts/validate_trace.py --schema-version 2 \
  --expect TextEncoder.encode tests/fixtures/golden-schema-v2.ndjson
# -> PASS: tests/fixtures/golden-schema-v2.ndjson
```

If Path A is green, the analysis side reproduces on your machine. Everything
below only adds a *real* browser capture on top.

---

## Path B — reproduce a real capture (macOS, full build)

Build the patched browser once (see [`chromium-build.md`](chromium-build.md);
~100 GB, hours), then capture and validate a self-contained smoke page.

```bash
scripts/bootstrap_chromium.sh          # pinned revision the patches target
scripts/apply_patches.sh               # 0001/0003/0004 -> src, 0002 -> src/v8
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/gn_gen_xtrace.sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/build_chromium.sh
```

### Case 1 — JSVMP families (schema v1), `reverse-smoke.html`

```bash
python3 scripts/serve_test_page.py --port 8791 &
cd xtrace-launcher
PYTHONPATH=. python3 -m xtrace_launcher run \
  --chromium ../chromium/src/out/XTrace/Chromium.app \
  --url http://127.0.0.1:8791/reverse-smoke.html \
  --log-dir ../logs --xtrace-categories reverse,fingerprint,network \
  --xtrace-capture-values full --xtrace-capture-assets full --capture-seconds 12

python3 ../scripts/validate_trace.py --schema-version 1 \
  --expect Shift.left \
  --require-vmp-family int_bitwise --require-vmp-family byte_buffer \
  --require-vmp-family-evidence \
  ../logs/trace_*.ndjson          # -> PASS
```

Expected shape: a few thousand `category:"reverse"` events; the `int_bitwise`
(`Shift.*`) and `byte_buffer` families present **with value/ref/result evidence**.

### Case 2 — causal schema v2, `causality-smoke.html`

```bash
PYTHONPATH=. python3 -m xtrace_launcher run \
  --chromium ../chromium/src/out/XTrace/Chromium.app \
  --url http://127.0.0.1:8791/causality-smoke.html \
  --log-dir ../logs --xtrace-categories reverse,fingerprint,network \
  --xtrace-capture-values full --xtrace-causality sync --capture-seconds 12

python3 ../scripts/validate_trace.py --schema-version 2 \
  --expect TextEncoder.encode ../logs/trace_*.ndjson     # -> PASS
```

Expected shape: every record `schema_version:2`; `causality_kind` is a mix of
`paired` (script `evaluate` call/return), `singleton` (children), and `external`
(network / injected). The validator checks parent-before-child ordering, depth,
and paired closure.

---

## What "reproduce" means here (and doesn't)

- **Captures are non-deterministic.** Event counts, pids, and timestamps vary per
  run and machine — validate the *structure and evidence*, do not byte-diff two
  traces. The committed golden (Path A) is the deterministic anchor.
- **The `--profile fingerprint|reverse|business-api|all` presets expect a rich,
  real-world API surface**, not a minimal smoke page. Smoke pages are validated
  with `--expect <an-API-they-actually-call>` plus family checks, as above. With
  no `--profile` and no `--expect`, the validator defaults to the *fingerprint*
  expectation set — so always pass one of them.
- **Real-site cases are not shipped.** XTrace is site-neutral: there are no
  captured traces of third-party targets in the repo. Bring your own URL you are
  authorized to study (`scripts/run_generic_vmp_readonly.sh 'https://…'`).
- **Build caveat — patch/live drift.** The exported `patches/*.patch` are the
  reproducible baseline, but a working checkout may carry local, un-exported
  refinements. If a case you reproduce looks thinner than expected, that gap is
  the first thing to check; see [`chromium-build.md`](chromium-build.md).
