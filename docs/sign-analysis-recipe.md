# Signing-analysis recipe

An auditable, site-neutral workflow for reducing a request-signing pipeline to
**inputs → operators → output** using the native trace plus the patch-free
injected API hooks. This is a data-flow *report*, not a token generator.

All commands from the repo root. Use a **release** build (`out/XTrace-release`);
debug builds crawl on heavy SPAs (see `scripts/build_xtrace_release.sh`).

## 1. Capture

```bash
cd xtrace-launcher
PYTHONPATH=. python3 -m xtrace_launcher run \
  --chromium ../chromium/src/out/XTrace-release/Chromium.app \
  --url '<page that signs>' \
  --log-dir ../logs/run-a \
  --xtrace-categories reverse,fingerprint,network \
  --xtrace-capture-values full \
  --inject-api-hooks \
  --capture-seconds 40
```

- `--inject-api-hooks` merges JS-level plaintext I/O (TextEncoder / crypto.subtle
  / JSON / btoa, the WASM boundary, and `String.scan` for CryptoJS-style
  `charCodeAt` hashing) into the same NDJSON, clock-aligned to the native trace.
  `crypto.subtle.*` outputs are captured too (`<api>.ret`), giving the full
  input→output hot path, not just the input.
- `--inject-scan-delay <ms>` (default 4000) delays the `String.scan` hook so the
  page hydrates first.
- `--inject-scan-cap <n>` (default 4096) bounds **every** captured value — the
  `crypto.subtle`/`TextEncoder`/`JSON` boundary I/O and `String.scan` alike.
  Values are kept whole up to the cap; `pairing.json`'s `capture_truncated_events`
  / `cap_hint` tell you to raise it if a hot-path value clipped.
- `--user-data-dir <dir>` reuses a **warm profile** (stable device/token
  cookies) — required for controlled diffs (step 4).

## 2. Discover the carrier (no token name needed)

```bash
python3 scripts/sign_pipeline.py discover --trace logs/run-a/trace_*.ndjson \
  --carrier-hint <known-param-if-any>
```

Ranks request params/headers/body values by entropy × per-request variance ×
preceding compute burst. `--carrier-hint` captures a non-token-shaped param
(e.g. a `;`-delimited value) raw and score-weights it.

## 3. Explain one window

```bash
python3 scripts/sign_pipeline.py explain --trace logs/run-a/trace_*.ndjson \
  --out analysis/a --carrier <name> --token-field-sep ';' --window-ms 500
```

Outputs in `analysis/a/`:

| file | what |
|------|------|
| `sign_artifact.json` | **per-field artifact**: each carrier leaf field's output value + evidence + matching materials/outputs + producing sub-DAG, plus shared phases / env reads / candidate input+output pools |
| `token.json` | the token(s) + generic `f0..fN` field split |
| `crypto_inputs.json` | plaintext fed into hash/cipher/sign (the digest/AES input) |
| `crypto_outputs.json` | the paired OUTPUT bytes (digest/signature/ciphertext) captured at the `crypto.subtle` boundary as `<api>.ret` — the input→output edge |
| `materials_timeline.jsonl` | deduped string I/O, tagged input/intermediate/output |
| `phases.json` | wordarray_in / block_cipher / encode_out / emit (fn-name clustering) |
| `dag.json`, `ops.csv` | value-ref data-flow + operator sequence |

`sign_artifact.json` is the assembled view the other files feed. Each field is
honest about what was **observed**: a `direct`/`composite` field carries the
material that string-matches it; an `unpaired` field (a hash/signature) carries
empty `materials` on purpose — its producing plaintext was not observed to equal
it, so the shared `candidate_inputs` (in-window plaintext) + `phases` (the crypto
ops) are what a replay/oracle pass must resolve. `dag` is the value-ref sub-graph
that produced the field, or `null` when the field has no source-ref lineage in
the window (e.g. a `crypto.subtle` digest) — again, exactly the gap a replay
closes. It is an assembly of capture, never a recomputation claim.

## 3b. Replay (one-click oracle: verify a field against its inputs)

```bash
python3 scripts/sign_pipeline.py replay analysis/a   # reads analysis/a/sign_artifact.json
```

The oracle tries every standard **keyless** transform of each captured candidate
input — md5 / sha1 / sha2 / sha3 / blake2 / crc32 digests and hex/base64
encodings — and reports which ones reproduce a field, as `exact`, `prefix`, or
`substring`. It also records an `observed_output_edge` when a captured
`crypto.subtle` `.ret` already equals the field (no recomputation needed).
`replay.json` gives a per-field `derivations` list and a `resolution_rate`.

This **verifies the observed signature** — it proves or falsifies the
input→output edge with general algorithms; it does **not** sign new inputs (not a
token generator). A field that `pairing.json` calls `unpaired` (a hash never seen
as plaintext) can become fully resolved here: `body.sign == sha256(<observed
input>)`. That is the `半知→可证` step — pairing checks string presence, replay
checks the actual crypto relationship.

## 3c. Export (project the verified derivations into an algo spec)

```bash
python3 scripts/sign_pipeline.py export analysis/a   # writes algo_spec.json + algo_spec.md
```

Projects the replay-verified derivations plus the in-window environment reads
into a minimal per-field spec, e.g. `body.sign = hex(sha256(input))` with the
input's capture source, the signer's `primitives` (e.g. `sha256`), the `phases`
pipeline shape, and the `environment_inputs` it read (`Date.now`, `Math.random`,
…). `algo_spec.md` is the readable companion. Fields replay could not resolve are
recorded `unresolved`, not guessed. This is a **description of the
reverse-engineered relationship** — a deobfuscation deliverable, not a generator
for new inputs.

## 4. Controlled diff (change one input, see what flips)

Reuse a fixed profile so only the factor under test changes:

```bash
PROFILE=../logs/warm-profile     # same dir across runs
# run A (baseline) and run B (one factor changed: body / functionId / ...),
# both with: --user-data-dir "$PROFILE" --inject-api-hooks
python3 scripts/sign_pipeline.py explain --trace logs/run-a/trace_*.ndjson --out analysis/a --token-field-sep ';'
python3 scripts/sign_pipeline.py explain --trace logs/run-b/trace_*.ndjson --out analysis/b --token-field-sep ';'
python3 scripts/sign_pipeline.py diff analysis/a analysis/b \
  --token-field-sep ';' --out analysis/diff   # dir OK → writes report.json
# or: --out analysis/diff/report.json
```

`diff` reports, per token field, `same` / `hamming` across runs (the 变/不变
table) plus added/removed materials — narrowing which segments depend on which
input without any site-specific code. `--out` accepts a **file** or a
**directory** (writes `report.json` inside).

`explain` also writes `pairing.json`. Its pairing percentage is measured over
the smallest available carrier fields (for example, `f0..fN` when a delimiter
is supplied), not the enclosing token and its fields together. Each field is
labelled `direct`, `composite`, `context_only`, or `unpaired` with the observed
API/category and time. `context_only` (for example, a field merely appearing in
the final carrier envelope) is intentionally excluded from the pairing rate.
These are capture facts, not a claim that the toolkit can recompute it.

> Site-specific field semantics and any closed-form re-computation belong in a
> local, un-committed layer (e.g. `local/`), not in this toolkit.
