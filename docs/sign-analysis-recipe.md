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
  --out analysis/a --carrier <name> --token-field-sep ';' --window-ms 500 \
  --anchor-select material
```

`--window-ms` (default 300) is the pre-request window everything downstream is
drawn from — **if the preimage was computed before the window opens, replay
cannot resolve the field**, and it reports `unresolved` rather than guessing. It
is worth widening when a field stays unresolved: on one real capture the SHA256
preimage landed 506ms before the anchor and a 500ms window missed it by 6ms.
`--anchor-select material` picks the carrier request whose window actually holds
injected material, instead of the first one.

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

The oracle tries a family of standard transforms of each captured candidate input
and reports which ones reproduce a field, as `exact`, `prefix`, or `substring`:

- **keyless single-step** — md5 / sha1 / sha2 / sha3 / blake2 / crc32 **and SM3
  (国密)** digests, with hex/base64 encodings (`H(input)`);
- **encode-then-hash** — `H(hex(input))`, `H(base64(input))`, …;
- **hash-of-hash** — `H2(H1(input))` over the digest bytes or its hex;
- **HMAC** — `HMAC(key, msg)` (incl. **HMAC-SM3**) with the key and message drawn
  from the candidate pool (each derivation names its `key` / `input` operands);
- **salted concat** — `H(input ‖ salt)`, salt drawn from the candidate pool;
- **SM4 (国密) cipher** — `SM4-ECB/CBC(key, msg)` verified by re-encrypting an
  *observed* plaintext under an *observed* 16-byte key (ASCII or 32-hex) and
  matching the captured ciphertext. Forward-only (never decrypts to reveal, never
  encrypts a novel input); deterministic, so a match is a proof.

**Where the candidate inputs come from.** A JS-implemented hash (CryptoJS and
friends) never calls `crypto.subtle` — it reads its message char-by-char, so the
preimage crosses the **native** `String.prototype.charCodeAt` hook, which carries
the whole subject string on every call. That is the primary source of the digest
preimage, and it needs no injection: it is uncapped, unevadable, and visible in
workers. The timeline dedups the per-char repeats into one candidate, so a
308-char message read 308 times is one pool entry. `--inject-api-hooks`'
`String.scan` is the JS-level approximation of the same signal, useful when the
native hooks are off; `crypto.subtle` / `TextEncoder` cover the WebCrypto signers.

Because signers routinely wrap the material in one `JSON.stringify` (e.g. JD's
`{key, signStr, msg}`), candidates that parse as a JSON object/array are **mined
for their string leaves**, so a nested HMAC/SM4 key and message become first-class
pool operands (each derivation records the `json_path` it came from). SM3/SM4 (国密)
are enabled automatically when the platform's `hashlib` provides SM3 (OpenSSL 3);
`replay.json` reports `operand_pool_size` / `json_leaf_operands_mined`.

HMAC keys, SM4 keys, and salts are only ever taken from **observed** material — an
unknown constant is never guessed (that would be generation, not verification). It also
records an `observed_output_edge` when a captured `crypto.subtle` `.ret` already
equals the field (no recomputation needed). `replay.json` gives a per-field
`derivations` list (each with a readable `spec`, e.g. `hex(HMAC_sha256(key,
msg))`) and a `resolution_rate`.

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

## 5. JSVMP signers — general opcode table (devirtualization)

When the signer is a JavaScript VM (JSVMP) rather than a standard-crypto pipeline,
`sign_pipeline`'s replay oracle will (correctly) not resolve it — a bespoke VM
transform is not a standard primitive. Use the VM analyzer instead:

```bash
python3 scripts/analyze_vmp_trace.py logs/run-a/trace_*.ndjson \
  --profile generic-vmp --target-param <signed-param> \
  --json-output analysis/a/vmp.json \
  --source-snippets-output analysis/a/snippets.json --skip-bad-json
```

It emits, **site-neutrally** (no per-VM code), three views of the VM:

| view | what |
|------|------|
| `opcode_table` | the **handler inventory** — each distinct VM handler site is one opcode, labeled by op-shape alone (`DISPATCH` / `CHAR_DECODE` / `ARX_MIX` / `ROTATE` / `MASK/BYTE` / `XOR_MIX` / …) plus its family role, constant profile, and — when attributable — its source snippet |
| `program_sketch` | the **hot opcode→opcode transitions** (the dispatch loop's repeated round, as a bigram count) |
| `program_trace` | the **devirtualized listing** — the executed opcode trace rolled back into loops (`body x repeat`) |

`program_trace` is the step from inventory to *program*: it labels every op in the
window with the opcode that ran it, then rolls that linear trace back into loops
(the inverse of unrolling), reporting each round at its **shortest true period**
rather than a multiple of it. So a VM round that executed 27k times reads as one
block, and `ops_total` → `blocks_total` is the compression the devirtualization
buys you. `blocks` is ranked by ops covered and bounded — a summary of the
program, not every block of it.

Together these turn millions of raw bitwise ops into a bounded, readable
deliverable for VM signers, the same way `algo_spec` is for standard-crypto
signers. Labels are op-shape heuristics; the joined source snippet is ground
truth.
