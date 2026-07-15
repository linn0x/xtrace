# XTrace: Capture Core → Runtime-State Trace — Engineering Plan

Status: phase-0-started · Date: 2026-07-08 · Scope: the trace-log producer (Blink + V8 patches), its
schema, and the offline consumers (`validate_trace.py`, `analyze_vmp_trace.py`, GUI).

This plan is the architectural companion to `docs/trace-log-improvements.md`. That document is a
bug/field-level punch list (fill the fields the schema already promises). **This document is the
step up a level**: what it takes for XTrace to be a *complete JS runtime-state capture* system
rather than a broad-but-flat per-call event logger.

> Verification note. All code references below were checked against the **live** `chromium/src`
> checkout, not just the patches, and against real `logs/*.ndjson` captures. A captured trace can
> come from a stale binary — always confirm behavior against live source + binary mtime vs source
> tip, never from an old trace alone.

---

## 1. Where we are

The capture *surface* is already strong and end-to-end:

- **Breadth.** 88 instrumented Blink files + 127 instrumented V8 files. Two real layers (V8
  builtins/runtime *and* Blink Web API), not a thin wrapper.
- **Dynamic code is covered.** `eval` and `new Function` are hooked (`LogXTraceDynamicCode` in
  `patches/0002-xtrace-v8-vmp-hooks.patch`) — the surface most tools miss.
- **Per-event context.** Every event carries a 16-frame detailed JS stack
  (`CaptureJavaScriptStack`, `xtrace_logger.cc:178`), args, and three clocks (wall/mono/`t`),
  over a sandbox-preserving Mojo pipeline, feeding validator + analyzer + GUI.

The *record model* and the *runtime semantics* are where it falls short of "complete":

| Gap | Evidence | Blocks |
|---|---|---|
| Schema states fields it never fills | `result`/`error` = `null` (`xtrace_logger.cc:392-393`); `frame_url`/`origin` = `""` (`:388-390`) — 0/2080 and 3/2080 populated in a real trace | Trusting the record at all |
| `seq` is per-process, not per-file | renderer `NextSequenceNumber()` atomic restarts at 1 per process; browser uses `g_xtrace_browser_network_sequence`; both funnel into one file — range 1–1836 over 2080 lines, non-monotonic, duplicated | Total order / replay |
| No structured causality | only a 16-frame **stack string** per event; no `call_id`/`parent_id`/`depth`/`span` | Call-tree reconstruction |
| No data-flow linkage | each event is an isolated call snapshot; return values are buried inside the `args` string via `AppendXTraceStringField(event, "result", ...)` | VMP pipeline reconstruction |
| No async causality | only scattered Torque hooks (e.g. `Array.fromAsync`); no promise/microtask/timer scheduling chain | Cross-tick correlation |
| Observer effect / volume | `LogBatch` implemented but never called (`xtrace_host_impl.cc:99`); per-event Mojo IPC + per-event 16-frame stack; uncapped bodies | Anti-debug timing fidelity, GB-scale traces |
| Coverage is lopsided | real trace = 2068 `reverse` / 9 `fingerprint` / 3 `network` | Confidence that non-reverse surfaces work |

---

## 2. The bar: what "complete runtime-state capture" means here

Acceptance criteria this plan is designed to hit. XTrace is *complete* when a raw trace, with no
extra runtime, lets an analyst answer all of:

1. **Ordering.** Every event has a single, monotonic, file-global position. Replay in emission
   order is unambiguous.
2. **Attribution.** Every event names its executing frame and security origin (not just the 3
   network events).
3. **Causality.** For any event you can walk to its caller and callees — a real call tree, not a
   grep over stack strings. Paired `call`/`return`/`exception` events share one activation id.
4. **Data flow.** For the curated VMP op set, you can follow a value: "the output of op A became
   the input of op B" is *recorded*, not re-guessed offline by heuristics.
5. **Async continuity.** A callback event links back to the `await`/`.then`/`setTimeout`/
   `queueMicrotask` that scheduled it.
6. **Self-description.** A frozen schema doc is the single source of truth, and a contract test
   fails if the producer stops populating a field it promises.
7. **Low perturbation.** Capture overhead is bounded and configurable enough that timing-sensitive
   anti-debug gates behave normally, and hot dispatch loops don't blow trace size unboundedly.

Today XTrace clears (1) partially (via `mono_time_us`, not `seq`), fails (2)-(5), and partially
clears (7). This plan closes the rest.

Implementation note: the first Phase 0 ordering slice has started. Newer producers keep `seq`,
emit explicit `session_seq`, and the browser-side writer stamps `global_seq` immediately before
append. Offline consumers still keep `_file_index` as the strongest order when reading NDJSON, with
`global_seq` as the producer-provided fallback.

---

## 3. Design principles / constraints

- **Sandbox stays on.** All new capture originates in the renderer/V8 and crosses to the browser
  over Mojo, exactly as today. No new privileged surface in the renderer.
- **Additive first, then a version bump.** Fields that only *add* information stay schema v1
  (tolerant consumers ignore unknown keys). The causality + data-flow work is a semantic change:
  ship it as **schema v2**, keep the v1 emitter available behind a flag for one release.
- **Offline does the joining.** Prefer emitting cheap, join-able primitives (ids, value hashes)
  and reconstructing graphs in `analyze_vmp_trace.py`, over expensive in-engine graph building.
- **Local-only, but honest.** Full-fidelity capture stays the local default; the security boundary
  is *local storage + an opt-in export redactor*, and the docs must say so (see
  `trace-log-improvements.md` §3.1).
- **Pay for stacks only where they earn it.** 16-frame capture per event is a Phase-4 cost target.

---

## 4. Phased plan

Phases are ordered by dependency and leverage. Phase 0 is a prerequisite for everything; Phase 1
is the highest architectural payoff; Phase 2 delivers the deobfuscation win; Phase 4 (performance)
must land before Phases 2-3 add event volume in anger.

### Phase 0 — Schema hygiene & self-verification (foundation)

**Goal.** Make the record honest and locked down so later phases build on solid ground.

**Work.**
- Fill or drop `result`/`error`. Wire the top-level fields where the hook already computes a return
  value (the V8 VMP hooks that call `AppendXTraceStringField(event, "result", ...)` should promote
  that to the top level; set `error` on the `exception` phase). If not wired, delete the fields
  and document that outcome data lives in `args`. (`xtrace_logger.cc:392-393`,
  `CreateXTraceBrowserNetworkEventJson`.)
- Populate `frame_url`/`origin` at renderer hook time from the executing `ExecutionContext` /
  `LocalFrame`, which is in scope at the hook sites. (`xtrace_logger.cc:388-390`.)
- Make ordering real: either rename `seq` → `session_seq` to signal its scope, **or** stamp a true
  file-global counter in the single browser-side writer (cheap — all writes already serialize
  through one `SequencedTaskRunner`). Prefer the file-global counter; keep `session_seq` too for
  per-process reasoning.
- Collapse the duplicated truncation shapes (top-level `truncation{}` vs `args[0].original_args`)
  to one.
- Freeze the schema: write `docs/trace-schema-v2.md` as the single source of truth (field names,
  types, phases, which fields are populated on which event kinds).
- Contract test: a fresh smoke capture asserts documented fields are actually populated on the
  event kinds that should carry them. Upgrade `validate_schema_v1_event()`
  (`validate_trace.py:~1890`) from presence-only to populated-per-kind.

**Schema delta.** `result`, `error`, `frame_url`, `origin` become real; `global_seq` added;
`truncation` deduplicated.

**Validation.** Contract test green; re-run the 2080-event trace and confirm non-null/non-empty
rates jump from ~0% to ~100% on the relevant kinds.

**Effort.** M (mostly wiring existing data to existing fields). **Risk.** Low.

### Phase 1 — Structured causality (call tree)

**Goal.** Replace "stack string per event" with a real, walkable call tree.

**Design.**
- Add a **thread-local activation stack** in the renderer/V8 logger. Each instrumented call opens
  an *activation*: assign `call_id` (monotonic per isolate/thread), record `parent_id` = the
  `call_id` on top of the stack before push, record `depth` = stack size. On `return`/`exception`,
  pop; the paired events reuse the same `call_id`.
- This requires the hooks to be **scoped** (enter → push, exit → pop). Audit which APIs already emit
  paired `call`/`return` (the phase enum implies many do) vs single-shot. For paired sites, wrap
  with an RAII activation guard. For single-shot sites, synthesize a zero-duration activation whose
  `parent_id` is the current stack top.
- `call_id` must be namespaced like `event_id` is (`session_id:call_id`) so it stays globally unique
  across processes when the browser merges streams.

**Schema delta.** `call_id`, `parent_id`, `depth`, plus `duration_us` (return.t − call.t) on the
`return`/`exception` event.

**Consumer work.** `analyze_vmp_trace.py` gains a real tree builder (parent_id join) and can drop
the stack-string heuristics for nesting. GUI can render a flamechart/call-tree instead of a flat
tail.

**Validation.** Invariants in the contract test: every `parent_id` resolves to a prior `call`;
every `return`/`exception` shares a `call_id` with exactly one open `call`; no negative depth; no
orphan activations at trace end (except in-flight at teardown).

**Effort.** L (needs the hook-pairing audit + a shadow stack that survives exceptions/re-entrancy).
**Risk.** Med — re-entrancy and exception unwinding must not corrupt the stack; guard with RAII so a
C++ early-return can't leak an activation.

### Phase 2 — Value identity & data-flow (the deobfuscation payoff)

**Goal.** Let the analyzer follow a value through the VMP pipeline without runtime taint.

**Design (80/20, no interpreter shadowing).**
- For the curated VMP op set (`base64`, `text_codec`, `byte_buffer`, `dynamic_dispatch`,
  `proxy_trap`, `hash_crypto`, `int_bitwise`, `source_probe`), emit **structured value
  descriptors** for inputs and outputs instead of, or alongside, the flat `args` string:
  `{type, len, sha256_16, preview}` where `sha256_16` is a 16-byte content hash prefix.
- The real `result` field from Phase 0 carries the output descriptor; a new `in` array carries
  input descriptors.
- **Offline join.** `analyze_vmp_trace.py` builds a data-flow DAG by matching `out.sha256_16` of one
  op to `in.sha256_16` of a later op. This reconstructs "A's output fed B" from hashes — cheap to
  emit, robust to reordering, and exactly what VMP pipeline recovery needs.

**Why not full taint.** Real dynamic taint means shadowing every V8 value — enormous surface,
large perturbation, and overkill for the pipeline-recovery goal. Value-identity hashing gets ~all
the linkage at a fraction of the cost. (A narrow, flag-gated shadow-taint mode for a handful of ops
can be a much later, optional Phase 2b if hash collisions on short values prove limiting.)

**Schema delta.** `result` becomes a value descriptor; add `in: [descriptor...]`. Descriptor shape
frozen in `trace-schema-v2.md`.

**Validation.** On a known VMP sample, assert the analyzer reconstructs a connected data-flow DAG
whose sink matches the known signature output; measure fraction of ops with a resolved input edge.

**Effort.** M-L (descriptor plumbing is mechanical; the analyzer DAG + hash-join is the real work).
**Risk.** Med — short values (e.g. single ints in `int_bitwise`) collide on hash; mitigate by
including `type`+`len` in the join key and keeping full preview for small values.

### Phase 3 — Async causality

**Goal.** Link a callback event back to whatever scheduled it across ticks.

**Design (Node `async_hooks` model).**
- Install a V8 `PromiseHook` (`Isolate::SetPromiseHook`) to emit async-boundary events with
  `{async_id, trigger_async_id, kind: init|before|after|resolve}`.
- Instrument the Blink schedulers: `DOMTimer` schedule/fire (`setTimeout`/`setInterval`) and
  `queueMicrotask`/microtask checkpoint, emitting the same `async_id`/`trigger_async_id` pair.
- Tag **every** event with the current `async_id` (the async execution context it runs in) so leaf
  events inherit the chain without extra work.

**Schema delta.** `async_id` on every event; async-boundary events add `trigger_async_id` + `kind`.

**Consumer work.** Analyzer stitches async chains (`trigger_async_id` → `async_id`); combined with
Phase 1 this gives sync call-tree *within* a tick and async edges *across* ticks.

**Validation.** A fixture that schedules work via `await`, `.then`, `setTimeout`, and
`queueMicrotask` must produce a fully connected async graph with no orphan `async_id`.

**Effort.** M. **Risk.** Med — `PromiseHook` fires very frequently; must respect Phase-4 batching
and sampling or it dominates the trace.

### Phase 4 — Observer effect & volume (must precede 2-3 at scale)

**Goal.** Bound and configure capture cost so anti-debug timing stays normal and traces stay sane.

**Work.**
- **Batch.** Wire the already-implemented `LogBatch` (`xtrace_host_impl.cc:99`): renderer-side ring
  buffer flushed on N events or T ms, replacing per-event `Log()` IPC.
- **Gate stacks.** Make the 16-frame capture (`CaptureJavaScriptStack:178`) configurable per
  category/API; default to a shallow depth (e.g. 4) with full-depth on demand for a curated
  high-value API set.
- **Sample hot ops.** For dispatch-loop ops (thousands per signature computation), support 1/k
  sampling with an emitted running count, so the loop is characterized without logging every
  iteration.
- **Cap bodies/headers.** Apply `--xtrace-max-value-bytes` (or a new `--xtrace-max-body-bytes`) to
  `CreateXTraceUploadBodyJson` and header values, and actually set `truncated`/emit `truncation`
  when tripped (today the out-param is initialized `false` and never set).

**Schema delta.** Optional `sampled: {rate, count}` on sampled events; `truncation` now appears on
capped bodies/headers.

**Validation.** Perf regression harness: median added latency per instrumented call under a target;
timing-gate fixture (a page that branches on `performance.now()` deltas) takes the non-detected
branch with capture on. Trace-size ceiling on a fixed workload.

**Effort.** M. **Risk.** Med — batching adds a flush-on-crash data-loss window; flush on unload and
on IPC disconnect.

### Phase 5 — Coverage evenness audit

**Goal.** Confirm the lopsided 2068/9/3 split is workload, not instrumentation holes.

**Work.** Build a coverage matrix: for each declared category (`reverse`/`fingerprint`/`network`)
and each VMP family, a fixture that *must* trigger it, and assert events appear. Fill gaps where a
surface is under-instrumented. Bring `fingerprint` and `network` to parity with `reverse` in the
smoke matrix.

**Effort.** M (mostly fixtures + gap-filling). **Risk.** Low.

---

## 5. Target record shape (schema v2, illustrative)

```jsonc
{
  "schema_version": 2,
  "event_id":  "SID:42",        // globally unique
  "global_seq": 1337,           // file-global monotonic (Phase 0)
  "session_seq": 42,            // per-process (was `seq`)
  "session_id": "SID",
  "t": 12345678, "wall_time_us": ..., "mono_time_us": ...,
  "pid": 111, "tid": 222,
  "category": "reverse", "phase": "return", "api": "base64.encode",

  // attribution (Phase 0)
  "frame_url": "https://target/app.js", "origin": "https://target",

  // causality (Phase 1)
  "call_id": "SID:900", "parent_id": "SID:874", "depth": 7, "duration_us": 12,

  // async (Phase 3)
  "async_id": 55, "trigger_async_id": 40,

  // data flow (Phase 2)
  "in":  [{ "type": "Uint8Array", "len": 32, "sha256_16": "ab12…", "preview": "…" }],
  "result": { "type": "string", "len": 44, "sha256_16": "cd34…", "preview": "…" },
  "error": null,

  "args": "…",                  // retained; canonical structured data now in in/result
  "stack": [ /* depth-gated (Phase 4) */ ],
  "truncated": false
}
```

Legacy v1 fields kept where additive; `seq` retained as `session_seq`; `result`/`error` change
type (string→descriptor) — the reason this is a **version bump**, not additive.

---

## 6. Sequencing & effort

| Phase | Deliverable | Depends on | Effort | Payoff |
|---|---|---|---|---|
| 0 | Honest fields, frozen schema, contract test | — | M | Trust the record |
| 1 | Call tree (`call_id`/`parent_id`/`depth`) | 0 | L | Highest architectural |
| 4 | Batching, stack gating, sampling, caps | — (do early) | M | Enables 2-3 at scale |
| 2 | Value-identity + data-flow DAG | 0, (4) | M-L | Deobfuscation win |
| 3 | Async causality | 4 | M | Cross-tick correlation |
| 5 | Coverage matrix / parity | 0 | M | Confidence |

Recommended order: **0 → 4 → 1 → 2 → 3 → 5.** (0 first always; 4 before the volume-heavy phases;
1 before 2 because data-flow reads best on top of a call tree.)

---

## 7. Testing strategy

- **Golden traces.** Freeze a small captured trace per fixture; diff structurally (ignoring
  timestamps/pids) on every change to catch silent schema drift.
- **Contract test** (Phase 0, extended each phase): populated-field assertions + causal invariants
  (parent resolves, call/return pair, no orphan async_id, no negative depth).
- **Deobfuscation end-to-end** (Phase 2): on a known VMP sample, the analyzer must recover a
  connected data-flow DAG whose sink equals the known signature output.
- **Perf/timing regression** (Phase 4): per-call overhead ceiling + an anti-debug timing-gate
  fixture that must not detect instrumentation.
- **Coverage matrix** (Phase 5): every category/family fixture must emit its events.

---

## 8. Risks & open questions

- **Hook pairing (Phase 1).** How many instrumented sites emit paired `call`/`return` vs single
  shot? The activation-stack design needs this audit before estimates firm up; RAII guards are
  mandatory so C++ early-returns/exceptions can't leak activations.
- **Hash collisions (Phase 2).** Short values (single ints in `int_bitwise`) will collide; join key
  must include `type`+`len`, and small values keep a full preview.
- **PromiseHook cost (Phase 3).** Fires extremely often; hard-depends on Phase-4 batching/sampling.
- **Schema-v2 migration.** Consumers (`validate_trace.py`, `analyze_vmp_trace.py`, GUI, launcher)
  all read fields directly — bump them together, gate v1 emission behind a flag for one release.
- **Export safety.** Richer capture (value previews, full call trees, tokens) makes an exported
  trace even more sensitive. The opt-in export redactor from `trace-log-improvements.md` §3.1
  should land alongside Phase 2, not after.

---

## 9. Bottom line

The capture core is broad and works; the missing piece is *runtime semantics*. Phase 0 makes the
record honest, Phase 1 gives it a call tree, and Phase 2 gives it data flow — those three are what
turn XTrace from a wide per-call event logger into a genuine JS runtime-state trace. Phases 3-5
round out async, cost, and coverage. Do **0 → 4 → 1 → 2 → 3 → 5**.
