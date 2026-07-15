# XTrace Trace-Log Improvement Suggestions

Findings and recommendations for the schema v1 NDJSON trace log. This document is site-neutral: XTrace is a generic JS/VMP/signature runtime capture framework, and concrete target parameters are only examples used during local validation.

- Date: 2026-07-08
- Method: read both native patches, cross-checked against the **live** `chromium/src` source (not just the patches), and validated against real `logs/*.ndjson` captures.
- Scope: the trace-log producer and its consumers (`validate_trace.py`, `analyze_vmp_trace.py`, GUI). Not a security review.

> **Verification caveat (learned the hard way).** A captured `.ndjson` can come from a **stale binary** whose behavior no longer matches source. One finding below was initially reported backwards because a Jul-2 trace reflected a pre-Jul-1 binary. Always confirm behavior against live source **and** the built-binary mtime vs source tip, never from an old trace alone.

---

## Priority 1 — The log states fields that are never populated

### 1.1 `result` and `error` are hardcoded `null` on every event

**Observation.** Schema v1 documents `result` and `error` as top-level fields, but every producer path emits them as `null`:

- Renderer: `third_party/blink/renderer/platform/xtrace/xtrace_logger.cc` (event builder) — `line.append(",\"result\":null"); line.append(",\"error\":null");`
- Browser network: `chrome/browser/chrome_content_browser_client.cc` — `event.Set("result", base::Value()); event.Set("error", base::Value());`

Confirmed empirically: 0 / 2080 events non-null in a real capture. The V8 VMP hooks *do* capture return values (`AppendXTraceStringField(event, "result", ...)` for BigInt/JSON/URI-codec/string-case ops), but that data is serialized **inside the `args` string**, never the top-level field.

**Why it matters.** The schema promises an outcome channel that is always empty, and hides the outcome data that *is* captured somewhere a consumer wouldn't look. At GB-scale traces this is also dead bytes on every line.

**Suggestion.** Pick one:
- Wire `result`/`error` for real — have the hooks that already compute a return value populate the top-level field (and set `error` on the exception phase), or
- Drop both fields from the schema and document that outcome data lives in `args`.

Either is fine; the current half-state is the worst option.

### 1.2 `seq` is per-process, not per-file (non-monotonic, duplicated)

**Observation.** Two independent counters feed one shared trace file:
- Renderer: `NextSequenceNumber()` — a `static std::atomic` that restarts at 1 in every renderer process (main frame, isolated iframes, service workers).
- Browser network: `g_xtrace_browser_network_sequence` — a separate counter.

The browser process funnels all of them into one file via a single `SequencedTaskRunner`. Result on a real trace: `seq` ranges 1–1836 across 2080 lines, non-monotonic, with duplicates. `event_id` stays globally unique (`session_id:seq`, and `session_id` embeds pid), so no data is lost — but bare `seq` is misleading if read as file position.

**Why it matters.** `analyze_vmp_trace.py` already works around it (`event_order()` prefers `mono_time_us` over `seq`), but `validate_trace.py` only checks `seq` is *present*, never monotonic, and the GUI live-tail streams raw file order. Anyone reasoning about ordering from `seq` will be wrong.

**Suggestion.** Either rename the field to signal its scope (e.g. `session_seq`), or have the single browser-side writer stamp a true file-global counter at write time. The latter is cheap since all writes already serialize through one task runner, and it would give the log a real total order.

### 1.3 Truncation metadata is duplicated in two different shapes

**Observation.** A truncated event carries the same fact twice, differently named:
- Schema-documented top level: `truncated: true` + `truncation: {original_size, preview, hash}`.
- A second copy nested in the value: `args[0].xtrace_truncated: true` + `args[0].original_args: {original_size, preview, ...}`.

**Why it matters.** The preview string (potentially large) is stored twice; two names for one concept invites consumer bugs. `validate_trace.py`'s recursive walk happens to tolerate both.

**Suggestion.** Keep the top-level `truncation` object as the single source of truth; drop the nested `xtrace_truncated`/`original_args` duplicate (or make it a ref to the top-level one).

---

## Priority 2 — Attribution and coverage

### 2.1 `frame_url` / `origin` are empty on ~99.9% of events

**Observation.** In the renderer event builder these are hardcoded empty:
`third_party/blink/renderer/platform/xtrace/xtrace_logger.cc` — `line.append(",\"frame_url\":\"\""); line.append(",\"origin\":\"\"");`. Only the browser-network path fills them (from `request.referrer` / `request.request_initiator`). Confirmed: 3 / 2080 events had non-empty values, exactly the 3 network events.

**Why it matters.** Every fingerprint/reverse/VMP event — the actual point of the tool — has no frame or origin attribution. A real capture showed `chrome-extension://` service-worker lifecycle noise sitting in the `reverse` category indistinguishable from page-originated calls, because the field that would let you filter it is empty. This blocks multi-origin analysis and noise filtering.

**Suggestion.** Populate `frame_url`/`origin` at renderer hook time from the executing context (Blink has the frame/`ExecutionContext` on hand at the hook sites). High leverage relative to cost — probably worth more than new analysis features.

**Minor, related.** Some hooks add a nested `args.origin` (event-target origin) that collides in name with the top-level `origin` (network-initiator origin) but means something different. Rename one before it causes a mix-up in the report layer.

---

## Priority 3 — Security boundary: doc vs. code

### 3.1 Header/cookie/token values are captured in full, contradicting the stated boundary

**Observation.** Earlier project docs described sensitive headers/cookies/tokens/signature values as redacted or summarized, but the runtime producer deliberately captures raw values for local reconstruction. Commit `0d9e19e` **"Preserve full browser network inputs"** (Jul 1) removed both `header.Set("redacted", true)` and the old fixed length cap, replacing them with plain `header.Set("value", value)`. The checked-in patch and live source agree — there is **no** patch/source drift here, and current default capture is full fidelity for token-like header/query/cookie material. `redacted: true` seen in older smoke traces is a relic of a then-stale binary, not current behavior.

**Why it matters.** Full capture is genuinely needed for authorized reconstruction of target signature parameters and token-like request material. But the doc previously promised the opposite, so a trace that leaves the machine carries more than the doc implied it would.

**Suggestion.** Reconcile the two, don't leave them contradictory:
- Update §11 to state the real boundary honestly: full local capture, and *local-only storage* is the actual protection — plus an explicit warning that raw traces contain live tokens/cookies and must not be shared as-is; **and/or**
- Add an export-side redaction mode (denylist or, better, an allowlist of known-benign header/query/cookie names) that applies only when a trace is shared, keeping full fidelity for local analysis.

---

## Priority 4 — Volume and performance

### 4.1 `LogBatch` is implemented but never called

**Observation.** `blink.mojom.XTraceHost.LogBatch` is fully implemented browser-side (`content/browser/xtrace/xtrace_host_impl.cc`) but has **no call site** anywhere — every event pays its own Mojo IPC round trip via `Log()`. Additionally, `LogEvent` (vs `LogEventNoStack`) does a synchronous 16-frame V8 stack capture per call.

**Why it matters.** In the VMP dispatch loops this tool exists to observe (thousands of base64/bitwise/dispatch ops per signature computation), per-op IPC + stack capture is real overhead — it feeds both the observer effect on timing-sensitive anti-debug gates and the GB-scale trace sizes already flagged in §12 of the technical doc.

**Suggestion.** Batch events on the renderer side (ring buffer flushed on size/time threshold) through the existing `LogBatch`. Consider gating full stack capture behind a config knob or capturing it only for a curated set of high-value APIs.

### 4.2 Upload request bodies are hex-encoded uncapped

**Observation.** `CreateXTraceUploadBodyJson` appends every in-memory body element into `body_bytes`, then emits full `body_hex` + `body_sha256`. Its `truncated` out-param is initialized `false` and **never set to `true`** anywhere in the function — there is no size cap (unlike the renderer value path, which respects `--xtrace-max-value-bytes`). Header values are now uncapped too (§3.1 removed `kXTraceMaxHeaderValueBytes`).

**Why it matters.** A single large POST writes its entire body (hex = 2× size) into the trace. Combined with 4.1, this is the main driver of runaway trace files.

**Suggestion.** Apply a byte cap to upload bodies (reuse `--xtrace-max-value-bytes` or add `--xtrace-max-body-bytes`), and set `truncated`/emit `truncation` metadata when it trips — consistent with the value path. Same for header values.

---

## Priority 5 — Make the schema self-verifying

### 5.1 No schema doc; the validator only checks field *presence*

**Observation.** `validate_schema_v1_event()` checks that required fields exist, that `phase` is valid, and that `truncated` is a bool — but never that documented fields are non-trivially populated. So findings 1.1, 1.2, and 2.1 all pass validation silently. There is no standalone schema doc; the fields are described only in prose in `docs/technical-solution.md` §5 and the README.

**Why it matters.** The producer and doc can drift from reality (they have), and nothing catches it. §12 of the technical doc already lists "freeze schema v1 into its own doc" as a next step — this seconds it with concrete justification.

**Suggestion.**
- Write `docs/trace-schema-v1.md` as the single source of truth for field names, types, phases, and which fields are populated on which event kinds.
- Add a contract test: run a fresh smoke capture and assert that documented fields are actually populated on the event kinds that should carry them (would have caught 1.1 / 2.1 immediately). Keep it in the smoke matrix §12 already proposes.

---

## Summary table

| # | Finding | Severity | Rough effort |
|---|---------|----------|--------------|
| 1.1 | `result`/`error` always null | High | Low (drop) / Med (wire) |
| 1.2 | `seq` per-process, not file-global | Med | Low–Med |
| 1.3 | Duplicated truncation shapes | Low | Low |
| 2.1 | `frame_url`/`origin` empty except network | High | Med |
| 3.1 | Full header/token capture contradicts older §11 wording | High (policy) | Low (doc) / Med (export-side redaction) |
| 4.1 | `LogBatch` unused; per-event IPC + stack | Med | Med |
| 4.2 | Upload bodies / headers uncapped | Med | Low |
| 5.1 | Schema doc + populated-field contract test | Med | Low–Med |
