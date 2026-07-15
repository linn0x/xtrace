# XTrace trace schema v2

Schema v2 is an explicit opt-in (`--xtrace-causality=sync`). It preserves all
schema v1 fields and adds renderer-thread synchronous causal identity. It does
not infer Promise, timer, microtask, IPC, or cross-process parentage.

Every record in a v2 trace has these additional fields:

| Field | Type | Contract |
| --- | --- | --- |
| `call_id` | string or `null` | Renderer causal node ID, formatted as `session_id:activation_seq`; `null` only for `external`. |
| `parent_id` | string or `null` | Causal parent; roots use `null`. Parents precede children in trace order. |
| `depth` | non-negative integer | Root is `0`; each child is parent depth + 1. |
| `causality_kind` | `paired`, `singleton`, or `external` | Node relationship contract. |
| `duration_us` | non-negative integer or `null` | Present only on paired terminal (`return` or `exception`) events. |

`ClassicScript.evaluate` and `ModuleScript.evaluate` are paired activations:
one `call`, followed by exactly one `return` or `exception` sharing the same
`call_id`. Existing Blink and V8 runtime records are singleton children of the
active script activation; records emitted without an activation are singleton
roots. A renderer RAII scope keeps activation state balanced on early returns.

Browser-network and CDP-injected records remain producer-local observations.
In schema v2 they use `causality_kind: "external"`, `call_id: null`,
`parent_id: null`, `depth: 0`, and `duration_us: null`; they do not claim a
renderer parent.

Use `python scripts/validate_trace.py --schema-version 2 TRACE.ndjson` to
validate causal field types, parent ordering, depth, paired closure, and mixed
schema rejection. `scripts/analyze_vmp_trace.py --json-output` includes a
bounded `causality` tree while retaining the v1 timeline/stack heuristics.

## Local smoke baseline

On the release Chromium build, `causality-smoke.html` was captured for ten
seconds with the same optional CDP injection settings in both modes:

| Mode | Events | Trace bytes | Launcher wall time |
| --- | ---: | ---: | ---: |
| schema v1 | 7,289 | 10,237,203 | 10.62 s |
| schema v2 sync | 7,223 | 11,068,430 | 10.26 s |

The differing event count is normal startup/run noise. v2 added about 8.1% to
this trace size; no batching or stack-depth cap is introduced in this milestone.
