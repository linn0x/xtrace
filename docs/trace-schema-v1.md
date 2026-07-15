# XTrace Trace Schema v1

`schema_version: 1` is a newline-delimited JSON event format for local XTrace captures. Each line is one event object. The schema is generic for JS/VMP/signature runtime analysis and is not tied to any site or parameter name.

## Ordering

- `seq` is scoped to the producer session. Renderer processes and browser-network capture each maintain their own sequence source, so bare `seq` is not a file-global order.
- Newer producers also emit `session_seq` as an explicit alias for `seq`, and `global_seq` as the browser-side write-order sequence stamped immediately before the event line is appended.
- `event_id` combines `session_id` and `seq` and is the stable event identity.
- Consumers must sort timelines by file position first. In code this is represented as `_file_index` or the NDJSON line number. If file position is unavailable, use `global_seq`, then `mono_time_us`, then `wall_time_us`/`ts`, and only then `seq` as a fallback.
- Duplicate or decreasing `seq` values across a trace are valid when they come from different producer sessions.

## Required Fields

Every schema v1 event has these top-level fields:

- `schema_version`: integer, currently `1`.
- `event_id`: string, unique for the producer session.
- `session_id`: string, producer/session identity.
- `seq`: integer, session-scoped sequence.
- `session_seq`: optional integer alias for `seq` in newer producers.
- `global_seq`: optional integer, file-global write sequence in newer producers.
- `t`: compact event type, usually matching `phase`.
- `wall_time_us` and `ts`: wall-clock microseconds.
- `mono_time_us`: monotonic microseconds from the producer process.
- `category`: high-level capture category such as `reverse`, `fingerprint`, or `network`.
- `phase`: one of `call`, `return`, `exception`, `get`, `set`, `lifecycle`, `complete`, or `iterate`.
- `api`: observed API or runtime hook name.
- `args`: array of captured argument/material objects.
- `stack`: array of JS stack frames when that hook captures stack; otherwise `[]`.
- `pid` and `tid`: producer process/thread ids.
- `frame_url`: execution frame, worker scope URL, browser referrer, or `""` when unavailable.
- `origin`: execution security origin, browser request initiator, or `""` when unavailable.
- `result` and `error`: compatibility fields. They may be `null`; authoritative return/error material currently lives in `args[*].result`, `args[*].result_ref`, `args[*].result_hex`, `args[*].error`, and related hook-specific fields.
- `truncated`: boolean.

## Context Attribution

Renderer hooks should fill `frame_url` and `origin` when they can obtain context cheaply at the hook site. Script evaluation events use the executing `ExecutionContext` URL and security origin. Worker and service-worker hooks should use the worker scope URL as `frame_url` and its scope origin as `origin`.

V8/VMP hot paths must not perform expensive context lookup or stack capture when that risks allocation, GC, or debug-side effects. They should keep lightweight numeric provenance such as `script_id`, `source_position`, `code_offset`, and `function_start_position`; analyzers resolve that provenance through the script registry built from script evaluation events.

Browser network events use request metadata: `frame_url` is the request referrer when available and `origin` is `request_initiator`. These are network-boundary context fields and should not be confused with nested `args` fields that describe API-specific data.

For a smoke or release contract, validate only APIs whose producer has cheap,
documented context available. For example:

```bash
python3 scripts/validate_trace.py --schema-version 1 \
  --expect ClassicScript.evaluate \
  --require-context-for ClassicScript.evaluate \
  path/to/trace.ndjson
```

`--require-context-for API` requires that API to occur and that every matching
event has non-empty `frame_url` and `origin`. It is deliberately opt-in: V8 hot
paths and injected hook records may not have cheap execution-context attribution.

## Truncation

Default capture is complete and local. No body/header cap is applied unless the user explicitly sets a positive cap.

When a producer truncates any value, the event must set:

- `truncated: true`
- top-level `truncation`: the authoritative truncation object

The `truncation` object includes:

- `original_size`: original byte/character size.
- `preview`: captured preview material.
- `hash`: hash of the complete original material.
- Optional `preview_size`, `path`, and `items` for multi-field truncation.

New producers should not emit nested `xtrace_truncated` or `original_args` as a second truncation schema. Consumers may continue to read those historical shapes for old traces, but top-level `truncated/truncation` is authoritative for schema v1.

## Raw Value Policy

Raw traces are local forensic artifacts. They may contain live headers, cookies, token-like query parameters, request/response values, upload bodies, and signature-related material. XTrace does not automatically upload them and does not redact them by default because incomplete values can mislead runtime reconstruction.

Any export/share workflow must make its own explicit redaction decision outside the raw trace producer.
