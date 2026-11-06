# Ignition bytecode steps

Opt-in trace of V8 Ignition (bytecode) execution. The category is `bytecode` and the API is `Ignition.step`. Events are ordinary schema v1 records, or schema v2 singletons when `--xtrace-causality=sync` is on. They use the same `seq`, `session_seq`, `mono_time_us`, `wall_time_us`, and, in v2, `call_id` / `parent_id` / `depth` as every other renderer event.

The feature is off unless the launcher passes `--xtrace-bytecode` (a V8 `--js-flags` switch). Turning it on also adds `bytecode` to `--xtrace-categories` when that list is not already `all`.

This tree was not compiled against the pinned Chromium revision. The patch matches V8 `af6aa2ec5047676cfb3150b46449faac7578be7e` (Chromium `73088b4e50b1dc69eaa0bdb14a8e4592813174fd`). Build and runtime checks are in the last section.

## Mechanism

V8's `--trace-ignition` prints bytecode to stdout, but the calls are emitted only when the interpreter builtins are generated with `V8_TRACE_UNOPTIMIZED`. A snapshot built without that define ignores the flag. Rebuilding the snapshot for every capture is the wrong switch for a session flag.

`patches/0005-xtrace-ignition-step.patch` leaves every bytecode handler unchanged. Ignition keeps a second dispatch table whose slots all point at one stub, `InterpreterTraceDispatch`. On arm64 and x64 the interpreter entry trampoline (and the return path back to that trampoline) picks a table:

- Flag byte is zero: one not-taken branch, then the clean table. Handlers run exactly as upstream.
- Flag is on: a one-entry cache of the bytecode-array pointer. A miss calls `Runtime_XTraceSelectDispatchTable` once. A non-matching function is cached as "clean" and is not pinned, so it can still tier up. A match is cached as "traced".
- Traced dispatch runs the stub, which calls `Runtime_XTraceBytecodeStep` and tail-calls the clean handler through the traced table, so the next bytecode re-enters the stub.

Wide and extra-wide prefixes are not logged; the stub tail-calls the real wide handler, which then dispatches the scaled opcode through the traced table. Inlined short `Star`s inside a clean handler are not separate steps. Other architectures keep the clean table only, so this patch does not trace them and does not add a per-bytecode check.

The step runtime does not allocate on the common path. Opcode allow and deny lists are a 256-bit set built once. Sampling and the step budget run before any formatting. Identity JSON is built once per matched function into a fixed buffer. Each step `memcpy`s that prefix and `snprintf`s the offset, opcode, scale, and a limited value (smi and number in full, string length only). Records sit in a thread-local buffer and flush about every eight steps as one `xtrace:bytecode-batch:` message. Drops (budget, or a record that does not fit) are counted and emitted as `Ignition.drop`.

`patches/0006-xtrace-ignition-step-blink.patch` turns that batch into one `XTraceHost::LogBatch`. Before any other V8 log line, Blink calls `XTraceFlushBytecodeBatch()` so later events stay after the steps. The renderer sandbox stays on.

### JIT tiers

Sparkplug, Maglev, and TurboFan do not run Ignition bytecode. Only a function that matches the script and function filters is pinned with `SharedFunctionInfo::DisableOptimization(kNeverOptimize)`. A cached non-match stays eligible for tier-up.

The first execution of a function is Ignition unless the process was started with `always_sparkplug` or an equivalent. Code that already tiered up before the filter matched is not stepped until it is deoptimized. Unfiltered `--xtrace-bytecode` pins every function that runs, because every function matches.

### Overhead and caps

With the flag off, the only added instruction stream is one predicted-not-taken branch each time execution returns to the entry trampoline, not once per bytecode. The handlers themselves are the upstream handlers.

With the flag on but the function filtered out, the next entries hit the cache and take the clean table. They do not enter the step runtime.

With the flag on and the function matching, each bytecode (except a wide prefix and an inlined short `Star`) enters the step runtime. The opcode bitset, sample counter, and budget run before the fixed-buffer format. The step budget stops emission. It does not clear `v8_flags.xtrace_bytecode`: V8 may freeze the flag page after startup, so a later store can fault. Steps past the budget increment a drop counter. `Ignition.drop` carries `{"kind":"vm_step_drop","dropped":N}`.

Value capture follows `--xtrace-capture-values` unless `--xtrace-bytecode-values` is set. The hot path does not copy string text and does not walk operand registers:

| Mode | What is recorded |
| --- | --- |
| `full` | Smi and number accumulators. A string accumulator is `accumulator_type: "string"` plus `accumulator_length`, with `truncated: false`. |
| `summary` | Same limited accumulator. String accumulators are length only. |
| `args-only` | Opcode, offset, and `LdaSmi` / `LdaZero` immediates. No accumulator. |

`operands` is empty except for `LdaSmi` and `LdaZero`. Other objects are omitted rather than printed, so the step path does not re-enter JavaScript. `--xtrace-bytecode-max-chars` remains on the flag list; this path does not use it because it does not copy string bytes. A batch can hold the last few steps until the next flush (another batch, a non-bytecode V8 event, or the next function select).

## Launcher flags

| Flag | Default when bytecode tracing is on | Role |
| --- | --- | --- |
| `--xtrace-bytecode` | off | Master switch. |
| `--xtrace-bytecode-scripts` | empty (all scripts) | Comma-separated URL substrings. Any match passes. |
| `--xtrace-bytecode-functions` | empty (all names) | Comma-separated function-name substrings. |
| `--xtrace-bytecode-opcodes` | empty (all opcodes) | Comma-separated exact Ignition names (`LdaSmi`, `JumpLoop`, `Star0`). |
| `--xtrace-bytecode-opcode-deny` | empty | Exact names to drop. |
| `--xtrace-bytecode-sample` | `1` | Emit 1 of every N matching steps. |
| `--xtrace-bytecode-budget` | `100000` | Emitted-step cap for the process. `0` is unlimited. |
| `--xtrace-bytecode-max-chars` | `512` | String cap before truncation metadata in `full` mode. |
| `--xtrace-bytecode-values` | the `--xtrace-capture-values` mode | `full`, `summary`, or `args-only`. |

Filter values cannot contain whitespace; they are placed in one `--js-flags` string. A non-empty script filter and a non-empty function filter must both match. Wide and extra-wide prefix bytecodes are not emitted. `SwitchOnSmiNoFeedback` and `JumpLoop` are normal opcodes and are what the dispatch-loop summary looks for.

## Event shape

`args` is a one-element array. `phase` is `call`. `stack` is `[]` (a stack walk per opcode is not taken). `frame_url` and `origin` stay empty on this hot path; identity is the fields below.

`args[0]`:

| Field | Type | Present |
| --- | --- | --- |
| `kind` | `"vm_step"` | always |
| `pre_state` | `true` | always |
| `capture_values` | `full`, `summary`, or `args-only` | always |
| `value_truncated` | bool | always, equal to top-level `truncated` |
| `script_id` | int | always |
| `script_url` | string | always, `""` when the script has no URL |
| `function_name` | string | always, `""` when the function is anonymous |
| `function_literal_id` | int | always; stable id of the shared function info inside the script |
| `bytecode_offset` | int ≥ 0 | always |
| `opcode` | string | always, `Bytecodes::ToString` |
| `operand_scale` | `Single`, `Double`, or `Quadruple` | always |
| `operands` | array | always |
| `accumulator_type` | string | `full` and `summary` |
| `accumulator` | JSON value | smi or number in `full` and `summary` |
| `accumulator_length` | int | string accumulator in `full` or `summary` |
| `registers` | array | not written by the hot path |

Operand objects have `index` (int), `type`, and `value`. The hot path fills that only for `LdaSmi` and `LdaZero`. `accumulator_length` is the V8 string length (UTF-16 code units).

`Ignition.drop` is a `call` in category `bytecode`. `args[0]` is `{"kind":"vm_step_drop","dropped":N}`.

Schema v2 adds the usual singleton fields. `Ignition.step` does not pair a return event and is not a parent of later records. `parent_id` is the active script activation when one is open. `duration_us` is null.

## Dispatch-loop summary

`scripts/analyze_vmp_trace.py` adds a `bytecode` object:

- `step_count` and `opcode_histogram` over `Ignition.step`
- `dispatch_loops`: functions with at least 32 steps and a `JumpLoop`, and either a `SwitchOnSmiNoFeedback` / `SwitchOnGeneratorState` or a compare/jump chain with at least four distinct `LdaSmi` / `LdaZero` / numeric `LdaConstant` immediates

Those immediates are reported as `guest_opcode_histogram`. This is a heuristic for a guest VM's opcode stream, not a lifted program. `hot_bytecode_offset` is the most frequent Ignition offset in that function (the dispatch PC when the loop is hot).

The file reader folds `Ignition.step` into that summary as it goes and does not keep the step objects. Per-function groups, guest immediates, and offsets are capped. `scripts/validate_trace.py` likewise keeps at most 8192 Ignition records and checks the rest online (shape, schema, `global_seq`, parent, and depth) so a multi-million-step trace stays bounded. A trace with no Ignition records uses the same checks as before. `dropped` on the summary is the sum of `Ignition.drop` counts.

## Build and check on macOS

Not run in this environment (no Chromium checkout, no Xcode):

```bash
scripts/bootstrap_chromium.sh
scripts/apply_patches.sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/gn_gen_xtrace.sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/build_chromium.sh

python3 scripts/serve_test_page.py --port 8765
cd xtrace-launcher
PYTHONPATH=. python3 -m xtrace_launcher run \
  --chromium ../chromium/src/out/XTrace/Chromium.app \
  --url http://127.0.0.1:8765/obfuscation-smoke.html \
  --log-dir ../logs \
  --xtrace-bytecode \
  --xtrace-bytecode-budget=2000 \
  --xtrace-bytecode-values=summary \
  --capture-seconds 20

python3 scripts/validate_trace.py --schema-version 1 ../logs/trace_*.ndjson
python3 scripts/analyze_vmp_trace.py --profile generic-vmp ../logs/trace_*.ndjson
```

`git -C chromium/src/v8 diff --check` after `apply_patches.sh` confirms the V8 patch applied cleanly. A full trace of an unfiltered page will pin every interpreted function and is expected to be large until the budget stops emission.
