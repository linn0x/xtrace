# Ignition bytecode steps

Opt-in trace of V8 Ignition (bytecode) execution. The category is `bytecode` and the API is `Ignition.step`. Events are ordinary schema v1 records, or schema v2 singletons when `--xtrace-causality=sync` is on. They use the same `seq`, `session_seq`, `mono_time_us`, `wall_time_us`, and, in v2, `call_id` / `parent_id` / `depth` as every other renderer event.

The feature is off unless the launcher passes `--xtrace-bytecode` (a V8 `--js-flags` switch). Turning it on also adds `bytecode` to `--xtrace-categories` when that list is not already `all`.

This tree was not compiled against the pinned Chromium revision. The patch matches V8 `af6aa2ec5047676cfb3150b46449faac7578be7e` (Chromium `73088b4e50b1dc69eaa0bdb14a8e4592813174fd`). Build and runtime checks are in the last section.

## Mechanism

V8's `--trace-ignition` prints bytecode to stdout, but the calls are emitted only when the interpreter builtins are generated with `V8_TRACE_UNOPTIMIZED`. A snapshot built without that define ignores the flag. Rebuilding the snapshot for every capture is the wrong switch for a session flag.

`patches/0005-xtrace-ignition-step.patch` instead emits, at the start of every Ignition handler and in the inlined short-`Star` path, a load of `v8_flags.xtrace_bytecode` (`LoadRuntimeFlag` on `ExternalReference::address_of_xtrace_bytecode_enabled`). The flag word is the first byte of `FlagValue<bool>`. When it is zero the handler branches past `Runtime_XTraceBytecodeStep`. When it is set, the runtime function decodes the bytecode array at the current offset — the same inputs as `Runtime_TraceUnoptimizedBytecodeEntry` — and sends one event through `isolate->event_logger()`.

That entry point is one site for every opcode, including wide variants, and it sees the bytecode the handler is about to run. Debug-break stepping was not used: it depends on the debugger, rewrites bytecode, and perturbs timing more than a flag check. Per-opcode hooks in Torque or each CSA handler would be a much larger, easier-to-miss patch against this pinned revision.

`patches/0006-xtrace-ignition-step-blink.patch` parses the `xtrace:bytecode:` prefix in the existing V8 event logger and writes the NDJSON line with `XTraceLogger`, so `seq` / `mono_time_us` and schema v2 causality stay on the renderer path. The renderer sandbox stays on; the line still crosses `blink.mojom.XTraceHost`.

### JIT tiers

Sparkplug, Maglev, and TurboFan do not run Ignition bytecode. The first time a function passes the script and function filters, the runtime calls `SharedFunctionInfo::DisableOptimization(kNeverOptimize)` so later tier-up does not drop that function out of Ignition. Other functions still tier up.

The first execution of a function is Ignition unless the process was started with `always_sparkplug` or an equivalent. Code that already tiered up before the filter matched is not stepped until it is deoptimized. Unfiltered `--xtrace-bytecode` pins every function that runs, because every function matches.

### Overhead and caps

With the flag off, each bytecode still executes one predicted-not-taken load and branch. That cost is in the patched binary even when tracing is disabled; it is the price of a runtime switch that does not rebuild the snapshot.

With the flag on, every interpreted bytecode of every function enters the runtime. Script, function, and opcode filters return before JSON formatting, and a one-entry cache skips repeat string work for the current function. The step budget stops emission. It does not clear `v8_flags.xtrace_bytecode`: V8 may freeze the flag page after startup, so a later store can fault. After the budget, the runtime returns immediately and the branch remains.

Value capture follows `--xtrace-capture-values` unless `--xtrace-bytecode-values` is set:

| Mode | What is recorded |
| --- | --- |
| `full` | Accumulator and operand-register values. Strings longer than `--xtrace-bytecode-max-chars` set `truncated: true` and top-level `truncation` (`original_size`, `preview`, `hash`). |
| `summary` | Types, numeric and boolean values, and string lengths. No string text and no truncation flag. |
| `args-only` | Opcode, offset, immediate operands, and register names. No accumulator and no register values. |

Register values are the pre-instruction state (handler entry). At most eight registers are formatted; a wider list sets `truncated`. `hash` is `fnv1a64:` plus 16 hex digits of FNV-1a over the original UTF-8 bytes, not SHA-1.

Objects, symbols, and bigints are recorded by type. Printing them would re-enter JavaScript.

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
| `accumulator` | JSON value | `full`; `summary` except string accumulators |
| `accumulator_length` | int | `summary` when the accumulator is a string |
| `registers` | array | `full` and `summary` when any operand register was read |

Operand objects have `index` (int) and `type` (Ignition operand type name). Immediates and indexes put the number in `value`. Register operands put the register name in `name`. In `full` / `summary`, register objects in `registers` use `name`, `type`, and either `value` or, for summary strings, `value_length`. Constant-pool operands use `value` for the pool index and, outside `args-only`, `constant` / `constant_type` for the pool entry.

String `accumulator_length` and `value_length` are V8 string lengths (UTF-16 code units). Truncation `original_size` is the UTF-8 byte size, or the full register count when the eight-register cap fired.

Schema v2 adds the usual singleton fields. `Ignition.step` does not pair a return event. `parent_id` is the active script activation when one is open.

## Dispatch-loop summary

`scripts/analyze_vmp_trace.py` adds a `bytecode` object:

- `step_count` and `opcode_histogram` over `Ignition.step`
- `dispatch_loops`: functions with at least 32 steps and a `JumpLoop`, and either a `SwitchOnSmiNoFeedback` / `SwitchOnGeneratorState` or a compare/jump chain with at least four distinct `LdaSmi` / `LdaZero` / numeric `LdaConstant` immediates

Those immediates are reported as `guest_opcode_histogram`. This is a heuristic for a guest VM's opcode stream, not a lifted program. `hot_bytecode_offset` is the most frequent Ignition offset in that function (the dispatch PC when the loop is hot).

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
