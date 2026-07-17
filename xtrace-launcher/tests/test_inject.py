"""Browser-free tests for the patch-free API-hook injector.

The CDP/websocket path (find_page_ws, run_injector) needs a live Chromium and is
validated manually; here we cover the preamble substitution and the clock
alignment/merge that turns injected events into windowable trace records."""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from xtrace_launcher import inject


class PreambleTests(unittest.TestCase):
    def test_binding_is_substituted_as_js_string(self):
        # the __XTRACE_BINDING__ placeholder must resolve to a quoted JS string,
        # not `window.<name>` (that was a real bug that broke the whole preamble)
        self.assertNotIn("__XTRACE_BINDING__", inject.PREAMBLE)
        self.assertIn('const B = "__xtrace_emit";', inject.PREAMBLE)
        self.assertIn("window[B](", inject.PREAMBLE)

    def test_preamble_uses_pristine_stringify(self):
        # emit() must use a pre-wrap JSON.stringify ref to avoid self-recursion
        self.assertIn("const _stringify = JSON.stringify;", inject.PREAMBLE)
        self.assertIn("if (_busy) return;", inject.PREAMBLE)

    def test_jscrypto_input_scan_present(self):
        # digest/AES input for JS-implemented crypto (CryptoJS reads the message
        # char-by-char via charCodeAt) is captured as a deduped String.scan event
        self.assertIn("String.scan", inject.PREAMBLE)
        self.assertIn("String.prototype.charCodeAt = hooked", inject.PREAMBLE)
        self.assertIn("!== _lastScan", inject.PREAMBLE)   # dedup, not per-char
        # must only materialize on i===0 — full-string copy on every char is O(n^2)
        self.assertIn("(i | 0) === 0", inject.PREAMBLE)
        # delayed install; re-arm via microtask so mid-scan chars stay native-speed
        self.assertIn("SCAN_DELAY_MS", inject.PREAMBLE)
        self.assertIn("queueMicrotask", inject.PREAMBLE)

    def test_scan_hook_stays_armed_across_back_to_back_scans(self):
        # Regression: a signer parses the body THEN the canonical preimage in ONE
        # sync turn. The hook must NOT disarm globally after the first scan (which
        # would drop the canonical -- the exact JD hash-input miss). Disarm is now
        # gated behind a high length threshold (pathological strings only).
        p = inject.PREAMBLE
        self.assertIn("SCAN_FASTPATH", p)
        self.assertIn("(i | 0) === 0 && !_busy", p)          # armed + re-entrancy safe
        # the only disarm is guarded by the fast-path length threshold
        disarm = "String.prototype.charCodeAt = orig;"
        idx = p.index(disarm)
        self.assertIn("len >= SCAN_FASTPATH", p[max(0, idx - 200):idx])

    def test_build_preamble_templates_scan_delay_and_cap(self):
        self.assertIn("SCAN_DELAY_MS = 1234;", inject.build_preamble(1234))
        self.assertIn("SCAN_CAP = 9999,", inject.build_preamble(scan_cap=9999))
        for p in (inject.build_preamble(500, 500), inject.PREAMBLE):
            self.assertNotIn("__SCAN_DELAY_MS__", p)   # all placeholders filled
            self.assertNotIn("__SCAN_CAP__", p)
            self.assertNotIn("__CAP__", p)

    def test_boundary_value_cap_is_full_and_configurable(self):
        # the crypto/JSON/btoa boundary preview must not clip to the old hardcoded
        # 512; CAP defaults to scan_cap (4096) and is templatable independently
        self.assertIn("const CAP = 4096;", inject.PREAMBLE)
        self.assertNotIn("const CAP = 512;", inject.PREAMBLE)
        self.assertIn("const CAP = 128;", inject.build_preamble(cap=128))
        self.assertIn("const CAP = 7000;", inject.build_preamble(scan_cap=7000))  # defaults to scan_cap
        # typed-array (ArrayBuffer) hex must honor CAP, not a fixed 64 bytes --
        # crypto.subtle digest/encrypt inputs are buffers
        self.assertIn("Math.min(v.byteLength, CAP)", inject.PREAMBLE)
        self.assertNotIn("Math.min(v.byteLength, 64)", inject.PREAMBLE)

    def test_crypto_subtle_outputs_are_captured(self):
        # replay/oracle needs the OUTPUT bytes, not just the input: crypto.subtle
        # methods are wrapped with ret=true and emit an <api>.ret event when the
        # result promise resolves, via a passive spur .then (chain unchanged)
        self.assertIn('wrap(crypto.subtle, m, "SubtleCrypto." + m, true)', inject.PREAMBLE)
        self.assertIn('emit(api + ".ret", [preview(v)])', inject.PREAMBLE)
        self.assertIn("typeof r.then === \"function\"", inject.PREAMBLE)

    def test_wasm_boundary_wrapping_present(self):
        self.assertIn("WebAssembly.export", inject.PREAMBLE)
        self.assertIn("WebAssembly.import", inject.PREAMBLE)
        # exports must be wrapped via Object.create, NOT a Proxy: WASM export
        # props are read-only + non-configurable, so a Proxy get() returning a
        # different fn violates a Proxy invariant and breaks instantiation.
        self.assertIn("Object.create(inst", inject.PREAMBLE)


class AlignAndAppendTests(unittest.TestCase):
    def test_injected_events_get_native_mono_clock_and_append(self):
        with TemporaryDirectory() as d:
            native = Path(d) / "trace.ndjson"
            inj = Path(d) / "trace.inject.ndjson"
            # realistic clock scales: mono ~ 4e11 us since boot, wall ~ epoch us
            M0, W0 = 400_000_000_000, 1_783_000_000_000_000  # offset = M0 - W0
            native.write_text("\n".join(json.dumps(e) for e in [
                {"api": "A", "mono_time_us": M0, "wall_time_us": W0, "global_seq": 1},
                {"api": "B", "mono_time_us": M0 + 100, "wall_time_us": W0 + 100, "global_seq": 2},
            ]) + "\n")
            inj.write_text(json.dumps(
                {"api": "TextEncoder.encode", "category": "inject",
                 "wall_time_us": W0 + 50, "args": [{"value": "x"}]}) + "\n")

            n = inject.align_and_append(native, inj)
            self.assertEqual(n, 1)

            rows = [json.loads(x) for x in native.read_text().splitlines()]
            self.assertEqual(len(rows), 3)               # appended
            added = rows[-1]
            self.assertEqual(added["category"], "inject")
            self.assertEqual(added["mono_time_us"], M0 + 50)   # wall + (M0 - W0)
            self.assertEqual(added["global_seq"], 3)               # continues seq
            self.assertIn("stack", added)
            for field in ("schema_version", "event_id", "session_id", "seq", "session_seq",
                          "t", "ts", "phase", "pid", "tid", "frame_url", "origin",
                          "result", "error", "truncated"):
                self.assertIn(field, added)
            self.assertEqual(added["schema_version"], 1)
            self.assertEqual(added["seq"], 1)
            self.assertEqual(added["session_seq"], 1)
            self.assertTrue(added["session_id"].startswith("inject:"))
            self.assertEqual(added["event_id"], f"{added['session_id']}:1")

    def test_missing_files_are_noops(self):
        with TemporaryDirectory() as d:
            self.assertEqual(inject.align_and_append(Path(d) / "no.ndjson",
                                                     Path(d) / "no.inject.ndjson"), 0)

    def test_schema_v2_injected_events_are_external(self):
        with TemporaryDirectory() as d:
            native = Path(d) / "trace.ndjson"
            injected = Path(d) / "trace.inject.ndjson"
            native.write_text(json.dumps({
                "api": "A", "mono_time_us": 500, "wall_time_us": 1_800_000_000_000_000,
            }) + "\n")
            injected.write_text(json.dumps({
                "api": "JSON.stringify", "wall_time_us": 1_800_000_000_000_100, "args": [],
            }) + "\n")
            self.assertEqual(inject.align_and_append(native, injected, schema_version=2), 1)
            added = json.loads(native.read_text().splitlines()[-1])
            self.assertEqual(added["schema_version"], 2)
            self.assertEqual(added["causality_kind"], "external")
            self.assertIsNone(added["call_id"])
            self.assertIsNone(added["parent_id"])
            self.assertEqual(added["depth"], 0)
            self.assertIsNone(added["duration_us"])

    def test_legacy_native_trace_does_not_gain_partial_global_sequence(self):
        with TemporaryDirectory() as d:
            native = Path(d) / "trace.ndjson"
            injected = Path(d) / "trace.inject.ndjson"
            native.write_text(json.dumps({
                "api": "A", "mono_time_us": 500, "wall_time_us": 1_800_000_000_000_000,
            }) + "\n")
            injected.write_text(json.dumps({
                "api": "B", "wall_time_us": 1_800_000_000_000_100, "args": [],
            }) + "\n")
            self.assertEqual(inject.align_and_append(native, injected), 1)
            rows = [json.loads(line) for line in native.read_text().splitlines()]
            self.assertNotIn("global_seq", rows[-1])


if __name__ == "__main__":
    unittest.main()
