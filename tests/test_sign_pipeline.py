"""Tests for scripts/sign_pipeline.py generalisation.

Uses a synthetic NDJSON trace (a compute burst in a signer script followed by a
request whose token is carried in the POST body) so the assertions do not depend
on any captured Chromium trace.
"""
import argparse
import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import sign_pipeline as sp  # noqa: E402

TOKEN = "aZ9kQ2mV8xR4tB7wL1pE5nD3sC6uH0gYtW"
SIGNER = "https://cdn.example.com/signer.js"


def write_synth_trace(path: Path, carrier="body", families="bitwise"):
    """Compute burst in SIGNER + a signed request carrying TOKEN via `carrier`."""
    T = 1_000_000_000.0
    lines, prev = [], None
    api = {"bitwise": "Bitwise.xor", "crypto": "SubtleCrypto.digest",
           "encoder": "TextEncoder.encode"}[families]
    for i in range(12):
        rr = f"number:{1000 + i}.000000"
        lines.append({
            "api": api, "category": "reverse", "mono_time_us": T - 100000 + i * 5000,
            "global_seq": i + 1,
            "args": [{"callsite_script": SIGNER, "callsite_function": "h",
                      "callsite_column": 4200 + i, "left": 7.0, "right": float(i),
                      "result": float(1000 + i),
                      "left_ref": prev or "number:7.000000",
                      "right_ref": f"number:{i}.000000", "result_ref": rr}]})
        prev = rr
    arg = {"method": "POST", "headers": [], "has_request_body": True}
    if carrier == "body":
        body = json.dumps({"header": {"aid": 123}, "sign": TOKEN}).encode().hex()
        arg["url"] = "https://api.example.com/submit?ts=1"
        arg["upload_body"] = {"body_hex": body}
    elif carrier == "query":
        arg["url"] = f"https://api.example.com/submit?ts=1&X-Sig={TOKEN}"
    lines.append({"api": "BrowserNetwork.request", "category": "network",
                  "mono_time_us": T, "global_seq": 99, "args": [arg]})
    path.write_text("\n".join(json.dumps(x) for x in lines) + "\n")


class SignPipelineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.trace = self.tmp / "synth.ndjson"

    def tearDown(self):
        self._tmp.cleanup()

    def test_discover_finds_body_carrier(self):
        write_synth_trace(self.trace, carrier="body")
        cands = sp.find_carriers(self.trace, window_ms=300, min_entropy=4.0,
                                 top=10, families=["bitwise"])
        by_name = {c["name"]: c for c in cands}
        self.assertIn("body.sign", by_name)
        self.assertEqual(by_name["body.sign"]["where"], ["body"])
        self.assertGreater(by_name["body.sign"]["max_compute_burst"], 0)

    def test_explain_anchors_on_body_and_detects_signer(self):
        write_synth_trace(self.trace, carrier="body")
        out = self.tmp / "out"
        rc = sp.main(["explain", "--trace", str(self.trace), "--out", str(out)])
        self.assertEqual(rc, 0)
        summary = json.loads((out / "summary.json").read_text())
        self.assertEqual(summary["anchor"]["carrier"], "body.sign")
        self.assertEqual(summary["signer_script"], SIGNER)
        self.assertGreater(summary["dag"]["inputs"], 0)
        token = json.loads((out / "token.json").read_text())
        self.assertEqual(token["tokens"]["body.sign"]["value"], TOKEN)

    def test_explain_writes_pairing_and_crypto_inputs(self):
        write_synth_trace(self.trace, carrier="body")
        out = self.tmp / "out"
        self.assertEqual(sp.main(["explain", "--trace", str(self.trace), "--out", str(out)]), 0)
        pairing = json.loads((out / "pairing.json").read_text())
        for k in ("token_field_pairing_rate", "capture_truncated_events",
                  "token_fields_total", "crypto_inputs_total"):
            self.assertIn(k, pairing)
        self.assertGreaterEqual(pairing["token_fields_total"], 1)
        self.assertTrue((out / "crypto_inputs.json").exists())

    def test_crypto_outputs_are_separated_from_inputs(self):
        # --inject-api-hooks captures the INPUT plaintext and the paired OUTPUT
        # bytes (<api>.ret). explain must route outputs to crypto_outputs.json and
        # never let a digest/signature be mistaken for hashed material in inputs.
        write_synth_trace(self.trace, carrier="body", families="crypto")
        T = 1_000_000_000.0
        plaintext = "PLAINTEXT-TO-HASH-abcdefghijklmnop"
        inject_events = [
            # input: plaintext fed to digest (callsite is top-level, args are pure
            # previews -- exactly the shape align_and_append produces)
            {"api": "SubtleCrypto.digest", "category": "inject",
             "mono_time_us": T - 60000, "global_seq": 200,
             "callsite_function": "enc", "callsite_script": SIGNER,
             "args": [{"type": "string", "len": len(plaintext), "value": plaintext}]},
            # output: the resulting digest bytes, emitted as <api>.ret
            {"api": "SubtleCrypto.digest.ret", "category": "inject",
             "mono_time_us": T - 59000, "global_seq": 201,
             "callsite_function": "enc", "callsite_script": SIGNER,
             "args": [{"type": "Uint8Array", "byteLength": 32, "hex": "ab" * 32}]},
        ]
        with self.trace.open("a") as fh:
            for e in inject_events:
                fh.write(json.dumps(e) + "\n")
        out = self.tmp / "out"
        self.assertEqual(sp.main(["explain", "--trace", str(self.trace), "--out", str(out)]), 0)
        inputs = json.loads((out / "crypto_inputs.json").read_text())
        outputs = json.loads((out / "crypto_outputs.json").read_text())
        in_apis = [r["api"] for r in inputs["inputs"]]
        out_apis = [r["api"] for r in outputs["outputs"]]
        self.assertIn("SubtleCrypto.digest", in_apis)          # plaintext input kept
        self.assertNotIn("SubtleCrypto.digest.ret", in_apis)   # output not in inputs
        self.assertIn("SubtleCrypto.digest.ret", out_apis)     # output surfaced
        self.assertEqual(json.loads((out / "summary.json").read_text())["crypto_outputs"],
                         len(outputs["outputs"]))

    def test_explain_writes_per_field_sign_artifact(self):
        # the keystone: one self-contained object per carrier leaf field, plus
        # shared phases/env/candidate pools, assembled from observed capture.
        write_synth_trace(self.trace, carrier="body", families="crypto")
        T = 1_000_000_000.0
        inject_events = [
            # the token observed as plaintext (String.scan) -> direct evidence
            {"api": "String.scan", "category": "inject",
             "mono_time_us": T - 55000, "global_seq": 202,
             "callsite_function": "s", "callsite_script": SIGNER,
             "args": [{"type": "string", "len": len(TOKEN), "value": TOKEN}]},
            # a crypto output byte string in the same window
            {"api": "SubtleCrypto.digest.ret", "category": "inject",
             "mono_time_us": T - 54000, "global_seq": 203,
             "callsite_function": "s", "callsite_script": SIGNER,
             "args": [{"type": "Uint8Array", "byteLength": 32, "hex": "cd" * 32}]},
        ]
        with self.trace.open("a") as fh:
            for e in inject_events:
                fh.write(json.dumps(e) + "\n")
        out = self.tmp / "out"
        self.assertEqual(sp.main(["explain", "--trace", str(self.trace), "--out", str(out)]), 0)
        art = json.loads((out / "sign_artifact.json").read_text())
        for key in ("note", "anchor", "phases", "env",
                    "candidate_inputs", "candidate_outputs", "fields"):
            self.assertIn(key, art)
        by_field = {f["field"]: f for f in art["fields"]}
        self.assertIn("body.sign", by_field)
        field = by_field["body.sign"]
        self.assertEqual(field["output_value"], TOKEN)
        self.assertEqual(field["evidence"], "direct")           # scanned as plaintext
        self.assertTrue(any(m["api"] == "String.scan" for m in field["materials"]))
        self.assertIn("dag", field)                             # present (may be null)
        # the .ret output byte string is available as a replay candidate
        self.assertTrue(any((o["api"] or "").endswith(".ret") for o in art["candidate_outputs"]))
        summary = json.loads((out / "summary.json").read_text())
        self.assertEqual(summary["sign_artifact_fields"], len(art["fields"]))

    def test_replay_oracle_proves_hashed_field_pairing_cannot(self):
        # the "半知→可证" step: a field pairing calls unpaired (it is a hash, never
        # observed as plaintext) is PROVEN by replay to be sha256(observed input).
        plain = "user=42&ts=1783000000&nonce=abcdefghijklmnop"
        digest = hashlib.sha256(plain.encode()).hexdigest()
        T = 1_000_000_000.0
        lines, prev = [], None
        for i in range(12):
            rr = f"number:{1000 + i}.000000"
            lines.append({"api": "Bitwise.xor", "category": "reverse",
                          "mono_time_us": T - 100000 + i * 5000, "global_seq": i + 1,
                          "args": [{"callsite_script": SIGNER, "callsite_function": "h",
                                    "callsite_column": 4200 + i, "left": 7.0, "right": float(i),
                                    "result": float(1000 + i),
                                    "left_ref": prev or "number:7.000000",
                                    "right_ref": f"number:{i}.000000", "result_ref": rr}]})
            prev = rr
        lines.append({"api": "String.scan", "category": "inject", "mono_time_us": T - 55000,
                      "global_seq": 50, "callsite_function": "s", "callsite_script": SIGNER,
                      "args": [{"type": "string", "len": len(plain), "value": plain}]})
        body = json.dumps({"header": {"aid": 123}, "sign": digest}).encode().hex()
        lines.append({"api": "BrowserNetwork.request", "category": "network", "mono_time_us": T,
                      "global_seq": 99, "args": [{"method": "POST", "headers": [],
                      "has_request_body": True, "url": "https://api.example.com/submit?ts=1",
                      "upload_body": {"body_hex": body}}]})
        self.trace.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
        out = self.tmp / "out"
        self.assertEqual(sp.main(["explain", "--trace", str(self.trace), "--out", str(out),
                                  "--carrier", "body.sign"]), 0)
        # pairing cannot pair a hash it never saw as plaintext
        self.assertEqual(json.loads((out / "pairing.json").read_text())["token_field_pairing_rate"], 0.0)
        # the artifact carries the FULL input (not the 80-char preview) so replay can re-hash
        ci = json.loads((out / "sign_artifact.json").read_text())["candidate_inputs"]
        self.assertTrue(any(c.get("value") == plain for c in ci))
        # replay proves it
        self.assertEqual(sp.main(["replay", str(out)]), 0)
        rep = json.loads((out / "replay.json").read_text())
        self.assertEqual(rep["summary"]["resolution_rate"], 1.0)
        self.assertEqual(rep["summary"]["newly_resolved_vs_pairing"], 1)
        d0 = rep["fields"][0]["derivations"][0]
        self.assertEqual((d0["algo"], d0["encoding"], d0["match_kind"]),
                         ("sha256", "hex_lower", "exact"))
        self.assertEqual(d0["input_api"], "String.scan")

    def test_replay_oracle_units_edge_encoding_and_unresolved(self):
        plain = "abcdefghijklmnop-0123456789"
        art = {
            "anchor": {"carrier": "t"},
            "candidate_inputs": [{"api": "String.scan", "d_ms": -5,
                                  "value_sha": "aa", "value": plain}],
            "candidate_outputs": [{"api": "SubtleCrypto.digest.ret", "d_ms": -4,
                                   "value_sha": "bb",
                                   "value": hashlib.sha256(plain.encode()).hexdigest()}],
            "fields": [
                {"field": "f_sha", "evidence": "unpaired",
                 "output_value": hashlib.sha256(plain.encode()).hexdigest()},
                {"field": "f_b64", "evidence": "unpaired",
                 "output_value": base64.b64encode(plain.encode()).decode()},
                {"field": "f_none", "evidence": "unpaired",
                 "output_value": "ZZ-not-derivable-from-any-observed-input-9999"},
            ],
        }
        rep = sp.replay_oracle(art)
        by = {f["field"]: f for f in rep["fields"]}
        # hash field: proven by recomputation AND by the observed .ret edge
        self.assertTrue(by["f_sha"]["resolved"])
        self.assertIsNotNone(by["f_sha"]["observed_output_edge"])
        self.assertTrue(any(d["algo"] == "sha256" for d in by["f_sha"]["derivations"]))
        # plain base64 of the input, no hash: identity/base64
        self.assertTrue(by["f_b64"]["resolved"])
        self.assertTrue(any(d["algo"] == "identity" and d["encoding"].startswith("base64")
                            for d in by["f_b64"]["derivations"]))
        # unrelated field is honestly left unresolved
        self.assertFalse(by["f_none"]["resolved"])
        self.assertIn("f_none", rep["summary"]["unresolved_fields"])

    def test_export_algo_spec_statuses_and_render(self):
        plain = "abcdefghijklmnop-0123456789"
        sha = hashlib.sha256(plain.encode()).hexdigest()
        edge_hex = "deadbeef" * 8                       # a captured output, not re-hashable
        artifact = {
            "anchor": {"carrier": "t"},
            "phases": [{"name": "block_cipher"}],
            "env": [{"api": "Math.random", "count": 2, "first_d_ms": -10}],
            "candidate_inputs": [{"api": "String.scan", "d_ms": -5,
                                  "value_sha": "aa", "value": plain}],
            "candidate_outputs": [{"api": "SubtleCrypto.digest.ret", "d_ms": -4,
                                   "value_sha": "bb", "value": edge_hex}],
            "fields": [
                {"field": "f_hash", "evidence": "unpaired", "output_value": sha},
                {"field": "f_edge", "evidence": "unpaired", "output_value": edge_hex},
                {"field": "f_none", "evidence": "unpaired",
                 "output_value": "QQ-no-derivation-here-4242-abcd"},
            ],
        }
        spec = sp.build_algo_spec(artifact, sp.replay_oracle(artifact))
        by = {f["field"]: f for f in spec["fields"]}
        self.assertEqual(by["f_hash"]["status"], "derived")
        self.assertEqual(by["f_hash"]["algo"], "sha256")
        self.assertIn("sha256(input)", by["f_hash"]["spec"])
        self.assertEqual(by["f_edge"]["status"], "observed_output")  # edge only, no re-hash
        self.assertEqual(by["f_none"]["status"], "unresolved")       # honest gap
        self.assertEqual(spec["primitives"], ["sha256"])
        self.assertEqual(spec["environment_inputs"][0]["api"], "Math.random")
        md = sp.render_algo_spec_md(spec)
        self.assertIn("f_hash = hex(sha256(input))", md)
        self.assertIn("Math.random", md)
        self.assertIn("_unresolved_", md)

    def test_export_cli_writes_spec_files(self):
        write_synth_trace(self.trace, carrier="body")
        out = self.tmp / "out"
        self.assertEqual(sp.main(["explain", "--trace", str(self.trace), "--out", str(out)]), 0)
        self.assertEqual(sp.main(["export", str(out)]), 0)
        self.assertTrue((out / "algo_spec.json").exists())
        self.assertTrue((out / "algo_spec.md").exists())
        spec = json.loads((out / "algo_spec.json").read_text())
        self.assertEqual(spec["summary"]["fields_total"], len(spec["fields"]))
        self.assertIn("carrier", spec["anchor"])
        self.assertIn("# Signing algorithm spec", (out / "algo_spec.md").read_text())

    def test_query_carrier_still_works(self):
        write_synth_trace(self.trace, carrier="query")
        cands = sp.find_carriers(self.trace, 300, 4.0, 10, ["bitwise"])
        self.assertIn("X-Sig", {c["name"] for c in cands})

    def test_compute_family_detection_is_algorithm_agnostic(self):
        # signer core uses SubtleCrypto, not bitwise: crypto family must detect it
        write_synth_trace(self.trace, carrier="body", families="crypto")
        ops, _, _ = sp.collect_window(self.trace, 1_000_000_000.0 - 300000, 1_000_000_000.0)
        self.assertEqual(sp.detect_signer_script(ops, ["crypto"]), SIGNER)
        self.assertEqual(sp.detect_signer_script(ops, ["bitwise"]), "")  # no bitwise ops

    def test_bad_compute_family_rejected(self):
        with self.assertRaises(ValueError):
            sp.parse_families("bitwise,nonsense")

    # ---- Slice 1: structured carriers / timeline / phases / field diff ----

    def test_structured_carrier_split_generic_fields(self):
        st = sp.split_token_fields("aaaa;bb;cccccc", ";")
        self.assertEqual(st["field_count"], 3)
        self.assertEqual([f["name"] for f in st["fields"]], ["f0", "f1", "f2"])
        self.assertEqual([f["len"] for f in st["fields"]], [4, 2, 6])
        self.assertIsNone(sp.split_token_fields("nodelimiter", ";"))

    def test_raw_carrier_captures_non_tokish(self):
        # a ';'-delimited value fails TOKISH but must be captured when hinted
        url = "https://x/y?x-token=17;abc;deadbeef&plain=hello"
        got = dict((n, v) for n, v, _ in sp.request_carriers(url, [], "", 4.0,
                                                             raw_names=["x-token"]))
        self.assertIn("x-token", got)
        self.assertEqual(got["x-token"], "17;abc;deadbeef")
        # without the hint it is dropped (TOKISH fails on ';')
        got2 = {n for n, _, _ in sp.request_carriers(url, [], "", 4.0)}
        self.assertNotIn("x-token", got2)

    def test_hint_weighting_ranks_known_param_first(self):
        write_synth_trace(self.trace, carrier="query")  # carrier param = X-Sig
        ranked = sp.find_carriers(self.trace, 300, 4.0, 10, ["bitwise"],
                                  hint_names=["X-Sig"])
        self.assertEqual(ranked[0]["name"], "X-Sig")
        self.assertTrue(ranked[0]["hinted"])

    def test_build_timeline_dedups_and_tags_output(self):
        base = 1000.0
        ops = []
        # same string scanned twice by charCodeAt -> one row, count 2, role input
        for _ in range(2):
            ops.append({"api": "String.prototype.charCodeAt", "mono_time_us": base,
                        "args": [{"subject": "MESSAGE_TO_HASH_ABC", "callsite_function": "h"}]})
        # a string that is part of a token field -> role output
        ops.append({"api": "String.prototype.concat", "mono_time_us": base,
                    "args": [{"value": "SIGVALUE1234", "callsite_function": "concat"}]})
        rows = sp.build_timeline(ops, base, {"sign": "xxSIGVALUE1234yy"}, {})
        by_sha = {r["value_preview"]: r for r in rows}
        self.assertEqual(by_sha["MESSAGE_TO_HASH_ABC"]["count"], 2)
        self.assertEqual(by_sha["MESSAGE_TO_HASH_ABC"]["role"], "input")
        self.assertEqual(by_sha["SIGVALUE1234"]["role"], "output")
        self.assertEqual(by_sha["SIGVALUE1234"]["appears_in_token_field"], "sign")

    def test_pairing_reports_leaf_level_evidence_without_algorithm_inference(self):
        token = "LEFT_VALUE_123;RIGHT_VALUE_456"
        structures = {"sig": sp.split_token_fields(token, ";")}
        leaves = sp.token_leaf_fields({"sig": token}, structures)
        # The first field is observed exactly; the second occurs only inside a
        # larger captured material.  The envelope is deliberately not another
        # denominator item.
        timeline = [
            {"d_ms": -2.0, "api": "String.scan", "category": "inject",
             "token_field_matches": ["sig.f0"], "token_match_kind": "equal"},
            {"d_ms": -1.0, "api": "JSON.stringify", "category": "inject",
             "token_field_matches": ["sig.f1"], "token_match_kind": "value_substring"},
        ]
        pairing = sp.build_pairing(timeline, leaves, timeline)
        self.assertEqual(pairing["token_fields_total"], 2)
        self.assertEqual(pairing["token_fields_paired"], 2)
        self.assertEqual(pairing["direct_fields"], 1)
        self.assertEqual(pairing["composite_fields"], 1)
        self.assertEqual(pairing["fields"][0]["evidence"], "direct")
        self.assertEqual(pairing["fields"][1]["evidence"], "composite")

    def test_pairing_does_not_count_carrier_envelope_as_field_production(self):
        structures = {"sig": sp.split_token_fields("LEFT_VALUE_123;RIGHT_VALUE_456", ";")}
        leaves = sp.token_leaf_fields({"sig": "LEFT_VALUE_123;RIGHT_VALUE_456"}, structures)
        # This is what the final carrier being visible looks like.  It is useful
        # context, but it must not inflate the evidence rate for its components.
        timeline = [{"d_ms": -1.0, "api": "String.concat", "category": "reverse",
                     "token_field_matches": ["sig.f0", "sig.f1"],
                     "token_match_kind": "field_substring"}]
        pairing = sp.build_pairing(timeline, leaves, [])
        self.assertEqual(pairing["token_fields_paired"], 0)
        self.assertEqual(pairing["context_only_fields"], 2)
        self.assertEqual([x["evidence"] for x in pairing["fields"]],
                         ["context_only", "context_only"])

    def test_classify_phases_by_generic_crypto_fn_names(self):
        base = 1000.0
        ops = [
            {"api": "X", "mono_time_us": base - 400, "args": [{"callsite_function": "fromWordArray"}]},
            {"api": "X", "mono_time_us": base - 200, "args": [{"callsite_function": "_doProcessBlock"}]},
            {"api": "X", "mono_time_us": base - 100, "args": [{"callsite_function": "stringify"}]},
        ]
        phases = sp.classify_phases(ops, base, emit_d_ms=-30.0)
        names = [p["name"] for p in phases]
        self.assertEqual(names, ["wordarray_in", "block_cipher", "encode_out", "emit"])

    def test_token_field_diff_same_and_hamming(self):
        runs = [
            {"_tokens": {"x-token": {"value": "aaaa;bbbb;cccc"}}},
            {"_tokens": {"x-token": {"value": "aaaa;bXbb;dddd"}}},
        ]
        diff = sp.token_field_diff(runs, ";")["x-token"]
        f = {x["i"]: x for x in diff["fields"]}
        self.assertTrue(f[0]["same"])              # aaaa == aaaa
        self.assertFalse(f[1]["same"])
        self.assertEqual(f[1]["hamming"], 1)       # bbbb vs bXbb
        self.assertFalse(f[2]["same"])
        self.assertEqual(f[2]["hamming"], 4)       # cccc vs dddd

    def test_cmd_diff_out_accepts_directory(self):
        # regression: --out DIR used to raise IsADirectoryError
        with TemporaryDirectory() as td:
            td = Path(td)
            for name, tok in (("a", "x;y;z"), ("b", "x;Y;z")):
                d = td / name
                d.mkdir()
                (d / "summary.json").write_text(json.dumps({
                    "anchor": {"carrier": "t"}, "signer_script": "s.js",
                    "window_ops": 1, "dag": {"inputs": 0, "edges": 0, "result_nodes": 0},
                    "tokens": {"t": {"value": tok, "length": len(tok)}},
                    "op_histogram": {}, "hot_callsite_functions": {},
                }))
                (d / "token.json").write_text(json.dumps({
                    "tokens": {"t": {"value": tok}}}))
                (d / "materials_timeline.jsonl").write_text("")
            out_dir = td / "diff_out"
            out_dir.mkdir()
            rc = sp.cmd_diff(argparse.Namespace(
                dirs=[td / "a", td / "b"], out=out_dir, token_field_sep=";"))
            self.assertEqual(rc, 0)
            self.assertTrue((out_dir / "report.json").is_file())

    def test_empty_trace_discovers_nothing(self):
        self.trace.write_text(
            json.dumps({"api": "BrowserNetwork.request", "category": "network",
                        "mono_time_us": 1.0, "args": [{"url": "https://x/y?a=1", "headers": []}]}) + "\n")
        self.assertEqual(sp.find_carriers(self.trace, 300, 4.0, 10, ["bitwise"]), [])


if __name__ == "__main__":
    unittest.main()
