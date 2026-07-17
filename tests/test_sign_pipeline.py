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

    def test_replay_resolves_a_js_implemented_hash_from_native_material_alone(self):
        # A JS-implemented hash (CryptoJS-style) never reaches crypto.subtle: it
        # reads its message char-by-char, so the preimage is exposed by the NATIVE
        # String.prototype.charCodeAt hook, which carries the whole subject on
        # every call. That material must reach the candidate pool -- otherwise the
        # oracle cannot see the one string that proves the field. No inject layer
        # here on purpose: this is the patch-free-hooks-OFF path.
        # synthetic, but shaped like a real salt-sandwich canonical string
        # (salt | k:v params | salt) so the fixture documents that structure.
        salt = "cafebabe" * 4
        plain = f"{salt}appid:demo&client=pc&t=1700000000000{salt}"
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
        # the Utf8.parse burst: one native event per character, each repeating the
        # full subject -- the timeline must collapse these into a single candidate.
        for pos in range(len(plain)):
            lines.append({"api": "String.prototype.charCodeAt", "category": "reverse",
                          "mono_time_us": T - 55000 + pos, "global_seq": 200 + pos,
                          "args": [{"callsite_script": SIGNER, "callsite_function": "parse",
                                    "callsite_column": 90, "subject": plain,
                                    "subject_length": len(plain), "position": float(pos),
                                    "result": float(ord(plain[pos])),
                                    "result_ref": f"number:{ord(plain[pos])}.000000"}]})
        body = json.dumps({"header": {"aid": 123}, "sign": digest}).encode().hex()
        lines.append({"api": "BrowserNetwork.request", "category": "network", "mono_time_us": T,
                      "global_seq": 999, "args": [{"method": "POST", "headers": [],
                      "has_request_body": True, "url": "https://api.example.com/submit?ts=1",
                      "upload_body": {"body_hex": body}}]})
        self.trace.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
        out = self.tmp / "out"
        self.assertEqual(sp.main(["explain", "--trace", str(self.trace), "--out", str(out),
                                  "--carrier", "body.sign"]), 0)
        # the per-char repeats collapse to ONE candidate carrying the full preimage
        ci = json.loads((out / "sign_artifact.json").read_text())["candidate_inputs"]
        native = [c for c in ci if c.get("api") == "String.prototype.charCodeAt"]
        self.assertEqual([c["value"] for c in native], [plain])
        # and the oracle proves the field off that native material alone
        self.assertEqual(sp.main(["replay", str(out)]), 0)
        rep = json.loads((out / "replay.json").read_text())
        self.assertEqual(rep["summary"]["resolution_rate"], 1.0)
        d0 = rep["fields"][0]["derivations"][0]
        self.assertEqual((d0["algo"], d0["encoding"], d0["match_kind"]),
                         ("sha256", "hex_lower", "exact"))
        self.assertEqual(d0["input_api"], "String.prototype.charCodeAt")

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

    def test_replay_oracle_hmac_and_multistep(self):
        import hmac as _hmac
        key = "device-secret-key-abcdef012345"
        msg = "user=42&ts=1783000000&nonce=abcd"
        plain = "payload-abcdefghijklmnop-0123456789"
        salt = "app-pepper-ZZZ-99887766"
        hmac_out = _hmac.new(key.encode(), msg.encode(), "sha256").hexdigest()
        hoh_out = hashlib.sha256(hashlib.sha1(plain.encode()).digest()).hexdigest()
        ethen_out = hashlib.sha256(base64.b64encode(plain.encode())).hexdigest()
        concat_out = hashlib.sha256((plain + salt).encode()).hexdigest()
        art = {
            "anchor": {"carrier": "t"},
            "candidate_inputs": [
                {"api": "String.scan", "d_ms": -9, "value_sha": "k", "value": key},
                {"api": "String.scan", "d_ms": -8, "value_sha": "m", "value": msg},
                {"api": "String.scan", "d_ms": -7, "value_sha": "p", "value": plain},
                {"api": "String.scan", "d_ms": -6, "value_sha": "s", "value": salt},
            ],
            "candidate_outputs": [],
            "fields": [
                {"field": "f_hmac", "evidence": "unpaired", "output_value": hmac_out},
                {"field": "f_hoh", "evidence": "unpaired", "output_value": hoh_out},
                {"field": "f_ethen", "evidence": "unpaired", "output_value": ethen_out},
                {"field": "f_concat", "evidence": "unpaired", "output_value": concat_out},
            ],
        }
        rep = sp.replay_oracle(art)
        by = {f["field"]: f for f in rep["fields"]}
        # every field a keyless single hash CANNOT reproduce is now resolved
        for k in ("f_hmac", "f_hoh", "f_ethen", "f_concat"):
            self.assertTrue(by[k]["resolved"], f"{k} should resolve")
        self.assertEqual(rep["summary"]["resolution_rate"], 1.0)
        self.assertEqual(rep["summary"]["newly_resolved_vs_pairing"], 4)

        def has(field, structure):
            return any(d["structure"] == structure for d in by[field]["derivations"])
        self.assertTrue(has("f_hmac", "HMAC(key, msg)"))
        self.assertTrue(has("f_hoh", "H2(H1(input))"))
        self.assertTrue(has("f_ethen", "H(enc(input))"))
        self.assertTrue(has("f_concat", "H(a||b)"))

        # the HMAC derivation names its key + msg operands and reads structurally
        hd = next(d for d in by["f_hmac"]["derivations"] if d["structure"] == "HMAC(key, msg)")
        self.assertIn("HMAC_sha256(key, msg)", hd["spec"])
        self.assertEqual(hd["key_value_sha"], "k")
        self.assertEqual(hd["input_value_sha"], "m")
        self.assertIn("hmac", rep["algorithms_tried"])

    def test_replay_oracle_mines_hmac_operands_from_a_json_envelope(self):
        # gap 2: a signer wraps key + message inside ONE JSON.stringify value
        # (a {key, signStr, ...} envelope); the HMAC operands must be mined out of it.
        import hmac as _hmac
        key = "device-secret-key-abcdef012345"
        msg = "appid=www&functionId=f&body={x}&t=1783000000"
        mac = _hmac.new(key.encode(), msg.encode(), "sha256").hexdigest()
        envelope = json.dumps({"key": key, "signStr": mac, "msg": msg, "_ste": 3})
        art = {
            "anchor": {"carrier": "sig"},
            "candidate_inputs": [
                {"api": "JSON.stringify", "d_ms": -30, "value_sha": "env", "value": envelope},
            ],
            "candidate_outputs": [],
            "fields": [{"field": "sig.f8", "evidence": "context_only", "output_value": mac}],
        }
        rep = sp.replay_oracle(art)
        # 3 string leaves (key, signStr, msg) mined out of the single envelope
        self.assertGreaterEqual(rep["json_leaf_operands_mined"], 3)
        f = rep["fields"][0]
        self.assertTrue(f["resolved"])
        hd = next(d for d in f["derivations"] if d["structure"] == "HMAC(key, msg)")
        self.assertIn("HMAC_sha256(key, msg)", hd["spec"])
        # operands carry the json_path they were mined from (provenance)
        self.assertEqual(hd["key_json_path"], "key")
        self.assertEqual(hd["input_json_path"], "msg")
        self.assertEqual(hd["key_json_leaf_of"], "env")

    @unittest.skipUnless("sm3" in sp.REPLAY_HASHES, "platform hashlib lacks SM3")
    def test_replay_oracle_resolves_sm3_and_hmac_sm3(self):
        # SM3 (国密) is a real-world signer digest; both plain SM3 and HMAC-SM3 must
        # resolve, the latter over operands mined from a nested JSON envelope.
        import hmac as _hmac
        key = "b129d28b20d8f75779ac168551a15eba63fec9ce12b90cd0acc12025b3a19370"
        msg = "appid=www-jd-com&functionId=jsfbox_pre_gb&t=1784214612610"
        f_sm3 = hashlib.new("sm3", msg.encode()).hexdigest()
        f_hmac = _hmac.new(key.encode(), msg.encode(), "sm3").hexdigest()
        envelope = json.dumps({"key": key, "signStr": f_hmac, "msg": msg})
        art = {
            "anchor": {"carrier": "sig"},
            "candidate_inputs": [
                {"api": "JSON.stringify", "d_ms": -30, "value_sha": "env", "value": envelope},
            ],
            "candidate_outputs": [],
            "fields": [
                {"field": "sig.f4", "evidence": "context_only", "output_value": f_sm3},
                {"field": "sig.f8", "evidence": "context_only", "output_value": f_hmac},
            ],
        }
        rep = sp.replay_oracle(art)
        self.assertEqual(rep["summary"]["resolution_rate"], 1.0)
        by = {f["field"]: f for f in rep["fields"]}
        self.assertIn("sm3(input)", by["sig.f4"]["derivations"][0]["spec"])
        self.assertTrue(any("HMAC_sm3(key, msg)" in d["spec"]
                            for d in by["sig.f8"]["derivations"]))

    def test_sm4_matches_official_test_vector(self):
        # GB/T 32907 worked example: single-block ECB
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        pt = bytes.fromhex("0123456789abcdeffedcba9876543210")
        self.assertEqual(sp._sm4_encrypt(key, pt).hex(),
                         "681edf34d206965e86b3e94f536e4246")

    def test_replay_oracle_resolves_sm4_cipher_field_from_json_envelope(self):
        # gap "所有国密": a 国密 SM4-encrypted carrier field, key + plaintext nested
        # in one JSON.stringify, must be VERIFIED (re-encrypt observed -> match).
        key = "0123456789abcdef"                      # 16-byte ASCII SM4 key
        plaintext = '{"source":"pc_home","adId":"04079308"}'
        pad = 16 - (len(plaintext) % 16)
        ct = sp._sm4_encrypt(key.encode(), plaintext.encode() + bytes([pad]) * pad)
        field = base64.b64encode(ct).decode()
        envelope = json.dumps({"key": key, "payload": plaintext})
        art = {
            "anchor": {"carrier": "sig"},
            "candidate_inputs": [
                {"api": "JSON.stringify", "d_ms": -30, "value_sha": "env", "value": envelope},
            ],
            "candidate_outputs": [],
            "fields": [{"field": "sig.f7", "evidence": "context_only", "output_value": field}],
        }
        rep = sp.replay_oracle(art)
        self.assertIn("sm4", rep["algorithms_tried"])
        f = rep["fields"][0]
        self.assertTrue(f["resolved"])
        d = next(d for d in f["derivations"] if d["structure"] == "SM4(key, msg)")
        self.assertIn("SM4-ECB(key, msg)", d["spec"])
        self.assertEqual(d["key_json_path"], "key")
        self.assertEqual(d["input_json_path"], "payload")

    def test_sm4_cbc_zero_iv_roundtrip_resolves(self):
        key = "fedcba9876543210"
        msg = "0123456789abcdef" * 2               # 32 bytes, block-aligned (nopad path)
        ct = sp._sm4_encrypt(key.encode(), msg.encode(), iv=b"\x00" * 16)
        art = {
            "anchor": {"carrier": "t"},
            "candidate_inputs": [
                {"api": "s", "d_ms": -3, "value_sha": "k", "value": key},
                {"api": "s", "d_ms": -2, "value_sha": "m", "value": msg},
            ],
            "candidate_outputs": [],
            "fields": [{"field": "c", "evidence": "unpaired", "output_value": ct.hex()}],
        }
        rep = sp.replay_oracle(art)
        f = rep["fields"][0]
        self.assertTrue(f["resolved"])
        self.assertTrue(any("SM4-CBC(key, msg)" in d["spec"] for d in f["derivations"]))

    def test_aes_matches_fips197_vectors(self):
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        for key_hex, ct_hex in (
            ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
            ("000102030405060708090a0b0c0d0e0f1011121314151617",
             "dda97ca4864cdfe06eaf70a0ec0d7191"),
            ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
             "8ea2b7ca516745bfeafc49904b496089"),
        ):
            self.assertEqual(sp._aes_encrypt(bytes.fromhex(key_hex), pt).hex(), ct_hex)

    def test_replay_oracle_resolves_aes_cbc_field_from_json_envelope(self):
        key = "0123456789abcdef0123456789abcdef"      # 32-hex -> AES-128
        plaintext = '{"functionId":"jsfbox_pre_gb","body":{"source":"pc_home"}}'
        pad = 16 - (len(plaintext) % 16)
        ct = sp._aes_encrypt(bytes.fromhex(key),
                             plaintext.encode() + bytes([pad]) * pad, iv=b"\x00" * 16)
        field = base64.b64encode(ct).decode()
        envelope = json.dumps({"key": key, "payload": plaintext})
        art = {
            "anchor": {"carrier": "sig"},
            "candidate_inputs": [
                {"api": "JSON.stringify", "d_ms": -30, "value_sha": "env", "value": envelope},
            ],
            "candidate_outputs": [],
            "fields": [{"field": "sig.f7", "evidence": "context_only", "output_value": field}],
        }
        rep = sp.replay_oracle(art)
        self.assertIn("aes", rep["algorithms_tried"])
        f = rep["fields"][0]
        self.assertTrue(f["resolved"])
        d = next(d for d in f["derivations"] if d["structure"] == "AES(key, msg)")
        self.assertIn("AES-CBC(key, msg)", d["spec"])
        self.assertEqual(d["input_json_path"], "payload")

    def test_explain_auto_anchor_selects_window_with_material(self):
        # gap 4: --anchor-select material picks the request whose pre-window holds
        # injected plaintext, not just the first carrier request.
        T = 1_000_000_000.0
        gap = 1_000_000.0                      # 1s between the two signed requests

        def op(mono, gs):
            return {"api": "Bitwise.xor", "category": "reverse", "mono_time_us": mono,
                    "global_seq": gs, "args": [{"callsite_script": SIGNER,
                    "callsite_function": "h", "left": 1.0, "right": 2.0, "result": 3.0,
                    "left_ref": "number:1.0", "right_ref": "number:2.0",
                    "result_ref": f"number:{gs}"}]}

        def req(mono, gs, tok):
            return {"api": "BrowserNetwork.request", "category": "network",
                    "mono_time_us": mono, "global_seq": gs, "args": [{"method": "GET",
                    "headers": [], "url": f"https://api.example.com/s?ts=1&X-Sig={tok}"}]}

        lines = [
            op(T - 40000, 1), req(T, 2, TOKEN),                       # index 0: no material
            op(T + gap - 40000, 3),                                   # index 1: has material
            {"api": "String.scan", "category": "inject", "mono_time_us": T + gap - 50000,
             "global_seq": 4, "callsite_script": SIGNER, "callsite_function": "s",
             "args": [{"type": "string", "len": 40,
                       "value": "MATERIAL-PLAINTEXT-abcdefghijklmnopqrst"}]},
            req(T + gap, 5, TOKEN + "ZZ"),
        ]
        self.trace.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
        out = self.tmp / "out"
        rc = sp.main(["explain", "--trace", str(self.trace), "--out", str(out),
                      "--carrier", "X-Sig", "--window-ms", "300", "--anchor-select", "material"])
        self.assertEqual(rc, 0)
        summary = json.loads((out / "summary.json").read_text())
        self.assertEqual(summary["anchor"]["index"], 1)          # picked the material window
        # and the material landed in the candidate pool
        art = json.loads((out / "sign_artifact.json").read_text())
        self.assertTrue(any("MATERIAL-PLAINTEXT" in (c.get("value") or "")
                            for c in art["candidate_inputs"]))

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
