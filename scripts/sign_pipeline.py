#!/usr/bin/env python3
"""sign_pipeline - auditable data-flow view of a request-signing pipeline in an XTrace trace.

General across JS-computed request signing, regardless of algorithm family
(hand-rolled bitwise, native crypto, encoder-based) or carrier location
(query, header, POST body, WebSocket frame).

Subcommands:
  discover   Find token carriers WITHOUT knowing their names, by entropy +
             per-request variance + a preceding compute burst. Scans query,
             headers, POST body, and WebSocket.send payloads.
  explain    Anchor on a carrier-bearing request, take the pre-request window,
             auto-detect the signer script (script with the densest compute
             ops), and emit inputs -> operators -> output
             (summary/token/inputs/materials/ops/dag). No hard-coded token name.
  diff       Compare several explain outputs: what stays constant across
             captures (the algorithm) vs what varies (inputs / nonces).

This is a data-flow *report*, not a token generator.

Examples:
  scripts/sign_pipeline.py discover --trace logs/run/trace.ndjson
  scripts/sign_pipeline.py explain  --trace logs/run/trace.ndjson --out analysis/w0
  scripts/sign_pipeline.py explain  --trace T --out D --carrier X-Sign --script auto
  scripts/sign_pipeline.py diff analysis/w0 analysis/w1 analysis/w2
"""
from __future__ import annotations

import argparse
import base64
import bisect
import collections
import csv
import hashlib
import hmac
import json
import math
import re
import sys
import zlib
from pathlib import Path
from urllib.parse import parse_qs, urlparse

MONO_RE = re.compile(rb'"mono_time_us"\s*:\s*([0-9.eE+]+)')
TOKISH = re.compile(r"^[A-Za-z0-9_\-+/=.]{16,}$")
TOKISH_SUB = re.compile(r"[A-Za-z0-9_\-+/=.]{16,}")
_RESULT_KEYS = {"result_ref", "result_register_ref"}
_VALUE_BASES = (
    "left", "right", "result", "first_arg", "second_arg", "value",
    "subject", "input", "key", "target", "this_arg", "separator", "search",
)

# Compute-op taxonomy: which api families count as "signing computation". Each
# entry is (api-prefixes for classification, byte markers for cheap line prefilter).
COMPUTE_FAMILIES = {
    "bitwise":  (("Bitwise.", "Shift."), (b'"Bitwise.', b'"Shift.')),
    "crypto":   (("SubtleCrypto.",), (b'"SubtleCrypto.',)),
    "encoder":  (("TextEncoder.", "TextDecoder."), (b'"TextEncoder.', b'"TextDecoder.')),
    "buffer":   (("DataView.", "TypedArray."), (b'"DataView.', b'"TypedArray.')),
    "charcode": (("String.fromCharCode", "String.prototype.charCodeAt"),
                 (b'"String.fromCharCode', b'"String.prototype.charCodeAt')),
    "wasm":     (("WebAssembly.",), (b'"WebAssembly.',)),
}
DEFAULT_FAMILIES = "bitwise,crypto,encoder,buffer"
# Generic signature-param name conventions (site-neutral). Site-specific names
# (e.g. a particular product's token key) are passed via --carrier-hint.
DEFAULT_CARRIER_HINTS = ("sign", "signature", "sig", "token")
# Generic crypto-library callsite-function name patterns for phase clustering.
# These are library conventions (CryptoJS/WebCrypto), not site-specific.
PHASE_PATTERNS = [
    ("wordarray_in", re.compile(r"WordArray|fromWordArray|parseHex|parseUtf8|\bparse\b", re.I)),
    ("block_cipher", re.compile(r"ProcessBlock|encryptBlock|decryptBlock|eKey|doFinal|doReset", re.I)),
    ("hash", re.compile(r"digest|finalize|\bsha\b|\bmd5\b|hmac|\bupdate\b", re.I)),
    ("encode_out", re.compile(r"stringify|format|base64|toString|\bencode\b", re.I)),
]
_ROLE_INPUT_APIS = ("TextEncoder.encode", "String.prototype.charCodeAt",
                    "String.scan", "SubtleCrypto.digest", "SubtleCrypto.sign",
                    "SubtleCrypto.encrypt")
# APIs whose captured plaintext IS a digest/AES/sign input (the "what got hashed"
# material). Populated by --inject-api-hooks (String.scan / crypto.subtle / JSON).
CRYPTO_INPUT_APIS = ("String.scan", "TextEncoder.encode", "SubtleCrypto.digest",
                     "SubtleCrypto.sign", "SubtleCrypto.encrypt",
                     "SubtleCrypto.verify", "JSON.stringify")


# ----------------------------- shared helpers -----------------------------

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    c = collections.Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def compute_prefixes(families):
    out = []
    for fam in families:
        out.extend(COMPUTE_FAMILIES[fam][0])
    return tuple(out)


def compute_markers(families):
    out = []
    for fam in families:
        out.extend(COMPUTE_FAMILIES[fam][1])
    return out


def is_compute(api, prefixes):
    return bool(api) and api.startswith(prefixes)


def ref_literal(ref):
    """Refs are self-describing (e.g. 'number:22.0', 'handler_arg:124/number:22.0')."""
    if not isinstance(ref, str):
        return None
    tail = ref.rsplit("/", 1)[-1]
    _, _, val = tail.partition(":")
    val = val or tail
    try:
        f = float(val)
        return int(f) if f.is_integer() else f
    except ValueError:
        return val or None


def decode_body(upload_body):
    """XTrace captures request bodies as {'body_hex': ...} (or 'body_text')."""
    if not isinstance(upload_body, dict):
        return ""
    if upload_body.get("body_text"):
        return upload_body["body_text"]
    hx = upload_body.get("body_hex")
    if hx:
        try:
            return bytes.fromhex(hx).decode("utf-8", "ignore")
        except ValueError:
            return ""
    return ""


def flatten_json(obj, prefix=""):
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += flatten_json(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += flatten_json(v, f"{prefix}[{i}]")
    else:
        out.append((prefix, obj))
    return out


def request_carriers(url, headers, body_text, min_entropy, raw_names=()):
    """Token-like (name, value, where) across query, headers, body.

    Params whose name is in raw_names are captured in full even if they aren't
    a single high-entropy token (structured carriers like a ';'-delimited value)."""
    raw = {n.lower() for n in raw_names}
    out = []

    def consider(name, val, where):
        if not val:
            return
        if (name or "").lower() in raw:
            out.append((name, val, where))
        elif TOKISH.match(val) and shannon_entropy(val) >= min_entropy:
            out.append((name, val, where))

    for k, v in parse_qs(urlparse(url or "").query).items():
        consider(k, v[0] if v else "", "query")
    for h in headers or []:
        consider(h.get("name"), h.get("value", ""), "header")
    if body_text:
        try:
            j = json.loads(body_text)
            for k, v in flatten_json(j):
                if isinstance(v, str):
                    consider(f"body.{k}", v, "body")
        except (json.JSONDecodeError, TypeError):
            for tok in set(TOKISH_SUB.findall(body_text)):
                consider(f"body:{tok[:8]}", tok, "body")
    return out


def iter_requests(trace: Path):
    """Yield (mono, url, headers, body_text, event) for HTTP requests and WS sends."""
    with trace.open("rb") as fh:
        for line in fh:
            is_req = b"BrowserNetwork.request" in line
            is_ws = b'"WebSocket.send"' in line
            if not (is_req or is_ws):
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            a = (e.get("args") or [{}])[0]
            if not isinstance(a, dict):
                continue
            if e.get("api") == "WebSocket.send":
                # treat the frame payload like a body; url = socket url if present
                payload = a.get("data") or a.get("message") or a.get("payload") or ""
                body = payload if isinstance(payload, str) else decode_body(payload)
                yield e.get("mono_time_us"), a.get("url", ""), [], body, e
            else:
                yield (e.get("mono_time_us"), a.get("url", ""), a.get("headers", []),
                       decode_body(a.get("upload_body")), e)


def collect_compute_monos(trace: Path, families):
    """Sorted mono times of every compute-family op (for burst detection)."""
    markers = compute_markers(families)
    monos = []
    with trace.open("rb") as fh:
        for line in fh:
            if not any(mk in line for mk in markers):
                continue
            m = MONO_RE.search(line)
            if m:
                try:
                    monos.append(float(m.group(1)))
                except ValueError:
                    pass
    monos.sort()
    return monos


def collect_window(trace: Path, lo: float, hi: float):
    """Full-parse only lines whose mono is in [lo, hi]. Returns (reverse_ops, net, str_hits)."""
    ops, net, str_hits = [], [], []
    with trace.open("rb") as fh:
        for line in fh:
            m = MONO_RE.search(line)
            if not m:
                continue
            try:
                mono = float(m.group(1))
            except ValueError:
                continue
            if not (lo <= mono <= hi):
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("category") == "network":
                net.append(e)
                continue
            args = e.get("args")
            if not (isinstance(args, list) and args and isinstance(args[0], dict)):
                continue
            for v in args[0].values():
                if isinstance(v, str) and len(v) >= 8:
                    str_hits.append((mono, v))
            ops.append(e)
    ops.sort(key=lambda e: (e.get("mono_time_us", 0.0), e.get("global_seq", 0)))
    return ops, net, str_hits


def detect_signer_script(ops, families):
    """The callsite_script carrying the most compute-family ops = the signer core."""
    prefixes = compute_prefixes(families)
    c = collections.Counter()
    for e in ops:
        if is_compute(e.get("api"), prefixes):
            c[e["args"][0].get("callsite_script") or ""] += 1
    return c.most_common(1)[0][0] if c else ""


def build_dag(ops):
    producers, ref_value = {}, {}
    for i, e in enumerate(ops):
        a = e["args"][0]
        rr = a.get("result_ref")
        if rr is not None:
            producers.setdefault(rr, i)
        for base in _VALUE_BASES:
            rk = f"{base}_ref"
            if rk in a and base in a:
                ref_value.setdefault(a[rk], a[base])
    edges, consumed = [], set()
    for i, e in enumerate(ops):
        a = e["args"][0]
        rr = a.get("result_ref")
        for k, v in a.items():
            if not k.endswith("_ref") or k in _RESULT_KEYS or v is None or v == rr:
                continue
            consumed.add(v)
            if rr is not None:
                edges.append({"from": v, "to": rr, "role": k[:-4], "op": i})
    inputs = sorted(consumed - set(producers))
    return producers, edges, inputs, ref_value


def token_provenance(str_hits, tokens, anchor_mono):
    prov = {}
    for name, val in tokens.items():
        earliest = None
        if val:
            for mono, s in str_hits:
                if val in s:
                    d = (mono - anchor_mono) / 1000.0
                    earliest = d if earliest is None else min(earliest, d)
        prov[name] = None if earliest is None else round(earliest, 3)
    return prov


def op_row(e, anchor_mono):
    a = e["args"][0]
    return {
        "seq": e.get("global_seq"),
        "d_ms": round((e.get("mono_time_us", anchor_mono) - anchor_mono) / 1000.0, 3),
        "api": e.get("api"),
        "callsite_function": a.get("callsite_function"),
        "callsite_column": a.get("callsite_column"),
        "callsite_source_position": a.get("callsite_source_position"),
        "left": a.get("left"), "right": a.get("right"), "result": a.get("result"),
        "left_ref": a.get("left_ref"), "right_ref": a.get("right_ref"),
        "result_ref": a.get("result_ref"),
        "left_source_ref": a.get("left_source_ref"),
        "right_source_ref": a.get("right_source_ref"),
    }


def write_ops(rows, out_dir):
    cols = list(rows[0].keys()) if rows else []
    with (out_dir / "ops.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    with (out_dir / "ops.jsonl").open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
        pq.write_table(pa.Table.from_pylist(rows), out_dir / "ops.parquet")
        return "ops.parquet + ops.csv + ops.jsonl"
    except Exception:
        return "ops.csv + ops.jsonl (install pyarrow for ops.parquet)"


def histogram(items, top=None):
    ordered = sorted(collections.Counter(items).items(), key=lambda kv: -kv[1])
    return dict(ordered[:top] if top else ordered)


def parse_families(spec):
    fams = [f.strip() for f in spec.split(",") if f.strip()]
    bad = [f for f in fams if f not in COMPUTE_FAMILIES]
    if bad:
        raise ValueError(f"unknown compute families {bad}; choose from {list(COMPUTE_FAMILIES)}")
    return fams


def sha8(s):
    return hashlib.sha256(s.encode("utf-8", "ignore")).hexdigest()[:8]


def split_token_fields(value, sep):
    """Structured carrier: split a multi-field token (e.g. ';'-delimited) into
    generic, site-neutral fields f0..fN. Semantic naming belongs in local/."""
    if not sep or sep not in value:
        return None
    parts = value.split(sep)
    return {
        "sep": sep, "field_count": len(parts),
        "fields": [{"i": i, "name": f"f{i}", "len": len(p), "value": p}
                   for i, p in enumerate(parts)],
    }


def classify_phases(ops, anchor_mono, emit_d_ms):
    """Cluster window ops into phases by generic crypto fn-name patterns."""
    buckets = {name: {"t0": None, "t1": None, "fns": set(), "ops": 0}
               for name, _ in PHASE_PATTERNS}
    for e in ops:
        fn = e["args"][0].get("callsite_function") or ""
        d = (e.get("mono_time_us", anchor_mono) - anchor_mono) / 1000.0
        for name, rx in PHASE_PATTERNS:
            if rx.search(fn):
                b = buckets[name]
                b["t0"] = d if b["t0"] is None else min(b["t0"], d)
                b["t1"] = d if b["t1"] is None else max(b["t1"], d)
                b["fns"].add(fn)
                b["ops"] += 1
                break
    phases = [{"name": name, "t": [round(b["t0"], 3), round(b["t1"], 3)],
               "fns": sorted(b["fns"])[:8], "ops": b["ops"]}
              for name, b in ((n, buckets[n]) for n, _ in PHASE_PATTERNS) if b["ops"]]
    phases.sort(key=lambda p: p["t"][0])
    if emit_d_ms is not None:
        phases.append({"name": "emit", "t": [round(emit_d_ms, 3), 0.0],
                       "evidence": "first full token string visible"})
    return phases


def build_timeline(all_ops, anchor_mono, token_fields, param_values, min_len=12, cap=80):
    """Per-string timeline: which plaintext strings pass through the signer and
    whether they land in a token field or equal a request param. Distinct strings
    are deduped by (value, api) with an occurrence count, so a long string scanned
    char-by-char (charCodeAt) is one row, not thousands.

    token_fields: {label: value}; param_values: {param: value}."""
    # Prefer the narrowest matching field.  For a structured carrier this keeps
    # evidence attached to ``carrier.fN`` instead of swallowing every component
    # into the full carrier envelope.
    field_items = sorted(((lbl, v) for lbl, v in token_fields.items() if v),
                         key=lambda item: (len(item[1]), item[0]))
    param_items = [(k, v) for k, v in param_values.items() if isinstance(v, str) and v]
    seen = {}
    for e in all_ops:
        a = e["args"][0]
        api = e.get("api", "")
        d = round((e.get("mono_time_us", anchor_mono) - anchor_mono) / 1000.0, 3)
        for k, v in a.items():
            if not isinstance(v, str) or len(v) < min_len:
                continue
            sha = sha8(v)
            key = (sha, api)
            if key in seen:
                row = seen[key]
                row["count"] += 1
                row["d_ms"] = min(row["d_ms"], d)
                continue
            equal = [lbl for lbl, fv in field_items if v == fv]
            part_of = [lbl for lbl, fv in field_items if v != fv and v in fv]
            contains = [lbl for lbl, fv in field_items if v != fv and fv in v]
            matches = equal or part_of or contains
            match_kind = ("equal" if equal else "value_substring" if part_of
                          else "field_substring" if contains else None)
            equals_param = next((p for p, pv in param_items if v == pv), None)
            if matches:
                role = "output"
            elif api.startswith(_ROLE_INPUT_APIS) or k in ("subject", "input", "data", "text"):
                role = "input"
            else:
                role = "intermediate"
            seen[key] = {
                "d_ms": d, "api": api, "category": e.get("category"),
                "fn": a.get("callsite_function"),
                "script": (a.get("callsite_script") or "").rsplit("/", 1)[-1],
                "role": role, "value_len": len(v), "value_preview": v[:cap],
                "value_sha": sha, "count": 1,
                # Keep the original scalar field for downstream compatibility;
                # the complete list and match kind make the association auditable.
                "appears_in_token_field": matches[0] if matches else None,
                "token_field_matches": matches,
                "token_match_kind": match_kind,
                "equals_query_param": equals_param,
            }
    return sorted(seen.values(), key=lambda r: r["d_ms"])


def token_leaf_fields(tokens, structures):
    """Return the smallest independently reportable carrier fields.

    A delimiter-structured carrier is an envelope plus its fields.  Counting
    both makes a pairing percentage ambiguous and double-counts the same
    evidence, so pairing measures the leaves while the timeline still retains
    the envelope for output visibility.
    """
    leaves = {}
    for token, value in tokens.items():
        structure = structures.get(token)
        if structure:
            for field in structure["fields"]:
                leaves[f"{token}.{field['name']}"] = field["value"]
        else:
            leaves[token] = value
    return leaves


def build_pairing(timeline, field_values, crypto_inputs):
    """Summarize field-to-material evidence without inferring an algorithm.

    ``equal`` is a direct observed materialization and ``value_substring`` is
    a captured component of a field.  ``field_substring`` is context only: the
    field appeared inside a larger material (often the carrier envelope itself)
    and cannot by itself establish how that field was produced.  This
    deliberately does not claim that a hash/cipher input can recreate a field:
    it only records the evidence that was observed.
    """
    fields = []
    direct = composite = context_only = 0
    for label, value in field_values.items():
        matches = [row for row in timeline if label in row.get("token_field_matches", [])]
        kinds = sorted({row.get("token_match_kind") for row in matches if row.get("token_match_kind")})
        if "equal" in kinds:
            evidence = "direct"
            direct += 1
        elif "value_substring" in kinds:
            evidence = "composite"
            composite += 1
        elif kinds:
            evidence = "context_only"
            context_only += 1
        else:
            evidence = "unpaired"
        fields.append({
            "field": label,
            "length": len(value),
            "evidence": evidence,
            "match_kinds": kinds,
            "material_events": len(matches),
            "first_d_ms": min((row["d_ms"] for row in matches), default=None),
            "apis": sorted({row.get("api") for row in matches if row.get("api")})[:8],
            "categories": sorted({row.get("category") for row in matches if row.get("category")}),
        })
    total = len(fields)
    paired = direct + composite
    return {
        "measurement": "structured carrier leaves when present; otherwise carrier value",
        "token_fields_total": total,
        "token_fields_paired": paired,
        "token_field_pairing_rate": round(paired / total, 3) if total else 0.0,
        "direct_fields": direct,
        "composite_fields": composite,
        "context_only_fields": context_only,
        "unpaired_fields": [field["field"] for field in fields
                            if field["evidence"] in ("context_only", "unpaired")][:24],
        "fields": fields,
        "crypto_inputs_total": len(crypto_inputs),
        "crypto_inputs_mapped_to_token": sum(
            1 for row in crypto_inputs if row.get("token_field_matches")),
    }


def _artifact_row(r):
    """Project a timeline row to the compact evidence shape used in the artifact."""
    return {k: r.get(k) for k in (
        "d_ms", "api", "category", "role", "fn", "script",
        "value_len", "value_preview", "value_sha", "count",
        "token_match_kind", "equals_query_param")}


def _field_subdag(value, edges, ref_value):
    """Backward-reachable value-ref sub-DAG that produced a field value.

    Anchor on every ref whose observed value equals the field, then walk edges
    (to <- from) backward. Best-effort: returns None when the field value is not
    a produced ref in-window (e.g. a crypto.subtle digest with no source-ref
    lineage) -- that gap is exactly what a replay/oracle pass then has to close."""
    anchors = [r for r, v in ref_value.items() if v == value]
    if not anchors:
        return None
    by_to = collections.defaultdict(list)
    for e in edges:
        by_to[e["to"]].append(e)
    nodes, kept, stack = set(anchors), {}, list(anchors)
    while stack:
        node = stack.pop()
        for e in by_to.get(node, []):
            kept[(e["from"], e["to"], e.get("role"), e.get("op"))] = e
            if e["from"] not in nodes:
                nodes.add(e["from"])
                stack.append(e["from"])
    return {"anchor_refs": sorted(anchors), "nodes": sorted(nodes),
            "edges": list(kept.values())}


def env_reads_in_window(all_ops, anchor_mono):
    """Environment dependencies read in the window (fingerprint-category events):
    nav / screen / time / random -- the non-material inputs a replay must pin."""
    env = {}
    for e in all_ops:
        if e.get("category") != "fingerprint":
            continue
        api = e.get("api") or ""
        d = round((e.get("mono_time_us", anchor_mono) - anchor_mono) / 1000.0, 3)
        slot = env.get(api)
        if slot is None:
            env[api] = {"api": api, "count": 1, "first_d_ms": d}
        else:
            slot["count"] += 1
            slot["first_d_ms"] = min(slot["first_d_ms"], d)
    return sorted(env.values(), key=lambda x: (x["first_d_ms"], x["api"]))


REPLAY_VALUE_CAP = 8192   # bound the full value stored per candidate for replay


def _candidate_row(r, full_by_sha):
    """A candidate-pool row: the compact evidence PLUS the full captured value
    (joined by value_sha) so the artifact is self-contained for a replay pass.
    Timeline previews are clipped to 80 chars, too short to re-hash."""
    row = _artifact_row(r)
    full = (full_by_sha or {}).get(r.get("value_sha"))
    row["value"] = full[:REPLAY_VALUE_CAP] if isinstance(full, str) else r.get("value_preview")
    return row


def build_sign_artifact(pairing, leaf_fields, timeline, crypto_inputs,
                        crypto_outputs, phases, env_reads, edges, ref_value,
                        carrier, anchor_url, anchor_mono, full_by_sha=None):
    """Assemble the per-field sign artifact (the keystone of the analysis pipeline).

    One self-contained object per carrier leaf field: the observed output value,
    the pairing verdict, the captured materials/outputs that string-match it, and
    the value-ref sub-DAG that produced it -- plus shared phases, env reads, and
    the window's plaintext/output pools (the preimage candidates a replay/oracle
    pass tests against). This is an assembly of OBSERVED capture, not a
    recomputation: an unpaired field (a hash/signature) carries empty ``materials``
    on purpose -- its producing plaintext was not observed to equal it, so the
    shared candidate pools + phases are what a downstream replay must resolve."""
    by_field = {f["field"]: f for f in pairing["fields"]}
    fields = []
    for label, value in leaf_fields.items():
        pf = by_field.get(label, {})
        matched = [r for r in timeline if label in r.get("token_field_matches", [])]
        fields.append({
            "field": label,
            "output_value": value,
            "length": len(value),
            "evidence": pf.get("evidence", "unpaired"),
            "match_kinds": pf.get("match_kinds", []),
            "first_material_d_ms": pf.get("first_d_ms"),
            "materials": [_artifact_row(r) for r in matched
                          if not (r.get("api") or "").endswith(".ret")],
            "outputs": [_artifact_row(r) for r in matched
                        if (r.get("api") or "").endswith(".ret")],
            "dag": _field_subdag(value, edges, ref_value),
        })
    return {
        "note": ("per-field sign artifact: observed output + evidence + matching "
                 "materials/outputs + producing sub-DAG, plus shared phases / env "
                 "/ candidate pools. Assembled from capture, not recomputed; "
                 "unpaired fields intentionally have empty materials."),
        "anchor": {"carrier": carrier, "url": (anchor_url or "")[:200],
                   "mono_us": anchor_mono},
        "phases": phases,
        "env": env_reads,
        "candidate_inputs": [_candidate_row(r, full_by_sha) for r in crypto_inputs[:200]],
        "candidate_outputs": [_candidate_row(r, full_by_sha) for r in crypto_outputs[:200]],
        "fields": fields,
    }


# ------------------------------- replay ---------------------------------
#
# An oracle over OBSERVED capture: does a standard transform of a captured input
# reproduce a captured field? This VERIFIES the observed signature (proves/falsifies
# the input->output edge with general algorithms) -- it is not a token generator:
# it never signs a new input, only re-derives the one already in the trace.

# Keyless digests available everywhere via hashlib, plus crc32 (zlib). Site-neutral.
REPLAY_HASHES = ("md5", "sha1", "sha224", "sha256", "sha384", "sha512",
                 "sha3_256", "sha3_512", "blake2b", "blake2s")
MIN_MATCH_LEN = 8   # gate prefix/substring hits so short fields don't match by chance


def _encode_forms(raw: bytes):
    """Every common textual encoding of a raw byte string (digest or input)."""
    b64 = base64.b64encode(raw).decode("ascii")
    b64u = base64.urlsafe_b64encode(raw).decode("ascii")
    yield "hex_lower", raw.hex()
    yield "hex_upper", raw.hex().upper()
    yield "base64", b64
    yield "base64_nopad", b64.rstrip("=")
    yield "base64url", b64u
    yield "base64url_nopad", b64u.rstrip("=")


def _transforms(value: str):
    """Yield (algo, encoding, produced_string) for one candidate input value.

    Covers keyless hashes of the utf-8 bytes and direct encodings of the bytes
    (a field that is just base64/hex of a plaintext, no hash)."""
    data = value.encode("utf-8", "surrogatepass")
    for algo in REPLAY_HASHES:
        try:
            digest = hashlib.new(algo, data).digest()
        except (ValueError, TypeError):
            continue
        for enc, produced in _encode_forms(digest):
            yield algo, enc, produced
    crc = format(zlib.crc32(data) & 0xFFFFFFFF, "08x")
    yield "crc32", "hex_lower", crc
    yield "crc32", "hex_upper", crc.upper()
    for enc, produced in _encode_forms(data):        # direct (no hash)
        yield "identity", enc, produced


def _match_slice(target: str, produced: str):
    """How ``target`` sits inside ``produced`` (exact / prefix / substring), or None.
    Short prefix/substring hits are gated by MIN_MATCH_LEN to avoid coincidence."""
    if not target or not produced:
        return None
    if produced == target:
        return {"match_kind": "exact", "slice": [0, len(produced)]}
    if len(target) < MIN_MATCH_LEN:
        return None
    idx = produced.find(target)
    if idx == 0:
        return {"match_kind": "prefix", "slice": [0, len(target)]}
    if idx > 0:
        return {"match_kind": "substring", "slice": [idx, idx + len(target)]}
    return None


# ---- multi-step / keyed derivations (HMAC, hash-of-hash, encode-then-hash, concat) ----
# Real signatures are frequently more than one keyless hash. These stay over OBSERVED
# material only: HMAC keys and concat salts are drawn from the captured candidate pool,
# never guessed -- guessing an unknown constant would be generation, not verification.
MULTI_HASHES = ("md5", "sha1", "sha256", "sha512")  # bounded set for 2-step / HMAC compositions
COMBINATORIAL_CAP = 24                              # distinct values paired for HMAC/concat (N^2)


def _digest(algo, data):
    return hashlib.new(algo, data).digest()


def _derivation_universe(values):
    """Yield derivation dicts {structure, algo, encoding, produced, <operands>} for every
    transform tested over de-duplicated candidate values. Field-independent, so it is
    built once and matched against all fields.

    Single-input: keyless H(input) + direct encodings (via _transforms), encode-then-hash
    H(enc(input)), and hash-of-hash H2(H1(input)). Pair-input over the candidate pool:
    HMAC(key, msg) and salted concatenation H(input || salt)."""
    seen, pool = set(), []
    for v in values:
        if v and v not in seen:
            seen.add(v)
            pool.append(v)
    combo = pool[:COMBINATORIAL_CAP]

    for v in pool:
        data = v.encode("utf-8", "surrogatepass")
        for algo, enc, produced in _transforms(v):          # keyless single + direct encodings
            yield {"structure": "H(input)", "algo": algo, "encoding": enc,
                   "produced": produced, "input": v}
        for pre_enc, pre in _encode_forms(data):             # encode-then-hash
            pb = pre.encode("ascii")
            for algo in MULTI_HASHES:
                for enc, produced in _encode_forms(_digest(algo, pb)):
                    yield {"structure": "H(enc(input))", "algo": algo, "encoding": enc,
                           "pre_encoding": pre_enc, "produced": produced, "input": v}
        for a1 in MULTI_HASHES:                              # hash-of-hash H2(H1(input))
            d1 = _digest(a1, data)
            for form, inner in (("digest", d1), ("hex", d1.hex().encode("ascii"))):
                for a2 in MULTI_HASHES:
                    for enc, produced in _encode_forms(_digest(a2, inner)):
                        yield {"structure": "H2(H1(input))", "algo": a2, "inner_algo": a1,
                               "inner_form": form, "encoding": enc, "produced": produced,
                               "input": v}

    for i, a in enumerate(combo):
        ad = a.encode("utf-8", "surrogatepass")
        for j, b in enumerate(combo):
            if i == j:
                continue
            bd = b.encode("utf-8", "surrogatepass")
            for algo in REPLAY_HASHES:                       # HMAC(key=a, msg=b)
                try:
                    mac = hmac.new(ad, bd, algo).digest()
                except (ValueError, TypeError):
                    continue
                for enc, produced in _encode_forms(mac):
                    yield {"structure": "HMAC(key, msg)", "algo": algo, "encoding": enc,
                           "produced": produced, "key": a, "input": b}
            catd = ad + bd                                   # salted concat H(input || salt)
            for algo in MULTI_HASHES:
                for enc, produced in _encode_forms(_digest(algo, catd)):
                    yield {"structure": "H(a||b)", "algo": algo, "encoding": enc,
                           "produced": produced, "input": a, "salt": b}


def _render_spec(d, ms):
    """Readable pseudocode for a matched derivation, including any field slice."""
    enc_fn = _ENC_FN.get(d.get("encoding"), d.get("encoding"))
    algo, st = d.get("algo"), d.get("structure")
    if st == "HMAC(key, msg)":
        core = f"HMAC_{algo}(key, msg)"
    elif st == "H(a||b)":
        core = f"{algo}(input || salt)"
    elif st == "H(enc(input))":
        core = f"{algo}({d.get('pre_encoding')}(input))"
    elif st == "H2(H1(input))":
        core = f"{algo}({d.get('inner_algo')}(input)[{d.get('inner_form')}])"
    elif algo == "identity":
        core = None
    else:
        core = f"{algo}(input)"
    expr = f"{enc_fn}(input)" if core is None else f"{enc_fn}({core})"
    mk, sl = ms.get("match_kind"), ms.get("slice") or [0, 0]
    if mk == "prefix":
        expr += f"[:{sl[1]}]"
    elif mk == "substring":
        expr += f"[{sl[0]}:{sl[1]}]"
    return expr


def _record_derivation(d, ms, value_meta):
    """Flatten a universe derivation + match into the replay.json derivation shape,
    enriching each operand with its capture metadata (api / d_ms / value_sha)."""
    def ref(val, prefix):
        m = value_meta.get(val, {})
        return {f"{prefix}_api": m.get("api"), f"{prefix}_d_ms": m.get("d_ms"),
                f"{prefix}_value_sha": m.get("value_sha"), f"{prefix}_preview": (val or "")[:80]}
    out = {"structure": d.get("structure"), "algo": d.get("algo"),
           "encoding": d.get("encoding"), **ms, "spec": _render_spec(d, ms),
           **ref(d.get("input"), "input")}
    if "key" in d:
        out.update(ref(d["key"], "key"))
    if "salt" in d:
        out.update(ref(d["salt"], "salt"))
    if d.get("inner_algo"):
        out["inner_algo"] = d["inner_algo"]
        out["inner_form"] = d.get("inner_form")
    if d.get("pre_encoding"):
        out["pre_encoding"] = d["pre_encoding"]
    return out


def replay_oracle(artifact: dict):
    """Try to reproduce each field from the artifact's candidate inputs.

    For every field: (1) if a captured crypto OUTPUT (.ret) already equals it,
    record that observed edge (no recomputation); (2) try every standard transform
    of every candidate input and record exact/prefix/substring reproductions.
    Returns the replay report; ``resolved`` = an observed-output edge or at least
    one derivation was found."""
    inputs = [c for c in artifact.get("candidate_inputs", []) if c.get("value")]
    outputs = artifact.get("candidate_outputs", [])
    value_meta = {}
    for c in inputs:
        value_meta.setdefault(c.get("value"), c)
    # field-independent: build the transform universe once, match every field against it
    universe = list(_derivation_universe([c["value"] for c in inputs]))
    _rank = {"exact": 0, "prefix": 1, "substring": 2}
    fields_out = []
    newly = 0
    for f in artifact.get("fields", []):
        target = f.get("output_value") or ""
        # (1) observed output edge: a captured .ret whose bytes carry the field
        edge = None
        for o in outputs:
            ov = o.get("value") or o.get("value_preview") or ""
            ms = _match_slice(target, ov)
            if ms:
                edge = {"api": o.get("api"), "d_ms": o.get("d_ms"),
                        "value_sha": o.get("value_sha"), **ms}
                break
        # (2) recomputation: keyless single-step, encode-then-hash, hash-of-hash,
        #     HMAC, and salted concat -- all over observed material only
        derivations = []
        if target:
            for d in universe:
                ms = _match_slice(target, d["produced"])
                if ms:
                    derivations.append(_record_derivation(d, ms, value_meta))
            derivations.sort(key=lambda x: _rank.get(x.get("match_kind"), 3))
        resolved = bool(edge or derivations)
        if resolved and f.get("evidence") in ("unpaired", "context_only", None):
            newly += 1
        fields_out.append({
            "field": f.get("field"),
            "output_value": target,
            "prior_evidence": f.get("evidence"),
            "resolved": resolved,
            "observed_output_edge": edge,
            "derivations": derivations[:12],
            "derivation_count": len(derivations),
        })
    total = len(fields_out)
    resolved_n = sum(1 for f in fields_out if f["resolved"])
    return {
        "note": ("oracle over OBSERVED capture: verifies whether a standard "
                 "transform of a captured input reproduces a captured field. "
                 "Proves/falsifies the input->output edge; not a token generator."),
        "anchor": artifact.get("anchor"),
        "algorithms_tried": list(REPLAY_HASHES) + ["crc32", "identity", "hmac"],
        "structures_tried": ["H(input)", "H(enc(input))", "H2(H1(input))",
                             "HMAC(key,msg)", "H(input||salt)"],
        "encodings_tried": ["hex_lower", "hex_upper", "base64", "base64_nopad",
                            "base64url", "base64url_nopad"],
        "candidate_inputs_used": len(inputs),
        "summary": {
            "fields_total": total,
            "fields_resolved": resolved_n,
            "resolution_rate": round(resolved_n / total, 3) if total else 0.0,
            "newly_resolved_vs_pairing": newly,
            "unresolved_fields": [f["field"] for f in fields_out if not f["resolved"]][:24],
        },
        "fields": fields_out,
    }


# ------------------------------- export ---------------------------------
#
# Project the replay-VERIFIED derivations + env reads into a minimal algorithm
# spec. This DOCUMENTS the reverse-engineered signing relationship over observed
# capture (a deobfuscation deliverable); it is not a generator for new inputs.

_ENC_FN = {"hex_lower": "hex", "hex_upper": "HEX", "base64": "base64",
           "base64_nopad": "base64_nopad", "base64url": "base64url",
           "base64url_nopad": "base64url_nopad"}


def _spec_pseudocode(deriv):
    """Readable pseudocode for one proven derivation. Prefers the spec the oracle
    built (which encodes multi-step / keyed structure); falls back for legacy dicts."""
    if deriv.get("spec"):
        return deriv["spec"]
    algo, enc = deriv.get("algo"), deriv.get("encoding")
    enc_fn = _ENC_FN.get(enc, enc)
    expr = f"{enc_fn}(input)" if algo == "identity" else f"{enc_fn}({algo}(input))"
    mk, sl = deriv.get("match_kind"), deriv.get("slice") or [0, 0]
    if mk == "prefix":
        expr += f"[:{sl[1]}]"
    elif mk == "substring":
        expr += f"[{sl[0]}:{sl[1]}]"
    return expr


def build_algo_spec(artifact, replay):
    """Per-field algorithm spec from replay's verified derivations, plus the
    environment inputs the signer read in-window. Only what replay PROVED is
    asserted; unresolved fields are recorded as such, not guessed."""
    rfields = {f["field"]: f for f in replay.get("fields", [])}
    primitives = set()
    counts = {"derived": 0, "observed_output": 0, "unresolved": 0}
    fields = []
    for f in artifact.get("fields", []):
        label = f.get("field")
        rf = rfields.get(label, {})
        derivations = rf.get("derivations") or []
        edge = rf.get("observed_output_edge")
        entry = {"field": label, "output_value": f.get("output_value"),
                 "evidence_prior": f.get("evidence")}
        if derivations:
            d = derivations[0]
            if d.get("algo") and d["algo"] != "identity":
                primitives.add(d["algo"])
            entry.update({
                "status": "derived", "spec": f"{label} = {_spec_pseudocode(d)}",
                "algo": d.get("algo"), "encoding": d.get("encoding"),
                "match_kind": d.get("match_kind"),
                "input": {"api": d.get("input_api"), "d_ms": d.get("input_d_ms"),
                          "value_sha": d.get("input_value_sha"),
                          "preview": d.get("input_preview")},
                "alternative_derivations": len(derivations) - 1,
            })
            counts["derived"] += 1
        elif edge:
            entry.update({
                "status": "observed_output",
                "spec": f"{label} = output of {edge.get('api')} @ d_ms={edge.get('d_ms')}",
                "note": "produced by a crypto.subtle call observed at the boundary; "
                        "the exact primitive parameters were not recomputed",
            })
            counts["observed_output"] += 1
        else:
            entry.update({
                "status": "unresolved",
                "note": "no standard keyless transform of the observed inputs "
                        "reproduced this field; needs deeper analysis "
                        "(HMAC / multi-step / an unobserved input)",
            })
            counts["unresolved"] += 1
        fields.append(entry)
    return {
        "note": ("verified algorithm spec: per-field derivations replay PROVED over "
                 "observed capture, plus the environment inputs the signer read. A "
                 "description of the reverse-engineered relationship, not a generator "
                 "for new inputs."),
        "anchor": artifact.get("anchor"),
        "phases": [p.get("name") if isinstance(p, dict) else p
                   for p in artifact.get("phases", [])],
        "environment_inputs": artifact.get("env", []),
        "primitives": sorted(primitives),
        "fields": fields,
        "summary": {"fields_total": len(fields), **counts,
                    "primitives": sorted(primitives)},
    }


def render_algo_spec_md(spec):
    """Human-readable companion to algo_spec.json."""
    a = spec.get("anchor") or {}
    lines = ["# Signing algorithm spec (verified over observed capture)", "",
             spec.get("note", ""), "",
             f"- carrier: `{a.get('carrier')}`"]
    if spec.get("primitives"):
        lines.append(f"- primitives: {', '.join(spec['primitives'])}")
    if spec.get("phases"):
        lines.append(f"- phases: {' -> '.join(map(str, spec['phases']))}")
    lines += ["", "## Fields", ""]
    for f in spec.get("fields", []):
        if f["status"] == "derived":
            inp = f.get("input") or {}
            lines.append(f"- **{f['field']}** — `{f['spec']}`  "
                         f"(input: {inp.get('api')} @ {inp.get('d_ms')}ms)")
        elif f["status"] == "observed_output":
            lines.append(f"- **{f['field']}** — {f['spec']} (observed crypto output)")
        else:
            lines.append(f"- **{f['field']}** — _unresolved_: {f.get('note', '')}")
    env = spec.get("environment_inputs") or []
    if env:
        lines += ["", "## Environment inputs read in-window", ""]
        for e in env:
            lines.append(f"- `{e.get('api')}` x{e.get('count')} (first {e.get('first_d_ms')}ms)")
    s = spec.get("summary", {})
    lines += ["", "## Summary", "",
              f"{s.get('derived', 0)} derived, {s.get('observed_output', 0)} "
              f"observed-output, {s.get('unresolved', 0)} unresolved of "
              f"{s.get('fields_total', 0)} fields."]
    return "\n".join(lines) + "\n"


# ------------------------------- discover -------------------------------

def find_carriers(trace: Path, window_ms, min_entropy, top, families, hint_names=()):
    """Rank token carriers name-free: entropy + per-request variance + preceding
    compute burst. Names in hint_names are captured raw and score-weighted, so
    known signature params beat noise (and structured tokens are not dropped)."""
    hints = {n.lower() for n in hint_names}
    seen = collections.defaultdict(lambda: {"values": [], "where": set(), "monos": []})
    for mono, url, headers, body_text, _ in iter_requests(trace):
        for name, val, where in request_carriers(url, headers, body_text, min_entropy,
                                                  raw_names=hint_names):
            rec = seen[name]
            rec["values"].append(val)
            rec["where"].add(where)
            rec["monos"].append(mono)
    if not seen:
        return []
    comp = collect_compute_monos(trace, families)

    def burst(mono):
        if mono is None or not comp:
            return 0
        return bisect.bisect_right(comp, mono) - bisect.bisect_left(comp, mono - window_ms * 1000.0)

    cands = []
    for name, rec in seen.items():
        vals = rec["values"]
        variance = len(set(vals)) / len(vals)
        ent = max(shannon_entropy(v) for v in vals)
        max_burst = max((burst(m) for m in rec["monos"]), default=0)
        hinted = name.lower() in hints
        score = round(variance * ent * math.log10(max_burst + 10) * (2.0 if hinted else 1.0), 3)
        cands.append({
            "name": name, "where": sorted(rec["where"]), "count": len(vals),
            "distinct_values": len(set(vals)), "variance": round(variance, 2),
            "max_entropy": round(ent, 2), "example_len": max(len(v) for v in vals),
            "max_compute_burst": max_burst, "hinted": hinted, "score": score,
            "example": vals[0][:24],
        })
    cands.sort(key=lambda c: -c["score"])
    return cands[:top]


def cmd_discover(args):
    fams = parse_families(args.compute_families)
    hints = tuple(args.carrier_hint) or DEFAULT_CARRIER_HINTS
    cands = find_carriers(args.trace, args.window_ms, args.min_entropy, args.top, fams, hints)
    # WASM presence: if a page instantiates WASM, a carrier with no JS compute
    # burst may be WASM-signed (per-call JS<->WASM capture is not yet available).
    wasm_events = len(collect_compute_monos(args.trace, ["wasm"]))
    report = {"trace": str(args.trace), "window_ms": args.window_ms,
              "min_entropy": args.min_entropy, "compute_families": fams,
              "wasm_boundary_events": wasm_events,
              "wasm_note": ("page uses WebAssembly; a low-burst carrier may be WASM-signed"
                            if wasm_events else "no WebAssembly boundary events seen"),
              "carriers": cands}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if cands else 3


# ------------------------------- explain --------------------------------

def cmd_explain(args):
    fams = parse_families(args.compute_families)
    hints = tuple(args.carrier_hint) or DEFAULT_CARRIER_HINTS
    carrier = args.carrier
    if not carrier:
        cands = find_carriers(args.trace, args.window_ms, args.min_entropy, 1, fams, hints)
        if not cands:
            print("No token carrier auto-discovered; pass --carrier NAME", file=sys.stderr)
            return 2
        carrier = cands[0]["name"]
        print(f"[auto] anchor carrier = {carrier} (score {cands[0]['score']})", file=sys.stderr)

    raw_names = set(hints) | {carrier}
    matches = []
    for mono, url, headers, body_text, e in iter_requests(args.trace):
        names = {n for n, _, _ in request_carriers(url, headers, body_text, args.min_entropy,
                                                    raw_names=raw_names)}
        if (carrier in names or f"{carrier}=" in (url or "")
                or any(h.get("name") == carrier for h in headers or [])):
            matches.append((mono, url, headers, body_text))
    matches.sort(key=lambda m: m[0])
    if not matches or args.anchor_index >= len(matches):
        print(f"No request carrying {carrier} at index {args.anchor_index} "
              f"(only {len(matches)} found)", file=sys.stderr)
        return 2
    anchor_mono, anchor_url, anchor_headers, anchor_body = matches[args.anchor_index]
    lo, hi = anchor_mono - args.window_ms * 1000.0, anchor_mono

    all_ops, net, str_hits = collect_window(args.trace, lo, hi)
    signer = args.script if args.script and args.script != "auto" else detect_signer_script(all_ops, fams)
    ops = [e for e in all_ops if signer in (e["args"][0].get("callsite_script") or "")] if signer else all_ops
    producers, edges, inputs, ref_value = build_dag(ops)

    # multi-carrier: every carrier on the anchor request (raw for hints/--carrier)
    tokens = {n: v for n, v, _ in request_carriers(
        anchor_url, anchor_headers, anchor_body, args.min_entropy, raw_names=raw_names)}
    q = parse_qs(urlparse(anchor_url or "").query)
    hdr = {h.get("name"): h.get("value", "") for h in anchor_headers or []}
    # force-extract the anchor carrier + any --token even if not token-shaped
    for name in [carrier, *(args.token or [])]:
        if name and name not in tokens:
            if name in q:
                tokens[name] = q[name][0]
            elif name in hdr:
                tokens[name] = hdr[name]
    prov = token_provenance(str_hits, tokens, anchor_mono)
    emit_d_ms = min((d for d in prov.values() if d is not None), default=None)

    # structured tokens: split multi-field values into generic f0..fN
    sep = args.token_field_sep
    structures = {k: split_token_fields(v, sep) for k, v in tokens.items()} if sep else {}

    # materials timeline: tag strings that land in a token field or equal a param
    token_fields = dict(tokens)
    token_fields.update(token_leaf_fields(tokens, structures))
    param_values = {k: (v[0] if v else "") for k, v in q.items()}
    try:
        for k, v in flatten_json(json.loads(anchor_body)):
            if isinstance(v, str):
                param_values[f"body.{k}"] = v
    except (json.JSONDecodeError, TypeError):
        pass
    timeline = build_timeline(all_ops, anchor_mono, token_fields, param_values)
    phases = classify_phases(ops, anchor_mono, emit_d_ms)
    # digest/AES inputs: the plaintext material fed into hash/cipher (from
    # --inject-api-hooks). Auto-surfaced so you don't have to dig the timeline.
    # Drop native value-refs (summary mode) and the injector's own emit payloads
    # (the native JSON.stringify hook sees the inject serialization -> feedback).
    def _plaintext(v):
        return bool(v) and not (
            v.startswith(("string_ref:", "object:", "number:", "bytes_",
                          "handler_arg:", "json:"))
            or '"category":"inject"' in v)

    def _is_crypto_input(api):
        # crypto.subtle / TextEncoder / ... capture the INPUT plaintext; the paired
        # <api>.ret events carry the OUTPUT bytes -- keep those out of the input set
        # so a digest/signature is never mistaken for hashed material.
        api = api or ""
        return api.startswith(CRYPTO_INPUT_APIS) and not api.endswith(".ret")

    crypto_inputs = [r for r in timeline
                     if _is_crypto_input(r.get("api"))
                     and _plaintext(r.get("value_preview", ""))]
    # Hot-path outputs: reproducible intermediate values (digest / signature /
    # ciphertext bytes) emitted by --inject-api-hooks as <api>.ret, kept so the
    # input->output edge is available for replay/oracle downstream.
    crypto_outputs = [r for r in timeline if (r.get("api") or "").endswith(".ret")]

    # pairing rate: how much of the token we can explain from captured material
    # (提证率), plus capture-truncation stats to tune --inject-scan-cap.
    leaf_fields = token_leaf_fields(tokens, structures)
    pairing = build_pairing(timeline, leaf_fields, crypto_inputs)
    trunc, max_input_len = 0, 0
    for e in all_ops:
        if not _is_crypto_input(e.get("api")):
            continue
        for a in (e.get("args") or []):
            if not isinstance(a, dict):
                continue
            if isinstance(a.get("len"), int) and isinstance(a.get("value"), str):
                max_input_len = max(max_input_len, a["len"])
                if a["len"] > len(a["value"]):
                    trunc += 1
            # typed-array boundary values (crypto.subtle buffers) carry byteLength +
            # hex (two chars/byte); a short hex vs byteLength means the buffer clipped.
            elif isinstance(a.get("byteLength"), int) and isinstance(a.get("hex"), str):
                if a["byteLength"] * 2 > len(a["hex"]):
                    trunc += 1
    pairing.update({
        "capture_truncated_events": trunc,
        "max_captured_input_len": max_input_len,
        "cap_hint": ("raise --inject-scan-cap (captured inputs were truncated)"
                     if trunc else "captured inputs not truncated"),
    })

    materials = {r: ref_value.get(r, ref_literal(r)) for r in set(inputs) | set(producers)}

    args.out.mkdir(parents=True, exist_ok=True)
    rows = [op_row(e, anchor_mono) for e in ops]
    ops_written = write_ops(rows, args.out)

    def token_entry(k, v):
        entry = {"value": v, "length": len(v), "earliest_visible_d_ms": prov.get(k)}
        if structures.get(k):
            entry["structure"] = structures[k]
        return entry

    (args.out / "token.json").write_text(json.dumps({
        "url": anchor_url, "anchor_mono_us": anchor_mono, "anchor_carrier": carrier,
        "tokens": {k: token_entry(k, v) for k, v in tokens.items()},
    }, ensure_ascii=False, indent=2))
    with (args.out / "materials_timeline.jsonl").open("w") as fh:
        for r in timeline:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    (args.out / "phases.json").write_text(
        json.dumps({"phases": phases}, ensure_ascii=False, indent=2))
    (args.out / "crypto_inputs.json").write_text(json.dumps({
        "count": len(crypto_inputs),
        "note": "plaintext fed into hash/cipher/sign in the window (from --inject-api-hooks)",
        "inputs": crypto_inputs,
    }, ensure_ascii=False, indent=2))
    (args.out / "crypto_outputs.json").write_text(json.dumps({
        "count": len(crypto_outputs),
        "note": "hash/sign/cipher OUTPUT bytes captured at the crypto.subtle boundary "
                "(<api>.ret from --inject-api-hooks); the input->output edge for replay",
        "outputs": crypto_outputs,
    }, ensure_ascii=False, indent=2))
    (args.out / "pairing.json").write_text(json.dumps(pairing, ensure_ascii=False, indent=2))
    # sign_artifact: the keystone -- per-field {output, materials, outputs, dag} +
    # shared phases/env/candidate pools, assembled from the pieces above. This is
    # what a replay/oracle and env/algo export consume.
    # full captured values (timeline previews are clipped to 80 chars); join by
    # value_sha so the artifact's candidate pools carry the whole plaintext/hex.
    full_by_sha = {}
    for e in all_ops:
        a = e.get("args")
        if not (isinstance(a, list) and a and isinstance(a[0], dict)):
            continue
        for v in a[0].values():
            if isinstance(v, str) and len(v) >= 12:
                full_by_sha.setdefault(sha8(v), v)
    artifact = build_sign_artifact(
        pairing, leaf_fields, timeline, crypto_inputs, crypto_outputs, phases,
        env_reads_in_window(all_ops, anchor_mono), edges, ref_value,
        carrier, anchor_url, anchor_mono, full_by_sha=full_by_sha)
    (args.out / "sign_artifact.json").write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2))
    (args.out / "inputs.json").write_text(json.dumps({
        "count": len(inputs),
        "note": "DAG leaves: value-refs consumed in-window but never produced in-window",
        "inputs": [{"ref": r, "observed_value": ref_value.get(r, ref_literal(r))} for r in inputs],
    }, ensure_ascii=False, indent=2))
    (args.out / "materials.json").write_text(json.dumps({
        "count": len(materials),
        "note": "ref -> concrete value for every input leaf and produced result node",
        "materials": materials,
    }, ensure_ascii=False))
    (args.out / "dag.json").write_text(json.dumps({
        "nodes": sorted({x for e in edges for x in (e["from"], e["to"])}),
        "edges": edges, "producers": {str(k): v for k, v in producers.items()},
    }, ensure_ascii=False))

    summary = {
        "trace": str(args.trace),
        "anchor": {"carrier": carrier, "index": args.anchor_index,
                   "matches_in_trace": len(matches), "mono_us": anchor_mono,
                   "url": (anchor_url or "")[:200]},
        "window_ms": args.window_ms, "compute_families": fams,
        "signer_script": signer or "(all scripts)",
        "signer_script_auto": args.script in (None, "auto"),
        "window_ops": len(ops), "window_ops_all_scripts": len(all_ops),
        "window_network_events": len(net),
        "op_histogram": histogram([e.get("api") for e in ops]),
        "hot_callsite_functions": histogram([e["args"][0].get("callsite_function") for e in ops], top=12),
        "hot_callsite_columns": histogram([e["args"][0].get("callsite_column") for e in ops], top=12),
        "dag": {"result_nodes": len(producers), "edges": len(edges), "inputs": len(inputs)},
        "tokens": {k: {"length": len(v),
                       "fields": structures[k]["field_count"] if structures.get(k) else None,
                       "earliest_visible_d_ms": prov.get(k)} for k, v in tokens.items()},
        "phases": [p["name"] for p in phases],
        "timeline_events": len(timeline),
        "crypto_inputs": len(crypto_inputs),
        "crypto_outputs": len(crypto_outputs),
        "sign_artifact_fields": len(artifact["fields"]),
        "pairing": {"token_field_pairing_rate": pairing["token_field_pairing_rate"],
                    "capture_truncated_events": pairing["capture_truncated_events"]},
        "outputs_written": ops_written,
    }
    (args.out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"\nWrote {args.out}/: summary.json sign_artifact.json token.json inputs.json "
          f"materials.json materials_timeline.jsonl phases.json crypto_inputs.json "
          f"crypto_outputs.json pairing.json dag.json {ops_written}")
    return 0


# --------------------------------- diff ---------------------------------

def _load_run(d):
    s = json.loads((d / "summary.json").read_text())
    s["_dir"] = str(d)
    tok = d / "token.json"
    s["_tokens"] = json.loads(tok.read_text()).get("tokens", {}) if tok.exists() else {}
    tl = d / "materials_timeline.jsonl"
    s["_materials"] = ({json.loads(x)["value_sha"] for x in tl.read_text().splitlines() if x}
                       if tl.exists() else set())
    return s


def token_field_diff(runs, sep):
    """Per-field same/hamming across runs for tokens common to all runs."""
    if not runs:
        return {}
    common = set.intersection(*[set(r["_tokens"]) for r in runs])
    out = {}
    for tk in sorted(common):
        vals = [r["_tokens"][tk].get("value", "") for r in runs]
        if sep and all(sep in v for v in vals):
            parts = [v.split(sep) for v in vals]
            fields = []
            for i in range(min(len(p) for p in parts)):
                col_i = [p[i] for p in parts]
                same = len(set(col_i)) == 1
                if not same and len({len(c) for c in col_i}) == 1:
                    hamming = max(sum(a != b for a, b in zip(col_i[0], c)) for c in col_i[1:])
                else:
                    hamming = None
                fields.append({"i": i, "name": f"f{i}", "same": same,
                               "hamming": hamming, "lens": [len(c) for c in col_i]})
            out[tk] = {"sep": sep, "fields": fields}
        else:
            out[tk] = {"same": len(set(vals)) == 1}
    return out


def cmd_diff(args):
    runs = [_load_run(d) for d in args.dirs]

    def col(getter):
        return [getter(r) for r in runs]

    all_apis = sorted({a for r in runs for a in r["op_histogram"]})
    op_table = {a: [r["op_histogram"].get(a, 0) for r in runs] for a in all_apis}
    stable_ops = {a: v[0] for a, v in op_table.items() if len(set(v)) == 1}
    variable_ops = {a: v for a, v in op_table.items() if len(set(v)) > 1}
    fns = sorted({f for r in runs for f in r["hot_callsite_functions"]})
    stable_fns = [f for f in fns if all(f in r["hot_callsite_functions"] for r in runs)]

    mat_diff = {}
    if len(runs) == 2:
        a, b = runs[0]["_materials"], runs[1]["_materials"]
        mat_diff = {"added": len(b - a), "removed": len(a - b), "shared": len(a & b)}

    report = {
        "runs": [{"dir": r["_dir"], "carrier": r["anchor"]["carrier"],
                  "signer_script": r.get("signer_script"),
                  "window_ops": r["window_ops"], "dag": r["dag"], "tokens": r["tokens"]} for r in runs],
        "invariant": {
            "signer_script_same": len({r.get("signer_script") for r in runs}) == 1,
            "hot_functions_shared": stable_fns,
            "ops_constant_count": stable_ops,
        },
        "variable": {
            "ops_varying_count": variable_ops,
            "window_ops_range": [min(col(lambda r: r["window_ops"])), max(col(lambda r: r["window_ops"]))],
            "input_leaf_range": [min(col(lambda r: r["dag"]["inputs"])), max(col(lambda r: r["dag"]["inputs"]))],
            "token_fields": token_field_diff(runs, args.token_field_sep),
            "materials": mat_diff,
        },
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.out:
        out = args.out
        # accept a directory (write report.json inside) or an explicit file path
        if out.exists() and out.is_dir():
            out = out / "report.json"
        elif not out.suffix and not out.exists():
            out.mkdir(parents=True, exist_ok=True)
            out = out / "report.json"
        else:
            out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def cmd_replay(args):
    """One-click oracle: verify each field of a sign_artifact against its own
    candidate inputs with standard algorithms, writing replay.json next to it."""
    art_path = args.artifact
    if art_path.is_dir():
        art_path = art_path / "sign_artifact.json"
    if not art_path.exists():
        raise ValueError(f"sign_artifact.json not found: {art_path} "
                         f"(run `explain` first)")
    artifact = json.loads(art_path.read_text())
    report = replay_oracle(artifact)
    out = args.out or art_path.with_name("replay.json")
    if out.is_dir() or (not out.suffix and not out.exists()):
        out.mkdir(parents=True, exist_ok=True)
        out = out / "replay.json"
    else:
        out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    print(f"\nWrote {out}")
    return 0


def cmd_export(args):
    """Project a sign_artifact (+ its replay verification) into a minimal algo+env
    spec: algo_spec.json and a readable algo_spec.md alongside the artifact."""
    art_path = args.artifact
    if art_path.is_dir():
        art_path = art_path / "sign_artifact.json"
    if not art_path.exists():
        raise ValueError(f"sign_artifact.json not found: {art_path} (run `explain` first)")
    artifact = json.loads(art_path.read_text())
    spec = build_algo_spec(artifact, replay_oracle(artifact))
    out_dir = args.out or art_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "algo_spec.json").write_text(json.dumps(spec, ensure_ascii=False, indent=2))
    (out_dir / "algo_spec.md").write_text(render_algo_spec_md(spec))
    print(json.dumps(spec["summary"], ensure_ascii=False, indent=2))
    print(f"\nWrote {out_dir}/algo_spec.json + algo_spec.md")
    return 0


# --------------------------------- cli ----------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("discover", help="find token carriers without knowing their names")
    d.add_argument("--trace", required=True, type=Path)
    d.add_argument("--out", type=Path, default=None)
    d.add_argument("--window-ms", type=float, default=300.0)
    d.add_argument("--min-entropy", type=float, default=4.0)
    d.add_argument("--top", type=int, default=10)
    d.add_argument("--carrier-hint", action="append", default=[],
                   help=f"param name(s) to capture raw + score-weight "
                        f"(default: {', '.join(DEFAULT_CARRIER_HINTS)})")
    d.add_argument("--compute-families", default=DEFAULT_FAMILIES,
                   help=f"comma list from {list(COMPUTE_FAMILIES)} (default: {DEFAULT_FAMILIES})")
    d.set_defaults(func=cmd_discover)

    e = sub.add_parser("explain", help="emit the inputs->operators->output data-flow")
    e.add_argument("--trace", required=True, type=Path)
    e.add_argument("--out", required=True, type=Path)
    e.add_argument("--carrier", default=None, help="anchor carrier name; omit to auto-discover")
    e.add_argument("--script", default="auto", help="signer script substring, or 'auto'")
    e.add_argument("--token", action="append", default=[], help="extra token param(s) to extract")
    e.add_argument("--carrier-hint", action="append", default=[],
                   help=f"param name(s) to capture raw (default: {', '.join(DEFAULT_CARRIER_HINTS)})")
    e.add_argument("--token-field-sep", default=None,
                   help="split token values into generic fields f0..fN on this separator (e.g. ';')")
    e.add_argument("--window-ms", type=float, default=300.0)
    e.add_argument("--min-entropy", type=float, default=4.0)
    e.add_argument("--anchor-index", type=int, default=0)
    e.add_argument("--compute-families", default=DEFAULT_FAMILIES,
                   help=f"comma list from {list(COMPUTE_FAMILIES)} (default: {DEFAULT_FAMILIES})")
    e.set_defaults(func=cmd_explain)

    f = sub.add_parser("diff", help="compare several explain outputs")
    f.add_argument("dirs", nargs="+", type=Path)
    f.add_argument("--out", type=Path, default=None)
    f.add_argument("--token-field-sep", default=None,
                   help="compare token values field-by-field on this separator (e.g. ';')")
    f.set_defaults(func=cmd_diff)

    rp = sub.add_parser("replay", help="oracle: verify fields against candidate inputs with standard algorithms")
    rp.add_argument("artifact", type=Path,
                    help="explain output dir or a sign_artifact.json path")
    rp.add_argument("--out", type=Path, default=None,
                    help="replay.json path or dir (default: next to the artifact)")
    rp.set_defaults(func=cmd_replay)

    xp = sub.add_parser("export", help="project replay-verified derivations into a minimal algo+env spec")
    xp.add_argument("artifact", type=Path,
                    help="explain output dir or a sign_artifact.json path")
    xp.add_argument("--out", type=Path, default=None,
                    help="output dir for algo_spec.json/.md (default: alongside the artifact)")
    xp.set_defaults(func=cmd_export)

    args = ap.parse_args(argv)
    if getattr(args, "trace", None) is not None and not args.trace.exists():
        ap.error(f"trace not found: {args.trace}")
    try:
        return args.func(args)
    except ValueError as exc:
        ap.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
