#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qs, urlparse

try:
    from scripts.validate_trace import VMP_API_FAMILY, event_has_vmp_family_evidence
except ModuleNotFoundError:
    from validate_trace import VMP_API_FAMILY, event_has_vmp_family_evidence


URL_RE = re.compile(r"https?://[^\s\"'<>\\]+")
DEFAULT_SNIPPET_BEFORE_CHARS = 240
DEFAULT_SNIPPET_AFTER_CHARS = 520
PROXIMITY_WINDOW_US = 250_000
PROFILE_SIGNATURE = "signature"
PROFILE_GENERIC_VMP = "generic-vmp"

DEFAULT_SIGNATURE_MARKERS: tuple[str, ...] = ()
GENERIC_VMP_DEFAULT_MARKERS: tuple[str, ...] = ()
VMP_FAMILY_WEIGHTS = {
    "dynamic_dispatch": 5,
    "byte_buffer": 3,
    "typed_array": 3,
    "int_bitwise": 3,
    "string_decode": 3,
    "string_transform": 3,
    "hash_crypto": 3,
    "anti_debug_timing": 2,
    "source_probe": 2,
    "stack_probe": 2,
}
DISPATCHER_FAMILIES = {"dynamic_dispatch"}
HANDLER_FAMILIES = {
    "int_bitwise",
    "string_transform",
    "string_decode",
    "array_table",
}
STATE_TABLE_FAMILIES = {
    "byte_buffer",
    "typed_array",
    "collection_table",
    "proxy_trap",
}
DECODER_FAMILIES = {"base64", "text_codec", "string_decode"}
CRYPTO_MIX_FAMILIES = {"hash_crypto", "int_bitwise", "random_source"}
ANTI_DEBUG_FAMILIES = {
    "anti_debug_timing",
    "source_probe",
    "stack_probe",
    "exception_probe",
}
NETWORK_APIS = {"fetch", "BrowserNetwork.request", "XMLHttpRequest.open"}
URL_ASSEMBLY_APIS = {
    "URLSearchParams.constructor",
    "URLSearchParams.set",
    "URLSearchParams.toString",
    "URLSearchParams.iterator.next",
    "URL.search.set",
    "URL.href.get",
    "Request.constructor",
}
FINGERPRINT_PREFIXES = (
    "Navigator.",
    "Screen.",
    "CanvasRenderingContext2D.",
    "WebGLRenderingContext.",
    "WebGL2RenderingContext.",
)
RUNTIME_SIGNAL_APIS = {
    "Date.now",
    "Performance.now",
    "Math.random",
    "Crypto.getRandomValues",
    "SubtleCrypto.digest",
    "SubtleCrypto.sign",
    "TextEncoder.encode",
    "TextDecoder.decode",
    "btoa",
    "atob",
    "encodeURI",
    "encodeURIComponent",
    "decodeURI",
    "decodeURIComponent",
    "JSON.stringify",
    "JSON.parse",
    "Reflect.apply",
    "Function.prototype.call",
    "Function.prototype.apply",
    "Promise.then",
    "Promise.resolve",
}
TIMELINE_ALWAYS_INCLUDE_PREFIXES = (
    "Array.",
    "Array.prototype.",
    "BigInt.",
    "DataView.",
    "Date.",
    "Function.",
    "JSON.",
    "Math.",
    "Navigator.",
    "Object.",
    "Promise.",
    "Reflect.",
    "RegExp.",
    "Screen.",
    "String.",
    "TextDecoder.",
    "TextEncoder.",
    "Uint8Array.",
    "URL.",
    "URLSearchParams.",
)
TIMELINE_ALWAYS_INCLUDE_APIS = {
    "fetch",
    "Request.constructor",
    "Request.headers.get",
    "Request.url.get",
    "Headers.constructor",
    "Headers.get",
    "Headers.set",
    "Headers.append",
    "Headers.iterator.next",
    "Crypto.getRandomValues",
    "SubtleCrypto.digest",
    "SubtleCrypto.sign",
}


def repair_ndjson_line(line: str) -> str:
    """Recover known XTrace serializer glitches (missing commas between fields)."""
    # Observed: "...:length:2""result":"$0"  and  "...\"undefined\"\"result\":..."
    repaired = re.sub(
        r'""(result|error|args|stack|frame_url|origin|truncated|global_seq|'
        r'result_length|result_ref|replace_ref|input_ref)":',
        r'","\1":',
        line,
    )
    return repaired


def load_events(path: Path, *, skip_bad_json: bool = False) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    bad_lines: list[tuple[int, str]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            event = None
            try:
                event = json.loads(stripped)
            except json.JSONDecodeError:
                repaired = repair_ndjson_line(stripped)
                try:
                    event = json.loads(repaired)
                except json.JSONDecodeError as exc:
                    if skip_bad_json:
                        bad_lines.append((line_number, str(exc)))
                        continue
                    raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if isinstance(event, dict):
                event.setdefault("_file_index", len(events))
                events.append(event)
    if bad_lines and skip_bad_json:
        # Keep going; callers can still produce a useful summary.
        print(
            f"warning: skipped {len(bad_lines)} invalid NDJSON line(s); "
            f"first at line {bad_lines[0][0]}: {bad_lines[0][1]}",
            file=sys.stderr,
        )
    return events


def sha1_ref(value: str) -> str:
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest().upper()
    return f"sha1:{digest}"


def manifest_path_for_trace(trace: Path) -> Path:
    return trace.parent / "assets" / trace.stem / "manifest.ndjson"


def load_asset_sources(trace: Path) -> dict[str, Any]:
    manifest_path = manifest_path_for_trace(trace)
    index: dict[str, Any] = {
        "manifest_path": str(manifest_path),
        "by_asset_id": {},
        "by_source_hash": {},
        "by_url": {},
    }
    if not manifest_path.exists():
        return index

    with manifest_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                manifest = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{manifest_path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(manifest, dict):
                continue

            source = manifest.get("source")
            content_path = manifest.get("content_path")
            if not isinstance(source, str) and isinstance(content_path, str) and content_path:
                content_file = trace.parent / content_path
                if content_file.exists():
                    source = content_file.read_text(encoding="utf-8")
            if not isinstance(source, str):
                continue

            source_hash = manifest.get("sha1")
            computed_hash = sha1_ref(source)
            record = {
                "asset_id": manifest.get("asset_id"),
                "source_hash": source_hash,
                "computed_source_hash": computed_hash,
                "source_unverified": bool(source_hash and source_hash != computed_hash),
                "url": manifest.get("url", ""),
                "kind": manifest.get("kind"),
                "size": manifest.get("size"),
                "content_path": content_path,
                "source": source,
            }
            asset_id = record.get("asset_id")
            if isinstance(asset_id, str) and asset_id:
                index["by_asset_id"][asset_id] = record
            if isinstance(source_hash, str) and source_hash:
                index["by_source_hash"][source_hash] = record
            url = record.get("url")
            if isinstance(url, str) and url and url not in index["by_url"]:
                index["by_url"][url] = record
    return index


def first_arg(event: dict[str, Any]) -> dict[str, Any]:
    args = event.get("args")
    if isinstance(args, list) and args and isinstance(args[0], dict):
        return args[0]
    return {}


def iter_string_fields(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], str]]:
    if isinstance(value, str):
        yield path, value
        return
    if isinstance(value, dict):
        for key, item in value.items():
            yield from iter_string_fields(item, path + (str(key),))
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_string_fields(item, path + (str(index),))


def contains_marker(value: str, markers: Iterable[str] = DEFAULT_SIGNATURE_MARKERS) -> bool:
    return any(marker in value for marker in markers)


def extract_urls(value: str) -> list[str]:
    if value.startswith(("http://", "https://")):
        return [value]
    return URL_RE.findall(value)


def as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def frame_url(frame: dict[str, Any]) -> str:
    value = frame.get("url") or frame.get("script") or ""
    return value if isinstance(value, str) else ""


def frame_record(frame: dict[str, Any]) -> dict[str, Any]:
    return {
        "function": frame.get("function", ""),
        "url": frame_url(frame),
        "line": frame.get("line"),
        "column": frame.get("column"),
    }


def utf16_offset_to_index(source: str, offset: int | None) -> int | None:
    if offset is None or offset < 0:
        return None
    code_units = 0
    for index, char in enumerate(source):
        if code_units >= offset:
            return index
        units = 2 if ord(char) > 0xFFFF else 1
        if code_units + units > offset:
            return index
        code_units += units
    return len(source)


def index_to_line_column(source: str, index: int) -> dict[str, int]:
    bounded = max(0, min(index, len(source)))
    line = source.count("\n", 0, bounded) + 1
    line_start = source.rfind("\n", 0, bounded) + 1
    return {"line": line, "column": bounded - line_start}


def line_column_to_index(source: str, line: Any, column: Any) -> int | None:
    line_number = as_int(line)
    column_number = as_int(column)
    if line_number is None or column_number is None or line_number <= 0 or column_number < 0:
        return None
    current_line = 1
    index = 0
    while current_line < line_number:
        next_newline = source.find("\n", index)
        if next_newline < 0:
            return None
        index = next_newline + 1
        current_line += 1
    return min(index + column_number, len(source))


def source_snippet(
    source: str,
    index: int | None,
    *,
    before: int = DEFAULT_SNIPPET_BEFORE_CHARS,
    after: int = DEFAULT_SNIPPET_AFTER_CHARS,
) -> dict[str, Any]:
    if index is None:
        return {"snippet": "", "snippet_start": None, "snippet_end": None}
    bounded = max(0, min(index, len(source)))
    start = max(0, bounded - before)
    end = min(len(source), bounded + after)
    return {
        "snippet": source[start:end],
        "snippet_start": start,
        "snippet_end": end,
    }


ScriptRegistryKey = int | tuple[str | None, int | None, int]
ScriptRegistry = dict[ScriptRegistryKey, dict[str, Any]]


def build_script_registry(events: list[dict[str, Any]]) -> ScriptRegistry:
    registry: ScriptRegistry = {}
    for event in events:
        arg = first_arg(event)
        script_id = as_int(arg.get("script_id"))
        if script_id is None:
            script_id = as_int(event.get("script_id"))
        if script_id is None or script_id <= 0:
            continue

        session_id_value = event.get("session_id")
        session_id = session_id_value if isinstance(session_id_value, str) else None
        isolate_id = as_int(arg.get("isolate_id"))
        if isolate_id is None:
            isolate_id = as_int(event.get("isolate_id"))
        scoped_key = (session_id, isolate_id, script_id)

        script_url = (
            arg.get("script_url")
            or event.get("script_url")
            or arg.get("url")
            or event.get("url")
            or ""
        )
        record = registry.get(scoped_key)
        if record is None:
            record = {
                "session_id": session_id,
                "isolate_id": isolate_id,
                "script_id": script_id,
            }
            registry[scoped_key] = record
            registry.setdefault(script_id, record)
        existing = record.copy()
        record.update({
            "session_id": session_id,
            "isolate_id": isolate_id,
            "script_id": script_id,
            "script_url": script_url or existing.get("script_url", ""),
            "asset_id": event.get("asset_id") or arg.get("asset_id") or existing.get("asset_id"),
            "source_hash": event.get("source_hash") or arg.get("source_hash") or existing.get("source_hash"),
            "source_length": arg.get("source_length") or existing.get("source_length"),
            "seq": event.get("seq") if existing.get("seq") is None else existing.get("seq"),
        })
        if not (record["script_url"] or record["asset_id"] or record["source_hash"]):
            registry.pop(scoped_key, None)
            if registry.get(script_id) is record:
                registry.pop(script_id, None)
    return registry


def script_registry_count(registry: ScriptRegistry) -> int:
    return sum(1 for key in registry if isinstance(key, tuple))


def script_registry_record(
    registry: ScriptRegistry | None,
    event: dict[str, Any],
    script_id: int | None,
    isolate_id: int | None,
) -> dict[str, Any]:
    if not registry or script_id is None:
        return {}
    session_value = event.get("session_id")
    session_id = session_value if isinstance(session_value, str) else None
    for key in (
        (session_id, isolate_id, script_id),
        (session_id, None, script_id),
        (None, isolate_id, script_id),
        (None, None, script_id),
        script_id,
    ):
        record = registry.get(key)
        if record:
            return record
    return {}


def resolve_dispatch_callsite(
    event: dict[str, Any],
    script_registry: ScriptRegistry | None = None,
) -> dict[str, Any]:
    arg = first_arg(event)
    if arg.get("callsite_mode") != "dispatch_light":
        return {}
    script_id = as_int(arg.get("callsite_script_id"))
    source_position = as_int(arg.get("callsite_source_position"))
    code_offset = as_int(arg.get("callsite_code_offset"))
    function_start_position = as_int(arg.get("callsite_function_start_position"))
    isolate_id = as_int(arg.get("isolate_id"))
    script_record = script_registry_record(
        script_registry, event, script_id, isolate_id
    )
    asset_id = script_record.get("asset_id")
    script_url = script_record.get("script_url")
    source_locator = script_url or (f"xtrace-asset:{asset_id}" if asset_id else None)
    return {
        "resolved": bool(script_url or asset_id or script_record.get("source_hash")),
        "isolate_id": isolate_id,
        "script_id": script_id,
        "url": script_url,
        "source_locator": source_locator,
        "asset_id": asset_id,
        "source_hash": script_record.get("source_hash"),
        "source_position": source_position,
        "code_offset": code_offset,
        "function_start_position": function_start_position,
    }


def stack_top(
    event: dict[str, Any],
    script_registry: ScriptRegistry | None = None,
) -> dict[str, Any]:
    stack = event.get("stack")
    if isinstance(stack, list):
        for frame in stack:
            if isinstance(frame, dict) and frame_url(frame):
                return frame_record(frame)
    arg = first_arg(event)
    vmp_stack = arg.get("js_stack")
    if isinstance(vmp_stack, list):
        for frame in vmp_stack:
            if isinstance(frame, dict) and frame_url(frame):
                return frame_record(frame)
    resolved = resolve_dispatch_callsite(event, script_registry)
    if resolved.get("resolved"):
        return {
            "function": arg.get("callsite_function") or arg.get("target_function") or "",
            "url": resolved.get("source_locator") or resolved.get("url") or "",
            "line": None,
            "column": None,
            "isolate_id": resolved.get("isolate_id"),
            "script_id": resolved.get("script_id"),
            "asset_id": resolved.get("asset_id"),
            "source_hash": resolved.get("source_hash"),
            "source_position": resolved.get("source_position"),
            "function_start_position": resolved.get("function_start_position"),
        }
    callsite_script = arg.get("callsite_script")
    if callsite_script:
        return {
            "function": arg.get("callsite_function", ""),
            "url": callsite_script,
            "line": arg.get("callsite_line"),
            "column": arg.get("callsite_column"),
        }
    return {}


def asset_source_for_resolved(
    resolved: dict[str, Any],
    asset_sources: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not asset_sources:
        return None
    asset_id = resolved.get("asset_id")
    if isinstance(asset_id, str) and asset_id:
        record = asset_sources.get("by_asset_id", {}).get(asset_id)
        if record:
            return record
    source_hash = resolved.get("source_hash")
    if isinstance(source_hash, str) and source_hash:
        record = asset_sources.get("by_source_hash", {}).get(source_hash)
        if record:
            return record
    url = resolved.get("url")
    if isinstance(url, str) and url:
        record = asset_sources.get("by_url", {}).get(url)
        if record:
            if asset_id or source_hash:
                return record | {"source_unverified": True}
            return record
    return None


def asset_source_for_stack(
    stack: dict[str, Any],
    asset_sources: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not asset_sources:
        return None
    url = stack.get("url")
    if isinstance(url, str) and url:
        return asset_sources.get("by_url", {}).get(url)
    return None


def candidate_role(url: str) -> str:
    lowered = url.lower()
    if any(
        term in lowered
        for term in (
            "signature",
            "security",
            "risk",
            "fingerprint",
            "sensor",
            "challenge",
            "captcha",
            "waf",
            "sdk",
            "vmp",
            "vm",
        )
    ):
        return "security_runtime_candidate"
    if "/sw/" in lowered or "workbox" in lowered or "cdn-sw" in lowered:
        return "request_transport_candidate"
    return "supporting_runtime_candidate"


def vmp_family_for_api(api: Any) -> str | None:
    return VMP_API_FAMILY.get(str(api))


def vmp_family_weight(family: str | None) -> int:
    if not family:
        return 0
    return VMP_FAMILY_WEIGHTS.get(family, 1)


def generic_candidate_role(family_counts: Counter[str]) -> str:
    family_set = {family for family, count in family_counts.items() if count > 0}
    if family_set & DISPATCHER_FAMILIES:
        return "dispatcher_candidate"
    if family_set & ANTI_DEBUG_FAMILIES:
        return "anti_debug_candidate"
    if family_set & STATE_TABLE_FAMILIES:
        return "state_table_candidate"
    if "hash_crypto" in family_set or {"random_source", "int_bitwise"} <= family_set:
        return "crypto_mix_candidate"
    if family_set & {"base64", "text_codec"} or (
        "string_decode" in family_set
        and not family_set & {"int_bitwise", "string_transform", "array_table"}
    ):
        return "decoder_candidate"
    if family_set & HANDLER_FAMILIES:
        return "handler_candidate"
    return "supporting_runtime_candidate"


def profile_marker_params(
    profile: str,
    marker_params: Iterable[str] | None,
) -> tuple[str, ...]:
    if marker_params is not None:
        return tuple(marker for marker in marker_params if marker)
    if profile == PROFILE_SIGNATURE:
        return DEFAULT_SIGNATURE_MARKERS
    return GENERIC_VMP_DEFAULT_MARKERS


def candidate_key(record: dict[str, Any]) -> tuple[Any, ...]:
    if record.get("function_start_position") is not None:
        return (
            record.get("url"),
            record.get("source_hash"),
            record.get("function_start_position"),
        )
    return (
        record.get("url"),
        record.get("source_hash"),
        record.get("function"),
        record.get("source_position"),
    )


def source_location_for_resolved(
    resolved: dict[str, Any],
    source_record: dict[str, Any],
) -> dict[str, Any] | None:
    source = source_record.get("source")
    if not isinstance(source, str):
        return None
    source_position = as_int(resolved.get("source_position"))
    function_start_position = as_int(resolved.get("function_start_position"))
    anchor_position = source_position
    if (anchor_position is None or anchor_position == 0) and function_start_position:
        anchor_position = function_start_position
    index = utf16_offset_to_index(source, anchor_position)
    if index is None:
        return None
    line_column = index_to_line_column(source, index)
    return {
        "line": line_column["line"],
        "column": line_column["column"],
        "source_position": source_position,
        "function_start_position": function_start_position,
        "code_offset": as_int(resolved.get("code_offset")),
        "source_index": index,
    }


def source_location_for_stack(
    stack: dict[str, Any],
    source_record: dict[str, Any],
) -> dict[str, Any] | None:
    source = source_record.get("source")
    if not isinstance(source, str):
        return None
    index = line_column_to_index(source, stack.get("line"), stack.get("column"))
    if index is None:
        return None
    source_position = index
    line_column = index_to_line_column(source, index)
    return {
        "line": line_column["line"],
        "column": line_column["column"],
        "source_position": source_position,
        "function_start_position": None,
        "code_offset": None,
        "source_index": index,
    }


def candidate_base(
    *,
    url: str,
    asset_id: Any,
    source_hash: Any,
    function: str,
    location: dict[str, Any],
    source_record: dict[str, Any],
) -> dict[str, Any]:
    return {
        "url": url,
        "asset_id": asset_id,
        "source_hash": source_hash,
        "function": function,
        "function_start_position": location.get("function_start_position"),
        "source_position": location.get("source_position"),
        "code_offset": location.get("code_offset"),
        "line": location.get("line"),
        "column": location.get("column"),
        "source_unverified": bool(source_record.get("source_unverified")),
        "role": candidate_role(url),
        "apis": Counter(),
        "families": Counter(),
        "vmp_score": 0,
        "event_count": 0,
        "marker_count": 0,
        "proximity_hits": 0,
        "first_seq": None,
        "last_seq": None,
        "_source_index": location.get("source_index"),
        "_source": source_record.get("source", ""),
    }


def update_candidate(
    candidates: dict[tuple[Any, ...], dict[str, Any]],
    record: dict[str, Any],
    event: dict[str, Any],
    focus_time_us: float,
    marker_params: Iterable[str] = DEFAULT_SIGNATURE_MARKERS,
) -> None:
    key = candidate_key(record)
    candidate = candidates.get(key)
    if not candidate:
        candidate = record
        candidates[key] = candidate

    api = str(event.get("api", ""))
    family = vmp_family_for_api(api)
    candidate["apis"][api] += 1
    if family:
        candidate["families"][family] += 1
        candidate["vmp_score"] += vmp_family_weight(family)
    candidate["event_count"] += 1
    if event_contains_marker(event, marker_params):
        candidate["marker_count"] += 1
    if focus_time_us - event_time_us(event) <= PROXIMITY_WINDOW_US:
        candidate["proximity_hits"] += 1
    seq = event.get("seq")
    if candidate["first_seq"] is None or (
        isinstance(seq, (int, float)) and seq < candidate["first_seq"]
    ):
        candidate["first_seq"] = seq
    if candidate["last_seq"] is None or (
        isinstance(seq, (int, float)) and seq > candidate["last_seq"]
    ):
        candidate["last_seq"] = seq


def finalize_candidate(candidate: dict[str, Any], *, profile: str = PROFILE_SIGNATURE) -> dict[str, Any]:
    public = {
        key: value
        for key, value in candidate.items()
        if not key.startswith("_") and key not in {"apis", "families"}
    }
    if profile == PROFILE_GENERIC_VMP:
        public["role"] = generic_candidate_role(candidate["families"])
    public["apis"] = [
        {"api": api, "count": count}
        for api, count in candidate["apis"].most_common(12)
    ]
    public["families"] = [
        {"family": family, "count": count}
        for family, count in candidate["families"].most_common(12)
    ]
    if profile == PROFILE_GENERIC_VMP:
        public["score"] = (
            candidate["vmp_score"] * 10
            + candidate["proximity_hits"] * 5
            + candidate["event_count"]
        )
    else:
        public["score"] = (
            candidate["marker_count"] * 100
            + candidate["proximity_hits"] * 10
            + candidate["event_count"]
        )
    return public


def snippet_record(candidate: dict[str, Any], *, profile: str = PROFILE_SIGNATURE) -> dict[str, Any]:
    snippet = source_snippet(candidate.get("_source", ""), candidate.get("_source_index"))
    public = finalize_candidate(candidate, profile=profile)
    public.update(snippet)
    return public


def build_source_analysis(
    events: list[dict[str, Any]],
    focus_event: dict[str, Any] | None,
    *,
    window_us: int,
    script_registry: ScriptRegistry,
    asset_sources: dict[str, Any] | None,
    max_snippets: int,
    marker_params: Iterable[str] = DEFAULT_SIGNATURE_MARKERS,
    profile: str = PROFILE_SIGNATURE,
) -> dict[str, Any]:
    if not focus_event or not asset_sources:
        return {
            "candidate_functions": [],
            "request_transport_candidates": [],
            "source_snippets": [],
        }

    focus_time = record_time_us(focus_event)
    if focus_time <= 0:
        return {
            "candidate_functions": [],
            "request_transport_candidates": [],
            "source_snippets": [],
        }
    focus_session = focus_event.get("session_id")
    window_start = focus_time - window_us
    candidates: dict[tuple[Any, ...], dict[str, Any]] = {}

    for event in events:
        order = event_time_us(event)
        if order > focus_time or order < window_start:
            continue
        if focus_session and event.get("session_id") != focus_session:
            continue

        arg = first_arg(event)
        resolved = resolve_dispatch_callsite(event, script_registry)
        source_record = asset_source_for_resolved(resolved, asset_sources)
        if source_record:
            location = source_location_for_resolved(resolved, source_record)
            if location:
                url = str(
                    resolved.get("url")
                    or source_record.get("url")
                    or resolved.get("source_locator")
                    or ""
                )
                record = candidate_base(
                    url=url,
                    asset_id=resolved.get("asset_id") or source_record.get("asset_id"),
                    source_hash=resolved.get("source_hash") or source_record.get("source_hash"),
                    function=arg.get("callsite_function") or arg.get("target_function") or "",
                    location=location,
                    source_record=source_record,
                )
                update_candidate(candidates, record, event, focus_time, marker_params)

        stack = stack_top(event, script_registry)
        source_record = asset_source_for_stack(stack, asset_sources)
        if source_record:
            location = source_location_for_stack(stack, source_record)
            if location:
                url = str(stack.get("url") or source_record.get("url") or "")
                record = candidate_base(
                    url=url,
                    asset_id=source_record.get("asset_id"),
                    source_hash=source_record.get("source_hash"),
                    function=str(stack.get("function", "")),
                    location=location,
                    source_record=source_record,
                )
                update_candidate(candidates, record, event, focus_time, marker_params)

    if profile == PROFILE_GENERIC_VMP:
        sort_key = lambda item: (
            item["vmp_score"],
            item["proximity_hits"],
            item["event_count"],
        )
    else:
        sort_key = lambda item: (
            item["marker_count"] * 100 + item["proximity_hits"] * 10 + item["event_count"],
            item["event_count"],
        )
    ranked = sorted(
        candidates.values(),
        key=sort_key,
        reverse=True,
    )
    public_candidates = [
        finalize_candidate(candidate, profile=profile) for candidate in ranked[:30]
    ]
    transport = [
        finalize_candidate(candidate, profile=profile) for candidate in ranked
        if candidate.get("role") == "request_transport_candidate"
    ]
    snippets = [
        snippet_record(candidate, profile=profile) for candidate in ranked[:max_snippets]
    ]
    return {
        "candidate_functions": public_candidates,
        "request_transport_candidates": transport[:20],
        "source_snippets": snippets,
    }


def event_order(event: dict[str, Any]) -> float:
    for key in ("_file_index", "file_index", "global_seq", "mono_time_us", "wall_time_us", "ts", "seq"):
        value = event.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    return 0.0


def record_order(record: dict[str, Any]) -> float:
    for key in ("_file_index", "file_index", "global_seq", "mono_time_us", "wall_time_us", "ts", "seq"):
        value = record.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    return 0.0


def event_time_us(event: dict[str, Any]) -> float:
    for key in ("mono_time_us", "wall_time_us", "ts"):
        value = event.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    return event_order(event)


def record_time_us(record: dict[str, Any]) -> float:
    for key in ("mono_time_us", "wall_time_us", "ts"):
        value = record.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    return record_order(record)


def event_order_fields(event: dict[str, Any]) -> dict[str, Any]:
    return {
        key: event[key]
        for key in ("_file_index", "file_index", "global_seq", "session_seq", "mono_time_us", "wall_time_us", "ts")
        if key in event
    }


def is_source_field(field_path: tuple[str, ...]) -> bool:
    return any(part in {"source", "source_hash", "asset_id"} for part in field_path)


def query_from_url(url: str) -> dict[str, list[str]]:
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def signed_url_record(
    event: dict[str, Any],
    field_path: tuple[str, ...],
    url: str,
    script_registry: ScriptRegistry | None = None,
    marker_params: Iterable[str] = DEFAULT_SIGNATURE_MARKERS,
) -> dict[str, Any] | None:
    query = query_from_url(url)
    markers = tuple(marker_params)
    if not markers:
        return None
    target_params = [marker for marker in markers if marker in query]
    if not target_params:
        return None
    parsed = urlparse(url)
    target_value_lengths = {
        param: len(query.get(param, [""])[0]) if query.get(param) else 0
        for param in target_params
    }
    return {
        **event_order_fields(event),
        "seq": event.get("seq"),
        "session_id": event.get("session_id"),
        "api": event.get("api"),
        "phase": event.get("phase"),
        "field": ".".join(field_path),
        "scheme": parsed.scheme,
        "host": parsed.netloc,
        "path": parsed.path,
        "query_keys": sorted(query.keys()),
        "target_params": target_params,
        "primary_target_param": target_params[0],
        "primary_target_value_length": target_value_lengths[target_params[0]],
        "target_value_lengths": target_value_lengths,
        "has_supporting_token": any("token" in key.lower() for key in query.keys()),
        "stack_top": stack_top(event, script_registry),
    }


def is_runtime_signal_api(api: str) -> bool:
    return api in RUNTIME_SIGNAL_APIS or any(api.startswith(prefix) for prefix in FINGERPRINT_PREFIXES)


def is_timeline_key_api(api: str) -> bool:
    return (
        api in TIMELINE_ALWAYS_INCLUDE_APIS
        or is_runtime_signal_api(api)
        or any(api.startswith(prefix) for prefix in TIMELINE_ALWAYS_INCLUDE_PREFIXES)
    )


def event_contains_marker(
    event: dict[str, Any],
    markers: Iterable[str] = DEFAULT_SIGNATURE_MARKERS,
) -> bool:
    for field_path, value in iter_string_fields(event.get("args", []), ("args",)):
        if is_source_field(field_path):
            continue
        if contains_marker(value, markers):
            return True
    return False


def event_signed_url_records(
    event: dict[str, Any],
    script_registry: ScriptRegistry | None = None,
    marker_params: Iterable[str] = DEFAULT_SIGNATURE_MARKERS,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for field_path, value in iter_string_fields(event.get("args", []), ("args",)):
        if is_source_field(field_path):
            continue
        for url in extract_urls(value):
            record = signed_url_record(event, field_path, url, script_registry, marker_params)
            if record is not None:
                records.append(record)
    return records


def event_value_shape(
    event: dict[str, Any],
    marker_params: Iterable[str] = DEFAULT_SIGNATURE_MARKERS,
) -> dict[str, Any]:
    fields: list[str] = []
    string_lengths: list[int] = []
    url_records: list[dict[str, Any]] = []
    for field_path, value in iter_string_fields(event.get("args", []), ("args",)):
        if is_source_field(field_path):
            continue
        field = ".".join(field_path)
        fields.append(field)
        string_lengths.append(len(value))
        for url in extract_urls(value):
            record = signed_url_record(event, field_path, url, marker_params=marker_params)
            if record is not None:
                url_records.append({
                    "host": record["host"],
                    "path": record["path"],
                    "query_keys": record["query_keys"],
                    "target_params": record["target_params"],
                    "primary_target_param": record["primary_target_param"],
                    "primary_target_value_length": record["primary_target_value_length"],
                    "has_supporting_token": record["has_supporting_token"],
                })

    arg = first_arg(event)
    material_refs = sorted(
        key for key, value in arg.items()
        if key.endswith("_ref") and value not in (None, "", "<redacted>")
    )
    return {
        "string_field_count": len(fields),
        "string_fields": fields[:12],
        "string_lengths": string_lengths[:12],
        "material_ref_fields": material_refs[:12],
        "signed_urls": url_records[:4],
    }


def timeline_event_record(
    event: dict[str, Any],
    focus_time_us: float,
    script_registry: ScriptRegistry | None = None,
    marker_params: Iterable[str] = DEFAULT_SIGNATURE_MARKERS,
) -> dict[str, Any]:
    order = event_time_us(event)
    api = str(event.get("api", ""))
    family = vmp_family_for_api(api)
    markers = tuple(marker_params)
    has_marker = event_contains_marker(event, markers) if markers else False
    record = {
        **event_order_fields(event),
        "seq": event.get("seq"),
        "session_id": event.get("session_id"),
        "delta_us": int(order - focus_time_us),
        "api": event.get("api"),
        "vmp_family": family,
        "phase": event.get("phase"),
        "category": event.get("category"),
        "has_marker": has_marker,
        "has_target_marker": has_marker,
        "stack_top": stack_top(event, script_registry),
    }
    resolved_callsite = resolve_dispatch_callsite(event, script_registry)
    if resolved_callsite:
        record["resolved_callsite"] = resolved_callsite
    record.update(event_value_shape(event, markers))
    return record


def build_pre_materialization_timeline(
    events: list[dict[str, Any]],
    first_assembly: dict[str, Any] | None,
    *,
    window_us: int,
    max_events: int,
    script_registry: ScriptRegistry | None = None,
    marker_params: Iterable[str] = DEFAULT_SIGNATURE_MARKERS,
) -> dict[str, Any] | None:
    if not first_assembly:
        return None

    focus_time = record_time_us(first_assembly)
    if focus_time <= 0:
        return None
    focus_session = first_assembly.get("session_id")
    window_start = focus_time - window_us
    window_events = [
        event for event in events
        if event_time_us(event) <= focus_time
        and event_time_us(event) >= window_start
        and (not focus_session or event.get("session_id") == focus_session)
    ]
    api_counts = Counter(str(event.get("api", "")) for event in window_events)
    stack_counts = Counter()
    marker_events: list[dict[str, Any]] = []
    key_events: list[dict[str, Any]] = []

    for event in window_events:
        stack = stack_top(event, script_registry)
        if stack:
            stack_counts[(stack.get("url", ""), stack.get("function", ""))] += 1
        api = str(event.get("api", ""))
        has_marker = event_contains_marker(event, marker_params) if marker_params else False
        if has_marker:
            marker_events.append(
                timeline_event_record(event, focus_time, script_registry, marker_params)
            )
        if has_marker or is_timeline_key_api(api):
            key_events.append(
                timeline_event_record(event, focus_time, script_registry, marker_params)
            )

    return {
        "focus_event": first_assembly,
        "window_us": window_us,
        "event_count": len(window_events),
        "api_counts": [
            {"api": api, "count": count}
            for api, count in api_counts.most_common(50)
        ],
        "stack_counts": [
            {"url": url, "function": function, "count": count}
            for (url, function), count in stack_counts.most_common(30)
        ],
        "marker_events": marker_events[:max_events],
        "last_key_events": key_events[-max_events:],
    }


def is_vmp_event(event: dict[str, Any]) -> bool:
    return vmp_family_for_api(event.get("api")) is not None


def vmp_event_weight(event: dict[str, Any]) -> int:
    return vmp_family_weight(vmp_family_for_api(event.get("api")))


def count_vmp_families(events: list[dict[str, Any]]) -> tuple[Counter[str], Counter[str], Counter[str]]:
    family_counts: Counter[str] = Counter()
    family_evidence_counts: Counter[str] = Counter()
    api_counts: Counter[str] = Counter()
    for event in events:
        api = str(event.get("api", ""))
        family = vmp_family_for_api(api)
        if not family:
            continue
        family_counts[family] += 1
        api_counts[api] += 1
        if event_has_vmp_family_evidence(event):
            family_evidence_counts[family] += 1
    return family_counts, family_evidence_counts, api_counts


def counter_records(counter: Counter[str], key_name: str, limit: int | None = None) -> list[dict[str, Any]]:
    records = [
        {key_name: key, "count": count}
        for key, count in counter.most_common(limit)
    ]
    return records


def select_vmp_focus(
    events: list[dict[str, Any]],
    *,
    window_us: int,
) -> dict[str, Any] | None:
    weighted_by_session: dict[str, list[tuple[float, float, dict[str, Any], int]]] = {}
    for index, event in enumerate(events):
        weight = vmp_event_weight(event)
        if weight <= 0:
            continue
        session_id = str(event.get("session_id") or f"missing-session:{index}")
        weighted_by_session.setdefault(session_id, []).append(
            (event_time_us(event), event_order(event), event, weight)
        )

    best_focus: dict[str, Any] | None = None
    best_rank: tuple[int, int, float] | None = None
    for session_id, weighted in weighted_by_session.items():
        focus = select_vmp_focus_for_weighted_session(
            weighted,
            window_us=window_us,
            session_id=session_id,
        )
        if not focus:
            continue
        rank = (
            int(focus["window_score"]),
            int(focus["window_vmp_event_count"]),
            -event_order(focus["event"]),
        )
        if best_rank is None or rank > best_rank:
            best_focus = focus
            best_rank = rank
    return best_focus


def select_vmp_focus_for_weighted_session(
    weighted: list[tuple[float, float, dict[str, Any], int]],
    *,
    window_us: int,
    session_id: str,
) -> dict[str, Any] | None:
    if not weighted:
        return None

    weighted.sort(key=lambda item: (item[0], item[1]))
    best_left = 0
    best_right = 0
    best_score = -1
    best_count = 0
    left = 0
    score = 0
    for right, (order, _, _, weight) in enumerate(weighted):
        score += weight
        while left <= right and order - weighted[left][0] > window_us:
            score -= weighted[left][3]
            left += 1
        count = right - left + 1
        if (score, count) > (best_score, best_count):
            best_score = score
            best_count = count
            best_left = left
            best_right = right

    focus_order, _, focus_event, _ = weighted[best_right]
    return {
        "event": focus_event,
        "window_score": best_score,
        "window_vmp_event_count": best_count,
        "window_session_id": session_id,
        "window_start_us": int(weighted[best_left][0]),
        "window_end_us": int(focus_order),
    }


def events_in_window(
    events: list[dict[str, Any]],
    focus_event: dict[str, Any],
    *,
    window_us: int,
) -> list[dict[str, Any]]:
    focus_time = record_time_us(focus_event)
    if focus_time <= 0:
        return []
    focus_session = focus_event.get("session_id")
    window_start = focus_time - window_us
    return [
        event for event in events
        if event_time_us(event) <= focus_time
        and event_time_us(event) >= window_start
        and (not focus_session or event.get("session_id") == focus_session)
    ]


def build_vmp_timeline(
    events: list[dict[str, Any]],
    focus_event: dict[str, Any] | None,
    *,
    window_us: int,
    max_events: int,
    script_registry: ScriptRegistry | None = None,
    marker_params: Iterable[str] = GENERIC_VMP_DEFAULT_MARKERS,
) -> dict[str, Any] | None:
    if not focus_event:
        return None
    focus_time = record_time_us(focus_event)
    if focus_time <= 0:
        return None

    window_events = events_in_window(events, focus_event, window_us=window_us)
    vmp_events = [event for event in window_events if is_vmp_event(event)]
    family_counts, _, api_counts = count_vmp_families(vmp_events)
    stack_counts = Counter()
    marker_events: list[dict[str, Any]] = []
    last_vmp_events: list[dict[str, Any]] = []

    for event in window_events:
        if marker_params and event_contains_marker(event, marker_params):
            marker_events.append(
                timeline_event_record(event, focus_time, script_registry, marker_params)
            )
        if not is_vmp_event(event):
            continue
        stack = stack_top(event, script_registry)
        if stack:
            stack_counts[(stack.get("url", ""), stack.get("function", ""))] += 1
        last_vmp_events.append(
            timeline_event_record(event, focus_time, script_registry, marker_params)
        )

    return {
        "focus_event": timeline_event_record(
            focus_event,
            focus_time,
            script_registry,
            marker_params,
        ),
        "window_us": window_us,
        "event_count": len(window_events),
        "vmp_event_count": len(vmp_events),
        "api_counts": counter_records(api_counts, "api", 50),
        "family_counts": counter_records(family_counts, "family", 50),
        "stack_counts": [
            {"url": url, "function": function, "count": count}
            for (url, function), count in stack_counts.most_common(30)
        ],
        "marker_events": marker_events[:max_events],
        "last_vmp_events": last_vmp_events[-max_events:],
    }


def build_vmp_hotspots(
    events: list[dict[str, Any]],
    focus_event: dict[str, Any] | None,
    *,
    window_us: int,
    script_registry: ScriptRegistry | None = None,
    limit: int = 30,
) -> list[dict[str, Any]]:
    if not focus_event:
        return []
    hotspots: dict[tuple[Any, ...], dict[str, Any]] = {}
    for event in events_in_window(events, focus_event, window_us=window_us):
        api = str(event.get("api", ""))
        family = vmp_family_for_api(api)
        if not family:
            continue
        stack = stack_top(event, script_registry)
        key = (
            stack.get("url", ""),
            stack.get("function", ""),
            stack.get("line"),
            stack.get("column"),
        )
        hotspot = hotspots.setdefault(
            key,
            {
                "url": stack.get("url", ""),
                "function": stack.get("function", ""),
                "line": stack.get("line"),
                "column": stack.get("column"),
                "apis": Counter(),
                "families": Counter(),
                "event_count": 0,
                "vmp_score": 0,
                "first_seq": None,
                "last_seq": None,
            },
        )
        hotspot["apis"][api] += 1
        hotspot["families"][family] += 1
        hotspot["event_count"] += 1
        hotspot["vmp_score"] += vmp_family_weight(family)
        seq = event.get("seq")
        if hotspot["first_seq"] is None or (
            isinstance(seq, (int, float)) and seq < hotspot["first_seq"]
        ):
            hotspot["first_seq"] = seq
        if hotspot["last_seq"] is None or (
            isinstance(seq, (int, float)) and seq > hotspot["last_seq"]
        ):
            hotspot["last_seq"] = seq

    records: list[dict[str, Any]] = []
    for hotspot in hotspots.values():
        records.append({
            "role": generic_candidate_role(hotspot["families"]),
            "score": hotspot["vmp_score"] * 10 + hotspot["event_count"],
            "event_count": hotspot["event_count"],
            "first_seq": hotspot["first_seq"],
            "last_seq": hotspot["last_seq"],
            "url": hotspot["url"],
            "function": hotspot["function"],
            "line": hotspot["line"],
            "column": hotspot["column"],
            "apis": counter_records(hotspot["apis"], "api", 12),
            "families": counter_records(hotspot["families"], "family", 12),
        })
    records.sort(key=lambda item: (item["score"], item["event_count"]), reverse=True)
    return records[:limit]


def first_marker_event(
    events: list[dict[str, Any]],
    marker_params: Iterable[str],
) -> dict[str, Any] | None:
    markers = tuple(marker_params)
    if not markers:
        return None
    matches = [event for event in events if event_contains_marker(event, markers)]
    return min(matches, key=event_order) if matches else None


def summarize(
    events: list[dict[str, Any]],
    *,
    profile: str = PROFILE_GENERIC_VMP,
    marker_params: Iterable[str] | None = None,
    timeline_window_us: int = 15_000_000,
    max_timeline_events: int = 80,
    asset_sources: dict[str, Any] | None = None,
    max_source_snippets: int = 80,
) -> dict[str, Any]:
    markers = profile_marker_params(profile, marker_params)
    api_counts = Counter(str(event.get("api", "")) for event in events)
    script_registry = build_script_registry(events)
    marker_occurrences: list[dict[str, Any]] = []
    signed_urls: list[dict[str, Any]] = []
    network_signed_urls: list[dict[str, Any]] = []
    assembly_events: list[dict[str, Any]] = []
    marker_api_counts = Counter()
    runtime_signal_counts = Counter()
    dispatch_light_resolved_count = 0
    dispatch_light_unresolved_count = 0

    for event in events:
        api = str(event.get("api", ""))
        resolved_callsite = resolve_dispatch_callsite(event, script_registry)
        if resolved_callsite:
            if resolved_callsite.get("resolved"):
                dispatch_light_resolved_count += 1
            else:
                dispatch_light_unresolved_count += 1
        if is_runtime_signal_api(api):
            runtime_signal_counts[api] += 1

        event_has_marker = False
        for field_path, value in iter_string_fields(event.get("args", []), ("args",)):
            if is_source_field(field_path):
                continue
            if markers and contains_marker(value, markers):
                event_has_marker = True
                marker_api_counts[api] += 1
                marker_occurrences.append({
                    **event_order_fields(event),
                    "seq": event.get("seq"),
                    "session_id": event.get("session_id"),
                    "api": api,
                    "phase": event.get("phase"),
                    "field": ".".join(field_path),
                    "stack_top": stack_top(event, script_registry),
                })
            for url in extract_urls(value):
                record = signed_url_record(event, field_path, url, script_registry, markers)
                if record is not None:
                    signed_urls.append(record)
                    if api in NETWORK_APIS:
                        network_signed_urls.append(record)

        if event_has_marker and api in URL_ASSEMBLY_APIS:
            arg = first_arg(event)
            assembly_events.append({
                **event_order_fields(event),
                "seq": event.get("seq"),
                "session_id": event.get("session_id"),
                "api": api,
                "phase": event.get("phase"),
                "name": arg.get("name"),
                "has_value": arg.get("value") not in (None, ""),
                "has_material_ref": any(
                    key.endswith("_ref") and arg.get(key)
                    for key in arg.keys()
                ),
                "stack_top": stack_top(event, script_registry),
            })

    first_signed_url = min(signed_urls, key=record_order) if signed_urls else None
    first_network_signed_url = (
        min(network_signed_urls, key=record_order)
        if network_signed_urls
        else None
    )
    first_assembly = (
        min(assembly_events, key=record_order)
        if assembly_events
        else None
    )
    vmp_family_counts, vmp_family_evidence_counts, vmp_api_counts = count_vmp_families(events)
    vmp_focus = (
        select_vmp_focus(events, window_us=timeline_window_us)
        if profile == PROFILE_GENERIC_VMP
        else None
    )
    vmp_focus_event = vmp_focus.get("event") if vmp_focus else None
    focus_window_family_counts = Counter()
    if profile == PROFILE_GENERIC_VMP and vmp_focus_event:
        focus_window_family_counts, _, _ = count_vmp_families([
            event for event in events_in_window(
                events,
                vmp_focus_event,
                window_us=timeline_window_us,
            )
            if is_vmp_event(event)
        ])
    source_focus_event = vmp_focus_event if profile == PROFILE_GENERIC_VMP else first_assembly
    source_analysis = build_source_analysis(
        events,
        source_focus_event,
        window_us=timeline_window_us,
        script_registry=script_registry,
        asset_sources=asset_sources,
        max_snippets=max_source_snippets,
        marker_params=markers,
        profile=profile,
    )

    observed_runtime_signals = [
        {"api": api, "count": count}
        for api, count in runtime_signal_counts.most_common()
    ]
    observed_materialization_apis = [
        {"api": api, "count": marker_api_counts[api]}
        for api in sorted(URL_ASSEMBLY_APIS | NETWORK_APIS)
        if marker_api_counts[api]
    ]

    conclusions: list[str] = []
    if first_assembly and first_network_signed_url:
        if record_order(first_assembly) <= record_order(first_network_signed_url):
            conclusions.append(
                "A target signature parameter was materialized in renderer-side URL/request assembly before the network request boundary."
            )
    if network_signed_urls:
        conclusions.append(
            "The signed URL reached the browser network layer with a target signature parameter already present."
        )
    if any(item["api"] in {"Reflect.apply", "Function.prototype.call", "Function.prototype.apply"} for item in observed_runtime_signals):
        conclusions.append(
            "The capture includes indirect call/apply dispatch signals consistent with obfuscated or VM-style runtime execution."
        )
    if profile == PROFILE_GENERIC_VMP and vmp_family_counts:
        conclusions.append(
            "Observed VMP-oriented runtime API families without requiring a signature marker."
        )
    if profile == PROFILE_GENERIC_VMP and focus_window_family_counts.get("dynamic_dispatch"):
        conclusions.append(
            "Dynamic dispatch signals were observed in the markerless VMP focus window."
        )
    if profile == PROFILE_SIGNATURE and not signed_urls:
        if markers:
            conclusions.append(
                "No signed URL carrying the configured target parameters was observed in this trace; the page may have been blocked, lazy-loaded, or missing the interaction path."
            )
        else:
            conclusions.append(
                "No target parameters were configured for signature analysis; use --target-param for parameter-specific materialization evidence."
            )

    gaps: list[str] = []
    if profile == PROFILE_SIGNATURE and not markers:
        gaps.append("No target parameters were configured for signature profile analysis.")
    if profile == PROFILE_SIGNATURE and markers and not network_signed_urls:
        gaps.append("No network-layer request containing configured target parameters was observed.")
    if profile == PROFILE_SIGNATURE and markers and not assembly_events:
        gaps.append("No renderer URL assembly event containing configured target parameters was observed.")
    if not observed_runtime_signals:
        gaps.append("No fingerprint/runtime dependency signals were observed.")
    if profile == PROFILE_GENERIC_VMP and not vmp_family_counts:
        gaps.append("No VMP-family API events were observed.")
    if profile == PROFILE_GENERIC_VMP and not vmp_focus_event:
        gaps.append("No markerless VMP focus event could be selected.")
    if profile == PROFILE_GENERIC_VMP and not source_analysis["source_snippets"]:
        gaps.append("No source snippets could be attributed for the VMP focus window.")

    vmp_focus_record = None
    if vmp_focus and vmp_focus_event:
        vmp_focus_record = {
            "window_score": vmp_focus["window_score"],
            "window_vmp_event_count": vmp_focus["window_vmp_event_count"],
            "window_session_id": vmp_focus.get("window_session_id"),
            "window_start_us": vmp_focus["window_start_us"],
            "window_end_us": vmp_focus["window_end_us"],
            "event": timeline_event_record(
                vmp_focus_event,
                record_time_us(vmp_focus_event),
                script_registry,
                markers,
            ),
        }

    vmp_timeline = (
        build_vmp_timeline(
            events,
            vmp_focus_event,
            window_us=timeline_window_us,
            max_events=max_timeline_events,
            script_registry=script_registry,
            marker_params=markers,
        )
        if profile == PROFILE_GENERIC_VMP
        else None
    )
    marker_adjacent_timeline = None
    if profile == PROFILE_GENERIC_VMP and markers:
        marker_adjacent_timeline = build_pre_materialization_timeline(
            events,
            first_marker_event(events, markers),
            window_us=timeline_window_us,
            max_events=max_timeline_events,
            script_registry=script_registry,
            marker_params=markers,
        )

    summary = {
        "profile": profile,
        "event_count": len(events),
        "target_params": list(markers),
        "script_registry_count": script_registry_count(script_registry),
        "dispatch_light_resolved_count": dispatch_light_resolved_count,
        "dispatch_light_unresolved_count": dispatch_light_unresolved_count,
        "marker_occurrence_count": len(marker_occurrences),
        "signed_url_count": len(signed_urls),
        "network_signed_url_count": len(network_signed_urls),
        "source_snippets_count": len(source_analysis["source_snippets"]),
        "source_snippets_output": None,
        "first_signed_url": first_signed_url,
        "first_network_signed_url": first_network_signed_url,
        "first_assembly_event": first_assembly,
        "materialization_apis": observed_materialization_apis,
        "runtime_signals": observed_runtime_signals[:40],
        "candidate_functions": source_analysis["candidate_functions"],
        "request_transport_candidates": source_analysis["request_transport_candidates"],
        "top_marker_occurrences": marker_occurrences[:40],
        "sample_signed_urls": signed_urls[:20],
        "pre_materialization_timeline": build_pre_materialization_timeline(
            events,
            first_assembly,
            window_us=timeline_window_us,
            max_events=max_timeline_events,
            script_registry=script_registry,
            marker_params=markers,
        ),
        "conclusions": conclusions,
        "gaps": gaps,
        "_source_snippets": source_analysis["source_snippets"],
    }
    if profile == PROFILE_GENERIC_VMP:
        summary.update({
            "vmp_event_count": sum(vmp_family_counts.values()),
            "vmp_family_counts": counter_records(vmp_family_counts, "family"),
            "vmp_family_evidence_counts": counter_records(
                vmp_family_evidence_counts,
                "family",
            ),
            "top_vmp_apis": counter_records(vmp_api_counts, "api", 40),
            "vmp_focus_event": vmp_focus_record,
            "vmp_timeline": vmp_timeline,
            "vmp_hotspots": build_vmp_hotspots(
                events,
                vmp_focus_event,
                window_us=timeline_window_us,
                script_registry=script_registry,
            ),
            "marker_adjacent_timeline": marker_adjacent_timeline,
        })
    return summary


def public_summary(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in summary.items()
        if not key.startswith("_")
    }


def write_source_snippets(summary: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    snippets = summary.get("_source_snippets", [])
    output.write_text(
        json.dumps(snippets, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary["source_snippets_output"] = str(output)
    summary["source_snippets_count"] = len(snippets)


def print_summary(summary: dict[str, Any], trace: Path) -> None:
    print(f"Trace: {trace}")
    print(f"Profile: {summary.get('profile', PROFILE_SIGNATURE)}")
    target_params = summary.get("target_params", [])
    if target_params:
        print(f"Target params: {','.join(target_params)}")
    print(f"Events: {summary['event_count']}")
    print(f"Script registry entries: {summary.get('script_registry_count', 0)}")
    print(
        "Dispatch light resolved/unresolved: "
        f"{summary.get('dispatch_light_resolved_count', 0)}/"
        f"{summary.get('dispatch_light_unresolved_count', 0)}"
    )
    if summary.get("profile", PROFILE_SIGNATURE) == PROFILE_GENERIC_VMP:
        print(f"VMP events observed: {summary.get('vmp_event_count', 0)}")
        family_counts = summary.get("vmp_family_counts", [])
        if family_counts:
            print("VMP families:")
            for item in family_counts[:12]:
                print(f"  {item['family']}: {item['count']}")
        top_vmp_apis = summary.get("top_vmp_apis", [])
        if top_vmp_apis:
            print("Top VMP APIs:")
            for item in top_vmp_apis[:12]:
                print(f"  {item['api']}: {item['count']}")
        focus = summary.get("vmp_focus_event") or {}
        if focus:
            event_record = focus.get("event") or {}
            print(
                "VMP focus: "
                f"seq={event_record.get('seq')} api={event_record.get('api')} "
                f"family={event_record.get('vmp_family')} "
                f"score={focus.get('window_score')} "
                f"window_events={focus.get('window_vmp_event_count')}"
            )
    else:
        print(f"Target marker occurrences: {summary['marker_occurrence_count']}")
        print(f"Signed URLs observed: {summary['signed_url_count']}")
        print(f"Network signed URLs observed: {summary['network_signed_url_count']}")
    print(f"Source snippets: {summary.get('source_snippets_count', 0)}")
    if summary.get("source_snippets_output"):
        print(f"Source snippets JSON: {summary['source_snippets_output']}")

    first_assembly = summary.get("first_assembly_event")
    if first_assembly:
        print(
            "First renderer assembly: "
            f"seq={first_assembly.get('seq')} api={first_assembly.get('api')}"
        )

    first_network = summary.get("first_network_signed_url")
    if first_network:
        print(
            "First network signed request: "
            f"seq={first_network.get('seq')} api={first_network.get('api')} "
            f"host={first_network.get('host')} path={first_network.get('path')} "
            f"query_keys={','.join(first_network.get('query_keys', []))} "
            f"target_params={','.join(first_network.get('target_params', []))}"
        )

    materialization = summary.get("materialization_apis", [])
    if materialization:
        print("Materialization APIs:")
        for item in materialization:
            print(f"  {item['api']}: {item['count']}")

    runtime = summary.get("runtime_signals", [])
    if runtime:
        print("Runtime/fingerprint signals:")
        for item in runtime[:20]:
            print(f"  {item['api']}: {item['count']}")

    candidates = summary.get("candidate_functions", [])
    if candidates:
        print("Candidate functions:")
        for item in candidates[:8]:
            print(
                f"  {item.get('role')} score={item.get('score')} "
                f"events={item.get('event_count')} markers={item.get('marker_count')} "
                f"{item.get('function')} @ {item.get('url')} "
                f"pos={item.get('source_position')}"
            )

    vmp_timeline = summary.get("vmp_timeline")
    if vmp_timeline:
        print("VMP timeline:")
        print(
            "  window: "
            f"window_us={vmp_timeline.get('window_us')} "
            f"events={vmp_timeline.get('event_count')} "
            f"vmp_events={vmp_timeline.get('vmp_event_count')}"
        )
        print("  top families:")
        for item in vmp_timeline.get("family_counts", [])[:8]:
            print(f"    {item['family']}: {item['count']}")

    timeline = summary.get("pre_materialization_timeline")
    if timeline:
        print("Pre-materialization timeline:")
        focus = timeline.get("focus_event") or {}
        print(
            "  focus: "
            f"seq={focus.get('seq')} api={focus.get('api')} "
            f"window_us={timeline.get('window_us')} "
            f"events={timeline.get('event_count')}"
        )
        print("  top APIs:")
        for item in timeline.get("api_counts", [])[:12]:
            print(f"    {item['api']}: {item['count']}")
        print("  top stacks:")
        for item in timeline.get("stack_counts", [])[:5]:
            print(
                f"    {item['function']} @ {item['url']}: {item['count']}"
            )
        marker_events = timeline.get("marker_events", [])
        if marker_events:
            print("  first marker events in window:")
            for item in marker_events[:5]:
                print(
                    f"    delta_us={item.get('delta_us')} "
                    f"seq={item.get('seq')} api={item.get('api')} "
                    f"stack={item.get('stack_top')}"
                )

    if summary.get("conclusions"):
        print("Conclusions:")
        for item in summary["conclusions"]:
            print(f"  - {item}")

    if summary.get("gaps"):
        print("Gaps:")
        for item in summary["gaps"]:
            print(f"  - {item}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Summarize generic signature or JSVMP runtime evidence from an XTrace NDJSON trace. "
            "The summary does not print reusable signature algorithms; raw values remain in the trace."
        )
    )
    parser.add_argument("trace", type=Path)
    parser.add_argument(
        "--profile",
        choices=(PROFILE_SIGNATURE, PROFILE_GENERIC_VMP),
        default=PROFILE_GENERIC_VMP,
    )
    parser.add_argument(
        "--target-param",
        dest="target_params",
        action="append",
        default=None,
        metavar="PARAM",
        help=(
            "target signature parameter to use for signature or marker-adjacent analysis; "
            "may be repeated. Defaults to no target parameter."
        ),
    )
    parser.add_argument(
        "--marker-param",
        dest="target_params",
        action="append",
        metavar="PARAM",
        help="deprecated alias for --target-param",
    )
    parser.add_argument("--json-output", type=Path, default=None)
    parser.add_argument("--source-snippets-output", type=Path, default=None)
    parser.add_argument("--timeline-window-us", type=int, default=15_000_000)
    parser.add_argument("--max-timeline-events", type=int, default=80)
    parser.add_argument("--max-source-snippets", type=int, default=80)
    parser.add_argument(
        "--skip-bad-json",
        action="store_true",
        help=(
            "skip NDJSON lines that remain invalid after known-serializer repairs "
            "instead of failing the whole analysis"
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        events = load_events(args.trace, skip_bad_json=args.skip_bad_json)
        asset_sources = load_asset_sources(args.trace)
        summary = summarize(
            events,
            profile=args.profile,
            marker_params=args.target_params,
            timeline_window_us=args.timeline_window_us,
            max_timeline_events=args.max_timeline_events,
            asset_sources=asset_sources,
            max_source_snippets=args.max_source_snippets,
        )
        if args.source_snippets_output:
            write_source_snippets(summary, args.source_snippets_output)
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print_summary(summary, args.trace)
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(public_summary(summary), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"JSON summary: {args.json_output}")
    if args.profile == PROFILE_GENERIC_VMP:
        return 0 if summary.get("vmp_event_count", 0) else 1
    return 0 if summary["signed_url_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
