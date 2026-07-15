from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from scripts.analyze_vmp_trace import (
    PROFILE_GENERIC_VMP,
    PROFILE_SIGNATURE,
    build_script_registry,
    event_order,
    load_asset_sources,
    load_events,
    main,
    resolve_dispatch_callsite,
    sha1_ref,
    stack_top,
    summarize as analyze_summarize,
    utf16_offset_to_index,
)

SIGNATURE_PARAM = "X-Signature"


def summarize(events, **kwargs):
    profile = kwargs.setdefault("profile", PROFILE_SIGNATURE)
    if profile == PROFILE_SIGNATURE:
        kwargs.setdefault("marker_params", [SIGNATURE_PARAM])
    return analyze_summarize(events, **kwargs)


def event(api, seq, args, stack=None, phase="call", category="reverse"):
    return {
        "schema_version": 1,
        "api": api,
        "seq": seq,
        "session_id": "session-1",
        "mono_time_us": seq * 100,
        "phase": phase,
        "category": category,
        "args": [args],
        "stack": stack or [],
    }


class AnalyzeVmpTraceTests(unittest.TestCase):
    def test_summarize_detects_renderer_materialization_before_network(self):
        signed_url = (
            "https://www.example.test/api/post/item_list/?cursor=0"
            "&sessionToken=token-value&X-Signature=signature-value"
        )
        stack = [{"url": "https://www.example.test/app", "line": 10, "column": 2}]
        events = [
            event("Navigator.userAgent.get", 1, {"value": "ua"}, category="fingerprint"),
            event("Function.prototype.call", 2, {"target_type": "function"}),
            event(
                "URLSearchParams.set",
                3,
                {
                    "name": "X-Signature",
                    "value": "signature-value",
                    "value_ref": "string_ref:sig",
                },
                stack=stack,
            ),
            event(
                "URL.search.set",
                4,
                {
                    "href": signed_url,
                    "href_ref": "string_ref:url",
                },
                stack=stack,
                phase="set",
            ),
            event(
                "BrowserNetwork.request",
                5,
                {
                    "method": "GET",
                    "url": signed_url,
                },
                category="network",
            ),
        ]

        summary = summarize(events)

        self.assertEqual(summary["signed_url_count"], 2)
        self.assertEqual(summary["network_signed_url_count"], 1)
        self.assertEqual(summary["first_assembly_event"]["api"], "URLSearchParams.set")
        self.assertEqual(summary["first_network_signed_url"]["path"], "/api/post/item_list/")
        self.assertEqual(
            summary["first_network_signed_url"]["primary_target_value_length"],
            len("signature-value"),
        )
        self.assertIn(
            "A target signature parameter was materialized in renderer-side URL/request assembly before the network request boundary.",
            summary["conclusions"],
        )

    def test_main_writes_json_summary_without_printing_signature_value(self):
        signed_url = "https://www.example.test/api/feed?X-Signature=secret-one"
        events = [
            event(
                "BrowserNetwork.request",
                1,
                {"url": signed_url},
                category="network",
            )
        ]
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "trace.ndjson"
            output = Path(tmp) / "summary.json"
            trace.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = main([
                    str(trace),
                    "--profile",
                    "signature",
                    "--target-param",
                    SIGNATURE_PARAM,
                    "--json-output",
                    str(output),
                ])

            self.assertEqual(result, 0)
            self.assertTrue(output.exists())
            self.assertNotIn("secret-one", stdout.getvalue())
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["network_signed_url_count"], 1)
            self.assertNotIn("_source_snippets", data)

    def test_main_writes_source_snippets_sidecar(self):
        source = 'function s(){return "material";}'
        source_hash = sha1_ref(source)
        asset_id = "sha1:asset"
        script_url = "https://cdn.example.test/runtime-sdk.js"
        signed_url = "https://www.example.test/api/feed?X-Signature=secret-one"
        events = [
            event(
                "ClassicScript.evaluate",
                1,
                {
                    "script_id": 42,
                    "script_url": script_url,
                    "source_length": len(source),
                },
                phase="return",
            ) | {"asset_id": asset_id, "source_hash": source_hash, "script_url": script_url},
            event(
                "Function.prototype.call",
                2,
                {
                    "callsite_mode": "dispatch_light",
                    "callsite_script_id": 42,
                    "callsite_source_position": source.index("return"),
                    "callsite_code_offset": 4,
                    "callsite_function_start_position": 0,
                    "target_function": "s",
                },
            ),
            event("Request.constructor", 3, {"url": signed_url, "url_ref": "string_ref:url"}),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace_test.ndjson"
            manifest = root / "assets" / "trace_test" / "manifest.ndjson"
            output = root / "summary.json"
            snippets = root / "sources.json"
            manifest.parent.mkdir(parents=True)
            trace.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
            manifest.write_text(
                json.dumps({
                    "asset_id": asset_id,
                    "url": script_url,
                    "sha1": source_hash,
                    "source": source,
                    "size": len(source),
                }) + "\n",
                encoding="utf-8",
            )

            result = main([
                str(trace),
                "--profile",
                "signature",
                "--target-param",
                SIGNATURE_PARAM,
                "--json-output",
                str(output),
                "--source-snippets-output",
                str(snippets),
            ])

            self.assertEqual(result, 0)
            self.assertTrue(snippets.exists())
            summary = json.loads(output.read_text(encoding="utf-8"))
            sidecar = json.loads(snippets.read_text(encoding="utf-8"))
            self.assertEqual(summary["source_snippets_output"], str(snippets))
            self.assertGreaterEqual(summary["source_snippets_count"], 1)
            self.assertIn("function s", sidecar[0]["snippet"])

    def test_summarize_ignores_static_script_source_markers(self):
        events = [
            event(
                "Script.external",
                1,
                {
                    "url": "https://cdn.example.test/app.js",
                    "source": "const sample = 'https://www.example.test/api/feed?X-Signature=static-only';",
                },
            )
        ]

        summary = summarize(events)

        self.assertEqual(summary["marker_occurrence_count"], 0)
        self.assertEqual(summary["signed_url_count"], 0)

    def test_summarize_builds_pre_materialization_timeline_by_mono_time(self):
        signed_url = (
            "https://www.example.test/api/post/item_list/?cursor=0"
            "&sessionToken=token-value&X-Signature=signature-value"
        )
        stack = [{"url": "https://cdn.example.test/loader.js", "function": "qn", "line": 4}]
        events = [
            event("Function.prototype.call", 9000, {"target_type": "function"}, stack=stack),
            event("TextEncoder.encode", 9001, {"input": "material", "input_ref": "string_ref:mat"}, stack=stack),
            event(
                "Request.constructor",
                3,
                {"url": signed_url, "url_ref": "string_ref:url"},
                stack=stack,
            ) | {"mono_time_us": 900_500},
            event(
                "BrowserNetwork.request",
                1,
                {"url": signed_url},
                category="network",
            ) | {"mono_time_us": 901_000},
        ]

        summary = summarize(events, timeline_window_us=1_000, max_timeline_events=10)
        timeline = summary["pre_materialization_timeline"]

        self.assertEqual(summary["first_assembly_event"]["api"], "Request.constructor")
        self.assertEqual(summary["first_network_signed_url"]["api"], "BrowserNetwork.request")
        self.assertEqual(timeline["focus_event"]["api"], "Request.constructor")
        self.assertGreaterEqual(timeline["event_count"], 3)
        self.assertEqual(timeline["marker_events"][0]["api"], "Request.constructor")
        self.assertTrue(any(item["api"] == "TextEncoder.encode" for item in timeline["last_key_events"]))

    def test_load_events_adds_file_index_and_order_prefers_file_position(self):
        events = [
            event("BrowserNetwork.request", 100, {"url": "https://example.test/a"}) | {"mono_time_us": 300},
            event("Function.prototype.call", 1, {"target_type": "function"}) | {"mono_time_us": 100},
            event("TextEncoder.encode", 100, {"input": "x"}) | {"mono_time_us": 200},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "trace.ndjson"
            trace.write_text(
                "\n".join(json.dumps(item) for item in events) + "\n",
                encoding="utf-8",
            )

            loaded = load_events(trace)

        self.assertEqual([item["_file_index"] for item in loaded], [0, 1, 2])
        self.assertEqual([item["api"] for item in sorted(loaded, key=event_order)], [
            "BrowserNetwork.request",
            "Function.prototype.call",
            "TextEncoder.encode",
        ])

    def test_signature_records_use_file_order_when_producer_times_cross(self):
        signed_url = "https://www.example.test/api/feed?X-Signature=secret-one"
        events = [
            event(
                "BrowserNetwork.request",
                1,
                {"url": signed_url},
                category="network",
            ) | {"mono_time_us": 200},
            event(
                "Request.constructor",
                2,
                {"url": signed_url, "url_ref": "string_ref:url"},
            ) | {"mono_time_us": 100},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "trace.ndjson"
            trace.write_text(
                "\n".join(json.dumps(item) for item in events) + "\n",
                encoding="utf-8",
            )

            loaded = load_events(trace)

        summary = summarize(loaded)

        self.assertEqual(summary["first_signed_url"]["api"], "BrowserNetwork.request")
        self.assertEqual(summary["first_signed_url"]["_file_index"], 0)
        self.assertEqual(summary["first_assembly_event"]["api"], "Request.constructor")
        self.assertEqual(summary["first_assembly_event"]["_file_index"], 1)
        self.assertNotIn(
            "A target signature parameter was materialized in renderer-side URL/request assembly before the network request boundary.",
            summary["conclusions"],
        )

    def test_signature_records_fall_back_to_global_sequence_without_file_index(self):
        signed_url = "https://www.example.test/api/feed?X-Signature=secret-one"
        events = [
            event(
                "BrowserNetwork.request",
                1,
                {"url": signed_url},
                category="network",
            ) | {"mono_time_us": 200, "global_seq": 1, "session_seq": 1},
            event(
                "Request.constructor",
                2,
                {"url": signed_url, "url_ref": "string_ref:url"},
            ) | {"mono_time_us": 100, "global_seq": 2, "session_seq": 2},
        ]

        summary = summarize(events)

        self.assertEqual(summary["first_signed_url"]["api"], "BrowserNetwork.request")
        self.assertEqual(summary["first_signed_url"]["global_seq"], 1)
        self.assertEqual(summary["first_assembly_event"]["api"], "Request.constructor")
        self.assertEqual(summary["first_assembly_event"]["global_seq"], 2)
        self.assertNotIn(
            "A target signature parameter was materialized in renderer-side URL/request assembly before the network request boundary.",
            summary["conclusions"],
        )

    def test_loaded_file_index_does_not_expand_time_windows(self):
        events = [
            event("Function.prototype.call", 1, {"target_type": "function"}) | {"mono_time_us": 0},
            event("Function.prototype.apply", 2, {"target_type": "function"}) | {"mono_time_us": 10_000_000},
            event("Reflect.apply", 3, {"target_type": "function"}) | {"mono_time_us": 10_000_100},
            event("Bitwise.xor", 4, {"left": 1, "right": 2, "result": 3}) | {"mono_time_us": 10_000_200},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "trace.ndjson"
            trace.write_text(
                "\n".join(json.dumps(item) for item in events) + "\n",
                encoding="utf-8",
            )

            loaded = load_events(trace)

        summary = summarize(
            loaded,
            profile=PROFILE_GENERIC_VMP,
            timeline_window_us=500,
        )

        self.assertEqual(summary["vmp_focus_event"]["event"]["seq"], 4)
        self.assertEqual(summary["vmp_focus_event"]["window_vmp_event_count"], 3)

    def test_stack_top_falls_back_to_v8_runtime_stack(self):
        item = event(
            "Array.prototype.push",
            1,
            {
                "js_stack": [
                    {
                        "function": "lt",
                        "script": "https://cdn.example.test/loader.js",
                        "line": 4,
                        "column": 7853,
                    }
                ],
                "callsite_function": "ignored",
                "callsite_script": "https://cdn.example.test/ignored.js",
            },
        )

        self.assertEqual(
            stack_top(item),
            {
                "function": "lt",
                "url": "https://cdn.example.test/loader.js",
                "line": 4,
                "column": 7853,
            },
        )

    def test_stack_top_falls_back_to_v8_callsite_fields(self):
        item = event(
            "String.prototype.substr",
            1,
            {
                "callsite_function": "qn",
                "callsite_script": "https://cdn.example.test/loader.js",
                "callsite_line": 4,
                "callsite_column": 7853,
            },
        )

        self.assertEqual(
            stack_top(item),
            {
                "function": "qn",
                "url": "https://cdn.example.test/loader.js",
                "line": 4,
                "column": 7853,
            },
        )

    def test_stack_top_skips_empty_builtin_frames(self):
        item = event(
            "Array.prototype.push",
            1,
            {"first_arg": "X-Signature"},
            stack=[
                {"function": "push", "url": None, "line": None, "column": None},
                {
                    "function": "s",
                    "url": "https://cdn.example.test/runtime-sdk.js",
                    "line": 1,
                    "column": 85324,
                },
            ],
        )

        self.assertEqual(
            stack_top(item),
            {
                "function": "s",
                "url": "https://cdn.example.test/runtime-sdk.js",
                "line": 1,
                "column": 85324,
            },
        )

    def test_script_registry_maps_classic_script_assets_by_script_id(self):
        item = event(
            "ClassicScript.evaluate",
            1,
            {
                "script_id": 42,
                "script_url": "https://cdn.example.test/runtime-sdk.js",
                "source_length": 1000,
            },
            phase="return",
        ) | {
            "asset_id": "sha1:asset",
            "source_hash": "sha1:source",
            "script_url": "https://cdn.example.test/runtime-sdk.js",
        }

        registry = build_script_registry([item])

        self.assertEqual(registry[42]["script_url"], "https://cdn.example.test/runtime-sdk.js")
        self.assertEqual(registry[42]["asset_id"], "sha1:asset")
        self.assertEqual(registry[42]["source_hash"], "sha1:source")
        self.assertEqual(registry[42]["source_length"], 1000)

    def test_load_asset_sources_maps_manifest_source(self):
        source = "const answer = 42;"
        source_hash = sha1_ref(source)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace_123.ndjson"
            manifest = root / "assets" / "trace_123" / "manifest.ndjson"
            manifest.parent.mkdir(parents=True)
            trace.write_text("", encoding="utf-8")
            manifest.write_text(
                json.dumps({
                    "asset_id": "sha1:asset",
                    "url": "https://cdn.example.test/app.js",
                    "sha1": source_hash,
                    "source": source,
                }) + "\n",
                encoding="utf-8",
            )

            assets = load_asset_sources(trace)

            self.assertEqual(assets["by_asset_id"]["sha1:asset"]["source"], source)
            self.assertEqual(assets["by_source_hash"][source_hash]["url"], "https://cdn.example.test/app.js")
            self.assertFalse(assets["by_asset_id"]["sha1:asset"]["source_unverified"])

    def test_utf16_offset_to_index_handles_astral_characters(self):
        source = "a😀b"

        self.assertEqual(utf16_offset_to_index(source, 0), 0)
        self.assertEqual(utf16_offset_to_index(source, 1), 1)
        self.assertEqual(utf16_offset_to_index(source, 2), 1)
        self.assertEqual(utf16_offset_to_index(source, 3), 2)

    def test_dispatch_light_resolves_through_script_registry(self):
        script = event(
            "ClassicScript.evaluate",
            1,
            {
                "script_id": 42,
                "script_url": "https://cdn.example.test/runtime-sdk.js",
                "source_length": 1000,
            },
        ) | {"asset_id": "sha1:asset", "source_hash": "sha1:source"}
        dispatch = event(
            "Function.prototype.call",
            2,
            {
                "callsite_mode": "dispatch_light",
                "callsite_script_id": 42,
                "callsite_source_position": 85324,
                "callsite_code_offset": 17,
                "callsite_function_start_position": 84000,
                "target_function": "s",
            },
        )

        registry = build_script_registry([script, dispatch])
        resolved = resolve_dispatch_callsite(dispatch, registry)

        self.assertTrue(resolved["resolved"])
        self.assertEqual(resolved["url"], "https://cdn.example.test/runtime-sdk.js")
        self.assertEqual(resolved["asset_id"], "sha1:asset")
        self.assertEqual(resolved["source_hash"], "sha1:source")
        self.assertEqual(stack_top(dispatch, registry)["url"], "https://cdn.example.test/runtime-sdk.js")

    def test_dynamic_code_asset_resolves_without_script_url(self):
        script = event(
            "Function",
            1,
            {
                "script_id": 7,
                "isolate_id": 12,
                "source_length": 4096,
                "compile_status": "success",
            },
        ) | {"asset_id": "sha1:dynamic", "source_hash": "sha1:source"}
        dispatch = event(
            "Function.prototype.call",
            2,
            {
                "isolate_id": 12,
                "callsite_mode": "dispatch_light",
                "callsite_script_id": 7,
                "callsite_source_position": 900,
                "callsite_code_offset": 17,
                "callsite_function_start_position": 850,
                "target_function": "handler",
            },
        )

        registry = build_script_registry([script, dispatch])
        resolved = resolve_dispatch_callsite(dispatch, registry)

        self.assertTrue(resolved["resolved"])
        self.assertEqual(resolved["asset_id"], "sha1:dynamic")
        self.assertEqual(resolved["source_locator"], "xtrace-asset:sha1:dynamic")
        self.assertEqual(stack_top(dispatch, registry)["url"], "xtrace-asset:sha1:dynamic")

    def test_script_registry_uses_isolate_scope_for_duplicate_script_ids(self):
        first = event(
            "Function",
            1,
            {"script_id": 7, "isolate_id": 1, "source_length": 10},
        ) | {"asset_id": "sha1:first", "source_hash": "sha1:first-source"}
        second = event(
            "Function",
            2,
            {"script_id": 7, "isolate_id": 2, "source_length": 20},
        ) | {"asset_id": "sha1:second", "source_hash": "sha1:second-source"}
        dispatch = event(
            "Function.prototype.call",
            3,
            {
                "isolate_id": 2,
                "callsite_mode": "dispatch_light",
                "callsite_script_id": 7,
                "callsite_source_position": 4,
                "callsite_function_start_position": 2,
            },
        )

        registry = build_script_registry([first, second])
        resolved = resolve_dispatch_callsite(dispatch, registry)

        self.assertEqual(resolved["asset_id"], "sha1:second")
        self.assertEqual(resolved["source_hash"], "sha1:second-source")

    def test_summarize_counts_unresolved_dispatch_light_without_failing(self):
        dispatch = event(
            "Function.prototype.call",
            1,
            {
                "callsite_mode": "dispatch_light",
                "callsite_script_id": 404,
                "callsite_source_position": 1,
                "callsite_code_offset": 2,
                "callsite_function_start_position": 3,
            },
        )

        summary = summarize([dispatch])

        self.assertEqual(summary["dispatch_light_resolved_count"], 0)
        self.assertEqual(summary["dispatch_light_unresolved_count"], 1)

    def test_summarize_ranks_source_candidates_and_transport_paths(self):
        web_source = 'function m(){return "a"};function s(){return "X-Signature"};'
        workbox_source = "function Request(){return 1;}"
        web_url = "https://cdn.example.test/runtime-sdk.js"
        workbox_url = "https://storage.googleapis.com/workbox-cdn/releases/7.4.0/workbox-core.prod.js"
        web_hash = sha1_ref(web_source)
        workbox_hash = sha1_ref(workbox_source)
        signed_url = "https://www.example.test/api/feed?X-Signature=secret-one"
        asset_sources = {
            "by_asset_id": {
                "sha1:web": {
                    "asset_id": "sha1:web",
                    "source_hash": web_hash,
                    "url": web_url,
                    "source": web_source,
                    "source_unverified": False,
                },
                "sha1:workbox": {
                    "asset_id": "sha1:workbox",
                    "source_hash": workbox_hash,
                    "url": workbox_url,
                    "source": workbox_source,
                    "source_unverified": False,
                },
            },
            "by_source_hash": {},
            "by_url": {},
        }
        asset_sources["by_source_hash"][web_hash] = asset_sources["by_asset_id"]["sha1:web"]
        asset_sources["by_source_hash"][workbox_hash] = asset_sources["by_asset_id"]["sha1:workbox"]
        asset_sources["by_url"][web_url] = asset_sources["by_asset_id"]["sha1:web"]
        asset_sources["by_url"][workbox_url] = asset_sources["by_asset_id"]["sha1:workbox"]
        events = [
            event(
                "ClassicScript.evaluate",
                1,
                {"script_id": 42, "script_url": web_url, "source_length": len(web_source)},
                phase="return",
            ) | {"asset_id": "sha1:web", "source_hash": web_hash, "script_url": web_url},
            event(
                "ClassicScript.evaluate",
                2,
                {"script_id": 43, "script_url": workbox_url, "source_length": len(workbox_source)},
                phase="return",
            ) | {"asset_id": "sha1:workbox", "source_hash": workbox_hash, "script_url": workbox_url},
            event(
                "Array.prototype.push",
                3,
                {"first_arg": "X-Signature"},
                stack=[{
                    "function": "s",
                    "url": web_url,
                    "line": 1,
                    "column": web_source.index("function s"),
                }],
            ),
            event(
                "Function.prototype.apply",
                4,
                {
                    "callsite_mode": "dispatch_light",
                    "callsite_script_id": 43,
                    "callsite_source_position": 0,
                    "callsite_code_offset": 5,
                    "callsite_function_start_position": 0,
                    "target_function": "Request",
                },
            ),
            event("Request.constructor", 5, {"url": signed_url, "url_ref": "string_ref:url"}),
        ]

        summary = summarize(events, asset_sources=asset_sources)

        self.assertGreaterEqual(summary["source_snippets_count"], 2)
        self.assertEqual(summary["candidate_functions"][0]["role"], "security_runtime_candidate")
        self.assertTrue(summary["request_transport_candidates"])
        self.assertIn("function s", summary["_source_snippets"][0]["snippet"])

    def test_source_candidate_marks_hash_mismatch_unverified(self):
        source = "function s(){return 1;}"
        script_url = "https://cdn.example.test/runtime-sdk.js"
        asset_sources = {
            "by_asset_id": {
                "sha1:asset": {
                    "asset_id": "sha1:asset",
                    "source_hash": "sha1:wrong",
                    "url": script_url,
                    "source": source,
                    "source_unverified": True,
                }
            },
            "by_source_hash": {"sha1:wrong": None},
            "by_url": {script_url: None},
        }
        asset_sources["by_source_hash"]["sha1:wrong"] = asset_sources["by_asset_id"]["sha1:asset"]
        asset_sources["by_url"][script_url] = asset_sources["by_asset_id"]["sha1:asset"]
        events = [
            event(
                "ClassicScript.evaluate",
                1,
                {"script_id": 42, "script_url": script_url, "source_length": len(source)},
                phase="return",
            ) | {"asset_id": "sha1:asset", "source_hash": "sha1:wrong", "script_url": script_url},
            event(
                "Function.prototype.call",
                2,
                {
                    "callsite_mode": "dispatch_light",
                    "callsite_script_id": 42,
                    "callsite_source_position": 0,
                    "callsite_code_offset": 0,
                    "callsite_function_start_position": 0,
                    "target_function": "s",
                },
            ),
            event("Request.constructor", 3, {"url": "https://www.example.test/api/feed?X-Signature=x"}),
        ]

        summary = summarize(events, asset_sources=asset_sources)

        self.assertTrue(summary["candidate_functions"][0]["source_unverified"])

    def test_resolved_url_fallback_marks_source_unverified(self):
        source = "function s(){return 1;}"
        script_url = "https://cdn.example.test/runtime-sdk.js"
        asset_sources = {
            "by_asset_id": {},
            "by_source_hash": {},
            "by_url": {
                script_url: {
                    "asset_id": "sha1:other",
                    "source_hash": sha1_ref(source),
                    "url": script_url,
                    "source": source,
                    "source_unverified": False,
                }
            },
        }
        events = [
            event(
                "ClassicScript.evaluate",
                1,
                {"script_id": 42, "script_url": script_url, "source_length": len(source)},
                phase="return",
            ) | {
                "asset_id": "sha1:missing",
                "source_hash": "sha1:missing",
                "script_url": script_url,
            },
            event(
                "Function.prototype.call",
                2,
                {
                    "callsite_mode": "dispatch_light",
                    "callsite_script_id": 42,
                    "callsite_source_position": 0,
                    "callsite_code_offset": 0,
                    "callsite_function_start_position": 0,
                    "target_function": "s",
                },
            ),
            event("Request.constructor", 3, {"url": "https://www.example.test/api/feed?X-Signature=x"}),
        ]

        summary = summarize(events, asset_sources=asset_sources)

        self.assertTrue(summary["candidate_functions"][0]["source_unverified"])
        generic_summary = summarize(
            events,
            profile=PROFILE_GENERIC_VMP,
            asset_sources=asset_sources,
        )
        self.assertTrue(generic_summary["candidate_functions"][0]["source_unverified"])

    def test_transport_candidates_are_selected_from_full_ranked_list(self):
        source = "function s(){return 1;}"
        transport_source = "function Request(){return 1;}"
        web_url = "https://cdn.example.test/runtime-sdk.js"
        transport_url = "https://storage.googleapis.com/workbox-cdn/releases/7.4.0/workbox-core.prod.js"
        web_hash = sha1_ref(source)
        transport_hash = sha1_ref(transport_source)
        web_asset = {
            "asset_id": "sha1:web",
            "source_hash": web_hash,
            "url": web_url,
            "source": source,
            "source_unverified": False,
        }
        transport_asset = {
            "asset_id": "sha1:transport",
            "source_hash": transport_hash,
            "url": transport_url,
            "source": transport_source,
            "source_unverified": False,
        }
        asset_sources = {
            "by_asset_id": {"sha1:web": web_asset, "sha1:transport": transport_asset},
            "by_source_hash": {web_hash: web_asset, transport_hash: transport_asset},
            "by_url": {web_url: web_asset, transport_url: transport_asset},
        }
        events = [
            event(
                "ClassicScript.evaluate",
                1,
                {"script_id": 42, "script_url": web_url, "source_length": len(source)},
                phase="return",
            ) | {"asset_id": "sha1:web", "source_hash": web_hash, "script_url": web_url},
            event(
                "ClassicScript.evaluate",
                2,
                {"script_id": 43, "script_url": transport_url, "source_length": len(transport_source)},
                phase="return",
            ) | {
                "asset_id": "sha1:transport",
                "source_hash": transport_hash,
                "script_url": transport_url,
            },
        ]
        for offset in range(35):
            events.append(
                event(
                    "Array.prototype.push",
                    3 + offset,
                    {"first_arg": "X-Signature"},
                    stack=[{
                        "function": f"s{offset}",
                        "url": web_url,
                        "line": 1,
                        "column": min(offset, len(source)),
                    }],
                )
            )
        events.extend([
            event(
                "Function.prototype.apply",
                100,
                {
                    "callsite_mode": "dispatch_light",
                    "callsite_script_id": 43,
                    "callsite_source_position": 0,
                    "callsite_code_offset": 0,
                    "callsite_function_start_position": 0,
                    "target_function": "Request",
                },
            ),
            event("Request.constructor", 101, {"url": "https://www.example.test/api/feed?X-Signature=x"}),
        ])

        summary = summarize(events, asset_sources=asset_sources)

        self.assertFalse(any(
            item["role"] == "request_transport_candidate"
            for item in summary["candidate_functions"]
        ))
        self.assertTrue(summary["request_transport_candidates"])
        self.assertEqual(
            summary["request_transport_candidates"][0]["role"],
            "request_transport_candidate",
        )

    def test_source_snippet_uses_function_start_when_source_position_is_zero(self):
        source = "var prefix=1;function s(){return 1;}"
        script_url = "https://cdn.example.test/runtime-sdk.js"
        source_hash = sha1_ref(source)
        asset_sources = {
            "by_asset_id": {
                "sha1:asset": {
                    "asset_id": "sha1:asset",
                    "source_hash": source_hash,
                    "url": script_url,
                    "source": source,
                    "source_unverified": False,
                }
            },
            "by_source_hash": {},
            "by_url": {},
        }
        asset_sources["by_source_hash"][source_hash] = asset_sources["by_asset_id"]["sha1:asset"]
        asset_sources["by_url"][script_url] = asset_sources["by_asset_id"]["sha1:asset"]
        function_start = source.index("function s")
        events = [
            event(
                "ClassicScript.evaluate",
                1,
                {"script_id": 42, "script_url": script_url, "source_length": len(source)},
                phase="return",
            ) | {"asset_id": "sha1:asset", "source_hash": source_hash, "script_url": script_url},
            event(
                "Function.prototype.call",
                2,
                {
                    "callsite_mode": "dispatch_light",
                    "callsite_script_id": 42,
                    "callsite_source_position": 0,
                    "callsite_code_offset": 5,
                    "callsite_function_start_position": function_start,
                    "target_function": "s",
                },
            ),
            event("Request.constructor", 3, {"url": "https://www.example.test/api/feed?X-Signature=x"}),
        ]

        summary = summarize(events, asset_sources=asset_sources)

        self.assertEqual(summary["candidate_functions"][0]["source_position"], 0)
        self.assertEqual(summary["candidate_functions"][0]["column"], function_start)

    def test_generic_vmp_profile_summarizes_markerless_trace(self):
        source = "function dispatcher(){return 1;}function handler(){return 2;}function table(){return 3;}"
        script_url = "https://cdn.example.test/obfuscated.js"
        source_hash = sha1_ref(source)
        asset = {
            "asset_id": "sha1:generic",
            "source_hash": source_hash,
            "url": script_url,
            "source": source,
            "source_unverified": False,
        }
        asset_sources = {
            "by_asset_id": {"sha1:generic": asset},
            "by_source_hash": {source_hash: asset},
            "by_url": {script_url: asset},
        }
        events = [
            event(
                "ClassicScript.evaluate",
                1,
                {"script_id": 42, "script_url": script_url, "source_length": len(source)},
                phase="return",
            ) | {"asset_id": "sha1:generic", "source_hash": source_hash, "script_url": script_url},
            event(
                "Function.prototype.call",
                20,
                {
                    "callsite_mode": "dispatch_light",
                    "callsite_script_id": 42,
                    "callsite_source_position": source.index("dispatcher"),
                    "callsite_code_offset": 4,
                    "callsite_function_start_position": source.index("function dispatcher"),
                    "target_function": "dispatcher",
                },
            ),
            event(
                "Bitwise.xor",
                21,
                {"left": 1, "right": 2, "result": 3},
                stack=[{"function": "handler", "url": script_url, "line": 1, "column": source.index("handler")}],
            ),
            event(
                "String.prototype.slice",
                22,
                {"subject": "abcdef", "start": 1, "result": "bcdef"},
                stack=[{"function": "handler", "url": script_url, "line": 1, "column": source.index("handler")}],
            ),
            event(
                "DataView.getUint8",
                23,
                {"byte_offset": 0, "result": 7},
                stack=[{"function": "table", "url": script_url, "line": 1, "column": source.index("table")}],
            ),
            event(
                "Proxy.get",
                24,
                {"property": "x", "result": "y"},
                stack=[{"function": "table", "url": script_url, "line": 1, "column": source.index("table")}],
            ),
        ]

        summary = summarize(
            events,
            profile=PROFILE_GENERIC_VMP,
            asset_sources=asset_sources,
            timeline_window_us=1_000,
        )
        families = {item["family"]: item["count"] for item in summary["vmp_family_counts"]}

        self.assertEqual(summary["signed_url_count"], 0)
        self.assertEqual(summary["vmp_event_count"], 6)
        self.assertIn("dynamic_dispatch", families)
        self.assertIn("int_bitwise", families)
        self.assertIn("string_transform", families)
        self.assertIn("byte_buffer", families)
        self.assertIn("proxy_trap", families)
        self.assertGreaterEqual(summary["source_snippets_count"], 1)
        self.assertTrue(summary["vmp_timeline"]["last_vmp_events"])

    def test_generic_vmp_focus_uses_highest_weighted_window(self):
        events = [
            event("Date.now", 1, {"result": 1}),
            event("String.prototype.slice", 2, {"subject": "low", "result": "ow"}),
            event("Function.prototype.call", 100, {"target_type": "function"}),
            event("Function.prototype.apply", 101, {"target_type": "function"}),
            event("Reflect.apply", 102, {"target_type": "function"}),
            event("Bitwise.xor", 103, {"left": 1, "right": 2, "result": 3}),
        ]

        summary = summarize(
            events,
            profile=PROFILE_GENERIC_VMP,
            timeline_window_us=350,
        )

        self.assertEqual(summary["vmp_focus_event"]["event"]["seq"], 103)
        self.assertEqual(summary["vmp_focus_event"]["window_vmp_event_count"], 4)
        self.assertGreater(summary["vmp_focus_event"]["window_score"], 10)

    def test_generic_vmp_focus_window_is_session_consistent(self):
        events = [
            event("Function.prototype.call", 1, {"target_type": "function"})
            | {"session_id": "session-a", "mono_time_us": 100},
            event("Bitwise.xor", 2, {"left": 1, "right": 2, "result": 3})
            | {"session_id": "session-a", "mono_time_us": 200},
            event("DataView.getUint8", 3, {"byte_offset": 0, "result": 7})
            | {"session_id": "session-a", "mono_time_us": 300},
            event("Function.prototype.apply", 4, {"target_type": "function"})
            | {"session_id": "session-b", "mono_time_us": 150},
            event("Reflect.apply", 5, {"target_type": "function"})
            | {"session_id": "session-b", "mono_time_us": 250},
        ]

        summary = summarize(
            events,
            profile=PROFILE_GENERIC_VMP,
            timeline_window_us=500,
        )

        self.assertEqual(summary["vmp_focus_event"]["window_session_id"], "session-a")
        self.assertEqual(summary["vmp_focus_event"]["window_vmp_event_count"], 3)
        self.assertEqual(summary["vmp_timeline"]["vmp_event_count"], 3)

    def test_generic_vmp_candidate_roles_cover_common_runtime_shapes(self):
        source = (
            "function dispatcher(){return 1;}"
            "function handler(){return 2;}"
            "function table(){return 3;}"
            "function decoder(){return 4;}"
            "function crypto(){return 5;}"
            "function anti(){return 6;}"
        )
        script_url = "https://cdn.example.test/vmp.js"
        source_hash = sha1_ref(source)
        asset = {
            "asset_id": "sha1:vmp",
            "source_hash": source_hash,
            "url": script_url,
            "source": source,
            "source_unverified": False,
        }
        asset_sources = {
            "by_asset_id": {"sha1:vmp": asset},
            "by_source_hash": {source_hash: asset},
            "by_url": {script_url: asset},
        }

        def stack(function: str):
            return [{"function": function, "url": script_url, "line": 1, "column": source.index(function)}]

        events = [
            event(
                "ClassicScript.evaluate",
                1,
                {"script_id": 42, "script_url": script_url, "source_length": len(source)},
                phase="return",
            ) | {"asset_id": "sha1:vmp", "source_hash": source_hash, "script_url": script_url},
            event(
                "Function.prototype.call",
                10,
                {
                    "callsite_mode": "dispatch_light",
                    "callsite_script_id": 42,
                    "callsite_source_position": source.index("dispatcher"),
                    "callsite_code_offset": 1,
                    "callsite_function_start_position": source.index("function dispatcher"),
                    "target_function": "dispatcher",
                },
            ),
            event("Bitwise.xor", 11, {"left": 1, "right": 2, "result": 3}, stack=stack("handler")),
            event("String.prototype.slice", 12, {"subject": "abcdef", "result": "abc"}, stack=stack("handler")),
            event("DataView.getUint8", 13, {"byte_offset": 0, "result": 7}, stack=stack("table")),
            event("Proxy.get", 14, {"property": "x", "result": "y"}, stack=stack("table")),
            event("atob", 15, {"input": "YQ==", "result": "a"}, stack=stack("decoder")),
            event("TextDecoder.decode", 16, {"input_hex": "61", "result": "a"}, stack=stack("decoder")),
            event("SubtleCrypto.digest", 17, {"algorithm": "SHA-256", "input_hex": "61"}, stack=stack("crypto")),
            event("Bitwise.or", 18, {"left": 1, "right": 4, "result": 5}, stack=stack("crypto")),
            event("Date.now", 19, {"result": 123}, stack=stack("anti")),
            event("Error.stack.get", 20, {"result": "stack"}, stack=stack("anti")),
        ]

        summary = summarize(
            events,
            profile=PROFILE_GENERIC_VMP,
            asset_sources=asset_sources,
            timeline_window_us=2_000,
        )
        roles = {item["role"] for item in summary["candidate_functions"]}
        hotspot_roles = {item["role"] for item in summary["vmp_hotspots"]}

        self.assertIn("dispatcher_candidate", roles)
        self.assertIn("handler_candidate", roles)
        self.assertIn("state_table_candidate", roles)
        self.assertIn("decoder_candidate", roles)
        self.assertIn("crypto_mix_candidate", roles)
        self.assertIn("anti_debug_candidate", roles)
        self.assertIn("dispatcher_candidate", hotspot_roles)
        self.assertIn("handler_candidate", hotspot_roles)
        self.assertIn("state_table_candidate", hotspot_roles)
        self.assertIn("decoder_candidate", hotspot_roles)
        self.assertIn("crypto_mix_candidate", hotspot_roles)
        self.assertIn("anti_debug_candidate", hotspot_roles)

    def test_generic_marker_param_adds_marker_timeline_without_changing_focus(self):
        events = [
            event("String.prototype.slice", 5, {"subject": "MARK", "result": "ARK"}),
            event("Function.prototype.call", 100, {"target_type": "function"}),
            event("Reflect.apply", 101, {"target_type": "function"}),
            event("Bitwise.xor", 102, {"left": 1, "right": 2, "result": 3}),
        ]

        summary = summarize(
            events,
            profile=PROFILE_GENERIC_VMP,
            marker_params=["MARK"],
            timeline_window_us=350,
        )

        self.assertEqual(summary["vmp_focus_event"]["event"]["seq"], 102)
        self.assertIsNotNone(summary["marker_adjacent_timeline"])
        self.assertEqual(summary["marker_adjacent_timeline"]["focus_event"]["seq"], 5)

    def test_generic_main_writes_source_sidecar_without_signature_marker(self):
        source = "function dispatcher(){return 1;}"
        source_hash = sha1_ref(source)
        script_url = "https://cdn.example.test/generic.js"
        events = [
            event(
                "ClassicScript.evaluate",
                1,
                {"script_id": 42, "script_url": script_url, "source_length": len(source)},
                phase="return",
            ) | {"asset_id": "sha1:generic", "source_hash": source_hash, "script_url": script_url},
            event(
                "Function.prototype.call",
                2,
                {
                    "callsite_mode": "dispatch_light",
                    "callsite_script_id": 42,
                    "callsite_source_position": source.index("dispatcher"),
                    "callsite_code_offset": 1,
                    "callsite_function_start_position": source.index("function dispatcher"),
                    "target_function": "dispatcher",
                },
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trace = root / "trace_generic.ndjson"
            manifest = root / "assets" / "trace_generic" / "manifest.ndjson"
            output = root / "summary.json"
            snippets = root / "sources.json"
            manifest.parent.mkdir(parents=True)
            trace.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
            manifest.write_text(
                json.dumps({
                    "asset_id": "sha1:generic",
                    "url": script_url,
                    "sha1": source_hash,
                    "source": source,
                    "size": len(source),
                }) + "\n",
                encoding="utf-8",
            )

            result = main([
                str(trace),
                "--profile",
                "generic-vmp",
                "--json-output",
                str(output),
                "--source-snippets-output",
                str(snippets),
            ])

            self.assertEqual(result, 0)
            summary = json.loads(output.read_text(encoding="utf-8"))
            sidecar = json.loads(snippets.read_text(encoding="utf-8"))
            self.assertEqual(summary["profile"], "generic-vmp")
            self.assertEqual(summary["signed_url_count"], 0)
            self.assertEqual(summary["vmp_event_count"], 2)
            self.assertIn("function dispatcher", sidecar[0]["snippet"])


if __name__ == "__main__":
    unittest.main()
