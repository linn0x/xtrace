import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_trace import TraceValidationError, load_events, main, validate_schema_v1_event, validate_trace
from scripts.validate_trace import REVERSE_EXPECTED_APIS
from scripts.validate_trace import VMP_API_FAMILY


def schema_v1_event(api: str, **overrides):
    event = {
        "schema_version": 1,
        "event_id": "session-1:1",
        "session_id": "session-1",
        "seq": 1,
        "t": "call",
        "wall_time_us": 1780000000000000,
        "mono_time_us": 123456789,
        "category": "fingerprint",
        "phase": "call",
        "api": api,
        "args": [],
        "stack": [],
        "pid": 100,
        "tid": 200,
        "frame_url": "",
        "origin": "",
        "result": None,
        "error": None,
        "truncated": False,
    }
    event.update(overrides)
    return event


def schema_v2_event(api: str, *, call_id: str, parent_id=None, depth=0,
                    kind="singleton", phase="call", duration_us=None, **overrides):
    if isinstance(call_id, str) and "session_id" not in overrides:
        overrides["session_id"] = call_id.rpartition(":")[0]
    event = schema_v1_event(
        api,
        schema_version=2,
        event_id=f"event:{call_id}:{phase}",
        phase=phase,
        t=phase,
        call_id=call_id,
        parent_id=parent_id,
        depth=depth,
        causality_kind=kind,
        duration_us=duration_us,
    )
    event.update(overrides)
    return event


class ValidateTraceTests(unittest.TestCase):
    def test_schema_v2_accepts_nested_paired_tree_and_external_record(self):
        rows = [
            schema_v2_event("ClassicScript.evaluate", call_id="renderer:1", kind="paired"),
            schema_v2_event("JSON.stringify", call_id="renderer:2", parent_id="renderer:1", depth=1),
            schema_v2_event("ClassicScript.evaluate", call_id="renderer:1", kind="paired", phase="return", duration_us=42),
            schema_v2_event("BrowserNetwork.request", call_id=None, kind="external", depth=0,
                            parent_id=None, duration_us=None),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "trace.ndjson"
            trace.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            validate_trace(trace, expected=[], schema_version=2)

    def test_schema_v2_rejects_cross_session_parent_and_orphan_terminal(self):
        cases = [
            [
                schema_v2_event("root", call_id="one:1", kind="singleton"),
                schema_v2_event("child", call_id="two:1", parent_id="one:1", depth=1),
            ],
            [schema_v2_event("root", call_id="one:1", kind="paired", phase="return", duration_us=1)],
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for number, rows in enumerate(cases):
                trace = Path(tmp) / f"bad-{number}.ndjson"
                trace.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
                with self.assertRaises(TraceValidationError):
                    validate_trace(trace, expected=[], schema_version=2)

    def test_schema_v2_accepts_exception_terminal(self):
        rows = [
            schema_v2_event("ModuleScript.evaluate", call_id="renderer:9", kind="paired"),
            schema_v2_event("ModuleScript.evaluate", call_id="renderer:9", kind="paired",
                            phase="exception", duration_us=7),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "exception.ndjson"
            trace.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            validate_trace(trace, expected=[], schema_version=2)

    def test_schema_v2_rejects_paired_terminal_with_different_api(self):
        rows = [
            schema_v2_event("ClassicScript.evaluate", call_id="renderer:1", kind="paired"),
            schema_v2_event("JSON.stringify", call_id="renderer:1", kind="paired",
                            phase="return", duration_us=7),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "mismatched-pair.ndjson"
            trace.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
            with self.assertRaises(TraceValidationError):
                validate_trace(trace, expected=[], schema_version=2)

    def test_schema_v2_rejects_bad_depth_unclosed_pair_and_mixed_schema(self):
        cases = [
            [
                schema_v2_event("root", call_id="one:1", kind="singleton"),
                schema_v2_event("child", call_id="one:2", parent_id="one:1", depth=2),
            ],
            [schema_v2_event("root", call_id="one:1", kind="paired")],
            [schema_v2_event("root", call_id="one:1"), schema_v1_event("legacy")],
            [schema_v2_event("root", call_id="one:1", depth=-1)],
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for number, rows in enumerate(cases):
                trace = Path(tmp) / f"bad-{number}.ndjson"
                trace.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
                with self.assertRaises(TraceValidationError):
                    validate_trace(trace, expected=[], schema_version=2)
    def test_load_events_adds_file_index_without_requiring_seq_monotonicity(self):
        rows = [
            schema_v1_event("DataView.getUint32", seq=3, event_id="session-1:3"),
            schema_v1_event("Function.prototype.call", seq=1, event_id="session-1:1"),
            schema_v1_event("Bitwise.xor", seq=1, event_id="session-2:1", session_id="session-2"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "trace.ndjson"
            trace.write_text(
                "\n".join(json.dumps(item) for item in rows) + "\n",
                encoding="utf-8",
            )

            loaded = load_events(trace)
            validate_trace(trace, expected=[], schema_version=1)

        self.assertEqual([event["_file_index"] for event in loaded], [0, 1, 2])

    def test_schema_v1_top_level_result_and_error_may_be_null(self):
        validate_schema_v1_event(schema_v1_event("JSON.stringify", result=None, error=None), 1)

    def test_validate_trace_can_require_context_for_selected_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "ClassicScript.evaluate",
                category="reverse",
                frame_url="https://example.test/app.js",
                origin="https://example.test",
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            validate_trace(
                path,
                expected=[],
                schema_version=1,
                require_context_for=["ClassicScript.evaluate"],
            )

    def test_validate_trace_rejects_missing_or_absent_required_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(json.dumps(schema_v1_event("ClassicScript.evaluate")) + "\n",
                            encoding="utf-8")
            with self.assertRaisesRegex(TraceValidationError, "frame_url/origin"):
                validate_trace(path, expected=[], require_context_for=["ClassicScript.evaluate"])
            with self.assertRaisesRegex(TraceValidationError, "not observed"):
                validate_trace(path, expected=[], require_context_for=["ModuleScript.evaluate"])

    def test_schema_v1_accepts_monotonic_global_sequence(self):
        rows = [
            schema_v1_event("DataView.getUint32", seq=3, session_seq=3, global_seq=1, event_id="session-1:3"),
            schema_v1_event("Function.prototype.call", seq=1, session_seq=1, global_seq=2, event_id="session-2:1", session_id="session-2"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "trace.ndjson"
            trace.write_text(
                "\n".join(json.dumps(item) for item in rows) + "\n",
                encoding="utf-8",
            )

            validate_trace(trace, expected=[], schema_version=1)

    def test_schema_v1_rejects_partial_or_non_monotonic_global_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            partial = Path(tmp) / "partial.ndjson"
            partial.write_text(
                "\n".join(json.dumps(item) for item in [
                    schema_v1_event("DataView.getUint32", global_seq=1),
                    schema_v1_event("Function.prototype.call", seq=2, event_id="session-1:2"),
                ]) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(TraceValidationError, "Partial global_seq coverage"):
                validate_trace(partial, expected=[], schema_version=1)

            non_monotonic = Path(tmp) / "non_monotonic.ndjson"
            non_monotonic.write_text(
                "\n".join(json.dumps(item) for item in [
                    schema_v1_event("DataView.getUint32", global_seq=2),
                    schema_v1_event("Function.prototype.call", seq=2, event_id="session-1:2", global_seq=2),
                ]) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(TraceValidationError, "non-monotonic global_seq"):
                validate_trace(non_monotonic, expected=[], schema_version=1)

    def uri_codec_args(self, input_value: str, result_value: str) -> dict:
        return {
            "input": input_value,
            "input_ref": f"string_ref:input:length:{len(input_value)}",
            "input_length": len(input_value),
            "result": result_value,
            "result_ref": f"string_ref:result:length:{len(result_value)}",
            "result_length": len(result_value),
        }

    def network_header_args(self, name: str, value: str) -> dict:
        return {
            "name": name,
            "name_length": len(name),
            "value": value,
            "value_length": len(value),
        }

    def url_search_params_set_args(self, name: str, value: str) -> dict:
        before_serialized = "cursor=1"
        serialized = f"{before_serialized}&{name}={value}"
        return {
            "search_params_id": 7,
            "url_object_id": 11,
            "name": name,
            "name_length": len(name),
            "name_ref": f"string_ref:name:length:{len(name)}",
            "value": value,
            "value_length": len(value),
            "value_ref": f"string_ref:value:length:{len(value)}",
            "replaced_existing": False,
            "before_serialized": before_serialized,
            "before_serialized_length": len(before_serialized),
            "before_serialized_ref": f"string_ref:before:length:{len(before_serialized)}",
            "serialized": serialized,
            "serialized_length": len(serialized),
            "serialized_ref": f"string_ref:serialized:length:{len(serialized)}",
        }

    def url_search_params_to_string_args(self) -> dict:
        serialized = "cursor=1&X-Signature=secret-one"
        return {
            "search_params_id": 7,
            "url_object_id": 11,
            "size": 2,
            "serialized": serialized,
            "serialized_length": len(serialized),
            "serialized_ref": f"string_ref:serialized:length:{len(serialized)}",
            "result_ref": f"string_ref:result:length:{len(serialized)}",
        }

    def url_search_params_constructor_args(self, name: str, value: str) -> dict:
        serialized = f"{name}={value}"
        return {
            "search_params_id": 7,
            "url_object_id": 0,
            "init_type": "record",
            "has_init": True,
            "entry_count": 1,
            "param_names": [name],
            "param_name_lengths": [len(name)],
            "param_name_refs": [f"string_ref:url-param-name:length:{len(name)}"],
            "param_values": [value],
            "param_value_lengths": [len(value)],
            "param_value_refs": [f"string_ref:url-param-value:length:{len(value)}"],
            "serialized": serialized,
            "serialized_length": len(serialized),
            "serialized_ref": f"string_ref:serialized:length:{len(serialized)}",
        }

    def url_search_params_iterator_args(self, name: str, value: str) -> dict:
        return {
            "search_params_id": 7,
            "url_object_id": 11,
            "iteration_index": 0,
            "name": name,
            "name_length": len(name),
            "name_ref": f"string_ref:url-param-name:length:{len(name)}",
            "value": value,
            "value_length": len(value),
            "value_ref": f"string_ref:url-param-value:length:{len(value)}",
        }

    def url_search_params_get_all_args(self, name: str, values: list[str]) -> dict:
        return {
            "search_params_id": 7,
            "url_object_id": 11,
            "name": name,
            "name_length": len(name),
            "name_ref": f"string_ref:url-param-name:length:{len(name)}",
            "result_count": len(values),
            "values": values,
            "result_value_lengths": [len(value) for value in values],
            "result_value_refs": [
                f"string_ref:url-param-value-{index}:length:{len(value)}"
                for index, value in enumerate(values)
            ],
        }

    def form_data_iterator_args(self, name: str, value: str) -> dict:
        return {
            "form_data_id": 3,
            "iteration_index": 0,
            "name": name,
            "name_length": len(name),
            "name_ref": f"string_ref:form-name:length:{len(name)}",
            "value_kind": "string",
            "value": value,
            "value_length": len(value),
            "value_ref": f"string_ref:form-value:length:{len(value)}",
        }

    def form_data_get_all_args(self, name: str, values: list[str]) -> dict:
        return {
            "form_data_id": 3,
            "name": name,
            "name_length": len(name),
            "name_ref": f"string_ref:form-name:length:{len(name)}",
            "result_count": len(values),
            "string_count": len(values),
            "blob_count": 0,
            "values": values,
            "result_value_lengths": [len(value) for value in values],
            "result_value_refs": [
                f"string_ref:form-value-{index}:length:{len(value)}"
                for index, value in enumerate(values)
            ],
        }

    def form_data_blob_args(self, name: str) -> dict:
        filename = "payload.bin"
        blob_type = "application/octet-stream"
        blob_uuid = "blob-uuid-1"
        return {
            "form_data_id": 3,
            "name": name,
            "name_length": len(name),
            "name_ref": f"string_ref:form-name:length:{len(name)}",
            "value_kind": "blob",
            "filename": filename,
            "filename_length": len(filename),
            "filename_ref": f"string_ref:form-filename:length:{len(filename)}",
            "blob_type": blob_type,
            "blob_type_length": len(blob_type),
            "blob_type_ref": f"string_ref:form-blob-type:length:{len(blob_type)}",
            "blob_size": 12,
            "blob_uuid": blob_uuid,
            "blob_uuid_ref": f"string_ref:form-blob-uuid:length:{len(blob_uuid)}",
        }

    def form_data_get_all_blob_args(self, name: str) -> dict:
        filename = "payload.bin"
        blob_type = "application/octet-stream"
        blob_uuid = "blob-uuid-1"
        return {
            "form_data_id": 3,
            "name": name,
            "name_length": len(name),
            "name_ref": f"string_ref:form-name:length:{len(name)}",
            "result_count": 1,
            "string_count": 0,
            "blob_count": 1,
            "values": [],
            "result_value_lengths": [],
            "result_value_refs": [],
            "blob_filenames": [filename],
            "blob_filename_lengths": [len(filename)],
            "blob_filename_refs": [f"string_ref:form-filename:length:{len(filename)}"],
            "blob_types": [blob_type],
            "blob_type_lengths": [len(blob_type)],
            "blob_type_refs": [f"string_ref:form-blob-type:length:{len(blob_type)}"],
            "blob_sizes": [12],
            "blob_uuids": [blob_uuid],
            "blob_uuid_refs": [f"string_ref:form-blob-uuid:length:{len(blob_uuid)}"],
        }

    def form_data_constructor_clone_args(self, name: str, value: str) -> dict:
        return {
            "form_data_id": 4,
            "cloned_from_form_data_id": 3,
            "entry_count": 1,
            "entries": [{
                "name": name,
                "name_length": len(name),
                "name_ref": f"string_ref:form-name:length:{len(name)}",
                "value_kind": "string",
                "value": value,
                "value_length": len(value),
                "value_ref": f"string_ref:form-value:length:{len(value)}",
            }],
        }

    def storage_get_item_args(self, key: str, result: str) -> dict:
        return {
            "storage": "localStorage",
            "key": key,
            "key_length": len(key),
            "key_ref": f"string_ref:key:length:{len(key)}",
            "result": result,
            "result_length": len(result),
            "result_ref": f"string_ref:result:length:{len(result)}",
        }

    def storage_set_item_args(self, key: str, value: str) -> dict:
        return {
            "storage": "localStorage",
            "key": key,
            "key_length": len(key),
            "key_ref": f"string_ref:key:length:{len(key)}",
            "value": value,
            "value_length": len(value),
            "value_ref": f"string_ref:value:length:{len(value)}",
        }

    def storage_remove_item_args(self, key: str) -> dict:
        return {
            "storage": "localStorage",
            "key": key,
            "key_length": len(key),
            "key_ref": f"string_ref:key:length:{len(key)}",
        }

    def storage_key_args(self, result: str) -> dict:
        return {
            "storage": "localStorage",
            "index": 0,
            "result": result,
            "result_length": len(result),
            "result_ref": f"string_ref:result:length:{len(result)}",
        }

    def document_cookie_get_args(self, value: str) -> dict:
        return {
            "value": value,
            "value_length": len(value),
            "value_ref": f"string_ref:cookie:length:{len(value)}",
        }

    def document_cookie_set_args(self, value: str, accepted: bool = True) -> dict:
        return {
            "value": value,
            "value_length": len(value),
            "value_ref": f"string_ref:cookie:length:{len(value)}",
            "accepted": accepted,
        }

    def document_context_args(self, result: str) -> dict:
        return {
            "result": result,
            "result_length": len(result),
            "result_ref": f"string_ref:document-context:length:{len(result)}",
        }

    def headers_constructor_args(self, name: str, value: str) -> dict:
        return {
            "headers_id": 19,
            "has_init": True,
            "init_type": "record",
            "entry_count": 1,
            "headers": [{
                "name": name,
                "name_length": len(name),
                "name_ref": f"string_ref:header-name:length:{len(name)}",
                "value": value,
                "value_length": len(value),
                "value_ref": f"string_ref:header-value:length:{len(value)}",
            }],
        }

    def headers_get_args(self, name: str, value: str, *, headers_id: int = 19) -> dict:
        return {
            "headers_id": headers_id,
            "name": name,
            "name_length": len(name),
            "name_ref": f"string_ref:header-name:length:{len(name)}",
            "found": True,
            "result": value,
            "result_length": len(value),
            "result_ref": f"string_ref:header-value:length:{len(value)}",
        }

    def headers_iterator_args(self, name: str, value: str) -> dict:
        return {
            "headers_id": 19,
            "iteration_index": 0,
            "name": name,
            "name_length": len(name),
            "name_ref": f"string_ref:header-name:length:{len(name)}",
            "value": value,
            "value_length": len(value),
            "value_ref": f"string_ref:header-value:length:{len(value)}",
        }

    def cookie_store_get_args(self, name: str, *, result_count: int = 1, value: str = "token-value") -> dict:
        result_names = [name for _ in range(result_count)]
        result_values = [value for _ in range(result_count)]
        return {
            "name": name,
            "name_length": len(name),
            "name_ref": f"string_ref:cookie-name:length:{len(name)}",
            "cookie_url": "https://www.example.test/path",
            "cookie_url_ref": "string_ref:cookie-url:length:29",
            "result_count": result_count,
            "result_names": result_names,
            "result_name_lengths": [len(item) for item in result_names],
            "result_name_refs": [f"string_ref:cookie-name:length:{len(item)}" for item in result_names],
            "result_values": result_values,
            "result_value_lengths": [len(item) for item in result_values],
            "result_value_refs": [f"string_ref:cookie-value:length:{len(item)}" for item in result_values],
        }

    def cookie_store_set_args(self, name: str, value: str, *, accepted: bool = True) -> dict:
        return {
            "name": name,
            "name_length": len(name),
            "name_ref": f"string_ref:cookie-name:length:{len(name)}",
            "value": value,
            "value_length": len(value),
            "value_ref": f"string_ref:cookie-value:length:{len(value)}",
            "cookie_url": "https://www.example.test/path",
            "cookie_url_ref": "string_ref:cookie-url:length:29",
            "accepted": accepted,
        }

    def cookie_store_delete_args(self, name: str, *, accepted: bool = True) -> dict:
        return {
            "name": name,
            "name_length": len(name),
            "name_ref": f"string_ref:cookie-name:length:{len(name)}",
            "cookie_url": "https://www.example.test/path",
            "cookie_url_ref": "string_ref:cookie-url:length:29",
            "accepted": accepted,
        }

    def location_read_args(self, result: str, *, href: str | None = None) -> dict:
        args = {
            "result": result,
            "result_length": len(result),
            "result_ref": f"string_ref:location-result:length:{len(result)}",
        }
        if href is not None:
            args.update({
                "href": href,
                "href_length": len(href),
                "href_ref": f"string_ref:location-href:length:{len(href)}",
            })
        return args

    def location_write_args(self, value: str, href: str) -> dict:
        return {
            "value": value,
            "value_length": len(value),
            "value_ref": f"string_ref:location-value:length:{len(value)}",
            "href": href,
            "href_length": len(href),
            "href_ref": f"string_ref:location-href:length:{len(href)}",
        }

    def vmp_next_core_events(self, *, start_seq: int = 1):
        current_href = (
            "https://www.example.test/api/records/list/"
            "?cursor=1&sessionToken=token-value"
        )
        current_search = "?cursor=1&sessionToken=token-value"
        specs = [
            ("Function.prototype.call", {"target_id": "function:sign"}),
            ("Function.prototype.apply", {"target_id": "function:encode"}),
            ("Reflect.apply", {"target_id": "function:mix"}),
            ("String.fromCharCode", {"first_code_ref": "number:65", "result_ref": "string:A"}),
            ("String.prototype.slice", {"subject_ref": "string:length:40", "result_ref": "string:length:39"}),
            ("encodeURIComponent", self.uri_codec_args("cursor=1&token=a b", "cursor%3D1%26token%3Da%20b")),
            ("Bitwise.xor", {"left_ref": "number:1", "right_ref": "number:2", "result_ref": "number:3"}),
            ("URLSearchParams.set", self.url_search_params_set_args("X-Signature", "secret-one")),
            ("URLSearchParams.toString", self.url_search_params_to_string_args()),
            ("URL.href.set", {"value_ref": "string:length:27", "href_ref": "string:length:27"}),
            ("URL.search.set", {
                "value_ref": "string:length:27",
                "search_ref": "string:length:27",
                "href_ref": "string:length:64",
            }),
            ("Location.href.get", self.location_read_args(current_href)),
            ("Location.search.get", self.location_read_args(current_search, href=current_href)),
            ("Location.href.set", self.location_write_args(
                "/api/records/list/?cursor=2",
                "https://www.example.test/api/records/list/?cursor=2",
            )),
            ("Location.search.set", self.location_write_args(
                "?cursor=2&X-Signature=secret-one",
                "https://www.example.test/api/records/list/?cursor=2&X-Signature=secret-one",
            )),
            ("Location.assign", self.location_write_args(
                "/api/records/list/?cursor=3",
                "https://www.example.test/api/records/list/?cursor=3",
            )),
            ("Location.replace", self.location_write_args(
                "/api/records/list/?cursor=4",
                "https://www.example.test/api/records/list/?cursor=4",
            )),
            ("Storage.getItem", self.storage_get_item_args("sessionToken", "token-value")),
            ("Storage.setItem", self.storage_set_item_args("x-signature-seed", "seed-value")),
            ("Storage.removeItem", self.storage_remove_item_args("old-token")),
            ("Storage.key", self.storage_key_args("sessionToken")),
            ("Document.cookie.get", self.document_cookie_get_args("sessionToken=token-value")),
            ("Document.cookie.set", self.document_cookie_set_args("x-signature-seed=seed-value; path=/")),
            ("Document.urlForBinding.get", self.document_context_args(current_href)),
            ("Document.referrer.get", self.document_context_args("https://www.example.test/from-feed")),
            ("Node.baseURI.get", self.document_context_args("https://www.example.test/")),
            ("CookieStore.get", self.cookie_store_get_args("sessionToken")),
            ("CookieStore.getAll", self.cookie_store_get_args("sessionToken", result_count=2)),
            ("CookieStore.set", self.cookie_store_set_args("x-signature-seed", "seed-value")),
            ("CookieStore.delete", self.cookie_store_delete_args("old-token")),
            ("BigInt.prototype.toString", {"result_ref": "string:length:4"}),
        ]
        events = []
        for offset, (api, args) in enumerate(specs):
            seq = start_seq + offset
            events.append(schema_v1_event(
                api,
                category="reverse",
                seq=seq,
                event_id=f"session-1:{seq}",
                args=[args],
            ))
        return events

    def business_api_events(self, *, include_signature_header_source: bool = True):
        stack = [{
            "function": "",
            "url": "https://www.example.test/business-api-smoke.html",
            "line": 1,
            "column": 1,
            "script_id": 5,
            "is_eval": False,
            "is_constructor": False,
        }]
        endpoint = "https://www.example.test/api/records/list/"
        get_url = (
            endpoint
            + "?client_time=1&app_id=1988&app_name=demo_web&browser_language=zh-CN"
            + "&browser_platform=MacIntel&count=30&device_platform=web_pc"
            + "&screen_height=600&screen_width=800&source=business-api-smoke"
            + "&sessionToken=query-demo&X-Signature=demo"
        )
        post_url = endpoint + "?transport=xhr&cursor=2&X-Signature=demo"
        post_body = '{"cursor":"2","body_marker":"xtrace"}'
        fetch_body = (
            '{"items":[{"id":"demo"}],"route":"/api/records/list/",'
            '"query":{"X-Signature":["demo"]}}'
        )
        get_key = "sha1:get-records"
        post_key = "sha1:post-records"
        events = []

        seq = 1
        events.append(schema_v1_event(
            "Navigator.language",
            category="fingerprint",
            seq=seq,
            event_id=f"session-1:{seq}",
            args=[{"value": "zh-CN"}],
            stack=stack,
        ))
        seq += 1
        for name in [
            "client_time",
            "app_id",
            "app_name",
            "browser_language",
            "browser_platform",
            "count",
            "device_platform",
            "screen_height",
            "screen_width",
            "source",
            "sessionToken",
            "X-Signature",
            "transport",
            "cursor",
        ]:
            events.append(schema_v1_event(
                "URLSearchParams.set",
                category="reverse",
                seq=seq,
                event_id=f"session-1:{seq}",
                args=[{
                    "name": name,
                    "value": "demo",
                    "value_ref": f"string_ref:url-param-{name.lower()}",
                    "serialized_ref": f"string_ref:url-param-{name.lower()}-serialized",
                }],
                stack=stack,
            ))
            seq += 1

        for api, args in [
            ("URLSearchParams.toString", [{
                "serialized": get_url.split("?", 1)[1],
                "result_ref": "string_ref:get-query-result",
                "serialized_ref": "string_ref:get-query-serialized",
            }]),
            ("URL.search.set", [{
                "href": get_url,
                "value_ref": "string_ref:get-query-value",
                "search_ref": "string_ref:get-query-search",
                "href_ref": "string_ref:get-url-href",
            }]),
            ("URL.href.get", [{"href": get_url}]),
            ("Headers.set", [{
                "name": "X-XTrace-Smoke",
                "value": "records-fetch",
                "value_ref": "string_ref:fetch-header-x-xtrace-smoke",
                "normalized_value_ref": "string_ref:fetch-header-x-xtrace-smoke-normalized",
            }]),
            ("Headers.set", [{
                "name": "X-Session-Token",
                "value": "header-demo",
                "value_ref": "string_ref:fetch-header-x-session-token",
                "normalized_value_ref": "string_ref:fetch-header-x-session-token-normalized",
            }]),
            ("Headers.append", [{
                "name": "x-xtrace-smoke",
                "value": "records-fetch",
                "value_ref": "string_ref:fetch-header-x-xtrace-smoke-append",
                "normalized_value_ref": "string_ref:fetch-header-x-xtrace-smoke-append-normalized",
            }]),
            ("Headers.append", [{
                "name": "x-session-token",
                "value": "header-demo",
                "value_ref": "string_ref:fetch-header-x-session-token-append",
                "normalized_value_ref": "string_ref:fetch-header-x-session-token-append-normalized",
            }]),
            ("Request.constructor", [{
                "input_type": "string",
                "method": "GET",
                "url": get_url,
                "url_ref": "string_ref:fetch-request-url",
                "headers_id": 29,
                "referrer": "",
                "has_init": True,
                "has_body": False,
                "form_data_id": 0,
                "body_search_params_id": 0,
                "body_type": None,
                "body_array_buffer_id": 0,
                "body_typed_array_id": 0,
                "body_byte_offset": 0,
                "body_byte_length": 0,
                "body": None,
                "body_hex": None,
                "body_ref": None,
                "network_correlation_key": get_key,
            }]),
            ("Request.headers.get", [{
                "method": "GET",
                "method_ref": "string_ref:fetch-request-method",
                "url": get_url,
                "url_ref": "string_ref:fetch-request-url",
                "headers_id": 29,
                "network_correlation_key": get_key,
            }]),
            ("Headers.get", [self.headers_get_args(
                "X-XTrace-Smoke",
                "records-fetch",
                headers_id=29,
            )]),
            ("Headers.get", [self.headers_get_args(
                "X-Session-Token",
                "header-demo",
                headers_id=29,
            )]),
            ("Headers.get", [self.headers_get_args(
                "X-Signature",
                "demo",
                headers_id=29,
            )]),
            ("Request.url.get", [{
                "method": "GET",
                "method_ref": "string_ref:fetch-request-method",
                "url": get_url,
                "url_ref": "string_ref:fetch-request-url",
                "network_correlation_key": get_key,
            }]),
            ("fetch", [{
                "method": "GET",
                "url": get_url,
                "url_ref": "string_ref:fetch-request-url",
                "headers_id": 29,
                "has_body": False,
                "body_byte_length": 0,
                "network_correlation_key": get_key,
            }]),
            ("Response.status.get", [{
                "response_id": 31,
                "status": 200,
                "status_ref": "number:200",
            }]),
            ("Response.url.get", [{
                "response_id": 31,
                "url": get_url,
                "url_ref": "string_ref:fetch-response-url",
            }]),
            ("Response.headers.get", [{
                "response_id": 31,
                "headers_id": 19,
            }]),
            ("Headers.get", [{
                "headers_id": 19,
                "name": "content-type",
                "name_length": len("content-type"),
                "name_ref": "string_ref:response-header-content-type-name",
                "result": "application/json",
                "result_length": len("application/json"),
                "result_ref": "string_ref:response-header-content-type-value",
                "found": True,
            }]),
            ("Headers.iterator.next", [{
                "headers_id": 19,
                "iteration_index": 0,
                "name": "content-type",
                "name_length": len("content-type"),
                "name_ref": "string_ref:response-header-iter-content-type-name",
                "value": "application/json",
                "value_length": len("application/json"),
                "value_ref": "string_ref:response-header-iter-content-type-value",
            }]),
            ("Body.json", [{
                "result": fetch_body,
                "result_length": len(fetch_body),
                "result_ref": "string_ref:fetch-json-body",
            }]),
            ("XMLHttpRequest.open", [{
                "method": "POST",
                "url": post_url,
                "url_ref": "string_ref:xhr-post-url",
                "network_correlation_key": post_key,
                "async": True,
            }]),
            ("XMLHttpRequest.setRequestHeader", [{
                "name": "Content-Type",
                "value": "application/json",
                "value_ref": "string_ref:xhr-header-content-type",
                "network_correlation_key": post_key,
            }]),
            ("XMLHttpRequest.setRequestHeader", [{
                "name": "X-XTrace-Smoke",
                "value": "business-api-xhr",
                "value_ref": "string_ref:xhr-header-x-xtrace-smoke",
                "network_correlation_key": post_key,
            }]),
            ("XMLHttpRequest.send", [{
                "xhr_id": 23,
                "method": "POST",
                "url": post_url,
                "url_ref": "string_ref:xhr-post-url",
                "network_correlation_key": post_key,
                "form_data_id": 0,
                "body_search_params_id": 0,
                "body_type": "string",
                "body_array_buffer_id": 0,
                "body_typed_array_id": 0,
                "body_byte_offset": 0,
                "body_size": 37,
                "body": post_body,
                "body_hex": None,
                "body_ref": "string_ref:xhr-body",
            }]),
            ("XMLHttpRequest.responseText", [{
                "xhr_id": 23,
                "url": post_url,
                "url_ref": "string_ref:xhr-post-url",
                "network_correlation_key": post_key,
                "status": 200,
                "value": "{}",
                "value_length": len("{}"),
                "value_ref": "string_ref:xhr-response-text",
            }]),
        ]:
            events.append(schema_v1_event(
                api,
                category="reverse",
                seq=seq,
                event_id=f"session-1:{seq}",
                args=args,
                stack=stack,
            ))
            seq += 1

        if include_signature_header_source:
            for api in ("Headers.set", "Headers.append"):
                events.append(schema_v1_event(
                    api,
                    category="reverse",
                    seq=seq,
                    event_id=f"session-1:{seq}",
                    args=[{
                        "name": "X-Signature",
                        "value": "demo",
                        "value_ref": f"string_ref:fetch-header-x-signature-{api.lower().replace('.', '-')}",
                        "normalized_value_ref": (
                            f"string_ref:fetch-header-x-signature-{api.lower().replace('.', '-')}-normalized"
                        ),
                    }],
                    stack=stack,
                ))
                seq += 1

        browser_headers = [
            self.network_header_args("Accept", "*/*"),
            self.network_header_args("Accept-Language", "zh-CN,zh;q=0.9"),
            self.network_header_args("sec-ch-ua", '"Chromium";v="151"'),
            self.network_header_args("sec-ch-ua-mobile", "?0"),
            self.network_header_args("sec-ch-ua-platform", '"macOS"'),
            self.network_header_args("User-Agent", "HeadlessChrome/151"),
        ]
        events.append(schema_v1_event(
            "BrowserNetwork.request",
            category="network",
            seq=seq,
            event_id=f"session-1:{seq}",
            args=[{
                "method": "GET",
                "url": get_url,
                "network_correlation_key": get_key,
                "headers": [
                    *browser_headers,
                    self.network_header_args("X-XTrace-Smoke", "records-fetch"),
                    self.network_header_args("X-Session-Token", "header-demo"),
                    self.network_header_args("X-Signature", "demo"),
                ],
            }],
        ))
        seq += 1
        events.append(schema_v1_event(
            "BrowserNetwork.request",
            category="network",
            seq=seq,
            event_id=f"session-1:{seq}",
            args=[{
                "method": "POST",
                "url": post_url,
                "network_correlation_key": post_key,
                "headers": [
                    *browser_headers,
                    self.network_header_args("Content-Type", "application/json"),
                    self.network_header_args("X-XTrace-Smoke", "business-api-xhr"),
                ],
                "upload_body": {
                    "total_bytes": 37,
                    "body_hex": "7B22637572736F72223A2232222C22626F64795F6D61726B6572223A22787472616365227D",
                    "body_sha256": "359d6b8d6ceddf13ae17d6d87cb21e25b4038bf641a5bb3d30fcd1b4e51e6fd5",
                },
            }],
        ))
        return events

    def test_reverse_profile_includes_url_mutation_and_request_constructor_hooks(self):
        for api in [
            "URLSearchParams.append",
            "URLSearchParams.set",
            "URLSearchParams.sort",
            "URLSearchParams.toString",
            "URLSearchParams.get",
            "URLSearchParams.getAll",
            "URLSearchParams.has",
            "URLSearchParams.iterator.next",
            "URL.constructor",
            "URL.href.get",
            "URL.search.get",
            "URL.href.set",
            "URL.search.set",
            "Location.href.get",
            "Location.search.get",
            "Location.href.set",
            "Location.search.set",
            "Location.assign",
            "Location.replace",
            "Document.urlForBinding.get",
            "Document.referrer.get",
            "Node.baseURI.get",
            "Headers.constructor",
            "Headers.append",
            "Headers.set",
            "Headers.delete",
            "btoa",
            "atob",
            "TextEncoder.constructor",
            "TextEncoder.encode",
            "TextEncoder.encodeInto",
            "TextDecoder.constructor",
            "TextDecoder.decode",
            "Crypto.getRandomValues",
            "Crypto.randomUUID",
            "SubtleCrypto.encrypt",
            "SubtleCrypto.decrypt",
            "SubtleCrypto.digest",
            "SubtleCrypto.verify",
            "SubtleCrypto.generateKey",
            "SubtleCrypto.exportKey",
            "SubtleCrypto.deriveBits",
            "SubtleCrypto.deriveKey",
            "SubtleCrypto.wrapKey",
            "SubtleCrypto.unwrapKey",
            "ArrayBuffer.constructor",
            "ArrayBuffer.prototype.slice",
            "DataView.getInt8",
            "DataView.getInt16",
            "DataView.getUint32",
            "DataView.setUint32",
            "DataView.setInt8",
            "DataView.setInt16",
            "DataView.getBigUint64",
            "DataView.getBigInt64",
            "DataView.setBigUint64",
            "DataView.setBigInt64",
            "DataView.getFloat16",
            "DataView.getFloat32",
            "DataView.getFloat64",
            "DataView.setFloat16",
            "DataView.setFloat32",
            "DataView.setFloat64",
            "TypedArray.at",
            "TypedArray.slice",
            "TypedArray.subarray",
            "TypedArray.set",
            "TypedArray.copyWithin",
            "TypedArray.fill",
            "TypedArray.reverse",
            "TypedArray.sort",
            "TypedArray.join",
            "TypedArray.indexOf",
            "TypedArray.includes",
            "TypedArray.lastIndexOf",
            "TypedArray.find",
            "TypedArray.findIndex",
            "TypedArray.findLast",
            "TypedArray.findLastIndex",
            "TypedArray.reduce",
            "TypedArray.reduceRight",
            "TypedArray.filter",
            "TypedArray.every",
            "TypedArray.some",
            "TypedArray.forEach",
            "TypedArray.entries",
            "TypedArray.keys",
            "TypedArray.values",
            "Array.from",
            "Array.of",
            "Array.prototype.at",
            "Array.prototype.indexOf",
            "Array.prototype.includes",
            "Array.prototype.lastIndexOf",
            "Array.prototype.find",
            "Array.prototype.findIndex",
            "Array.prototype.findLast",
            "Array.prototype.findLastIndex",
            "Array.prototype.reduce",
            "Array.prototype.reduceRight",
            "Array.prototype.map",
            "Array.prototype.filter",
            "Array.prototype.every",
            "Array.prototype.some",
            "Array.prototype.forEach",
            "Array.prototype.push",
            "Array.prototype.pop",
            "Array.prototype.unshift",
            "Array.prototype.shift",
            "Array.prototype.splice",
            "Array.prototype.reverse",
            "Array.prototype.sort",
            "Array.prototype.copyWithin",
            "Array.prototype.fill",
            "Array.prototype.slice",
            "Array.prototype.join",
            "Array.prototype.entries",
            "Array.prototype.keys",
            "Array.prototype.values",
            "ArrayIterator.prototype.next",
            "Reflect.construct",
            "Object.keys",
            "Object.prototype.toString",
            "Array.isArray",
            "Object.is",
            "Object.hasOwn",
            "Object.prototype.hasOwnProperty",
            "Object.prototype.propertyIsEnumerable",
            "Object.assign",
            "Object.create",
            "Object.getPrototypeOf",
            "Object.setPrototypeOf",
            "Object.preventExtensions",
            "Object.freeze",
            "Object.seal",
            "Object.isExtensible",
            "Object.isFrozen",
            "Object.isSealed",
            "Object.getOwnPropertyDescriptor",
            "Object.getOwnPropertyDescriptors",
            "Object.defineProperty",
            "Object.defineProperties",
            "Object.values",
            "Object.entries",
            "Object.getOwnPropertyNames",
            "Reflect.getPrototypeOf",
            "Reflect.setPrototypeOf",
            "Reflect.preventExtensions",
            "Reflect.isExtensible",
            "Reflect.defineProperty",
            "Reflect.ownKeys",
            "Reflect.getOwnPropertyDescriptor",
            "Reflect.get",
            "Reflect.set",
            "Reflect.has",
            "Reflect.deleteProperty",
            "Map.prototype.get",
            "Map.prototype.has",
            "Map.prototype.set",
            "Map.prototype.delete",
            "Map.prototype.clear",
            "Map.prototype.getOrInsert",
            "Map.prototype.getOrInsertComputed",
            "Map.prototype.forEach",
            "Map.prototype.entries",
            "Map.prototype.keys",
            "Map.prototype.values",
            "Set.prototype.add",
            "Set.prototype.has",
            "Set.prototype.delete",
            "Set.prototype.clear",
            "Set.prototype.forEach",
            "Set.prototype.entries",
            "Set.prototype.values",
            "MapIterator.prototype.next",
            "SetIterator.prototype.next",
            "WeakMap.prototype.get",
            "WeakMap.prototype.has",
            "WeakMap.prototype.set",
            "WeakMap.prototype.delete",
            "WeakMap.prototype.getOrInsert",
            "WeakMap.prototype.getOrInsertComputed",
            "WeakSet.prototype.add",
            "WeakSet.prototype.has",
            "WeakSet.prototype.delete",
            "Proxy.get",
            "Proxy.set",
            "Proxy.has",
            "Proxy.ownKeys",
            "Proxy.getOwnPropertyDescriptor",
            "Proxy.defineProperty",
            "Proxy.deleteProperty",
            "String.fromCharCode",
            "String.fromCodePoint",
            "String.prototype.charCodeAt",
            "String.prototype.codePointAt",
            "String.prototype.charAt",
            "String.prototype.concat",
            "StringAdd",
            "StringAdd.constant_lhs",
            "StringAdd.constant_rhs",
            "String.prototype.slice",
            "String.prototype.substring",
            "String.prototype.substr",
            "String.prototype.padStart",
            "String.prototype.padEnd",
            "String.prototype.repeat",
            "String.prototype.startsWith",
            "String.prototype.endsWith",
            "String.prototype.trim",
            "String.prototype.trimStart",
            "String.prototype.trimEnd",
            "String.prototype.@@iterator",
            "StringIterator.prototype.next",
            "Number.prototype.toString",
            "BigInt.prototype.toString",
            "String.prototype.indexOf",
            "String.prototype.lastIndexOf",
            "String.prototype.includes",
            "String.prototype.replace",
            "String.prototype.replaceAll",
            "String.prototype.split",
            "String.prototype.matchAll",
            "RegExp.prototype.test",
            "RegExp.prototype.exec",
            "RegExp.prototype.@@search",
            "RegExp.prototype.@@match",
            "RegExp.prototype.@@matchAll",
            "RegExp.prototype.@@split",
            "RegExp.prototype.@@replace",
            "RegExpStringIterator.prototype.next",
            "Math.imul",
            "Bitwise.and",
            "Bitwise.or",
            "Bitwise.xor",
            "Bitwise.not",
            "Shift.left",
            "Shift.right",
            "Shift.unsignedRight",
            "Math.random",
            "Performance.now",
            "Date.now",
            "console.debug",
            "console.clear",
            "debugger.statement",
            "Function.prototype.toString",
            "Error.captureStackTrace",
            "Error.stack.get",
            "Error.constructor",
            "Exception.throw",
            "Request.constructor",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)

    def test_reverse_profile_requires_smoke_exercised_byte_buffer_and_hmac_hooks(self):
        for api in [
            "DataView.getInt8",
            "DataView.getInt16",
            "DataView.getUint8",
            "DataView.getUint16",
            "DataView.getInt32",
            "DataView.getBigUint64",
            "DataView.getBigInt64",
            "DataView.getFloat16",
            "DataView.getFloat32",
            "DataView.getFloat64",
            "DataView.setInt8",
            "DataView.setInt16",
            "DataView.setUint8",
            "DataView.setUint16",
            "DataView.setInt32",
            "DataView.setBigUint64",
            "DataView.setBigInt64",
            "DataView.setFloat16",
            "DataView.setFloat32",
            "DataView.setFloat64",
            "TypedArray.subarray",
            "TypedArray.set",
            "TypedArray.copyWithin",
            "TypedArray.fill",
            "TypedArray.reverse",
            "TypedArray.sort",
            "SubtleCrypto.encrypt",
            "SubtleCrypto.decrypt",
            "SubtleCrypto.importKey",
            "SubtleCrypto.sign",
            "SubtleCrypto.verify",
            "SubtleCrypto.generateKey",
            "SubtleCrypto.exportKey",
            "SubtleCrypto.deriveBits",
            "SubtleCrypto.deriveKey",
            "SubtleCrypto.wrapKey",
            "SubtleCrypto.unwrapKey",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)

    def test_reverse_profile_requires_stable_smoke_network_material_hooks(self):
        for api in [
            "URLSearchParams.constructor",
            "XMLHttpRequest.setRequestHeader",
            "XMLHttpRequest.responseText",
            "Headers.get",
            "Headers.has",
            "Headers.iterator.next",
            "Request.method.get",
            "Request.url.get",
            "Request.headers.get",
            "Request.clone",
            "Response.type.get",
            "Response.status.get",
            "Response.redirected.get",
            "Response.ok.get",
            "Response.url.get",
            "Response.statusText.get",
            "Response.headers.get",
            "Response.clone",
            "Body.text",
            "Body.json",
            "Body.arrayBuffer",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)

    def test_reverse_profile_requires_formdata_material_hooks(self):
        for api in [
            "FormData.constructor",
            "FormData.append",
            "FormData.set",
            "FormData.get",
            "FormData.getAll",
            "FormData.has",
            "FormData.delete",
            "FormData.iterator.next",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)

    def test_reverse_profile_includes_async_event_flow_hooks(self):
        for api in [
            "EventTarget.addEventListener",
            "EventTarget.removeEventListener",
            "EventTarget.dispatchEvent",
            "EventTarget.listener.invoke",
            "queueMicrotask",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)

    def test_reverse_profile_includes_promise_async_chain_hooks(self):
        for api in [
            "Promise.prototype.then",
            "Promise.prototype.catch",
            "Promise.prototype.finally",
            "Promise.resolve",
            "Promise.reject",
            "Promise.all",
            "Promise.allSettled",
            "Promise.race",
            "Promise.any",
            "Promise.try",
            "Promise.withResolvers",
            "Array.fromAsync",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)

    def test_reverse_profile_includes_script_execution_hooks(self):
        for api in [
            "ClassicScript.evaluate",
            "ModuleScript.evaluate",
            "DynamicImport.resolve",
            "DynamicImport.load",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)

    def test_reverse_profile_requires_storage_and_cookie_input_material_hooks(self):
        for api in [
            "Storage.getItem",
            "Storage.setItem",
            "Storage.removeItem",
            "Storage.key",
            "Storage.clear",
            "Document.cookie.get",
            "Document.cookie.set",
            "CookieStore.get",
            "CookieStore.getAll",
            "CookieStore.set",
            "CookieStore.delete",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)

    def test_load_events_rejects_malformed_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.ndjson"
            path.write_text('{"api":"CanvasRenderingContext2D.fillText"}\nnot-json\n', encoding="utf-8")
            with self.assertRaises(TraceValidationError) as ctx:
                load_events(path)
            self.assertIn("line 2", str(ctx.exception))

    def test_validate_trace_finds_expected_apis(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            expected = [
                "CanvasRenderingContext2D.fillText",
                "CanvasRenderingContext2D.getImageData",
                "HTMLCanvasElement.toDataURL",
                "Crypto.getRandomValues",
                "Navigator.platform",
                "Navigator.webdriver",
                "Navigator.cookieEnabled",
                "Screen.width",
                "Screen.height",
                "Screen.colorDepth",
                "WebGLRenderingContext.getParameter",
                "WebGLRenderingContext.getSupportedExtensions",
                "WebGLRenderingContext.getExtension",
                "WebGLRenderingContext.readPixels",
                "AudioContext.constructor",
                "OfflineAudioContext.constructor",
                "BaseAudioContext.createAnalyser",
                "BaseAudioContext.createOscillator",
                "Permissions.query",
                "MediaDevices.enumerateDevices",
                "RTCPeerConnection.constructor",
                "Intl.DateTimeFormat.constructor",
                "Intl.DateTimeFormat.resolvedOptions",
            ]
            path.write_text(
                "\n".join(
                    json.dumps({"t": "call", "api": api, "args": []})
                    for api in expected
                )
                + "\n",
                encoding="utf-8",
            )
            validate_trace(path, expected=expected)

    def test_validate_schema_v1_requires_core_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event("Crypto.getRandomValues")
            del event["event_id"]
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(path, expected=["Crypto.getRandomValues"], schema_version=1)

            self.assertIn("event_id", str(ctx.exception))

    def test_validate_schema_v1_accepts_truncation_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "Storage.setItem",
                category="reverse",
                truncated=True,
                truncation={
                    "original_size": 524288,
                    "preview": "aaaa",
                    "hash": "sha256:abcdef",
                },
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            validate_trace(path, expected=["Storage.setItem"], schema_version=1)

    def test_validate_trace_rejects_truncation_when_complete_values_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "Storage.setItem",
                category="reverse",
                truncated=True,
                truncation={
                    "original_size": 524288,
                    "preview": "aaaa",
                    "hash": "sha256:abcdef",
                },
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=["Storage.setItem"],
                    schema_version=1,
                    require_complete_values=True,
                )

            self.assertIn("truncated event 1: Storage.setItem", str(ctx.exception))

    def test_validate_trace_rejects_preview_fields_when_complete_values_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "String.prototype.substr",
                category="reverse",
                args=[{"subject_ref": "string:length:40", "result_preview": "X-Signature=secret"}],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=["String.prototype.substr"],
                    schema_version=1,
                    require_complete_values=True,
                )

            self.assertIn("preview field event 1: args[0].result_preview", str(ctx.exception))

    def test_validate_trace_rejects_redacted_markers_when_complete_values_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "Request.constructor",
                category="reverse",
                args=[{
                    "method": "GET",
                    "url": "https://www.example.test/api/feed",
                    "headers": [{"name": "x-signature", "value": "<redacted>"}],
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=["Request.constructor"],
                    schema_version=1,
                    require_complete_values=True,
                )

            self.assertIn("redacted marker event 1: args[0].headers[0].value", str(ctx.exception))

    def test_validate_trace_rejects_summary_refs_when_material_refs_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "String.prototype.substr",
                category="reverse",
                args=[{
                    "subject": "input-material",
                    "subject_ref": "string:length:14",
                    "result": "X-Signature=secret",
                    "result_ref": "string:length:14",
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=["String.prototype.substr"],
                    schema_version=1,
                    require_material_refs=True,
                )

            self.assertIn("summary ref event 1: args[0].subject_ref", str(ctx.exception))
            self.assertIn("args[0].result_ref", str(ctx.exception))

    def test_validate_trace_rejects_byte_and_array_summary_refs_when_material_refs_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "TypedArray.slice",
                category="reverse",
                args=[{
                    "source_ref": "bytes:length:8",
                    "result_ref": "array:length:2",
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=["TypedArray.slice"],
                    schema_version=1,
                    require_material_refs=True,
                )

            self.assertIn("summary ref event 1: args[0].source_ref", str(ctx.exception))
            self.assertIn("args[0].result_ref", str(ctx.exception))

    def test_validate_trace_rejects_opaque_refs_without_raw_material_when_material_refs_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "String.prototype.slice",
                category="reverse",
                args=[{
                    "subject_ref": "string_ref:fnv1a64:111:length:12",
                    "result_ref": "string_ref:fnv1a64:222:length:8",
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=["String.prototype.slice"],
                    schema_version=1,
                    require_material_refs=True,
                )

            self.assertIn("opaque ref event 1: args[0].subject_ref", str(ctx.exception))
            self.assertIn("args[0].result_ref", str(ctx.exception))

    def test_validate_trace_accepts_stable_refs_when_material_refs_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "Headers.set",
                category="reverse",
                args=[{
                    "name": "X-Signature",
                    "value": "secret",
                    "value_ref": "string_ref:sha1:abcdef",
                    "normalized_value": "secret",
                    "normalized_value_ref": "string_ref:sha1:abcdef",
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            validate_trace(
                path,
                expected=["Headers.set"],
                schema_version=1,
                require_material_refs=True,
            )

    def test_validate_trace_accepts_serialized_material_for_result_ref(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "URLSearchParams.toString",
                category="reverse",
                args=[{
                    "serialized": "a=1",
                    "serialized_length": 3,
                    "serialized_ref": "string_ref:sha1:abcdef",
                    "result_ref": "string_ref:sha1:abcdef",
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            validate_trace(
                path,
                expected=["URLSearchParams.toString"],
                schema_version=1,
                require_material_refs=True,
            )

    def test_validate_schema_v1_rejects_truncated_event_without_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event("Storage.setItem", truncated=True)
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(path, expected=["Storage.setItem"], schema_version=1)

            self.assertIn("truncation", str(ctx.exception))

    def test_validate_trace_can_require_stack_for_selected_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "Request.constructor",
                category="reverse",
                stack=[
                    {
                        "function": "buildSignedRequest",
                        "url": "https://example.test/app.js",
                        "line": 10,
                        "column": 2,
                    }
                ],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            validate_trace(
                path,
                expected=["Request.constructor"],
                schema_version=1,
                require_stack_for=["Request.constructor"],
            )

    def test_validate_trace_rejects_missing_required_stack(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event("Request.constructor", category="reverse")
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=["Request.constructor"],
                    schema_version=1,
                    require_stack_for=["Request.constructor"],
                )

            self.assertIn("non-empty stack", str(ctx.exception))

    def test_validate_trace_can_require_vmp_families(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event("DataView.getUint32", category="reverse", seq=1, event_id="session-1:1"),
                schema_v1_event("Proxy.get", category="reverse", seq=2, event_id="session-1:2"),
                schema_v1_event("Bitwise.xor", category="reverse", seq=3, event_id="session-1:3"),
                schema_v1_event("Performance.now", category="reverse", seq=4, event_id="session-1:4"),
                schema_v1_event("debugger.statement", category="reverse", seq=5, event_id="session-1:5"),
                schema_v1_event("Function.prototype.toString", category="reverse", seq=6, event_id="session-1:6"),
                schema_v1_event("Error.captureStackTrace", category="reverse", seq=7, event_id="session-1:7"),
                schema_v1_event("Error.stack.get", category="reverse", seq=8, event_id="session-1:8"),
                schema_v1_event("Error.constructor", category="reverse", seq=9, event_id="session-1:9"),
                schema_v1_event("Exception.throw", category="reverse", seq=10, event_id="session-1:10"),
                schema_v1_event("String.prototype.slice", category="reverse", seq=11, event_id="session-1:11"),
                schema_v1_event("RegExp.prototype.test", category="reverse", seq=12, event_id="session-1:12"),
                schema_v1_event("encodeURIComponent", category="reverse", seq=13, event_id="session-1:13"),
                schema_v1_event("Function.prototype.call.call", category="reverse", seq=14, event_id="session-1:14"),
                schema_v1_event("Function.prototype.apply.call", category="reverse", seq=15, event_id="session-1:15"),
                schema_v1_event("BigInt.prototype.toString", category="reverse", seq=16, event_id="session-1:16"),
                schema_v1_event("Math.random", category="reverse", seq=17, event_id="session-1:17"),
            ]
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            validate_trace(
                path,
                expected=[],
                schema_version=1,
                require_vmp_families=[
                    "byte_buffer",
                    "proxy_trap",
                    "int_bitwise",
                    "anti_debug_timing",
                    "source_probe",
                    "stack_probe",
                    "exception_probe",
                    "string_transform",
                    "regexp_probe",
                    "url_encoding",
                    "dynamic_dispatch",
                    "random_source",
                ],
            )

    def test_validate_trace_requires_bigint_to_string_material_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "BigInt.prototype.toString",
                category="reverse",
                args=[{
                    "shape": "bigint_to_string",
                    "radix": 16,
                    "result_preview": "1234",
                    "result_ref": "string:length:4",
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            validate_trace(
                path,
                expected=["BigInt.prototype.toString"],
                schema_version=1,
                require_arg_fields=["BigInt.prototype.toString:result_ref"],
                require_vmp_families=["string_transform"],
            )

    def test_validate_trace_can_require_promise_async_vmp_family(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event("Promise.prototype.then", category="reverse")
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            validate_trace(
                path,
                expected=[],
                schema_version=1,
                require_vmp_families=["async_flow"],
            )

    def test_array_from_async_can_satisfy_async_vmp_family(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event("Array.fromAsync", category="reverse")
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            validate_trace(
                path,
                expected=[],
                schema_version=1,
                require_vmp_families=["async_flow"],
            )

    def test_validate_trace_can_require_script_execution_vmp_family(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event("ClassicScript.evaluate", category="reverse")
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            validate_trace(
                path,
                expected=[],
                schema_version=1,
                require_vmp_families=["script_execution"],
            )

    def test_validate_trace_rejects_missing_vmp_family(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event("TextEncoder.encode", category="reverse")
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_families=["byte_buffer"],
                )

            self.assertIn("Missing expected VMP families: byte_buffer", str(ctx.exception))

    def test_validate_trace_rejects_vmp_family_without_material_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event("DataView.getUint32", category="reverse")
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_families=["byte_buffer"],
                    require_vmp_family_evidence=True,
                )

            self.assertIn("Missing VMP family evidence: byte_buffer", str(ctx.exception))

    def test_validate_trace_rejects_vmp_family_with_only_stack_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "DataView.getUint32",
                category="reverse",
                stack=[{
                    "function": "decode",
                    "url": "https://example.test/vmp.js",
                    "line": 10,
                    "column": 4,
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_families=["byte_buffer"],
                    require_vmp_family_evidence=True,
                )

            self.assertIn("Missing VMP family evidence: byte_buffer", str(ctx.exception))

    def test_validate_trace_rejects_vmp_family_with_only_metadata_args(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "DataView.getUint32",
                category="reverse",
                args=[{
                    "byte_offset": 4,
                    "little_endian": False,
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_families=["byte_buffer"],
                    require_vmp_family_evidence=True,
                )

            self.assertIn("Missing VMP family evidence: byte_buffer", str(ctx.exception))

    def test_validate_trace_rejects_vmp_family_with_only_summary_ref(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "String.prototype.slice",
                category="reverse",
                args=[{"result_ref": "string:length:10"}],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_families=["string_transform"],
                    require_vmp_family_evidence=True,
                )

            self.assertIn("Missing VMP family evidence: string_transform", str(ctx.exception))

    def test_validate_trace_rejects_vmp_family_with_only_shape_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "BigInt.prototype.toString",
                category="reverse",
                args=[{"shape": "bigint_to_string", "radix": 16}],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_families=["string_transform"],
                    require_vmp_family_evidence=True,
                )

            self.assertIn("Missing VMP family evidence: string_transform", str(ctx.exception))

    def test_validate_trace_rejects_vmp_family_with_only_algorithm_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "SubtleCrypto.sign",
                category="reverse",
                args=[{"algorithm": "HMAC"}],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_families=["hash_crypto"],
                    require_vmp_family_evidence=True,
                )

            self.assertIn("Missing VMP family evidence: hash_crypto", str(ctx.exception))

    def test_validate_trace_accepts_vmp_family_with_material_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "DataView.getUint32",
                category="reverse",
                args=[{
                    "byte_offset": 4,
                    "little_endian": False,
                    "result": 3735928559,
                    "result_ref": "number:3735928559",
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            validate_trace(
                path,
                expected=[],
                schema_version=1,
                require_vmp_families=["byte_buffer"],
                require_vmp_family_evidence=True,
            )

    def test_validate_trace_can_require_arg_fields_for_selected_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "Bitwise.xor",
                category="reverse",
                args=[{
                    "left": 1,
                    "left_ref": "number:1.000000",
                    "right": 2,
                    "right_ref": "number:2.000000",
                    "result": 3,
                    "result_ref": "number:3.000000",
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            validate_trace(
                path,
                expected=["Bitwise.xor"],
                schema_version=1,
                require_arg_fields=["Bitwise.xor:left_ref", "Bitwise.xor:result_ref"],
            )

    def test_validate_trace_rejects_missing_required_arg_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "Bitwise.xor",
                category="reverse",
                args=[{"left": 1, "right": 2, "result": 3}],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=["Bitwise.xor"],
                    schema_version=1,
                    require_arg_fields=["Bitwise.xor:left_ref"],
                )

            self.assertIn("Expected arg fields", str(ctx.exception))

    def test_validate_trace_rejects_empty_required_arg_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "Bitwise.xor",
                category="reverse",
                args=[{
                    "left_ref": "number:1.000000",
                    "right_ref": "number:2.000000",
                    "result_ref": "",
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=["Bitwise.xor"],
                    schema_version=1,
                    require_arg_fields=["Bitwise.xor:result_ref"],
                )

            self.assertIn("Expected arg fields", str(ctx.exception))
            self.assertIn("Bitwise.xor:result_ref", str(ctx.exception))

    def test_validate_trace_rejects_redacted_required_arg_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "Request.constructor",
                category="reverse",
                args=[{
                    "method": "GET",
                    "url": "https://www.example.test/api/feed",
                    "url_ref": "<redacted>",
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=["Request.constructor"],
                    schema_version=1,
                    require_arg_fields=["Request.constructor:url_ref"],
                )

            self.assertIn("Expected arg fields", str(ctx.exception))
            self.assertIn("Request.constructor:url_ref", str(ctx.exception))

    def test_validate_trace_can_require_vmp_next_hook_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "Function.prototype.call",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{"target_id": "function:sign"}],
                ),
                schema_v1_event(
                    "Function.prototype.apply",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"target_id": "function:encode"}],
                ),
                schema_v1_event(
                    "Reflect.apply",
                    category="reverse",
                    seq=3,
                    event_id="session-1:3",
                    args=[{"target_id": "function:mix"}],
                ),
                schema_v1_event(
                    "Reflect.construct",
                    category="reverse",
                    seq=68,
                    event_id="session-1:68",
                    args=[{
                        "target_ref": "function:ctor",
                        "arguments_list_ref": "object:args",
                        "new_target_ref": "function:new-target",
                        "arg_count": 2,
                    }],
                ),
                schema_v1_event(
                    "Reflect.construct",
                    category="reverse",
                    seq=69,
                    event_id="session-1:69",
                    args=[{"result_ref": "object:constructed"}],
                ),
                schema_v1_event(
                    "String.fromCharCode",
                    category="reverse",
                    seq=4,
                    event_id="session-1:4",
                    args=[{"first_code_ref": "number:65", "result_ref": "string:A"}],
                ),
                schema_v1_event(
                    "String.prototype.slice",
                    category="reverse",
                    seq=6,
                    event_id="session-1:6",
                    args=[{
                        "subject_ref": "string:length:40",
                        "result_ref": "string:length:39",
                    }],
                ),
                schema_v1_event(
                    "encodeURIComponent",
                    category="reverse",
                    seq=7,
                    event_id="session-1:7",
                    args=[self.uri_codec_args("cursor=1&token=a b", "cursor%3D1%26token%3Da%20b")],
                ),
                schema_v1_event(
                    "Bitwise.xor",
                    category="reverse",
                    seq=8,
                    event_id="session-1:8",
                    args=[{"left_ref": "number:1", "right_ref": "number:2", "result_ref": "number:3"}],
                ),
                schema_v1_event(
                    "URLSearchParams.set",
                    category="reverse",
                    seq=9,
                    event_id="session-1:9",
                    args=[self.url_search_params_set_args("X-Signature", "secret-one")],
                ),
                schema_v1_event(
                    "URLSearchParams.toString",
                    category="reverse",
                    seq=10,
                    event_id="session-1:10",
                    args=[self.url_search_params_to_string_args()],
                ),
                schema_v1_event(
                    "URL.href.set",
                    category="reverse",
                    seq=11,
                    event_id="session-1:11",
                    args=[{"value_ref": "string:length:27", "href_ref": "string:length:27"}],
                ),
                schema_v1_event(
                    "URL.search.set",
                    category="reverse",
                    seq=12,
                    event_id="session-1:12",
                    args=[{
                        "value_ref": "string:length:27",
                        "search_ref": "string:length:27",
                        "href_ref": "string:length:64",
                    }],
                ),
                schema_v1_event(
                    "Location.href.get",
                    category="reverse",
                    seq=25,
                    event_id="session-1:25",
                    args=[self.location_read_args("https://www.example.test/api/records/list/?cursor=1")],
                ),
                schema_v1_event(
                    "Location.search.get",
                    category="reverse",
                    seq=26,
                    event_id="session-1:26",
                    args=[self.location_read_args(
                        "?cursor=1",
                        href="https://www.example.test/api/records/list/?cursor=1",
                    )],
                ),
                schema_v1_event(
                    "Location.href.set",
                    category="reverse",
                    seq=27,
                    event_id="session-1:27",
                    args=[self.location_write_args(
                        "/api/records/list/?cursor=2",
                        "https://www.example.test/api/records/list/?cursor=2",
                    )],
                ),
                schema_v1_event(
                    "Location.search.set",
                    category="reverse",
                    seq=28,
                    event_id="session-1:28",
                    args=[self.location_write_args(
                        "?cursor=2&X-Signature=secret-one",
                        "https://www.example.test/api/records/list/?cursor=2&X-Signature=secret-one",
                    )],
                ),
                schema_v1_event(
                    "Location.assign",
                    category="reverse",
                    seq=29,
                    event_id="session-1:29",
                    args=[self.location_write_args(
                        "/api/records/list/?cursor=3",
                        "https://www.example.test/api/records/list/?cursor=3",
                    )],
                ),
                schema_v1_event(
                    "Location.replace",
                    category="reverse",
                    seq=30,
                    event_id="session-1:30",
                    args=[self.location_write_args(
                        "/api/records/list/?cursor=4",
                        "https://www.example.test/api/records/list/?cursor=4",
                    )],
                ),
                schema_v1_event(
                    "Storage.getItem",
                    category="reverse",
                    seq=14,
                    event_id="session-1:14",
                    args=[self.storage_get_item_args("sessionToken", "token-value")],
                ),
                schema_v1_event(
                    "Storage.setItem",
                    category="reverse",
                    seq=15,
                    event_id="session-1:15",
                    args=[self.storage_set_item_args("x-signature-seed", "seed-value")],
                ),
                schema_v1_event(
                    "Storage.removeItem",
                    category="reverse",
                    seq=16,
                    event_id="session-1:16",
                    args=[self.storage_remove_item_args("old-token")],
                ),
                schema_v1_event(
                    "Storage.key",
                    category="reverse",
                    seq=17,
                    event_id="session-1:17",
                    args=[self.storage_key_args("sessionToken")],
                ),
                schema_v1_event(
                    "Document.cookie.get",
                    category="reverse",
                    seq=18,
                    event_id="session-1:18",
                    args=[self.document_cookie_get_args("sessionToken=token-value")],
                ),
                schema_v1_event(
                    "Document.cookie.set",
                    category="reverse",
                    seq=19,
                    event_id="session-1:19",
                    args=[self.document_cookie_set_args("x-signature-seed=seed-value; path=/")],
                ),
                schema_v1_event(
                    "Document.urlForBinding.get",
                    category="reverse",
                    seq=31,
                    event_id="session-1:31",
                    args=[self.document_context_args("https://www.example.test/api/records/list/?cursor=1")],
                ),
                schema_v1_event(
                    "Document.referrer.get",
                    category="reverse",
                    seq=32,
                    event_id="session-1:32",
                    args=[self.document_context_args("https://www.example.test/from-feed")],
                ),
                schema_v1_event(
                    "Node.baseURI.get",
                    category="reverse",
                    seq=33,
                    event_id="session-1:33",
                    args=[self.document_context_args("https://www.example.test/")],
                ),
                schema_v1_event(
                    "CookieStore.get",
                    category="reverse",
                    seq=20,
                    event_id="session-1:20",
                    args=[self.cookie_store_get_args("sessionToken")],
                ),
                schema_v1_event(
                    "CookieStore.getAll",
                    category="reverse",
                    seq=21,
                    event_id="session-1:21",
                    args=[self.cookie_store_get_args("sessionToken", result_count=2)],
                ),
                schema_v1_event(
                    "CookieStore.set",
                    category="reverse",
                    seq=22,
                    event_id="session-1:22",
                    args=[self.cookie_store_set_args("x-signature-seed", "seed-value")],
                ),
                schema_v1_event(
                    "CookieStore.delete",
                    category="reverse",
                    seq=23,
                    event_id="session-1:23",
                    args=[self.cookie_store_delete_args("old-token")],
                ),
                schema_v1_event(
                    "BigInt.prototype.toString",
                    category="reverse",
                    seq=24,
                    event_id="session-1:24",
                    args=[{"result_ref": "string:length:4"}],
                ),
            ]
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            validate_trace(
                path,
                expected=[],
                schema_version=1,
                require_vmp_next_hook_fields=True,
            )

    def test_validate_trace_requires_uri_codec_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    api,
                    category="reverse",
                    seq=index,
                    event_id=f"session-1:{index}",
                    args=[{"input_ref": "string_ref:input", "result_ref": "string_ref:result"}],
                )
                for index, api in enumerate(
                    [
                        "encodeURI",
                        "encodeURIComponent",
                        "decodeURI",
                        "decodeURIComponent",
                    ],
                    start=1,
                )
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in ["encodeURI", "encodeURIComponent", "decodeURI", "decodeURIComponent"]:
                self.assertIn(f"{api}:input", message)
                self.assertIn(f"{api}:input_length", message)
                self.assertIn(f"{api}:result", message)
                self.assertIn(f"{api}:result_length", message)

    def test_validate_trace_rejects_missing_vmp_next_hook_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "Function.prototype.call",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{"target_id": "function:sign"}],
                ),
                schema_v1_event(
                    "Function.prototype.apply",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"target_id": "function:encode", "result_ref": "array:1"}],
                ),
                schema_v1_event(
                    "Reflect.apply",
                    category="reverse",
                    seq=3,
                    event_id="session-1:3",
                    args=[{"target_id": "function:mix", "result_ref": "number:42"}],
                ),
                schema_v1_event(
                    "String.fromCharCode",
                    category="reverse",
                    seq=4,
                    event_id="session-1:4",
                    args=[{"first_code_ref": "number:65", "result_ref": "string:A"}],
                ),
                schema_v1_event(
                    "Bitwise.xor",
                    category="reverse",
                    seq=5,
                    event_id="session-1:5",
                    args=[{"left_ref": "number:1", "right_ref": "number:2"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            self.assertIn("Bitwise.xor:result_ref", str(ctx.exception))

    def test_validate_trace_requires_storage_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = self.vmp_next_core_events()
            events = [event for event in events if event["api"] != "Storage.setItem"]
            events.append(schema_v1_event(
                "Storage.setItem",
                category="reverse",
                seq=100,
                event_id="session-1:100",
                args=[{"storage": "localStorage", "key": "x-signature-seed", "value": "seed-value"}],
            ))
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("Storage.setItem:key_length", message)
            self.assertIn("Storage.setItem:key_ref", message)
            self.assertIn("Storage.setItem:value_length", message)
            self.assertIn("Storage.setItem:value_ref", message)

    def test_validate_trace_requires_document_cookie_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = self.vmp_next_core_events()
            events = [event for event in events if event["api"] != "Document.cookie.set"]
            events.append(schema_v1_event(
                "Document.cookie.set",
                category="reverse",
                seq=100,
                event_id="session-1:100",
                args=[{"value": "x-signature-seed=seed-value; path=/"}],
            ))
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("Document.cookie.set:value_length", message)
            self.assertIn("Document.cookie.set:value_ref", message)
            self.assertIn("Document.cookie.set:accepted", message)

    def test_validate_trace_requires_cookie_store_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = self.vmp_next_core_events()
            events = [event for event in events if event["api"] != "CookieStore.set"]
            events.append(schema_v1_event(
                "CookieStore.set",
                category="reverse",
                seq=100,
                event_id="session-1:100",
                args=[{
                    "name": "x-signature-seed",
                    "value": "seed-value",
                    "accepted": True,
                }],
            ))
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("CookieStore.set:name_length", message)
            self.assertIn("CookieStore.set:name_ref", message)
            self.assertIn("CookieStore.set:value_length", message)
            self.assertIn("CookieStore.set:value_ref", message)

    def test_validate_trace_requires_cookie_store_read_result_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = self.vmp_next_core_events()
            events = [event for event in events if event["api"] != "CookieStore.get"]
            events.append(schema_v1_event(
                "CookieStore.get",
                category="reverse",
                phase="return",
                seq=100,
                event_id="session-1:100",
                args=[{
                    "name": "sessionToken",
                    "name_length": 7,
                    "name_ref": "string_ref:cookie-name",
                    "cookie_url": "https://www.example.test/path",
                    "cookie_url_ref": "string_ref:cookie-url",
                    "result_count": 1,
                    "result_name_refs": ["string_ref:cookie-name"],
                    "result_value_refs": ["string_ref:cookie-value"],
                }],
            ))
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("CookieStore.get:result_names", message)
            self.assertIn("CookieStore.get:result_name_lengths", message)
            self.assertIn("CookieStore.get:result_values", message)
            self.assertIn("CookieStore.get:result_value_lengths", message)

    def test_validate_trace_requires_json_parse_result_ref_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "JSON.parse",
                category="reverse",
                args=[{"source_ref": "string_ref:json-source", "result_type": "object"}],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            self.assertIn("JSON.parse:result_ref", str(ctx.exception))

    def test_validate_trace_requires_json_parse_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = self.vmp_next_core_events()
            events.append(schema_v1_event(
                "JSON.parse",
                category="reverse",
                seq=100,
                event_id="session-1:100",
                args=[{
                    "source_ref": "string_ref:json-source",
                    "reviver_type": "undefined",
                    "result_type": "object",
                    "result_ref": "object:42",
                }],
            ))
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("JSON.parse:source", message)
            self.assertIn("JSON.parse:source_length", message)
            self.assertIn("JSON.parse:reviver_ref", message)

    def test_validate_trace_requires_json_stringify_value_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "JSON.stringify",
                category="reverse",
                args=[{"input_type": "object"}],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("JSON.stringify:input_ref", message)
            self.assertIn("JSON.stringify:replacer_ref", message)
            self.assertIn("JSON.stringify:space_ref", message)
            self.assertIn("JSON.stringify:result_ref", message)

    def test_validate_trace_requires_json_stringify_result_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = self.vmp_next_core_events()
            events.append(schema_v1_event(
                "JSON.stringify",
                category="reverse",
                seq=100,
                event_id="session-1:100",
                args=[{
                    "input_type": "object",
                    "input_ref": "object:42",
                    "replacer_type": "undefined",
                    "replacer_ref": "undefined",
                    "space_type": "undefined",
                    "space_ref": "undefined",
                    "result_type": "string",
                    "result_ref": "string_ref:json-result",
                }],
            ))
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("JSON.stringify:result", message)
            self.assertIn("JSON.stringify:result_length", message)

    def test_validate_trace_requires_collection_table_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "Map.prototype.get",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{"key": "token"}],
                ),
                schema_v1_event(
                    "Map.prototype.has",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"key": "token"}],
                ),
                schema_v1_event(
                    "Map.prototype.set",
                    category="reverse",
                    seq=3,
                    event_id="session-1:3",
                    args=[{"key": "token", "value": "abc"}],
                ),
                schema_v1_event(
                    "Map.prototype.delete",
                    category="reverse",
                    seq=4,
                    event_id="session-1:4",
                    args=[{"key": "token"}],
                ),
                schema_v1_event(
                    "Set.prototype.add",
                    category="reverse",
                    seq=5,
                    event_id="session-1:5",
                    args=[{"key": "token"}],
                ),
                schema_v1_event(
                    "Set.prototype.has",
                    category="reverse",
                    seq=6,
                    event_id="session-1:6",
                    args=[{"key": "token"}],
                ),
                schema_v1_event(
                    "Set.prototype.delete",
                    category="reverse",
                    seq=7,
                    event_id="session-1:7",
                    args=[{"key": "token"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in [
                "Map.prototype.get",
                "Map.prototype.has",
                "Map.prototype.set",
                "Map.prototype.delete",
                "Set.prototype.add",
                "Set.prototype.has",
                "Set.prototype.delete",
            ]:
                self.assertIn(f"{api}:collection_ref", message)
                self.assertIn(f"{api}:key_ref", message)
                self.assertIn(f"{api}:result_ref", message)
            self.assertIn("Map.prototype.set:value_ref", message)
            self.assertIn("Set.prototype.add:value_ref", message)

    def test_validate_trace_requires_weak_collection_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "WeakMap.prototype.get",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{"key": "token"}],
                ),
                schema_v1_event(
                    "WeakMap.prototype.has",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"key": "token"}],
                ),
                schema_v1_event(
                    "WeakMap.prototype.set",
                    category="reverse",
                    seq=3,
                    event_id="session-1:3",
                    args=[{"key": "token", "value": "abc"}],
                ),
                schema_v1_event(
                    "WeakMap.prototype.delete",
                    category="reverse",
                    seq=4,
                    event_id="session-1:4",
                    args=[{"key": "token"}],
                ),
                schema_v1_event(
                    "WeakSet.prototype.add",
                    category="reverse",
                    seq=5,
                    event_id="session-1:5",
                    args=[{"key": "token"}],
                ),
                schema_v1_event(
                    "WeakSet.prototype.has",
                    category="reverse",
                    seq=6,
                    event_id="session-1:6",
                    args=[{"key": "token"}],
                ),
                schema_v1_event(
                    "WeakSet.prototype.delete",
                    category="reverse",
                    seq=7,
                    event_id="session-1:7",
                    args=[{"key": "token"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in [
                "WeakMap.prototype.get",
                "WeakMap.prototype.has",
                "WeakMap.prototype.set",
                "WeakMap.prototype.delete",
                "WeakSet.prototype.add",
                "WeakSet.prototype.has",
                "WeakSet.prototype.delete",
            ]:
                self.assertIn(f"{api}:collection_ref", message)
                self.assertIn(f"{api}:key_ref", message)
                self.assertIn(f"{api}:result_ref", message)
            self.assertIn("WeakMap.prototype.set:value_ref", message)
            self.assertIn("WeakSet.prototype.add:value_ref", message)

    def test_validate_trace_requires_get_or_insert_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "Map.prototype.getOrInsert",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{"key": "token"}],
                ),
                schema_v1_event(
                    "Map.prototype.getOrInsertComputed",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"key": "token"}],
                ),
                schema_v1_event(
                    "WeakMap.prototype.getOrInsert",
                    category="reverse",
                    seq=3,
                    event_id="session-1:3",
                    args=[{"key": "token"}],
                ),
                schema_v1_event(
                    "WeakMap.prototype.getOrInsertComputed",
                    category="reverse",
                    seq=4,
                    event_id="session-1:4",
                    args=[{"key": "token"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in [
                "Map.prototype.getOrInsert",
                "Map.prototype.getOrInsertComputed",
                "WeakMap.prototype.getOrInsert",
                "WeakMap.prototype.getOrInsertComputed",
            ]:
                self.assertIn(f"{api}:collection_ref", message)
                self.assertIn(f"{api}:key_ref", message)
                self.assertIn(f"{api}:result_ref", message)
                self.assertIn(f"{api}:inserted", message)
            self.assertIn("Map.prototype.getOrInsert:value_ref", message)
            self.assertIn("WeakMap.prototype.getOrInsert:value_ref", message)
            self.assertIn("Map.prototype.getOrInsertComputed:callback_ref", message)
            self.assertIn("WeakMap.prototype.getOrInsertComputed:callback_ref", message)

    def test_validate_trace_requires_collection_for_each_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "Map.prototype.forEach",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{"key": "token"}],
                ),
                schema_v1_event(
                    "Set.prototype.forEach",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"key": "token"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in ["Map.prototype.forEach", "Set.prototype.forEach"]:
                self.assertIn(f"{api}:collection_ref", message)
                self.assertIn(f"{api}:callback_ref", message)
                self.assertIn(f"{api}:this_arg_ref", message)
                self.assertIn(f"{api}:key_ref", message)
                self.assertIn(f"{api}:value_ref", message)
                self.assertIn(f"{api}:result_ref", message)

    def test_validate_trace_requires_collection_iterator_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "Map.prototype.entries",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{}],
                ),
                schema_v1_event(
                    "Map.prototype.keys",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{}],
                ),
                schema_v1_event(
                    "Map.prototype.values",
                    category="reverse",
                    seq=3,
                    event_id="session-1:3",
                    args=[{}],
                ),
                schema_v1_event(
                    "Set.prototype.entries",
                    category="reverse",
                    seq=4,
                    event_id="session-1:4",
                    args=[{}],
                ),
                schema_v1_event(
                    "Set.prototype.values",
                    category="reverse",
                    seq=5,
                    event_id="session-1:5",
                    args=[{}],
                ),
                schema_v1_event(
                    "MapIterator.prototype.next",
                    category="reverse",
                    seq=6,
                    event_id="session-1:6",
                    args=[{}],
                ),
                schema_v1_event(
                    "SetIterator.prototype.next",
                    category="reverse",
                    seq=7,
                    event_id="session-1:7",
                    args=[{}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in [
                "Map.prototype.entries",
                "Map.prototype.keys",
                "Map.prototype.values",
                "Set.prototype.entries",
                "Set.prototype.values",
            ]:
                self.assertIn(f"{api}:collection_ref", message)
                self.assertIn(f"{api}:iterator_ref", message)
                self.assertIn(f"{api}:result_ref", message)
                self.assertIn(f"{api}:iteration_kind", message)
            for api in ["MapIterator.prototype.next", "SetIterator.prototype.next"]:
                self.assertIn(f"{api}:iterator_ref", message)
                self.assertIn(f"{api}:key_ref", message)
                self.assertIn(f"{api}:value_ref", message)
                self.assertIn(f"{api}:result_ref", message)
                self.assertIn(f"{api}:done", message)

    def test_validate_trace_requires_sequence_iterator_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "Array.prototype.entries",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{}],
                ),
                schema_v1_event(
                    "Array.prototype.keys",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{}],
                ),
                schema_v1_event(
                    "Array.prototype.values",
                    category="reverse",
                    seq=3,
                    event_id="session-1:3",
                    args=[{}],
                ),
                schema_v1_event(
                    "TypedArray.entries",
                    category="reverse",
                    seq=4,
                    event_id="session-1:4",
                    args=[{}],
                ),
                schema_v1_event(
                    "TypedArray.keys",
                    category="reverse",
                    seq=5,
                    event_id="session-1:5",
                    args=[{}],
                ),
                schema_v1_event(
                    "TypedArray.values",
                    category="reverse",
                    seq=6,
                    event_id="session-1:6",
                    args=[{}],
                ),
                schema_v1_event(
                    "String.prototype.@@iterator",
                    category="reverse",
                    seq=7,
                    event_id="session-1:7",
                    args=[{}],
                ),
                schema_v1_event(
                    "ArrayIterator.prototype.next",
                    category="reverse",
                    seq=8,
                    event_id="session-1:8",
                    args=[{}],
                ),
                schema_v1_event(
                    "StringIterator.prototype.next",
                    category="reverse",
                    seq=9,
                    event_id="session-1:9",
                    args=[{}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in [
                "Array.prototype.entries",
                "Array.prototype.keys",
                "Array.prototype.values",
                "TypedArray.entries",
                "TypedArray.keys",
                "TypedArray.values",
                "String.prototype.@@iterator",
            ]:
                self.assertIn(f"{api}:sequence_ref", message)
                self.assertIn(f"{api}:iterator_ref", message)
                self.assertIn(f"{api}:result_ref", message)
                self.assertIn(f"{api}:iteration_kind", message)
            for api in ["ArrayIterator.prototype.next", "StringIterator.prototype.next"]:
                self.assertIn(f"{api}:iterator_ref", message)
                self.assertIn(f"{api}:key_ref", message)
                self.assertIn(f"{api}:value_ref", message)
                self.assertIn(f"{api}:result_ref", message)
                self.assertIn(f"{api}:done", message)

    def test_validate_trace_requires_generator_resume_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    api,
                    category="reverse",
                    seq=index,
                    event_id=f"session-1:{index}",
                    args=[{}],
                )
                for index, api in enumerate(
                    [
                        "Generator.prototype.next",
                        "Generator.prototype.return",
                        "Generator.prototype.throw",
                        "AsyncGenerator.prototype.next",
                        "AsyncGenerator.prototype.return",
                        "AsyncGenerator.prototype.throw",
                    ],
                    start=1,
                )
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in [
                "Generator.prototype.next",
                "Generator.prototype.return",
                "Generator.prototype.throw",
            ]:
                self.assertIn(f"{api}:generator_ref", message)
                self.assertIn(f"{api}:input_ref", message)
                self.assertIn(f"{api}:result_ref", message)
                self.assertIn(f"{api}:resume_mode", message)
                self.assertIn(f"{api}:generator_state", message)
            for api in [
                "AsyncGenerator.prototype.next",
                "AsyncGenerator.prototype.return",
                "AsyncGenerator.prototype.throw",
            ]:
                self.assertIn(f"{api}:generator_ref", message)
                self.assertIn(f"{api}:input_ref", message)
                self.assertIn(f"{api}:request_promise_ref", message)
                self.assertIn(f"{api}:resume_mode", message)
                self.assertIn(f"{api}:generator_state", message)

    def test_validate_trace_requires_array_constructor_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "Array.from",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{}],
                ),
                schema_v1_event(
                    "Array.of",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for field in [
                "source_ref",
                "mapfn_ref",
                "this_arg_ref",
                "result_ref",
                "result_element_refs",
                "result_elements_complete",
            ]:
                self.assertIn(f"Array.from:{field}", message)
            for field in [
                "arg_count",
                "result_ref",
                "result_element_refs",
                "result_elements_complete",
            ]:
                self.assertIn(f"Array.of:{field}", message)

    def test_validate_trace_requires_array_from_async_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "Array.fromAsync",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for field in [
                "source_ref",
                "mapfn_ref",
                "this_arg_ref",
                "promise_ref",
                "result_ref",
                "result_element_refs",
                "result_elements_complete",
                "async_mode",
            ]:
                self.assertIn(f"Array.fromAsync:{field}", message)

    def test_validate_trace_requires_promise_static_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "Promise.resolve",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{}],
                ),
                schema_v1_event(
                    "Promise.reject",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("Promise.resolve:input_ref", message)
            self.assertIn("Promise.resolve:result_promise_ref", message)
            self.assertIn("Promise.reject:reason_ref", message)
            self.assertIn("Promise.reject:result_promise_ref", message)

    def test_validate_trace_requires_promise_combinator_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    api,
                    category="reverse",
                    seq=index,
                    event_id=f"session-1:{index}",
                    args=[{}],
                )
                for index, api in enumerate(
                    [
                        "Promise.all",
                        "Promise.allSettled",
                        "Promise.race",
                        "Promise.any",
                    ],
                    start=1,
                )
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in [
                "Promise.all",
                "Promise.allSettled",
                "Promise.race",
                "Promise.any",
            ]:
                self.assertIn(f"{api}:iterable_ref", message)
                self.assertIn(f"{api}:result_promise_ref", message)
                self.assertIn(f"{api}:combinator", message)

    def test_validate_trace_requires_promise_capability_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "Promise.try",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{}],
                ),
                schema_v1_event(
                    "Promise.withResolvers",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for field in [
                "callback_ref",
                "result_promise_ref",
                "completion_state",
                "completion_ref",
            ]:
                self.assertIn(f"Promise.try:{field}", message)
            for field in [
                "promise_ref",
                "resolve_ref",
                "reject_ref",
                "result_ref",
            ]:
                self.assertIn(f"Promise.withResolvers:{field}", message)

    def test_validate_trace_requires_webcrypto_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    api,
                    category="reverse",
                    seq=index,
                    event_id=f"session-1:{index}",
                    args=[{}],
                )
                for index, api in enumerate(
                    [
                        "SubtleCrypto.encrypt",
                        "SubtleCrypto.decrypt",
                        "SubtleCrypto.digest",
                        "SubtleCrypto.importKey",
                        "SubtleCrypto.sign",
                        "SubtleCrypto.verify",
                    ],
                    start=1,
                )
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in [
                "SubtleCrypto.encrypt",
                "SubtleCrypto.decrypt",
                "SubtleCrypto.sign",
            ]:
                self.assertIn(f"{api}:algorithm", message)
                self.assertIn(f"{api}:key_ref", message)
                self.assertIn(f"{api}:input_ref", message)
                self.assertIn(f"{api}:input_hex", message)
                self.assertIn(f"{api}:result_ref", message)
                self.assertIn(f"{api}:result_hex", message)
            for field in [
                "algorithm",
                "input_ref",
                "input_hex",
                "result_ref",
                "result_hex",
            ]:
                self.assertIn(f"SubtleCrypto.digest:{field}", message)
            for field in [
                "algorithm",
                "key_data_ref",
                "key_data_hex",
                "key_ref",
            ]:
                self.assertIn(f"SubtleCrypto.importKey:{field}", message)
            for field in [
                "algorithm",
                "key_ref",
                "signature_ref",
                "signature_hex",
                "input_ref",
                "input_hex",
                "result_ref",
            ]:
                self.assertIn(f"SubtleCrypto.verify:{field}", message)

    def test_validate_trace_requires_webcrypto_key_lifecycle_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    api,
                    category="reverse",
                    seq=index,
                    event_id=f"session-1:{index}",
                    args=[{}],
                )
                for index, api in enumerate(
                    [
                        "SubtleCrypto.generateKey",
                        "SubtleCrypto.exportKey",
                        "SubtleCrypto.deriveBits",
                        "SubtleCrypto.deriveKey",
                        "SubtleCrypto.wrapKey",
                        "SubtleCrypto.unwrapKey",
                    ],
                    start=1,
                )
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for field in [
                "algorithm",
                "extractable",
                "key_usages_mask",
                "result_type",
            ]:
                self.assertIn(f"SubtleCrypto.generateKey:{field}", message)
            for field in [
                "format",
                "key_ref",
                "key_algorithm",
                "key_type",
                "result_ref",
            ]:
                self.assertIn(f"SubtleCrypto.exportKey:{field}", message)
            for field in [
                "algorithm",
                "base_key_ref",
                "length_bits",
                "result_ref",
                "result_hex",
            ]:
                self.assertIn(f"SubtleCrypto.deriveBits:{field}", message)
            for field in [
                "algorithm",
                "base_key_ref",
                "derived_key_algorithm",
                "extractable",
                "key_usages_mask",
                "key_ref",
            ]:
                self.assertIn(f"SubtleCrypto.deriveKey:{field}", message)
            for field in [
                "format",
                "key_ref",
                "wrapping_key_ref",
                "wrap_algorithm",
                "result_ref",
                "result_hex",
            ]:
                self.assertIn(f"SubtleCrypto.wrapKey:{field}", message)
            for field in [
                "format",
                "unwrapping_key_ref",
                "unwrap_algorithm",
                "unwrapped_key_algorithm",
                "extractable",
                "key_usages_mask",
                "wrapped_key_ref",
                "wrapped_key_hex",
                "key_ref",
            ]:
                self.assertIn(f"SubtleCrypto.unwrapKey:{field}", message)

    def test_validate_trace_requires_math_random_result_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "Math.random",
                category="reverse",
                args=[{}],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("Math.random:result", message)
            self.assertIn("Math.random:result_ref", message)
            self.assertIn("Math.random:random_source", message)

    def test_validate_trace_requires_text_codec_byte_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    api,
                    category="reverse",
                    seq=index,
                    event_id=f"session-1:{index}",
                    args=[{}],
                )
                for index, api in enumerate(
                    [
                        "TextEncoder.encode",
                        "TextEncoder.encodeInto",
                        "TextDecoder.decode",
                    ],
                    start=1,
                )
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for field in [
                "input_ref",
                "result_hex",
                "result_ref",
                "result_typed_array_id",
                "result_array_buffer_id",
                "result_byte_length",
            ]:
                self.assertIn(f"TextEncoder.encode:{field}", message)
            for field in [
                "input_ref",
                "destination_typed_array_id",
                "destination_array_buffer_id",
                "destination_byte_length",
                "read",
                "written",
                "written_hex",
                "written_ref",
                "destination_hex",
                "destination_ref",
            ]:
                self.assertIn(f"TextEncoder.encodeInto:{field}", message)
            for field in [
                "input_hex",
                "input_ref",
                "result",
                "result_ref",
            ]:
                self.assertIn(f"TextDecoder.decode:{field}", message)

    def test_validate_trace_requires_base64_byte_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    api,
                    category="reverse",
                    seq=index,
                    event_id=f"session-1:{index}",
                    args=[{}],
                )
                for index, api in enumerate(["btoa", "atob"], start=1)
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in ["btoa", "atob"]:
                for field in [
                    "input_hex",
                    "input_ref",
                    "result_hex",
                    "result_ref",
                ]:
                    self.assertIn(f"{api}:{field}", message)

    def test_validate_trace_requires_webcrypto_random_source_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "Crypto.getRandomValues",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{}],
                ),
                schema_v1_event(
                    "Crypto.randomUUID",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for field in [
                "random_source",
                "typed_array_type",
                "byte_length",
                "array_buffer_id",
                "typed_array_id",
                "byte_offset",
                "result_ref",
                "result_hex",
            ]:
                self.assertIn(f"Crypto.getRandomValues:{field}", message)
            for field in [
                "random_source",
                "result",
                "result_ref",
                "result_length",
            ]:
                self.assertIn(f"Crypto.randomUUID:{field}", message)

    def test_validate_trace_requires_async_function_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    api,
                    category="reverse",
                    seq=index,
                    event_id=f"session-1:{index}",
                    args=[{}],
                )
                for index, api in enumerate(
                    [
                        "AsyncFunction.enter",
                        "AsyncFunction.await",
                        "AsyncFunction.resume",
                        "AsyncFunction.resolve",
                        "AsyncFunction.reject",
                    ],
                    start=1,
                )
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for field in [
                "async_function_ref",
                "closure_ref",
                "receiver_ref",
                "promise_ref",
                "async_state",
            ]:
                self.assertIn(f"AsyncFunction.enter:{field}", message)
            for field in [
                "async_function_ref",
                "await_value_ref",
                "outer_promise_ref",
                "await_mode",
                "async_state",
            ]:
                self.assertIn(f"AsyncFunction.await:{field}", message)
            for field in [
                "async_function_ref",
                "sent_value_ref",
                "outer_promise_ref",
                "resume_mode",
                "async_state",
            ]:
                self.assertIn(f"AsyncFunction.resume:{field}", message)
            for field in [
                "async_function_ref",
                "value_ref",
                "promise_ref",
                "settlement_state",
                "async_state",
            ]:
                self.assertIn(f"AsyncFunction.resolve:{field}", message)
            for field in [
                "async_function_ref",
                "reason_ref",
                "promise_ref",
                "settlement_state",
                "async_state",
            ]:
                self.assertIn(f"AsyncFunction.reject:{field}", message)

    def test_validate_trace_requires_regexp_match_all_iterator_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "String.prototype.matchAll",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{}],
                ),
                schema_v1_event(
                    "RegExp.prototype.@@matchAll",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{}],
                ),
                schema_v1_event(
                    "RegExpStringIterator.prototype.next",
                    category="reverse",
                    seq=3,
                    event_id="session-1:3",
                    args=[{}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in ["String.prototype.matchAll", "RegExp.prototype.@@matchAll"]:
                self.assertIn(f"{api}:input_ref", message)
                self.assertIn(f"{api}:regexp_ref", message)
                self.assertIn(f"{api}:iterator_ref", message)
                self.assertIn(f"{api}:result_ref", message)
            self.assertIn("RegExpStringIterator.prototype.next:iterator_ref", message)
            self.assertIn("RegExpStringIterator.prototype.next:regexp_ref", message)
            self.assertIn("RegExpStringIterator.prototype.next:input_ref", message)
            self.assertIn("RegExpStringIterator.prototype.next:result_ref", message)
            self.assertIn("RegExpStringIterator.prototype.next:done", message)

    def test_validate_trace_requires_collection_clear_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "Map.prototype.clear",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{"operation": "clear"}],
                ),
                schema_v1_event(
                    "Set.prototype.clear",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"operation": "clear"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in ["Map.prototype.clear", "Set.prototype.clear"]:
                self.assertIn(f"{api}:collection_ref", message)
                self.assertIn(f"{api}:size_before", message)
                self.assertIn(f"{api}:result_ref", message)

    def test_validate_trace_rejects_missing_url_search_params_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "String.fromCharCode",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{"first_code_ref": "number:65", "result_ref": "string:length:1"}],
                ),
                schema_v1_event(
                    "String.prototype.slice",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"subject_ref": "string:length:40", "result_ref": "string:length:39"}],
                ),
                schema_v1_event(
                    "encodeURIComponent",
                    category="reverse",
                    seq=3,
                    event_id="session-1:3",
                    args=[{"input_ref": "string:length:39", "result_ref": "string:length:41"}],
                ),
                schema_v1_event(
                    "Bitwise.xor",
                    category="reverse",
                    seq=4,
                    event_id="session-1:4",
                    args=[{"left_ref": "number:1", "right_ref": "number:2", "result_ref": "number:3"}],
                ),
                schema_v1_event(
                    "URLSearchParams.set",
                    category="reverse",
                    seq=5,
                    event_id="session-1:5",
                    args=[{"value": "secret-one"}],
                ),
                schema_v1_event(
                    "URLSearchParams.toString",
                    category="reverse",
                    seq=6,
                    event_id="session-1:6",
                    args=[{"serialized": "cursor=1&X-Signature=secret-one"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("URLSearchParams.set:value_ref", message)
            self.assertIn("URLSearchParams.toString:result_ref", message)

    def test_validate_trace_requires_url_search_params_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "String.fromCharCode",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{"first_code_ref": "number:65", "result_ref": "string:length:1"}],
                ),
                schema_v1_event(
                    "String.prototype.slice",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"subject_ref": "string:length:40", "result_ref": "string:length:39"}],
                ),
                schema_v1_event(
                    "encodeURIComponent",
                    category="reverse",
                    seq=3,
                    event_id="session-1:3",
                    args=[self.uri_codec_args("cursor=1&token=a b", "cursor%3D1%26token%3Da%20b")],
                ),
                schema_v1_event(
                    "Bitwise.xor",
                    category="reverse",
                    seq=4,
                    event_id="session-1:4",
                    args=[{"left_ref": "number:1", "right_ref": "number:2", "result_ref": "number:3"}],
                ),
                schema_v1_event(
                    "URLSearchParams.set",
                    category="reverse",
                    seq=5,
                    event_id="session-1:5",
                    args=[{"value_ref": "string:length:10", "serialized_ref": "string:length:27"}],
                ),
                schema_v1_event(
                    "URLSearchParams.toString",
                    category="reverse",
                    seq=6,
                    event_id="session-1:6",
                    args=[{"result_ref": "string:length:27", "serialized_ref": "string:length:27"}],
                ),
                schema_v1_event(
                    "URL.href.set",
                    category="reverse",
                    seq=7,
                    event_id="session-1:7",
                    args=[{"value_ref": "string:length:27", "href_ref": "string:length:27"}],
                ),
                schema_v1_event(
                    "URL.search.set",
                    category="reverse",
                    seq=8,
                    event_id="session-1:8",
                    args=[{
                        "value_ref": "string:length:27",
                        "search_ref": "string:length:27",
                        "href_ref": "string:length:64",
                    }],
                ),
                schema_v1_event(
                    "BigInt.prototype.toString",
                    category="reverse",
                    seq=9,
                    event_id="session-1:9",
                    args=[{"result_ref": "string:length:4"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for field in [
                "search_params_id",
                "url_object_id",
                "name",
                "name_length",
                "name_ref",
                "value",
                "value_length",
                "before_serialized",
                "before_serialized_length",
                "before_serialized_ref",
                "serialized",
                "serialized_length",
                "replaced_existing",
            ]:
                self.assertIn(f"URLSearchParams.set:{field}", message)
            for field in [
                "search_params_id",
                "url_object_id",
                "size",
                "serialized",
                "serialized_length",
            ]:
                self.assertIn(f"URLSearchParams.toString:{field}", message)

    def test_validate_trace_requires_url_search_params_iterator_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "URLSearchParams.iterator.next",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[{
                        "search_params_id": 7,
                        "url_object_id": 11,
                        "iteration_index": 0,
                        "name": "X-Signature",
                        "value": "secret-one",
                    }],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for field in ["name_length", "name_ref", "value_length", "value_ref"]:
                self.assertIn(f"URLSearchParams.iterator.next:{field}", message)

    def test_validate_trace_requires_url_search_params_probe_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "URLSearchParams.append",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[{"search_params_id": 7, "url_object_id": 11, "name": "X-Signature", "value": "secret-one"}],
                ),
                schema_v1_event(
                    "URLSearchParams.delete",
                    category="reverse",
                    seq=102,
                    event_id="session-1:102",
                    args=[{"search_params_id": 7, "url_object_id": 11, "name": "X-Signature", "value": ""}],
                ),
                schema_v1_event(
                    "URLSearchParams.get",
                    category="reverse",
                    seq=103,
                    event_id="session-1:103",
                    args=[{"search_params_id": 7, "url_object_id": 11, "name": "X-Signature", "result": "secret-one"}],
                ),
                schema_v1_event(
                    "URLSearchParams.getAll",
                    category="reverse",
                    seq=104,
                    event_id="session-1:104",
                    args=[{"search_params_id": 7, "url_object_id": 11, "name": "X-Signature", "values": ["secret-one"]}],
                ),
                schema_v1_event(
                    "URLSearchParams.has",
                    category="reverse",
                    seq=105,
                    event_id="session-1:105",
                    args=[{"search_params_id": 7, "url_object_id": 11, "name": "X-Signature"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in [
                "URLSearchParams.append",
                "URLSearchParams.delete",
                "URLSearchParams.get",
                "URLSearchParams.getAll",
                "URLSearchParams.has",
            ]:
                self.assertIn(f"{api}:name_length", message)
                self.assertIn(f"{api}:name_ref", message)
            for api in ["URLSearchParams.append", "URLSearchParams.delete"]:
                self.assertIn(f"{api}:value_length", message)
                self.assertIn(f"{api}:value_ref", message)
            self.assertIn("URLSearchParams.get:result_length", message)
            self.assertIn("URLSearchParams.get:result_ref", message)
            self.assertIn("URLSearchParams.getAll:result_value_lengths", message)
            self.assertIn("URLSearchParams.getAll:result_value_refs", message)

    def test_validate_trace_requires_location_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = self.vmp_next_core_events()
            for event in events:
                if event["api"] == "Location.href.set":
                    event["args"] = [{
                        "value": "/api/records/list/?cursor=2",
                        "href": "https://www.example.test/api/records/list/?cursor=2",
                    }]
                    break
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for field in [
                "value_length",
                "value_ref",
                "href_length",
                "href_ref",
            ]:
                self.assertIn(f"Location.href.set:{field}", message)

    def test_validate_trace_requires_document_context_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = self.vmp_next_core_events()
            for event in events:
                if event["api"] == "Document.urlForBinding.get":
                    event["args"] = [{"result": "https://www.example.test/api/records/list/?cursor=1"}]
                    break
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("Document.urlForBinding.get:result_length", message)
            self.assertIn("Document.urlForBinding.get:result_ref", message)

    def test_validate_trace_requires_string_boundary_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "String.fromCharCode",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{"first_code_ref": "number:65", "result_ref": "string:length:1"}],
                ),
                schema_v1_event(
                    "Bitwise.xor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"left_ref": "number:1", "right_ref": "number:2", "result_ref": "number:3"}],
                ),
                schema_v1_event(
                    "String.prototype.slice",
                    category="reverse",
                    seq=3,
                    event_id="session-1:3",
                    args=[{"subject_ref": "string:length:40", "result_length": 39}],
                ),
                schema_v1_event(
                    "encodeURIComponent",
                    category="reverse",
                    seq=4,
                    event_id="session-1:4",
                    args=[{"input_ref": "string:length:39", "result_length": 39}],
                ),
                schema_v1_event(
                    "String.prototype.charCodeAt",
                    category="reverse",
                    seq=5,
                    event_id="session-1:5",
                    args=[{"result_ref": "number:88"}],
                ),
                schema_v1_event(
                    "String.prototype.codePointAt",
                    category="reverse",
                    seq=6,
                    event_id="session-1:6",
                    args=[{"subject_ref": "string:length:40"}],
                ),
                schema_v1_event(
                    "String.prototype.lastIndexOf",
                    category="reverse",
                    seq=7,
                    event_id="session-1:7",
                    args=[{"subject_ref": "string:length:40"}],
                ),
                schema_v1_event(
                    "String.prototype.repeat",
                    category="reverse",
                    seq=8,
                    event_id="session-1:8",
                    args=[{"subject_ref": "string:length:2"}],
                ),
                schema_v1_event(
                    "String.prototype.at",
                    category="reverse",
                    seq=9,
                    event_id="session-1:9",
                    args=[{"subject_ref": "string:length:9"}],
                ),
                schema_v1_event(
                    "String.prototype.search",
                    category="reverse",
                    seq=10,
                    event_id="session-1:10",
                    args=[{"input_ref": "string:length:40"}],
                ),
                schema_v1_event(
                    "String.prototype.match",
                    category="reverse",
                    seq=11,
                    event_id="session-1:11",
                    args=[{"result_ref": "array:length:1"}],
                ),
                schema_v1_event(
                    "Number.parseInt",
                    category="reverse",
                    seq=12,
                    event_id="session-1:12",
                    args=[{"input_ref": "string:length:2", "radix_ref": "number:16"}],
                ),
                schema_v1_event(
                    "Number.parseFloat",
                    category="reverse",
                    seq=13,
                    event_id="session-1:13",
                    args=[{"result_ref": "number:3.14"}],
                ),
                schema_v1_event(
                    "Reflect.construct",
                    category="reverse",
                    seq=256,
                    event_id="session-1:256",
                    args=[{}],
                ),
                schema_v1_event(
                    "Array.prototype.at",
                    category="reverse",
                    seq=14,
                    event_id="session-1:14",
                    args=[{"index": 2, "length": 5, "result": "xor"}],
                ),
                schema_v1_event(
                    "Array.prototype.indexOf",
                    category="reverse",
                    seq=15,
                    event_id="session-1:15",
                    args=[{"search": "xor", "from_index": 0, "result": 2}],
                ),
                schema_v1_event(
                    "Array.prototype.includes",
                    category="reverse",
                    seq=16,
                    event_id="session-1:16",
                    args=[{"search": "store", "from_index": 0, "result": True}],
                ),
                schema_v1_event(
                    "Array.prototype.lastIndexOf",
                    category="reverse",
                    seq=17,
                    event_id="session-1:17",
                    args=[{"search": "xor", "from_index": 4, "result": 2}],
                ),
                schema_v1_event(
                    "Array.prototype.find",
                    category="reverse",
                    seq=18,
                    event_id="session-1:18",
                    args=[{"callback_type": "function", "length": 5, "result": "xor"}],
                ),
                schema_v1_event(
                    "Array.prototype.findIndex",
                    category="reverse",
                    seq=19,
                    event_id="session-1:19",
                    args=[{"callback_type": "function", "length": 5, "result": 2}],
                ),
                schema_v1_event(
                    "Array.prototype.findLast",
                    category="reverse",
                    seq=20,
                    event_id="session-1:20",
                    args=[{"callback_type": "function", "length": 5, "result": "ret"}],
                ),
                schema_v1_event(
                    "Array.prototype.findLastIndex",
                    category="reverse",
                    seq=21,
                    event_id="session-1:21",
                    args=[{"callback_type": "function", "length": 5, "result": 4}],
                ),
                schema_v1_event(
                    "Array.prototype.reduce",
                    category="reverse",
                    seq=22,
                    event_id="session-1:22",
                    args=[{"callback_type": "function", "initial_value": "seed", "result": "seed:op"}],
                ),
                schema_v1_event(
                    "Array.prototype.reduceRight",
                    category="reverse",
                    seq=23,
                    event_id="session-1:23",
                    args=[{"callback_type": "function", "initial_value": "seed", "result": "seed:ret"}],
                ),
                schema_v1_event(
                    "Array.prototype.map",
                    category="reverse",
                    seq=24,
                    event_id="session-1:24",
                    args=[{"callback_type": "function", "length": 5, "result_ref": "object:map-result"}],
                ),
                schema_v1_event(
                    "Array.prototype.filter",
                    category="reverse",
                    seq=25,
                    event_id="session-1:25",
                    args=[{"callback_type": "function", "length": 5, "result_ref": "object:filter-result"}],
                ),
                schema_v1_event(
                    "Array.prototype.flat",
                    category="reverse",
                    seq=42,
                    event_id="session-1:42",
                    args=[{"depth": 2, "length": 5, "result_ref": "object:flat-result"}],
                ),
                schema_v1_event(
                    "Array.prototype.flatMap",
                    category="reverse",
                    seq=43,
                    event_id="session-1:43",
                    args=[{"callback_type": "function", "length": 5, "result_ref": "object:flat-map-result"}],
                ),
                schema_v1_event(
                    "Array.prototype.every",
                    category="reverse",
                    seq=26,
                    event_id="session-1:26",
                    args=[{"callback_type": "function", "length": 5, "result": True}],
                ),
                schema_v1_event(
                    "Array.prototype.some",
                    category="reverse",
                    seq=27,
                    event_id="session-1:27",
                    args=[{"callback_type": "function", "length": 5, "result": True}],
                ),
                schema_v1_event(
                    "Array.prototype.forEach",
                    category="reverse",
                    seq=28,
                    event_id="session-1:28",
                    args=[{"callback_type": "function", "length": 5, "result": None}],
                ),
                schema_v1_event(
                    "TypedArray.indexOf",
                    category="reverse",
                    seq=29,
                    event_id="session-1:29",
                    args=[{"search": 4, "from_index": 0, "result": 2}],
                ),
                schema_v1_event(
                    "TypedArray.includes",
                    category="reverse",
                    seq=30,
                    event_id="session-1:30",
                    args=[{"search": 9, "from_index": 0, "result": True}],
                ),
                schema_v1_event(
                    "TypedArray.lastIndexOf",
                    category="reverse",
                    seq=31,
                    event_id="session-1:31",
                    args=[{"search": 1, "from_index": 5, "result": 3}],
                ),
                schema_v1_event(
                    "TypedArray.find",
                    category="reverse",
                    seq=32,
                    event_id="session-1:32",
                    args=[{"callback_type": "function", "length": 5, "result": 5}],
                ),
                schema_v1_event(
                    "TypedArray.findIndex",
                    category="reverse",
                    seq=33,
                    event_id="session-1:33",
                    args=[{"callback_type": "function", "length": 5, "result": 4}],
                ),
                schema_v1_event(
                    "TypedArray.findLast",
                    category="reverse",
                    seq=34,
                    event_id="session-1:34",
                    args=[{"callback_type": "function", "length": 5, "result": 1}],
                ),
                schema_v1_event(
                    "TypedArray.findLastIndex",
                    category="reverse",
                    seq=35,
                    event_id="session-1:35",
                    args=[{"callback_type": "function", "length": 5, "result": 3}],
                ),
                schema_v1_event(
                    "TypedArray.reduce",
                    category="reverse",
                    seq=36,
                    event_id="session-1:36",
                    args=[{"callback_type": "function", "initial_value": 0, "result": 19}],
                ),
                schema_v1_event(
                    "TypedArray.reduceRight",
                    category="reverse",
                    seq=37,
                    event_id="session-1:37",
                    args=[{"callback_type": "function", "initial_value": 7, "result": 1}],
                ),
                schema_v1_event(
                    "TypedArray.filter",
                    category="reverse",
                    seq=38,
                    event_id="session-1:38",
                    args=[{"callback_type": "function", "length": 5, "result_ref": "object:typed-filter-result"}],
                ),
                schema_v1_event(
                    "TypedArray.every",
                    category="reverse",
                    seq=39,
                    event_id="session-1:39",
                    args=[{"callback_type": "function", "length": 5, "result": True}],
                ),
                schema_v1_event(
                    "TypedArray.some",
                    category="reverse",
                    seq=40,
                    event_id="session-1:40",
                    args=[{"callback_type": "function", "length": 5, "result": True}],
                ),
                schema_v1_event(
                    "TypedArray.forEach",
                    category="reverse",
                    seq=41,
                    event_id="session-1:41",
                    args=[{"callback_type": "function", "length": 5, "result": None}],
                ),
                schema_v1_event(
                    "Object.assign",
                    category="reverse",
                    seq=42,
                    event_id="session-1:42",
                    args=[{"source_count": 2}],
                ),
                schema_v1_event(
                    "Object.hasOwn",
                    category="reverse",
                    seq=65,
                    event_id="session-1:65",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.prototype.hasOwnProperty",
                    category="reverse",
                    seq=66,
                    event_id="session-1:66",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.prototype.toString",
                    category="reverse",
                    seq=67,
                    event_id="session-1:67",
                    args=[{"receiver": {"kind": "object"}}],
                ),
                schema_v1_event(
                    "Array.isArray",
                    category="reverse",
                    seq=68,
                    event_id="session-1:68",
                    args=[{"input": []}],
                ),
                schema_v1_event(
                    "Object.is",
                    category="reverse",
                    seq=69,
                    event_id="session-1:69",
                    args=[{"left": 0, "right": -0.0}],
                ),
                schema_v1_event(
                    "Object.create",
                    category="reverse",
                    seq=44,
                    event_id="session-1:44",
                    args=[{"prototype_ref": "object:proto"}],
                ),
                schema_v1_event(
                    "Object.getPrototypeOf",
                    category="reverse",
                    seq=48,
                    event_id="session-1:48",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.setPrototypeOf",
                    category="reverse",
                    seq=49,
                    event_id="session-1:49",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.preventExtensions",
                    category="reverse",
                    seq=54,
                    event_id="session-1:54",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.freeze",
                    category="reverse",
                    seq=55,
                    event_id="session-1:55",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.seal",
                    category="reverse",
                    seq=56,
                    event_id="session-1:56",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.isExtensible",
                    category="reverse",
                    seq=57,
                    event_id="session-1:57",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.isFrozen",
                    category="reverse",
                    seq=58,
                    event_id="session-1:58",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.isSealed",
                    category="reverse",
                    seq=59,
                    event_id="session-1:59",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.getOwnPropertyDescriptor",
                    category="reverse",
                    seq=52,
                    event_id="session-1:52",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.getOwnPropertyDescriptors",
                    category="reverse",
                    seq=53,
                    event_id="session-1:53",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.defineProperty",
                    category="reverse",
                    seq=45,
                    event_id="session-1:45",
                    args=[{"target_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.defineProperties",
                    category="reverse",
                    seq=67,
                    event_id="session-1:67",
                    args=[{}],
                ),
                schema_v1_event(
                    "Reflect.defineProperty",
                    category="reverse",
                    seq=46,
                    event_id="session-1:46",
                    args=[{"target_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Reflect.getPrototypeOf",
                    category="reverse",
                    seq=50,
                    event_id="session-1:50",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Reflect.setPrototypeOf",
                    category="reverse",
                    seq=51,
                    event_id="session-1:51",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Reflect.preventExtensions",
                    category="reverse",
                    seq=60,
                    event_id="session-1:60",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Reflect.isExtensible",
                    category="reverse",
                    seq=61,
                    event_id="session-1:61",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.values",
                    category="reverse",
                    seq=47,
                    event_id="session-1:47",
                    args=[{"result_ref": "object:values-result"}],
                ),
                schema_v1_event(
                    "Object.entries",
                    category="reverse",
                    seq=48,
                    event_id="session-1:48",
                    args=[{"result_ref": "object:entries-result"}],
                ),
                schema_v1_event(
                    "Reflect.get",
                    category="reverse",
                    seq=62,
                    event_id="session-1:62",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Reflect.set",
                    category="reverse",
                    seq=65,
                    event_id="session-1:65",
                    args=[{}],
                ),
                schema_v1_event(
                    "Reflect.has",
                    category="reverse",
                    seq=63,
                    event_id="session-1:63",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Reflect.deleteProperty",
                    category="reverse",
                    seq=64,
                    event_id="session-1:64",
                    args=[{"object_ref": "object:target"}],
                ),
                schema_v1_event(
                    "Object.prototype.propertyIsEnumerable",
                    category="reverse",
                    seq=66,
                    event_id="session-1:66",
                    args=[{}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("String.prototype.slice:result_ref", message)
            self.assertIn("encodeURIComponent:result_ref", message)
            self.assertIn("String.prototype.charCodeAt:subject_ref", message)
            self.assertIn("String.prototype.codePointAt:result_ref", message)
            self.assertIn("String.prototype.lastIndexOf:search_ref", message)
            self.assertIn("String.prototype.lastIndexOf:result_ref", message)
            self.assertIn("String.prototype.repeat:repeat_count_ref", message)
            self.assertIn("String.prototype.repeat:result_ref", message)
            self.assertIn("String.prototype.at:result_ref", message)
            self.assertIn("String.prototype.search:result_ref", message)
            self.assertIn("String.prototype.match:input_ref", message)
            self.assertIn("Number.parseInt:result_ref", message)
            self.assertIn("Number.parseFloat:input_ref", message)
            self.assertIn("Reflect.construct:target_ref", message)
            self.assertIn("Reflect.construct:arguments_list_ref", message)
            self.assertIn("Reflect.construct:new_target_ref", message)
            self.assertIn("Reflect.construct:arg_count", message)
            self.assertIn("Reflect.construct:result_ref", message)
            self.assertIn("Array.prototype.at:result_ref", message)
            self.assertIn("Array.prototype.indexOf:search_ref", message)
            self.assertIn("Array.prototype.indexOf:from_index_ref", message)
            self.assertIn("Array.prototype.indexOf:result_ref", message)
            self.assertIn("Array.prototype.includes:search_ref", message)
            self.assertIn("Array.prototype.includes:from_index_ref", message)
            self.assertIn("Array.prototype.includes:result_ref", message)
            self.assertIn("Array.prototype.lastIndexOf:search_ref", message)
            self.assertIn("Array.prototype.lastIndexOf:from_index_ref", message)
            self.assertIn("Array.prototype.lastIndexOf:result_ref", message)
            self.assertIn("Array.prototype.find:callback_ref", message)
            self.assertIn("Array.prototype.find:this_arg_ref", message)
            self.assertIn("Array.prototype.find:result_ref", message)
            self.assertIn("Array.prototype.findIndex:callback_ref", message)
            self.assertIn("Array.prototype.findIndex:this_arg_ref", message)
            self.assertIn("Array.prototype.findIndex:result_ref", message)
            self.assertIn("Array.prototype.findLast:callback_ref", message)
            self.assertIn("Array.prototype.findLast:this_arg_ref", message)
            self.assertIn("Array.prototype.findLast:result_ref", message)
            self.assertIn("Array.prototype.findLastIndex:callback_ref", message)
            self.assertIn("Array.prototype.findLastIndex:this_arg_ref", message)
            self.assertIn("Array.prototype.findLastIndex:result_ref", message)
            self.assertIn("Array.prototype.reduce:callback_ref", message)
            self.assertIn("Array.prototype.reduce:initial_value_ref", message)
            self.assertIn("Array.prototype.reduce:result_ref", message)
            self.assertIn("Array.prototype.reduceRight:callback_ref", message)
            self.assertIn("Array.prototype.reduceRight:initial_value_ref", message)
            self.assertIn("Array.prototype.reduceRight:result_ref", message)
            self.assertIn("Array.prototype.map:callback_ref", message)
            self.assertIn("Array.prototype.map:this_arg_ref", message)
            self.assertIn("Array.prototype.map:result_element_refs", message)
            self.assertIn("Array.prototype.filter:callback_ref", message)
            self.assertIn("Array.prototype.filter:this_arg_ref", message)
            self.assertIn("Array.prototype.filter:result_element_refs", message)
            self.assertIn("Array.prototype.flat:depth_ref", message)
            self.assertIn("Array.prototype.flat:result_element_refs", message)
            self.assertIn("Array.prototype.flatMap:callback_ref", message)
            self.assertIn("Array.prototype.flatMap:this_arg_ref", message)
            self.assertIn("Array.prototype.flatMap:result_element_refs", message)
            self.assertIn("Array.prototype.every:callback_ref", message)
            self.assertIn("Array.prototype.every:this_arg_ref", message)
            self.assertIn("Array.prototype.every:result_ref", message)
            self.assertIn("Array.prototype.some:callback_ref", message)
            self.assertIn("Array.prototype.some:this_arg_ref", message)
            self.assertIn("Array.prototype.some:result_ref", message)
            self.assertIn("Array.prototype.forEach:callback_ref", message)
            self.assertIn("Array.prototype.forEach:this_arg_ref", message)
            self.assertIn("Array.prototype.forEach:result_ref", message)
            self.assertIn("Object.assign:source_index", message)
            self.assertIn("Object.assign:source_ref", message)
            self.assertIn("Object.assign:result_ref", message)
            self.assertIn("Object.hasOwn:key_ref", message)
            self.assertIn("Object.hasOwn:result_ref", message)
            self.assertIn("Object.prototype.hasOwnProperty:key_ref", message)
            self.assertIn("Object.prototype.hasOwnProperty:result_ref", message)
            self.assertIn("Object.prototype.propertyIsEnumerable:object_ref", message)
            self.assertIn("Object.prototype.propertyIsEnumerable:key_ref", message)
            self.assertIn("Object.prototype.propertyIsEnumerable:result_ref", message)
            self.assertIn("Object.prototype.toString:receiver_ref", message)
            self.assertIn("Object.prototype.toString:result_ref", message)
            self.assertIn("Array.isArray:input_ref", message)
            self.assertIn("Array.isArray:result_ref", message)
            self.assertIn("Object.is:left_ref", message)
            self.assertIn("Object.is:right_ref", message)
            self.assertIn("Object.is:result_ref", message)
            self.assertIn("Object.create:descriptors_ref", message)
            self.assertIn("Object.create:descriptors_kind", message)
            self.assertIn("Object.create:result_ref", message)
            self.assertIn("Object.getPrototypeOf:result_ref", message)
            self.assertIn("Object.setPrototypeOf:prototype_ref", message)
            self.assertIn("Object.setPrototypeOf:result_ref", message)
            self.assertIn("Object.preventExtensions:result_ref", message)
            self.assertIn("Object.freeze:result_ref", message)
            self.assertIn("Object.seal:result_ref", message)
            self.assertIn("Object.isExtensible:result_ref", message)
            self.assertIn("Object.isFrozen:result_ref", message)
            self.assertIn("Object.isSealed:result_ref", message)
            self.assertIn("Object.getOwnPropertyDescriptor:key_ref", message)
            self.assertIn("Object.getOwnPropertyDescriptor:result_ref", message)
            self.assertIn("Object.getOwnPropertyDescriptors:result_ref", message)
            self.assertIn("Object.getOwnPropertyDescriptors:descriptor_key_refs", message)
            self.assertIn("Object.defineProperty:key_ref", message)
            self.assertIn("Object.defineProperty:descriptor_kind", message)
            self.assertIn("Object.defineProperty:descriptor_value_ref", message)
            self.assertIn("Object.defineProperties:target_ref", message)
            self.assertIn("Object.defineProperties:properties_ref", message)
            self.assertIn("Object.defineProperties:descriptor_key_refs", message)
            self.assertIn("Object.defineProperties:descriptor_kinds", message)
            self.assertIn("Object.defineProperties:descriptor_value_refs", message)
            self.assertIn("Object.defineProperties:result_ref", message)
            self.assertIn("Reflect.defineProperty:key_ref", message)
            self.assertIn("Reflect.defineProperty:descriptor_kind", message)
            self.assertIn("Reflect.defineProperty:descriptor_value_ref", message)
            self.assertIn("Reflect.getPrototypeOf:result_ref", message)
            self.assertIn("Reflect.setPrototypeOf:prototype_ref", message)
            self.assertIn("Reflect.setPrototypeOf:result_ref", message)
            self.assertIn("Reflect.preventExtensions:result_ref", message)
            self.assertIn("Reflect.isExtensible:result_ref", message)
            self.assertIn("Reflect.get:key_ref", message)
            self.assertIn("Reflect.get:result_ref", message)
            self.assertIn("Reflect.set:target_ref", message)
            self.assertIn("Reflect.set:key_ref", message)
            self.assertIn("Reflect.set:value_ref", message)
            self.assertIn("Reflect.set:receiver_ref", message)
            self.assertIn("Reflect.set:result_ref", message)
            self.assertIn("Reflect.has:key_ref", message)
            self.assertIn("Reflect.has:result_ref", message)
            self.assertIn("Reflect.deleteProperty:key_ref", message)
            self.assertIn("Reflect.deleteProperty:result_ref", message)
            self.assertIn("Object.values:result_element_refs", message)
            self.assertIn("Object.entries:result_element_refs", message)
            self.assertIn("Object.entries:result_entries", message)
            self.assertIn("TypedArray.indexOf:search_ref", message)
            self.assertIn("TypedArray.indexOf:from_index_ref", message)
            self.assertIn("TypedArray.indexOf:result_ref", message)
            self.assertIn("TypedArray.includes:search_ref", message)
            self.assertIn("TypedArray.includes:from_index_ref", message)
            self.assertIn("TypedArray.includes:result_ref", message)
            self.assertIn("TypedArray.lastIndexOf:search_ref", message)
            self.assertIn("TypedArray.lastIndexOf:from_index_ref", message)
            self.assertIn("TypedArray.lastIndexOf:result_ref", message)
            self.assertIn("TypedArray.find:callback_ref", message)
            self.assertIn("TypedArray.find:this_arg_ref", message)
            self.assertIn("TypedArray.find:result_ref", message)
            self.assertIn("TypedArray.findIndex:callback_ref", message)
            self.assertIn("TypedArray.findIndex:this_arg_ref", message)
            self.assertIn("TypedArray.findIndex:result_ref", message)
            self.assertIn("TypedArray.findLast:callback_ref", message)
            self.assertIn("TypedArray.findLast:this_arg_ref", message)
            self.assertIn("TypedArray.findLast:result_ref", message)
            self.assertIn("TypedArray.findLastIndex:callback_ref", message)
            self.assertIn("TypedArray.findLastIndex:this_arg_ref", message)
            self.assertIn("TypedArray.findLastIndex:result_ref", message)
            self.assertIn("TypedArray.reduce:callback_ref", message)
            self.assertIn("TypedArray.reduce:initial_value_ref", message)
            self.assertIn("TypedArray.reduce:result_ref", message)
            self.assertIn("TypedArray.reduceRight:callback_ref", message)
            self.assertIn("TypedArray.reduceRight:initial_value_ref", message)
            self.assertIn("TypedArray.reduceRight:result_ref", message)
            self.assertIn("TypedArray.filter:callback_ref", message)
            self.assertIn("TypedArray.filter:this_arg_ref", message)
            self.assertIn("TypedArray.filter:result_element_refs", message)
            self.assertIn("TypedArray.every:callback_ref", message)
            self.assertIn("TypedArray.every:this_arg_ref", message)
            self.assertIn("TypedArray.every:result_ref", message)
            self.assertIn("TypedArray.some:callback_ref", message)
            self.assertIn("TypedArray.some:this_arg_ref", message)
            self.assertIn("TypedArray.some:result_ref", message)
            self.assertIn("TypedArray.forEach:callback_ref", message)
            self.assertIn("TypedArray.forEach:this_arg_ref", message)
            self.assertIn("TypedArray.forEach:result_ref", message)

    def test_validate_trace_requires_signature_string_materialization_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "String.prototype.substr",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{
                        "subject_ref": "string:length:64",
                        "result_preview": "X-Signature=secret-one",
                    }],
                ),
                schema_v1_event(
                    "String.prototype.replace",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{
                        "subject_ref": "string:length:72",
                        "search_ref": "string:length:1",
                        "replace_ref": "string:length:1",
                    }],
                ),
                schema_v1_event(
                    "Number.prototype.toString",
                    category="reverse",
                    seq=3,
                    event_id="session-1:3",
                    args=[{
                        "input_ref": "number:1325431901.000000",
                    }],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("String.prototype.substr:result_ref", message)
            self.assertIn("String.prototype.replace:result_ref", message)
            self.assertIn("Number.prototype.toString:result_ref", message)

    def test_validate_trace_requires_request_boundary_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/records/list/?cursor=1&X-Signature=secret-one"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "Headers.set",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[{"name": "X-Signature", "value": "secret-one"}],
                ),
                schema_v1_event(
                    "Headers.append",
                    category="reverse",
                    seq=102,
                    event_id="session-1:102",
                    args=[{"name": "X-Session-Token", "value": "token-one"}],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=103,
                    event_id="session-1:103",
                    args=[{"method": "GET", "url": signed_url, "headers_id": 19}],
                ),
                schema_v1_event(
                    "fetch",
                    category="reverse",
                    seq=104,
                    event_id="session-1:104",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
                schema_v1_event(
                    "XMLHttpRequest.open",
                    category="reverse",
                    seq=105,
                    event_id="session-1:105",
                    args=[{"method": "POST", "url": signed_url}],
                ),
                schema_v1_event(
                    "XMLHttpRequest.setRequestHeader",
                    category="reverse",
                    seq=106,
                    event_id="session-1:106",
                    args=[{"method": "POST", "url": signed_url, "name": "X-Signature", "value": "secret-one"}],
                ),
                schema_v1_event(
                    "XMLHttpRequest.send",
                    category="reverse",
                    seq=107,
                    event_id="session-1:107",
                    args=[{"method": "POST", "url": signed_url, "body": "{\"cursor\":1}"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("Headers.set:value_ref", message)
            self.assertIn("Headers.append:value_ref", message)
            self.assertIn("Request.constructor:network_correlation_key", message)
            self.assertIn("fetch:network_correlation_key", message)
            self.assertIn("XMLHttpRequest.open:url_ref", message)
            self.assertIn("XMLHttpRequest.open:network_correlation_key", message)
            self.assertIn("XMLHttpRequest.setRequestHeader:value_ref", message)
            self.assertIn("XMLHttpRequest.send:body_size", message)

    def test_validate_trace_requires_url_search_params_constructor_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "URLSearchParams.constructor",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[{
                        "search_params_id": 7,
                        "url_object_id": 0,
                        "init_type": "record",
                        "has_init": True,
                        "entry_count": 1,
                        "param_names": ["X-Signature"],
                        "param_value_refs": ["string_ref:url-param-value"],
                        "param_value_lengths": [10],
                        "serialized": "X-Signature=secret-one",
                        "serialized_length": len("X-Signature=secret-one"),
                        "serialized_ref": "string_ref:serialized",
                    }],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("URLSearchParams.constructor:param_name_lengths", message)
            self.assertIn("URLSearchParams.constructor:param_name_refs", message)
            self.assertIn("URLSearchParams.constructor:param_values", message)

    def test_validate_trace_requires_request_header_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/records/list/?cursor=1"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "Headers.set",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[{
                        "headers_id": 19,
                        "name": "X-Signature",
                        "value": " secret-one ",
                        "value_ref": "string_ref:x-signature-raw",
                        "normalized_value": "secret-one",
                        "normalized_value_ref": "string_ref:x-signature-normalized",
                    }],
                ),
                schema_v1_event(
                    "Headers.append",
                    category="reverse",
                    seq=102,
                    event_id="session-1:102",
                    args=[{
                        "headers_id": 19,
                        "name": "X-Session-Token",
                        "value": " token-one ",
                        "value_ref": "string_ref:ms-token-raw",
                        "normalized_value": "token-one",
                        "normalized_value_ref": "string_ref:ms-token-normalized",
                    }],
                ),
                schema_v1_event(
                    "XMLHttpRequest.setRequestHeader",
                    category="reverse",
                    seq=103,
                    event_id="session-1:103",
                    args=[{
                        "xhr_id": 23,
                        "method": "POST",
                        "url": signed_url,
                        "url_ref": "string_ref:xhr-url",
                        "network_correlation_key": "sha1:records-post",
                        "name": "X-Signature",
                        "value": " secret-one ",
                        "value_ref": "string_ref:x-signature-raw",
                    }],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in ["Headers.set", "Headers.append"]:
                self.assertIn(f"{api}:name_length", message)
                self.assertIn(f"{api}:name_ref", message)
                self.assertIn(f"{api}:value_length", message)
                self.assertIn(f"{api}:normalized_value_length", message)
            for field in [
                "name_length",
                "name_ref",
                "value_length",
                "normalized_value",
                "normalized_value_length",
                "normalized_value_ref",
            ]:
                self.assertIn(f"XMLHttpRequest.setRequestHeader:{field}", message)

    def test_validate_trace_requires_headers_constructor_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "Headers.constructor",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[{
                        "headers_id": 19,
                        "has_init": True,
                        "init_type": "record",
                    }],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("Headers.constructor:entry_count", message)
            self.assertIn("Headers.constructor:headers", message)

    def test_validate_trace_requires_header_iterator_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "Headers.iterator.next",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[{
                        "headers_id": 19,
                        "iteration_index": 0,
                        "name": "content-type",
                        "value": "application/json",
                    }],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for field in ["name_length", "name_ref", "value_length", "value_ref"]:
                self.assertIn(f"Headers.iterator.next:{field}", message)

    def test_validate_trace_requires_formdata_iterator_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "FormData.iterator.next",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[{
                        "form_data_id": 3,
                        "iteration_index": 0,
                        "name": "X-Signature",
                        "value": "form-secret-one",
                    }],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for field in [
                "name_length",
                "name_ref",
                "value_kind",
                "value_length",
                "value_ref",
            ]:
                self.assertIn(f"FormData.iterator.next:{field}", message)

    def test_validate_trace_requires_formdata_probe_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "FormData.append",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[{"form_data_id": 3, "name": "X-Signature", "value": "form-secret-one"}],
                ),
                schema_v1_event(
                    "FormData.set",
                    category="reverse",
                    seq=102,
                    event_id="session-1:102",
                    args=[{"form_data_id": 3, "name": "X-Secondary-Signature", "value": "form-secret-two"}],
                ),
                schema_v1_event(
                    "FormData.delete",
                    category="reverse",
                    seq=103,
                    event_id="session-1:103",
                    args=[{"form_data_id": 3, "name": "X-Signature"}],
                ),
                schema_v1_event(
                    "FormData.get",
                    category="reverse",
                    seq=104,
                    event_id="session-1:104",
                    args=[{"form_data_id": 3, "name": "X-Secondary-Signature", "found": True, "result": "form-secret-two"}],
                ),
                schema_v1_event(
                    "FormData.getAll",
                    category="reverse",
                    seq=105,
                    event_id="session-1:105",
                    args=[{"form_data_id": 3, "name": "X-Signature", "values": ["form-secret-one"]}],
                ),
                schema_v1_event(
                    "FormData.has",
                    category="reverse",
                    seq=106,
                    event_id="session-1:106",
                    args=[{"form_data_id": 3, "name": "X-Signature"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in [
                "FormData.append",
                "FormData.set",
                "FormData.delete",
                "FormData.get",
                "FormData.getAll",
                "FormData.has",
            ]:
                self.assertIn(f"{api}:name_length", message)
                self.assertIn(f"{api}:name_ref", message)
            for api in ["FormData.append", "FormData.set"]:
                self.assertIn(f"{api}:value_length", message)
                self.assertIn(f"{api}:value_ref", message)
            self.assertIn("FormData.get:result_length", message)
            self.assertIn("FormData.get:result_ref", message)
            self.assertIn("FormData.getAll:result_value_lengths", message)
            self.assertIn("FormData.getAll:result_value_refs", message)

    def test_validate_trace_requires_formdata_blob_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "FormData.append",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[{"form_data_id": 3, "name": "X-Signature", "value_kind": "blob"}],
                ),
                schema_v1_event(
                    "FormData.set",
                    category="reverse",
                    seq=102,
                    event_id="session-1:102",
                    args=[{"form_data_id": 3, "name": "X-Secondary-Signature", "value_kind": "blob"}],
                ),
                schema_v1_event(
                    "FormData.get",
                    category="reverse",
                    seq=103,
                    event_id="session-1:103",
                    args=[{
                        "form_data_id": 3,
                        "name": "X-Secondary-Signature",
                        "found": True,
                        "value_kind": "blob",
                    }],
                ),
                schema_v1_event(
                    "FormData.getAll",
                    category="reverse",
                    seq=104,
                    event_id="session-1:104",
                    args=[{
                        "form_data_id": 3,
                        "name": "X-Signature",
                        "result_count": 1,
                        "blob_count": 1,
                    }],
                ),
                schema_v1_event(
                    "FormData.iterator.next",
                    category="reverse",
                    seq=105,
                    event_id="session-1:105",
                    args=[{
                        "form_data_id": 3,
                        "iteration_index": 0,
                        "name": "X-Signature",
                        "value_kind": "blob",
                    }],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in [
                "FormData.append",
                "FormData.set",
                "FormData.get",
                "FormData.iterator.next",
            ]:
                for field in [
                    "filename",
                    "filename_length",
                    "filename_ref",
                    "blob_type",
                    "blob_type_length",
                    "blob_type_ref",
                    "blob_size",
                    "blob_uuid",
                    "blob_uuid_ref",
                ]:
                    self.assertIn(f"{api}:{field}", message)
            for field in [
                "blob_filenames",
                "blob_filename_lengths",
                "blob_filename_refs",
                "blob_types",
                "blob_type_lengths",
                "blob_type_refs",
                "blob_sizes",
                "blob_uuids",
                "blob_uuid_refs",
            ]:
                self.assertIn(f"FormData.getAll:{field}", message)

    def test_validate_trace_accepts_formdata_blob_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "FormData.append",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[self.form_data_blob_args("X-Signature")],
                ),
                schema_v1_event(
                    "FormData.set",
                    category="reverse",
                    seq=102,
                    event_id="session-1:102",
                    args=[self.form_data_blob_args("X-Secondary-Signature")],
                ),
                schema_v1_event(
                    "FormData.get",
                    category="reverse",
                    seq=103,
                    event_id="session-1:103",
                    args=[self.form_data_blob_args("X-Secondary-Signature") | {"found": True}],
                ),
                schema_v1_event(
                    "FormData.getAll",
                    category="reverse",
                    seq=104,
                    event_id="session-1:104",
                    args=[self.form_data_get_all_blob_args("X-Signature")],
                ),
                schema_v1_event(
                    "FormData.iterator.next",
                    category="reverse",
                    seq=105,
                    event_id="session-1:105",
                    args=[self.form_data_blob_args("X-Signature") | {"iteration_index": 0}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            validate_trace(
                path,
                expected=[],
                schema_version=1,
                require_vmp_next_hook_fields=True,
            )

    def test_validate_trace_requires_formdata_constructor_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "FormData.constructor",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[{"form_data_id": 4}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            self.assertIn("FormData.constructor:cloned_from_form_data_id", message)
            self.assertIn("FormData.constructor:entry_count", message)
            self.assertIn("FormData.constructor:entries", message)

    def test_validate_trace_requires_header_probe_material_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "Headers.has",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[{
                        "headers_id": 19,
                        "name": "x-session-token",
                        "result": True,
                    }],
                ),
                schema_v1_event(
                    "Headers.delete",
                    category="reverse",
                    seq=102,
                    event_id="session-1:102",
                    args=[{
                        "headers_id": 19,
                        "name": "x-session-token",
                    }],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            message = str(ctx.exception)
            for api in ["Headers.has", "Headers.delete"]:
                self.assertIn(f"{api}:name_length", message)
                self.assertIn(f"{api}:name_ref", message)

    def test_validate_trace_requires_header_delete_result_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "Headers.delete",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[{
                        "headers_id": 19,
                        "name": "x-session-token",
                        "name_length": len("x-session-token"),
                        "name_ref": "string_ref:header-name",
                    }],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_vmp_next_hook_fields=True,
                )

            self.assertIn("Headers.delete:removed", str(ctx.exception))

    def test_validate_trace_accepts_request_boundary_refs_for_vmp_next_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/records/list/?cursor=1&X-Signature=secret-one"
            key = "sha1:records-get"
            post_key = "sha1:records-post"
            events = [
                *self.vmp_next_core_events(),
                schema_v1_event(
                    "Headers.set",
                    category="reverse",
                    seq=101,
                    event_id="session-1:101",
                    args=[{
                        "headers_id": 19,
                        "name": "X-Signature",
                        "name_length": 7,
                        "name_ref": "string_ref:x-signature-name",
                        "value": "secret-one",
                        "value_length": 10,
                        "value_ref": "string_ref:x-signature",
                        "normalized_value": "secret-one",
                        "normalized_value_length": 10,
                        "normalized_value_ref": "string_ref:x-signature",
                    }],
                ),
                schema_v1_event(
                    "Headers.append",
                    category="reverse",
                    seq=102,
                    event_id="session-1:102",
                    args=[{
                        "headers_id": 19,
                        "name": "X-Session-Token",
                        "name_length": 10,
                        "name_ref": "string_ref:ms-token-name",
                        "value": "token-one",
                        "value_length": 9,
                        "value_ref": "string_ref:ms-token",
                        "normalized_value": "token-one",
                        "normalized_value_length": 9,
                        "normalized_value_ref": "string_ref:ms-token",
                    }],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=103,
                    event_id="session-1:103",
                    args=[{
                        "method": "GET",
                        "url": signed_url,
                        "url_ref": "string_ref:signed",
                        "headers_id": 19,
                        "has_body": False,
                        "body_byte_length": 0,
                        "body": None,
                        "body_ref": None,
                        "network_correlation_key": key,
                    }],
                ),
                schema_v1_event(
                    "fetch",
                    category="reverse",
                    seq=104,
                    event_id="session-1:104",
                    args=[{
                        "method": "GET",
                        "url": signed_url,
                        "url_ref": "string_ref:signed",
                        "headers_id": 19,
                        "has_body": False,
                        "body_byte_length": 0,
                        "network_correlation_key": key,
                    }],
                ),
                schema_v1_event(
                    "XMLHttpRequest.open",
                    category="reverse",
                    seq=105,
                    event_id="session-1:105",
                    args=[{
                        "method": "POST",
                        "url": signed_url,
                        "url_ref": "string_ref:signed",
                        "network_correlation_key": post_key,
                        "async": True,
                    }],
                ),
                schema_v1_event(
                    "XMLHttpRequest.setRequestHeader",
                    category="reverse",
                    seq=106,
                    event_id="session-1:106",
                    args=[{
                        "xhr_id": 23,
                        "method": "POST",
                        "url": signed_url,
                        "url_ref": "string_ref:signed",
                        "network_correlation_key": post_key,
                        "name": "X-Signature",
                        "name_length": 7,
                        "name_ref": "string_ref:x-signature-name",
                        "value": "secret-one",
                        "value_length": 10,
                        "value_ref": "string_ref:x-signature",
                        "normalized_value": "secret-one",
                        "normalized_value_length": 10,
                        "normalized_value_ref": "string_ref:x-signature",
                    }],
                ),
                schema_v1_event(
                    "XMLHttpRequest.send",
                    category="reverse",
                    seq=107,
                    event_id="session-1:107",
                    args=[{
                        "method": "POST",
                        "url": signed_url,
                        "url_ref": "string_ref:signed",
                        "network_correlation_key": post_key,
                        "body_type": "string",
                        "body_size": 12,
                        "body": "{\"cursor\":1}",
                        "body_ref": "string_ref:xhr-body",
                    }],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            validate_trace(
                path,
                expected=[],
                schema_version=1,
                require_vmp_next_hook_fields=True,
            )

    def test_validate_trace_can_require_signature_param_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "String.prototype.substr",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{
                        "subject_ref": "string:length:40",
                        "result": "X-Signature=secret-one",
                        "result_ref": "string:length:18",
                    }],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
                schema_v1_event(
                    "BrowserNetwork.request",
                    category="network",
                    seq=3,
                    event_id="session-1:3",
                    args=[{"method": "GET", "url": signed_url}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            validate_trace(
                path,
                expected=[],
                schema_version=1,
                require_signature_param_materialization=["X-Signature"],
            )

    def test_validate_trace_rejects_signature_param_materialization_from_preview_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "String.prototype.substr",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{
                        "subject_ref": "string:length:40",
                        "result_preview": "X-Signature=secret-one",
                        "result_ref": "string:length:18",
                    }],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_signature_param_materialization=["X-Signature"],
                )

            self.assertIn("X-Signature runtime materialization", str(ctx.exception))

    def test_validate_trace_rejects_signature_materialization_with_empty_ref(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "String.prototype.substr",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{
                        "subject_ref": "string:length:40",
                        "result": "X-Signature=secret-one",
                        "result_ref": None,
                    }],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_signature_param_materialization=["X-Signature"],
                )

            self.assertIn("X-Signature runtime materialization", str(ctx.exception))

    def test_validate_trace_rejects_signature_materialization_with_redacted_ref(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "String.prototype.substr",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{
                        "subject_ref": "string:length:40",
                        "result": "X-Signature=secret-one",
                        "result_ref": "<redacted>",
                    }],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_signature_param_materialization=["X-Signature"],
                )

            self.assertIn("X-Signature runtime materialization", str(ctx.exception))

    def test_validate_trace_rejects_signed_param_without_runtime_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
                schema_v1_event(
                    "BrowserNetwork.request",
                    category="network",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(
                    path,
                    expected=[],
                    schema_version=1,
                    require_signature_param_materialization=["X-Signature"],
                )

            self.assertIn("X-Signature runtime materialization", str(ctx.exception))

    def test_main_accepts_required_vmp_family(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event("DataView.getUint32", category="reverse")
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "DataView.getUint32",
                    "--require-vmp-family",
                    "byte_buffer",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_required_vmp_family_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "DataView.getUint32",
                category="reverse",
                args=[{
                    "byte_offset": 4,
                    "result": 3735928559,
                    "result_ref": "number:3735928559",
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "DataView.getUint32",
                    "--require-vmp-family",
                    "byte_buffer",
                    "--require-vmp-family-evidence",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_required_vmp_next_hook_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "Function.prototype.call",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{"target_id": "function:sign"}],
                ),
                schema_v1_event(
                    "Function.prototype.apply",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"target_id": "function:encode"}],
                ),
                schema_v1_event(
                    "Reflect.apply",
                    category="reverse",
                    seq=3,
                    event_id="session-1:3",
                    args=[{"target_id": "function:mix"}],
                ),
                schema_v1_event(
                    "String.fromCharCode",
                    category="reverse",
                    seq=4,
                    event_id="session-1:4",
                    args=[{"first_code_ref": "number:65", "result_ref": "string:A"}],
                ),
                schema_v1_event(
                    "String.prototype.slice",
                    category="reverse",
                    seq=5,
                    event_id="session-1:5",
                    args=[{
                        "subject_ref": "string:length:40",
                        "result_ref": "string:length:39",
                    }],
                ),
                schema_v1_event(
                    "encodeURIComponent",
                    category="reverse",
                    seq=6,
                    event_id="session-1:6",
                    args=[self.uri_codec_args("cursor=1&token=a b", "cursor%3D1%26token%3Da%20b")],
                ),
                schema_v1_event(
                    "Bitwise.xor",
                    category="reverse",
                    seq=7,
                    event_id="session-1:7",
                    args=[{"left_ref": "number:1", "right_ref": "number:2", "result_ref": "number:3"}],
                ),
                schema_v1_event(
                    "URLSearchParams.set",
                    category="reverse",
                    seq=8,
                    event_id="session-1:8",
                    args=[self.url_search_params_set_args("X-Signature", "secret-one")],
                ),
                schema_v1_event(
                    "URLSearchParams.toString",
                    category="reverse",
                    seq=9,
                    event_id="session-1:9",
                    args=[self.url_search_params_to_string_args()],
                ),
                schema_v1_event(
                    "URL.href.set",
                    category="reverse",
                    seq=10,
                    event_id="session-1:10",
                    args=[{"value_ref": "string:length:27", "href_ref": "string:length:27"}],
                ),
                schema_v1_event(
                    "URL.search.set",
                    category="reverse",
                    seq=11,
                    event_id="session-1:11",
                    args=[{
                        "value_ref": "string:length:27",
                        "search_ref": "string:length:27",
                        "href_ref": "string:length:64",
                    }],
                ),
                schema_v1_event(
                    "Location.href.get",
                    category="reverse",
                    seq=24,
                    event_id="session-1:24",
                    args=[self.location_read_args("https://www.example.test/api/records/list/?cursor=1")],
                ),
                schema_v1_event(
                    "Location.search.get",
                    category="reverse",
                    seq=25,
                    event_id="session-1:25",
                    args=[self.location_read_args(
                        "?cursor=1",
                        href="https://www.example.test/api/records/list/?cursor=1",
                    )],
                ),
                schema_v1_event(
                    "Location.href.set",
                    category="reverse",
                    seq=26,
                    event_id="session-1:26",
                    args=[self.location_write_args(
                        "/api/records/list/?cursor=2",
                        "https://www.example.test/api/records/list/?cursor=2",
                    )],
                ),
                schema_v1_event(
                    "Location.search.set",
                    category="reverse",
                    seq=27,
                    event_id="session-1:27",
                    args=[self.location_write_args(
                        "?cursor=2&X-Signature=secret-one",
                        "https://www.example.test/api/records/list/?cursor=2&X-Signature=secret-one",
                    )],
                ),
                schema_v1_event(
                    "Location.assign",
                    category="reverse",
                    seq=28,
                    event_id="session-1:28",
                    args=[self.location_write_args(
                        "/api/records/list/?cursor=3",
                        "https://www.example.test/api/records/list/?cursor=3",
                    )],
                ),
                schema_v1_event(
                    "Location.replace",
                    category="reverse",
                    seq=29,
                    event_id="session-1:29",
                    args=[self.location_write_args(
                        "/api/records/list/?cursor=4",
                        "https://www.example.test/api/records/list/?cursor=4",
                    )],
                ),
                schema_v1_event(
                    "Storage.getItem",
                    category="reverse",
                    seq=13,
                    event_id="session-1:13",
                    args=[self.storage_get_item_args("sessionToken", "token-value")],
                ),
                schema_v1_event(
                    "Storage.setItem",
                    category="reverse",
                    seq=14,
                    event_id="session-1:14",
                    args=[self.storage_set_item_args("x-signature-seed", "seed-value")],
                ),
                schema_v1_event(
                    "Storage.removeItem",
                    category="reverse",
                    seq=15,
                    event_id="session-1:15",
                    args=[self.storage_remove_item_args("old-token")],
                ),
                schema_v1_event(
                    "Storage.key",
                    category="reverse",
                    seq=16,
                    event_id="session-1:16",
                    args=[self.storage_key_args("sessionToken")],
                ),
                schema_v1_event(
                    "Document.cookie.get",
                    category="reverse",
                    seq=17,
                    event_id="session-1:17",
                    args=[self.document_cookie_get_args("sessionToken=token-value")],
                ),
                schema_v1_event(
                    "Document.cookie.set",
                    category="reverse",
                    seq=18,
                    event_id="session-1:18",
                    args=[self.document_cookie_set_args("x-signature-seed=seed-value; path=/")],
                ),
                schema_v1_event(
                    "Document.urlForBinding.get",
                    category="reverse",
                    seq=30,
                    event_id="session-1:30",
                    args=[self.document_context_args("https://www.example.test/api/records/list/?cursor=1")],
                ),
                schema_v1_event(
                    "Document.referrer.get",
                    category="reverse",
                    seq=31,
                    event_id="session-1:31",
                    args=[self.document_context_args("https://www.example.test/from-feed")],
                ),
                schema_v1_event(
                    "Node.baseURI.get",
                    category="reverse",
                    seq=32,
                    event_id="session-1:32",
                    args=[self.document_context_args("https://www.example.test/")],
                ),
                schema_v1_event(
                    "CookieStore.get",
                    category="reverse",
                    seq=19,
                    event_id="session-1:19",
                    args=[self.cookie_store_get_args("sessionToken")],
                ),
                schema_v1_event(
                    "CookieStore.getAll",
                    category="reverse",
                    seq=20,
                    event_id="session-1:20",
                    args=[self.cookie_store_get_args("sessionToken", result_count=2)],
                ),
                schema_v1_event(
                    "CookieStore.set",
                    category="reverse",
                    seq=21,
                    event_id="session-1:21",
                    args=[self.cookie_store_set_args("x-signature-seed", "seed-value")],
                ),
                schema_v1_event(
                    "CookieStore.delete",
                    category="reverse",
                    seq=22,
                    event_id="session-1:22",
                    args=[self.cookie_store_delete_args("old-token")],
                ),
                schema_v1_event(
                    "BigInt.prototype.toString",
                    category="reverse",
                    seq=23,
                    event_id="session-1:23",
                    args=[{"result_ref": "string:length:4"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "Function.prototype.call",
                    "--require-vmp-next-hook-fields",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_required_signature_param_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "String.prototype.substr",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{
                        "result": "X-Signature=secret-one",
                        "result_ref": "string:length:18",
                    }],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "String.prototype.substr",
                    "--require-signature-param-materialization",
                    "X-Signature",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_headers_constructor_signature_param_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "Headers.constructor",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[self.headers_constructor_args("X-Signature", "secret-one")],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "Headers.constructor",
                    "--require-signature-param-materialization",
                    "X-Signature",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_headers_get_signature_param_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "Headers.get",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[self.headers_get_args("X-Signature", "secret-one")],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "Headers.get",
                    "--require-signature-param-materialization",
                    "X-Signature",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_headers_iterator_signature_param_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "Headers.iterator.next",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[self.headers_iterator_args("X-Signature", "secret-one")],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "Headers.iterator.next",
                    "--require-signature-param-materialization",
                    "X-Signature",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_url_search_params_iterator_signature_param_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "URLSearchParams.iterator.next",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[self.url_search_params_iterator_args("X-Signature", "secret-one")],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "URLSearchParams.iterator.next",
                    "--require-signature-param-materialization",
                    "X-Signature",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_url_search_params_constructor_signature_param_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "URLSearchParams.constructor",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[self.url_search_params_constructor_args("X-Signature", "secret-one")],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "URLSearchParams.constructor",
                    "--require-signature-param-materialization",
                    "X-Signature",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_url_search_params_get_all_signature_param_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "URLSearchParams.getAll",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[self.url_search_params_get_all_args("X-Signature", ["secret-one"])],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "URLSearchParams.getAll",
                    "--require-signature-param-materialization",
                    "X-Signature",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_cookie_store_get_signature_param_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "CookieStore.get",
                    category="reverse",
                    phase="return",
                    seq=1,
                    event_id="session-1:1",
                    args=[self.cookie_store_get_args("X-Signature", value="secret-one")],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "CookieStore.get",
                    "--require-signature-param-materialization",
                    "X-Signature",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_cookie_store_get_all_signature_param_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "CookieStore.getAll",
                    category="reverse",
                    phase="return",
                    seq=1,
                    event_id="session-1:1",
                    args=[self.cookie_store_get_args("X-Signature", value="secret-one")],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "CookieStore.getAll",
                    "--require-signature-param-materialization",
                    "X-Signature",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_cookie_store_set_signature_param_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "CookieStore.set",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[self.cookie_store_set_args("X-Signature", "secret-one")],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "GET", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "CookieStore.set",
                    "--require-signature-param-materialization",
                    "X-Signature",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_formdata_get_all_signature_param_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "FormData.getAll",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[self.form_data_get_all_args("X-Signature", ["secret-one"])],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "POST", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "FormData.getAll",
                    "--require-signature-param-materialization",
                    "X-Signature",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_formdata_constructor_signature_param_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "FormData.constructor",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[self.form_data_constructor_clone_args("X-Signature", "secret-one")],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "POST", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "FormData.constructor",
                    "--require-signature-param-materialization",
                    "X-Signature",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_formdata_iterator_signature_param_materialization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            signed_url = "https://www.example.test/api/feed/list?cursor=1&X-Signature=secret-one"
            events = [
                schema_v1_event(
                    "FormData.iterator.next",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[self.form_data_iterator_args("X-Signature", "secret-one")],
                ),
                schema_v1_event(
                    "Request.constructor",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{"method": "POST", "url": signed_url, "url_ref": "string_ref:signed"}],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "FormData.iterator.next",
                    "--require-signature-param-materialization",
                    "X-Signature",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_required_complete_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "Request.constructor",
                category="reverse",
                args=[{
                    "method": "GET",
                    "url": "https://www.example.test/api/feed?X-Signature=secret",
                    "url_ref": "string_ref:signed",
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "Request.constructor",
                    "--require-complete-values",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_accepts_required_material_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "Headers.set",
                category="reverse",
                args=[{
                    "name": "X-Signature",
                    "value": "secret",
                    "value_ref": "string_ref:sha1:abcdef",
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "Headers.set",
                    "--require-material-refs",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_strict_capture_defaults_to_schema_v1(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                json.dumps({"t": "call", "api": "Headers.set", "args": []}) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "Headers.set",
                    "--strict-capture",
                    str(path),
                ])

            self.assertEqual(result, 1)
            self.assertIn("schema_version", stdout.getvalue())

    def test_main_strict_capture_rejects_summary_refs_without_manual_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event(
                "Headers.set",
                category="reverse",
                args=[{
                    "name": "X-Signature",
                    "value": "secret",
                    "value_ref": "string:length:6",
                }],
            )
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--expect",
                    "Headers.set",
                    "--strict-capture",
                    str(path),
                ])

            self.assertEqual(result, 1)
            self.assertIn("Non-material refs", stdout.getvalue())
            self.assertIn("summary ref event 1: args[0].value_ref", stdout.getvalue())

    def test_validate_trace_keeps_legacy_proof_of_life_compatible(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.ndjson"
            path.write_text(
                '{"t":"call","api":"Crypto.getRandomValues","args":[],"stack":[],"pid":100,"tid":200}\n',
                encoding="utf-8",
            )
            validate_trace(path, expected=["Crypto.getRandomValues"])

    def test_schema_v1_accepts_complete_and_iterate_phase_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event("BrowserNetwork.request", category="network", phase="complete"),
                schema_v1_event("Headers.iterator.next", category="reverse", phase="iterate"),
            ]
            path.write_text(
                "\n".join(json.dumps(item) for item in events) + "\n",
                encoding="utf-8",
            )

            validate_trace(
                path,
                expected=["BrowserNetwork.request", "Headers.iterator.next"],
                schema_version=1,
            )

    def test_generic_vmp_profile_strict_capture_accepts_markerless_vmp_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            item = schema_v1_event(
                "Bitwise.xor",
                category="reverse",
                args=[{
                    "left": 1,
                    "left_ref": "number:1",
                    "right": 2,
                    "right_ref": "number:2",
                    "result": 3,
                    "result_ref": "number:3",
                }],
            )
            path.write_text(json.dumps(item) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--profile",
                    "generic-vmp",
                    "--strict-capture",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_generic_vmp_profile_strict_capture_does_not_require_all_vmp_families(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            item = schema_v1_event(
                "String.prototype.slice",
                category="reverse",
                args=[{
                    "subject": "abcdef",
                    "subject_ref": "string_ref:subject",
                    "start": 1,
                    "result": "bcdef",
                    "result_ref": "string_ref:result",
                }],
            )
            path.write_text(json.dumps(item) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--profile",
                    "generic-vmp",
                    "--strict-capture",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertNotIn("Missing expected VMP families", stdout.getvalue())
            self.assertNotIn("X-Signature", stdout.getvalue())

    def test_generic_vmp_profile_keeps_explicit_family_requirements(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            item = schema_v1_event(
                "Function.prototype.call",
                category="reverse",
                args=[{"target_type": "function", "target_ref": "function:dispatcher"}],
            )
            path.write_text(json.dumps(item) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--profile",
                    "generic-vmp",
                    "--strict-capture",
                    "--require-vmp-family",
                    "dynamic_dispatch",
                    str(path),
                ])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_main_extends_profile_expectations_with_explicit_expect(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            event = schema_v1_event("SubtleCrypto.sign", category="reverse")
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([
                    "--profile",
                    "reverse",
                    "--expect",
                    "SubtleCrypto.sign",
                    "--schema-version",
                    "1",
                    str(path),
                ])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("Missing expected APIs", output)
            self.assertIn("fetch", output)

    def test_profile_reverse_checks_reverse_expected_apis(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event("fetch", category="reverse", seq=1, event_id="session-1:1"),
                schema_v1_event("XMLHttpRequest.open", category="reverse", seq=2, event_id="session-1:2"),
                schema_v1_event("XMLHttpRequest.send", category="reverse", seq=3, event_id="session-1:3"),
                schema_v1_event("XMLHttpRequest.setRequestHeader", category="reverse", seq=129, event_id="session-1:129"),
                schema_v1_event("XMLHttpRequest.responseText", category="reverse", seq=130, event_id="session-1:130"),
                schema_v1_event("Storage.setItem", category="reverse", seq=4, event_id="session-1:4"),
                schema_v1_event("Document.cookie.get", category="reverse", seq=5, event_id="session-1:5"),
                schema_v1_event("eval", category="reverse", seq=6, event_id="session-1:6"),
                schema_v1_event("Function", category="reverse", seq=7, event_id="session-1:7"),
                schema_v1_event("setTimeout.string", category="reverse", seq=8, event_id="session-1:8"),
                schema_v1_event("HTMLScriptElement.src.set", category="reverse", seq=9, event_id="session-1:9"),
                schema_v1_event("EventTarget.addEventListener", category="reverse", seq=10, event_id="session-1:10"),
                schema_v1_event("EventTarget.removeEventListener", category="reverse", seq=11, event_id="session-1:11"),
                schema_v1_event("EventTarget.dispatchEvent", category="reverse", seq=12, event_id="session-1:12"),
                schema_v1_event("EventTarget.listener.invoke", category="reverse", seq=13, event_id="session-1:13"),
                schema_v1_event("queueMicrotask", category="reverse", seq=14, event_id="session-1:14"),
                schema_v1_event("Promise.prototype.then", category="reverse", seq=114, event_id="session-1:114"),
                schema_v1_event("Promise.prototype.catch", category="reverse", seq=115, event_id="session-1:115"),
                schema_v1_event("Promise.prototype.finally", category="reverse", seq=116, event_id="session-1:116"),
                schema_v1_event("Promise.resolve", category="reverse", seq=295, event_id="session-1:295"),
                schema_v1_event("Promise.reject", category="reverse", seq=296, event_id="session-1:296"),
                schema_v1_event("Promise.all", category="reverse", seq=297, event_id="session-1:297"),
                schema_v1_event("Promise.allSettled", category="reverse", seq=298, event_id="session-1:298"),
                schema_v1_event("Promise.race", category="reverse", seq=299, event_id="session-1:299"),
                schema_v1_event("Promise.any", category="reverse", seq=300, event_id="session-1:300"),
                schema_v1_event("Promise.try", category="reverse", seq=301, event_id="session-1:301"),
                schema_v1_event("Promise.withResolvers", category="reverse", seq=302, event_id="session-1:302"),
                schema_v1_event("Array.fromAsync", category="reverse", seq=294, event_id="session-1:294"),
                schema_v1_event("AsyncFunction.enter", category="reverse", seq=309, event_id="session-1:309"),
                schema_v1_event("AsyncFunction.await", category="reverse", seq=310, event_id="session-1:310"),
                schema_v1_event("AsyncFunction.resume", category="reverse", seq=311, event_id="session-1:311"),
                schema_v1_event("AsyncFunction.resolve", category="reverse", seq=312, event_id="session-1:312"),
                schema_v1_event("AsyncFunction.reject", category="reverse", seq=313, event_id="session-1:313"),
                schema_v1_event("ClassicScript.evaluate", category="reverse", seq=117, event_id="session-1:117"),
                schema_v1_event("ModuleScript.evaluate", category="reverse", seq=118, event_id="session-1:118"),
                schema_v1_event("DynamicImport.resolve", category="reverse", seq=119, event_id="session-1:119"),
                schema_v1_event("DynamicImport.load", category="reverse", seq=120, event_id="session-1:120"),
                schema_v1_event("URLSearchParams.constructor", category="reverse", seq=131, event_id="session-1:131"),
                schema_v1_event("URLSearchParams.append", category="reverse", seq=15, event_id="session-1:15"),
                schema_v1_event("URLSearchParams.set", category="reverse", seq=16, event_id="session-1:16"),
                schema_v1_event("URLSearchParams.delete", category="reverse", seq=17, event_id="session-1:17"),
                schema_v1_event("URL.constructor", category="reverse", seq=18, event_id="session-1:18"),
                schema_v1_event("URL.href.set", category="reverse", seq=19, event_id="session-1:19"),
                schema_v1_event("URL.search.set", category="reverse", seq=20, event_id="session-1:20"),
                schema_v1_event("Location.href.set", category="reverse", seq=326, event_id="session-1:326"),
                schema_v1_event("Location.search.set", category="reverse", seq=327, event_id="session-1:327"),
                schema_v1_event("Location.assign", category="reverse", seq=328, event_id="session-1:328"),
                schema_v1_event("Location.replace", category="reverse", seq=329, event_id="session-1:329"),
                schema_v1_event("Document.urlForBinding.get", category="reverse", seq=332, event_id="session-1:332"),
                schema_v1_event("Document.referrer.get", category="reverse", seq=333, event_id="session-1:333"),
                schema_v1_event("Node.baseURI.get", category="reverse", seq=334, event_id="session-1:334"),
                schema_v1_event("Headers.constructor", category="reverse", seq=21, event_id="session-1:21"),
                schema_v1_event("Headers.append", category="reverse", seq=22, event_id="session-1:22"),
                schema_v1_event("Headers.set", category="reverse", seq=23, event_id="session-1:23"),
                schema_v1_event("Headers.delete", category="reverse", seq=24, event_id="session-1:24"),
                schema_v1_event("Headers.get", category="reverse", seq=139, event_id="session-1:139"),
                schema_v1_event("Headers.has", category="reverse", seq=140, event_id="session-1:140"),
                schema_v1_event("FormData.constructor", category="reverse", seq=132, event_id="session-1:132"),
                schema_v1_event("FormData.append", category="reverse", seq=133, event_id="session-1:133"),
                schema_v1_event("FormData.set", category="reverse", seq=134, event_id="session-1:134"),
                schema_v1_event("FormData.get", category="reverse", seq=135, event_id="session-1:135"),
                schema_v1_event("FormData.getAll", category="reverse", seq=136, event_id="session-1:136"),
                schema_v1_event("FormData.has", category="reverse", seq=137, event_id="session-1:137"),
                schema_v1_event("FormData.delete", category="reverse", seq=138, event_id="session-1:138"),
                schema_v1_event("FormData.iterator.next", category="reverse", seq=141, event_id="session-1:141"),
                schema_v1_event("btoa", category="reverse", seq=25, event_id="session-1:25"),
                schema_v1_event("atob", category="reverse", seq=26, event_id="session-1:26"),
                schema_v1_event("TextEncoder.constructor", category="reverse", seq=27, event_id="session-1:27"),
                schema_v1_event("TextEncoder.encode", category="reverse", seq=28, event_id="session-1:28"),
                schema_v1_event("TextEncoder.encodeInto", category="reverse", seq=29, event_id="session-1:29"),
                schema_v1_event("TextDecoder.constructor", category="reverse", seq=30, event_id="session-1:30"),
                schema_v1_event("TextDecoder.decode", category="reverse", seq=31, event_id="session-1:31"),
                schema_v1_event("Crypto.getRandomValues", category="reverse", seq=324, event_id="session-1:324"),
                schema_v1_event("Crypto.randomUUID", category="reverse", seq=325, event_id="session-1:325"),
                schema_v1_event("SubtleCrypto.encrypt", category="reverse", seq=314, event_id="session-1:314"),
                schema_v1_event("SubtleCrypto.decrypt", category="reverse", seq=315, event_id="session-1:315"),
                schema_v1_event("SubtleCrypto.digest", category="reverse", seq=32, event_id="session-1:32"),
                schema_v1_event("SubtleCrypto.importKey", category="reverse", seq=121, event_id="session-1:121"),
                schema_v1_event("SubtleCrypto.sign", category="reverse", seq=122, event_id="session-1:122"),
                schema_v1_event("SubtleCrypto.verify", category="reverse", seq=316, event_id="session-1:316"),
                schema_v1_event("SubtleCrypto.generateKey", category="reverse", seq=317, event_id="session-1:317"),
                schema_v1_event("SubtleCrypto.exportKey", category="reverse", seq=318, event_id="session-1:318"),
                schema_v1_event("SubtleCrypto.deriveBits", category="reverse", seq=319, event_id="session-1:319"),
                schema_v1_event("SubtleCrypto.deriveKey", category="reverse", seq=320, event_id="session-1:320"),
                schema_v1_event("SubtleCrypto.wrapKey", category="reverse", seq=321, event_id="session-1:321"),
                schema_v1_event("SubtleCrypto.unwrapKey", category="reverse", seq=322, event_id="session-1:322"),
                schema_v1_event("ArrayBuffer.constructor", category="reverse", seq=33, event_id="session-1:33"),
                schema_v1_event("ArrayBuffer.prototype.slice", category="reverse", seq=153, event_id="session-1:153"),
                schema_v1_event("DataView.getInt8", category="reverse", seq=129, event_id="session-1:129"),
                schema_v1_event("DataView.getInt16", category="reverse", seq=130, event_id="session-1:130"),
                schema_v1_event("DataView.getUint8", category="reverse", seq=123, event_id="session-1:123"),
                schema_v1_event("DataView.getUint16", category="reverse", seq=124, event_id="session-1:124"),
                schema_v1_event("DataView.getUint32", category="reverse", seq=34, event_id="session-1:34"),
                schema_v1_event("DataView.getInt32", category="reverse", seq=125, event_id="session-1:125"),
                schema_v1_event("DataView.getBigUint64", category="reverse", seq=143, event_id="session-1:143"),
                schema_v1_event("DataView.getBigInt64", category="reverse", seq=144, event_id="session-1:144"),
                schema_v1_event("DataView.getFloat16", category="reverse", seq=151, event_id="session-1:151"),
                schema_v1_event("DataView.getFloat32", category="reverse", seq=147, event_id="session-1:147"),
                schema_v1_event("DataView.getFloat64", category="reverse", seq=148, event_id="session-1:148"),
                schema_v1_event("DataView.setInt8", category="reverse", seq=131, event_id="session-1:131"),
                schema_v1_event("DataView.setInt16", category="reverse", seq=132, event_id="session-1:132"),
                schema_v1_event("DataView.setUint8", category="reverse", seq=126, event_id="session-1:126"),
                schema_v1_event("DataView.setUint16", category="reverse", seq=127, event_id="session-1:127"),
                schema_v1_event("DataView.setUint32", category="reverse", seq=35, event_id="session-1:35"),
                schema_v1_event("DataView.setInt32", category="reverse", seq=128, event_id="session-1:128"),
                schema_v1_event("DataView.setBigUint64", category="reverse", seq=145, event_id="session-1:145"),
                schema_v1_event("DataView.setBigInt64", category="reverse", seq=146, event_id="session-1:146"),
                schema_v1_event("DataView.setFloat16", category="reverse", seq=152, event_id="session-1:152"),
                schema_v1_event("DataView.setFloat32", category="reverse", seq=149, event_id="session-1:149"),
                schema_v1_event("DataView.setFloat64", category="reverse", seq=150, event_id="session-1:150"),
                schema_v1_event("TypedArray.at", category="reverse", seq=36, event_id="session-1:36"),
                schema_v1_event("TypedArray.slice", category="reverse", seq=37, event_id="session-1:37"),
                schema_v1_event("TypedArray.subarray", category="reverse", seq=139, event_id="session-1:139"),
                schema_v1_event("TypedArray.set", category="reverse", seq=140, event_id="session-1:140"),
                schema_v1_event("TypedArray.copyWithin", category="reverse", seq=141, event_id="session-1:141"),
                schema_v1_event("TypedArray.fill", category="reverse", seq=142, event_id="session-1:142"),
                schema_v1_event("TypedArray.reverse", category="reverse", seq=154, event_id="session-1:154"),
                schema_v1_event("TypedArray.sort", category="reverse", seq=155, event_id="session-1:155"),
                schema_v1_event("TypedArray.join", category="reverse", seq=38, event_id="session-1:38"),
                schema_v1_event("TypedArray.indexOf", category="reverse", seq=203, event_id="session-1:203"),
                schema_v1_event("TypedArray.includes", category="reverse", seq=204, event_id="session-1:204"),
                schema_v1_event("TypedArray.lastIndexOf", category="reverse", seq=205, event_id="session-1:205"),
                schema_v1_event("TypedArray.find", category="reverse", seq=218, event_id="session-1:218"),
                schema_v1_event("TypedArray.findIndex", category="reverse", seq=219, event_id="session-1:219"),
                schema_v1_event("TypedArray.findLast", category="reverse", seq=220, event_id="session-1:220"),
                schema_v1_event("TypedArray.findLastIndex", category="reverse", seq=221, event_id="session-1:221"),
                schema_v1_event("TypedArray.reduce", category="reverse", seq=222, event_id="session-1:222"),
                schema_v1_event("TypedArray.reduceRight", category="reverse", seq=223, event_id="session-1:223"),
                schema_v1_event("TypedArray.filter", category="reverse", seq=224, event_id="session-1:224"),
                schema_v1_event("TypedArray.every", category="reverse", seq=225, event_id="session-1:225"),
                schema_v1_event("TypedArray.some", category="reverse", seq=226, event_id="session-1:226"),
                schema_v1_event("TypedArray.forEach", category="reverse", seq=227, event_id="session-1:227"),
                schema_v1_event("TypedArray.entries", category="reverse", seq=284, event_id="session-1:284"),
                schema_v1_event("TypedArray.keys", category="reverse", seq=285, event_id="session-1:285"),
                schema_v1_event("TypedArray.values", category="reverse", seq=286, event_id="session-1:286"),
                schema_v1_event("Array.prototype.at", category="reverse", seq=200, event_id="session-1:200"),
                schema_v1_event("Array.prototype.indexOf", category="reverse", seq=201, event_id="session-1:201"),
                schema_v1_event("Array.prototype.includes", category="reverse", seq=202, event_id="session-1:202"),
                schema_v1_event("Array.prototype.lastIndexOf", category="reverse", seq=206, event_id="session-1:206"),
                schema_v1_event("Array.prototype.find", category="reverse", seq=207, event_id="session-1:207"),
                schema_v1_event("Array.prototype.findIndex", category="reverse", seq=208, event_id="session-1:208"),
                schema_v1_event("Array.prototype.findLast", category="reverse", seq=209, event_id="session-1:209"),
                schema_v1_event("Array.prototype.findLastIndex", category="reverse", seq=210, event_id="session-1:210"),
                schema_v1_event("Array.prototype.reduce", category="reverse", seq=211, event_id="session-1:211"),
                schema_v1_event("Array.prototype.reduceRight", category="reverse", seq=212, event_id="session-1:212"),
                schema_v1_event("Array.prototype.map", category="reverse", seq=213, event_id="session-1:213"),
                schema_v1_event("Array.prototype.filter", category="reverse", seq=214, event_id="session-1:214"),
                schema_v1_event("Array.prototype.flat", category="reverse", seq=228, event_id="session-1:228"),
                schema_v1_event("Array.prototype.flatMap", category="reverse", seq=229, event_id="session-1:229"),
                schema_v1_event("Array.prototype.every", category="reverse", seq=215, event_id="session-1:215"),
                schema_v1_event("Array.prototype.some", category="reverse", seq=216, event_id="session-1:216"),
                schema_v1_event("Array.prototype.forEach", category="reverse", seq=217, event_id="session-1:217"),
                schema_v1_event("Array.prototype.push", category="reverse", seq=39, event_id="session-1:39"),
                schema_v1_event("Array.prototype.pop", category="reverse", seq=157, event_id="session-1:157"),
                schema_v1_event("Array.prototype.unshift", category="reverse", seq=158, event_id="session-1:158"),
                schema_v1_event("Array.prototype.shift", category="reverse", seq=156, event_id="session-1:156"),
                schema_v1_event("Array.prototype.splice", category="reverse", seq=159, event_id="session-1:159"),
                schema_v1_event("Array.prototype.reverse", category="reverse", seq=160, event_id="session-1:160"),
                schema_v1_event("Array.prototype.sort", category="reverse", seq=161, event_id="session-1:161"),
                schema_v1_event("Array.prototype.copyWithin", category="reverse", seq=162, event_id="session-1:162"),
                schema_v1_event("Array.prototype.fill", category="reverse", seq=163, event_id="session-1:163"),
                schema_v1_event("Array.prototype.slice", category="reverse", seq=40, event_id="session-1:40"),
                schema_v1_event("Array.prototype.join", category="reverse", seq=41, event_id="session-1:41"),
                schema_v1_event("Array.prototype.entries", category="reverse", seq=280, event_id="session-1:280"),
                schema_v1_event("Array.prototype.keys", category="reverse", seq=281, event_id="session-1:281"),
                schema_v1_event("Array.prototype.values", category="reverse", seq=282, event_id="session-1:282"),
                schema_v1_event("ArrayIterator.prototype.next", category="reverse", seq=283, event_id="session-1:283"),
                schema_v1_event("Generator.prototype.next", category="reverse", seq=303, event_id="session-1:303"),
                schema_v1_event("Generator.prototype.return", category="reverse", seq=304, event_id="session-1:304"),
                schema_v1_event("Generator.prototype.throw", category="reverse", seq=305, event_id="session-1:305"),
                schema_v1_event("AsyncGenerator.prototype.next", category="reverse", seq=306, event_id="session-1:306"),
                schema_v1_event("AsyncGenerator.prototype.return", category="reverse", seq=307, event_id="session-1:307"),
                schema_v1_event("AsyncGenerator.prototype.throw", category="reverse", seq=308, event_id="session-1:308"),
                schema_v1_event("Array.from", category="reverse", seq=292, event_id="session-1:292"),
                schema_v1_event("Array.of", category="reverse", seq=293, event_id="session-1:293"),
                schema_v1_event("Reflect.construct", category="reverse", seq=259, event_id="session-1:259"),
                schema_v1_event("Object.keys", category="reverse", seq=42, event_id="session-1:42"),
                schema_v1_event("Object.prototype.toString", category="reverse", seq=253, event_id="session-1:253"),
                schema_v1_event("Array.isArray", category="reverse", seq=254, event_id="session-1:254"),
                schema_v1_event("Object.is", category="reverse", seq=255, event_id="session-1:255"),
                schema_v1_event("Object.hasOwn", category="reverse", seq=251, event_id="session-1:251"),
                schema_v1_event("Object.prototype.hasOwnProperty", category="reverse", seq=252, event_id="session-1:252"),
                schema_v1_event("Object.assign", category="reverse", seq=232, event_id="session-1:232"),
                schema_v1_event("Object.create", category="reverse", seq=235, event_id="session-1:235"),
                schema_v1_event("Object.getPrototypeOf", category="reverse", seq=236, event_id="session-1:236"),
                schema_v1_event("Object.setPrototypeOf", category="reverse", seq=237, event_id="session-1:237"),
                schema_v1_event("Object.preventExtensions", category="reverse", seq=242, event_id="session-1:242"),
                schema_v1_event("Object.freeze", category="reverse", seq=243, event_id="session-1:243"),
                schema_v1_event("Object.seal", category="reverse", seq=244, event_id="session-1:244"),
                schema_v1_event("Object.isExtensible", category="reverse", seq=245, event_id="session-1:245"),
                schema_v1_event("Object.isFrozen", category="reverse", seq=246, event_id="session-1:246"),
                schema_v1_event("Object.isSealed", category="reverse", seq=247, event_id="session-1:247"),
                schema_v1_event("Object.getOwnPropertyDescriptor", category="reverse", seq=240, event_id="session-1:240"),
                schema_v1_event("Object.getOwnPropertyDescriptors", category="reverse", seq=241, event_id="session-1:241"),
                schema_v1_event("Object.defineProperty", category="reverse", seq=233, event_id="session-1:233"),
                schema_v1_event("Object.defineProperties", category="reverse", seq=258, event_id="session-1:258"),
                schema_v1_event("Object.values", category="reverse", seq=230, event_id="session-1:230"),
                schema_v1_event("Object.entries", category="reverse", seq=231, event_id="session-1:231"),
                schema_v1_event("Object.getOwnPropertyNames", category="reverse", seq=43, event_id="session-1:43"),
                schema_v1_event("Reflect.getPrototypeOf", category="reverse", seq=238, event_id="session-1:238"),
                schema_v1_event("Reflect.setPrototypeOf", category="reverse", seq=239, event_id="session-1:239"),
                schema_v1_event("Reflect.preventExtensions", category="reverse", seq=248, event_id="session-1:248"),
                schema_v1_event("Reflect.isExtensible", category="reverse", seq=249, event_id="session-1:249"),
                schema_v1_event("Reflect.defineProperty", category="reverse", seq=234, event_id="session-1:234"),
                schema_v1_event("Reflect.ownKeys", category="reverse", seq=44, event_id="session-1:44"),
                schema_v1_event("Reflect.getOwnPropertyDescriptor", category="reverse", seq=45, event_id="session-1:45"),
                schema_v1_event("Reflect.get", category="reverse", seq=46, event_id="session-1:46"),
                schema_v1_event("Reflect.set", category="reverse", seq=256, event_id="session-1:256"),
                schema_v1_event("Reflect.has", category="reverse", seq=47, event_id="session-1:47"),
                schema_v1_event("Reflect.deleteProperty", category="reverse", seq=250, event_id="session-1:250"),
                schema_v1_event(
                    "Object.prototype.propertyIsEnumerable",
                    category="reverse",
                    seq=257,
                    event_id="session-1:257",
                ),
                schema_v1_event("Map.prototype.get", category="reverse", seq=48, event_id="session-1:48"),
                schema_v1_event("Map.prototype.has", category="reverse", seq=49, event_id="session-1:49"),
                schema_v1_event("Map.prototype.set", category="reverse", seq=50, event_id="session-1:50"),
                schema_v1_event("Map.prototype.delete", category="reverse", seq=51, event_id="session-1:51"),
                schema_v1_event("Map.prototype.clear", category="reverse", seq=258, event_id="session-1:258"),
                schema_v1_event("Map.prototype.getOrInsert", category="reverse", seq=267, event_id="session-1:267"),
                schema_v1_event("Map.prototype.getOrInsertComputed", category="reverse", seq=268, event_id="session-1:268"),
                schema_v1_event("Map.prototype.forEach", category="reverse", seq=271, event_id="session-1:271"),
                schema_v1_event("Map.prototype.entries", category="reverse", seq=273, event_id="session-1:273"),
                schema_v1_event("Map.prototype.keys", category="reverse", seq=274, event_id="session-1:274"),
                schema_v1_event("Map.prototype.values", category="reverse", seq=275, event_id="session-1:275"),
                schema_v1_event("Set.prototype.add", category="reverse", seq=52, event_id="session-1:52"),
                schema_v1_event("Set.prototype.has", category="reverse", seq=53, event_id="session-1:53"),
                schema_v1_event("Set.prototype.delete", category="reverse", seq=54, event_id="session-1:54"),
                schema_v1_event("Set.prototype.clear", category="reverse", seq=259, event_id="session-1:259"),
                schema_v1_event("Set.prototype.forEach", category="reverse", seq=272, event_id="session-1:272"),
                schema_v1_event("Set.prototype.entries", category="reverse", seq=276, event_id="session-1:276"),
                schema_v1_event("Set.prototype.values", category="reverse", seq=277, event_id="session-1:277"),
                schema_v1_event("MapIterator.prototype.next", category="reverse", seq=278, event_id="session-1:278"),
                schema_v1_event("SetIterator.prototype.next", category="reverse", seq=279, event_id="session-1:279"),
                schema_v1_event("WeakMap.prototype.get", category="reverse", seq=260, event_id="session-1:260"),
                schema_v1_event("WeakMap.prototype.has", category="reverse", seq=261, event_id="session-1:261"),
                schema_v1_event("WeakMap.prototype.set", category="reverse", seq=262, event_id="session-1:262"),
                schema_v1_event("WeakMap.prototype.delete", category="reverse", seq=263, event_id="session-1:263"),
                schema_v1_event("WeakMap.prototype.getOrInsert", category="reverse", seq=269, event_id="session-1:269"),
                schema_v1_event("WeakMap.prototype.getOrInsertComputed", category="reverse", seq=270, event_id="session-1:270"),
                schema_v1_event("WeakSet.prototype.add", category="reverse", seq=264, event_id="session-1:264"),
                schema_v1_event("WeakSet.prototype.has", category="reverse", seq=265, event_id="session-1:265"),
                schema_v1_event("WeakSet.prototype.delete", category="reverse", seq=266, event_id="session-1:266"),
                schema_v1_event("Proxy.get", category="reverse", seq=55, event_id="session-1:55"),
                schema_v1_event("Proxy.set", category="reverse", seq=56, event_id="session-1:56"),
                schema_v1_event("Proxy.has", category="reverse", seq=57, event_id="session-1:57"),
                schema_v1_event("Proxy.ownKeys", category="reverse", seq=58, event_id="session-1:58"),
                schema_v1_event("Proxy.getOwnPropertyDescriptor", category="reverse", seq=59, event_id="session-1:59"),
                schema_v1_event("Proxy.defineProperty", category="reverse", seq=60, event_id="session-1:60"),
                schema_v1_event("Proxy.deleteProperty", category="reverse", seq=61, event_id="session-1:61"),
                schema_v1_event("String.fromCharCode", category="reverse", seq=62, event_id="session-1:62"),
                schema_v1_event("String.fromCodePoint", category="reverse", seq=63, event_id="session-1:63"),
                schema_v1_event("String.prototype.charCodeAt", category="reverse", seq=64, event_id="session-1:64"),
                schema_v1_event("String.prototype.codePointAt", category="reverse", seq=192, event_id="session-1:192"),
                schema_v1_event("String.prototype.charAt", category="reverse", seq=175, event_id="session-1:175"),
                schema_v1_event("String.prototype.at", category="reverse", seq=197, event_id="session-1:197"),
                schema_v1_event("String.prototype.concat", category="reverse", seq=176, event_id="session-1:176"),
                schema_v1_event("StringAdd", category="reverse", seq=65, event_id="session-1:65"),
                schema_v1_event("StringAdd.constant_lhs", category="reverse", seq=66, event_id="session-1:66"),
                schema_v1_event("StringAdd.constant_rhs", category="reverse", seq=67, event_id="session-1:67"),
                schema_v1_event("String.prototype.slice", category="reverse", seq=68, event_id="session-1:68"),
                schema_v1_event("String.prototype.substring", category="reverse", seq=69, event_id="session-1:69"),
                schema_v1_event("String.prototype.substr", category="reverse", seq=177, event_id="session-1:177"),
                schema_v1_event("String.prototype.padStart", category="reverse", seq=178, event_id="session-1:178"),
                schema_v1_event("String.prototype.padEnd", category="reverse", seq=179, event_id="session-1:179"),
                schema_v1_event("String.prototype.repeat", category="reverse", seq=194, event_id="session-1:194"),
                schema_v1_event("String.prototype.startsWith", category="reverse", seq=187, event_id="session-1:187"),
                schema_v1_event("String.prototype.endsWith", category="reverse", seq=188, event_id="session-1:188"),
                schema_v1_event("String.prototype.trim", category="reverse", seq=189, event_id="session-1:189"),
                schema_v1_event("String.prototype.trimStart", category="reverse", seq=190, event_id="session-1:190"),
                schema_v1_event("String.prototype.trimEnd", category="reverse", seq=191, event_id="session-1:191"),
                schema_v1_event("String.prototype.@@iterator", category="reverse", seq=287, event_id="session-1:287"),
                schema_v1_event("StringIterator.prototype.next", category="reverse", seq=288, event_id="session-1:288"),
                schema_v1_event("Number.prototype.toString", category="reverse", seq=180, event_id="session-1:180"),
                schema_v1_event("BigInt.prototype.toString", category="reverse", seq=181, event_id="session-1:181"),
                schema_v1_event(
                    "Number.parseInt",
                    category="reverse",
                    seq=198,
                    event_id="session-1:198",
                    args=[{
                        "input": "ff",
                        "input_ref": "string:length:2",
                        "radix": 16,
                        "radix_ref": "number:16",
                        "result": 255,
                        "result_ref": "number:255",
                    }],
                ),
                schema_v1_event(
                    "Number.parseFloat",
                    category="reverse",
                    seq=199,
                    event_id="session-1:199",
                    args=[{
                        "input": "3.14159",
                        "input_ref": "string:length:7",
                        "result": 3.14159,
                        "result_ref": "number:3.141590",
                    }],
                ),
                schema_v1_event("String.prototype.indexOf", category="reverse", seq=70, event_id="session-1:70"),
                schema_v1_event("String.prototype.lastIndexOf", category="reverse", seq=193, event_id="session-1:193"),
                schema_v1_event("String.prototype.includes", category="reverse", seq=71, event_id="session-1:71"),
                schema_v1_event("String.prototype.replace", category="reverse", seq=72, event_id="session-1:72"),
                schema_v1_event("String.prototype.replaceAll", category="reverse", seq=186, event_id="session-1:186"),
                schema_v1_event("String.prototype.split", category="reverse", seq=172, event_id="session-1:172"),
                schema_v1_event("String.prototype.search", category="reverse", seq=195, event_id="session-1:195"),
                schema_v1_event("String.prototype.match", category="reverse", seq=196, event_id="session-1:196"),
                schema_v1_event("String.prototype.matchAll", category="reverse", seq=289, event_id="session-1:289"),
                schema_v1_event("String.prototype.toLowerCase", category="reverse", seq=173, event_id="session-1:173"),
                schema_v1_event("String.prototype.toUpperCase", category="reverse", seq=174, event_id="session-1:174"),
                schema_v1_event("RegExp.prototype.test", category="reverse", seq=73, event_id="session-1:73"),
                schema_v1_event("RegExp.prototype.exec", category="reverse", seq=74, event_id="session-1:74"),
                schema_v1_event("RegExp.prototype.@@search", category="reverse", seq=182, event_id="session-1:182"),
                schema_v1_event("RegExp.prototype.@@match", category="reverse", seq=183, event_id="session-1:183"),
                schema_v1_event("RegExp.prototype.@@matchAll", category="reverse", seq=290, event_id="session-1:290"),
                schema_v1_event("RegExp.prototype.@@split", category="reverse", seq=184, event_id="session-1:184"),
                schema_v1_event("RegExp.prototype.@@replace", category="reverse", seq=185, event_id="session-1:185"),
                schema_v1_event("RegExpStringIterator.prototype.next", category="reverse", seq=291, event_id="session-1:291"),
                schema_v1_event("encodeURI", category="reverse", seq=75, event_id="session-1:75"),
                schema_v1_event("encodeURIComponent", category="reverse", seq=76, event_id="session-1:76"),
                schema_v1_event("decodeURI", category="reverse", seq=77, event_id="session-1:77"),
                schema_v1_event("decodeURIComponent", category="reverse", seq=78, event_id="session-1:78"),
                schema_v1_event("Math.imul", category="reverse", seq=79, event_id="session-1:79"),
                schema_v1_event("Bitwise.and", category="reverse", seq=79, event_id="session-1:79"),
                schema_v1_event("Bitwise.or", category="reverse", seq=80, event_id="session-1:80"),
                schema_v1_event("Bitwise.xor", category="reverse", seq=81, event_id="session-1:81"),
                schema_v1_event("Bitwise.not", category="reverse", seq=82, event_id="session-1:82"),
                schema_v1_event("Shift.left", category="reverse", seq=83, event_id="session-1:83"),
                schema_v1_event("Shift.right", category="reverse", seq=84, event_id="session-1:84"),
                schema_v1_event("Shift.unsignedRight", category="reverse", seq=85, event_id="session-1:85"),
                schema_v1_event("Math.random", category="reverse", seq=323, event_id="session-1:323"),
                schema_v1_event("URLSearchParams.sort", category="reverse", seq=86, event_id="session-1:86"),
                schema_v1_event("URLSearchParams.toString", category="reverse", seq=87, event_id="session-1:87"),
                schema_v1_event("URLSearchParams.get", category="reverse", seq=88, event_id="session-1:88"),
                schema_v1_event("URLSearchParams.getAll", category="reverse", seq=89, event_id="session-1:89"),
                schema_v1_event("URLSearchParams.has", category="reverse", seq=90, event_id="session-1:90"),
                schema_v1_event("URLSearchParams.iterator.next", category="reverse", seq=142, event_id="session-1:142"),
                schema_v1_event("URL.href.get", category="reverse", seq=91, event_id="session-1:91"),
                schema_v1_event("URL.search.get", category="reverse", seq=92, event_id="session-1:92"),
                schema_v1_event("Location.href.get", category="reverse", seq=330, event_id="session-1:330"),
                schema_v1_event("Location.search.get", category="reverse", seq=331, event_id="session-1:331"),
                schema_v1_event("Performance.now", category="reverse", seq=93, event_id="session-1:93"),
                schema_v1_event("Date.now", category="reverse", seq=94, event_id="session-1:94"),
                schema_v1_event("console.debug", category="reverse", seq=95, event_id="session-1:95"),
                schema_v1_event("console.clear", category="reverse", seq=96, event_id="session-1:96"),
                schema_v1_event("debugger.statement", category="reverse", seq=97, event_id="session-1:97"),
                schema_v1_event("Function.prototype.toString", category="reverse", seq=98, event_id="session-1:98"),
                schema_v1_event("Error.captureStackTrace", category="reverse", seq=99, event_id="session-1:99"),
                schema_v1_event("Error.stack.get", category="reverse", seq=100, event_id="session-1:100"),
                schema_v1_event("Error.constructor", category="reverse", seq=101, event_id="session-1:101"),
                schema_v1_event("Exception.throw", category="reverse", seq=102, event_id="session-1:102"),
                schema_v1_event("Reflect.apply", category="reverse", seq=103, event_id="session-1:103"),
                schema_v1_event("Function.prototype.call", category="reverse", seq=104, event_id="session-1:104"),
                schema_v1_event("Function.prototype.apply", category="reverse", seq=105, event_id="session-1:105"),
                schema_v1_event("Request.constructor", category="reverse", seq=106, event_id="session-1:106"),
                schema_v1_event("Request.method.get", category="reverse", seq=141, event_id="session-1:141"),
                schema_v1_event("Request.url.get", category="reverse", seq=142, event_id="session-1:142"),
                schema_v1_event("Request.headers.get", category="reverse", seq=143, event_id="session-1:143"),
                schema_v1_event("Request.clone", category="reverse", seq=144, event_id="session-1:144"),
                schema_v1_event("Headers.iterator.next", category="reverse", seq=156, event_id="session-1:156"),
                schema_v1_event("Response.type.get", category="reverse", seq=148, event_id="session-1:148"),
                schema_v1_event("Response.url.get", category="reverse", seq=149, event_id="session-1:149"),
                schema_v1_event("Response.redirected.get", category="reverse", seq=150, event_id="session-1:150"),
                schema_v1_event("Response.status.get", category="reverse", seq=151, event_id="session-1:151"),
                schema_v1_event("Response.ok.get", category="reverse", seq=152, event_id="session-1:152"),
                schema_v1_event("Response.statusText.get", category="reverse", seq=153, event_id="session-1:153"),
                schema_v1_event("Response.headers.get", category="reverse", seq=154, event_id="session-1:154"),
                schema_v1_event("Response.clone", category="reverse", seq=155, event_id="session-1:155"),
                schema_v1_event("Body.text", category="reverse", seq=145, event_id="session-1:145"),
                schema_v1_event("Body.json", category="reverse", seq=146, event_id="session-1:146"),
                schema_v1_event("Body.arrayBuffer", category="reverse", seq=147, event_id="session-1:147"),
                schema_v1_event("JSON.parse", category="reverse", seq=107, event_id="session-1:107"),
                schema_v1_event("JSON.stringify", category="reverse", seq=108, event_id="session-1:108"),
                schema_v1_event("Storage.getItem", category="reverse", seq=109, event_id="session-1:109"),
                schema_v1_event("Storage.removeItem", category="reverse", seq=110, event_id="session-1:110"),
                schema_v1_event("Storage.key", category="reverse", seq=111, event_id="session-1:111"),
                schema_v1_event("Storage.clear", category="reverse", seq=112, event_id="session-1:112"),
                schema_v1_event("Document.cookie.set", category="reverse", seq=113, event_id="session-1:113"),
                schema_v1_event("CookieStore.get", category="reverse", seq=324, event_id="session-1:324"),
                schema_v1_event("CookieStore.getAll", category="reverse", seq=325, event_id="session-1:325"),
                schema_v1_event("CookieStore.set", category="reverse", seq=326, event_id="session-1:326"),
                schema_v1_event("CookieStore.delete", category="reverse", seq=327, event_id="session-1:327"),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "reverse", "--schema-version", "1", str(path)])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_validate_trace_reports_missing_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text('{"t":"call","api":"Crypto.getRandomValues","args":[]}\n', encoding="utf-8")
            with self.assertRaises(TraceValidationError) as ctx:
                validate_trace(path, expected=["CanvasRenderingContext2D.fillText"])
            self.assertIn("Missing expected APIs", str(ctx.exception))

    def test_hash_crypto_family_accepts_webcrypto_material_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            events = [
                schema_v1_event(
                    "SubtleCrypto.encrypt",
                    category="reverse",
                    seq=1,
                    event_id="session-1:1",
                    args=[{
                        "operation_id": 1000,
                        "algorithm": "AES-CBC",
                        "key_ref": "crypto_key:6001",
                        "input_ref": "bytes_sha1:plain",
                    }],
                ),
                schema_v1_event(
                    "SubtleCrypto.importKey",
                    category="reverse",
                    seq=2,
                    event_id="session-1:2",
                    args=[{
                        "operation_id": 1001,
                        "algorithm": "HMAC",
                        "key_data_ref": "bytes_sha1:key-material",
                    }],
                ),
                schema_v1_event(
                    "SubtleCrypto.sign",
                    category="reverse",
                    seq=3,
                    event_id="session-1:3",
                    args=[{
                        "operation_id": 1002,
                        "algorithm": "HMAC",
                        "key_ref": "crypto_key:7001",
                        "input_ref": "bytes_sha1:canonical-request",
                    }],
                ),
                schema_v1_event(
                    "SubtleCrypto.verify",
                    category="reverse",
                    seq=4,
                    event_id="session-1:4",
                    args=[{
                        "operation_id": 1003,
                        "algorithm": "HMAC",
                        "key_ref": "crypto_key:7001",
                        "signature_ref": "bytes_sha1:signature",
                        "input_ref": "bytes_sha1:canonical-request",
                    }],
                ),
                schema_v1_event(
                    "SubtleCrypto.generateKey",
                    category="reverse",
                    seq=5,
                    event_id="session-1:5",
                    args=[{
                        "operation_id": 1004,
                        "algorithm": "AES-GCM",
                        "extractable": True,
                        "key_usages_mask": 3,
                    }],
                ),
                schema_v1_event(
                    "SubtleCrypto.exportKey",
                    category="reverse",
                    seq=6,
                    event_id="session-1:6",
                    args=[{
                        "operation_id": 1005,
                        "format": "jwk",
                        "key_ref": "crypto_key:7001",
                        "result_ref": "bytes_sha1:exported-jwk",
                    }],
                ),
                schema_v1_event(
                    "SubtleCrypto.deriveBits",
                    category="reverse",
                    seq=7,
                    event_id="session-1:7",
                    args=[{
                        "operation_id": 1006,
                        "algorithm": "HKDF",
                        "base_key_ref": "crypto_key:8001",
                        "result_ref": "bytes_sha1:derived-bits",
                    }],
                ),
                schema_v1_event(
                    "SubtleCrypto.deriveKey",
                    category="reverse",
                    seq=8,
                    event_id="session-1:8",
                    args=[{
                        "operation_id": 1007,
                        "algorithm": "HKDF",
                        "base_key_ref": "crypto_key:8001",
                        "derived_key_algorithm": "AES-GCM",
                        "key_ref": "crypto_key:8002",
                    }],
                ),
                schema_v1_event(
                    "SubtleCrypto.wrapKey",
                    category="reverse",
                    seq=9,
                    event_id="session-1:9",
                    args=[{
                        "operation_id": 1008,
                        "format": "raw",
                        "key_ref": "crypto_key:7001",
                        "wrapping_key_ref": "crypto_key:9001",
                        "result_ref": "bytes_sha1:wrapped-key",
                    }],
                ),
                schema_v1_event(
                    "SubtleCrypto.unwrapKey",
                    category="reverse",
                    seq=10,
                    event_id="session-1:10",
                    args=[{
                        "operation_id": 1009,
                        "format": "raw",
                        "wrapped_key_ref": "bytes_sha1:wrapped-key",
                        "unwrapping_key_ref": "crypto_key:9001",
                        "key_ref": "crypto_key:7002",
                    }],
                ),
            ]
            path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")

            validate_trace(
                path,
                expected=[
                    "SubtleCrypto.encrypt",
                    "SubtleCrypto.importKey",
                    "SubtleCrypto.sign",
                    "SubtleCrypto.verify",
                    "SubtleCrypto.generateKey",
                    "SubtleCrypto.exportKey",
                    "SubtleCrypto.deriveBits",
                    "SubtleCrypto.deriveKey",
                    "SubtleCrypto.wrapKey",
                    "SubtleCrypto.unwrapKey",
                ],
                schema_version=1,
                require_vmp_families=["hash_crypto"],
            )

    def test_number_to_string_radix_conversion_is_string_transform_material(self):
        self.assertIn("Number.prototype.toString", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["Number.prototype.toString"], "string_transform")

    def test_math_random_is_reverse_random_source_material(self):
        self.assertIn("Math.random", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["Math.random"], "random_source")

    def test_webcrypto_random_sources_are_reverse_random_source_material(self):
        for api in [
            "Crypto.getRandomValues",
            "Crypto.randomUUID",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "random_source")

    def test_regexp_search_is_reverse_regexp_probe(self):
        self.assertIn("RegExp.prototype.@@search", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["RegExp.prototype.@@search"], "regexp_probe")

    def test_regexp_match_is_reverse_regexp_probe(self):
        self.assertIn("RegExp.prototype.@@match", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["RegExp.prototype.@@match"], "regexp_probe")

    def test_string_search_is_reverse_regexp_probe(self):
        self.assertIn("String.prototype.search", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["String.prototype.search"], "regexp_probe")

    def test_string_match_is_reverse_regexp_probe(self):
        self.assertIn("String.prototype.match", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["String.prototype.match"], "regexp_probe")

    def test_regexp_match_all_is_reverse_regexp_probe(self):
        for api in [
            "String.prototype.matchAll",
            "RegExp.prototype.@@matchAll",
            "RegExpStringIterator.prototype.next",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "regexp_probe")

    def test_regexp_split_is_reverse_regexp_probe(self):
        self.assertIn("RegExp.prototype.@@split", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["RegExp.prototype.@@split"], "regexp_probe")

    def test_regexp_replace_is_reverse_regexp_probe(self):
        self.assertIn("RegExp.prototype.@@replace", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["RegExp.prototype.@@replace"], "regexp_probe")

    def test_array_at_is_reverse_array_table(self):
        self.assertIn("Array.prototype.at", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["Array.prototype.at"], "array_table")

    def test_array_constructor_batch_is_reverse_array_table(self):
        self.assertIn("Array.from", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.of", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["Array.from"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.of"], "array_table")

    def test_array_from_async_is_reverse_async_flow(self):
        self.assertIn("Array.fromAsync", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["Array.fromAsync"], "async_flow")

    def test_promise_static_is_reverse_async_flow(self):
        self.assertIn("Promise.resolve", REVERSE_EXPECTED_APIS)
        self.assertIn("Promise.reject", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["Promise.resolve"], "async_flow")
        self.assertEqual(VMP_API_FAMILY["Promise.reject"], "async_flow")

    def test_promise_combinator_is_reverse_async_flow(self):
        for api in [
            "Promise.all",
            "Promise.allSettled",
            "Promise.race",
            "Promise.any",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "async_flow")

    def test_promise_capability_is_reverse_async_flow(self):
        for api in [
            "Promise.try",
            "Promise.withResolvers",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "async_flow")

    def test_async_function_is_reverse_async_flow(self):
        for api in [
            "AsyncFunction.enter",
            "AsyncFunction.await",
            "AsyncFunction.resume",
            "AsyncFunction.resolve",
            "AsyncFunction.reject",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "async_flow")

    def test_array_search_is_reverse_array_table(self):
        self.assertIn("Array.prototype.indexOf", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.includes", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.lastIndexOf", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.find", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.findIndex", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.findLast", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.findLastIndex", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.reduce", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.reduceRight", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.map", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.filter", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.flat", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.flatMap", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.every", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.some", REVERSE_EXPECTED_APIS)
        self.assertIn("Array.prototype.forEach", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["Array.prototype.indexOf"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.includes"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.lastIndexOf"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.find"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.findIndex"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.findLast"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.findLastIndex"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.reduce"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.reduceRight"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.map"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.filter"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.flat"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.flatMap"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.every"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.some"], "array_table")
        self.assertEqual(VMP_API_FAMILY["Array.prototype.forEach"], "array_table")

    def test_object_assign_is_reverse_dynamic_dispatch_material(self):
        self.assertIn("Object.assign", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["Object.assign"], "dynamic_dispatch")

    def test_weak_collections_are_reverse_collection_table_material(self):
        for api in [
            "WeakMap.prototype.get",
            "WeakMap.prototype.has",
            "WeakMap.prototype.set",
            "WeakMap.prototype.delete",
            "WeakSet.prototype.add",
            "WeakSet.prototype.has",
            "WeakSet.prototype.delete",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "collection_table")

    def test_get_or_insert_is_reverse_collection_table_material(self):
        for api in [
            "Map.prototype.getOrInsert",
            "Map.prototype.getOrInsertComputed",
            "WeakMap.prototype.getOrInsert",
            "WeakMap.prototype.getOrInsertComputed",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "collection_table")

    def test_collection_for_each_is_reverse_collection_table_material(self):
        for api in ["Map.prototype.forEach", "Set.prototype.forEach"]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "collection_table")

    def test_collection_iterators_are_reverse_collection_table_material(self):
        for api in [
            "Map.prototype.entries",
            "Map.prototype.keys",
            "Map.prototype.values",
            "Set.prototype.entries",
            "Set.prototype.values",
            "MapIterator.prototype.next",
            "SetIterator.prototype.next",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "collection_table")

    def test_sequence_iterators_are_reverse_sequence_iterator_material(self):
        for api in [
            "Array.prototype.entries",
            "Array.prototype.keys",
            "Array.prototype.values",
            "TypedArray.entries",
            "TypedArray.keys",
            "TypedArray.values",
            "String.prototype.@@iterator",
            "ArrayIterator.prototype.next",
            "StringIterator.prototype.next",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "sequence_iterator")

    def test_generator_resume_is_reverse_generator_state_material(self):
        for api in [
            "Generator.prototype.next",
            "Generator.prototype.return",
            "Generator.prototype.throw",
            "AsyncGenerator.prototype.next",
            "AsyncGenerator.prototype.return",
            "AsyncGenerator.prototype.throw",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "generator_state")

    def test_reflect_construct_is_reverse_dynamic_dispatch_material(self):
        self.assertIn("Reflect.construct", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["Reflect.construct"], "dynamic_dispatch")

    def test_object_create_is_reverse_dynamic_dispatch_material(self):
        self.assertIn("Object.create", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["Object.create"], "dynamic_dispatch")

    def test_prototype_chain_is_reverse_dynamic_dispatch_material(self):
        for api in [
            "Object.getPrototypeOf",
            "Object.setPrototypeOf",
            "Reflect.getPrototypeOf",
            "Reflect.setPrototypeOf",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "dynamic_dispatch")

    def test_descriptor_introspection_is_reverse_dynamic_dispatch_material(self):
        for api in [
            "Object.getOwnPropertyDescriptor",
            "Object.getOwnPropertyDescriptors",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "dynamic_dispatch")

    def test_object_integrity_is_reverse_dynamic_dispatch_material(self):
        for api in [
            "Object.preventExtensions",
            "Object.freeze",
            "Object.seal",
            "Object.isExtensible",
            "Object.isFrozen",
            "Object.isSealed",
            "Reflect.preventExtensions",
            "Reflect.isExtensible",
        ]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "dynamic_dispatch")

    def test_reflect_property_delete_is_reverse_dynamic_dispatch_material(self):
        self.assertIn("Reflect.deleteProperty", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["Reflect.deleteProperty"], "dynamic_dispatch")

    def test_property_set_enumerability_is_reverse_dynamic_dispatch_material(self):
        for api in ["Reflect.set", "Object.prototype.propertyIsEnumerable"]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "dynamic_dispatch")

    def test_object_has_own_is_reverse_dynamic_dispatch_material(self):
        for api in ["Object.hasOwn", "Object.prototype.hasOwnProperty"]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "dynamic_dispatch")

    def test_object_type_identity_probes_are_reverse_dynamic_dispatch_material(self):
        for api in ["Object.prototype.toString", "Array.isArray", "Object.is"]:
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "dynamic_dispatch")

    def test_property_define_is_reverse_dynamic_dispatch_material(self):
        self.assertIn("Object.defineProperty", REVERSE_EXPECTED_APIS)
        self.assertIn("Object.defineProperties", REVERSE_EXPECTED_APIS)
        self.assertIn("Reflect.defineProperty", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["Object.defineProperty"], "dynamic_dispatch")
        self.assertEqual(VMP_API_FAMILY["Object.defineProperties"], "dynamic_dispatch")
        self.assertEqual(VMP_API_FAMILY["Reflect.defineProperty"], "dynamic_dispatch")

    def test_typed_array_search_is_reverse_typed_array(self):
        self.assertIn("TypedArray.indexOf", REVERSE_EXPECTED_APIS)
        self.assertIn("TypedArray.includes", REVERSE_EXPECTED_APIS)
        self.assertIn("TypedArray.lastIndexOf", REVERSE_EXPECTED_APIS)
        self.assertIn("TypedArray.find", REVERSE_EXPECTED_APIS)
        self.assertIn("TypedArray.findIndex", REVERSE_EXPECTED_APIS)
        self.assertIn("TypedArray.findLast", REVERSE_EXPECTED_APIS)
        self.assertIn("TypedArray.findLastIndex", REVERSE_EXPECTED_APIS)
        self.assertIn("TypedArray.reduce", REVERSE_EXPECTED_APIS)
        self.assertIn("TypedArray.reduceRight", REVERSE_EXPECTED_APIS)
        self.assertIn("TypedArray.filter", REVERSE_EXPECTED_APIS)
        self.assertIn("TypedArray.every", REVERSE_EXPECTED_APIS)
        self.assertIn("TypedArray.some", REVERSE_EXPECTED_APIS)
        self.assertIn("TypedArray.forEach", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["TypedArray.indexOf"], "typed_array")
        self.assertEqual(VMP_API_FAMILY["TypedArray.includes"], "typed_array")
        self.assertEqual(VMP_API_FAMILY["TypedArray.lastIndexOf"], "typed_array")
        self.assertEqual(VMP_API_FAMILY["TypedArray.find"], "typed_array")
        self.assertEqual(VMP_API_FAMILY["TypedArray.findIndex"], "typed_array")
        self.assertEqual(VMP_API_FAMILY["TypedArray.findLast"], "typed_array")
        self.assertEqual(VMP_API_FAMILY["TypedArray.findLastIndex"], "typed_array")
        self.assertEqual(VMP_API_FAMILY["TypedArray.reduce"], "typed_array")
        self.assertEqual(VMP_API_FAMILY["TypedArray.reduceRight"], "typed_array")
        self.assertEqual(VMP_API_FAMILY["TypedArray.filter"], "typed_array")
        self.assertEqual(VMP_API_FAMILY["TypedArray.every"], "typed_array")
        self.assertEqual(VMP_API_FAMILY["TypedArray.some"], "typed_array")
        self.assertEqual(VMP_API_FAMILY["TypedArray.forEach"], "typed_array")

    def test_string_replace_all_is_reverse_string_transform(self):
        self.assertIn("String.prototype.replaceAll", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["String.prototype.replaceAll"], "string_transform")

    def test_string_prefix_suffix_predicates_are_reverse_string_transform(self):
        self.assertIn("String.prototype.startsWith", REVERSE_EXPECTED_APIS)
        self.assertIn("String.prototype.endsWith", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["String.prototype.startsWith"], "string_transform")
        self.assertEqual(VMP_API_FAMILY["String.prototype.endsWith"], "string_transform")

    def test_string_last_index_of_is_reverse_string_transform(self):
        self.assertIn("String.prototype.lastIndexOf", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["String.prototype.lastIndexOf"], "string_transform")

    def test_string_repeat_is_reverse_string_transform(self):
        self.assertIn("String.prototype.repeat", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["String.prototype.repeat"], "string_transform")

    def test_string_trim_variants_are_reverse_string_transform(self):
        for api in (
            "String.prototype.trim",
            "String.prototype.trimStart",
            "String.prototype.trimEnd",
        ):
            self.assertIn(api, REVERSE_EXPECTED_APIS)
            self.assertEqual(VMP_API_FAMILY[api], "string_transform")

    def test_string_code_point_at_is_reverse_string_decode(self):
        self.assertIn("String.prototype.codePointAt", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["String.prototype.codePointAt"], "string_decode")

    def test_string_at_is_reverse_string_decode(self):
        self.assertIn("String.prototype.at", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["String.prototype.at"], "string_decode")

    def test_number_parse_is_reverse_number_parse(self):
        self.assertIn("Number.parseInt", REVERSE_EXPECTED_APIS)
        self.assertIn("Number.parseFloat", REVERSE_EXPECTED_APIS)
        self.assertEqual(VMP_API_FAMILY["Number.parseInt"], "number_parse")
        self.assertEqual(VMP_API_FAMILY["Number.parseFloat"], "number_parse")

    def test_business_api_profile_accepts_records_field_and_header_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in self.business_api_events()) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            self.assertEqual(result, 0)
            self.assertIn("PASS:", stdout.getvalue())

    def test_business_api_profile_rejects_missing_fetch_body_material(self):
        events = [
            event
            for event in self.business_api_events()
            if event["api"] not in {"Body.json", "Body.text", "Body.arrayBuffer", "Body.bytes"}
        ]

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("fetch response Body.json material evidence", output)

    def test_business_api_profile_rejects_missing_fetch_response_metadata_material(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "Response.status.get":
                arg.pop("status_ref", None)
            elif event["api"] == "Response.url.get":
                arg.pop("url_ref", None)
            elif event["api"] == "Response.headers.get":
                arg.pop("headers_id", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("fetch response Response.status.get material evidence", output)
            self.assertIn("fetch response Response.url.get material evidence", output)
            self.assertIn("fetch response Response.headers.get object link", output)

    def test_business_api_profile_rejects_missing_fetch_response_header_material(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "Headers.get" and arg.get("name") == "content-type":
                arg.pop("name_ref", None)
                arg.pop("result_ref", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("fetch response Headers.get content-type material evidence", output)

    def test_business_api_profile_rejects_mismatched_fetch_response_headers_id(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "Response.headers.get":
                arg["headers_id"] = 1185445128176

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("fetch response Headers.get content-type material evidence", output)
            self.assertIn(
                "fetch response Headers.iterator.next content-type material evidence",
                output,
            )

    def test_business_api_profile_rejects_missing_fetch_response_header_iteration_material(self):
        events = [
            event
            for event in self.business_api_events()
            if event["api"] != "Headers.iterator.next"
        ]

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("fetch response Headers.iterator.next content-type material evidence", output)

    def test_business_api_profile_rejects_missing_request_header_read_material(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "Request.headers.get":
                arg.pop("headers_id", None)
                arg.pop("method_ref", None)
                arg.pop("url_ref", None)
            elif event["api"] == "Headers.get" and arg.get("headers_id") == 29:
                arg.pop("result_ref", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("GET Request.headers.get object link", output)
            self.assertIn("GET Request Headers.get x-signature material evidence", output)
            self.assertIn("GET Request Headers.get x-session-token material evidence", output)

    def test_business_api_profile_rejects_missing_request_url_read_material(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "Request.url.get":
                arg.pop("url_ref", None)
                arg.pop("network_correlation_key", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("GET Request.url.get material evidence", output)

    def test_business_api_profile_rejects_missing_request_constructor_material(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "Request.constructor":
                arg.pop("url_ref", None)
                arg.pop("headers_id", None)
                arg.pop("network_correlation_key", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("GET Request.constructor material evidence", output)

    def test_business_api_profile_rejects_missing_fetch_call_material(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "fetch":
                arg.pop("url_ref", None)
                arg.pop("headers_id", None)
                arg.pop("network_correlation_key", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("GET fetch call material evidence", output)

    def test_business_api_profile_rejects_missing_records_header_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(
                    json.dumps(event)
                    for event in self.business_api_events(include_signature_header_source=False)
                )
                + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("fetch header source fields: x-signature", output)

    def test_business_api_profile_rejects_header_source_without_material_ref(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if (
                event["api"] in {"Headers.set", "Headers.append"}
                and arg.get("name", "").lower() == "x-signature"
            ):
                arg.pop("value_ref", None)
                arg.pop("normalized_value_ref", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("fetch header source material refs: x-signature", output)

    def test_business_api_profile_rejects_url_param_source_without_material_ref(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "URLSearchParams.set" and arg.get("name") == "X-Signature":
                arg.pop("value_ref", None)
                arg.pop("serialized_ref", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("URLSearchParams.set source material refs: X-Signature", output)

    def test_business_api_profile_rejects_full_url_source_without_material_ref(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "URL.search.set":
                arg.pop("value_ref", None)
                arg.pop("search_ref", None)
                arg.pop("href_ref", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("URL.search.set material refs for full GET records query", output)

    def test_business_api_profile_rejects_network_header_without_material_value(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "BrowserNetwork.request" and arg.get("method") == "GET":
                for header in arg["headers"]:
                    if header.get("name", "").lower() == "x-signature":
                        header["value"] = None

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("GET request header values: x-signature", output)

    def test_business_api_profile_rejects_network_header_without_complete_lengths(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "BrowserNetwork.request" and arg.get("method") == "GET":
                for header in arg["headers"]:
                    if header.get("name", "").lower() == "x-session-token":
                        header.pop("name_length", None)
                        header.pop("value_length", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("GET complete request header values: x-session-token", output)

    def test_business_api_profile_rejects_xhr_open_without_material_evidence(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "XMLHttpRequest.open":
                arg.pop("url_ref", None)
                arg.pop("network_correlation_key", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("POST XMLHttpRequest.open material evidence", output)

    def test_business_api_profile_rejects_xhr_send_body_without_material_ref(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "XMLHttpRequest.send":
                arg.pop("body_ref", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("POST XMLHttpRequest.send body material refs", output)

    def test_business_api_profile_rejects_xhr_send_without_complete_material(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "XMLHttpRequest.send":
                arg.pop("xhr_id", None)
                arg.pop("url_ref", None)
                arg.pop("body_type", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("POST XMLHttpRequest.send material evidence", output)

    def test_business_api_profile_rejects_xhr_response_text_without_material(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "XMLHttpRequest.responseText":
                arg.pop("xhr_id", None)
                arg.pop("url_ref", None)
                arg.pop("network_correlation_key", None)
                arg.pop("value_length", None)
                arg.pop("value_ref", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("POST XMLHttpRequest.responseText material evidence", output)

    def test_business_api_profile_rejects_upload_body_without_material_evidence(self):
        events = self.business_api_events()
        for event in events:
            arg = event["args"][0]
            if event["api"] == "BrowserNetwork.request" and arg.get("method") == "POST":
                arg["upload_body"].pop("body_hex", None)
                arg["upload_body"].pop("body_sha256", None)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trace.ndjson"
            path.write_text(
                "\n".join(json.dumps(event) for event in events) + "\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main(["--profile", "business-api", "--schema-version", "1", str(path)])

            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("POST upload_body material evidence", output)

    def test_main_reports_missing_trace_file_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "missing.ndjson"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = main([str(path)])
            output = stdout.getvalue()
            self.assertEqual(result, 1)
            self.assertIn("FAIL:", output)
            self.assertNotIn("Traceback", output)


if __name__ == "__main__":
    unittest.main()
