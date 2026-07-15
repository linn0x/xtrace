import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# Several tests assert that the XTrace patches are wired into the *live* Chromium
# checkout under chromium/ (git-ignored). Skip them cleanly when that tree is
# absent (fresh clone / CI) instead of erroring on a missing source file.
CHROMIUM_SRC = ROOT / "chromium" / "src"
requires_chromium_tree = unittest.skipUnless(
    CHROMIUM_SRC.exists(), "requires a patched chromium/src checkout"
)


class BuildScriptTests(unittest.TestCase):
    def test_gn_args_enable_common_web_video_codecs(self):
        script = (ROOT / "scripts" / "gn_gen_xtrace.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("proprietary_codecs=true", script)
        self.assertIn('ffmpeg_branding="Chrome"', script)
        self.assertIn("rtc_use_h264=true", script)

    def test_build_scripts_prefer_installed_xcode_over_command_line_tools(self):
        gn_script = (ROOT / "scripts" / "gn_gen_xtrace.sh").read_text(
            encoding="utf-8"
        )
        build_script = (ROOT / "scripts" / "build_chromium.sh").read_text(
            encoding="utf-8"
        )

        for script in (gn_script, build_script):
            self.assertIn("/Applications/Xcode.app/Contents/Developer", script)
            self.assertIn("DEVELOPER_DIR", script)
            self.assertIn("xcodebuild", script)

    def test_build_scripts_prefer_depot_tools_python3(self):
        gn_script = (ROOT / "scripts" / "gn_gen_xtrace.sh").read_text(
            encoding="utf-8"
        )
        build_script = (ROOT / "scripts" / "build_chromium.sh").read_text(
            encoding="utf-8"
        )

        for script in (gn_script, build_script):
            self.assertIn('$DEPOT_TOOLS/python-bin:$DEPOT_TOOLS:$PATH', script)
            self.assertIn("sys.version_info < (3, 10)", script)
            self.assertIn("Chromium build requires python3 >= 3.10", script)

    def test_build_scripts_use_local_ninja_without_siso(self):
        gn_script = (ROOT / "scripts" / "gn_gen_xtrace.sh").read_text(
            encoding="utf-8"
        )
        build_script = (ROOT / "scripts" / "build_chromium.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("use_siso=false", gn_script)
        self.assertIn("use_reclient=false", gn_script)
        self.assertIn('NINJA_BIN="${NINJA_BIN:-$(command -v ninja || true)}"', build_script)
        self.assertIn('"$NINJA_BIN" -C out/XTrace chrome', build_script)
        self.assertNotIn("autoninja -C out/XTrace chrome", build_script)

    def test_bootstrap_accepts_git_worktree_checkout(self):
        script = (ROOT / "scripts" / "bootstrap_chromium.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn('git -C src rev-parse --git-dir', script)
        self.assertNotIn('[[ ! -d src/.git ]]', script)
        self.assertIn("Existing path is not a Chromium Git checkout", script)

    def test_apply_patches_orders_schema_v2_patches_after_native_base(self):
        script = (ROOT / "scripts" / "apply_patches.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("ensure_git_tree \"$SRC\" \"Chromium\"", script)
        self.assertIn("ensure_git_tree \"$SRC/v8\" \"V8\"", script)
        self.assertIn("rev-parse --show-toplevel", script)
        self.assertIn("is not a standalone Git checkout", script)
        self.assertIn("NATIVE_MODE=\"$(preflight_one \"$SRC\" \"$PATCH_NATIVE\")\"", script)
        self.assertIn("V8_MODE=\"$(preflight_one \"$SRC/v8\" \"$PATCH_V8\")\"", script)
        self.assertIn("PATCH_CAUSALITY_RENDERER", script)
        self.assertIn("PATCH_CAUSALITY_BROWSER", script)
        self.assertLess(script.index("NATIVE_MODE="), script.index("apply_one \"$SRC\""))
        self.assertLess(script.index("V8_MODE="), script.index("apply_one \"$SRC\""))
        self.assertLess(script.index("apply_one \"$SRC\" \"$PATCH_NATIVE\""),
                        script.index("CAUSALITY_RENDERER_MODE="))
        self.assertLess(script.index("CAUSALITY_RENDERER_MODE="),
                        script.index("CAUSALITY_BROWSER_MODE="))
        self.assertIn("apply --3way --check", script)

    def test_relink_runtime_script_targets_minimal_native_hook_chain(self):
        script = (ROOT / "scripts" / "relink_chromium_runtime.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("Chromium.app -> Chromium Framework ->", script)
        self.assertIn("libchrome_dll.dylib", script)
        self.assertIn(
            '"obj/chrome/chrome_framework_shared_library/Chromium Framework"',
            script,
        )
        self.assertIn("Chromium.app", script)
        self.assertIn("-n -d explain libchrome_dll.dylib", script)
        self.assertIn("missing deps", script)
        self.assertIn("codesign --force --deep --sign -", script)
        self.assertIn("codesign --verify --deep --strict", script)
        self.assertIn("--dry-run", script)
        self.assertIn("--diagnose-only", script)
        self.assertNotIn('"$NINJA_BIN" -C "$OUT_DIR" chrome', script)
        self.assertNotIn('"$NINJA_BIN" -C out/XTrace chrome', script)

    def test_xtrace_mojo_remote_is_thread_local(self):
        logger = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "platform"
            / "xtrace"
            / "xtrace_logger.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("thread_local mojo::Remote<mojom::blink::XTraceHost>", logger)
        self.assertNotIn(
            "DEFINE_STATIC_LOCAL(mojo::Remote<mojom::blink::XTraceHost>",
            logger,
        )

    def test_xtrace_asset_mojo_and_renderer_switches_are_wired(self):
        mojom = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "public"
            / "mojom"
            / "xtrace"
            / "xtrace.mojom"
        ).read_text(encoding="utf-8")
        client = (
            ROOT
            / "chromium"
            / "src"
            / "chrome"
            / "browser"
            / "chrome_content_browser_client.cc"
        ).read_text(encoding="utf-8")
        logger = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "platform"
            / "xtrace"
            / "xtrace_logger.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("LogAsset(string content_path", mojom)
        self.assertIn('"xtrace-capture-assets"', client)
        self.assertNotIn('"xtrace-asset-max-bytes"', client)
        self.assertNotIn('"xtrace-max-value-bytes"', client)
        self.assertIn("XTRACE_CAPTURE_ASSETS", logger)
        self.assertIn('std::string capture_assets = "full";', logger)
        self.assertIn('.value_or("full")', logger)
        self.assertIn("content = source_utf8;", logger)
        self.assertIn('manifest.append(",\\"source\\":");', logger)
        self.assertIn('fields.append(",\\"source\\":");', logger)
        self.assertIn('manifest.append("false");', logger)
        self.assertNotIn("kSourcePreviewBytes", logger)
        self.assertNotIn("source_preview", logger)
        self.assertNotIn("std::min(source_utf8.size()", logger)
        self.assertNotIn("XTRACE_ASSET_MAX_BYTES", logger)
        self.assertNotIn("asset_max_bytes", logger)

    def test_xtrace_logger_preserves_full_event_payloads(self):
        logger = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "platform"
            / "xtrace"
            / "xtrace_logger.cc"
        ).read_text(encoding="utf-8")

        self.assertIn('line.append(args);', logger)
        self.assertIn('line.append(",\\"truncated\\":false");', logger)
        self.assertNotIn("XTRACE_MAX_VALUE_BYTES", logger)
        self.assertNotIn("max_value_bytes", logger)
        self.assertNotIn("kMaxEventBytes", logger)
        self.assertNotIn("kDefaultMaxValueBytes", logger)
        self.assertNotIn("BuildTruncationJson", logger)
        self.assertNotIn("BuildTruncatedArgsJson", logger)
        self.assertNotIn("xtrace_truncated", logger)
        self.assertNotIn("args.size() > config", logger)

    def test_trace_schema_doc_records_seq_result_and_truncation_semantics(self):
        schema_doc = (ROOT / "docs" / "trace-schema-v1.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("`seq` is scoped to the producer session", schema_doc)
        self.assertIn("`global_seq`", schema_doc)
        self.assertIn("`session_seq`", schema_doc)
        self.assertIn("_file_index", schema_doc)
        self.assertIn("compatibility fields", schema_doc)
        self.assertIn("top-level `truncation`", schema_doc)
        self.assertIn("does not redact them by default", schema_doc)

    def test_xtrace_browser_network_throttle_is_wired(self):
        client = (
            ROOT
            / "chromium"
            / "src"
            / "chrome"
            / "browser"
            / "chrome_content_browser_client.cc"
        ).read_text(encoding="utf-8")
        self.assertIn("XTraceBrowserNetworkThrottle", client)
        self.assertIn("BrowserNetwork.request", client)
        self.assertIn("BrowserNetwork.redirect", client)
        self.assertIn("BrowserNetwork.response", client)
        self.assertIn("BrowserNetwork.complete", client)
        self.assertIn("WillProcessResponse", client)
        self.assertIn("CreateXTraceBrowserNetworkEventJson", client)
        self.assertIn("CreateXTraceBrowserNetworkResponseEventJson", client)
        self.assertIn("CreateXTraceBrowserNetworkCompleteEventJson", client)
        self.assertIn("content/browser/xtrace/xtrace_host_impl.h", client)
        self.assertIn('event.Set("session_seq", seq);', client)
        self.assertIn("content::XTraceHostImpl::GetTaskRunner()", client)
        self.assertIn("content::XTraceHostImpl::StampGlobalSequenceForWrite", client)
        self.assertIn("response_code", client)
        self.assertIn("mime_type", client)
        self.assertIn("response_headers", client)
        self.assertIn("completion_status.error_code", client)
        self.assertIn("completion_status.encoded_data_length", client)
        self.assertIn("completion_status.encoded_body_length", client)
        self.assertIn("completion_status.decoded_body_length", client)
        self.assertIn("LogXTraceBrowserNetworkEvent", client)
        self.assertIn("result.push_back(std::make_unique<XTraceBrowserNetworkThrottle>", client)
        self.assertIn("XTraceBrowserNetworkProxyingURLLoaderFactory", client)
        self.assertIn("XTraceBrowserNetworkURLLoaderClient", client)
        self.assertIn("factory_builder.Append()", client)
        self.assertIn("CreateLoaderAndStart(", client)
        self.assertIn("OnReceiveResponse(", client)
        self.assertIn("OnComplete(", client)
        self.assertIn("mojo::PendingReceiver<network::mojom::URLLoaderClient>", client)
        self.assertIn(
            "XTraceBrowserNetworkProxyingURLLoaderFactory::MaybeProxyRequest",
            client,
        )
        self.assertIn("browser_context, factory_builder", client)
        self.assertNotIn("IsXTraceSensitiveRequestHeader", client)
        self.assertNotIn("IsXTraceSensitiveResponseHeader", client)
        self.assertNotIn('header.Set("redacted"', client)
        self.assertNotIn("kXTraceMaxRequestHeaders", client)
        self.assertNotIn("kXTraceMaxResponseHeaders", client)
        self.assertNotIn("kXTraceMaxUploadPreviewBytes", client)
        self.assertIn("kXTraceMaxBodyBytesSwitch", client)
        self.assertIn("kXTraceMaxHeaderValueBytesSwitch", client)
        self.assertIn("XTRACE_MAX_BODY_BYTES", client)
        self.assertIn("XTRACE_MAX_HEADER_VALUE_BYTES", client)
        self.assertIn('header.Set("value", captured_value);', client)
        self.assertIn('header.Set("name_length", static_cast<int>(name.size()));', client)
        self.assertIn('header.Set("value_truncated", true);', client)
        self.assertIn('event.Set("truncated", truncated);', client)
        self.assertIn('event.Set("truncation", std::move(top_level_truncation));', client)
        self.assertIn('upload.Set("body_hex"', client)
        self.assertIn('upload.Set("body_sha256", body_hash);', client)

        native_patch = (
            ROOT
            / "patches"
            / "0001-xtrace-native-logger.patch"
        ).read_text(encoding="utf-8")
        for marker in (
            "BrowserNetwork.complete",
            "CreateXTraceBrowserNetworkCompleteEventJson",
            "XTraceBrowserNetworkURLLoaderClient",
            "mojo::PendingReceiver<network::mojom::URLLoaderClient>",
            "std::move(wrapped_client)",
            "completion_status.error_code",
            "completion_status.encoded_body_length",
            "completion_status.decoded_body_length",
        ):
            self.assertIn(marker, native_patch)
        self.assertIn("base::HexEncode(base::as_byte_span(captured_body))", client)
        self.assertNotIn("preview_sha256", client)

    def test_xtrace_browser_writer_stamps_global_sequence(self):
        host_header = (
            ROOT
            / "chromium"
            / "src"
            / "content"
            / "browser"
            / "xtrace"
            / "xtrace_host_impl.h"
        ).read_text(encoding="utf-8")
        host_impl = (
            ROOT
            / "chromium"
            / "src"
            / "content"
            / "browser"
            / "xtrace"
            / "xtrace_host_impl.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("StampGlobalSequenceForWrite", host_header)
        self.assertIn("class CONTENT_EXPORT XTraceHostImpl", host_header)
        self.assertIn("g_xtrace_file_global_sequence", host_impl)
        self.assertIn(
            "std::atomic<uint64_t> g_xtrace_file_global_sequence",
            host_impl,
        )
        self.assertIn(
            "HasTopLevelJsonKey(event_json, \"global_seq\")",
            host_impl,
        )
        self.assertIn("fetch_add(1, std::memory_order_relaxed)", host_impl)
        self.assertIn('",\\"global_seq\\":"', host_impl)
        self.assertIn("StampGlobalSequenceForWrite(event_json)", host_impl)

    def test_xtrace_url_mutation_and_request_constructor_hooks_are_wired(self):
        url_search_params = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "url"
            / "url_search_params.cc"
        ).read_text(encoding="utf-8")
        dom_url = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "url"
            / "dom_url.cc"
        ).read_text(encoding="utf-8")
        location = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "frame"
            / "location.cc"
        ).read_text(encoding="utf-8")
        xtrace_logger_header = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "platform"
            / "xtrace"
            / "xtrace_logger.h"
        ).read_text(encoding="utf-8")
        xtrace_logger = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "platform"
            / "xtrace"
            / "xtrace_logger.cc"
        ).read_text(encoding="utf-8")
        request = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "fetch"
            / "request.cc"
        ).read_text(encoding="utf-8")
        xhr = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "xmlhttprequest"
            / "xml_http_request.cc"
        ).read_text(encoding="utf-8")

        self.assertIn('"URLSearchParams.append"', url_search_params)
        self.assertIn('"URLSearchParams.constructor"', url_search_params)
        self.assertIn('"URLSearchParams.set"', url_search_params)
        self.assertIn('"URLSearchParams.delete"', url_search_params)
        self.assertIn('"URLSearchParams.sort"', url_search_params)
        self.assertIn('"URLSearchParams.toString"', url_search_params)
        self.assertIn('"URLSearchParams.get"', url_search_params)
        self.assertIn('"URLSearchParams.getAll"', url_search_params)
        self.assertIn('"URLSearchParams.has"', url_search_params)
        self.assertIn('"URLSearchParams.iterator.next"', url_search_params)
        self.assertIn("before_serialized", url_search_params)
        self.assertIn("serialized", url_search_params)
        self.assertIn("iteration_index", url_search_params)
        self.assertIn("init_type", url_search_params)
        self.assertIn("param_names", url_search_params)
        self.assertIn("param_name_refs", url_search_params)
        self.assertIn("param_name_lengths", url_search_params)
        self.assertIn("param_values", url_search_params)
        self.assertIn("param_value_refs", url_search_params)
        self.assertIn("param_value_lengths", url_search_params)
        self.assertIn("name_length", url_search_params)
        self.assertIn("name_ref", url_search_params)
        self.assertIn("value_ref", url_search_params)
        self.assertIn("serialized_ref", url_search_params)
        self.assertIn("before_serialized_ref", url_search_params)
        self.assertIn("result_ref", url_search_params)
        self.assertIn("value_length", url_search_params)
        self.assertIn("result_value_refs", url_search_params)
        self.assertIn("result_value_lengths", url_search_params)
        self.assertIn("serialized_length", url_search_params)
        self.assertIn("result_count", url_search_params)
        self.assertIn("StringHashRefJson", xtrace_logger_header)
        self.assertIn("string_ref:sha1:", xtrace_logger)
        self.assertIn("XTraceLogger::StringHashRefJson(name)", url_search_params)
        self.assertIn("XTraceLogger::StringHashRefJson(value)", url_search_params)
        self.assertIn("XTraceLogger::StringHashRefJson(serialized)", url_search_params)
        self.assertIn("XTraceJsonStringRefArray", url_search_params)
        self.assertIn("LogXTraceConstructor", url_search_params)
        self.assertIn("XTraceId()", url_search_params)
        self.assertIn("search_params_id", url_search_params)
        self.assertIn("url_object_id", url_search_params)
        self.assertIn('"URL.constructor"', dom_url)
        self.assertIn('"URL.href.get"', dom_url)
        self.assertIn('"URL.search.get"', dom_url)
        self.assertIn('"URL.href.set"', dom_url)
        self.assertIn('"URL.search.set"', dom_url)
        self.assertIn("XTraceId()", dom_url)
        self.assertIn("url_object_id", dom_url)
        self.assertIn("search_params_id", dom_url)
        self.assertIn("url_ref", dom_url)
        self.assertIn("base_ref", dom_url)
        self.assertIn("value_ref", dom_url)
        self.assertIn("href_length", dom_url)
        self.assertIn("href_ref", dom_url)
        self.assertIn("search_ref", dom_url)
        self.assertIn("XTraceLogger::StringHashRefJson(url)", dom_url)
        self.assertIn("XTraceLogger::StringHashRefJson(base_string)", dom_url)
        self.assertIn("XTraceLogger::StringHashRefJson(value)", dom_url)
        self.assertIn("XTraceLogger::StringHashRefJson(href)", dom_url)
        self.assertIn("XTraceLogger::StringHashRefJson(search)", dom_url)
        self.assertIn("platform/xtrace/xtrace_logger.h", location)
        self.assertIn('"Location.href.get"', location)
        self.assertIn('"Location.search.get"', location)
        self.assertIn('"Location.href.set"', location)
        self.assertIn('"Location.search.set"', location)
        self.assertIn('"Location.assign"', location)
        self.assertIn('"Location.replace"', location)
        self.assertIn("result_length", location)
        self.assertIn("result_ref", location)
        self.assertIn("value_length", location)
        self.assertIn("value_ref", location)
        self.assertIn("href_length", location)
        self.assertIn("href_ref", location)
        self.assertIn("XTraceLogger::StringHashRefJson(result)", location)
        self.assertIn("XTraceLogger::StringHashRefJson(value)", location)
        self.assertIn("XTraceLogger::StringHashRefJson(href)", location)
        self.assertIn('"Request.constructor"', request)
        self.assertIn('"Request.method.get"', request)
        self.assertIn('"Request.url.get"', request)
        self.assertIn('"Request.headers.get"', request)
        self.assertIn('"Request.clone"', request)
        self.assertIn("source_headers_id", request)
        self.assertIn("cloned_headers_id", request)
        self.assertIn("url_ref", request)
        self.assertIn("method_ref", request)
        self.assertIn("headers_id", request)
        self.assertIn("body_ref", request)
        self.assertIn('\\"body\\":%s', request)
        self.assertNotIn("body_preview", request)
        self.assertIn("body_type", request)
        self.assertIn("body_array_buffer_id", request)
        self.assertIn("body_typed_array_id", request)
        self.assertIn("body_byte_offset", request)
        self.assertIn("body_hex", request)
        self.assertIn("XTraceBytesHexString(array_buffer->ByteSpan())", request)
        self.assertIn(
            "XTraceBytesHexString(array_buffer_view->ByteSpan())", request
        )
        self.assertIn("XTraceBytesHexJson(array_buffer->ByteSpan())", request)
        self.assertIn("XTraceBytesHexJson(array_buffer_view->ByteSpan())", request)
        self.assertNotIn("XTraceBytesPreview", request)
        self.assertNotIn("kPreviewBytes", request)
        self.assertNotIn("std::min(bytes.size()", request)
        self.assertIn("XTraceLogger::StringHashRefJson(method)", request)
        self.assertIn("XTraceLogger::StringHashRefJson(body_value)", request)
        self.assertIn("XTraceLogger::StringHashRefJson(url.GetString())", request)
        self.assertIn("DOMArrayBuffer::ByteSpan", request)
        self.assertIn("DOMArrayBufferView::ByteSpan", request)
        self.assertIn(
            "XTraceLogger::StringHashRefJson(request->Url().GetString())",
            request,
        )
        self.assertIn('"XMLHttpRequest.open"', xhr)
        self.assertIn("url_ref", xhr)
        self.assertIn(
            "XTraceLogger::StringHashRefJson(url_.GetString())",
            xhr,
        )

    def test_xtrace_body_consumption_hooks_are_wired(self):
        body = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "fetch"
            / "body.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("third_party/blink/renderer/platform/xtrace/xtrace_logger.h", body)
        self.assertIn('"Body.text"', body)
        self.assertIn('"Body.json"', body)
        self.assertIn('"Body.arrayBuffer"', body)
        self.assertIn('"Body.bytes"', body)
        self.assertIn("has_body", body)
        self.assertIn("body_used", body)
        self.assertIn("body_locked", body)
        self.assertIn("content_type", body)
        self.assertIn("mime_type", body)
        self.assertIn("byte_length", body)
        self.assertIn("result_hex", body)
        self.assertIn("result_length", body)
        self.assertIn("result_ref", body)
        self.assertIn("XTraceBytesHexJson(bytes)", body)
        self.assertIn("XTraceBytesHashRefJson", body)
        self.assertNotIn("preview_hex", body)
        self.assertNotIn("XTraceBytesPreview", body)
        self.assertNotIn("kPreviewBytes", body)
        self.assertNotIn("std::min(bytes.size()", body)
        self.assertIn("array_buffer->ByteSpan()", body)
        self.assertIn("XTraceLogger::StringHashRefJson(string)", body)

    def test_xtrace_response_metadata_hooks_are_wired(self):
        response = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "fetch"
            / "response.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("third_party/blink/renderer/platform/xtrace/xtrace_logger.h", response)
        self.assertIn("LogXTraceResponseStringGetter", response)
        self.assertIn('"Response.type.get"', response)
        self.assertIn('"Response.url.get"', response)
        self.assertIn('"Response.status.get"', response)
        self.assertIn('"Response.ok.get"', response)
        self.assertIn('"Response.statusText.get"', response)
        self.assertIn('"Response.headers.get"', response)
        self.assertIn('"Response.clone"', response)
        self.assertIn("response_id", response)
        self.assertIn("headers_id", response)
        self.assertIn("cloned_response_id", response)
        self.assertIn("status_ref", response)
        self.assertIn("url_ref", response)
        self.assertIn('LogXTraceResponseStringGetter(*this, "Response.type.get", "type"', response)
        self.assertIn('"Response.statusText.get",', response)
        self.assertIn('"status_text"', response)
        self.assertIn("XTraceLogger::StringHashRefJson(url)", response)
        self.assertNotIn("url_preview", response)
        self.assertNotIn("status_text_preview", response)

    def test_xtrace_v8_string_add_hooks_are_wired(self):
        runtime_strings = (
            ROOT
            / "chromium"
            / "src"
            / "v8"
            / "src"
            / "runtime"
            / "runtime-strings.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("LogXTraceStringAdd", runtime_strings)
        self.assertIn('"StringAdd"', runtime_strings)
        self.assertIn('"StringAdd.constant_lhs"', runtime_strings)
        self.assertIn('"StringAdd.constant_rhs"', runtime_strings)
        self.assertIn("left_ref", runtime_strings)
        self.assertIn("right_ref", runtime_strings)
        self.assertIn("result_ref", runtime_strings)
        self.assertIn("result_length", runtime_strings)
        self.assertIn("value->ToCString()", runtime_strings)
        self.assertIn('AppendXTraceStringField(event, "left", left)', runtime_strings)
        self.assertIn('AppendXTraceStringField(event, "right", right)', runtime_strings)
        self.assertIn('AppendXTraceStringField(event, "result", result)', runtime_strings)
        self.assertNotIn("kXTraceStringAddPreviewChars", runtime_strings)
        self.assertNotIn("kXTraceStringAddValueChars", runtime_strings)
        self.assertNotIn("preview_only", runtime_strings)
        self.assertNotIn("_truncated", runtime_strings)
        self.assertNotIn("_preview", runtime_strings)
        self.assertNotIn("std::min(original_length", runtime_strings)
        self.assertIn("Runtime_StringAdd_LhsIsStringConstant_Internalize", runtime_strings)
        self.assertIn("Runtime_StringAdd_RhsIsStringConstant_Internalize", runtime_strings)

    def test_xtrace_network_correlation_key_is_wired(self):
        client = (
            ROOT
            / "chromium"
            / "src"
            / "chrome"
            / "browser"
            / "chrome_content_browser_client.cc"
        ).read_text(encoding="utf-8")
        logger_header = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "platform"
            / "xtrace"
            / "xtrace_logger.h"
        ).read_text(encoding="utf-8")
        logger = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "platform"
            / "xtrace"
            / "xtrace_logger.cc"
        ).read_text(encoding="utf-8")
        request = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "fetch"
            / "request.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("NetworkCorrelationKey", logger_header)
        self.assertIn("NetworkCorrelationKey", logger)
        self.assertIn("network_correlation_key", request)
        self.assertIn("network_correlation_key", client)
        self.assertIn("CreateXTraceNetworkCorrelationKey", client)

    def test_xtrace_fetch_boundary_refs_are_wired(self):
        global_fetch = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "fetch"
            / "global_fetch.cc"
        ).read_text(encoding="utf-8")

        self.assertIn('"fetch"', global_fetch)
        self.assertIn("url_ref", global_fetch)
        self.assertIn("headers_id", global_fetch)
        self.assertIn("has_body", global_fetch)
        self.assertIn("body_byte_length", global_fetch)
        self.assertIn("network_correlation_key", global_fetch)
        self.assertIn("XTraceLogger::NetworkCorrelationKey", global_fetch)
        self.assertIn("XTraceLogger::StringHashRefJson", global_fetch)
        self.assertIn("request_data->Url().GetString()", global_fetch)

    def test_xtrace_worker_script_entry_hooks_are_wired(self):
        dedicated_worker = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "workers"
            / "dedicated_worker.cc"
        ).read_text(encoding="utf-8")
        shared_worker = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "workers"
            / "shared_worker.cc"
        ).read_text(encoding="utf-8")
        worker_global_scope = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "workers"
            / "worker_global_scope.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("platform/xtrace/xtrace_logger.h", dedicated_worker)
        self.assertIn('"Worker.constructor"', dedicated_worker)
        self.assertIn("worker_type", dedicated_worker)
        self.assertIn("dedicated", dedicated_worker)
        self.assertIn("script_request_url.GetString()", dedicated_worker)
        self.assertIn("XTraceLogger::LogEvent", dedicated_worker)

        self.assertIn("platform/xtrace/xtrace_logger.h", shared_worker)
        self.assertIn('"SharedWorker.constructor"', shared_worker)
        self.assertIn("worker_type", shared_worker)
        self.assertIn("shared", shared_worker)
        self.assertIn("script_url.GetString()", shared_worker)
        self.assertIn("XTraceLogger::LogEvent", shared_worker)

        self.assertIn("platform/xtrace/xtrace_logger.h", worker_global_scope)
        self.assertIn('"WorkerGlobalScope.importScripts"', worker_global_scope)
        self.assertIn("url_count", worker_global_scope)
        self.assertIn("response_url", worker_global_scope)
        self.assertIn("XTraceLogger::LogEvent", worker_global_scope)

    def test_xtrace_worker_script_source_assets_are_wired(self):
        worker_global_scope = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "workers"
            / "worker_global_scope.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("XTraceLogger::LogAssetEvent", worker_global_scope)
        self.assertIn('"WorkerGlobalScope.mainScript"', worker_global_scope)
        self.assertIn('"WorkerGlobalScope.importScripts.asset"', worker_global_scope)
        self.assertIn('"worker-main-script"', worker_global_scope)
        self.assertIn('"worker-imported-script"', worker_global_scope)
        self.assertIn("source_code", worker_global_scope)
        self.assertIn("script_url.GetString()", worker_global_scope)
        self.assertIn("response_url.GetString()", worker_global_scope)

    def test_xtrace_worker_message_hooks_are_wired(self):
        dedicated_worker = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "workers"
            / "dedicated_worker.cc"
        ).read_text(encoding="utf-8")
        dedicated_worker_global_scope = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "workers"
            / "dedicated_worker_global_scope.cc"
        ).read_text(encoding="utf-8")
        dedicated_worker_messaging_proxy = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "workers"
            / "dedicated_worker_messaging_proxy.cc"
        ).read_text(encoding="utf-8")
        worker_global_scope = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "workers"
            / "worker_global_scope.cc"
        ).read_text(encoding="utf-8")

        self.assertIn('"Worker.postMessage"', dedicated_worker)
        self.assertIn("BuildXTraceWorkerMessageArgs", dedicated_worker)
        self.assertIn("message_type", dedicated_worker)
        self.assertNotIn("message_preview", dedicated_worker)
        self.assertIn("message_value", dedicated_worker)
        self.assertIn("serialized_data_hex", dedicated_worker)
        self.assertIn("serialized_data_ref", dedicated_worker)
        self.assertIn("GetWireData()", dedicated_worker)
        self.assertIn("transfer_count", dedicated_worker)
        self.assertIn("trace_id", dedicated_worker)
        self.assertIn('"window_to_worker"', dedicated_worker)
        self.assertIn("XTraceLogger::LogEvent", dedicated_worker)

        self.assertIn('"DedicatedWorkerGlobalScope.postMessage"', dedicated_worker_global_scope)
        self.assertIn("BuildXTraceWorkerMessageArgs", dedicated_worker_global_scope)
        self.assertNotIn("message_preview", dedicated_worker_global_scope)
        self.assertIn("message_value", dedicated_worker_global_scope)
        self.assertIn("serialized_data_hex", dedicated_worker_global_scope)
        self.assertIn("serialized_data_ref", dedicated_worker_global_scope)
        self.assertIn("GetWireData()", dedicated_worker_global_scope)
        self.assertIn('"worker_to_window"', dedicated_worker_global_scope)
        self.assertIn("XTraceLogger::LogEvent", dedicated_worker_global_scope)

        self.assertIn('"WorkerGlobalScope.message"', worker_global_scope)
        self.assertIn("receive_window_to_worker", worker_global_scope)
        self.assertIn("ports->size()", worker_global_scope)
        self.assertIn("message.trace_id", worker_global_scope)

        self.assertIn('"Worker.message"', dedicated_worker_messaging_proxy)
        self.assertIn("receive_worker_to_window", dedicated_worker_messaging_proxy)
        self.assertIn("ports->size()", dedicated_worker_messaging_proxy)
        self.assertIn("message.trace_id", dedicated_worker_messaging_proxy)

    def test_xtrace_cross_context_message_hooks_are_wired(self):
        broadcast_channel = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "broadcastchannel"
            / "broadcast_channel.cc"
        ).read_text(encoding="utf-8")
        message_port = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "messaging"
            / "message_port.cc"
        ).read_text(encoding="utf-8")
        message_channel = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "messaging"
            / "message_channel.cc"
        ).read_text(encoding="utf-8")
        dom_window = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "frame"
            / "dom_window.cc"
        ).read_text(encoding="utf-8")
        local_dom_window = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "frame"
            / "local_dom_window.cc"
        ).read_text(encoding="utf-8")
        service_worker_client = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "service_worker"
            / "service_worker_client.cc"
        ).read_text(encoding="utf-8")
        service_worker_clients = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "service_worker"
            / "service_worker_clients.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("platform/xtrace/xtrace_logger.h", broadcast_channel)
        self.assertIn('"BroadcastChannel.constructor"', broadcast_channel)
        self.assertIn('"BroadcastChannel.postMessage"', broadcast_channel)
        self.assertIn('"BroadcastChannel.message"', broadcast_channel)
        self.assertIn("channel_name_ref", broadcast_channel)
        self.assertIn("message_type", broadcast_channel)
        self.assertNotIn("message_preview", broadcast_channel)
        self.assertIn("message_value", broadcast_channel)
        self.assertIn("serialized_data_hex", broadcast_channel)
        self.assertIn("serialized_data_ref", broadcast_channel)
        self.assertIn("GetWireData()", broadcast_channel)
        self.assertIn("message_ref", broadcast_channel)
        self.assertIn("origin", broadcast_channel)
        self.assertIn("XTraceLogger::StringHashRefJson", broadcast_channel)

        self.assertIn("platform/xtrace/xtrace_logger.h", message_port)
        self.assertIn('"MessagePort.postMessage"', message_port)
        self.assertIn('"MessagePort.message"', message_port)
        self.assertIn('"MessagePort.start"', message_port)
        self.assertIn('"MessagePort.close"', message_port)
        self.assertIn("message_port_id", message_port)
        self.assertIn("message_type", message_port)
        self.assertNotIn("message_preview", message_port)
        self.assertIn("message_value", message_port)
        self.assertIn("serialized_data_hex", message_port)
        self.assertIn("serialized_data_ref", message_port)
        self.assertIn("GetWireData()", message_port)
        self.assertIn("message_ref", message_port)
        self.assertIn("transfer_count", message_port)

        self.assertIn("platform/xtrace/xtrace_logger.h", message_channel)
        self.assertIn('"MessageChannel.constructor"', message_channel)
        self.assertIn("port1_id", message_channel)
        self.assertIn("port2_id", message_channel)
        self.assertIn("XTraceMessagePortId", message_channel)

        self.assertIn("platform/xtrace/xtrace_logger.h", dom_window)
        self.assertIn('"Window.postMessage"', dom_window)
        self.assertIn("source_origin", dom_window)
        self.assertIn("target_origin", dom_window)
        self.assertIn("target_window_url_ref", dom_window)
        self.assertIn("message_type", dom_window)
        self.assertNotIn("message_preview", dom_window)
        self.assertIn("message_value", dom_window)
        self.assertIn("serialized_data_hex", dom_window)
        self.assertIn("serialized_data_ref", dom_window)
        self.assertIn("GetWireData()", dom_window)
        self.assertIn("message_ref", dom_window)
        self.assertIn("transfer_count", dom_window)

        self.assertIn("platform/xtrace/xtrace_logger.h", local_dom_window)
        self.assertIn('"Window.message"', local_dom_window)
        self.assertIn("sender_origin", local_dom_window)
        self.assertIn("target_window_url_ref", local_dom_window)
        self.assertIn("event->ports()", local_dom_window)

        self.assertIn("platform/xtrace/xtrace_logger.h", service_worker_client)
        self.assertIn('"ServiceWorkerClient.postMessage"', service_worker_client)
        self.assertIn("client_id", service_worker_client)
        self.assertIn("client_url_ref", service_worker_client)
        self.assertIn("client_type", service_worker_client)
        self.assertIn("message_type", service_worker_client)
        self.assertNotIn("message_preview", service_worker_client)
        self.assertIn("message_value", service_worker_client)
        self.assertIn("serialized_data_hex", service_worker_client)
        self.assertIn("serialized_data_ref", service_worker_client)
        self.assertIn("GetWireData()", service_worker_client)
        self.assertIn("transfer_count", service_worker_client)

        self.assertIn("platform/xtrace/xtrace_logger.h", service_worker_clients)
        self.assertIn('"ServiceWorkerClients.get"', service_worker_clients)
        self.assertIn('"ServiceWorkerClients.matchAll"', service_worker_clients)
        self.assertIn('"ServiceWorkerClients.openWindow"', service_worker_clients)
        self.assertIn("include_uncontrolled", service_worker_clients)
        self.assertIn("client_type", service_worker_clients)
        self.assertIn("url_ref", service_worker_clients)

    def test_xtrace_service_worker_hooks_are_wired(self):
        service_worker_container = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "service_worker"
            / "service_worker_container.cc"
        ).read_text(encoding="utf-8")
        service_worker_global_scope = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "service_worker"
            / "service_worker_global_scope.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("platform/xtrace/xtrace_logger.h", service_worker_container)
        self.assertIn('"ServiceWorkerContainer.register"', service_worker_container)
        self.assertIn("script_url.GetString()", service_worker_container)
        self.assertIn("scope_url.GetString()", service_worker_container)
        self.assertIn("update_via_cache", service_worker_container)
        self.assertIn("script_type", service_worker_container)
        self.assertIn("XTraceLogger::StringHashRefJson", service_worker_container)

        self.assertIn("platform/xtrace/xtrace_logger.h", service_worker_global_scope)
        self.assertIn('"ServiceWorkerGlobalScope.mainScript"', service_worker_global_scope)
        self.assertIn('"service-worker-main-script"', service_worker_global_scope)
        self.assertIn('"ServiceWorkerGlobalScope.importScripts"', service_worker_global_scope)
        self.assertIn('"ServiceWorkerGlobalScope.importScripts.asset"', service_worker_global_scope)
        self.assertIn('"service-worker-imported-script"', service_worker_global_scope)
        self.assertIn('"ServiceWorkerGlobalScope.fetch"', service_worker_global_scope)
        self.assertIn("fetch_request.url.GetString()", service_worker_global_scope)
        self.assertIn("fetch_request.method", service_worker_global_scope)
        self.assertIn("header_count", service_worker_global_scope)
        self.assertIn("event_id", service_worker_global_scope)

    def test_xtrace_service_worker_response_cache_hooks_are_wired(self):
        fetch_event = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "service_worker"
            / "fetch_event.cc"
        ).read_text(encoding="utf-8")
        fetch_respond_with_observer = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "service_worker"
            / "fetch_respond_with_observer.cc"
        ).read_text(encoding="utf-8")
        cache = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "cache_storage"
            / "cache.cc"
        ).read_text(encoding="utf-8")
        cache_storage = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "cache_storage"
            / "cache_storage.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("platform/xtrace/xtrace_logger.h", fetch_event)
        self.assertIn('"FetchEvent.respondWith"', fetch_event)
        self.assertIn("event_id", fetch_event)
        self.assertIn("request_url", fetch_event)
        self.assertIn("XTraceLogger::LogEvent", fetch_event)

        self.assertIn("platform/xtrace/xtrace_logger.h", fetch_respond_with_observer)
        self.assertIn('"FetchEvent.respondWith.fulfilled"', fetch_respond_with_observer)
        self.assertIn('"FetchEvent.respondWith.rejected"', fetch_respond_with_observer)
        self.assertIn('"FetchEvent.respondWith.noResponse"', fetch_respond_with_observer)
        self.assertIn("response->status()", fetch_respond_with_observer)
        self.assertIn("response->url()", fetch_respond_with_observer)
        self.assertIn("request_url_", fetch_respond_with_observer)
        self.assertIn("request_url_ref", fetch_respond_with_observer)
        self.assertIn("response_url_ref", fetch_respond_with_observer)
        self.assertIn("XTraceLogger::LogEventNoStack", fetch_respond_with_observer)

        self.assertIn("platform/xtrace/xtrace_logger.h", cache)
        self.assertIn('"Cache.match"', cache)
        self.assertIn('"Cache.put"', cache)
        self.assertIn('"Cache.delete"', cache)
        self.assertIn("request->url().GetString()", cache)
        self.assertIn("response->status()", cache)
        self.assertIn("request_url_ref", cache)
        self.assertIn("response_url_ref", cache)
        self.assertIn("cache_result", cache)
        self.assertIn("XTraceLogger::StringHashRefJson", cache)

        self.assertIn("platform/xtrace/xtrace_logger.h", cache_storage)
        self.assertIn('"CacheStorage.open"', cache_storage)
        self.assertIn('"CacheStorage.match"', cache_storage)
        self.assertIn('"CacheStorage.delete"', cache_storage)
        self.assertIn("cache_name_ref", cache_storage)
        self.assertIn("request_url_ref", cache_storage)
        self.assertIn("cache_result", cache_storage)
        self.assertIn("XTraceLogger::StringHashRefJson", cache_storage)

    def test_xtrace_indexeddb_hooks_are_wired(self):
        indexeddb_root = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "indexeddb"
        )
        idb_factory = (indexeddb_root / "idb_factory.cc").read_text(
            encoding="utf-8"
        )
        idb_database = (indexeddb_root / "idb_database.cc").read_text(
            encoding="utf-8"
        )
        idb_object_store = (indexeddb_root / "idb_object_store.cc").read_text(
            encoding="utf-8"
        )
        idb_index = (indexeddb_root / "idb_index.cc").read_text(
            encoding="utf-8"
        )
        idb_cursor = (indexeddb_root / "idb_cursor.cc").read_text(
            encoding="utf-8"
        )
        idb_request = (indexeddb_root / "idb_request.cc").read_text(
            encoding="utf-8"
        )

        for source in (
            idb_factory,
            idb_database,
            idb_object_store,
            idb_index,
            idb_cursor,
            idb_request,
        ):
            self.assertIn("platform/xtrace/xtrace_logger.h", source)
            self.assertIn("XTraceLogger::StringHashRefJson", source)

        self.assertIn('"IDBFactory.open"', idb_factory)
        self.assertIn('"IDBFactory.deleteDatabase"', idb_factory)
        self.assertIn("database_name_ref", idb_factory)
        self.assertIn("version", idb_factory)

        self.assertIn('"IDBDatabase.transaction"', idb_database)
        self.assertIn("database_name_ref", idb_database)
        self.assertIn("store_count", idb_database)
        self.assertIn("transaction_mode", idb_database)

        self.assertIn('"IDBObjectStore.get"', idb_object_store)
        self.assertIn('"IDBObjectStore.getAll"', idb_object_store)
        self.assertIn('"IDBObjectStore.put"', idb_object_store)
        self.assertIn('"IDBObjectStore.add"', idb_object_store)
        self.assertIn('"IDBObjectStore.delete"', idb_object_store)
        self.assertIn('"IDBObjectStore.clear"', idb_object_store)
        self.assertIn('"IDBObjectStore.openCursor"', idb_object_store)
        self.assertIn("object_store_name_ref", idb_object_store)
        self.assertIn("key_range", idb_object_store)
        self.assertIn("value_size", idb_object_store)
        self.assertIn("value_ref", idb_object_store)

        self.assertIn('"IDBIndex.get"', idb_index)
        self.assertIn('"IDBIndex.getAll"', idb_index)
        self.assertIn('"IDBIndex.openCursor"', idb_index)
        self.assertIn("index_name_ref", idb_index)
        self.assertIn("object_store_name_ref", idb_index)

        self.assertIn('"IDBCursor.advance"', idb_cursor)
        self.assertIn('"IDBCursor.continue"', idb_cursor)
        self.assertIn('"IDBCursor.continuePrimaryKey"', idb_cursor)
        self.assertIn("primary_key_ref", idb_cursor)

        self.assertIn('"IDBRequest.result"', idb_request)
        self.assertIn('"IDBRequest.error"', idb_request)
        self.assertIn("RequestTypeToName", idb_request)
        self.assertIn("result_type", idb_request)
        self.assertIn("result_value_size", idb_request)
        self.assertIn("result_key_ref", idb_request)

    def test_xtrace_headers_hooks_are_wired(self):
        headers_header = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "fetch"
            / "headers.h"
        ).read_text(encoding="utf-8")
        headers = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "fetch"
            / "headers.cc"
        ).read_text(encoding="utf-8")

        self.assertIn('"Headers.constructor"', headers)
        self.assertIn('"Headers.append"', headers)
        self.assertIn('"Headers.set"', headers)
        self.assertIn('"Headers.delete"', headers)
        self.assertIn('"Headers.get"', headers)
        self.assertIn('"Headers.has"', headers)
        self.assertIn('"Headers.iterator.next"', headers)
        self.assertIn("XTraceId()", headers_header)
        self.assertIn("headers_id", headers)
        self.assertIn("XTraceHeadersArrayJson", headers)
        self.assertIn("entry_count", headers)
        self.assertIn('\\"headers\\":%s', headers)
        self.assertIn("iteration_index", headers)
        self.assertIn("name_length", headers)
        self.assertIn("name_ref", headers)
        self.assertIn("value_length", headers)
        self.assertIn("value_ref", headers)
        self.assertIn("normalized_value_length", headers)
        self.assertIn("result_ref", headers)
        self.assertIn("result_length", headers)
        self.assertIn("normalized_value_ref", headers)
        self.assertIn("XTraceLogger::StringHashRefJson(name)", headers)
        self.assertIn("XTraceLogger::StringHashRefJson(value)", headers)
        self.assertIn("XTraceLogger::StringHashRefJson(result)", headers)
        self.assertIn("XTraceLogger::StringHashRefJson(normalized_value)", headers)
        headers_get = headers.split('"Headers.get"', 1)[1].split("return result;", 1)[0]
        self.assertIn("name_length", headers_get)
        self.assertIn("name_ref", headers_get)
        headers_has = headers.split('"Headers.has"', 1)[1].split("return result;", 1)[0]
        self.assertIn("name_length", headers_has)
        self.assertIn("name_ref", headers_has)
        headers_delete = headers.split('"Headers.delete"', 1)[1].split("for (auto& iter", 1)[0]
        self.assertIn("name_length", headers_delete)
        self.assertIn("name_ref", headers_delete)
        self.assertIn("removed", headers_delete)

    def test_xtrace_storage_hooks_capture_material_refs(self):
        storage_area = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "storage"
            / "storage_area.cc"
        ).read_text(encoding="utf-8")

        self.assertIn('"Storage.getItem"', storage_area)
        self.assertIn('"Storage.setItem"', storage_area)
        self.assertIn('"Storage.removeItem"', storage_area)
        self.assertIn('"Storage.key"', storage_area)
        self.assertIn("key_length", storage_area)
        self.assertIn("key_ref", storage_area)
        self.assertIn("value_length", storage_area)
        self.assertIn("value_ref", storage_area)
        self.assertIn("result_length", storage_area)
        self.assertIn("result_ref", storage_area)
        self.assertIn("XTraceLogger::StringHashRefJson(key)", storage_area)
        self.assertIn("XTraceLogger::StringHashRefJson(value)", storage_area)
        self.assertIn("XTraceJsonStringRefOrNull(result)", storage_area)

    def test_xtrace_document_cookie_hooks_capture_material_refs(self):
        document_idl = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "dom"
            / "document.idl"
        ).read_text(encoding="utf-8")
        document = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "dom"
            / "document.cc"
        ).read_text(encoding="utf-8")
        node = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "dom"
            / "node.cc"
        ).read_text(encoding="utf-8")

        self.assertIn('"Document.cookie.get"', document)
        self.assertIn('"Document.cookie.set"', document)
        self.assertIn("[ImplementedAs=urlForBinding] readonly attribute USVString documentURI", document_idl)
        self.assertIn('"Document.urlForBinding.get"', document)
        self.assertIn('"Document.referrer.get"', document)
        self.assertIn('"Node.baseURI.get"', node)
        self.assertIn("result_length", document)
        self.assertIn("result_ref", document)
        self.assertIn("result_length", node)
        self.assertIn("result_ref", node)
        self.assertIn("value_length", document)
        self.assertIn("value_ref", document)
        self.assertIn("accepted", document)
        self.assertIn("XTraceLogger::StringHashRefJson(result)", document)
        self.assertIn("XTraceLogger::StringHashRefJson(result)", node)
        self.assertIn("XTraceLogger::StringHashRefJson(cookies)", document)
        self.assertIn("XTraceLogger::StringHashRefJson(value)", document)

    def test_xtrace_cookie_store_hooks_capture_material_refs(self):
        cookie_store = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "cookie_store"
            / "cookie_store.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("platform/xtrace/xtrace_logger.h", cookie_store)
        self.assertIn('"CookieStore.get"', cookie_store)
        self.assertIn('"CookieStore.getAll"', cookie_store)
        self.assertIn('"CookieStore.set"', cookie_store)
        self.assertIn('"CookieStore.delete"', cookie_store)
        self.assertIn("name_length", cookie_store)
        self.assertIn("name_ref", cookie_store)
        self.assertIn("value_length", cookie_store)
        self.assertIn("value_ref", cookie_store)
        self.assertIn("cookie_url_ref", cookie_store)
        self.assertIn("result_count", cookie_store)
        self.assertIn("result_names", cookie_store)
        self.assertIn("result_name_lengths", cookie_store)
        self.assertIn("result_name_refs", cookie_store)
        self.assertIn("result_values", cookie_store)
        self.assertIn("result_value_lengths", cookie_store)
        self.assertIn("result_value_refs", cookie_store)
        self.assertIn("accepted", cookie_store)
        self.assertIn("XTraceLogger::StringHashRefJson", cookie_store)

    def test_xtrace_header_mutations_have_request_link_refs(self):
        request = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "fetch"
            / "request.cc"
        ).read_text(encoding="utf-8")
        xhr = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "xmlhttprequest"
            / "xml_http_request.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("headers_id", request)
        self.assertIn("r->getHeaders()->XTraceId()", request)
        self.assertIn("xhr_id", xhr)
        self.assertIn("network_correlation_key", xhr)
        self.assertIn("XTraceLogger::NetworkCorrelationKey", xhr)
        self.assertIn("method", xhr)
        self.assertIn("url", xhr)
        self.assertIn("name_ref", xhr)
        self.assertIn("name_length", xhr)
        self.assertIn("value_length", xhr)
        self.assertIn("value_ref", xhr)
        self.assertIn("normalized_value", xhr)
        self.assertIn("normalized_value_length", xhr)
        self.assertIn("normalized_value_ref", xhr)
        self.assertIn("body_ref", xhr)
        self.assertIn("XTraceLogger::QuoteJson(raw_value)", xhr)
        self.assertIn("XTraceLogger::StringHashRefJson(header_name)", xhr)
        self.assertIn("XTraceLogger::StringHashRefJson(raw_value)", xhr)
        self.assertIn("XTraceLogger::StringHashRefJson(normalized_value)", xhr)
        self.assertIn("XTraceLogger::StringHashRefJson(body)", xhr)

    def test_xtrace_xhr_open_has_network_correlation_key(self):
        xhr = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "xmlhttprequest"
            / "xml_http_request.cc"
        ).read_text(encoding="utf-8")

        open_start = xhr.index("void XMLHttpRequest::open(const AtomicString& method,")
        open_log = xhr.index('"XMLHttpRequest.open"', open_start)
        open_section = xhr[open_start : open_log + 900]
        self.assertIn("XTraceLogger::NetworkCorrelationKey", open_section)
        self.assertIn('\\"network_correlation_key\\":%s', open_section)
        self.assertIn("XTraceLogger::QuoteJson(xtrace_network_correlation_key)", open_section)

    def test_xtrace_xhr_response_text_has_material_refs(self):
        xhr = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "xmlhttprequest"
            / "xml_http_request.cc"
        ).read_text(encoding="utf-8")

        response_start = xhr.index("String XMLHttpRequest::responseText")
        response_log = xhr.index('"XMLHttpRequest.responseText"', response_start)
        response_section = xhr[response_start : response_log + 900]
        self.assertIn("XTracePointerId(this)", response_section)
        self.assertIn("XTraceLogger::NetworkCorrelationKey", response_section)
        self.assertIn('\\"url_ref\\":%s', response_section)
        self.assertIn('\\"network_correlation_key\\":%s', response_section)
        self.assertIn('\\"value_length\\":%u', response_section)
        self.assertIn('\\"value_ref\\":%s', response_section)

    def test_xtrace_xhr_binary_body_refs_are_wired(self):
        xhr = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "xmlhttprequest"
            / "xml_http_request.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("body_type", xhr)
        self.assertIn("body_array_buffer_id", xhr)
        self.assertIn("body_typed_array_id", xhr)
        self.assertIn("body_byte_offset", xhr)
        self.assertIn("body_size", xhr)
        self.assertIn('\\"body\\":%s', xhr)
        self.assertNotIn("body_preview", xhr)
        self.assertIn("body_hex", xhr)
        self.assertIn("XTraceBytesHexString(bytes)", xhr)
        self.assertIn("XTraceBytesHexJson(bytes)", xhr)
        self.assertIn("XTraceBytesHashRefJson", xhr)
        self.assertNotIn("XTraceBytesPreview", xhr)
        self.assertNotIn("kPreviewBytes", xhr)
        self.assertNotIn("std::min(bytes.size()", xhr)
        self.assertIn("DOMArrayBuffer::ByteSpan", xhr)
        self.assertIn("DOMArrayBufferView::ByteSpan", xhr)

    def test_xtrace_form_data_hooks_are_wired(self):
        form_data_header = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "html"
            / "forms"
            / "form_data.h"
        ).read_text(encoding="utf-8")
        form_data = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "html"
            / "forms"
            / "form_data.cc"
        ).read_text(encoding="utf-8")
        request = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "fetch"
            / "request.cc"
        ).read_text(encoding="utf-8")
        xhr = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "xmlhttprequest"
            / "xml_http_request.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("XTraceId()", form_data_header)
        self.assertIn("form_data_id", form_data)
        self.assertIn('"FormData.constructor"', form_data)
        self.assertIn("XTraceFormDataEntriesJson", form_data)
        self.assertIn("cloned_from_form_data_id", form_data)
        self.assertIn('\\"entries\\":%s', form_data)
        self.assertIn("XTraceLogFormDataConstructor(*this, form_data.XTraceId())", form_data)
        self.assertIn('"FormData.append"', form_data)
        self.assertIn('"FormData.set"', form_data)
        self.assertIn('"FormData.delete"', form_data)
        self.assertIn('"FormData.get"', form_data)
        self.assertIn('"FormData.getAll"', form_data)
        self.assertIn('"FormData.has"', form_data)
        self.assertIn('"FormData.iterator.next"', form_data)
        self.assertIn("iteration_index", form_data)
        self.assertIn("value_kind", form_data)
        self.assertIn("value_ref", form_data)
        self.assertIn("result_ref", form_data)
        self.assertIn("result_value_refs", form_data)
        self.assertIn("result_value_lengths", form_data)
        self.assertIn(
            'XTraceLogFormDataBlobMutation("FormData.append", *this, name, blob, filename)',
            form_data,
        )
        self.assertIn(
            'XTraceLogFormDataBlobMutation("FormData.set", *this, name, blob, filename',
            form_data,
        )
        self.assertIn("filename_length", form_data)
        self.assertIn("blob_type_ref", form_data)
        self.assertIn("blob_size", form_data)
        self.assertIn("blob_uuid_ref", form_data)
        self.assertIn("blob_filenames", form_data)
        self.assertIn("blob_filename_refs", form_data)
        self.assertIn("blob_type_refs", form_data)
        self.assertIn("blob_sizes", form_data)
        self.assertIn("blob_uuid_refs", form_data)
        self.assertIn("XTraceLogger::StringHashRefJson(value)", form_data)
        self.assertIn("form->XTraceId()", request)
        self.assertIn("xtrace_form_data_id", request)
        self.assertIn("form_data_id", request)
        self.assertIn("body->XTraceId()", xhr)
        self.assertIn("xtrace_form_data_id", xhr)
        self.assertIn("form_data_id", xhr)

    def test_xtrace_url_search_params_body_refs_are_wired(self):
        request = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "fetch"
            / "request.cc"
        ).read_text(encoding="utf-8")
        xhr = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "xmlhttprequest"
            / "xml_http_request.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("xtrace_body_search_params_id", request)
        self.assertIn("url_search_params->XTraceId()", request)
        self.assertIn("body_search_params_id", request)
        self.assertIn("xtrace_body_search_params_id", xhr)
        self.assertIn("body->XTraceId()", xhr)
        self.assertIn(
            "CreateRequest(std::move(http_body), exception_state, 0, body->XTraceId(),",
            xhr,
        )
        self.assertIn('"url_search_params"', xhr)
        self.assertNotIn(
            "void XMLHttpRequest::send(const String& body, ExceptionState& exception_state) {"
            "\n  if (!InitSend(exception_state))"
            "\n    return;"
            "\n\n  scoped_refptr<EncodedFormData> http_body;"
            "\n\n  if (!body.IsNull() && AreMethodAndURLValidForSend()) {"
            "\n    http_body = EncodedFormData::Create("
            "\n        Utf8Encoding().Encode(body, UnencodableHandling::kNone));"
            "\n    UpdateContentTypeAndCharset(AtomicString(\"text/plain;charset=UTF-8\"),"
            "\n                                \"UTF-8\");"
            "\n  }"
            "\n\n  CreateRequest(std::move(http_body), exception_state, 0, body->XTraceId());",
            xhr,
        )
        self.assertIn("body_search_params_id", xhr)

    def test_xtrace_vmp_decode_hooks_are_wired(self):
        universal_global_scope = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "frame"
            / "universal_global_scope.cc"
        ).read_text(encoding="utf-8")
        text_encoder = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "encoding"
            / "text_encoder.cc"
        ).read_text(encoding="utf-8")
        text_decoder = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "encoding"
            / "text_decoder.cc"
        ).read_text(encoding="utf-8")
        crypto_cc = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "crypto"
            / "crypto.cc"
        ).read_text(encoding="utf-8")
        subtle_crypto = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "crypto"
            / "subtle_crypto.cc"
        ).read_text(encoding="utf-8")
        crypto_result_impl_header = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "crypto"
            / "crypto_result_impl.h"
        ).read_text(encoding="utf-8")
        crypto_result_impl = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "crypto"
            / "crypto_result_impl.cc"
        ).read_text(encoding="utf-8")

        self.assertIn('"btoa"', universal_global_scope)
        self.assertIn('"atob"', universal_global_scope)
        self.assertIn("XTraceBase64ArgsJson", universal_global_scope)
        self.assertIn('\\"input_hex\\"', universal_global_scope)
        self.assertIn('\\"input_ref\\"', universal_global_scope)
        self.assertIn('\\"result_hex\\"', universal_global_scope)
        self.assertIn('\\"result_ref\\"', universal_global_scope)
        self.assertIn('"TextEncoder.constructor"', text_encoder)
        self.assertIn('"TextEncoder.encode"', text_encoder)
        self.assertIn('"TextEncoder.encodeInto"', text_encoder)
        self.assertIn("XTraceBytesHexJson", text_encoder)
        self.assertIn("XTraceBytesHashRefJson", text_encoder)
        self.assertIn('\\"result_hex\\"', text_encoder)
        self.assertIn('\\"result_ref\\"', text_encoder)
        self.assertIn('\\"written_hex\\"', text_encoder)
        self.assertIn('\\"written_ref\\"', text_encoder)
        self.assertIn('\\"destination_hex\\"', text_encoder)
        self.assertIn('\\"destination_ref\\"', text_encoder)
        self.assertIn('"TextDecoder.constructor"', text_decoder)
        self.assertIn('"TextDecoder.decode"', text_decoder)
        self.assertIn("XTraceBytesHexJson", text_decoder)
        self.assertIn("XTraceBytesHashRefJson", text_decoder)
        self.assertIn('\\"input_hex\\"', text_decoder)
        self.assertIn('\\"input_ref\\"', text_decoder)
        self.assertIn('\\"result_ref\\"', text_decoder)
        self.assertIn('"Crypto.getRandomValues"', crypto_cc)
        self.assertIn('"Crypto.randomUUID"', crypto_cc)
        self.assertIn("XTraceRandomValuesResultArgsJson", crypto_cc)
        self.assertIn("XTraceRandomUuidArgsJson", crypto_cc)
        self.assertIn('\\"random_source\\":\\"Crypto.getRandomValues\\"', crypto_cc)
        self.assertIn('\\"random_source\\":\\"Crypto.randomUUID\\"', crypto_cc)
        self.assertIn('\\"typed_array_type\\"', crypto_cc)
        self.assertIn('\\"array_buffer_id\\"', crypto_cc)
        self.assertIn('\\"typed_array_id\\"', crypto_cc)
        self.assertIn('\\"byte_offset\\"', crypto_cc)
        self.assertIn('\\"result_hex\\"', crypto_cc)
        self.assertIn('\\"result_ref\\"', crypto_cc)
        self.assertIn('LogEvent("reverse", "return", "Crypto.getRandomValues"', crypto_cc)
        self.assertIn('"SubtleCrypto.encrypt"', subtle_crypto)
        self.assertIn('"SubtleCrypto.decrypt"', subtle_crypto)
        self.assertIn('"SubtleCrypto.digest"', subtle_crypto)
        self.assertIn('"SubtleCrypto.sign"', subtle_crypto)
        self.assertIn('"SubtleCrypto.verify"', subtle_crypto)
        self.assertIn('"SubtleCrypto.importKey"', subtle_crypto)
        self.assertIn('"SubtleCrypto.generateKey"', subtle_crypto)
        self.assertIn('"SubtleCrypto.exportKey"', subtle_crypto)
        self.assertIn('"SubtleCrypto.deriveBits"', subtle_crypto)
        self.assertIn('"SubtleCrypto.deriveKey"', subtle_crypto)
        self.assertIn('"SubtleCrypto.wrapKey"', subtle_crypto)
        self.assertIn('"SubtleCrypto.unwrapKey"', subtle_crypto)
        self.assertIn("XTraceSignArgsJson", subtle_crypto)
        self.assertIn("XTraceVerifyArgsJson", subtle_crypto)
        self.assertIn("XTraceImportKeyArgsJson", subtle_crypto)
        self.assertIn("XTraceGenerateKeyArgsJson", subtle_crypto)
        self.assertIn("XTraceExportKeyArgsJson", subtle_crypto)
        self.assertIn("XTraceDeriveBitsArgsJson", subtle_crypto)
        self.assertIn("XTraceDeriveKeyArgsJson", subtle_crypto)
        self.assertIn("XTraceWrapKeyArgsJson", subtle_crypto)
        self.assertIn("XTraceUnwrapKeyArgsJson", subtle_crypto)
        self.assertIn("key_id", subtle_crypto)
        self.assertIn("key_handle_id", subtle_crypto)
        self.assertIn("key_algorithm", subtle_crypto)
        self.assertIn("key_type", subtle_crypto)
        self.assertIn("key_data_ref", subtle_crypto)
        self.assertIn("key_data_hex", subtle_crypto)
        self.assertIn("key_usages_mask", subtle_crypto)
        self.assertIn('"base_", base_key', subtle_crypto)
        self.assertIn('"wrapping_", wrapping_key', subtle_crypto)
        self.assertIn('"unwrapping_", unwrapping_key', subtle_crypto)
        self.assertIn("wrapped_key_hex", subtle_crypto)
        self.assertIn("derived_key_algorithm", subtle_crypto)
        self.assertIn("unwrapped_key_algorithm", subtle_crypto)
        self.assertIn("SetXTraceOperation", crypto_result_impl_header)
        self.assertIn("SetXTraceOperation", subtle_crypto)
        self.assertIn("xtrace_api_", crypto_result_impl)
        self.assertIn("operation_id", crypto_result_impl)
        self.assertIn("result_ref", crypto_result_impl)
        self.assertIn("result_hex", crypto_result_impl)
        self.assertIn("result_json", crypto_result_impl)
        self.assertIn('"public_", result->publicKey()', crypto_result_impl)
        self.assertIn('"private_", result->privateKey()', crypto_result_impl)
        self.assertIn("XTraceJsonResultArgsJson", crypto_result_impl)
        self.assertIn("XTraceGeneratedKeyPairResultArgsJson", crypto_result_impl)
        self.assertIn("key_ref", crypto_result_impl)
        self.assertIn("result_array_buffer_id", crypto_result_impl)
        self.assertIn("XTraceLogger::LogEventNoStack", crypto_result_impl)
        self.assertIn("XTraceBufferSourceArrayBufferId", subtle_crypto)
        self.assertIn("XTraceBufferSourceTypedArrayId", subtle_crypto)
        self.assertIn("XTraceBufferSourceByteOffset", subtle_crypto)
        self.assertIn("array_buffer_id", subtle_crypto)
        self.assertIn("typed_array_id", subtle_crypto)
        self.assertIn("byte_offset", subtle_crypto)
        self.assertIn("input_ref", subtle_crypto)
        self.assertIn("input_hex", subtle_crypto)
        self.assertIn("signature_ref", subtle_crypto)
        self.assertIn("signature_hex", subtle_crypto)
        self.assertIn("XTraceBooleanResultArgsJson", crypto_result_impl)
        self.assertIn('result_type\\":\\"boolean', crypto_result_impl)
        self.assertNotIn("preview_hex", subtle_crypto)
        self.assertNotIn("kPreviewBytes", subtle_crypto)
        self.assertNotIn("std::min(data_span.size()", subtle_crypto)
        self.assertNotIn("preview_hex", crypto_result_impl)
        self.assertNotIn("kPreviewBytes", crypto_result_impl)
        self.assertNotIn("std::min(bytes.size()", crypto_result_impl)

    def test_native_patch_exports_webcrypto_signature_hooks(self):
        native_patch = (
            ROOT
            / "patches"
            / "0001-xtrace-native-logger.patch"
        ).read_text(encoding="utf-8")

        self.assertIn('"SubtleCrypto.encrypt"', native_patch)
        self.assertIn('"SubtleCrypto.decrypt"', native_patch)
        self.assertIn('"SubtleCrypto.sign"', native_patch)
        self.assertIn('"SubtleCrypto.verify"', native_patch)
        self.assertIn('"SubtleCrypto.importKey"', native_patch)
        self.assertIn('"SubtleCrypto.generateKey"', native_patch)
        self.assertIn('"SubtleCrypto.exportKey"', native_patch)
        self.assertIn('"SubtleCrypto.deriveBits"', native_patch)
        self.assertIn('"SubtleCrypto.deriveKey"', native_patch)
        self.assertIn('"SubtleCrypto.wrapKey"', native_patch)
        self.assertIn('"SubtleCrypto.unwrapKey"', native_patch)
        self.assertIn("XTraceSignArgsJson", native_patch)
        self.assertIn("XTraceVerifyArgsJson", native_patch)
        self.assertIn("XTraceImportKeyArgsJson", native_patch)
        self.assertIn("XTraceGenerateKeyArgsJson", native_patch)
        self.assertIn("XTraceExportKeyArgsJson", native_patch)
        self.assertIn("XTraceDeriveBitsArgsJson", native_patch)
        self.assertIn("XTraceDeriveKeyArgsJson", native_patch)
        self.assertIn("XTraceWrapKeyArgsJson", native_patch)
        self.assertIn("XTraceUnwrapKeyArgsJson", native_patch)
        self.assertIn("SetXTraceOperation", native_patch)
        self.assertIn("xtrace_api_", native_patch)
        self.assertIn("operation_id", native_patch)
        self.assertIn("result_ref", native_patch)
        self.assertIn("result_hex", native_patch)
        self.assertIn("result_json", native_patch)
        self.assertIn("key_ref", native_patch)
        self.assertIn('"public_", result->publicKey()', native_patch)
        self.assertIn('"private_", result->privateKey()', native_patch)
        self.assertIn('"wrapping_", wrapping_key', native_patch)
        self.assertIn('"unwrapping_", unwrapping_key', native_patch)
        self.assertIn("wrapped_key_hex", native_patch)
        self.assertIn("input_ref", native_patch)
        self.assertIn("input_hex", native_patch)
        self.assertIn("signature_ref", native_patch)
        self.assertIn("signature_hex", native_patch)
        self.assertIn("XTraceBooleanResultArgsJson", native_patch)
        self.assertIn("key_data_hex", native_patch)
        self.assertIn("XTraceBase64ArgsJson", native_patch)
        self.assertIn("XTraceBytesHexJson", native_patch)
        self.assertIn("XTraceBytesHashRefJson", native_patch)
        self.assertIn('\\"input_hex\\"', native_patch)
        self.assertIn('\\"result_hex\\"', native_patch)
        self.assertIn('\\"input_ref\\"', native_patch)
        self.assertIn('\\"written_hex\\"', native_patch)
        self.assertIn('\\"written_ref\\"', native_patch)
        self.assertIn('\\"destination_hex\\"', native_patch)
        self.assertIn('\\"destination_ref\\"', native_patch)
        self.assertIn("XTraceRandomValuesResultArgsJson", native_patch)
        self.assertIn("XTraceRandomUuidArgsJson", native_patch)
        self.assertIn('\\"random_source\\":\\"Crypto.getRandomValues\\"', native_patch)
        self.assertIn('\\"random_source\\":\\"Crypto.randomUUID\\"', native_patch)
        self.assertIn('\\"typed_array_type\\"', native_patch)
        self.assertIn('\\"array_buffer_id\\"', native_patch)
        self.assertIn('\\"typed_array_id\\"', native_patch)
        self.assertIn('\\"byte_offset\\"', native_patch)
        self.assertIn('\\"result_hex\\"', native_patch)
        self.assertIn('\\"result_ref\\"', native_patch)
        self.assertIn('LogEvent("reverse", "return", "Crypto.getRandomValues"', native_patch)

    def test_v8_patch_exports_typed_array_byte_material_hooks(self):
        v8_patch = (
            ROOT
            / "patches"
            / "0002-xtrace-v8-vmp-hooks.patch"
        ).read_text(encoding="utf-8")

        self.assertIn("StringConstant('TypedArray.subarray')", v8_patch)
        self.assertIn("StringConstant('TypedArray.set')", v8_patch)
        self.assertIn("StringConstant('sequence_subarray')", v8_patch)
        self.assertIn("StringConstant('sequence_set')", v8_patch)
        self.assertIn("TypedArray.copyWithin", v8_patch)
        self.assertIn("TypedArray.fill", v8_patch)
        self.assertIn("TypedArray.reverse", v8_patch)
        self.assertIn("StringConstant('TypedArray.sort')", v8_patch)
        self.assertIn("StringConstant('sequence_sort')", v8_patch)
        self.assertIn("StringConstant('Math.random')", v8_patch)
        self.assertIn("StringConstant('math_random')", v8_patch)
        self.assertIn('"random_source"', v8_patch)
        self.assertIn('"result_ref"', v8_patch)
        self.assertIn('"xtrace:vmp-runtime:"', v8_patch)
        self.assertIn('"TypedArray.includes"', v8_patch)
        self.assertIn('"TypedArray.indexOf"', v8_patch)
        self.assertIn('"TypedArray.lastIndexOf"', v8_patch)
        self.assertIn("LogXTraceTypedArraySearch", v8_patch)
        self.assertIn("StringConstant('TypedArray.find')", v8_patch)
        self.assertIn("StringConstant('TypedArray.findIndex')", v8_patch)
        self.assertIn("StringConstant('TypedArray.findLast')", v8_patch)
        self.assertIn("StringConstant('TypedArray.findLastIndex')", v8_patch)
        self.assertIn("StringConstant('typed_array_find')", v8_patch)
        self.assertIn("StringConstant('TypedArray.reduce')", v8_patch)
        self.assertIn("StringConstant('TypedArray.reduceRight')", v8_patch)
        self.assertIn("StringConstant('typed_array_reduce')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.flat')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.flatMap')", v8_patch)
        self.assertIn("StringConstant('array_flat')", v8_patch)
        self.assertIn("StringConstant('array_flat_map')", v8_patch)
        self.assertIn('StringConstant("Object.assign")', v8_patch)
        self.assertIn('StringConstant("object_assign_source")', v8_patch)
        self.assertIn('StringConstant("object_assign")', v8_patch)
        self.assertIn("StringConstant('Object.prototype.toString')", v8_patch)
        self.assertIn("StringConstant('object_to_string')", v8_patch)
        self.assertIn("StringConstant('Array.isArray')", v8_patch)
        self.assertIn("StringConstant('array_is_array')", v8_patch)
        self.assertIn('StringConstant("Object.is")', v8_patch)
        self.assertIn('StringConstant("same_value")', v8_patch)
        self.assertIn('StringConstant("Object.hasOwn")', v8_patch)
        self.assertIn('StringConstant("Object.prototype.hasOwnProperty")', v8_patch)
        self.assertIn('StringConstant("property_has_own")', v8_patch)
        self.assertIn('shape_string == "property_has_own"', v8_patch)
        self.assertIn('StringConstant("Object.create")', v8_patch)
        self.assertIn('StringConstant("object_create")', v8_patch)
        self.assertIn('shape_string == "object_create"', v8_patch)
        self.assertIn('"prototype_ref"', v8_patch)
        self.assertIn('"descriptors_ref"', v8_patch)
        self.assertIn("StringConstant('Object.getPrototypeOf')", v8_patch)
        self.assertIn("StringConstant('Object.setPrototypeOf')", v8_patch)
        self.assertIn("StringConstant('Reflect.getPrototypeOf')", v8_patch)
        self.assertIn("StringConstant('Reflect.setPrototypeOf')", v8_patch)
        self.assertIn("StringConstant('prototype_chain')", v8_patch)
        self.assertIn('shape_string == "prototype_chain"', v8_patch)
        self.assertIn("StringConstant('Object.preventExtensions')", v8_patch)
        self.assertIn("StringConstant('Object.isExtensible')", v8_patch)
        self.assertIn("StringConstant('Reflect.preventExtensions')", v8_patch)
        self.assertIn("StringConstant('Reflect.isExtensible')", v8_patch)
        self.assertIn("StringConstant('object_integrity')", v8_patch)
        self.assertIn('shape_string == "object_integrity"', v8_patch)
        self.assertIn('"xtrace:vmp-runtime:Object.freeze:"', v8_patch)
        self.assertIn('"xtrace:vmp-runtime:Object.seal:"', v8_patch)
        self.assertIn('"xtrace:vmp-runtime:Object.isFrozen:"', v8_patch)
        self.assertIn('"xtrace:vmp-runtime:Object.isSealed:"', v8_patch)
        self.assertIn('StringConstant("Object.getOwnPropertyDescriptor")', v8_patch)
        self.assertIn('"xtrace:vmp-runtime:Object.getOwnPropertyDescriptors:"', v8_patch)
        self.assertIn('shape_string == "property_descriptor"', v8_patch)
        self.assertIn('"key_ref"', v8_patch)
        self.assertIn('"descriptor_key_refs"', v8_patch)
        self.assertIn('LogXTracePropertyDefine(isolate, "Object.defineProperty"', v8_patch)
        self.assertIn('"xtrace:vmp-runtime:Object.defineProperties:"', v8_patch)
        self.assertIn("LogXTraceObjectDefineProperties", v8_patch)
        self.assertIn('"xtrace:vmp-runtime:Reflect.defineProperty:"', v8_patch)
        self.assertIn('"descriptor_kind"', v8_patch)
        self.assertIn('"descriptor_value_ref"', v8_patch)
        self.assertIn('"descriptor_key_refs"', v8_patch)
        self.assertIn('"descriptor_kinds"', v8_patch)
        self.assertIn('"descriptor_value_refs"', v8_patch)
        self.assertIn('StringConstant("Object.values")', v8_patch)
        self.assertIn('StringConstant("Object.entries")', v8_patch)
        self.assertIn('StringConstant("object_values")', v8_patch)
        self.assertIn('StringConstant("object_entries")', v8_patch)
        self.assertIn("StringConstant('Reflect.deleteProperty')", v8_patch)
        self.assertIn("StringConstant('property_delete')", v8_patch)
        self.assertIn('shape_string == "property_delete"', v8_patch)
        self.assertIn('"xtrace:vmp-runtime:Reflect.set:"', v8_patch)
        self.assertIn('"xtrace:vmp-runtime:Object.prototype.propertyIsEnumerable:"', v8_patch)
        self.assertIn('"property_set"', v8_patch)
        self.assertIn('"property_enumerable"', v8_patch)
        self.assertIn('shape_string == "property_set"', v8_patch)
        self.assertIn('shape_string == "property_enumerable"', v8_patch)
        self.assertIn("StringConstant('TypedArray.filter')", v8_patch)
        self.assertIn("StringConstant('typed_array_filter')", v8_patch)
        self.assertIn("StringConstant('TypedArray.every')", v8_patch)
        self.assertIn("StringConstant('TypedArray.some')", v8_patch)
        self.assertIn("StringConstant('TypedArray.forEach')", v8_patch)
        self.assertIn("StringConstant('typed_array_iteration')", v8_patch)
        self.assertIn("target_index", v8_patch)
        self.assertIn("search_ref", v8_patch)
        self.assertIn("from_index_ref", v8_patch)
        self.assertIn("fill_value_ref", v8_patch)
        self.assertIn("comparefn_type", v8_patch)
        self.assertIn("element_count", v8_patch)
        self.assertIn("source_typed_array_id", v8_patch)
        self.assertIn("source_array_buffer_id", v8_patch)
        self.assertIn("result_typed_array_id", v8_patch)
        self.assertIn("result_array_buffer_id", v8_patch)
        self.assertIn('"NaN"', v8_patch)
        self.assertIn('"Infinity"', v8_patch)
        self.assertIn('"-Infinity"', v8_patch)
        self.assertIn('"number:NaN"', v8_patch)
        self.assertIn('"number:Infinity"', v8_patch)
        self.assertIn('"number:-Infinity"', v8_patch)
        self.assertIn('"Reflect.construct"', v8_patch)
        self.assertIn('"construct_dispatch"', v8_patch)
        self.assertIn('shape_string == "construct_dispatch"', v8_patch)
        self.assertIn('"new_target_ref"', v8_patch)

    def test_v8_patch_exports_array_table_mutation_hooks(self):
        v8_patch = (
            ROOT
            / "patches"
            / "0002-xtrace-v8-vmp-hooks.patch"
        ).read_text(encoding="utf-8")

        self.assertIn("StringConstant('Array.prototype.shift')", v8_patch)
        self.assertIn("StringConstant('array_shift')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.splice')", v8_patch)
        self.assertIn("StringConstant('array_splice')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.at')", v8_patch)
        self.assertIn('StringConstant("Array.prototype.indexOf")', v8_patch)
        self.assertIn('StringConstant("Array.prototype.includes")', v8_patch)
        self.assertIn("StringConstant('Array.prototype.lastIndexOf')", v8_patch)
        self.assertIn('StringConstant("array_search")', v8_patch)
        self.assertIn("StringConstant('Array.prototype.find')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.findIndex')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.findLast')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.findLastIndex')", v8_patch)
        self.assertIn("StringConstant('array_find')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.reduce')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.reduceRight')", v8_patch)
        self.assertIn("StringConstant('array_reduce')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.map')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.filter')", v8_patch)
        self.assertIn("StringConstant('array_transform')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.every')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.some')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.forEach')", v8_patch)
        self.assertIn("StringConstant('array_iteration')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.reverse')", v8_patch)
        self.assertIn("StringConstant('array_reverse')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.sort')", v8_patch)
        self.assertIn("StringConstant('array_sort')", v8_patch)
        self.assertIn("StringConstant('Array.prototype.copyWithin')", v8_patch)
        self.assertIn("StringConstant('array_copy_within')", v8_patch)
        self.assertIn("xtrace:vmp-runtime:Array.prototype.fill", v8_patch)
        self.assertIn('"shape":"array_fill"', v8_patch)
        self.assertIn('StringConstant("Array.prototype.pop")', v8_patch)
        self.assertIn('StringConstant("array_pop")', v8_patch)
        self.assertIn("StringConstant('Array.prototype.unshift')", v8_patch)
        self.assertIn("StringConstant('array_unshift')", v8_patch)
        self.assertIn("xtrace:vmp-runtime:Array.prototype.unshift", v8_patch)
        self.assertIn("length_before", v8_patch)
        self.assertIn("length_after", v8_patch)
        self.assertIn("result_ref", v8_patch)

    def test_v8_patch_exports_string_transform_material_hooks(self):
        v8_patch = (
            ROOT
            / "patches"
            / "0002-xtrace-v8-vmp-hooks.patch"
        ).read_text(encoding="utf-8")

        self.assertIn('StringConstant("String.prototype.replace")', v8_patch)
        self.assertIn('StringConstant("string_replace")', v8_patch)
        self.assertIn("StringConstant('String.prototype.replaceAll')", v8_patch)
        self.assertIn("StringConstant('string_replace_all')", v8_patch)
        self.assertIn('StringConstant("String.prototype.split")', v8_patch)
        self.assertIn('StringConstant("string_split")', v8_patch)
        self.assertIn('StringConstant("String.prototype.toLowerCase")', v8_patch)
        self.assertIn("String.prototype.toUpperCase", v8_patch)
        self.assertIn('StringConstant("string_case")', v8_patch)
        self.assertIn("StringConstant('String.prototype.charAt')", v8_patch)
        self.assertIn("StringConstant('String.prototype.codePointAt')", v8_patch)
        self.assertIn("StringConstant('string_code_point_at')", v8_patch)
        self.assertIn(
            "StringConstant('string_char_code_at'), string, position, result",
            v8_patch,
        )
        self.assertIn("StringConstant('string_char_at')", v8_patch)
        self.assertIn("StringConstant('String.prototype.concat')", v8_patch)
        self.assertIn("StringConstant('string_concat')", v8_patch)
        self.assertIn("StringConstant('String.prototype.substr')", v8_patch)
        self.assertIn("StringConstant('string_substr')", v8_patch)
        self.assertIn("StringConstant('String.prototype.padStart')", v8_patch)
        self.assertIn("StringConstant('String.prototype.padEnd')", v8_patch)
        self.assertIn("StringConstant('string_pad')", v8_patch)
        self.assertIn("StringConstant('String.prototype.repeat')", v8_patch)
        self.assertIn("StringConstant('string_repeat')", v8_patch)
        self.assertIn("StringConstant('String.prototype.at')", v8_patch)
        self.assertIn("StringConstant('string_at')", v8_patch)
        self.assertIn('shape_string == "string_at"', v8_patch)
        self.assertIn("StringConstant('String.prototype.startsWith')", v8_patch)
        self.assertIn("StringConstant('string_starts_with')", v8_patch)
        self.assertIn("StringConstant('String.prototype.endsWith')", v8_patch)
        self.assertIn("StringConstant('string_ends_with')", v8_patch)
        self.assertIn("LogXTraceStringLastIndexOf", v8_patch)
        self.assertIn("xtrace:vmp-runtime:String.prototype.lastIndexOf", v8_patch)
        self.assertIn("'String.prototype.trim'", v8_patch)
        self.assertIn("'String.prototype.trimStart'", v8_patch)
        self.assertIn("'String.prototype.trimEnd'", v8_patch)
        self.assertIn("StringConstant(apiName)", v8_patch)
        self.assertIn("StringConstant('string_trim')", v8_patch)
        self.assertIn("StringConstant('Number.prototype.toString')", v8_patch)
        self.assertIn("StringConstant('number_to_string')", v8_patch)
        self.assertIn("StringConstant('Number.parseInt')", v8_patch)
        self.assertIn("StringConstant('number_parse_int')", v8_patch)
        self.assertIn("StringConstant('Number.parseFloat')", v8_patch)
        self.assertIn("StringConstant('number_parse_float')", v8_patch)
        self.assertIn('shape_string == "number_parse_int"', v8_patch)
        self.assertIn('shape_string == "number_parse_float"', v8_patch)
        self.assertIn("StringConstant('RegExp.prototype.@@match')", v8_patch)
        self.assertIn("StringConstant('regexp_match')", v8_patch)
        self.assertIn("'String.prototype.match', 'string_match'", v8_patch)
        self.assertIn("'String.prototype.search', 'string_search'", v8_patch)
        self.assertIn("StringConstant('RegExp.prototype.@@replace')", v8_patch)
        self.assertIn("StringConstant('regexp_replace')", v8_patch)
        self.assertIn("StringConstant('RegExp.prototype.@@split')", v8_patch)
        self.assertIn("StringConstant('regexp_split')", v8_patch)
        self.assertIn("StringConstant('RegExp.prototype.@@search')", v8_patch)
        self.assertIn("StringConstant('regexp_search')", v8_patch)
        self.assertIn(
            'shape == "regexp_exec" || shape == "regexp_search" ||\n'
            '+             shape == "regexp_match" || shape == "regexp_split" ||\n'
            '+             shape == "regexp_replace" ||\n'
            '+             shape == "regexp_match_all_create" ||\n'
            '+             shape == "string_search" ||\n'
            '+             shape == "string_match"',
            v8_patch,
        )
        self.assertIn("xtrace:vmp-runtime:BigInt.prototype.toString", v8_patch)
        self.assertIn("bigint_to_string", v8_patch)
        self.assertIn("LogXTraceBigIntToString", v8_patch)
        self.assertIn("LogXTraceStringCase", v8_patch)
        self.assertIn("case_direction", v8_patch)
        self.assertIn("lower", v8_patch)
        self.assertIn("upper", v8_patch)
        self.assertIn("subject_string", v8_patch)
        self.assertIn("separator", v8_patch)
        self.assertIn("search_string", v8_patch)
        self.assertIn("AppendStringMaterialJson", v8_patch)
        for field in ("subject", "first_arg", "fill", "search", "replace", "separator"):
            self.assertIn(
                f'AppendStringMaterialJson(args, &has_field, "{field}", ',
                v8_patch,
            )
        starts_with_start = v8_patch.index('shape_string == "string_starts_with"')
        starts_with_end = v8_patch.index(
            '+  } else if (shape_string == "string_ends_with")',
            starts_with_start,
        )
        starts_with_block = v8_patch[starts_with_start:starts_with_end]
        self.assertIn(
            '+    AppendStringMaterialJson(args, &has_field, "subject", subject);',
            starts_with_block,
        )
        self.assertIn(
            '+    AppendStringMaterialJson(args, &has_field, "search", value1);',
            starts_with_block,
        )
        self.assertIn(
            '+    AppendFieldPrefix(args, &has_field, "position");',
            starts_with_block,
        )
        self.assertIn('+    args.append(JsonValue(value3));', starts_with_block)
        ends_with_start = v8_patch.index('shape_string == "string_ends_with"')
        ends_with_end = v8_patch.index(
            '+  } else if (shape_string == "string_replace" ||',
            ends_with_start,
        )
        ends_with_block = v8_patch[ends_with_start:ends_with_end]
        self.assertIn(
            '+    AppendStringMaterialJson(args, &has_field, "subject", subject);',
            ends_with_block,
        )
        self.assertIn(
            '+    AppendStringMaterialJson(args, &has_field, "search", value1);',
            ends_with_block,
        )
        self.assertIn(
            '+    AppendFieldPrefix(args, &has_field, "end_position");',
            ends_with_block,
        )
        self.assertIn('+    args.append(JsonValue(value3));', ends_with_block)
        trim_start = v8_patch.index('shape_string == "string_trim"')
        trim_end = v8_patch.index(
            '+  } else if (shape_string == "string_replace" ||',
            trim_start,
        )
        trim_block = v8_patch[trim_start:trim_end]
        self.assertIn(
            '+    AppendStringMaterialJson(args, &has_field, "subject", subject);',
            trim_block,
        )
        self.assertIn(
            '+    AppendFieldPrefix(args, &has_field, "trim_mode");',
            trim_block,
        )
        self.assertIn(
            '+    AppendStringResultJson(args, &has_field, value2);',
            trim_block,
        )
        self.assertIn(
            '+    AppendValueRefJson(isolate, args, &has_field, "result_ref", value2);',
            trim_block,
        )
        replace_all_start = v8_patch.index('shape_string == "string_replace_all"')
        replace_all_end = v8_patch.index(
            '+  } else if (shape_string == "string_split")',
            replace_all_start,
        )
        replace_all_block = v8_patch[replace_all_start:replace_all_end]
        self.assertIn(
            '+    AppendStringMaterialJson(args, &has_field, "subject", subject);',
            replace_all_block,
        )
        self.assertIn(
            '+    AppendStringMaterialJson(args, &has_field, "search", value1);',
            replace_all_block,
        )
        self.assertIn(
            '+    AppendStringMaterialJson(args, &has_field, "replace", value2);',
            replace_all_block,
        )
        self.assertIn(
            '+    AppendStringResultJson(args, &has_field, value3);',
            replace_all_block,
        )
        search_start = v8_patch.index('+  } else if (shape_string == "regexp_search")')
        search_end = v8_patch.index(
            '+  } else if (shape_string == "regexp_exec")',
            search_start,
        )
        search_block = v8_patch[search_start:search_end]
        self.assertIn(
            '+    AppendStringMaterialJson(args, &has_field, "input", value1);',
            search_block,
        )
        self.assertIn(
            '+    AppendValueRefJson(isolate, args, &has_field, "input_ref", value1);',
            search_block,
        )
        self.assertIn(
            '+    AppendValueRefJson(isolate, args, &has_field, "result_ref", value2);',
            search_block,
        )
        split_start = v8_patch.index('+  } else if (shape_string == "regexp_split")')
        split_end = v8_patch.index(
            '+  } else if (shape_string == "regexp_match")',
            split_start,
        )
        split_block = v8_patch[split_start:split_end]
        self.assertIn(
            '+    AppendArrayElementsJson(isolate, args, &has_field, value2,',
            split_block,
        )
        self.assertIn('"result_elements"', split_block)
        self.assertIn('"result_element_refs"', split_block)
        self.assertIn('"result_elements_complete"', split_block)
        replace_start = v8_patch.index('+  } else if (shape_string == "regexp_replace")')
        replace_end = v8_patch.index(
            '+  } else if (shape_string == "regexp_split")',
            replace_start,
        )
        replace_block = v8_patch[replace_start:replace_end]
        self.assertIn(
            '+    AppendStringMaterialJson(args, &has_field, "input", value1);',
            replace_block,
        )
        self.assertIn(
            '+    AppendStringMaterialJson(args, &has_field, "replace", value2);',
            replace_block,
        )
        self.assertIn(
            '+    AppendObjectTypeJson(args, &has_field, "replace_type", value2);',
            replace_block,
        )
        self.assertIn(
            '+    AppendStringResultJson(args, &has_field, value3);',
            replace_block,
        )
        self.assertIn(
            '+    AppendValueRefJson(isolate, args, &has_field, "result_ref", value3);',
            replace_block,
        )
        match_start = v8_patch.index('+  } else if (shape_string == "regexp_match")')
        match_end = v8_patch.index(
            '+  } else if (shape_string == "regexp_search")',
            match_start,
        )
        match_block = v8_patch[match_start:match_end]
        self.assertIn(
            '+    AppendObjectTypeJson(args, &has_field, "result_type", value2);',
            match_block,
        )
        self.assertIn(
            '+    AppendRegExpResultArrayJson(isolate, args, &has_field, value2);',
            match_block,
        )
        regexp_start = v8_patch.index('+  } else if (shape_string == "regexp_exec")')
        regexp_end = v8_patch.index(
            '+  } else if (shape_string == "dynamic_dispatch")',
            regexp_start,
        )
        regexp_block = v8_patch[regexp_start:regexp_end]
        self.assertIn(
            '+    AppendStringMaterialJson(args, &has_field, "input", value1);',
            regexp_block,
        )
        self.assertIn(
            '+    AppendValueRefJson(isolate, args, &has_field, "input_ref", value1);',
            regexp_block,
        )
        self.assertIn(
            '+    AppendObjectTypeJson(args, &has_field, "result_type", value2);',
            regexp_block,
        )
        self.assertIn(
            '+    AppendValueRefJson(isolate, args, &has_field, "result_ref", value2);',
            regexp_block,
        )
        self.assertIn(
            '+    AppendObjectIdJson(isolate, args, &has_field, "result_array_id", value2);',
            regexp_block,
        )
        self.assertIn(
            '+    AppendRegExpResultArrayJson(isolate, args, &has_field, value2);',
            regexp_block,
        )
        self.assertIn("separator_ref", v8_patch)
        self.assertIn("result_array_id", v8_patch)
        self.assertIn("result_ref", v8_patch)

    def test_v8_patch_exports_signed_data_view_byte_hooks(self):
        v8_patch = (
            ROOT
            / "patches"
            / "0002-xtrace-v8-vmp-hooks.patch"
        ).read_text(encoding="utf-8")

        self.assertIn("StringConstant('DataView.getInt8')", v8_patch)
        self.assertIn("StringConstant('DataView.getInt16')", v8_patch)
        self.assertIn("StringConstant('DataView.setInt8')", v8_patch)
        self.assertIn("StringConstant('DataView.setInt16')", v8_patch)

    def test_v8_patch_exports_bigint_data_view_byte_hooks(self):
        v8_patch = (
            ROOT
            / "patches"
            / "0002-xtrace-v8-vmp-hooks.patch"
        ).read_text(encoding="utf-8")

        self.assertIn("StringConstant('DataView.getBigUint64')", v8_patch)
        self.assertIn("StringConstant('DataView.getBigInt64')", v8_patch)
        self.assertIn("StringConstant('DataView.setBigUint64')", v8_patch)
        self.assertIn("StringConstant('DataView.setBigInt64')", v8_patch)
        self.assertIn("bigint:int64:", v8_patch)
        self.assertIn("bigint:uint64:", v8_patch)

    def test_v8_patch_exports_float_data_view_byte_hooks(self):
        v8_patch = (
            ROOT
            / "patches"
            / "0002-xtrace-v8-vmp-hooks.patch"
        ).read_text(encoding="utf-8")

        self.assertIn("StringConstant('DataView.getFloat16')", v8_patch)
        self.assertIn("StringConstant('DataView.getFloat32')", v8_patch)
        self.assertIn("StringConstant('DataView.getFloat64')", v8_patch)
        self.assertIn("StringConstant('DataView.setFloat16')", v8_patch)
        self.assertIn("StringConstant('DataView.setFloat32')", v8_patch)
        self.assertIn("StringConstant('DataView.setFloat64')", v8_patch)

    def test_xtrace_v8_runtime_events_skip_js_stack_capture(self):
        logger_header = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "platform"
            / "xtrace"
            / "xtrace_logger.h"
        ).read_text(encoding="utf-8")
        logger_cc = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "platform"
            / "xtrace"
            / "xtrace_logger.cc"
        ).read_text(encoding="utf-8")
        v8_initializer = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "bindings"
            / "core"
            / "v8"
            / "v8_initializer.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("LogEventNoStack", logger_header)
        self.assertIn("bool capture_stack", logger_cc)
        self.assertIn('capture_stack ? CaptureJavaScriptStack() : "[]"', logger_cc)
        self.assertIn(
            'XTraceLogger::LogEventNoStack("reverse", phase, api.c_str(), args_json)',
            v8_initializer,
        )

    def test_xtrace_async_event_flow_hooks_are_wired(self):
        event_target = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "dom"
            / "events"
            / "event_target.cc"
        ).read_text(encoding="utf-8")
        universal_global_scope = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "frame"
            / "universal_global_scope.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("platform/xtrace/xtrace_logger.h", event_target)
        self.assertIn('"EventTarget.addEventListener"', event_target)
        self.assertIn('"EventTarget.removeEventListener"', event_target)
        self.assertIn('"EventTarget.dispatchEvent"', event_target)
        self.assertIn('"EventTarget.listener.invoke"', event_target)
        self.assertIn("target_interface", event_target)
        self.assertIn("event_type", event_target)
        self.assertIn("listener_id", event_target)
        self.assertIn("listener_count", event_target)
        self.assertIn("capture", event_target)
        self.assertIn("once", event_target)
        self.assertIn("passive", event_target)
        self.assertIn("is_trusted", event_target)
        self.assertIn("event_phase", event_target)
        self.assertIn('\\"context_url\\":%s', event_target)
        self.assertIn('\\"context_url_ref\\":%s', event_target)
        self.assertIn("XTraceLogger::LogEventNoStack", event_target)

        self.assertIn('"queueMicrotask"', universal_global_scope)
        self.assertIn("callback_id", universal_global_scope)
        self.assertIn("context_url_ref", universal_global_scope)
        self.assertIn("XTraceLogger::LogEvent", universal_global_scope)

    @requires_chromium_tree
    def test_xtrace_promise_async_hooks_are_wired(self):
        v8_root = ROOT / "chromium" / "src" / "v8"
        promise_then = (
            v8_root / "src" / "builtins" / "promise-then.tq"
        ).read_text(encoding="utf-8")
        promise_constructor = (
            v8_root / "src" / "builtins" / "promise-constructor.tq"
        ).read_text(encoding="utf-8")
        promise_finally = (
            v8_root / "src" / "builtins" / "promise-finally.tq"
        ).read_text(encoding="utf-8")
        promise_resolve = (
            v8_root / "src" / "builtins" / "promise-resolve.tq"
        ).read_text(encoding="utf-8")
        promise_abstract_operations = (
            v8_root / "src" / "builtins" / "promise-abstract-operations.tq"
        ).read_text(encoding="utf-8")
        promise_all = (
            v8_root / "src" / "builtins" / "promise-all.tq"
        ).read_text(encoding="utf-8")
        promise_race = (
            v8_root / "src" / "builtins" / "promise-race.tq"
        ).read_text(encoding="utf-8")
        promise_any = (
            v8_root / "src" / "builtins" / "promise-any.tq"
        ).read_text(encoding="utf-8")
        promise_try = (
            v8_root / "src" / "builtins" / "promise-try.tq"
        ).read_text(encoding="utf-8")
        promise_with_resolvers = (
            v8_root / "src" / "builtins" / "promise-withresolvers.tq"
        ).read_text(encoding="utf-8")
        array_from_async = (
            v8_root / "src" / "builtins" / "array-from-async.tq"
        ).read_text(encoding="utf-8")
        async_function_gen = (
            v8_root / "src" / "builtins" / "builtins-async-function-gen.cc"
        ).read_text(encoding="utf-8")
        microtask_queue_gen = (
            v8_root / "src" / "builtins" / "builtins-microtask-queue-gen.cc"
        ).read_text(encoding="utf-8")
        runtime_typedarray = (
            v8_root / "src" / "runtime" / "runtime-typedarray.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("Promise.prototype.then", promise_then)
        self.assertIn("Promise.prototype.catch", promise_constructor)
        self.assertIn("Promise.prototype.finally", promise_finally)
        for source in (promise_then, promise_constructor, promise_finally):
            self.assertIn("XTraceVmpRuntime(", source)
            self.assertIn("StringConstant('promise_chain')", source)

        self.assertIn('shape_string == "promise_chain"', runtime_typedarray)
        self.assertIn("promise_id", runtime_typedarray)
        self.assertIn("result_promise_id", runtime_typedarray)
        self.assertIn("on_fulfilled_id", runtime_typedarray)
        self.assertIn("on_rejected_id", runtime_typedarray)
        self.assertIn("handler_role", runtime_typedarray)
        self.assertIn("has_on_fulfilled", runtime_typedarray)
        self.assertIn("has_on_rejected", runtime_typedarray)
        self.assertIn("promise_ref", runtime_typedarray)
        self.assertIn("result_promise_ref", runtime_typedarray)
        self.assertIn("StringConstant('Promise.resolve')", promise_resolve)
        self.assertIn("StringConstant('promise_static_resolve')", promise_resolve)
        self.assertIn("XTraceVmpRuntime(", promise_resolve)
        self.assertIn("StringConstant('Promise.reject')", promise_abstract_operations)
        self.assertIn(
            "StringConstant('promise_static_reject')",
            promise_abstract_operations,
        )
        self.assertIn("XTraceVmpRuntime(", promise_abstract_operations)
        self.assertIn('"promise_static_resolve"', runtime_typedarray)
        self.assertIn('"promise_static_reject"', runtime_typedarray)
        promise_static_resolve = runtime_typedarray.index(
            'shape_string == "promise_static_resolve"'
        )
        promise_static_reject = runtime_typedarray.index(
            'shape_string == "promise_static_reject"'
        )
        promise_static_resolve_block = runtime_typedarray[
            promise_static_resolve:promise_static_reject
        ]
        promise_static_reject_end = runtime_typedarray.index(
            'shape_string == "promise_combinator"',
            promise_static_reject,
        )
        promise_static_reject_block = runtime_typedarray[
            promise_static_reject:promise_static_reject_end
        ]
        for field in [
            '"input_ref"',
            '"result_promise_ref"',
            '"result_promise_id"',
        ]:
            self.assertIn(field, promise_static_resolve_block)
        for field in [
            '"reason_ref"',
            '"result_promise_ref"',
            '"result_promise_id"',
        ]:
            self.assertIn(field, promise_static_reject_block)
        self.assertIn("StringConstant('Promise.all')", promise_all)
        self.assertIn("StringConstant('Promise.allSettled')", promise_all)
        self.assertIn("StringConstant('Promise.race')", promise_race)
        self.assertIn("StringConstant('Promise.any')", promise_any)
        for source in (promise_all, promise_race, promise_any):
            self.assertIn("XTraceVmpRuntime(", source)
            self.assertIn("StringConstant('promise_combinator')", source)
        self.assertIn('"promise_combinator"', runtime_typedarray)
        promise_combinator = runtime_typedarray.index(
            'shape_string == "promise_combinator"'
        )
        promise_combinator_end = runtime_typedarray.index(
            'shape_string == "promise_chain"',
            promise_combinator,
        )
        promise_combinator_block = runtime_typedarray[
            promise_combinator:promise_combinator_end
        ]
        for field in [
            '"iterable_ref"',
            '"iterable_element_refs"',
            '"iterable_elements_complete"',
            '"constructor_ref"',
            '"result_promise_ref"',
            '"result_promise_id"',
            '"combinator"',
        ]:
            self.assertIn(field, promise_combinator_block)
        self.assertIn("StringConstant('Promise.try')", promise_try)
        self.assertIn("StringConstant('promise_try')", promise_try)
        self.assertIn("XTraceVmpRuntime(", promise_try)
        self.assertIn(
            "StringConstant('Promise.withResolvers')",
            promise_with_resolvers,
        )
        self.assertIn(
            "StringConstant('promise_with_resolvers')",
            promise_with_resolvers,
        )
        self.assertIn("XTraceVmpRuntime(", promise_with_resolvers)
        self.assertIn('"promise_try"', runtime_typedarray)
        self.assertIn('"promise_with_resolvers"', runtime_typedarray)
        promise_try_shape = runtime_typedarray.index(
            'shape_string == "promise_try"'
        )
        promise_with_resolvers_shape = runtime_typedarray.index(
            'shape_string == "promise_with_resolvers"'
        )
        promise_try_block = runtime_typedarray[
            promise_try_shape:promise_with_resolvers_shape
        ]
        promise_with_resolvers_end = runtime_typedarray.index(
            'shape_string == "promise_chain"',
            promise_with_resolvers_shape,
        )
        promise_with_resolvers_block = runtime_typedarray[
            promise_with_resolvers_shape:promise_with_resolvers_end
        ]
        for field in [
            '"callback_ref"',
            '"argument_refs"',
            '"result_promise_ref"',
            '"result_promise_id"',
            '"completion_state"',
            '"completion_ref"',
        ]:
            self.assertIn(field, promise_try_block)
        for field in [
            '"promise_ref"',
            '"resolve_ref"',
            '"reject_ref"',
            '"result_ref"',
        ]:
            self.assertIn(field, promise_with_resolvers_block)
        self.assertIn("StringConstant('Array.fromAsync')", array_from_async)
        self.assertIn("StringConstant('array_from_async_start')", array_from_async)
        self.assertIn("StringConstant('array_from_async_resolve')", array_from_async)
        self.assertIn("XTraceVmpRuntime(", array_from_async)
        self.assertIn('"array_from_async_start"', runtime_typedarray)
        self.assertIn('"array_from_async_resolve"', runtime_typedarray)
        from_async_start = runtime_typedarray.index(
            'shape_string == "array_from_async_start"'
        )
        from_async_resolve = runtime_typedarray.index(
            'shape_string == "array_from_async_resolve"'
        )
        from_async_start_block = runtime_typedarray[
            from_async_start:from_async_resolve
        ]
        from_async_resolve_end = runtime_typedarray.index(
            'shape_string == "promise_chain"',
            from_async_resolve,
        )
        from_async_resolve_block = runtime_typedarray[
            from_async_resolve:from_async_resolve_end
        ]
        for field in [
            '"source_ref"',
            '"mapfn_ref"',
            '"this_arg_ref"',
            '"promise_ref"',
            '"async_mode"',
        ]:
            self.assertIn(field, from_async_start_block)
        for field in [
            '"promise_ref"',
            '"result_ref"',
            '"result_element_refs"',
            '"result_elements_complete"',
            '"async_mode"',
        ]:
            self.assertIn(field, from_async_resolve_block)
        for api_name in [
            "AsyncFunction.enter",
            "AsyncFunction.await",
            "AsyncFunction.resume",
            "AsyncFunction.resolve",
            "AsyncFunction.reject",
        ]:
            self.assertIn(f'StringConstant("{api_name}")', async_function_gen)
        self.assertIn('StringConstant("async_function_enter")', async_function_gen)
        self.assertIn('StringConstant("async_function_await")', async_function_gen)
        self.assertIn('StringConstant("async_function_resume")', async_function_gen)
        self.assertIn('StringConstant("async_function_resolve")', async_function_gen)
        self.assertIn('StringConstant("async_function_reject")', async_function_gen)
        self.assertIn("Runtime::kXTraceVmpRuntime", async_function_gen)
        self.assertIn('StringConstant("AsyncFunction.resume")', microtask_queue_gen)
        self.assertIn('StringConstant("async_function_resume")', microtask_queue_gen)
        self.assertIn("Runtime::kXTraceVmpRuntime", microtask_queue_gen)
        async_function_enter_start = runtime_typedarray.index(
            'shape_string == "async_function_enter"'
        )
        async_function_await_start = runtime_typedarray.index(
            'shape_string == "async_function_await"'
        )
        async_function_resume_start = runtime_typedarray.index(
            'shape_string == "async_function_resume"'
        )
        async_function_resolve_start = runtime_typedarray.index(
            'shape_string == "async_function_resolve"'
        )
        async_function_reject_start = runtime_typedarray.index(
            'shape_string == "async_function_reject"'
        )
        async_function_reject_end = runtime_typedarray.index(
            'shape_string == "promise_chain"',
            async_function_reject_start,
        )
        async_function_enter_block = runtime_typedarray[
            async_function_enter_start:async_function_await_start
        ]
        async_function_await_block = runtime_typedarray[
            async_function_await_start:async_function_resume_start
        ]
        async_function_resume_block = runtime_typedarray[
            async_function_resume_start:async_function_resolve_start
        ]
        async_function_resolve_block = runtime_typedarray[
            async_function_resolve_start:async_function_reject_start
        ]
        async_function_reject_block = runtime_typedarray[
            async_function_reject_start:async_function_reject_end
        ]
        for field in [
            '"async_function_ref"',
            '"closure_ref"',
            '"receiver_ref"',
            '"promise_ref"',
            '"async_state"',
        ]:
            self.assertIn(field, async_function_enter_block)
        for field in [
            '"async_function_ref"',
            '"await_value_ref"',
            '"outer_promise_ref"',
            '"await_mode"',
            '"async_state"',
        ]:
            self.assertIn(field, async_function_await_block)
        for field in [
            '"async_function_ref"',
            '"sent_value_ref"',
            '"outer_promise_ref"',
            '"resume_mode"',
            '"async_state"',
        ]:
            self.assertIn(field, async_function_resume_block)
        for field in [
            '"async_function_ref"',
            '"value_ref"',
            '"promise_ref"',
            '"settlement_state"',
            '"async_state"',
        ]:
            self.assertIn(field, async_function_resolve_block)
        for field in [
            '"async_function_ref"',
            '"reason_ref"',
            '"promise_ref"',
            '"settlement_state"',
            '"async_state"',
        ]:
            self.assertIn(field, async_function_reject_block)

    def test_xtrace_script_execution_hooks_are_wired(self):
        v8_script_runner = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "bindings"
            / "core"
            / "v8"
            / "v8_script_runner.cc"
        ).read_text(encoding="utf-8")
        dynamic_module_resolver = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "core"
            / "script"
            / "dynamic_module_resolver.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("platform/xtrace/xtrace_logger.h", v8_script_runner)
        self.assertIn('"ClassicScript.evaluate"', v8_script_runner)
        self.assertIn('"ModuleScript.evaluate"', v8_script_runner)
        self.assertIn("script_url_ref", v8_script_runner)
        self.assertIn('\\"script_id\\":%d', v8_script_runner)
        self.assertIn("script->ScriptId()", v8_script_runner)
        self.assertIn("context_origin", v8_script_runner)
        self.assertIn("XTraceContextOrigin", v8_script_runner)
        self.assertIn("GetSecurityOrigin()->ToString()", v8_script_runner)
        self.assertIn("source_length", v8_script_runner)
        self.assertIn("start_line", v8_script_runner)
        self.assertIn("start_column", v8_script_runner)
        self.assertIn("result_type", v8_script_runner)
        self.assertIn("import_phase", v8_script_runner)

        self.assertIn("platform/xtrace/xtrace_logger.h", dynamic_module_resolver)
        self.assertIn('"DynamicImport.resolve"', dynamic_module_resolver)
        self.assertIn('"DynamicImport.load"', dynamic_module_resolver)
        self.assertIn("specifier_ref", dynamic_module_resolver)
        self.assertIn("base_url_ref", dynamic_module_resolver)
        self.assertIn("resolved_url_ref", dynamic_module_resolver)
        self.assertIn("module_type", dynamic_module_resolver)
        self.assertIn("import_phase", dynamic_module_resolver)
        self.assertIn("promise_resolver_id", dynamic_module_resolver)

    def test_schema_v2_causality_switch_raii_and_v8_bridge_are_wired(self):
        logger = (
            ROOT / "chromium" / "src" / "third_party" / "blink" / "renderer"
            / "platform" / "xtrace" / "xtrace_logger.cc"
        ).read_text(encoding="utf-8")
        header = (
            ROOT / "chromium" / "src" / "third_party" / "blink" / "renderer"
            / "platform" / "xtrace" / "xtrace_logger.h"
        ).read_text(encoding="utf-8")
        runner = (
            ROOT / "chromium" / "src" / "third_party" / "blink" / "renderer"
            / "bindings" / "core" / "v8" / "v8_script_runner.cc"
        ).read_text(encoding="utf-8")
        initializer = (
            ROOT / "chromium" / "src" / "third_party" / "blink" / "renderer"
            / "bindings" / "core" / "v8" / "v8_initializer.cc"
        ).read_text(encoding="utf-8")
        browser = (ROOT / "chromium" / "src" / "chrome" / "browser"
                   / "chrome_content_browser_client.cc").read_text(encoding="utf-8")

        self.assertIn('"xtrace-causality"', logger)
        self.assertIn('"schema_version\\":2"', logger)
        self.assertIn("thread_local std::vector<XTraceActivation>", logger)
        self.assertIn("AppendCausalityFields", logger)
        self.assertIn("XTraceActivationScope", header)
        self.assertIn("XTraceActivationScope xtrace_activation", runner)
        self.assertIn("xtrace:vmp-runtime:", initializer)
        self.assertIn("LogEventNoStack(\"reverse\"", initializer)
        self.assertIn("AddXTraceExternalCausality", browser)

    def test_xtrace_classic_script_evaluate_links_asset_metadata(self):
        v8_script_runner = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "bindings"
            / "core"
            / "v8"
            / "v8_script_runner.cc"
        ).read_text(encoding="utf-8")
        xtrace_logger_header = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "platform"
            / "xtrace"
            / "xtrace_logger.h"
        ).read_text(encoding="utf-8")
        xtrace_logger = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "platform"
            / "xtrace"
            / "xtrace_logger.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("LogEventWithOptionalAsset", xtrace_logger_header)
        self.assertIn("LogEventWithContext", xtrace_logger_header)
        self.assertIn("LogEventNoStackWithContext", xtrace_logger_header)
        self.assertIn("LogEventWithOptionalAssetAndContext", xtrace_logger_header)
        self.assertIn("LogEventWithOptionalAsset", xtrace_logger)
        self.assertIn("frame_url_utf8", xtrace_logger)
        self.assertIn('line.append(",\\"frame_url\\":");', xtrace_logger)
        self.assertIn('line.append(",\\"origin\\":");', xtrace_logger)
        self.assertIn("BuildScriptAssetFieldsAndSend", xtrace_logger)
        self.assertIn("IsInternalScriptUrl(url)", xtrace_logger)
        self.assertIn("LogEventWithSequence", xtrace_logger)
        self.assertIn('line.append(",\\"session_seq\\":");', xtrace_logger)
        self.assertIn("XTraceClassicScriptAssetKind", v8_script_runner)
        self.assertIn("classic_script->SourceText().ToString()", v8_script_runner)
        self.assertIn("XTraceLogger::LogEventWithOptionalAssetAndContext", v8_script_runner)
        self.assertIn('"ClassicScript.evaluate"', v8_script_runner)

    @requires_chromium_tree
    def test_xtrace_v8_dynamic_dispatch_args_capture_raw_strings(self):
        v8_root = ROOT / "chromium" / "src" / "v8"
        runtime_typedarray = (
            v8_root / "src" / "runtime" / "runtime-typedarray.cc"
        ).read_text(encoding="utf-8")
        source_start = runtime_typedarray.index("void AppendDynamicDispatchArgRefsJson")
        source_end = runtime_typedarray.index(
            "DirectHandle<Object> XTraceDispatchStateObject",
            source_start,
        )
        source_block = runtime_typedarray[source_start:source_end]

        patch = (
            ROOT / "patches" / "0002-xtrace-v8-vmp-hooks.patch"
        ).read_text(encoding="utf-8")
        patch_start = patch.index("+void AppendDynamicDispatchArgRefsJson")
        patch_end = patch.index(
            "+DirectHandle<Object> XTraceDispatchStateObject",
            patch_start,
        )
        patch_block = patch[patch_start:patch_end]

        for field in ("first_arg", "second_arg"):
            self.assertIn(
                f'AppendStringMaterialJson(args, has_field, "{field}", {field});',
                source_block,
            )
            self.assertIn(
                f'+    AppendStringMaterialJson(args, has_field, "{field}", {field});',
                patch_block,
            )

    @requires_chromium_tree
    def test_xtrace_wasm_boundary_hooks_are_wired(self):
        wasm_js = (
            ROOT / "chromium" / "src" / "v8" / "src" / "wasm" / "wasm-js.cc"
        ).read_text(encoding="utf-8")
        patch = (
            ROOT / "patches" / "0002-xtrace-v8-vmp-hooks.patch"
        ).read_text(encoding="utf-8")

        self.assertIn("void XTraceWasmBoundary(", wasm_js)
        self.assertIn("+void XTraceWasmBoundary(", patch)
        for api in (
            "WebAssembly.compile",
            "WebAssembly.Module",
            "WebAssembly.Instance",
            "WebAssembly.instantiate",
            "WebAssembly.Memory",
        ):
            call = f'XTraceWasmBoundary(i_isolate, "{api}", info);'
            self.assertIn(call, wasm_js)
            self.assertIn(f"+  {call}", patch)

    @requires_chromium_tree
    def test_xtrace_v8_vmp_runtime_hooks_are_wired(self):
        v8_root = ROOT / "chromium" / "src" / "v8"
        runtime_header = (v8_root / "src" / "runtime" / "runtime.h").read_text(
            encoding="utf-8"
        )
        runtime_typedarray = (
            v8_root / "src" / "runtime" / "runtime-typedarray.cc"
        ).read_text(encoding="utf-8")
        runtime_strings = (
            v8_root / "src" / "runtime" / "runtime-strings.cc"
        ).read_text(encoding="utf-8")
        runtime_debug = (
            v8_root / "src" / "runtime" / "runtime-debug.cc"
        ).read_text(encoding="utf-8")
        function_cc = (
            v8_root / "src" / "builtins" / "builtins-function.cc"
        ).read_text(encoding="utf-8")
        builtins_json = (
            v8_root / "src" / "builtins" / "builtins-json.cc"
        ).read_text(encoding="utf-8")
        arm64_builtins = (
            v8_root / "src" / "builtins" / "arm64" / "builtins-arm64.cc"
        ).read_text(encoding="utf-8")
        base_tq = (v8_root / "src" / "builtins" / "base.tq").read_text(
            encoding="utf-8"
        )
        math_tq = (v8_root / "src" / "builtins" / "math.tq").read_text(
            encoding="utf-8"
        )
        string_tq = (
            v8_root / "src" / "builtins" / "builtins-string.tq"
        ).read_text(encoding="utf-8")
        string_gen = (
            v8_root / "src" / "builtins" / "builtins-string-gen.cc"
        ).read_text(encoding="utf-8")
        string_cc = (
            v8_root / "src" / "builtins" / "builtins-string.cc"
        ).read_text(encoding="utf-8")
        builtins_intl = (
            v8_root / "src" / "builtins" / "builtins-intl.cc"
        ).read_text(encoding="utf-8")
        builtins_intl_gen = (
            v8_root / "src" / "builtins" / "builtins-intl-gen.cc"
        ).read_text(encoding="utf-8")
        string_slice_tq = (
            v8_root / "src" / "builtins" / "string-slice.tq"
        ).read_text(encoding="utf-8")
        string_substring_tq = (
            v8_root / "src" / "builtins" / "string-substring.tq"
        ).read_text(encoding="utf-8")
        string_substr_tq = (
            v8_root / "src" / "builtins" / "string-substr.tq"
        ).read_text(encoding="utf-8")
        string_pad_tq = (
            v8_root / "src" / "builtins" / "string-pad.tq"
        ).read_text(encoding="utf-8")
        string_repeat_tq = (
            v8_root / "src" / "builtins" / "string-repeat.tq"
        ).read_text(encoding="utf-8")
        string_indexof_tq = (
            v8_root / "src" / "builtins" / "string-indexof.tq"
        ).read_text(encoding="utf-8")
        string_includes_tq = (
            v8_root / "src" / "builtins" / "string-includes.tq"
        ).read_text(encoding="utf-8")
        string_iterator_tq = (
            v8_root / "src" / "builtins" / "string-iterator.tq"
        ).read_text(encoding="utf-8")
        data_view_tq = (
            v8_root / "src" / "builtins" / "data-view.tq"
        ).read_text(encoding="utf-8")
        typed_array_at = (
            v8_root / "src" / "builtins" / "typed-array-at.tq"
        ).read_text(encoding="utf-8")
        typed_array_slice = (
            v8_root / "src" / "builtins" / "typed-array-slice.tq"
        ).read_text(encoding="utf-8")
        typed_array_subarray = (
            v8_root / "src" / "builtins" / "typed-array-subarray.tq"
        ).read_text(encoding="utf-8")
        typed_array_set = (
            v8_root / "src" / "builtins" / "typed-array-set.tq"
        ).read_text(encoding="utf-8")
        typed_array_builtin = (
            v8_root / "src" / "builtins" / "builtins-typed-array.cc"
        ).read_text(encoding="utf-8")
        typed_array_sort = (
            v8_root / "src" / "builtins" / "typed-array-sort.tq"
        ).read_text(encoding="utf-8")
        typed_array_find = (
            v8_root / "src" / "builtins" / "typed-array-find.tq"
        ).read_text(encoding="utf-8")
        typed_array_findindex = (
            v8_root / "src" / "builtins" / "typed-array-findindex.tq"
        ).read_text(encoding="utf-8")
        typed_array_findlast = (
            v8_root / "src" / "builtins" / "typed-array-findlast.tq"
        ).read_text(encoding="utf-8")
        typed_array_findlastindex = (
            v8_root / "src" / "builtins" / "typed-array-findlastindex.tq"
        ).read_text(encoding="utf-8")
        typed_array_reduce = (
            v8_root / "src" / "builtins" / "typed-array-reduce.tq"
        ).read_text(encoding="utf-8")
        typed_array_reduce_right = (
            v8_root / "src" / "builtins" / "typed-array-reduceright.tq"
        ).read_text(encoding="utf-8")
        typed_array_filter = (
            v8_root / "src" / "builtins" / "typed-array-filter.tq"
        ).read_text(encoding="utf-8")
        typed_array_every = (
            v8_root / "src" / "builtins" / "typed-array-every.tq"
        ).read_text(encoding="utf-8")
        typed_array_some = (
            v8_root / "src" / "builtins" / "typed-array-some.tq"
        ).read_text(encoding="utf-8")
        typed_array_foreach = (
            v8_root / "src" / "builtins" / "typed-array-foreach.tq"
        ).read_text(encoding="utf-8")
        typed_array_entries = (
            v8_root / "src" / "builtins" / "typed-array-entries.tq"
        ).read_text(encoding="utf-8")
        typed_array_keys = (
            v8_root / "src" / "builtins" / "typed-array-keys.tq"
        ).read_text(encoding="utf-8")
        typed_array_values = (
            v8_root / "src" / "builtins" / "typed-array-values.tq"
        ).read_text(encoding="utf-8")
        array_join = (
            v8_root / "src" / "builtins" / "array-join.tq"
        ).read_text(encoding="utf-8")
        array_at = (
            v8_root / "src" / "builtins" / "array-at.tq"
        ).read_text(encoding="utf-8")
        array_flat = (
            v8_root / "src" / "builtins" / "array-flat.tq"
        ).read_text(encoding="utf-8")
        array_gen = (
            v8_root / "src" / "builtins" / "builtins-array-gen.cc"
        ).read_text(encoding="utf-8")
        generator_gen = (
            v8_root / "src" / "builtins" / "builtins-generator-gen.cc"
        ).read_text(encoding="utf-8")
        async_generator_gen = (
            v8_root / "src" / "builtins" / "builtins-async-generator-gen.cc"
        ).read_text(encoding="utf-8")
        array_cc = (
            v8_root / "src" / "builtins" / "builtins-array.cc"
        ).read_text(encoding="utf-8")
        array_unshift = (
            v8_root / "src" / "builtins" / "array-unshift.tq"
        ).read_text(encoding="utf-8")
        array_slice = (
            v8_root / "src" / "builtins" / "array-slice.tq"
        ).read_text(encoding="utf-8")
        array_shift = (
            v8_root / "src" / "builtins" / "array-shift.tq"
        ).read_text(encoding="utf-8")
        array_lastindexof = (
            v8_root / "src" / "builtins" / "array-lastindexof.tq"
        ).read_text(encoding="utf-8")
        array_find = (
            v8_root / "src" / "builtins" / "array-find.tq"
        ).read_text(encoding="utf-8")
        array_findindex = (
            v8_root / "src" / "builtins" / "array-findindex.tq"
        ).read_text(encoding="utf-8")
        array_findlast = (
            v8_root / "src" / "builtins" / "array-findlast.tq"
        ).read_text(encoding="utf-8")
        array_findlastindex = (
            v8_root / "src" / "builtins" / "array-findlastindex.tq"
        ).read_text(encoding="utf-8")
        array_reduce = (
            v8_root / "src" / "builtins" / "array-reduce.tq"
        ).read_text(encoding="utf-8")
        array_reduce_right = (
            v8_root / "src" / "builtins" / "array-reduce-right.tq"
        ).read_text(encoding="utf-8")
        array_map = (
            v8_root / "src" / "builtins" / "array-map.tq"
        ).read_text(encoding="utf-8")
        array_filter = (
            v8_root / "src" / "builtins" / "array-filter.tq"
        ).read_text(encoding="utf-8")
        array_every = (
            v8_root / "src" / "builtins" / "array-every.tq"
        ).read_text(encoding="utf-8")
        array_some = (
            v8_root / "src" / "builtins" / "array-some.tq"
        ).read_text(encoding="utf-8")
        array_foreach = (
            v8_root / "src" / "builtins" / "array-foreach.tq"
        ).read_text(encoding="utf-8")
        array_from = (
            v8_root / "src" / "builtins" / "array-from.tq"
        ).read_text(encoding="utf-8")
        array_of = (
            v8_root / "src" / "builtins" / "array-of.tq"
        ).read_text(encoding="utf-8")
        array_copywithin = (
            v8_root / "src" / "builtins" / "array-copywithin.tq"
        ).read_text(encoding="utf-8")
        array_splice = (
            v8_root / "src" / "builtins" / "array-splice.tq"
        ).read_text(encoding="utf-8")
        array_reverse = (
            v8_root / "src" / "builtins" / "array-reverse.tq"
        ).read_text(encoding="utf-8")
        array_sort = (
            v8_root / "third_party" / "v8" / "builtins" / "array-sort.tq"
        ).read_text(encoding="utf-8")
        array_tq = (v8_root / "src" / "builtins" / "array.tq").read_text(
            encoding="utf-8"
        )
        number_tq = (v8_root / "src" / "builtins" / "number.tq").read_text(
            encoding="utf-8"
        )
        builtins_bigint = (
            v8_root / "src" / "builtins" / "builtins-bigint.cc"
        ).read_text(encoding="utf-8")
        number_gen = (
            v8_root / "src" / "builtins" / "builtins-number-gen.cc"
        ).read_text(encoding="utf-8")
        interpreter_generator = (
            v8_root / "src" / "interpreter" / "interpreter-generator.cc"
        ).read_text(encoding="utf-8")
        object_gen = (
            v8_root / "src" / "builtins" / "builtins-object-gen.cc"
        ).read_text(encoding="utf-8")
        object_tq = (v8_root / "src" / "builtins" / "object.tq").read_text(
            encoding="utf-8"
        )
        array_isarray_tq = (
            v8_root / "src" / "builtins" / "array-isarray.tq"
        ).read_text(encoding="utf-8")
        object_cc = (
            v8_root / "src" / "builtins" / "builtins-object.cc"
        ).read_text(encoding="utf-8")
        collections_gen = (
            v8_root / "src" / "builtins" / "builtins-collections-gen.cc"
        ).read_text(encoding="utf-8")
        builtins_collections = (
            v8_root / "src" / "builtins" / "builtins-collections.cc"
        ).read_text(encoding="utf-8")
        proxy_get_tq = (
            v8_root / "src" / "builtins" / "proxy-get-property.tq"
        ).read_text(encoding="utf-8")
        proxy_set_tq = (
            v8_root / "src" / "builtins" / "proxy-set-property.tq"
        ).read_text(encoding="utf-8")
        proxy_has_tq = (
            v8_root / "src" / "builtins" / "proxy-has-property.tq"
        ).read_text(encoding="utf-8")
        proxy_delete_tq = (
            v8_root / "src" / "builtins" / "proxy-delete-property.tq"
        ).read_text(encoding="utf-8")
        objects_cc = (v8_root / "src" / "objects" / "objects.cc").read_text(
            encoding="utf-8"
        )
        js_objects_cc = (
            v8_root / "src" / "objects" / "js-objects.cc"
        ).read_text(encoding="utf-8")
        keys_cc = (v8_root / "src" / "objects" / "keys.cc").read_text(
            encoding="utf-8"
        )
        reflect_tq = (v8_root / "src" / "builtins" / "reflect.tq").read_text(
            encoding="utf-8"
        )
        reflect_cc = (
            v8_root / "src" / "builtins" / "builtins-reflect.cc"
        ).read_text(encoding="utf-8")
        arm64_builtins = (
            v8_root / "src" / "builtins" / "arm64" / "builtins-arm64.cc"
        ).read_text(encoding="utf-8")
        array_buffer = (
            v8_root / "src" / "builtins" / "builtins-arraybuffer.cc"
        ).read_text(encoding="utf-8")
        builtins_error = (
            v8_root / "src" / "builtins" / "builtins-error.cc"
        ).read_text(encoding="utf-8")
        builtins_global = (
            v8_root / "src" / "builtins" / "builtins-global.cc"
        ).read_text(encoding="utf-8")
        messages_cc = (
            v8_root / "src" / "execution" / "messages.cc"
        ).read_text(encoding="utf-8")
        isolate_cc = (
            v8_root / "src" / "execution" / "isolate.cc"
        ).read_text(encoding="utf-8")
        regexp_test_tq = (
            v8_root / "src" / "builtins" / "regexp-test.tq"
        ).read_text(encoding="utf-8")
        regexp_exec_tq = (
            v8_root / "src" / "builtins" / "regexp-exec.tq"
        ).read_text(encoding="utf-8")
        regexp_match_tq = (
            v8_root / "src" / "builtins" / "regexp-match.tq"
        ).read_text(encoding="utf-8")
        regexp_match_all_tq = (
            v8_root / "src" / "builtins" / "regexp-match-all.tq"
        ).read_text(encoding="utf-8")
        regexp_replace_tq = (
            v8_root / "src" / "builtins" / "regexp-replace.tq"
        ).read_text(encoding="utf-8")
        regexp_search_tq = (
            v8_root / "src" / "builtins" / "regexp-search.tq"
        ).read_text(encoding="utf-8")
        regexp_split_tq = (
            v8_root / "src" / "builtins" / "regexp-split.tq"
        ).read_text(encoding="utf-8")
        string_at_tq = (
            v8_root / "src" / "builtins" / "string-at.tq"
        ).read_text(encoding="utf-8")
        string_match_search_tq = (
            v8_root / "src" / "builtins" / "string-match-search.tq"
        ).read_text(encoding="utf-8")
        string_replaceall_tq = (
            v8_root / "src" / "builtins" / "string-replaceall.tq"
        ).read_text(encoding="utf-8")
        string_startswith_tq = (
            v8_root / "src" / "builtins" / "string-startswith.tq"
        ).read_text(encoding="utf-8")
        string_endswith_tq = (
            v8_root / "src" / "builtins" / "string-endswith.tq"
        ).read_text(encoding="utf-8")
        string_trim_tq = (
            v8_root / "src" / "builtins" / "string-trim.tq"
        ).read_text(encoding="utf-8")

        self.assertIn("F(XTraceVmpRuntime, 6, 1)", runtime_header)
        self.assertNotIn("XTraceVmpDispatchCall", runtime_header)
        self.assertIn("Runtime_XTraceVmpRuntime", runtime_typedarray)
        self.assertNotIn("Runtime_XTraceVmpDispatchCall", runtime_typedarray)
        self.assertIn("BuildXTraceVmpArgsJson", runtime_typedarray)
        self.assertIn("std::isfinite", runtime_typedarray)
        self.assertIn("xtrace:vmp-runtime:", runtime_typedarray)
        self.assertIn("AppendStringResultJson", runtime_typedarray)
        self.assertIn("AppendStringMaterialJson", runtime_typedarray)
        self.assertIn('AppendFieldPrefix(args, has_field, "result")', runtime_typedarray)
        self.assertIn("string->ToCString()", runtime_typedarray)
        for field in ("subject", "first_arg", "fill", "search", "replace", "separator"):
            self.assertIn(
                f'AppendStringMaterialJson(args, &has_field, "{field}", ',
                runtime_typedarray,
            )
        self.assertNotIn("AppendStringPreviewJson", runtime_typedarray)
        self.assertNotIn("kXTraceStringPreviewChars", runtime_typedarray)
        self.assertNotIn("result_preview", runtime_typedarray)
        self.assertNotIn(",\\\"truncated\\\":", runtime_typedarray)
        self.assertNotIn("ToCString(0", runtime_typedarray)
        self.assertNotIn("std::min(original_length", runtime_typedarray)
        self.assertIn("xtrace:vmp-runtime:debugger.statement", runtime_debug)
        self.assertIn("LogXTraceFunctionPrototypeToString", function_cc)
        self.assertIn("xtrace:vmp-runtime:Function.prototype.toString", function_cc)
        self.assertIn("thread_local bool in_xtrace_function_to_string_log", function_cc)
        self.assertIn("if (in_xtrace_function_to_string_log) return;", function_cc)
        self.assertIn("LogXTraceJsonParse", builtins_json)
        self.assertIn("LogXTraceJsonStringify", builtins_json)
        self.assertIn('std::string event = "xtrace:vmp-runtime:";', builtins_json)
        self.assertIn('"JSON.parse"', builtins_json)
        self.assertIn('"JSON.stringify"', builtins_json)
        self.assertIn("value->ToCString()", builtins_json)
        self.assertIn(
            'AppendXTraceJsonStringField(args, &has_field, "source", source)',
            builtins_json,
        )
        self.assertIn(
            'AppendXTraceJsonStringRefField(args, &has_field, "source_ref", source)',
            builtins_json,
        )
        self.assertIn('"reviver_ref"', builtins_json)
        self.assertIn(
            'AppendXTraceJsonValueRefField(isolate, args, &has_field, "reviver_ref",',
            builtins_json,
        )
        self.assertIn("AppendXTraceJsonValueRefField", builtins_json)
        self.assertIn(
            'AppendXTraceJsonValueRefField(isolate, args, &has_field, "result_ref", result)',
            builtins_json,
        )
        self.assertIn(
            'AppendXTraceMaybeStringField(isolate, args, &has_field, "input", object)',
            builtins_json,
        )
        self.assertIn(
            'AppendXTraceJsonValueRefField(isolate, args, &has_field, "replacer_ref", replacer)',
            builtins_json,
        )
        self.assertIn(
            'AppendXTraceJsonValueRefField(isolate, args, &has_field, "space_ref", indent)',
            builtins_json,
        )
        self.assertIn(
            'AppendXTraceMaybeStringField(isolate, args, &has_field, "result", result)',
            builtins_json,
        )
        self.assertNotIn("kXTraceJsonPreviewChars", builtins_json)
        self.assertNotIn("AppendXTraceJsonStringPreview", builtins_json)
        self.assertNotIn("AppendXTraceMaybeStringPreview", builtins_json)
        self.assertNotIn("_preview", builtins_json)
        self.assertNotIn("_truncated", builtins_json)
        self.assertNotIn("ToCString(0", builtins_json)
        self.assertNotIn("std::min(original_length", builtins_json)
        v8_string_ref_sources = {
            "runtime-strings": runtime_strings,
            "runtime-typedarray": runtime_typedarray,
            "builtins-array": array_cc,
            "builtins-bigint": builtins_bigint,
            "builtins-global": builtins_global,
            "builtins-intl": builtins_intl,
            "builtins-json": builtins_json,
            "builtins-string": string_cc,
            "builtins-typed-array": typed_array_builtin,
        }
        for label, source in v8_string_ref_sources.items():
            self.assertNotIn("string:length:", source, label)
        self.assertIn("string_ref:fnv1a64:", runtime_strings)
        self.assertIn("string_ref:fnv1a64:", runtime_typedarray)
        self.assertIn("string_ref:fnv1a64:", builtins_json)
        self.assertIn("LogXTraceErrorCaptureStackTrace", builtins_error)
        self.assertIn("xtrace:vmp-runtime:Error.captureStackTrace", builtins_error)
        self.assertIn("LogXTraceErrorConstructor", builtins_error)
        self.assertIn("xtrace:vmp-runtime:Error.constructor", builtins_error)
        self.assertIn("LogXTraceErrorStackGet", messages_cc)
        self.assertIn("xtrace:vmp-runtime:Error.stack.get", messages_cc)
        self.assertIn("thread_local bool in_xtrace_error_stack_get_log", messages_cc)
        self.assertIn("LogXTraceExceptionThrow", isolate_cc)
        self.assertIn("xtrace:vmp-runtime:Exception.throw", isolate_cc)
        self.assertIn("XTraceCatchTypeName", isolate_cc)
        self.assertIn("extern runtime XTraceVmpRuntime(Context, String, String, JSAny, JSAny, JSAny, JSAny)", base_tq)
        self.assertIn("StringConstant('Math.imul')", math_tq)
        self.assertIn("StringConstant('String.prototype.charCodeAt')", string_tq)
        self.assertIn("StringConstant('String.prototype.codePointAt')", string_tq)
        self.assertIn("StringConstant('String.prototype.charAt')", string_tq)
        self.assertIn("StringConstant('String.prototype.at')", string_at_tq)
        self.assertIn("StringConstant('string_at')", string_at_tq)
        self.assertIn("s, index, result, k", string_at_tq)
        self.assertIn(
            "StringConstant('string_char_code_at'), string, position, result",
            string_tq,
        )
        self.assertNotIn(
            "StringConstant('string_char_code_at'), Undefined, position, result",
            string_tq,
        )
        self.assertIn("StringConstant('string_code_point_at')", string_tq)
        self.assertIn("StringConstant('string_char_at')", string_tq)
        self.assertIn("StringConstant('String.prototype.concat')", string_tq)
        self.assertIn("StringConstant('string_concat')", string_tq)
        self.assertIn('AppendValueRefJson(isolate, args, &has_field, "result_ref", value2)', runtime_typedarray)
        self.assertIn("StringConstant('String.prototype.slice')", string_slice_tq)
        self.assertIn("StringConstant('String.prototype.substring')", string_substring_tq)
        self.assertIn("StringConstant('String.prototype.substr')", string_substr_tq)
        self.assertIn("StringConstant('string_substr')", string_substr_tq)
        self.assertIn("StringConstant('String.prototype.padStart')", string_pad_tq)
        self.assertIn("StringConstant('String.prototype.padEnd')", string_pad_tq)
        self.assertIn("StringConstant('string_pad')", string_pad_tq)
        self.assertIn("StringConstant('String.prototype.repeat')", string_repeat_tq)
        self.assertIn("StringConstant('string_repeat')", string_repeat_tq)
        self.assertIn("s, n, result", string_repeat_tq)
        self.assertIn('shape_string == "string_repeat"', runtime_typedarray)
        self.assertIn('"repeat_count"', runtime_typedarray)
        self.assertIn('"repeat_count_ref"', runtime_typedarray)
        self.assertIn("StringConstant('String.prototype.startsWith')", string_startswith_tq)
        self.assertIn("StringConstant('string_starts_with')", string_startswith_tq)
        self.assertIn(
            "string, searchStr,\n      Convert<Number>(start), result",
            string_startswith_tq,
        )
        self.assertIn("StringConstant('String.prototype.endsWith')", string_endswith_tq)
        self.assertIn("StringConstant('string_ends_with')", string_endswith_tq)
        self.assertIn(
            "string, searchStr,\n      Convert<Number>(end), result",
            string_endswith_tq,
        )
        self.assertIn("'String.prototype.trim'", string_trim_tq)
        self.assertIn("'String.prototype.trimStart'", string_trim_tq)
        self.assertIn("'String.prototype.trimEnd'", string_trim_tq)
        self.assertIn("StringConstant(apiName)", string_trim_tq)
        self.assertIn("StringConstant('string_trim')", string_trim_tq)
        self.assertIn("receiverString, StringConstant(modeName), result", string_trim_tq)
        self.assertIn("StringConstant('Number.prototype.toString')", number_tq)
        self.assertIn("StringConstant('number_to_string')", number_tq)
        self.assertIn("XTraceNumberToString(", number_tq)
        self.assertIn("StringConstant('Number.parseInt')", number_tq)
        self.assertIn("StringConstant('number_parse_int')", number_tq)
        self.assertIn("StringConstant('Number.parseFloat')", number_tq)
        self.assertIn("StringConstant('number_parse_float')", number_tq)
        parse_int_start = runtime_typedarray.index('shape_string == "number_parse_int"')
        parse_int_end = runtime_typedarray.index(
            'shape_string == "number_parse_float"',
            parse_int_start,
        )
        parse_int_block = runtime_typedarray[parse_int_start:parse_int_end]
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "input", value1);',
            parse_int_block,
        )
        self.assertIn(
            'AppendValueRefJson(isolate, args, &has_field, "radix_ref", value2);',
            parse_int_block,
        )
        self.assertIn(
            'AppendValueRefJson(isolate, args, &has_field, "result_ref", value3);',
            parse_int_block,
        )
        parse_float_start = runtime_typedarray.index(
            'shape_string == "number_parse_float"'
        )
        parse_float_end = runtime_typedarray.index(
            'shape_string == "string_starts_with"',
            parse_float_start,
        )
        parse_float_block = runtime_typedarray[parse_float_start:parse_float_end]
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "input", value1);',
            parse_float_block,
        )
        self.assertIn(
            'AppendValueRefJson(isolate, args, &has_field, "result_ref", value2);',
            parse_float_block,
        )
        self.assertIn("LogXTraceBigIntToString", builtins_bigint)
        self.assertIn("xtrace:vmp-runtime:BigInt.prototype.toString", builtins_bigint)
        self.assertIn("bigint_to_string", builtins_bigint)
        self.assertIn('AppendXTraceStringField(event, "result", result)', builtins_bigint)
        self.assertIn('event.append("_ref\\":");', builtins_bigint)
        self.assertNotIn("kXTraceBigIntPreviewChars", builtins_bigint)
        self.assertNotIn("result_preview", builtins_bigint)
        self.assertNotIn("result_truncated", builtins_bigint)
        self.assertNotIn("ToCString(0", builtins_bigint)
        self.assertNotIn("std::min(original_length", builtins_bigint)
        self.assertIn("StringConstant('String.prototype.indexOf')", string_indexof_tq)
        self.assertIn("StringConstant('String.prototype.includes')", string_includes_tq)
        self.assertIn('StringConstant("String.prototype.replace")', string_gen)
        self.assertIn('StringConstant("string_replace")', string_gen)
        self.assertIn("StringConstant('String.prototype.replaceAll')", string_replaceall_tq)
        self.assertIn("StringConstant('string_replace_all')", string_replaceall_tq)
        self.assertIn("string, searchString,\n      replaceValueArg, result", string_replaceall_tq)
        self.assertIn('StringConstant("String.prototype.split")', string_gen)
        self.assertIn('StringConstant("string_split")', string_gen)
        self.assertIn("LogXTraceStringCase", string_cc)
        self.assertIn('LogXTraceStringCase(isolate, "String.prototype.toLowerCase", "lower"', string_cc)
        self.assertIn('LogXTraceStringCase(isolate, "String.prototype.toUpperCase", "upper"', string_cc)
        self.assertIn("LogXTraceStringLastIndexOf", string_cc)
        self.assertIn("xtrace:vmp-runtime:String.prototype.lastIndexOf", string_cc)
        self.assertIn("string_search", string_cc)
        self.assertIn(
            "LogXTraceStringLastIndexOf(isolate, string, search, start_index,",
            string_cc,
        )
        self.assertIn("string_case", string_cc)
        self.assertIn("case_direction", string_cc)
        self.assertIn('AppendXTraceStringField(event, "subject", subject)', string_cc)
        self.assertIn('AppendXTraceStringField(event, "result", result)', string_cc)
        self.assertNotIn("kXTraceStringPreviewChars", string_cc)
        self.assertNotIn("AppendXTraceStringPreview", string_cc)
        self.assertNotIn("_preview", string_cc)
        self.assertNotIn("ToCString(0", string_cc)
        self.assertNotIn("std::min(original_length", string_cc)
        self.assertIn("LogXTraceStringCase", builtins_intl)
        self.assertIn('LogXTraceStringCase(isolate, "String.prototype.toUpperCase", "upper"', builtins_intl)
        self.assertIn('AppendXTraceStringField(event, "subject", subject)', builtins_intl)
        self.assertIn('AppendXTraceStringField(event, "result", result)', builtins_intl)
        self.assertNotIn("kXTraceStringPreviewChars", builtins_intl)
        self.assertNotIn("AppendXTraceStringPreview", builtins_intl)
        self.assertNotIn("_preview", builtins_intl)
        self.assertNotIn("ToCString(0", builtins_intl)
        self.assertNotIn("std::min(original_length", builtins_intl)
        self.assertIn("StringPrototypeToLowerCaseIntl", builtins_intl_gen)
        self.assertIn('StringConstant("String.prototype.toLowerCase")', builtins_intl_gen)
        self.assertIn('StringConstant("string_case")', builtins_intl_gen)
        self.assertIn('StringConstant("lower")', builtins_intl_gen)
        self.assertIn('"string_replace"', runtime_typedarray)
        self.assertIn('"string_replace_all"', runtime_typedarray)
        self.assertIn('"string_split"', runtime_typedarray)
        self.assertIn('"string_case"', runtime_typedarray)
        self.assertIn('"string_char_at"', runtime_typedarray)
        self.assertIn('"string_concat"', runtime_typedarray)
        self.assertIn('"string_substr"', runtime_typedarray)
        self.assertIn('"string_pad"', runtime_typedarray)
        self.assertIn('"string_starts_with"', runtime_typedarray)
        self.assertIn('"string_ends_with"', runtime_typedarray)
        self.assertIn('"string_trim"', runtime_typedarray)
        self.assertIn('"max_length"', runtime_typedarray)
        self.assertIn('"fill_ref"', runtime_typedarray)
        self.assertIn('"replace_ref"', runtime_typedarray)
        self.assertIn('"separator_ref"', runtime_typedarray)
        self.assertIn('"result_array_id"', runtime_typedarray)
        starts_with_start = runtime_typedarray.index('shape_string == "string_starts_with"')
        starts_with_end = runtime_typedarray.index(
            'shape_string == "string_ends_with"',
            starts_with_start,
        )
        starts_with_block = runtime_typedarray[starts_with_start:starts_with_end]
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "subject", subject);',
            starts_with_block,
        )
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "search", value1);',
            starts_with_block,
        )
        self.assertIn('AppendFieldPrefix(args, &has_field, "position");', starts_with_block)
        self.assertIn('args.append(JsonValue(value3));', starts_with_block)
        ends_with_start = runtime_typedarray.index('shape_string == "string_ends_with"')
        ends_with_end = runtime_typedarray.index(
            'shape_string == "string_replace" ||',
            ends_with_start,
        )
        ends_with_block = runtime_typedarray[ends_with_start:ends_with_end]
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "subject", subject);',
            ends_with_block,
        )
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "search", value1);',
            ends_with_block,
        )
        self.assertIn('AppendFieldPrefix(args, &has_field, "end_position");', ends_with_block)
        self.assertIn('args.append(JsonValue(value3));', ends_with_block)
        trim_start = runtime_typedarray.index('shape_string == "string_trim"')
        trim_end = runtime_typedarray.index(
            'shape_string == "string_replace" ||',
            trim_start,
        )
        trim_block = runtime_typedarray[trim_start:trim_end]
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "subject", subject);',
            trim_block,
        )
        self.assertIn('AppendFieldPrefix(args, &has_field, "trim_mode");', trim_block)
        self.assertIn("AppendStringResultJson(args, &has_field, value2);", trim_block)
        self.assertIn(
            'AppendValueRefJson(isolate, args, &has_field, "result_ref", value2);',
            trim_block,
        )
        replace_all_start = runtime_typedarray.index('shape_string == "string_replace_all"')
        replace_all_end = runtime_typedarray.index(
            'shape_string == "string_split"',
            replace_all_start,
        )
        replace_all_block = runtime_typedarray[replace_all_start:replace_all_end]
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "subject", subject);',
            replace_all_block,
        )
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "search", value1);',
            replace_all_block,
        )
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "replace", value2);',
            replace_all_block,
        )
        self.assertIn("AppendStringResultJson(args, &has_field, value3);", replace_all_block)
        self.assertIn("StringConstant('RegExp.prototype.test')", regexp_test_tq)
        self.assertIn("StringConstant('RegExp.prototype.exec')", regexp_exec_tq)
        self.assertIn("receiver, string,\n      result,", regexp_exec_tq)
        self.assertIn("SelectBooleanConstant(result != Null));", regexp_exec_tq)
        self.assertIn("StringConstant('RegExp.prototype.@@match')", regexp_match_tq)
        self.assertIn("StringConstant('regexp_match')", regexp_match_tq)
        self.assertIn("receiver, string, result,", regexp_match_tq)
        self.assertIn("SelectBooleanConstant(result != Null)", regexp_match_tq)
        self.assertIn("StringConstant('RegExp.prototype.@@matchAll')", regexp_match_all_tq)
        self.assertIn('StringConstant("String.prototype.matchAll")', string_gen)
        self.assertIn("StringConstant('regexp_match_all_create')", regexp_match_all_tq)
        self.assertIn('StringConstant("regexp_match_all_create")', string_gen)
        self.assertIn("StringConstant('RegExpStringIterator.prototype.next')", regexp_match_all_tq)
        self.assertIn("StringConstant('regexp_iterator_next_entry')", regexp_match_all_tq)
        self.assertIn("StringConstant('regexp_iterator_next_done')", regexp_match_all_tq)
        self.assertIn("XTraceVmpRuntime", regexp_match_all_tq)
        self.assertIn("StringConstant('RegExp.prototype.@@replace')", regexp_replace_tq)
        self.assertIn("StringConstant('regexp_replace')", regexp_replace_tq)
        self.assertIn("rx, s, replaceValue, result", regexp_replace_tq)
        self.assertIn("StringConstant('RegExp.prototype.@@split')", regexp_split_tq)
        self.assertIn("StringConstant('regexp_split')", regexp_split_tq)
        self.assertIn("receiver, string, result, limit", regexp_split_tq)
        self.assertIn("StringConstant('RegExp.prototype.@@search')", regexp_search_tq)
        self.assertIn("StringConstant('regexp_search')", regexp_search_tq)
        self.assertIn("receiver, string, result, Undefined", regexp_search_tq)
        self.assertIn("StringConstant(methodName)", string_match_search_tq)
        self.assertIn("StringConstant(shapeName)", string_match_search_tq)
        self.assertIn("'String.prototype.search', 'string_search'", string_match_search_tq)
        self.assertIn("'String.prototype.match', 'string_match'", string_match_search_tq)
        self.assertGreaterEqual(string_match_search_tq.count("XTraceVmpRuntime("), 3)
        self.assertIn("regexp, receiver, result", string_match_search_tq)
        self.assertIn("StringConstant(shapeName), rx,", string_match_search_tq)
        self.assertIn("UnsafeCast<JSAny>(string), result,", string_match_search_tq)
        self.assertIn(
            "UnsafeCast<JSAny>(StringConstant('regexp_create'))",
            string_match_search_tq,
        )
        self.assertIn("StringConstant('string_slice')", string_slice_tq)
        self.assertIn("StringConstant('string_search')", string_indexof_tq)
        self.assertIn("StringConstant('regexp_exec')", regexp_exec_tq)
        self.assertIn('"regexp_match_all_create"', runtime_typedarray)
        self.assertIn('"regexp_iterator_next_entry"', runtime_typedarray)
        self.assertIn('"regexp_iterator_next_done"', runtime_typedarray)
        regexp_match_all_create_start = runtime_typedarray.index(
            'shape_string == "regexp_match_all_create"'
        )
        regexp_iterator_next_entry_start = runtime_typedarray.index(
            'shape_string == "regexp_iterator_next_entry"'
        )
        regexp_iterator_next_done_start = runtime_typedarray.index(
            'shape_string == "regexp_iterator_next_done"'
        )
        regexp_search_start = runtime_typedarray.index(
            'shape_string == "regexp_search"'
        )
        regexp_iterator_subject_link_start = runtime_typedarray.index(
            'shape == "regexp_iterator_next_entry"'
        )
        regexp_iterator_subject_link_end = runtime_typedarray.index(
            '} else if (shape == "dynamic_dispatch"',
            regexp_iterator_subject_link_start,
        )
        regexp_iterator_subject_link_block = runtime_typedarray[
            regexp_iterator_subject_link_start:regexp_iterator_subject_link_end
        ]
        regexp_match_all_create_block = runtime_typedarray[
            regexp_match_all_create_start:regexp_iterator_next_entry_start
        ]
        regexp_iterator_next_entry_block = runtime_typedarray[
            regexp_iterator_next_entry_start:regexp_iterator_next_done_start
        ]
        regexp_iterator_next_done_block = runtime_typedarray[
            regexp_iterator_next_done_start:regexp_search_start
        ]
        for block in [
            regexp_match_all_create_block,
            regexp_iterator_next_entry_block,
            regexp_iterator_next_done_block,
        ]:
            self.assertIn('"regexp_ref"', block)
            self.assertIn('"input_ref"', block)
            self.assertIn('"result_ref"', block)
        self.assertIn('"iterator_ref"', regexp_match_all_create_block)
        self.assertIn('"iterator_ref"', regexp_iterator_subject_link_block)
        self.assertIn('"done"', regexp_iterator_next_entry_block)
        self.assertIn('"done"', regexp_iterator_next_done_block)
        self.assertIn(
            'shape == "regexp_exec" || shape == "regexp_search" ||\n'
            '             shape == "regexp_match" || shape == "regexp_split" ||\n'
            '             shape == "regexp_replace" ||\n'
            '             shape == "regexp_match_all_create" ||\n'
            '             shape == "string_search" ||\n'
            '             shape == "string_match"',
            runtime_typedarray,
        )
        replace_start = runtime_typedarray.index('shape_string == "regexp_replace"')
        replace_end = runtime_typedarray.index(
            'shape_string == "regexp_split"',
            replace_start,
        )
        replace_block = runtime_typedarray[replace_start:replace_end]
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "input", value1);',
            replace_block,
        )
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "replace", value2);',
            replace_block,
        )
        self.assertIn(
            'AppendObjectTypeJson(args, &has_field, "replace_type", value2);',
            replace_block,
        )
        self.assertIn("AppendStringResultJson(args, &has_field, value3);", replace_block)
        self.assertIn(
            'AppendValueRefJson(isolate, args, &has_field, "result_ref", value3);',
            replace_block,
        )
        split_start = runtime_typedarray.index('shape_string == "regexp_split"')
        split_end = runtime_typedarray.index(
            'shape_string == "regexp_match"',
            split_start,
        )
        split_block = runtime_typedarray[split_start:split_end]
        self.assertIn(
            'AppendArrayElementsJson(isolate, args, &has_field, value2,',
            split_block,
        )
        self.assertIn('"result_elements"', split_block)
        self.assertIn('"result_element_refs"', split_block)
        self.assertIn('"result_elements_complete"', split_block)
        match_start = runtime_typedarray.index('shape_string == "regexp_match"')
        match_end = runtime_typedarray.index(
            'shape_string == "regexp_search"',
            match_start,
        )
        match_block = runtime_typedarray[match_start:match_end]
        self.assertIn(
            'AppendObjectTypeJson(args, &has_field, "result_type", value2);',
            match_block,
        )
        self.assertIn(
            'AppendRegExpResultArrayJson(isolate, args, &has_field, value2);',
            match_block,
        )
        search_start = runtime_typedarray.index('shape_string == "regexp_search"')
        search_end = runtime_typedarray.index(
            'shape_string == "regexp_exec"',
            search_start,
        )
        search_block = runtime_typedarray[search_start:search_end]
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "input", value1);',
            search_block,
        )
        self.assertIn(
            'AppendValueRefJson(isolate, args, &has_field, "input_ref", value1);',
            search_block,
        )
        string_search_start = runtime_typedarray.index(
            'shape_string == "string_search"'
        )
        string_search_end = runtime_typedarray.index(
            'shape_string == "string_match"',
            string_search_start,
        )
        string_search_block = runtime_typedarray[string_search_start:string_search_end]
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "input", value1);',
            string_search_block,
        )
        self.assertIn(
            'AppendObjectTypeJson(args, &has_field, "result_type", value2);',
            string_search_block,
        )
        self.assertIn(
            'AppendValueRefJson(isolate, args, &has_field, "result_ref", value2);',
            string_search_block,
        )
        string_match_start = runtime_typedarray.index(
            'shape_string == "string_match"'
        )
        string_match_end = runtime_typedarray.index(
            'shape_string == "regexp_exec"',
            string_match_start,
        )
        string_match_block = runtime_typedarray[string_match_start:string_match_end]
        self.assertIn(
            'AppendRegExpResultArrayJson(isolate, args, &has_field, value2);',
            string_match_block,
        )
        self.assertIn(
            'AppendValueRefJson(isolate, args, &has_field, "input_ref", value1);',
            string_match_block,
        )
        self.assertIn(
            'AppendValueRefJson(isolate, args, &has_field, "result_ref", value2);',
            search_block,
        )
        regexp_start = runtime_typedarray.index('shape_string == "regexp_exec"')
        regexp_end = runtime_typedarray.index(
            'shape_string == "dynamic_dispatch"',
            regexp_start,
        )
        regexp_block = runtime_typedarray[regexp_start:regexp_end]
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "input", value1);',
            regexp_block,
        )
        self.assertIn(
            'AppendValueRefJson(isolate, args, &has_field, "input_ref", value1);',
            regexp_block,
        )
        self.assertIn(
            'AppendObjectTypeJson(args, &has_field, "result_type", value2);',
            regexp_block,
        )
        self.assertIn(
            'AppendValueRefJson(isolate, args, &has_field, "result_ref", value2);',
            regexp_block,
        )
        self.assertIn(
            'AppendObjectIdJson(isolate, args, &has_field, "result_array_id", value2);',
            regexp_block,
        )
        self.assertIn(
            'AppendRegExpResultArrayJson(isolate, args, &has_field, value2);',
            regexp_block,
        )
        self.assertIn("LogXTraceUriCodec", builtins_global)
        self.assertIn("value->ToCString()", builtins_global)
        self.assertIn('event.append("_length\\":");', builtins_global)
        self.assertIn('AppendXTraceStringField(event, "input", input)', builtins_global)
        self.assertIn('AppendXTraceStringRefField(event, "input_ref", input)', builtins_global)
        self.assertIn('AppendXTraceStringField(event, "result", result)', builtins_global)
        self.assertIn('AppendXTraceStringRefField(event, "result_ref", result)', builtins_global)
        self.assertNotIn("kXTraceUriPreviewChars", builtins_global)
        self.assertNotIn("kXTraceUriValueChars", builtins_global)
        self.assertNotIn("preview_only", builtins_global)
        self.assertNotIn("_preview", builtins_global)
        self.assertNotIn("_truncated", builtins_global)
        self.assertNotIn("std::min(original_length", builtins_global)
        self.assertIn("xtrace:vmp-runtime:encodeURIComponent", builtins_global)
        self.assertIn("xtrace:vmp-runtime:decodeURIComponent", builtins_global)
        self.assertIn('StringConstant("String.fromCharCode")', string_gen)
        self.assertIn('AppendValueRefJson(isolate, args, &has_field, "first_code_ref", value2)', runtime_typedarray)
        self.assertIn('AppendValueRefJson(isolate, args, &has_field, "result_ref", value3)', runtime_typedarray)
        self.assertIn('AppendValueRefJson(isolate, args, &has_field, "subject_ref", subject)', runtime_typedarray)
        self.assertIn('AppendValueRefJson(isolate, args, &has_field, "result_ref", value3)', runtime_typedarray)
        self.assertIn("xtrace:vmp-runtime:String.fromCodePoint", string_cc)
        self.assertIn(
            "  {\n"
            "    DisallowGarbageCollection no_gc;\n"
            "    CopyChars(result->GetChars(no_gc), one_byte_buffer.data(),\n"
            "              one_byte_buffer.size());\n"
            "    CopyChars(result->GetChars(no_gc) + one_byte_buffer.size(),\n"
            "              two_byte_buffer.data(), two_byte_buffer.size());\n"
            "  }\n\n"
            "  LogXTraceStringFromCodePoint(isolate, length, first_code, result);",
            string_cc,
        )
        self.assertIn("StringConstant('DataView.getUint8')", data_view_tq)
        self.assertIn("StringConstant('DataView.getInt8')", data_view_tq)
        self.assertIn("StringConstant('DataView.getUint16')", data_view_tq)
        self.assertIn("StringConstant('DataView.getInt16')", data_view_tq)
        self.assertIn("StringConstant('DataView.getUint32')", data_view_tq)
        self.assertIn("StringConstant('DataView.getInt32')", data_view_tq)
        self.assertIn("StringConstant('DataView.getBigUint64')", data_view_tq)
        self.assertIn("StringConstant('DataView.getBigInt64')", data_view_tq)
        self.assertIn("StringConstant('DataView.getFloat16')", data_view_tq)
        self.assertIn("StringConstant('DataView.getFloat32')", data_view_tq)
        self.assertIn("StringConstant('DataView.getFloat64')", data_view_tq)
        self.assertIn("StringConstant('DataView.setUint8')", data_view_tq)
        self.assertIn("StringConstant('DataView.setInt8')", data_view_tq)
        self.assertIn("StringConstant('DataView.setUint16')", data_view_tq)
        self.assertIn("StringConstant('DataView.setInt16')", data_view_tq)
        self.assertIn("StringConstant('DataView.setUint32')", data_view_tq)
        self.assertIn("StringConstant('DataView.setInt32')", data_view_tq)
        self.assertIn("StringConstant('DataView.setBigUint64')", data_view_tq)
        self.assertIn("StringConstant('DataView.setBigInt64')", data_view_tq)
        self.assertIn("StringConstant('DataView.setFloat16')", data_view_tq)
        self.assertIn("StringConstant('DataView.setFloat32')", data_view_tq)
        self.assertIn("StringConstant('DataView.setFloat64')", data_view_tq)
        self.assertIn('"result_ref"', runtime_typedarray)
        self.assertIn('"value_ref"', runtime_typedarray)
        self.assertIn("IsBigInt(*value)", runtime_typedarray)
        self.assertIn("bigint:int64:", runtime_typedarray)
        self.assertIn("bigint:uint64:", runtime_typedarray)
        self.assertIn("StringConstant('TypedArray.at')", typed_array_at)
        self.assertIn("StringConstant('Array.prototype.at')", array_at)
        self.assertIn("StringConstant('sequence_at')", array_at)
        self.assertIn("XTraceVmpRuntime", array_at)
        self.assertIn("StringConstant('TypedArray.slice')", typed_array_slice)
        self.assertIn("StringConstant('TypedArray.subarray')", typed_array_subarray)
        self.assertIn("StringConstant('TypedArray.set')", typed_array_set)
        self.assertIn("StringConstant('sequence_subarray')", typed_array_subarray)
        self.assertIn("StringConstant('sequence_set')", typed_array_set)
        self.assertIn("TypedArray.copyWithin", typed_array_builtin)
        self.assertIn("TypedArray.fill", typed_array_builtin)
        self.assertIn("TypedArray.reverse", typed_array_builtin)
        self.assertIn('"xtrace:vmp-runtime:"', typed_array_builtin)
        self.assertIn('"TypedArray.includes"', typed_array_builtin)
        self.assertIn('"TypedArray.indexOf"', typed_array_builtin)
        self.assertIn('"TypedArray.lastIndexOf"', typed_array_builtin)
        self.assertIn("LogXTraceTypedArraySearch", typed_array_builtin)
        self.assertIn("search_ref", typed_array_builtin)
        self.assertIn("from_index_ref", typed_array_builtin)
        for api_name, source in [
            ("TypedArray.find", typed_array_find),
            ("TypedArray.findIndex", typed_array_findindex),
            ("TypedArray.findLast", typed_array_findlast),
            ("TypedArray.findLastIndex", typed_array_findlastindex),
        ]:
            self.assertIn(f"StringConstant('{api_name}')", source)
            self.assertIn("StringConstant('typed_array_find')", source)
            self.assertIn("XTraceVmpRuntime", source)
        for api_name, source in [
            ("TypedArray.reduce", typed_array_reduce),
            ("TypedArray.reduceRight", typed_array_reduce_right),
        ]:
            self.assertIn(f"StringConstant('{api_name}')", source)
            self.assertIn("StringConstant('typed_array_reduce')", source)
            self.assertIn("XTraceVmpRuntime", source)
        self.assertIn("StringConstant('TypedArray.filter')", typed_array_filter)
        self.assertIn("StringConstant('typed_array_filter')", typed_array_filter)
        self.assertIn("XTraceVmpRuntime", typed_array_filter)
        for api_name, source in [
            ("TypedArray.every", typed_array_every),
            ("TypedArray.some", typed_array_some),
            ("TypedArray.forEach", typed_array_foreach),
        ]:
            self.assertIn(f"StringConstant('{api_name}')", source)
            self.assertIn("StringConstant('typed_array_iteration')", source)
            self.assertIn("XTraceVmpRuntime", source)
        for api_name, source in [
            ("TypedArray.entries", typed_array_entries),
            ("TypedArray.keys", typed_array_keys),
            ("TypedArray.values", typed_array_values),
        ]:
            self.assertIn(f"StringConstant('{api_name}')", source)
            self.assertIn("StringConstant('sequence_iterator_create')", source)
            self.assertIn("XTraceVmpRuntime", source)
        self.assertIn("StringConstant('String.prototype.@@iterator')", string_iterator_tq)
        self.assertIn("StringConstant('StringIterator.prototype.next')", string_iterator_tq)
        self.assertIn("StringConstant('sequence_iterator_create')", string_iterator_tq)
        self.assertIn("StringConstant('sequence_iterator_next_entry')", string_iterator_tq)
        self.assertIn("StringConstant('sequence_iterator_next_done')", string_iterator_tq)
        self.assertIn("XTraceVmpRuntime", string_iterator_tq)
        self.assertNotIn(
            "ASSIGN_RETURN_FAILURE_ON_EXCEPTION(\n  ASSIGN_RETURN_FAILURE_ON_EXCEPTION(",
            typed_array_builtin,
        )
        self.assertNotIn(
            "search_element, from_index_arg, index, len,\n"
            "                              search_element, from_index_arg",
            typed_array_builtin,
        )
        self.assertIn("StringConstant('TypedArray.sort')", typed_array_sort)
        self.assertIn("StringConstant('sequence_sort')", typed_array_sort)
        self.assertIn("target_index", typed_array_builtin)
        self.assertIn("source_index", typed_array_builtin)
        self.assertIn("element_count", typed_array_builtin)
        self.assertIn("comparefn_type", runtime_typedarray)
        self.assertIn("fill_value_ref", typed_array_builtin)
        self.assertIn('"source_typed_array_id"', runtime_typedarray)
        self.assertIn('"source_array_buffer_id"', runtime_typedarray)
        self.assertIn('"result_typed_array_id"', runtime_typedarray)
        self.assertIn('"result_array_buffer_id"', runtime_typedarray)
        self.assertIn('"target_offset"', runtime_typedarray)
        self.assertIn("source_length", runtime_typedarray)
        self.assertIn("StringConstant('TypedArray.join')", array_join)
        self.assertIn("StringConstant('Array.prototype.join')", array_join)
        self.assertIn('StringConstant("Array.prototype.push")', array_gen)
        self.assertIn('StringConstant("Array.prototype.pop")', array_gen)
        self.assertIn('StringConstant("Array.prototype.indexOf")', array_gen)
        self.assertIn('StringConstant("Array.prototype.includes")', array_gen)
        self.assertIn('StringConstant("array_search")', array_gen)
        self.assertIn('StringConstant("Array.prototype.entries")', array_gen)
        self.assertIn('StringConstant("Array.prototype.keys")', array_gen)
        self.assertIn('StringConstant("Array.prototype.values")', array_gen)
        self.assertIn('StringConstant("ArrayIterator.prototype.next")', array_gen)
        self.assertIn('StringConstant("sequence_iterator_create")', array_gen)
        self.assertIn('StringConstant("sequence_iterator_next_entry")', array_gen)
        self.assertIn('StringConstant("sequence_iterator_next_done")', array_gen)
        for api_name in [
            "Generator.prototype.next",
            "Generator.prototype.return",
            "Generator.prototype.throw",
        ]:
            self.assertIn(f'StringConstant("{api_name}")', generator_gen)
        self.assertIn('StringConstant("generator_resume")', generator_gen)
        self.assertIn("Runtime::kXTraceVmpRuntime", generator_gen)
        self.assertIn('"generator_resume"', runtime_typedarray)
        generator_resume_start = runtime_typedarray.index(
            'shape_string == "generator_resume"'
        )
        generator_resume_end = runtime_typedarray.index(
            'shape_string == "promise_chain"',
            generator_resume_start,
        )
        generator_resume_block = runtime_typedarray[
            generator_resume_start:generator_resume_end
        ]
        for field in [
            '"generator_ref"',
            '"input_ref"',
            '"result_ref"',
            '"resume_mode"',
            '"generator_state"',
        ]:
            self.assertIn(field, generator_resume_block)
        for api_name in [
            "AsyncGenerator.prototype.next",
            "AsyncGenerator.prototype.return",
            "AsyncGenerator.prototype.throw",
        ]:
            self.assertIn(f'StringConstant("{api_name}")', async_generator_gen)
        self.assertIn('StringConstant("async_generator_enqueue")', async_generator_gen)
        self.assertIn("Runtime::kXTraceVmpRuntime", async_generator_gen)
        self.assertIn('"async_generator_enqueue"', runtime_typedarray)
        async_generator_enqueue_start = runtime_typedarray.index(
            'shape_string == "async_generator_enqueue"'
        )
        async_generator_enqueue_end = runtime_typedarray.index(
            'shape_string == "generator_resume"',
            async_generator_enqueue_start,
        )
        async_generator_enqueue_block = runtime_typedarray[
            async_generator_enqueue_start:async_generator_enqueue_end
        ]
        for field in [
            '"generator_ref"',
            '"input_ref"',
            '"request_promise_ref"',
            '"request_promise_id"',
            '"resume_mode"',
            '"generator_state"',
        ]:
            self.assertIn(field, async_generator_enqueue_block)
        self.assertIn("StringConstant('Array.prototype.flat')", array_flat)
        self.assertIn("StringConstant('Array.prototype.flatMap')", array_flat)
        self.assertIn("StringConstant('array_flat')", array_flat)
        self.assertIn("StringConstant('array_flat_map')", array_flat)
        self.assertIn("XTraceVmpRuntime", array_flat)
        self.assertIn("StringConstant('Array.from')", array_from)
        self.assertIn("StringConstant('array_from')", array_from)
        self.assertIn("XTraceVmpRuntime", array_from)
        self.assertIn("StringConstant('Array.of')", array_of)
        self.assertIn("StringConstant('array_of')", array_of)
        self.assertIn("XTraceVmpRuntime", array_of)
        self.assertIn('"array_from"', runtime_typedarray)
        self.assertIn('"array_of"', runtime_typedarray)
        array_from_start = runtime_typedarray.index('shape_string == "array_from"')
        array_of_start = runtime_typedarray.index('shape_string == "array_of"')
        array_from_block = runtime_typedarray[array_from_start:array_of_start]
        array_of_end = runtime_typedarray.index(
            'shape_string == "array_search"',
            array_of_start,
        )
        array_of_block = runtime_typedarray[array_of_start:array_of_end]
        for field in [
            '"source_ref"',
            '"mapfn_ref"',
            '"this_arg_ref"',
            '"result_ref"',
            '"result_element_refs"',
            '"result_elements_complete"',
        ]:
            self.assertIn(field, array_from_block)
        for field in [
            '"arg_count"',
            '"result_ref"',
            '"result_element_refs"',
            '"result_elements_complete"',
        ]:
            self.assertIn(field, array_of_block)
        self.assertIn("StringConstant('Array.prototype.lastIndexOf')", array_lastindexof)
        self.assertIn("StringConstant('array_search')", array_lastindexof)
        self.assertIn("XTraceVmpRuntime", array_lastindexof)
        for api_name, source in [
            ("Array.prototype.find", array_find),
            ("Array.prototype.findIndex", array_findindex),
            ("Array.prototype.findLast", array_findlast),
            ("Array.prototype.findLastIndex", array_findlastindex),
        ]:
            self.assertIn(f"StringConstant('{api_name}')", source)
            self.assertIn("StringConstant('array_find')", source)
            self.assertIn("XTraceVmpRuntime", source)
        for api_name, source in [
            ("Array.prototype.reduce", array_reduce),
            ("Array.prototype.reduceRight", array_reduce_right),
        ]:
            self.assertIn(f"StringConstant('{api_name}')", source)
            self.assertIn("StringConstant('array_reduce')", source)
            self.assertIn("XTraceVmpRuntime", source)
        for api_name, source in [
            ("Array.prototype.map", array_map),
            ("Array.prototype.filter", array_filter),
        ]:
            self.assertIn(f"StringConstant('{api_name}')", source)
            self.assertIn("StringConstant('array_transform')", source)
            self.assertIn("XTraceVmpRuntime", source)
        for api_name, source in [
            ("Array.prototype.every", array_every),
            ("Array.prototype.some", array_some),
            ("Array.prototype.forEach", array_foreach),
        ]:
            self.assertIn(f"StringConstant('{api_name}')", source)
            self.assertIn("StringConstant('array_iteration')", source)
            self.assertIn("XTraceVmpRuntime", source)
        self.assertIn("xtrace:vmp-runtime:Array.prototype.pop", array_cc)
        self.assertIn("xtrace:vmp-runtime:Array.prototype.unshift", array_cc)
        self.assertIn("StringConstant('Array.prototype.unshift')", array_unshift)
        self.assertIn("StringConstant('array_unshift')", array_unshift)
        self.assertIn("StringConstant('Array.prototype.slice')", array_slice)
        self.assertIn("StringConstant('Array.prototype.shift')", array_shift)
        self.assertIn("StringConstant('array_shift')", array_shift)
        self.assertIn("StringConstant('Array.prototype.copyWithin')", array_copywithin)
        self.assertIn("StringConstant('array_copy_within')", array_copywithin)
        self.assertIn("xtrace:vmp-runtime:Array.prototype.fill", array_cc)
        self.assertIn('"shape":"array_fill"', array_cc)
        self.assertIn("start_index", array_cc)
        self.assertIn("end_index", array_cc)
        self.assertIn("fill_value_ref", array_cc)
        self.assertIn("StringConstant('Array.prototype.splice')", array_splice)
        self.assertIn("StringConstant('array_splice')", array_splice)
        self.assertIn("StringConstant('Array.prototype.reverse')", array_reverse)
        self.assertIn("StringConstant('array_reverse')", array_reverse)
        self.assertIn("StringConstant('Array.prototype.sort')", array_sort)
        self.assertIn("StringConstant('array_sort')", array_sort)
        self.assertIn("ArraySortContinueFromSnapshot", array_tq)
        self.assertIn("StringConstant('array_sort')", array_tq)
        self.assertIn("StringConstant('Bitwise.and')", number_tq)
        self.assertIn("StringConstant('Bitwise.or')", number_tq)
        self.assertIn("StringConstant('Bitwise.xor')", number_tq)
        self.assertIn("StringConstant('Bitwise.not')", number_tq)
        self.assertIn("StringConstant('Shift.left')", number_tq)
        self.assertIn("StringConstant('Shift.right')", number_tq)
        self.assertIn("StringConstant('Shift.unsignedRight')", number_tq)
        self.assertIn("LogXTraceBitwiseBinaryResult", number_gen)
        self.assertIn("LogXTraceBitwiseUnaryResult", number_gen)
        self.assertIn('"Bitwise.and"', number_gen)
        self.assertIn('"Bitwise.or"', number_gen)
        self.assertIn('"Bitwise.xor"', number_gen)
        self.assertIn('"Bitwise.not"', number_gen)
        self.assertIn('"Shift.left"', number_gen)
        self.assertIn('"Shift.right"', number_gen)
        self.assertIn('"Shift.unsignedRight"', number_gen)
        self.assertIn("LogXTraceInterpreterBitwiseBinaryResult", interpreter_generator)
        self.assertIn("LogXTraceInterpreterBitwiseUnaryResult", interpreter_generator)
        self.assertIn('"Bitwise.and"', interpreter_generator)
        self.assertIn('"Bitwise.or"', interpreter_generator)
        self.assertIn('"Bitwise.xor"', interpreter_generator)
        self.assertIn('"Bitwise.not"', interpreter_generator)
        self.assertIn('"Shift.left"', interpreter_generator)
        self.assertIn('"Shift.right"', interpreter_generator)
        self.assertIn('"Shift.unsignedRight"', interpreter_generator)
        self.assertIn('StringConstant("Object.keys")', object_gen)
        self.assertIn('StringConstant("Object.assign")', object_gen)
        self.assertIn('StringConstant("object_assign_source")', object_gen)
        self.assertIn('StringConstant("object_assign")', object_gen)
        self.assertIn("StringConstant('Object.prototype.toString')", object_tq)
        self.assertIn("StringConstant('object_to_string')", object_tq)
        self.assertIn("StringConstant('Array.isArray')", array_isarray_tq)
        self.assertIn("StringConstant('array_is_array')", array_isarray_tq)
        self.assertIn('StringConstant("Object.is")', object_gen)
        self.assertIn('StringConstant("same_value")', object_gen)
        self.assertIn('shape_string == "object_to_string"', runtime_typedarray)
        self.assertIn('shape_string == "array_is_array"', runtime_typedarray)
        self.assertIn('shape_string == "same_value"', runtime_typedarray)
        self.assertIn('StringConstant("Object.hasOwn")', object_gen)
        self.assertIn('StringConstant("Object.prototype.hasOwnProperty")', object_gen)
        self.assertIn('StringConstant("property_has_own")', object_gen)
        self.assertIn('shape_string == "property_has_own"', runtime_typedarray)
        self.assertIn('StringConstant("Object.create")', object_gen)
        self.assertIn('StringConstant("object_create")', object_gen)
        self.assertIn('shape_string == "object_create"', runtime_typedarray)
        self.assertIn('"prototype_ref"', runtime_typedarray)
        self.assertIn('"descriptors_ref"', runtime_typedarray)
        self.assertIn('"result_ref"', runtime_typedarray)
        self.assertIn("StringConstant('Object.getPrototypeOf')", object_tq)
        self.assertIn("StringConstant('Object.setPrototypeOf')", object_tq)
        self.assertIn("StringConstant('prototype_chain')", object_tq)
        self.assertIn("StringConstant('Reflect.getPrototypeOf')", reflect_tq)
        self.assertIn("StringConstant('Reflect.setPrototypeOf')", reflect_tq)
        self.assertIn("StringConstant('prototype_chain')", reflect_tq)
        self.assertIn('shape_string == "prototype_chain"', runtime_typedarray)
        self.assertIn('"object_ref"', runtime_typedarray)
        self.assertIn('"prototype_ref"', runtime_typedarray)
        self.assertIn('"result_ref"', runtime_typedarray)
        self.assertIn("StringConstant('Object.preventExtensions')", object_tq)
        self.assertIn("StringConstant('Object.isExtensible')", object_tq)
        self.assertIn("StringConstant('Reflect.preventExtensions')", reflect_tq)
        self.assertIn("StringConstant('Reflect.isExtensible')", reflect_tq)
        self.assertIn("StringConstant('object_integrity')", object_tq)
        self.assertIn("StringConstant('object_integrity')", reflect_tq)
        self.assertIn('shape_string == "object_integrity"', runtime_typedarray)
        self.assertIn('"operation"', runtime_typedarray)
        self.assertIn('"object_ref"', runtime_typedarray)
        self.assertIn('"result_ref"', runtime_typedarray)
        self.assertIn('"xtrace:vmp-runtime:Object.freeze:"', object_cc)
        self.assertIn('"xtrace:vmp-runtime:Object.seal:"', object_cc)
        self.assertIn('"xtrace:vmp-runtime:Object.isFrozen:"', object_cc)
        self.assertIn('"xtrace:vmp-runtime:Object.isSealed:"', object_cc)
        self.assertIn('StringConstant("Object.getOwnPropertyDescriptor")', object_gen)
        self.assertIn('shape_string == "property_descriptor"', runtime_typedarray)
        self.assertIn('"key_ref"', runtime_typedarray)
        self.assertIn('"xtrace:vmp-runtime:Object.getOwnPropertyDescriptors:"', object_cc)
        self.assertIn('"descriptor_key_refs"', object_cc)
        self.assertIn('StringConstant("Object.values")', object_gen)
        self.assertIn('StringConstant("Object.entries")', object_gen)
        self.assertIn('StringConstant("object_values")', object_gen)
        self.assertIn('StringConstant("object_entries")', object_gen)
        self.assertIn('StringConstant("Object.getOwnPropertyNames")', object_gen)
        self.assertIn("Object.defineProperty", object_cc)
        self.assertIn("LogXTracePropertyDefine", object_cc)
        self.assertIn('"descriptor_kind"', object_cc)
        self.assertIn('"descriptor_value_ref"', object_cc)
        self.assertIn("Object.defineProperties", js_objects_cc)
        self.assertIn("LogXTraceObjectDefineProperties", js_objects_cc)
        self.assertIn('"xtrace:vmp-runtime:Object.defineProperties:"', js_objects_cc)
        self.assertIn('"target_ref"', js_objects_cc)
        self.assertIn('"properties_ref"', js_objects_cc)
        self.assertIn('"descriptor_key_refs"', js_objects_cc)
        self.assertIn('"descriptor_kinds"', js_objects_cc)
        self.assertIn('"descriptor_value_refs"', js_objects_cc)
        self.assertIn('"result_ref"', js_objects_cc)
        self.assertIn("Reflect.defineProperty", reflect_cc)
        self.assertIn("LogXTraceReflectDefineProperty", reflect_cc)
        self.assertIn("Reflect.ownKeys", reflect_cc)
        self.assertIn("Reflect.getOwnPropertyDescriptor", reflect_tq)
        self.assertIn("Reflect.get", reflect_tq)
        self.assertIn("Reflect.has", reflect_tq)
        self.assertIn("StringConstant('Reflect.deleteProperty')", reflect_tq)
        self.assertIn("StringConstant('property_delete')", reflect_tq)
        self.assertIn('shape_string == "property_delete"', runtime_typedarray)
        self.assertIn("Reflect.set", reflect_cc)
        self.assertIn("LogXTraceReflectSet", reflect_cc)
        self.assertIn('"xtrace:vmp-runtime:Reflect.set:"', reflect_cc)
        self.assertIn("property_set", runtime_typedarray)
        self.assertIn('shape_string == "property_set"', runtime_typedarray)
        self.assertIn("Object.prototype.propertyIsEnumerable", object_cc)
        self.assertIn("LogXTraceObjectPropertyIsEnumerable", object_cc)
        self.assertIn('"xtrace:vmp-runtime:Object.prototype.propertyIsEnumerable:"', object_cc)
        self.assertIn("property_enumerable", runtime_typedarray)
        self.assertIn('shape_string == "property_enumerable"', runtime_typedarray)
        self.assertIn("XTraceLogArm64DispatchBuiltin", arm64_builtins)
        self.assertIn("XTraceLogArm64DispatchResultBuiltin", arm64_builtins)
        self.assertIn("Generate_ReflectConstruct", arm64_builtins)
        self.assertIn("XTraceLogArm64DispatchBuiltin(masm, 4, target", arm64_builtins)
        self.assertIn("XTraceLogArm64DispatchResultBuiltin(masm, 4, x0)", arm64_builtins)
        self.assertIn("case 4:", runtime_typedarray)
        self.assertIn('return "Reflect.construct";', runtime_typedarray)
        self.assertIn('shape_string == "construct_dispatch"', runtime_typedarray)
        self.assertIn('"target_ref"', runtime_typedarray)
        self.assertIn('"arguments_list_ref"', runtime_typedarray)
        self.assertIn('"new_target_ref"', runtime_typedarray)
        self.assertIn('"arg_count"', runtime_typedarray)
        self.assertIn("XTraceMaybeExcludeScratch", arm64_builtins)
        self.assertIn("temps.Available()->IncludesAliasOf(reg)", arm64_builtins)
        self.assertNotIn("temps.Exclude(subject);", arm64_builtins)
        self.assertNotIn("__ Drop(1);", arm64_builtins)
        self.assertIn("FrameScope scope(masm, StackFrame::INTERNAL);", arm64_builtins)
        # x0 is SmiTagged before the push so the untagged argument count stays
        # GC-safe while the runtime hook frame is active.
        self.assertIn("__ SmiTag(x0);", arm64_builtins)
        self.assertIn("__ Push(x0, x1, x2, x3, x4, x5);", arm64_builtins)
        self.assertIn("UseScratchRegisterScope temps(masm);", arm64_builtins)
        self.assertIn(
            "      __ Push(code, subject, arg1, arg2, arg3, arg4);\n"
            "    }\n"
            "    __ CallRuntime(Runtime::kXTraceVmpRuntimeDispatch);",
            arm64_builtins,
        )
        self.assertIn("Runtime::kXTraceVmpRuntimeDispatch", arm64_builtins)
        self.assertIn("XTraceLogArm64DispatchBuiltin(masm, 1, target", arm64_builtins)
        self.assertIn("XTraceLogArm64DispatchBuiltin(masm, 2, function", arm64_builtins)
        self.assertIn("__ Peek(this_arg, kSystemPointerSize);", arm64_builtins)
        self.assertIn(
            "__ Sub(forwarded_arg_count, argc, JSParameterCount(1));",
            arm64_builtins,
        )
        self.assertIn("__ SmiTag(forwarded_arg_count);", arm64_builtins)
        self.assertIn("Register first_forwarded_arg = x4;", arm64_builtins)
        self.assertIn("Register second_forwarded_arg = x5;", arm64_builtins)
        self.assertIn("__ Peek(first_forwarded_arg, 2 * kSystemPointerSize);", arm64_builtins)
        self.assertIn("__ Peek(second_forwarded_arg, 3 * kSystemPointerSize);", arm64_builtins)
        self.assertIn(
            "XTraceLogArm64DispatchBuiltin(masm, 2, function, this_arg,\n"
            "                                  first_forwarded_arg,\n"
            "                                  second_forwarded_arg,\n"
            "                                  forwarded_arg_count);",
            arm64_builtins,
        )
        self.assertIn("XTraceLogArm64DispatchBuiltin(masm, 3, receiver", arm64_builtins)
        self.assertIn("Smi::FromInt(code_id)", arm64_builtins)
        self.assertIn("Runtime_XTraceVmpRuntimeDispatch", runtime_typedarray)
        self.assertIn("DCHECK_EQ(6, args.length())", runtime_typedarray)
        self.assertIn("XTraceVmpProvenanceMode::kDispatchLight", runtime_typedarray)
        self.assertIn("AppendXTraceVmpDispatchLightProvenanceJson", runtime_typedarray)
        self.assertIn("Summarize(AllowAllocation::kNo)", runtime_typedarray)
        self.assertIn('"callsite_mode"', runtime_typedarray)
        self.assertIn('"dispatch_light"', runtime_typedarray)
        self.assertIn('"callsite_script_id"', runtime_typedarray)
        self.assertIn('"callsite_function_start_position"', runtime_typedarray)
        self.assertIn('shape_string == "dynamic_dispatch"', runtime_typedarray)
        self.assertIn('"target_function"', runtime_typedarray)
        self.assertIn('"target_type"', runtime_typedarray)
        self.assertIn('"this_type"', runtime_typedarray)
        self.assertIn('"arg_count"', runtime_typedarray)
        self.assertIn('"first_arg_ref"', runtime_typedarray)
        self.assertIn('"second_arg_ref"', runtime_typedarray)
        self.assertIn('"handler_arg_ref"', runtime_typedarray)
        self.assertIn('"arguments_list_type"', runtime_typedarray)
        self.assertIn('"target_id"', runtime_typedarray)
        self.assertIn('"arguments_list_id"', runtime_typedarray)
        self.assertIn('"state_object_id"', runtime_typedarray)
        self.assertIn('"register_ref"', runtime_typedarray)
        self.assertIn('"state_ref"', runtime_typedarray)
        self.assertIn('"target_ref"', runtime_typedarray)
        self.assertIn('"register_source_ref"', runtime_typedarray)
        self.assertIn('"handler_return_ref"', runtime_typedarray)
        self.assertIn('"dispatch_id"', runtime_typedarray)
        self.assertIn('"entry_only"', runtime_typedarray)
        self.assertIn('"entry_and_result"', runtime_typedarray)
        self.assertIn("std::vector<XTracePendingDispatchSource>", runtime_typedarray)
        self.assertIn('"Reflect.apply"', runtime_typedarray)
        self.assertIn('"Function.prototype.call"', runtime_typedarray)
        self.assertIn('"Function.prototype.apply"', runtime_typedarray)
        self.assertIn("Runtime_XTraceVmpRuntimeDispatchResult", runtime_typedarray)
        self.assertIn("if (!has_pending_source && code == 4)", runtime_typedarray)
        self.assertNotIn("kXTraceDispatchResultEventLimit", runtime_typedarray)
        self.assertNotIn("XTraceShouldLogDispatchResult", runtime_typedarray)
        self.assertNotIn("xtrace_dispatch_result_counters", runtime_typedarray)
        self.assertNotIn("sample_index", runtime_typedarray)
        self.assertIn('shape_string == "dynamic_dispatch_result"', runtime_typedarray)
        self.assertIn('"dispatch_code"', runtime_typedarray)
        self.assertNotIn('"dispatch_result_index"', runtime_typedarray)
        self.assertIn(
            'AppendValueRefJson(isolate, args, &has_field, "result_ref", value3)',
            runtime_typedarray,
        )
        self.assertNotIn("GenerateCallAndLogXTraceResult", arm64_builtins)
        self.assertIn("Runtime::kXTraceVmpRuntimeDispatchResult", arm64_builtins)
        self.assertNotIn("GenerateXTraceVmpDispatchCall", arm64_builtins)
        self.assertNotIn("Runtime::kXTraceVmpDispatchCall", arm64_builtins)
        self.assertIn('StringConstant("Map.prototype.get")', collections_gen)
        self.assertIn('StringConstant("Map.prototype.has")', collections_gen)
        self.assertIn('StringConstant("Map.prototype.set")', collections_gen)
        self.assertIn('StringConstant("Map.prototype.delete")', collections_gen)
        self.assertIn('StringConstant("Map.prototype.getOrInsert")', collections_gen)
        self.assertIn(
            'StringConstant("Map.prototype.getOrInsertComputed")',
            collections_gen,
        )
        self.assertIn('StringConstant("Map.prototype.forEach")', collections_gen)
        self.assertIn('StringConstant("Map.prototype.entries")', collections_gen)
        self.assertIn('StringConstant("Map.prototype.keys")', collections_gen)
        self.assertIn('StringConstant("Map.prototype.values")', collections_gen)
        self.assertIn('StringConstant("MapIterator.prototype.next")', collections_gen)
        self.assertIn('StringConstant("Set.prototype.add")', collections_gen)
        self.assertIn('StringConstant("Set.prototype.has")', collections_gen)
        self.assertIn('StringConstant("Set.prototype.delete")', collections_gen)
        self.assertIn('StringConstant("Set.prototype.forEach")', collections_gen)
        self.assertIn('StringConstant("Set.prototype.entries")', collections_gen)
        self.assertIn('StringConstant("Set.prototype.values")', collections_gen)
        self.assertIn('StringConstant("SetIterator.prototype.next")', collections_gen)
        self.assertIn('StringConstant("WeakMap.prototype.get")', collections_gen)
        self.assertIn('StringConstant("WeakMap.prototype.has")', collections_gen)
        self.assertIn('StringConstant("WeakMap.prototype.set")', collections_gen)
        self.assertIn('StringConstant("WeakMap.prototype.delete")', collections_gen)
        self.assertIn(
            'StringConstant("WeakMap.prototype.getOrInsert")',
            collections_gen,
        )
        self.assertIn(
            'StringConstant("WeakMap.prototype.getOrInsertComputed")',
            collections_gen,
        )
        self.assertIn('StringConstant("WeakSet.prototype.add")', collections_gen)
        self.assertIn('StringConstant("WeakSet.prototype.has")', collections_gen)
        self.assertIn('StringConstant("WeakSet.prototype.delete")', collections_gen)
        self.assertIn("LogXTraceCollectionClear", builtins_collections)
        self.assertIn('"xtrace:vmp-runtime:"', builtins_collections)
        self.assertIn('"Map.prototype.clear"', builtins_collections)
        self.assertIn('"Set.prototype.clear"', builtins_collections)
        self.assertIn("event.append(api)", builtins_collections)
        self.assertIn('"collection_ref"', builtins_collections)
        self.assertIn('"size_before"', builtins_collections)
        self.assertIn('"result_ref"', builtins_collections)
        self.assertIn("OrderedHashMap", builtins_collections)
        self.assertIn("OrderedHashSet", builtins_collections)
        self.assertIn("StringConstant('Proxy.get')", proxy_get_tq)
        self.assertIn("StringConstant('Proxy.set')", proxy_set_tq)
        self.assertIn("StringConstant('proxy_set')", proxy_set_tq)
        self.assertIn("key, value, False", proxy_set_tq)
        self.assertIn("StringConstant('Proxy.has')", proxy_has_tq)
        self.assertIn("StringConstant('Proxy.deleteProperty')", proxy_delete_tq)
        self.assertIn("StringConstant('proxy_delete')", proxy_delete_tq)
        self.assertIn("LogXTraceProxySet", objects_cc)
        self.assertIn("xtrace:vmp-runtime:Proxy.set", objects_cc)
        self.assertIn("xtrace:vmp-runtime:Proxy.deleteProperty", objects_cc)
        self.assertIn("xtrace:vmp-runtime:Proxy.defineProperty", objects_cc)
        self.assertIn("xtrace:vmp-runtime:Proxy.getOwnPropertyDescriptor", objects_cc)
        self.assertIn("XTraceProxyStringJson", objects_cc)
        self.assertIn("string->ToCString()", objects_cc)
        self.assertNotIn("kXTraceProxyPreviewChars", objects_cc)
        self.assertNotIn("ToCString(0", objects_cc)
        self.assertNotIn("std::min(string->length()", objects_cc)
        self.assertIn("xtrace:vmp-runtime:Proxy.ownKeys", keys_cc)
        self.assertIn('"sequence_at"', runtime_typedarray)
        sequence_at_start = runtime_typedarray.index('shape_string == "sequence_at"')
        sequence_at_end = runtime_typedarray.index(
            '} else if (shape_string == "sequence_slice")',
            sequence_at_start,
        )
        sequence_at_block = runtime_typedarray[sequence_at_start:sequence_at_end]
        self.assertIn('"result_ref"', sequence_at_block)
        self.assertIn('"array_search"', runtime_typedarray)
        array_search_start = runtime_typedarray.index('shape_string == "array_search"')
        array_search_end = runtime_typedarray.index(
            '} else if (shape_string == "sequence_slice")',
            array_search_start,
        )
        array_search_block = runtime_typedarray[array_search_start:array_search_end]
        self.assertIn('"search_ref"', array_search_block)
        self.assertIn('"from_index_ref"', array_search_block)
        self.assertIn('"result_ref"', array_search_block)
        self.assertIn('"array_find"', runtime_typedarray)
        array_find_start = runtime_typedarray.index('shape_string == "array_find"')
        array_find_end = runtime_typedarray.index(
            '} else if (shape_string == "array_push")',
            array_find_start,
        )
        array_find_block = runtime_typedarray[array_find_start:array_find_end]
        self.assertIn('"callback_ref"', array_find_block)
        self.assertIn('"this_arg_ref"', array_find_block)
        self.assertIn('"result_ref"', array_find_block)
        self.assertIn('"array_reduce"', runtime_typedarray)
        array_reduce_start = runtime_typedarray.index('shape_string == "array_reduce"')
        array_reduce_end = runtime_typedarray.index(
            '} else if (shape_string == "sequence_slice")',
            array_reduce_start,
        )
        array_reduce_block = runtime_typedarray[array_reduce_start:array_reduce_end]
        self.assertIn('"callback_ref"', array_reduce_block)
        self.assertIn('"initial_value_ref"', array_reduce_block)
        self.assertIn('"result_ref"', array_reduce_block)
        self.assertIn('"array_transform"', runtime_typedarray)
        array_transform_start = runtime_typedarray.index('shape_string == "array_transform"')
        array_transform_end = runtime_typedarray.index(
            '} else if (shape_string == "sequence_slice")',
            array_transform_start,
        )
        array_transform_block = runtime_typedarray[array_transform_start:array_transform_end]
        self.assertIn('"callback_ref"', array_transform_block)
        self.assertIn('"this_arg_ref"', array_transform_block)
        self.assertIn('"result_ref"', array_transform_block)
        self.assertIn('"result_element_refs"', array_transform_block)
        self.assertIn('"array_iteration"', runtime_typedarray)
        array_iteration_start = runtime_typedarray.index('shape_string == "array_iteration"')
        array_iteration_end = runtime_typedarray.index(
            '} else if (shape_string == "sequence_slice")',
            array_iteration_start,
        )
        array_iteration_block = runtime_typedarray[array_iteration_start:array_iteration_end]
        self.assertIn('"callback_ref"', array_iteration_block)
        self.assertIn('"this_arg_ref"', array_iteration_block)
        self.assertIn('"result_ref"', array_iteration_block)
        self.assertIn('"sequence_slice"', runtime_typedarray)
        self.assertIn('"sequence_join"', runtime_typedarray)
        self.assertIn('"array_push"', runtime_typedarray)
        self.assertIn('"array_pop"', runtime_typedarray)
        self.assertIn('"array_unshift"', runtime_typedarray)
        self.assertIn('"array_shift"', runtime_typedarray)
        self.assertIn('"array_splice"', runtime_typedarray)
        self.assertIn('"array_reverse"', runtime_typedarray)
        self.assertIn('"array_sort"', runtime_typedarray)
        self.assertIn('"array_copy_within"', runtime_typedarray)
        self.assertIn('"array_fill"', array_cc)
        self.assertIn("auto log_array_push = [&](TNode<Object> length_after,", array_gen)
        self.assertIn("auto log_array_pop = [&](TNode<Object> length_before,", array_gen)
        self.assertIn("TNode<Object> first_arg)", array_gen)
        self.assertIn(
            "TNode<Object> first_push_arg = args.GetOptionalArgumentValue(0);",
            array_gen,
        )
        self.assertNotIn("args.AtIndex(0);", array_gen)
        self.assertIn("log_array_push(new_length, first_push_arg);", array_gen)
        self.assertIn('"first_arg_ref"', runtime_typedarray)
        self.assertIn('"length_before"', runtime_typedarray)
        self.assertIn('"length_after"', runtime_typedarray)
        self.assertIn('"result_ref"', runtime_typedarray)
        self.assertIn('"argc"', runtime_typedarray)
        self.assertIn(
            'AppendValueRefJson(isolate, args, &has_field, "first_arg_ref", value3);',
            runtime_typedarray,
        )
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "first_arg", value3);',
            runtime_typedarray,
        )
        self.assertIn("kXTraceVmpStackFrameLimit", runtime_typedarray)
        self.assertIn("AppendXTraceVmpCallsiteJson(isolate, args, &has_field);", runtime_typedarray)
        self.assertIn("AppendXTraceVmpStackJson(isolate, args, &has_field);", runtime_typedarray)
        self.assertIn('"callsite_function"', runtime_typedarray)
        self.assertIn('"callsite_script"', runtime_typedarray)
        self.assertIn('"callsite_source_position"', runtime_typedarray)
        self.assertIn('"js_stack"', runtime_typedarray)
        self.assertIn('"js_stack_truncated"', runtime_typedarray)
        self.assertIn('"object_assign_source"', runtime_typedarray)
        self.assertIn('"object_assign"', runtime_typedarray)
        self.assertIn('"construct_dispatch"', runtime_typedarray)
        self.assertIn('"source_index"', runtime_typedarray)
        self.assertIn('"source_count"', runtime_typedarray)
        self.assertIn('"source_ref"', runtime_typedarray)
        self.assertIn('"object_keys"', runtime_typedarray)
        self.assertIn('"object_values"', runtime_typedarray)
        self.assertIn('"object_entries"', runtime_typedarray)
        self.assertIn('"result_entries"', runtime_typedarray)
        self.assertIn('"property_get"', runtime_typedarray)
        self.assertIn('"property_has"', runtime_typedarray)
        self.assertIn('"object_to_string"', runtime_typedarray)
        self.assertIn('"array_is_array"', runtime_typedarray)
        self.assertIn('"same_value"', runtime_typedarray)
        self.assertIn('"property_has_own"', runtime_typedarray)
        self.assertIn('"property_delete"', runtime_typedarray)
        self.assertIn('"property_set"', runtime_typedarray)
        self.assertIn('"property_enumerable"', runtime_typedarray)
        self.assertIn('"property_descriptor"', runtime_typedarray)
        self.assertIn('"collection_get"', runtime_typedarray)
        self.assertIn('"collection_has"', runtime_typedarray)
        self.assertIn('"collection_set"', runtime_typedarray)
        self.assertIn('"collection_add"', runtime_typedarray)
        self.assertIn('"collection_delete"', runtime_typedarray)
        self.assertIn('"collection_get_or_insert_existing"', runtime_typedarray)
        self.assertIn('"collection_get_or_insert_inserted"', runtime_typedarray)
        self.assertIn('"collection_get_or_insert_computed_existing"', runtime_typedarray)
        self.assertIn('"collection_get_or_insert_computed_inserted"', runtime_typedarray)
        self.assertIn('"collection_for_each_setup"', runtime_typedarray)
        self.assertIn('"collection_for_each_entry"', runtime_typedarray)
        self.assertIn('"collection_for_each_done"', runtime_typedarray)
        self.assertIn('"collection_iterator_create"', runtime_typedarray)
        self.assertIn('"collection_iterator_next_entry"', runtime_typedarray)
        self.assertIn('"collection_iterator_next_done"', runtime_typedarray)
        self.assertIn('"sequence_iterator_create"', runtime_typedarray)
        self.assertIn('"sequence_iterator_next_entry"', runtime_typedarray)
        self.assertIn('"sequence_iterator_next_done"', runtime_typedarray)
        self.assertIn('"collection_ref"', runtime_typedarray)
        self.assertIn('"proxy_get"', runtime_typedarray)
        self.assertIn('"proxy_set"', runtime_typedarray)
        self.assertIn('"proxy_has"', runtime_typedarray)
        self.assertIn('"proxy_delete"', runtime_typedarray)
        self.assertIn('"bitwise_binary"', runtime_typedarray)
        self.assertIn('"bitwise_unary"', runtime_typedarray)
        self.assertIn("AppendValueRefJson", runtime_typedarray)
        self.assertIn('"x_ref"', runtime_typedarray)
        self.assertIn('"y_ref"', runtime_typedarray)
        self.assertIn('"left_ref"', runtime_typedarray)
        self.assertIn('"right_ref"', runtime_typedarray)
        self.assertIn('"target_ref"', runtime_typedarray)
        self.assertIn('"value_ref"', runtime_typedarray)
        self.assertIn('"receiver_ref"', runtime_typedarray)
        self.assertIn('"result_ref"', runtime_typedarray)
        self.assertIn('"value_ref"', runtime_typedarray)
        self.assertIn('"result_ref"', runtime_typedarray)
        self.assertIn("XTraceRememberValueSource", runtime_typedarray)
        collection_iterator_subject_link_start = runtime_typedarray.index(
            'shape == "collection_iterator_next_entry"'
        )
        collection_iterator_subject_link_end = runtime_typedarray.index(
            '} else if (shape == "proxy_get"',
            collection_iterator_subject_link_start,
        )
        collection_iterator_subject_link_block = runtime_typedarray[
            collection_iterator_subject_link_start:collection_iterator_subject_link_end
        ]
        sequence_iterator_create_subject_link_start = runtime_typedarray.index(
            'shape == "sequence_iterator_create"'
        )
        sequence_iterator_create_subject_link_end = runtime_typedarray.index(
            '} else if (shape == "sequence_iterator_next_entry"',
            sequence_iterator_create_subject_link_start,
        )
        sequence_iterator_create_subject_link_block = runtime_typedarray[
            sequence_iterator_create_subject_link_start:sequence_iterator_create_subject_link_end
        ]
        sequence_iterator_subject_link_start = runtime_typedarray.index(
            'shape == "sequence_iterator_next_entry"'
        )
        sequence_iterator_subject_link_end = runtime_typedarray.index(
            '} else if (shape == "proxy_get"',
            sequence_iterator_subject_link_start,
        )
        sequence_iterator_subject_link_block = runtime_typedarray[
            sequence_iterator_subject_link_start:sequence_iterator_subject_link_end
        ]
        collection_get_start = runtime_typedarray.index('shape_string == "collection_get"')
        collection_has_start = runtime_typedarray.index('shape_string == "collection_has"')
        collection_set_start = runtime_typedarray.index('shape_string == "collection_set"')
        collection_add_start = runtime_typedarray.index('shape_string == "collection_add"')
        collection_delete_start = runtime_typedarray.index('shape_string == "collection_delete"')
        collection_get_or_insert_start = runtime_typedarray.index(
            'shape_string == "collection_get_or_insert_existing"'
        )
        collection_for_each_start = runtime_typedarray.index(
            'shape_string == "collection_for_each_setup"'
        )
        collection_iterator_create_start = runtime_typedarray.index(
            'shape_string == "collection_iterator_create"'
        )
        collection_iterator_next_entry_start = runtime_typedarray.index(
            'shape_string == "collection_iterator_next_entry"'
        )
        collection_iterator_next_done_start = runtime_typedarray.index(
            'shape_string == "collection_iterator_next_done"'
        )
        sequence_iterator_create_start = runtime_typedarray.index(
            'shape_string == "sequence_iterator_create"'
        )
        sequence_iterator_next_entry_start = runtime_typedarray.index(
            'shape_string == "sequence_iterator_next_entry"'
        )
        sequence_iterator_next_done_start = runtime_typedarray.index(
            'shape_string == "sequence_iterator_next_done"'
        )
        proxy_get_start = runtime_typedarray.index('shape_string == "proxy_get"')
        collection_get_block = runtime_typedarray[collection_get_start:collection_has_start]
        collection_has_block = runtime_typedarray[collection_has_start:collection_set_start]
        collection_set_block = runtime_typedarray[collection_set_start:collection_add_start]
        collection_add_block = runtime_typedarray[collection_add_start:collection_delete_start]
        collection_delete_block = runtime_typedarray[
            collection_delete_start:collection_get_or_insert_start
        ]
        collection_get_or_insert_block = runtime_typedarray[
            collection_get_or_insert_start:collection_for_each_start
        ]
        collection_for_each_block = runtime_typedarray[
            collection_for_each_start:collection_iterator_create_start
        ]
        collection_iterator_create_block = runtime_typedarray[
            collection_iterator_create_start:collection_iterator_next_entry_start
        ]
        collection_iterator_next_entry_block = runtime_typedarray[
            collection_iterator_next_entry_start:collection_iterator_next_done_start
        ]
        collection_iterator_next_done_block = runtime_typedarray[
            collection_iterator_next_done_start:sequence_iterator_create_start
        ]
        sequence_iterator_create_block = runtime_typedarray[
            sequence_iterator_create_start:sequence_iterator_next_entry_start
        ]
        sequence_iterator_next_entry_block = runtime_typedarray[
            sequence_iterator_next_entry_start:sequence_iterator_next_done_start
        ]
        sequence_iterator_next_done_block = runtime_typedarray[
            sequence_iterator_next_done_start:proxy_get_start
        ]
        for block in [
            collection_get_block,
            collection_has_block,
            collection_set_block,
            collection_add_block,
            collection_delete_block,
        ]:
            self.assertIn('"key_ref"', block)
            self.assertIn('"result_ref"', block)
        self.assertIn('"value_ref"', collection_set_block)
        self.assertIn('"value_ref"', collection_add_block)
        self.assertIn(
            'AppendStringMaterialJson(args, &has_field, "value", value1);',
            collection_add_block,
        )
        self.assertIn('"value_ref"', collection_get_or_insert_block)
        self.assertIn('"callback_ref"', collection_get_or_insert_block)
        self.assertIn('"inserted"', collection_get_or_insert_block)
        self.assertIn('"callback_ref"', collection_for_each_block)
        self.assertIn('"this_arg_ref"', collection_for_each_block)
        self.assertIn('"key_ref"', collection_for_each_block)
        self.assertIn('"value_ref"', collection_for_each_block)
        self.assertIn('"result_ref"', collection_for_each_block)
        self.assertIn('"iterator_ref"', collection_iterator_create_block)
        self.assertIn('"iteration_kind"', collection_iterator_create_block)
        self.assertIn('"result_ref"', collection_iterator_create_block)
        self.assertIn('"iterator_ref"', collection_iterator_subject_link_block)
        for block in [
            collection_iterator_next_entry_block,
            collection_iterator_next_done_block,
        ]:
            self.assertIn('"key_ref"', block)
            self.assertIn('"value_ref"', block)
            self.assertIn('"result_ref"', block)
            self.assertIn('"done"', block)
        self.assertIn('"sequence_ref"', sequence_iterator_create_subject_link_block)
        self.assertIn('"iterator_ref"', sequence_iterator_create_block)
        self.assertIn('"iteration_kind"', sequence_iterator_create_block)
        self.assertIn('"result_ref"', sequence_iterator_create_block)
        self.assertIn('"iterator_ref"', sequence_iterator_subject_link_block)
        for block in [
            sequence_iterator_next_entry_block,
            sequence_iterator_next_done_block,
        ]:
            self.assertIn('"key_ref"', block)
            self.assertIn('"value_ref"', block)
            self.assertIn('"result_ref"', block)
            self.assertIn('"done"', block)
        self.assertIn("AppendBitwiseSourceRefJson", runtime_typedarray)
        self.assertIn('"left_source_ref"', runtime_typedarray)
        self.assertIn('"right_source_ref"', runtime_typedarray)
        self.assertIn('"left_register_ref"', runtime_typedarray)
        self.assertIn('"right_register_ref"', runtime_typedarray)
        self.assertIn('"ArrayBuffer.constructor"', array_buffer)
        self.assertIn('"ArrayBuffer.prototype.slice"', array_buffer)
        self.assertIn("source_byte_length", array_buffer)
        self.assertIn("result_byte_length", array_buffer)

    def test_v8_patch_exports_array_buffer_slice_byte_material_hook(self):
        v8_patch = (
            ROOT
            / "patches"
            / "0002-xtrace-v8-vmp-hooks.patch"
        ).read_text(encoding="utf-8")

        self.assertIn("LogXTraceArrayBufferSlice", v8_patch)
        self.assertIn("source_byte_length", v8_patch)
        self.assertIn("result_byte_length", v8_patch)

    @requires_chromium_tree
    def test_xtrace_vmp_hooks_emit_object_linking_fields(self):
        v8_root = ROOT / "chromium" / "src" / "v8"
        runtime_header = (v8_root / "src" / "runtime" / "runtime.h").read_text(
            encoding="utf-8"
        )
        runtime_typedarray = (
            v8_root / "src" / "runtime" / "runtime-typedarray.cc"
        ).read_text(encoding="utf-8")
        base_tq = (v8_root / "src" / "builtins" / "base.tq").read_text(
            encoding="utf-8"
        )
        initializer = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "bindings"
            / "core"
            / "v8"
            / "v8_initializer.cc"
        ).read_text(encoding="utf-8")
        data_view_tq = (
            v8_root / "src" / "builtins" / "data-view.tq"
        ).read_text(encoding="utf-8")
        typed_array_builtin = (
            v8_root / "src" / "builtins" / "builtins-typed-array.cc"
        ).read_text(encoding="utf-8")
        text_encoder = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "encoding"
            / "text_encoder.cc"
        ).read_text(encoding="utf-8")
        text_decoder = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "modules"
            / "encoding"
            / "text_decoder.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("F(XTraceVmpRuntime, 6, 1)", runtime_header)
        self.assertIn(
            "extern runtime XTraceVmpRuntime(Context, String, String, JSAny, JSAny, JSAny, JSAny): JSAny",
            base_tq,
        )
        self.assertIn("AppendDataViewLinkingJson", runtime_typedarray)
        self.assertIn('"data_view_id"', runtime_typedarray)
        self.assertIn('"array_buffer_id"', runtime_typedarray)
        self.assertIn('"typed_array_id"', runtime_typedarray)
        self.assertIn('"typed_array_find"', runtime_typedarray)
        typed_array_find_start = runtime_typedarray.index('shape_string == "typed_array_find"')
        typed_array_find_end = runtime_typedarray.index(
            '} else if (shape_string == "sequence_slice")',
            typed_array_find_start,
        )
        typed_array_find_block = runtime_typedarray[typed_array_find_start:typed_array_find_end]
        self.assertIn('"callback_ref"', typed_array_find_block)
        self.assertIn('"this_arg_ref"', typed_array_find_block)
        self.assertIn('"result_ref"', typed_array_find_block)
        self.assertIn('"typed_array_reduce"', runtime_typedarray)
        typed_array_reduce_start = runtime_typedarray.index('shape_string == "typed_array_reduce"')
        typed_array_reduce_end = runtime_typedarray.index(
            '} else if (shape_string == "sequence_slice")',
            typed_array_reduce_start,
        )
        typed_array_reduce_block = runtime_typedarray[typed_array_reduce_start:typed_array_reduce_end]
        self.assertIn('"callback_ref"', typed_array_reduce_block)
        self.assertIn('"initial_value_ref"', typed_array_reduce_block)
        self.assertIn('"result_ref"', typed_array_reduce_block)
        self.assertIn('"typed_array_filter"', runtime_typedarray)
        typed_array_filter_start = runtime_typedarray.index('shape_string == "typed_array_filter"')
        typed_array_filter_end = runtime_typedarray.index(
            '} else if (shape_string == "sequence_slice")',
            typed_array_filter_start,
        )
        typed_array_filter_block = runtime_typedarray[typed_array_filter_start:typed_array_filter_end]
        self.assertIn('"callback_ref"', typed_array_filter_block)
        self.assertIn('"this_arg_ref"', typed_array_filter_block)
        self.assertIn('"result_ref"', typed_array_filter_block)
        self.assertIn('"result_element_refs"', typed_array_filter_block)
        self.assertIn('"typed_array_iteration"', runtime_typedarray)
        typed_array_iteration_start = runtime_typedarray.index('shape_string == "typed_array_iteration"')
        typed_array_iteration_end = runtime_typedarray.index(
            '} else if (shape_string == "sequence_slice")',
            typed_array_iteration_start,
        )
        typed_array_iteration_block = runtime_typedarray[typed_array_iteration_start:typed_array_iteration_end]
        self.assertIn('"callback_ref"', typed_array_iteration_block)
        self.assertIn('"this_arg_ref"', typed_array_iteration_block)
        self.assertIn('"result_ref"', typed_array_iteration_block)
        self.assertIn('"array_flat"', runtime_typedarray)
        array_flat_start = runtime_typedarray.index('shape_string == "array_flat"')
        array_flat_end = runtime_typedarray.index(
            '} else if (shape_string == "array_iteration")',
            array_flat_start,
        )
        array_flat_block = runtime_typedarray[array_flat_start:array_flat_end]
        self.assertIn('"depth_ref"', array_flat_block)
        self.assertIn('"result_ref"', array_flat_block)
        self.assertIn('"result_element_refs"', array_flat_block)
        self.assertIn('"array_flat_map"', runtime_typedarray)
        array_flat_map_start = runtime_typedarray.index('shape_string == "array_flat_map"')
        array_flat_map_end = runtime_typedarray.index(
            '} else if (shape_string == "array_iteration")',
            array_flat_map_start,
        )
        array_flat_map_block = runtime_typedarray[array_flat_map_start:array_flat_map_end]
        self.assertIn('"callback_ref"', array_flat_map_block)
        self.assertIn('"this_arg_ref"', array_flat_map_block)
        self.assertIn('"result_ref"', array_flat_map_block)
        self.assertIn('"result_element_refs"', array_flat_map_block)
        self.assertIn("Object::GetOrCreateHash", runtime_typedarray)
        self.assertIn("StringConstant('data_view_get'), receiver", data_view_tq)
        self.assertIn("receiver, offset, isLittleEndian", data_view_tq)
        self.assertIn("StringConstant('data_view_set'), receiver", data_view_tq)
        self.assertIn("receiver, offset, value", data_view_tq)
        self.assertIn("TypedArray.buffer.get", typed_array_builtin)
        self.assertIn("typed_array_id", typed_array_builtin)
        self.assertIn("array_buffer_id", typed_array_builtin)
        self.assertIn("Object::GetOrCreateHash", typed_array_builtin)
        self.assertIn('api.compare(api.size() - 4, 4, ".get") == 0', initializer)
        self.assertIn(
            'XTraceLogger::LogEventNoStack("reverse", phase, api.c_str(), args_json)',
            initializer,
        )
        self.assertIn("text_encoder_id", text_encoder)
        self.assertIn("input_ref", text_encoder)
        self.assertIn("XTraceLogger::StringHashRefJson(input)", text_encoder)
        self.assertIn("XTraceLogger::StringHashRefJson(source)", text_encoder)
        self.assertIn("result_typed_array_id", text_encoder)
        self.assertIn("result_array_buffer_id", text_encoder)
        self.assertIn("destination_typed_array_id", text_encoder)
        self.assertIn("destination_array_buffer_id", text_encoder)
        self.assertIn("text_decoder_id", text_decoder)

    def test_xtrace_logger_captures_javascript_stack(self):
        logger = (
            ROOT
            / "chromium"
            / "src"
            / "third_party"
            / "blink"
            / "renderer"
            / "platform"
            / "xtrace"
            / "xtrace_logger.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("CaptureJavaScriptStack", logger)
        self.assertIn("v8::StackTrace::CurrentStackTrace", logger)
        self.assertIn("v8::StackTrace::kDetailed", logger)
        self.assertNotIn('line.append(",\\"stack\\":[]")', logger)

    @requires_chromium_tree
    def test_xtrace_vmp_native_dispatch_stub_hooks_are_disabled(self):
        blink_root = ROOT / "chromium" / "src" / "third_party" / "blink"
        initializer = (
            blink_root
            / "renderer"
            / "bindings"
            / "core"
            / "v8"
            / "v8_initializer.cc"
        ).read_text(encoding="utf-8")
        logger_header = (
            blink_root / "renderer" / "platform" / "xtrace" / "xtrace_logger.h"
        ).read_text(encoding="utf-8")
        logger = (
            blink_root
            / "renderer"
            / "platform"
            / "xtrace"
            / "xtrace_logger.cc"
        ).read_text(encoding="utf-8")
        arm64_builtins = (
            ROOT
            / "chromium"
            / "src"
            / "v8"
            / "src"
            / "builtins"
            / "arm64"
            / "builtins-arm64.cc"
        ).read_text(encoding="utf-8")

        self.assertIn("LogEventNoStack", logger_header)
        self.assertNotIn("XTraceIsVmpDispatchApi", initializer)
        self.assertIn("XTraceLogger::LogEventNoStack", initializer)
        self.assertNotIn("include_stack", logger)
        self.assertNotIn("GenerateXTraceVmpDispatchCall", arm64_builtins)

    def test_gui_start_script_uses_launchservices(self):
        script = (ROOT / "scripts" / "start_xtrace_gui.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("open -n", script)
        self.assertIn("Electron.app", script)
        self.assertIn("xtrace-gui", script)


if __name__ == "__main__":
    unittest.main()
