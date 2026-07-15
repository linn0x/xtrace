import json
import socketserver
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from scripts import serve_test_page


ROOT = Path(__file__).resolve().parents[1]


class SmokeServerTests(unittest.TestCase):
    def test_reverse_smoke_page_exercises_webcrypto_signature_pipeline(self):
        page = ROOT / "test-pages" / "reverse-smoke.html"
        readme = ROOT / "README.md"

        content = page.read_text(encoding="utf-8")
        docs = readme.read_text(encoding="utf-8")

        self.assertIn("crypto.subtle.digest", content)
        self.assertIn("crypto.subtle.importKey", content)
        self.assertIn("crypto.subtle.sign", content)
        self.assertIn("HMAC", content)
        self.assertIn("results.hmacBytes", content)
        self.assertIn("--require-vmp-family hash_crypto", docs)
        self.assertIn("--expect SubtleCrypto.importKey", docs)
        self.assertIn("--expect SubtleCrypto.sign", docs)

    def test_reverse_smoke_page_exercises_formdata_material_pipeline(self):
        page = ROOT / "test-pages" / "reverse-smoke.html"

        content = page.read_text(encoding="utf-8")

        self.assertIn("new FormData()", content)
        self.assertIn("formData.append", content)
        self.assertIn("formData.set", content)
        self.assertIn("formData.get(", content)
        self.assertIn("formData.getAll", content)
        self.assertIn("formData.has", content)
        self.assertIn("formData.delete", content)
        self.assertIn("results.formData", content)

    def test_reverse_smoke_page_exercises_header_read_pipeline(self):
        page = ROOT / "test-pages" / "reverse-smoke.html"

        content = page.read_text(encoding="utf-8")

        self.assertIn("headers.get", content)
        self.assertIn("headers.has", content)
        self.assertIn("results.headerHas", content)

    def test_reverse_smoke_page_exercises_request_read_pipeline(self):
        page = ROOT / "test-pages" / "reverse-smoke.html"

        content = page.read_text(encoding="utf-8")

        self.assertIn("request.url", content)
        self.assertIn("request.method", content)
        self.assertIn("request.headers.get", content)
        self.assertIn("request.clone()", content)
        self.assertIn("clonedRequest.text()", content)
        self.assertIn("typedBodyRequest", content)
        self.assertIn("results.requestMethod", content)
        self.assertIn("results.requestHeader", content)
        self.assertIn("results.clonedRequestHeader", content)
        self.assertIn("results.clonedRequestTextLength", content)
        self.assertIn("results.typedBodyRequestUrl", content)
        self.assertIn("fetchResponse.arrayBuffer()", content)
        self.assertIn("results.fetchArrayBufferBytes", content)

    def test_reverse_smoke_page_exercises_xhr_binary_body_pipeline(self):
        page = ROOT / "test-pages" / "reverse-smoke.html"

        content = page.read_text(encoding="utf-8")

        self.assertIn("typedBodyXhr", content)
        self.assertIn("typedBodyXhr.send(encodedBytes)", content)
        self.assertIn("results.typedBodyXhrStatus", content)
        self.assertIn("results.typedBodyXhrBodySize", content)

    def test_reverse_smoke_page_exercises_typed_array_byte_material_moves(self):
        page = ROOT / "test-pages" / "reverse-smoke.html"

        content = page.read_text(encoding="utf-8")

        self.assertIn("typed.subarray", content)
        self.assertIn("transformSource.replace", content)
        self.assertIn("results.stringReplace", content)
        self.assertIn("transformSource.split", content)
        self.assertIn("results.stringSplitLength", content)
        self.assertIn("charAt", content)
        self.assertIn("results.charAt", content)
        self.assertIn("transformSource.concat", content)
        self.assertIn("results.stringConcat", content)
        self.assertIn("transformSource.substr(", content)
        self.assertIn("results.stringSubstr =", content)
        self.assertIn("padStart", content)
        self.assertIn("results.stringPadStart", content)
        self.assertIn("toString(16)", content)
        self.assertIn("results.numberToStringHex", content)
        self.assertIn("0x1234n.toString(16)", content)
        self.assertIn("results.bigIntToStringHex", content)
        self.assertIn("padEnd", content)
        self.assertIn("results.stringPadEnd", content)
        self.assertIn("toLowerCase", content)
        self.assertIn("results.stringLower", content)
        self.assertIn("toUpperCase", content)
        self.assertIn("results.stringUpper", content)
        self.assertIn("encodedBytes.subarray", content)
        self.assertIn("typedSetTarget.set", content)
        self.assertIn("typedSetTarget.copyWithin", content)
        self.assertIn("typedSetTarget.fill", content)
        self.assertIn("typedSetTarget.reverse", content)
        self.assertIn("typedSetTarget.sort", content)
        self.assertIn("buffer.slice", content)
        self.assertIn("view.setInt8", content)
        self.assertIn("view.setInt16", content)
        self.assertIn("view.getInt8", content)
        self.assertIn("view.getInt16", content)
        self.assertIn("view.setBigUint64", content)
        self.assertIn("view.setBigInt64", content)
        self.assertIn("view.getBigUint64", content)
        self.assertIn("view.getBigInt64", content)
        self.assertIn("view.setFloat16", content)
        self.assertIn("view.setFloat32", content)
        self.assertIn("view.setFloat64", content)
        self.assertIn("view.getFloat16", content)
        self.assertIn("view.getFloat32", content)
        self.assertIn("view.getFloat64", content)
        self.assertIn("results.typedSubarrayLength", content)
        self.assertIn("results.typedSetJoin", content)
        self.assertIn("results.typedCopyWithinHead", content)
        self.assertIn("results.typedFillTail", content)
        self.assertIn("results.typedReverseHead", content)
        self.assertIn("results.typedSortHead", content)
        self.assertIn("results.arrayBufferSliceBytes", content)
        self.assertIn("results.viewSignedByte", content)
        self.assertIn("results.viewSignedWord", content)
        self.assertIn("results.viewBigUnsigned", content)
        self.assertIn("results.viewBigSigned", content)
        self.assertIn("results.viewFloat16", content)
        self.assertIn("results.viewFloat32", content)
        self.assertIn("results.viewFloat64", content)
        self.assertIn("table.pop", content)
        self.assertIn("results.tablePop", content)
        self.assertIn("table.unshift", content)
        self.assertIn("results.tableUnshift", content)
        self.assertIn("table.shift", content)
        self.assertIn("results.tableShift", content)
        self.assertIn("table.splice", content)
        self.assertIn("results.tableSpliceDeleted", content)
        self.assertIn("results.tableSpliceLength", content)
        self.assertIn("table.reverse", content)
        self.assertIn("results.tableReverseHead", content)
        self.assertIn("table.sort", content)
        self.assertIn("results.tableSortHead", content)
        self.assertIn("table.copyWithin", content)
        self.assertIn("results.tableCopyWithinHead", content)
        self.assertIn("fillTable.fill", content)
        self.assertIn("results.tableFillHead", content)

    def test_business_api_smoke_page_targets_records_api(self):
        page = ROOT / "test-pages" / "business-api-smoke.html"

        self.assertTrue(page.exists(), "business-api-smoke.html should exist")

        content = page.read_text(encoding="utf-8")
        self.assertIn("/api/records/list/", content)
        self.assertIn("new Request", content)
        self.assertIn("fetch(request", content)
        self.assertIn("fetchResponse.json()", content)
        self.assertIn("XMLHttpRequest", content)
        self.assertIn("itemHeaders.set", content)
        self.assertIn("URLSearchParams", content)
        self.assertIn("X-Signature", content)
        self.assertIn("sessionToken", content)
        self.assertIn("requestSessionTokenHeader", content)
        self.assertIn("requestXSignatureHeader", content)
        self.assertIn("itemListRequestHeaderNames", content)
        self.assertIn("TextEncoder", content)
        self.assertIn("DataView", content)
        self.assertIn("Math.imul", content)
        self.assertIn("makeDemoTraceMarker", content)
        self.assertIn("new DataView(bytes.buffer)", content)
        self.assertIn("Reflect.apply", content)
        self.assertIn("Function.prototype.call.call", content)
        self.assertIn("Function.prototype.apply.call", content)
        self.assertNotIn("padded.set(bytes)", content)

    def test_business_api_route_returns_json_from_local_server(self):
        self.assertTrue(
            hasattr(serve_test_page, "make_test_page_handler"),
            "serve_test_page should expose make_test_page_handler",
        )
        handler = serve_test_page.make_test_page_handler(
            directory=ROOT / "test-pages"
        )

        with socketserver.TCPServer(("127.0.0.1", 0), handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                request = urllib.request.Request(
                    (
                        f"http://127.0.0.1:{port}/api/records/list/"
                        "?cursor=1&sessionToken=token-secret&X-Signature=demo-secret"
                    ),
                    headers={
                        "X-Signature": "header-secret",
                        "X-Session-Token": "header-token-secret",
                        "X-XTrace-Smoke": "records-test",
                    },
                )
                with urllib.request.urlopen(request, timeout=5) as response:
                    body = response.read()
                    content_type = response.headers.get("Content-Type", "")
            finally:
                server.shutdown()
                thread.join(timeout=5)

        payload = json.loads(body.decode("utf-8"))
        headers = {
            header["name"].lower(): header
            for header in payload["request_headers"]
        }
        self.assertIn("application/json", content_type)
        self.assertEqual(payload["route"], "/api/records/list/")
        self.assertEqual(payload["query"]["cursor"], ["1"])
        self.assertEqual(payload["query"]["sessionToken"], ["token-secret"])
        self.assertEqual(payload["query"]["X-Signature"], ["demo-secret"])
        self.assertEqual(headers["x-signature"]["value"], "header-secret")
        self.assertEqual(headers["x-session-token"]["value"], "header-token-secret")
        self.assertNotIn("redacted", headers["x-signature"])
        self.assertNotIn("redacted", headers["x-session-token"])
        self.assertEqual(headers["x-xtrace-smoke"]["value"], "records-test")

    def test_non_api_options_request_returns_404(self):
        handler = serve_test_page.make_test_page_handler(
            directory=ROOT / "test-pages"
        )

        with socketserver.TCPServer(("127.0.0.1", 0), handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/not-an-api",
                    method="OPTIONS",
                )
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(request, timeout=5)
            finally:
                server.shutdown()
                thread.join(timeout=5)

        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
