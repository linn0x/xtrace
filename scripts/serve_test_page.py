from __future__ import annotations

import argparse
import functools
import http.server
import json
import socketserver
from pathlib import Path
from urllib.parse import parse_qs, urlparse


BUSINESS_API_ROUTES = {
    "/api/feed/list",
    "/api/records/list",
    "/api/records/list/",
}

class XTraceTestPageHandler(http.server.SimpleHTTPRequestHandler):
    def _send_api_headers(self, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, X-XTrace-Smoke, X-Signature, X-Session-Token",
        )
        self.send_header("Cache-Control", "no-store")

    def _request_header_metadata(self) -> list[dict[str, object]]:
        headers = []
        for name, value in self.headers.items():
            item: dict[str, object] = {
                "name": name,
                "value_length": len(value.encode("utf-8")),
                "value": value,
            }
            headers.append(item)
        return headers

    def _send_business_api_response(self) -> None:
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        request_body = self.rfile.read(content_length).decode("utf-8", "replace") if content_length else ""
        payload = {
            "ok": True,
            "route": parsed.path,
            "query": parse_qs(parsed.query, keep_blank_values=True),
            "method": self.command,
            "request_headers": self._request_header_metadata(),
            "body_size": len(request_body.encode("utf-8")),
            "items": [
                {"id": "xtrace-smoke-1", "title": "local business api smoke"},
                {"id": "xtrace-smoke-2", "title": "trace gate anchor"},
            ],
        }
        body = json.dumps(payload, sort_keys=True).encode("utf-8")

        self._send_api_headers(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in BUSINESS_API_ROUTES:
            self._send_api_headers(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_error(404, "File not found")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in BUSINESS_API_ROUTES:
            self._send_business_api_response()
            return
        super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in BUSINESS_API_ROUTES:
            self._send_business_api_response()
            return
        super().do_POST()


def make_test_page_handler(directory: Path):
    return functools.partial(XTraceTestPageHandler, directory=directory)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "test-pages",
    )
    args = parser.parse_args()

    handler = make_test_page_handler(directory=args.directory)
    with socketserver.TCPServer(("127.0.0.1", args.port), handler) as server:
        print(f"Serving {args.directory} at http://127.0.0.1:{args.port}/")
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
