"""
A real mock CAMARA SIM Swap API endpoint — FOR TESTS ONLY.

Simulates the `POST /sim-swap/v1/check` resource endpoint, configurable
to either impose a hard per-phone-number request cap (the secure case
— returns 429 once a configured request count is exceeded for that
number) or apply no throttling at all (the vulnerable case — every
request gets a normal response, regardless of how many times the same
number was already queried), matching this fixtures directory's
established configurable-vulnerable-vs-secure pattern.
"""

from __future__ import annotations

import http.server
import json
import threading
from collections import defaultdict


class _SimSwapHandler(http.server.BaseHTTPRequestHandler):
    rate_limit_after = None  # set per-server-instance below
    _counts = None  # set per-server-instance below
    _lock = None

    def log_message(self, format, *args):
        pass  # keep test output quiet

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else ""
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            payload = {}
        phone_number = payload.get("phoneNumber", "")

        with self._lock:
            self._counts[phone_number] += 1
            count = self._counts[phone_number]

        if self.rate_limit_after is not None and count > self.rate_limit_after:
            status = 429
            resp_body = {"status": 429, "code": "TOO_MANY_REQUESTS", "message": "Rate limit exceeded"}
        else:
            status = 401
            resp_body = {"status": 401, "code": "UNAUTHENTICATED", "message": "Invalid or missing access token"}

        payload_bytes = json.dumps(resp_body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload_bytes)))
        self.end_headers()
        self.wfile.write(payload_bytes)


class MockSimSwapGateway:
    def __init__(self, host: str = "127.0.0.1", rate_limit_after: int | None = None):
        handler_cls = type("_ConfiguredSimSwapHandler", (_SimSwapHandler,), {
            "rate_limit_after": rate_limit_after,
            "_counts": defaultdict(int),
            "_lock": threading.Lock(),
        })
        self._server = http.server.HTTPServer((host, 0), handler_cls)
        self.http_port = self._server.server_address[1]
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def start_mock_sim_swap_gateway(**kwargs) -> MockSimSwapGateway:
    server = MockSimSwapGateway(**kwargs)
    server.start()
    return server
