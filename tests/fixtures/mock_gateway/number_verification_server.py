"""
A real mock CAMARA Number Verification API endpoint — FOR TESTS ONLY.

Simulates the `POST /number-verification/v0/verify` resource endpoint's
behavior when a request carries no (or an invalid) three-legged access
token, configurable to either echo the requested phoneNumber back in
the error body (the vulnerable case) or return a fully generic error
that never mentions the number at all (the secure case) — same
configurable-vulnerable-vs-secure pattern as the sibling
tests/fixtures/mock_gateway/server.py used for the token endpoint.
"""

from __future__ import annotations

import http.server
import json
import threading


class _NumberVerificationHandler(http.server.BaseHTTPRequestHandler):
    echo_phone_number_on_error = False  # set per-server-instance below

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

        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") and auth_header != "Bearer camara-audit-invalid-probe-token":
            status = 200
            resp_body = {"devicePhoneNumberVerified": True}
        elif self.echo_phone_number_on_error:
            status = 401
            resp_body = {
                "status": 401, "code": "UNAUTHENTICATED",
                "message": f"No active access token found for phoneNumber {phone_number}",
            }
        else:
            status = 401
            resp_body = {"status": 401, "code": "UNAUTHENTICATED", "message": "Invalid or missing access token"}

        payload_bytes = json.dumps(resp_body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload_bytes)))
        self.end_headers()
        self.wfile.write(payload_bytes)


class MockNumberVerificationGateway:
    def __init__(self, host: str = "127.0.0.1", echo_phone_number_on_error: bool = False):
        handler_cls = type("_ConfiguredNVHandler", (_NumberVerificationHandler,), {
            "echo_phone_number_on_error": echo_phone_number_on_error,
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


def start_mock_number_verification_gateway(**kwargs) -> MockNumberVerificationGateway:
    server = MockNumberVerificationGateway(**kwargs)
    server.start()
    return server
