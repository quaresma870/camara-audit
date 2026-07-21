"""
A real mock OIDC issuer — FOR TESTS ONLY.

Serves a real `/.well-known/openid-configuration` document and a real
JWKS endpoint (both plain HTTP, real sockets) backing
core/jwt_verify.py's opt-in signature-verification path. Callers
supply the actual JWK(s) to publish — generated from a real RSA key
pair via PyJWT + cryptography in the tests that use this fixture, no
simulated/hand-rolled crypto or key material.
"""

from __future__ import annotations

import http.server
import json
import threading
from urllib.parse import urlparse


class _OIDCHandler(http.server.BaseHTTPRequestHandler):
    jwks_document = None  # set per-server-instance below

    def log_message(self, format, *args):
        pass  # keep test output quiet

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/.well-known/openid-configuration":
            body = json.dumps({"jwks_uri": f"{self.server.base_url}/jwks.json"}).encode()
        elif parsed.path == "/jwks.json":
            body = json.dumps(self.jwks_document).encode()
        else:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class MockOIDCIssuer:
    def __init__(self, host: str = "127.0.0.1", jwks_document: dict | None = None):
        handler_cls = type("_ConfiguredOIDCHandler", (_OIDCHandler,), {
            "jwks_document": jwks_document if jwks_document is not None else {"keys": []},
        })
        self._server = http.server.HTTPServer((host, 0), handler_cls)
        self.http_port = self._server.server_address[1]
        self.base_url = f"http://{host}:{self.http_port}"
        self._server.base_url = self.base_url
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def start_mock_oidc_issuer(**kwargs) -> MockOIDCIssuer:
    server = MockOIDCIssuer(**kwargs)
    server.start()
    return server
