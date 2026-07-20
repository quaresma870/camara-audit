"""
A real mock CAMARA/OAuth2 token gateway — FOR TESTS ONLY.

Two independent real servers, matching this portfolio's established
"test against a real protocol implementation, not a mock/assumption"
pattern:

- A plain HTTP server (http.server-based) simulating a token endpoint,
  configurable to either process query-string client credentials (the
  vulnerable case) or ignore them entirely (the secure case).
- A real TLS server (using a real, openssl-generated self-signed
  certificate — certs/cert.pem + certs/key.pem, checked into this
  fixtures directory) for testing HTTPS-enforcement: a plain-HTTP
  request against this TLS-only port fails the handshake, the same
  real behavior a genuinely HTTPS-only endpoint would produce.

Both listeners route through the SAME decide_response() function —
confirmed this matters for real, not just as a tidiness preference: an
earlier version had the TLS listener return a hardcoded response
regardless of what was actually sent, which made it impossible for any
test going through HTTPS to ever distinguish the vulnerable
(accept_query_string_credentials=True) and secure configurations, since
the TLS path never actually looked at the request's query string at
all. Found by running the real plugin against both configurations over
HTTPS and noticing they produced identical results.
"""

from __future__ import annotations

import http.server
import json
import socket
import ssl
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlparse

_CERTS_DIR = Path(__file__).parent / "certs"


def decide_response(
    path: str, headers: dict[str, str], body: str, accept_query_string_credentials: bool,
) -> tuple[int, dict]:
    """The single source of truth for how this mock token endpoint
    responds to a request — used by both the plain HTTP handler and
    the raw-socket TLS handler, so their behavior can never silently
    diverge the way it did before this was extracted."""
    parsed = urlparse(path)
    query_params = parse_qs(parsed.query)
    body_params = parse_qs(body)

    has_query_creds = "client_id" in query_params and "client_secret" in query_params
    has_body_creds = "client_id" in body_params and "client_secret" in body_params
    has_basic_auth = headers.get("authorization", "").startswith("Basic ")

    if has_query_creds and accept_query_string_credentials:
        return 401, {"error": "invalid_client", "error_description": "Unknown client"}
    if has_body_creds or has_basic_auth:
        return 401, {"error": "invalid_client", "error_description": "Unknown client"}
    return 400, {"error": "invalid_request", "error_description": "Missing client authentication"}


class _TokenHandler(http.server.BaseHTTPRequestHandler):
    accept_query_string_credentials = False  # set per-server-instance below

    def log_message(self, format, *args):
        pass  # keep test output quiet

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else ""
        headers_lower = {k.lower(): v for k, v in self.headers.items()}
        status, resp_body = decide_response(
            self.path, headers_lower, body, self.accept_query_string_credentials
        )
        payload = json.dumps(resp_body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class MockTokenGateway:
    def __init__(self, host: str = "127.0.0.1", accept_query_string_credentials: bool = False):
        handler_cls = type("_ConfiguredHandler", (_TokenHandler,), {
            "accept_query_string_credentials": accept_query_string_credentials,
        })
        self._http_server = http.server.HTTPServer((host, 0), handler_cls)
        self.http_port = self._http_server.server_address[1]

        self._tls_raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tls_raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tls_raw_sock.bind((host, 0))
        self._tls_raw_sock.listen(8)
        self.tls_port = self._tls_raw_sock.getsockname()[1]
        self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._tls_context.load_cert_chain(
            certfile=str(_CERTS_DIR / "cert.pem"), keyfile=str(_CERTS_DIR / "key.pem")
        )
        self._accept_query_string_credentials = accept_query_string_credentials

        self._running = False
        self._http_thread: threading.Thread | None = None
        self._tls_thread: threading.Thread | None = None

    def start(self) -> None:
        self._running = True
        self._http_thread = threading.Thread(target=self._http_server.serve_forever, daemon=True)
        self._http_thread.start()
        self._tls_thread = threading.Thread(target=self._serve_tls_forever, daemon=True)
        self._tls_thread.start()

    def stop(self) -> None:
        self._running = False
        self._http_server.shutdown()
        self._http_server.server_close()
        self._tls_raw_sock.close()

    def _serve_tls_forever(self) -> None:
        while self._running:
            try:
                conn, _addr = self._tls_raw_sock.accept()
            except OSError:
                break
            try:
                tls_conn = self._tls_context.wrap_socket(conn, server_side=True)
            except ssl.SSLError:
                conn.close()  # e.g. a plain-HTTP probe hit this port — the real behavior being tested
                continue
            threading.Thread(target=self._handle_tls_connection, args=(tls_conn,), daemon=True).start()

    def _handle_tls_connection(self, conn: ssl.SSLSocket) -> None:
        try:
            conn.settimeout(5.0)
            request_bytes = self._read_one_http_request(conn)
            if not request_bytes:
                return

            request_line, _, rest = request_bytes.partition(b"\r\n")
            header_block, _, body_bytes = rest.partition(b"\r\n\r\n")
            method, path, _version = request_line.decode().split(" ", 2)
            headers = {}
            for line in header_block.decode(errors="replace").split("\r\n"):
                if ":" in line:
                    name, _, value = line.partition(":")
                    headers[name.strip().lower()] = value.strip()

            status, resp_body = decide_response(
                path, headers, body_bytes.decode(errors="replace"), self._accept_query_string_credentials,
            )
            payload = json.dumps(resp_body).encode()
            response = (
                f"HTTP/1.1 {status} X\r\n".encode()
                + b"Content-Type: application/json\r\n"
                + b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                + b"\r\n" + payload
            )
            conn.sendall(response)
            # Confirmed a real, reproducible bug here: closing a TLS
            # socket with a plain close() immediately after sendall()
            # races ahead of the client's own read on some connections
            # -- Python's ssl module doesn't guarantee sendall()'s
            # underlying TCP write has actually reached the peer (or
            # that the peer has finished consuming it) before close()
            # tears down the connection, and an abrupt TLS-level close
            # (no close_notify) can arrive before the client has
            # finished processing the buffered response, producing a
            # real "Remote end closed connection without response"
            # error on the client side even though the server DID send
            # valid bytes -- reproduced directly with server-side debug
            # logging showing every response actually sent, before
            # fixing it. unwrap() performs the proper TLS closure
            # handshake (send this side's close_notify, wait for the
            # peer's) instead.
            try:
                conn.unwrap()
            except (ssl.SSLError, OSError):
                pass  # peer may have already closed its side; nothing more to do
        except Exception:
            pass
        finally:
            conn.close()

    @staticmethod
    def _read_one_http_request(conn: ssl.SSLSocket) -> bytes:
        """Minimal Content-Length-aware HTTP/1.1 request framing —
        mirrors the sibling voipaudit repo's own _read_sip_message
        pattern applied to HTTP instead of SIP."""
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return buf
            buf += chunk
        header_end = buf.find(b"\r\n\r\n")
        header_bytes = buf[:header_end]
        body_so_far = buf[header_end + 4:]

        import re
        match = re.search(rb"^content-length\s*:\s*(\d+)\s*$", header_bytes, re.IGNORECASE | re.MULTILINE)
        content_length = int(match.group(1)) if match else 0

        while len(body_so_far) < content_length:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body_so_far += chunk

        return buf[:header_end + 4] + body_so_far


def start_mock_gateway(**kwargs) -> MockTokenGateway:
    server = MockTokenGateway(**kwargs)
    server.start()
    return server
