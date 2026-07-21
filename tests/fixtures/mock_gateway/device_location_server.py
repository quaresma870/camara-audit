"""
A real mock CAMARA Device Location Verification API endpoint — FOR
TESTS ONLY.

Simulates the `POST /location-verification/v1/verify` resource
endpoint. The CAMARA spec's own Circle schema declares `radius` with
only `minimum: 1` (meter), alongside an explicit implementation note:
"The area surface could be restricted locally depending on
regulations. Implementations may enforce a larger minimum radius (e.g.
1000 meters)." — configurable here to either enforce such a floor
independently of authentication (the compliant case — rejects a
below-floor radius with a distinct validation error even for an
unauthenticated/invalid-token request) or apply no floor at all (the
case that leaves this recon-tier check unable to draw a conclusion,
same configurable-behavior pattern as this fixtures directory's other
mock gateways).
"""

from __future__ import annotations

import http.server
import json
import threading


class _DeviceLocationHandler(http.server.BaseHTTPRequestHandler):
    radius_floor_meters = None  # set per-server-instance below

    def log_message(self, format, *args):
        pass  # keep test output quiet

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else ""
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            payload = {}
        radius = (payload.get("area") or {}).get("radius")

        auth_header = self.headers.get("Authorization", "")
        authenticated = auth_header.startswith("Bearer ") and auth_header != "Bearer camara-audit-invalid-probe-token"

        if authenticated:
            status = 200
            resp_body = {"verificationResult": "TRUE", "lastLocationTime": "2026-07-21T00:00:00Z"}
        elif (
            self.radius_floor_meters is not None
            and isinstance(radius, (int, float))
            and radius < self.radius_floor_meters
        ):
            status = 400
            resp_body = {
                "status": 400, "code": "INVALID_ARGUMENT",
                "message": f"area.radius must be >= {self.radius_floor_meters} meters",
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


class MockDeviceLocationGateway:
    def __init__(self, host: str = "127.0.0.1", radius_floor_meters: int | None = 1000):
        handler_cls = type("_ConfiguredDeviceLocationHandler", (_DeviceLocationHandler,), {
            "radius_floor_meters": radius_floor_meters,
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


def start_mock_device_location_gateway(**kwargs) -> MockDeviceLocationGateway:
    server = MockDeviceLocationGateway(**kwargs)
    server.start()
    return server
