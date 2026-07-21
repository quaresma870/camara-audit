"""
Device Location accuracy-floor enforcement — checks whether a CAMARA
Device Location Verification `verify` endpoint appears to enforce a
minimum area radius (i.e. a floor on how precisely a client can pin a
device) independently of authentication.

Grounded in a real, specific detail of the CAMARA Device Location
Verification spec: its `Circle` schema declares `radius` with only
`minimum: 1` (meter) — but the spec itself carries an explicit
implementation note next to that field: "The area surface could be
restricted locally depending on regulations. Implementations may
enforce a larger minimum radius (e.g. 1000 meters)." A deployment that
never rejects a radius far below any sane floor risks letting a client
request finer-grained device location than its consent/scope should
allow.

This is deliberately a *narrower* claim than "the endpoint is
vulnerable": without a valid, scope-limited access token this plugin
cannot observe what an authenticated caller would actually be granted
(the same real limitation the roadmap notes for full scope-enforcement
testing). What it *can* observe, with no valid token at all, is
whether a radius far below the spec's own suggested floor gets a
distinct, radius-specific validation error compared to a normal-radius
request — evidence the floor is enforced at the input-validation layer,
independent of auth. If both requests get an identical, generic
auth-only error, that's genuinely inconclusive from a recon-tier probe
alone (reported as a LOW-severity "needs an authenticated follow-up"
finding, not a confirmed vulnerability), and if a distinct
radius-specific rejection is observed, this is reported as a positive
(INFO) signal.

Deliberately recon-tier: two read-only requests against a documented
endpoint, using a deliberately invalid bearer token and a probe area
centered at 0,0 (null island) rather than any real device/location —
no fuzzing, no attempt to obtain a real subscriber's location.
"""

from __future__ import annotations

import re
import warnings
from typing import Any

import requests
import urllib3

from camara_audit.core.models import Finding, FindingCategory, Severity
from camara_audit.plugins.base import BasePlugin

DEFAULT_PROBE_PHONE_NUMBER = "+15550123456"
COMPLIANT_PROBE_RADIUS_METERS = 2000
FLOOR_PROBE_RADIUS_METERS = 1

_RADIUS_MENTION_RE = re.compile(r"radius|accuracy|area", re.IGNORECASE)


class DeviceLocationAccuracyFloorModule(BasePlugin):
    name = "device_location_accuracy_floor"
    category = "recon"

    def __init__(
        self, engagement, timeout: float = 10.0,
        tls_verify: bool = True, session: requests.Session | None = None,
    ):
        super().__init__(engagement)
        self.timeout = timeout
        self.tls_verify = tls_verify
        if not tls_verify:
            # A deliberate, explicit user choice (--insecure), same
            # reasoning as this portfolio's other plugins.
            warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
        self._session = session or requests.Session()

    def scan(
        self, target: str, phone_number: str = DEFAULT_PROBE_PHONE_NUMBER, **kwargs: Any,
    ) -> list[Finding]:
        url = target if "://" in target else f"https://{target}"
        self.engagement.authorize_action(
            self.name, url, "device_location_accuracy_probe", category=self.category
        )
        return self._accuracy_floor_findings(url, phone_number)

    def _probe(self, url: str, phone_number: str, radius: int) -> requests.Response:
        return self._session.post(
            url,
            json={
                "device": {"phoneNumber": phone_number},
                "area": {
                    "areaType": "CIRCLE",
                    "center": {"latitude": 0.0, "longitude": 0.0},
                    "radius": radius,
                },
            },
            headers={"Authorization": "Bearer camara-audit-invalid-probe-token"},
            timeout=self.timeout,
            verify=self.tls_verify,
        )

    def _accuracy_floor_findings(self, url: str, phone_number: str) -> list[Finding]:
        try:
            compliant_resp = self._probe(url, phone_number, COMPLIANT_PROBE_RADIUS_METERS)
            floor_resp = self._probe(url, phone_number, FLOOR_PROBE_RADIUS_METERS)
        except requests.exceptions.RequestException as exc:
            return [Finding(
                module=self.name,
                title="Could not test Device Location accuracy-floor behavior",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=url,
                description=str(exc),
            )]

        if compliant_resp.status_code < 400 or floor_resp.status_code < 400:
            return [Finding(
                module=self.name,
                title="Probe token unexpectedly accepted — cannot assess accuracy-floor behavior",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=url,
                description="A request carrying a deliberately invalid bearer token was not "
                             "rejected, so no error response was produced to compare.",
            )]

        floor_rejected_distinctly = (
            floor_resp.status_code != compliant_resp.status_code
            and _RADIUS_MENTION_RE.search(floor_resp.text) is not None
        )

        if floor_rejected_distinctly:
            return [Finding(
                module=self.name,
                title="Device Location endpoint appears to validate area radius independently of authentication",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=url,
                description=(
                    f"A request with a {FLOOR_PROBE_RADIUS_METERS}m radius (below any "
                    "reasonable accuracy floor, though still >= the spec schema's own "
                    "'minimum: 1') got a distinct, radius-referencing rejection "
                    f"(HTTP {floor_resp.status_code}) compared to a "
                    f"{COMPLIANT_PROBE_RADIUS_METERS}m-radius request "
                    f"(HTTP {compliant_resp.status_code}) — suggesting the endpoint enforces "
                    "an accuracy floor at the input-validation layer, independent of whether "
                    "the caller's token is valid."
                ),
                evidence=f"{FLOOR_PROBE_RADIUS_METERS}m -> HTTP {floor_resp.status_code}: "
                         f"{floor_resp.text[:200]}",
            )]

        return [Finding(
            module=self.name,
            title="Could not determine whether Device Location enforces a minimum radius/accuracy floor",
            severity=Severity.LOW,
            category=FindingCategory.RECON,
            target=url,
            description=(
                f"A {FLOOR_PROBE_RADIUS_METERS}m-radius request and a "
                f"{COMPLIANT_PROBE_RADIUS_METERS}m-radius request both produced the same "
                f"generic authentication error (HTTP {floor_resp.status_code}) with no "
                "radius-specific signal — the CAMARA spec's own Circle schema only requires "
                "radius >= 1 meter and separately notes implementations 'may enforce a larger "
                "minimum radius (e.g. 1000 meters)' for privacy/regulatory reasons, but this "
                "recon-tier, unauthenticated probe cannot confirm whether that floor is "
                "actually enforced once a caller has a valid token. Follow up with an "
                "authenticated request (a real, scope-limited access token) to confirm "
                "whether a sub-floor radius is honored or rejected."
            ),
            evidence=f"Both probes returned HTTP {floor_resp.status_code}",
        )]
