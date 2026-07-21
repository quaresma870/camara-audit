"""
Number Verification error-response phone-number enumeration — checks
whether a CAMARA Number Verification API's `verify` endpoint echoes the
queried phoneNumber back in its error response body, even on a
failed/denied request (e.g. a missing or invalid three-legged access
token).

Why this matters: the Number Verification API exists specifically to
answer "does this access token belong to this phone number" without
otherwise revealing whether a number is a real, registered subscriber.
An error response that echoes the requested number back (rather than a
fully generic "invalid or missing token" message) confirms the endpoint
validated/looked up the number *before* rejecting the request for
authentication reasons — turning the endpoint into an oracle an
attacker can hammer with candidate numbers, no valid token required, to
learn which ones the API actually processed.

Deliberately recon-tier: a single, syntactically well-formed but
non-real phone number, sent with a deliberately invalid bearer token —
read-only, no fuzzing, no attempt to obtain or use a real subscriber's
data, the same risk level as this portfolio's other recon-tier plugins.
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


class NumberVerificationEnumerationModule(BasePlugin):
    name = "number_verification_enumeration"
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
            # reasoning as TokenEndpointSecurityModule's own handling.
            warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
        self._session = session or requests.Session()

    def scan(
        self, target: str, phone_number: str = DEFAULT_PROBE_PHONE_NUMBER, **kwargs: Any,
    ) -> list[Finding]:
        url = target if "://" in target else f"https://{target}"
        self.engagement.authorize_action(
            self.name, url, "number_verification_probe", category=self.category
        )
        return self._phone_number_echo_findings(url, phone_number)

    def _phone_number_echo_findings(self, url: str, phone_number: str) -> list[Finding]:
        try:
            resp = self._session.post(
                url,
                json={"phoneNumber": phone_number},
                headers={"Authorization": "Bearer camara-audit-invalid-probe-token"},
                timeout=self.timeout,
                verify=self.tls_verify,
            )
        except requests.exceptions.RequestException as exc:
            return [Finding(
                module=self.name,
                title="Could not test Number Verification error-response behavior",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=url,
                description=str(exc),
            )]

        if resp.status_code < 400:
            return [Finding(
                module=self.name,
                title="Probe token unexpectedly accepted — cannot assess error-response behavior",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=url,
                description=f"HTTP {resp.status_code} for a request carrying a deliberately "
                             f"invalid bearer token — the endpoint did not reject it, so no "
                             f"error response was produced to inspect.",
            )]

        if _contains_phone_number(resp.text, phone_number):
            return [Finding(
                module=self.name,
                title="Number Verification error response echoes queried phone number",
                severity=Severity.MEDIUM,
                category=FindingCategory.RECON,
                target=url,
                description=(
                    f"A request with an invalid access token (HTTP {resp.status_code}) got "
                    f"back an error response that includes the requested phoneNumber "
                    f"({phone_number}) rather than a fully generic authentication error — "
                    "confirming the endpoint validates/processes the number before rejecting "
                    "the request for auth reasons. An attacker with no valid token can use "
                    "this as an oracle: send candidate numbers and read the response to learn "
                    "which ones the API actually processed, without ever needing a valid token."
                ),
                evidence=f"HTTP {resp.status_code}: {resp.text[:300]}",
                remediation="Return a fully generic authentication error for unauthenticated/"
                             "unauthorized requests — never include the requested phoneNumber "
                             "(or any value derived from it) until the token itself is valid.",
            )]

        return [Finding(
            module=self.name,
            title="Number Verification error response does not echo the queried phone number",
            severity=Severity.INFO,
            category=FindingCategory.RECON,
            target=url,
            description=f"HTTP {resp.status_code} for an invalid-token probe — the error "
                         f"response does not include the requested phone number.",
        )]


def _contains_phone_number(text: str, phone_number: str) -> bool:
    digits = re.sub(r"\D", "", phone_number)
    if not digits:
        return False
    return digits in re.sub(r"\D", "", text)
