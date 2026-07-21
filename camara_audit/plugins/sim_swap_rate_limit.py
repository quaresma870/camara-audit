"""
SIM Swap query rate limiting — checks whether a CAMARA SIM Swap API's
`check` endpoint imposes any request throttling on repeated queries for
the same phone number.

Why this matters: SIM Swap's whole purpose is to answer "has this
number's SIM changed recently" for anti-fraud use cases — but the same
capability, queried with no limit, turns the endpoint into a
surveillance oracle: repeatedly polling the same target number lets an
attacker learn the *exact moment* a SIM swap happens (e.g. to time a
SIM-swap-fraud attack, or simply to track a target), independent of
whatever legitimate anti-fraud checks the caller's own token/client is
otherwise subject to.

Deliberately recon-tier: a short burst of read-only requests against a
documented endpoint using a single, non-real phone number and a
deliberately invalid bearer token — no fuzzing, no attempt to obtain or
use a real subscriber's data. The probe count defaults to a modest
burst (20 requests), enough to observe whether *any* throttling kicks
in without hammering a real target.
"""

from __future__ import annotations

import warnings
from typing import Any

import requests
import urllib3

from camara_audit.core.models import Finding, FindingCategory, Severity
from camara_audit.plugins.base import BasePlugin

DEFAULT_PROBE_PHONE_NUMBER = "+15550123456"
DEFAULT_PROBE_COUNT = 20


class SimSwapRateLimitModule(BasePlugin):
    name = "sim_swap_rate_limit"
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
        self, target: str, phone_number: str = DEFAULT_PROBE_PHONE_NUMBER,
        probe_count: int = DEFAULT_PROBE_COUNT, **kwargs: Any,
    ) -> list[Finding]:
        url = target if "://" in target else f"https://{target}"
        self.engagement.authorize_action(
            self.name, url, "sim_swap_rate_limit_probe", category=self.category
        )
        return self._rate_limit_findings(url, phone_number, probe_count)

    def _rate_limit_findings(self, url: str, phone_number: str, probe_count: int) -> list[Finding]:
        statuses: list[int] = []
        for _ in range(probe_count):
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
                    title="Could not test SIM Swap rate-limiting behavior",
                    severity=Severity.INFO,
                    category=FindingCategory.RECON,
                    target=url,
                    description=f"Request {len(statuses) + 1}/{probe_count} failed: {exc}",
                )]
            statuses.append(resp.status_code)
            if resp.status_code == 429:
                break

        if 429 in statuses:
            return [Finding(
                module=self.name,
                title="SIM Swap endpoint rate-limits repeated queries for the same number",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=url,
                description=f"Received HTTP 429 after {len(statuses)} request(s) for the same "
                             f"phone number — the endpoint throttles repeated queries.",
            )]

        return [Finding(
            module=self.name,
            title="No rate limiting observed on repeated SIM Swap queries for the same number",
            severity=Severity.MEDIUM,
            category=FindingCategory.RECON,
            target=url,
            description=(
                f"{len(statuses)} consecutive requests for the same phone number all received "
                f"a normal response with no HTTP 429 at any point — an endpoint whose "
                "SIM-swap-status queries aren't rate-limited per number can be polled "
                "repeatedly to detect the exact moment a target's SIM changes, turning a "
                "fraud-prevention API into a surveillance oracle."
            ),
            evidence=f"{len(statuses)}/{len(statuses)} requests returned a non-429 status: "
                      f"{sorted(set(statuses))}",
            remediation="Rate-limit SIM Swap status queries per phone number (not just per "
                         "client/token) tightly enough that repeated polling cannot be used to "
                         "detect a swap in near-real-time.",
        )]
