"""
Token endpoint security — checks a CAMARA/Open Gateway OAuth2/OIDC token
endpoint for two real, documented anti-patterns:

1. HTTPS not enforced. CAMARA's own Security and Interoperability
   Profile mandates TLS for every endpoint carrying credentials/tokens
   — an endpoint that also (or only) answers over plain HTTP exposes
   client credentials and access tokens to any network observer.
2. Credentials accepted via URL query string. RFC 6749 §2.3.1 (OAuth2)
   requires client credentials to be sent via the Authorization header
   (HTTP Basic) or the POST request body — never the URL — because
   URLs are routinely logged by proxies, load balancers, browser
   history, and web server access logs, all of which credentials in a
   query string would leak into. An endpoint that *works* when
   credentials are passed as query parameters (even if POST-body auth
   also works) means a misconfigured or copy-pasted client integration
   would silently leak credentials into every log line, undetected.

Deliberately recon-tier: both checks are read-only requests against a
documented, expected-to-exist endpoint (no fuzzing, no credential
guessing), the same "OPTIONS-ping" risk level as this portfolio's other
recon-tier plugins.
"""

from __future__ import annotations

import warnings
from typing import Any

import requests
import urllib3

from camara_audit.core.models import Finding, FindingCategory, Severity
from camara_audit.plugins.base import BasePlugin


class TokenEndpointSecurityModule(BasePlugin):
    name = "token_endpoint_security"
    category = "recon"

    def __init__(
        self, engagement, timeout: float = 10.0,
        tls_verify: bool = True, session: requests.Session | None = None,
    ):
        super().__init__(engagement)
        self.timeout = timeout
        # Passed explicitly as the `verify=` kwarg on every individual
        # request below, NOT set via session.verify = tls_verify --
        # confirmed session-level assignment doesn't reliably take
        # effect in this environment (reproduced directly: a request
        # against a real self-signed cert still raised
        # SSLCertVerificationError with session.verify already set to
        # False, while the same request with an explicit verify=False
        # per-call argument succeeded) before switching to the
        # explicit-per-call approach. Needed to reach a self-signed or
        # otherwise unverifiable target at all -- an internal/staging
        # CAMARA gateway using a self-signed or internally-issued
        # certificate is a common, real scenario, the same reasoning
        # already established for the sibling voipaudit repo's
        # --insecure flag.
        self.tls_verify = tls_verify
        if not tls_verify:
            # A deliberate, explicit user choice (--insecure) — not
            # something that should spam a scary warning on every
            # single request the same way an accidental/unnoticed
            # disable would.
            warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
        # Injectable purely for fast, deterministic unit tests — every
        # test that verifies real network behavior end-to-end still
        # goes through the real requests library against
        # tests/fixtures/mock_gateway, matching this portfolio's
        # established injectable-transport-for-speed,
        # real-target-for-integration pattern.
        self._session = session or requests.Session()

    def scan(self, target: str, **kwargs: Any) -> list[Finding]:
        url = target if "://" in target else f"https://{target}"
        self.engagement.authorize_action(self.name, url, "token_endpoint_probe", category=self.category)

        findings: list[Finding] = []
        findings.extend(self._https_enforcement_findings(url))
        findings.extend(self._query_string_credential_findings(url))
        return findings

    def _https_enforcement_findings(self, url: str) -> list[Finding]:
        if not url.startswith("https://"):
            return [Finding(
                module=self.name,
                title="Token endpoint target is not HTTPS",
                severity=Severity.CRITICAL,
                category=FindingCategory.RECON,
                target=url,
                description="The target URL itself uses plain HTTP, not HTTPS — client "
                             "credentials and tokens exchanged with this endpoint are exposed "
                             "to any network observer.",
            )]

        http_url = "http://" + url[len("https://"):]
        try:
            resp = self._session.post(
                http_url, data={"grant_type": "client_credentials"}, timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.exceptions.ConnectionError:
            return [Finding(
                module=self.name,
                title="Plain HTTP correctly refused",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=url,
                description=f"{http_url} refused the connection entirely — HTTPS-only, as expected.",
            )]
        except requests.exceptions.RequestException as exc:
            return [Finding(
                module=self.name,
                title="Could not determine HTTP behavior",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=url,
                description=f"Request to {http_url} failed in an inconclusive way: {exc}",
            )]

        if 300 <= resp.status_code < 400 and str(resp.headers.get("location", "")).startswith("https://"):
            return [Finding(
                module=self.name,
                title="Plain HTTP redirects to HTTPS",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=url,
                description=f"{http_url} redirects to HTTPS ({resp.status_code}) rather than "
                             f"serving the request directly — correct behavior.",
            )]

        return [Finding(
            module=self.name,
            title="Token endpoint answers over plain HTTP",
            severity=Severity.CRITICAL,
            category=FindingCategory.RECON,
            target=url,
            description=f"{http_url} responded directly (HTTP {resp.status_code}) instead of "
                         f"refusing the connection or redirecting to HTTPS — client credentials "
                         f"sent to this URL over plain HTTP are exposed to any network observer.",
            evidence=f"HTTP {resp.status_code} from {http_url}",
            remediation="Disable the plain-HTTP listener for this endpoint entirely, or ensure "
                         "it only ever redirects to HTTPS and never processes credentials directly.",
        )]

    def _query_string_credential_findings(self, url: str) -> list[Finding]:
        probe_id, probe_secret = "camara-audit-probe", "camara-audit-probe-secret"
        try:
            resp = self._session.post(
                url,
                params={"client_id": probe_id, "client_secret": probe_secret},
                data={"grant_type": "client_credentials"},
                timeout=self.timeout,
                verify=self.tls_verify,
            )
        except requests.exceptions.RequestException as exc:
            return [Finding(
                module=self.name,
                title="Could not test query-string credential handling",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=url,
                description=str(exc),
            )]

        # A 401/403 (rejected — this probe client doesn't exist) still
        # confirms the endpoint *processed* query-string credentials
        # rather than ignoring the parameter entirely — the real
        # signal is whether the error is about the client's validity,
        # not the credential-transport mechanism. A 400 specifically
        # about malformed/missing parameters (rather than invalid
        # client) is more consistent with the endpoint not reading
        # query-string params for auth at all, which is the secure case.
        if resp.status_code in (401, 403):
            return [Finding(
                module=self.name,
                title="Token endpoint processes credentials passed via URL query string",
                severity=Severity.MEDIUM,
                category=FindingCategory.RECON,
                target=url,
                description=(
                    "The endpoint returned an authentication-specific error "
                    f"(HTTP {resp.status_code}) for a request with client_id/client_secret in "
                    "the URL query string, rather than ignoring those parameters outright — "
                    "meaning a real (valid) query-string credential would likely also be "
                    "accepted. RFC 6749 §2.3.1 requires client credentials via the "
                    "Authorization header or POST body only, specifically because URLs are "
                    "routinely logged by proxies, load balancers, and access logs."
                ),
                evidence=f"HTTP {resp.status_code}",
                remediation="Reject any request that carries client_id/client_secret as query "
                             "parameters, independent of whether the credentials themselves are "
                             "valid — don't just rely on the credentials being wrong in testing.",
            )]

        return [Finding(
            module=self.name,
            title="Token endpoint does not appear to process query-string credentials",
            severity=Severity.INFO,
            category=FindingCategory.RECON,
            target=url,
            description=f"HTTP {resp.status_code} for a query-string credential probe — "
                         f"doesn't show the same behavior a real credential-processing "
                         f"endpoint would (see MEDIUM finding case for what that looks like).",
        )]
