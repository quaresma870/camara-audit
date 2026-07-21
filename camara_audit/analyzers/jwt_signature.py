"""
JWT signature + expiry verification findings — wraps
core/jwt_verify.py's live JWKS-fetch verification into Finding
objects, for the opt-in `analyze-token --verify-signature` path.

Severities here are deliberately conservative: a token being expired
or not-yet-valid is routine and expected (not itself a finding), so
those are reported as INFO. A signature that doesn't match any key the
issuer actually publishes is a genuinely notable anomaly — it could
mean a forged/altered token, but just as plausibly a mismatched
issuer/JWKS or a token from a different environment — so it's reported
as MEDIUM with an honest description of both possibilities, not
inflated to HIGH/CRITICAL on a single offline check.
"""

from __future__ import annotations

from camara_audit.core.jwt_verify import JWTVerificationError, verify_jwt_signature
from camara_audit.core.models import Finding, FindingCategory, Severity

MODULE_NAME = "jwt_signature_verification"


def verify_jwt_signature_findings(
    token: str, jwks_url: str | None = None, issuer: str | None = None,
    timeout: float = 10.0, tls_verify: bool = True,
) -> list[Finding]:
    try:
        result = verify_jwt_signature(
            token, jwks_url=jwks_url, issuer=issuer, timeout=timeout, tls_verify=tls_verify,
        )
    except JWTVerificationError as exc:
        return [Finding(
            module=MODULE_NAME,
            title="Could not verify token signature",
            severity=Severity.INFO,
            category=FindingCategory.RECON,
            target=jwks_url or issuer or "token",
            description=str(exc),
        )]

    if result.verified:
        return [Finding(
            module=MODULE_NAME,
            title="Token signature and expiry are valid",
            severity=Severity.INFO,
            category=FindingCategory.RECON,
            target=result.jwks_url,
            description=result.reason,
        )]

    if "does NOT match" in result.reason:
        return [Finding(
            module=MODULE_NAME,
            title="Token signature does not match any key at the issuer's JWKS endpoint",
            severity=Severity.MEDIUM,
            category=FindingCategory.RECON,
            target=result.jwks_url,
            description=(
                f"{result.reason} This could mean the token was forged or altered after "
                "issuance — but just as plausibly a mismatched issuer/JWKS URL, a token from a "
                "different environment (staging vs. production), or a key that has since been "
                "rotated out of the JWKS. Confirm the issuer/JWKS URL is genuinely the one that "
                "issued this token before treating this as a forgery."
            ),
            remediation="Re-run against the correct issuer/JWKS URL for this token's environment "
                         "before drawing conclusions; if the URL is confirmed correct, treat the "
                         "token as untrustworthy.",
        )]

    return [Finding(
        module=MODULE_NAME,
        title="Token verification result",
        severity=Severity.INFO,
        category=FindingCategory.RECON,
        target=result.jwks_url,
        description=result.reason,
    )]
