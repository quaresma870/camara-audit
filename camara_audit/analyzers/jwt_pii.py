"""
JWT PII leakage analysis — offline, no network access needed.

Grounded in a real, specific CAMARA spec requirement (CAMARA Security
and Interoperability Profile, camaraproject/IdentityAndConsentManagement):
for a Three-Legged Access Token, "the sub claim of the ID token... will
not identify the User directly given that the sub will not be a
globally unique identifier nor contain PII as per the CAMARA Security
and Interoperability Profile requirements." This is an explicit MUST
in CAMARA's own design, not a general best-practice guess — an
implementation that puts a phone number, email address, or other
directly-identifying value in `sub` (or leaks it elsewhere in the
token) is a real, specific CAMARA spec violation.

File/data analysis only, like the sibling voipaudit repo's
`analyze-cdr` — a JWT handed to this tool for inspection isn't a live
network target, so no Authorization/Engagement gate applies here.
"""

from __future__ import annotations

import re

from camara_audit.core.jwt_tools import JWTDecodeError, decode_jwt_claims
from camara_audit.core.models import Finding, FindingCategory, Severity

# Real E.164 phone number shape: optional +, 8-15 digits (ITU-T E.164
# §6 caps international numbers at 15 digits; 8 is a practical lower
# bound to avoid matching short internal extension-like numeric IDs).
_PHONE_RE = re.compile(r"^\+?\d{8,15}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# IMSI (International Mobile Subscriber Identity): exactly 15 digits,
# a real, specific, directly-identifying subscriber ID — distinct
# from a generic long numeric string, since not every 15-digit value
# is an IMSI, but flagging the shape is still worth a LOW/INFO note
# rather than silently treating it as equivalent to any other digit
# string.
_IMSI_SHAPE_RE = re.compile(r"^\d{15}$")

# Claims worth checking beyond `sub` — CAMARA's own spec only makes
# the explicit no-PII promise about `sub`, but a real implementation
# leaking PII into an *adjacent* claim (e.g. a custom claim carrying
# the phone number anyway) is just as real a problem, worth a
# slightly lower severity than a direct `sub` violation since it's
# not a documented spec MUST the same way `sub` is.
_OTHER_CLAIMS_TO_CHECK = ("email", "phone_number", "msisdn", "preferred_username", "name")


def analyze_jwt_for_pii(token: str, source_label: str = "token") -> list[Finding]:
    try:
        _header, payload = decode_jwt_claims(token)
    except JWTDecodeError as exc:
        return [Finding(
            module="jwt_pii_leakage",
            title="Could not decode token",
            severity=Severity.INFO,
            category=FindingCategory.RECON,
            target=source_label,
            description=str(exc),
        )]

    findings: list[Finding] = []

    sub = payload.get("sub")
    if sub is not None:
        sub_str = str(sub)
        reason = _classify_pii_shape(sub_str)
        if reason:
            findings.append(Finding(
                module="jwt_pii_leakage",
                title="sub claim appears to contain PII (CAMARA spec violation)",
                severity=Severity.CRITICAL,
                category=FindingCategory.RECON,
                target=source_label,
                description=(
                    f"The 'sub' claim looks like {reason}. CAMARA's own Security and "
                    f"Interoperability Profile explicitly requires sub to NOT be a globally "
                    f"unique identifier nor contain PII for a Three-Legged Access Token — "
                    f"this is a documented MUST, not a general best-practice guess."
                ),
                evidence=f"sub={sub_str!r}",
                remediation=(
                    "Replace sub with an opaque, non-identifying value (e.g. a random UUID "
                    "scoped to this client/user pair) that carries no directly-recoverable PII."
                ),
            ))

    for claim_name in _OTHER_CLAIMS_TO_CHECK:
        value = payload.get(claim_name)
        if value is None:
            continue
        value_str = str(value)
        reason = _classify_pii_shape(value_str)
        if reason:
            findings.append(Finding(
                module="jwt_pii_leakage",
                title=f"'{claim_name}' claim appears to contain PII",
                severity=Severity.MEDIUM,
                category=FindingCategory.RECON,
                target=source_label,
                description=(
                    f"The '{claim_name}' claim looks like {reason}. Not every token payload "
                    f"needs every claim minimized the same strict way CAMARA's spec mandates "
                    f"for sub specifically, but carrying raw PII in any claim widens exposure "
                    f"if this token is logged, cached, or forwarded."
                ),
                evidence=f"{claim_name}={value_str!r}",
            ))

    if not findings:
        findings.append(Finding(
            module="jwt_pii_leakage",
            title="No obvious PII found in inspected claims",
            severity=Severity.INFO,
            category=FindingCategory.RECON,
            target=source_label,
            description=(
                f"Checked 'sub' and {', '.join(_OTHER_CLAIMS_TO_CHECK)} — none matched a "
                f"phone number, email, or IMSI-like shape. This does not guarantee full CAMARA "
                f"spec compliance (PII could still be present in a claim this check doesn't "
                f"inspect, or encoded in a form this pattern-matching doesn't recognize)."
            ),
        ))

    return findings


def _classify_pii_shape(value: str) -> str | None:
    if _EMAIL_RE.match(value):
        return "an email address"
    if _IMSI_SHAPE_RE.match(value):
        return "an IMSI (15-digit subscriber identifier)"
    if _PHONE_RE.match(value):
        return "a phone number"
    return None
