"""
Optional, opt-in JWT signature + expiry verification.

`core/jwt_tools.py` deliberately never verifies a token's signature
(see its own docstring for why: claims-only, fully offline analysis is
the always-safe default path). This module is the explicit opt-in
addition the roadmap calls for: given a JWKS URL (or one discovered
from the token's own `iss` claim via the standard OIDC discovery
document), fetch the issuer's public keys and verify (a) the token's
signature genuinely matches one of them, and (b) `exp`/`nbf` haven't
lapsed.

Uses PyJWT (with its `crypto` extra) rather than hand-rolling RSA/EC
signature math — this is exactly the kind of code where a well-audited
library beats a bespoke implementation.

Unlike `analyze_jwt_for_pii`, calling this makes one or two real
outbound HTTPS requests (OIDC discovery, then the JWKS endpoint
itself) — that live-network step is exactly why this is opt-in and
kept separate from the always-offline claims analysis.
"""

from __future__ import annotations

from dataclasses import dataclass

import jwt as pyjwt
import requests


class JWTVerificationError(ValueError):
    """Raised when the JWKS can't be discovered/fetched/parsed, or no
    single matching key can be identified for the token — distinct
    from a *failed* verification (bad signature / expired), which is
    reported as a normal (non-exception) result instead."""


@dataclass
class SignatureVerificationResult:
    verified: bool
    reason: str
    jwks_url: str


def _discover_jwks_url(issuer: str, timeout: float, tls_verify: bool, session: requests.Session) -> str:
    discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        resp = session.get(discovery_url, timeout=timeout, verify=tls_verify)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as exc:
        raise JWTVerificationError(
            f"Could not fetch OIDC discovery document from {discovery_url}: {exc}"
        ) from exc
    except ValueError as exc:
        raise JWTVerificationError(f"{discovery_url} did not return valid JSON: {exc}") from exc

    jwks_uri = data.get("jwks_uri")
    if not jwks_uri:
        raise JWTVerificationError(f"{discovery_url} did not include a 'jwks_uri'.")
    return jwks_uri


def _fetch_jwks(jwks_url: str, timeout: float, tls_verify: bool, session: requests.Session) -> pyjwt.PyJWKSet:
    try:
        resp = session.get(jwks_url, timeout=timeout, verify=tls_verify)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as exc:
        raise JWTVerificationError(f"Could not fetch JWKS from {jwks_url}: {exc}") from exc
    except ValueError as exc:
        raise JWTVerificationError(f"{jwks_url} did not return valid JSON: {exc}") from exc

    try:
        return pyjwt.PyJWKSet.from_dict(data)
    except pyjwt.exceptions.PyJWKError as exc:
        raise JWTVerificationError(f"{jwks_url} did not return a valid JWKS document: {exc}") from exc


def verify_jwt_signature(
    token: str, jwks_url: str | None = None, issuer: str | None = None,
    timeout: float = 10.0, tls_verify: bool = True, session: requests.Session | None = None,
) -> SignatureVerificationResult:
    """Verifies `token`'s signature against a real JWKS endpoint, plus
    exp/nbf. If `jwks_url` isn't given, `issuer` (or, failing that, the
    token's own `iss` claim) is used to discover one via OIDC
    discovery."""
    session = session or requests.Session()
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    if jwks_url is None:
        if issuer is None:
            try:
                unverified_payload = pyjwt.decode(token, options={"verify_signature": False})
            except pyjwt.exceptions.PyJWTError as exc:
                raise JWTVerificationError(f"Could not decode token to find an 'iss' claim: {exc}") from exc
            issuer = unverified_payload.get("iss")
            if not issuer:
                raise JWTVerificationError(
                    "No jwks_url/issuer given and the token has no 'iss' claim to discover one from."
                )
        jwks_url = _discover_jwks_url(issuer, timeout, tls_verify, session)

    jwks = _fetch_jwks(jwks_url, timeout, tls_verify, session)

    try:
        header = pyjwt.get_unverified_header(token)
    except pyjwt.exceptions.PyJWTError as exc:
        raise JWTVerificationError(f"Could not decode token header: {exc}") from exc
    kid = header.get("kid")
    alg = header.get("alg", "RS256")

    matching = [k for k in jwks.keys if k.key_id == kid] if kid is not None else list(jwks.keys)
    if not matching:
        raise JWTVerificationError(f"No key in {jwks_url} matches this token's kid ({kid!r}).")
    if len(matching) > 1:
        raise JWTVerificationError(
            f"Token has no 'kid' and {jwks_url} publishes {len(matching)} keys — can't tell which to use."
        )
    signing_key = matching[0]

    try:
        pyjwt.decode(
            token, signing_key.key, algorithms=[alg],
            options={"verify_aud": False, "verify_iss": False},
        )
        return SignatureVerificationResult(
            verified=True, reason="Signature is valid and the token has not expired.", jwks_url=jwks_url,
        )
    except pyjwt.ExpiredSignatureError:
        return SignatureVerificationResult(
            verified=False,
            reason="Signature is valid but the token has expired ('exp' has passed).",
            jwks_url=jwks_url,
        )
    except pyjwt.ImmatureSignatureError:
        return SignatureVerificationResult(
            verified=False,
            reason="Signature is valid but the token is not yet valid ('nbf' is in the future).",
            jwks_url=jwks_url,
        )
    except pyjwt.InvalidSignatureError:
        return SignatureVerificationResult(
            verified=False,
            reason="Signature does NOT match any key published at the issuer's JWKS endpoint.",
            jwks_url=jwks_url,
        )
    except pyjwt.exceptions.PyJWTError as exc:
        return SignatureVerificationResult(
            verified=False, reason=f"Token failed verification: {exc}", jwks_url=jwks_url,
        )
