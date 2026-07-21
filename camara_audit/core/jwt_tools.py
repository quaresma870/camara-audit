"""
JWT decoding for claims inspection.

Deliberately does NOT verify the token's signature — this tool is given
a real access/ID token to audit for CAMARA spec compliance in its
*claims* (e.g. "does sub contain PII, which the CAMARA Security and
Interoperability Profile explicitly forbids"), not asked to establish
trust in the token as a credential. Signature verification would also
require the issuer's public key/JWKS endpoint, which isn't always
reachable or relevant to what this specific check needs.

For the separate, explicit opt-in case where full signature + expiry
verification IS wanted, see core/jwt_verify.py (used by
`analyze-token --verify-signature`).
"""

from __future__ import annotations

import base64
import json


class JWTDecodeError(ValueError):
    """Raised when a string doesn't have the basic shape of a JWT
    (three dot-separated base64url segments) or a segment isn't valid
    base64url-encoded JSON."""


def _b64url_decode(segment: str) -> bytes:
    # JWT base64url encoding omits padding; re-add it before decoding.
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def decode_jwt_claims(token: str) -> tuple[dict, dict]:
    """Returns (header, payload) dicts. Raises JWTDecodeError on
    anything that doesn't parse — never returns a partial/guessed
    result."""
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    parts = token.split(".")
    if len(parts) != 3:
        raise JWTDecodeError(f"Expected a 3-part JWT (header.payload.signature), got {len(parts)} part(s).")

    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError) as exc:
        raise JWTDecodeError(f"Could not decode JWT header/payload as base64url JSON: {exc}") from exc

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JWTDecodeError("JWT header and payload must both decode to JSON objects.")

    return header, payload
