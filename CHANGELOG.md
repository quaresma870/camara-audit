# Changelog

All notable changes to this project are documented here. See the
[README](README.md) for current features and usage.

### v0.2.0
- feat: **`number_verification_enumeration`** (recon tier) — checks a CAMARA Number Verification
  `verify` endpoint for whether its error response echoes back the queried phone number on a
  failed/denied (invalid-token) request, which would let an attacker use the endpoint as an
  unauthenticated oracle for which numbers it actually processes. New `scan-number-verification`
  CLI command.
- test: new mock Number Verification gateway fixture (real HTTP), covering both an echoing
  (vulnerable) and a fully generic (secure) configuration; CI's integration test now also runs
  `scan-number-verification` against it.

### v0.1.0
- feat: **initial release** — authorized CAMARA/Open Gateway API security auditing CLI.
  Authorization/scope model and hash-chained tamper-evident audit logging adapted directly from
  the sibling voipaudit/redteam-toolkit repos' already-audited patterns.
- feat: **`token_endpoint_security`** (recon tier) — checks a CAMARA OAuth2/OIDC token endpoint
  for HTTPS enforcement and client-credentials-via-URL-query-string leakage (RFC 6749 §2.3.1).
  `--insecure` support for self-signed/staging targets.
- feat: **`analyze-token`** — offline JWT claims analysis for PII leakage, grounded in CAMARA's
  own Security and Interoperability Profile requirement that the `sub` claim must not be a
  globally unique identifier or contain PII. File analysis only, no live target touched.
- test: 29 tests, including real HTTP+TLS round trips against a real mock OAuth2 gateway (both a
  securely and a deliberately vulnerably configured instance) — 3 real bugs found and fixed while
  building this: a mismatched bracket, a TLS connection-close race condition causing intermittent
  failures on repeated requests to the same target, and the mock gateway's TLS listener returning
  a hardcoded response regardless of the actual request content (making the vulnerable/secure
  distinction untestable over HTTPS until fixed).
