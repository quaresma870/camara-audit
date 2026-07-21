# Changelog

All notable changes to this project are documented here. See the
[README](README.md) for current features and usage.

### v0.4.0
- feat: **`device_location_accuracy_floor`** (recon tier) — checks a CAMARA Device Location
  Verification `verify` endpoint for signs it enforces a minimum area radius (an accuracy floor)
  independently of authentication. Grounded in the spec's own `Circle` schema note that
  implementations "may enforce a larger minimum radius (e.g. 1000 meters)" beyond the bare
  `minimum: 1` the schema requires. Honestly reports an inconclusive result as LOW (not a false
  MEDIUM/HIGH claim) when it can't confirm the floor without a real authenticated token. New
  `scan-device-location` CLI command.
- test: new mock Device Location gateway fixture (real HTTP), covering both a
  pre-authentication-radius-floor-enforcing and a non-enforcing configuration; CI's integration
  test now also runs `scan-device-location` against it.
- This closes out the "more CAMARA APIs" roadmap goal from v0.1: Number Verification, SIM Swap,
  and Device Location — the three most widely deployed CAMARA APIs today — each now have at least
  one live check.

### v0.3.0
- feat: **`sim_swap_rate_limit`** (recon tier) — checks a CAMARA SIM Swap `check` endpoint for
  whether it imposes any per-phone-number request throttling; an endpoint that answers an
  unlimited number of repeated queries for the same number can be polled to detect the exact
  moment a target's SIM changes, turning a fraud-prevention API into a surveillance oracle. New
  `scan-sim-swap` CLI command.
- test: new mock SIM Swap gateway fixture (real HTTP), covering both a throttled (secure) and an
  unthrottled (vulnerable) configuration; CI's integration test now also runs `scan-sim-swap`
  against it.

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
