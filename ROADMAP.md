# Roadmap

This tracks what's shipped and what's planned for `camara-audit`. Order
reflects current priority, not a fixed release schedule.

## Shipped

### v0.1.0
- Authorization/scope model, hash-chained tamper-evident audit log
  (adapted from the sibling voipaudit/redteam-toolkit repos' own proven
  pattern, with HTTP/URL target matching instead of SIP host:port).
- `token_endpoint_security` (recon) — HTTPS enforcement and
  query-string-credential-leakage checks against a real OAuth2/CAMARA
  token endpoint, tested against a real mock gateway over real HTTP and
  TLS sockets, `--insecure` support for self-signed/staging targets.
- `analyze-token` — offline JWT claims analysis for PII leakage,
  grounded in a real, specific CAMARA spec requirement (the `sub` claim
  must not be a globally unique identifier or contain PII). File
  analysis only, no live target touched, no Authorization/Engagement
  gate needed — matching the sibling voipaudit repo's `analyze-cdr`
  precedent for the same reasoning.
- CI: builds the real wheel, installs it in a clean venv, runs every
  documented command against a real mock gateway (both a securely and a
  deliberately vulnerably configured instance).

### v0.2.0
- `number_verification_enumeration` (recon) — checks whether a CAMARA
  Number Verification `verify` endpoint echoes the queried phone number
  back in its error response even on a failed/denied (invalid-token)
  request, which would let an attacker use the endpoint as an
  unauthenticated oracle for which numbers it actually processes.
  Tested against a real mock Number Verification gateway over real
  HTTP, in both an echoing (vulnerable) and a fully generic (secure)
  configuration.

### v0.3.0
- `sim_swap_rate_limit` (recon) — checks whether a CAMARA SIM Swap
  `check` endpoint imposes any per-phone-number request throttling; an
  endpoint with no such limit can be polled repeatedly to detect the
  exact moment a target's SIM changes, turning an anti-fraud API into a
  surveillance oracle. Tested against a real mock SIM Swap gateway over
  real HTTP, in both a throttled (secure) and an unthrottled
  (vulnerable) configuration.

### v0.4.0
- `device_location_accuracy_floor` (recon) — checks whether a CAMARA
  Device Location Verification `verify` endpoint shows signs of
  enforcing a minimum area radius independently of authentication. The
  spec's own `Circle` schema only requires `radius >= 1` meter, with an
  explicit note that implementations "may enforce a larger minimum
  radius (e.g. 1000 meters)" for privacy/regulatory reasons. Unlike the
  two checks above, this one is honest about a real limitation: without
  a valid, scope-limited access token it cannot confirm what an
  authenticated caller would actually be granted, so an inconclusive
  result is reported as LOW ("needs an authenticated follow-up"), never
  as a false MEDIUM/HIGH claim. Tested against a real mock Device
  Location gateway over real HTTP, both with and without a
  pre-authentication radius floor.

This closes out v0.1's "more CAMARA APIs" goal: Number Verification,
SIM Swap, and Device Location — the three most widely deployed CAMARA
APIs today — each now have at least one live check.

## Next

### Scope enforcement testing
A live check for whether an API endpoint actually rejects a request
whose token lacks the required scope — CAMARA's own documented error
format ("Permission denied. OAuth2 token access does not have the
required scope...") gives a concrete signature to test for. Needs a
real token with a deliberately-wrong scope to test with, which is a
bigger practical hurdle than the token-endpoint-only checks shipped so
far (real sandbox credentials from an actual CAMARA-supporting operator
are needed to obtain one).

### Persistence + dashboard
A `--db` flag to persist scan results and a read-only web dashboard,
matching the pattern already used in the sibling secureaudit/
redteam-toolkit/voipaudit repos.

### JWT signature verification (optional, opt-in)
`analyze-token` deliberately never verifies a token's signature today
(see `core/jwt_tools.py`'s own docstring for why) — an opt-in mode that
fetches the issuer's JWKS and verifies signature + expiry would be a
useful, separate addition for auditing a token's full validity, not
just its claim contents.
