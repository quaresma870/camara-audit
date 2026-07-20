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

## Next

### More CAMARA APIs beyond Number Verification's token endpoint
v0.1 focuses on the OAuth2/OIDC layer common to every CAMARA API. Next:
API-specific checks for the actual resource endpoints —
Number Verification, SIM Swap, and Device Location are the most widely
deployed today and the natural next targets:
- **Number Verification**: does the API's error response ever echo back
  the queried phone number in a way that lets an attacker enumerate
  which numbers are valid/registered, even on a failed/denied request?
- **SIM Swap**: does the API rate-limit swap-status queries per
  phone number tightly enough to prevent using it as a surveillance
  oracle (repeatedly querying to detect exactly when a target's SIM
  changes)?
- **Device Location**: does the API enforce the documented accuracy/
  consent-scope restrictions, or can a client request finer-grained
  location than its granted scope should allow?

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
