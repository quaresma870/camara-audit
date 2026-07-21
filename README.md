# 📡 camara-audit

Authorized security auditing for CAMARA / GSMA Open Gateway APIs.

CAMARA is the standardized, telco-industry-backed framework operators are
exposing network capabilities through (Number Verification, SIM Swap,
Device Location, Quality on Demand, and more) — as of March 2026, roughly
80% of global mobile connections are covered by operators supporting the
CAMARA/Open Gateway framework. This is a genuinely new, fast-moving API
surface with very little mature open-source security tooling yet.

---

## ⚠️ Authorization required — read this first

**This tool will not run a single probe without a validated
`authorization.yml`.** CAMARA APIs expose real subscriber data (phone
numbers, device location, SIM status) — probing them without explicit,
written authorization from the target owner is not something this tool
exists to help with. Same tamper-evident audit log design as the sibling
[voipaudit](https://github.com/quaresma870/voipaudit) and
[redteam-toolkit](https://github.com/quaresma870/redteam-toolkit) repos.

---

## Status

Early, actively developed. Covers:

- **`token_endpoint_security`** (recon tier, live scan) — checks a CAMARA
  OAuth2/OIDC token endpoint for two real, documented anti-patterns:
  HTTPS not enforced, and client credentials accepted via URL query
  string (RFC 6749 §2.3.1 requires POST body or Basic auth only — query
  strings get logged everywhere: proxies, load balancers, access logs).
- **`number_verification_enumeration`** (recon tier, live scan) — checks
  whether a CAMARA Number Verification `verify` endpoint echoes the
  queried phone number back in its error response, even when the
  request carries no valid access token — a signal the endpoint can be
  used as an unauthenticated oracle for which numbers it actually
  processes.
- **`sim_swap_rate_limit`** (recon tier, live scan) — checks whether a
  CAMARA SIM Swap `check` endpoint imposes any per-phone-number request
  throttling; an endpoint with no such limit can be polled repeatedly
  to detect the exact moment a target's SIM changes, turning an
  anti-fraud API into a surveillance oracle.
- **`analyze-token`** — offline JWT claims analysis. CAMARA's own
  Security and Interoperability Profile explicitly requires a
  Three-Legged Access Token's `sub` claim to NOT be a globally unique
  identifier nor contain PII — this checks a real token against that
  documented spec requirement (and a few adjacent claims for the same
  class of leak). File/data analysis only, no live target touched.

All live-scan plugins are tested against a real mock OAuth2/CAMARA-style
gateway over real HTTP (and, for the token endpoint, TLS) sockets — not
simulated or assumed.

See [ROADMAP.md](ROADMAP.md) for what's planned next.

## Installation

```bash
git clone https://github.com/quaresma870/camara-audit.git
cd camara-audit
pip install .
```

## Quickstart

```bash
# 1. Create a template — every field still requires manual completion
camara-audit init

# 2. Fill in authorization.yml by hand, get explicit written sign-off
#    from the target owner, then validate it
camara-audit validate-scope

# 3. Scan a token endpoint
camara-audit scan https://api.operator.com/oauth2/token
camara-audit scan https://staging.operator.com/oauth2/token --insecure  # self-signed cert

# 4. Scan a Number Verification endpoint for phone-number-echo enumeration
camara-audit scan-number-verification https://api.operator.com/number-verification/v0/verify

# 5. Scan a SIM Swap endpoint for missing per-phone-number rate limiting
camara-audit scan-sim-swap https://api.operator.com/sim-swap/v1/check

# 6. Analyze a token you already have for PII leakage (no authorization.yml needed)
camara-audit analyze-token "eyJhbGc..."
camara-audit analyze-token "@/path/to/token.txt"
```

## The audit log

Every probe is recorded in `<engagement_id>.audit.jsonl`, hash-chained
so that editing, deleting, or reordering any historical entry is
detectable — same design already used (and audited) in the sibling
voipaudit/redteam-toolkit/secureaudit repos.

## Project structure

```
camara-audit/
├── camara_audit/
│   ├── cli.py                      # init, validate-scope, scan, analyze-token, list-plugins
│   ├── core/
│   │   ├── authorization.py        # Authorization/Scope/Window — HTTP/URL target matching
│   │   ├── engagement.py           # Engagement — ties Authorization + audit log together
│   │   ├── audit_log.py            # hash-chained, append-only audit log
│   │   ├── rate_limit.py           # rate budget defaults
│   │   ├── jwt_tools.py            # unverified JWT claims decoding
│   │   └── models.py               # Finding, Severity, ModuleResult
│   ├── plugins/
│   │   ├── base.py
│   │   ├── token_endpoint_security.py
│   │   ├── number_verification_enumeration.py
│   │   └── sim_swap_rate_limit.py
│   └── analyzers/
│       └── jwt_pii.py              # offline JWT PII leakage analysis, no Engagement gate
├── tests/
│   ├── fixtures/mock_gateway/
│   │   ├── server.py                       # a real HTTP+TLS OAuth2 token gateway, for tests only
│   │   ├── number_verification_server.py   # a real HTTP Number Verification gateway, for tests only
│   │   └── sim_swap_server.py              # a real HTTP SIM Swap gateway, for tests only
│   └── test_camara_audit.py
└── .github/workflows/ci.yml
```

## CI

On every push/PR: lint → build the real wheel → install it in a clean
venv → run the real installed `camara-audit` CLI against a real mock
gateway (both configurations: secure and deliberately vulnerable) — the
same "build it, run it for real" method used throughout this portfolio.

---

## License

MIT — see [LICENSE](LICENSE).
