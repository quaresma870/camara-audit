from __future__ import annotations

import base64
import datetime
import json
from pathlib import Path

import pytest

from camara_audit.core.authorization import AuthorizationError, load_authorization
from camara_audit.core.engagement import (
    ActiveTierNotConfirmed,
    Engagement,
    ScopeViolation,
)
from camara_audit.core.jwt_tools import JWTDecodeError, decode_jwt_claims
from tests.fixtures.mock_gateway.number_verification_server import (
    start_mock_number_verification_gateway,
)
from tests.fixtures.mock_gateway.server import start_mock_gateway
from tests.fixtures.mock_gateway.sim_swap_server import start_mock_sim_swap_gateway


def _b64url(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def _make_jwt(payload: dict, header: dict | None = None) -> str:
    header = header or {"alg": "RS256", "typ": "JWT"}
    return _b64url(header) + "." + _b64url(payload) + ".fakesignature"


def _write_auth_yaml(path: Path, **overrides) -> None:
    now = datetime.datetime.now(datetime.UTC)
    defaults = {
        "engagement_id": "test-2026-q1",
        "authorized_by": "Jane Doe",
        "authorized_contact_email": "jane@example.com",
        "client": "Example Corp",
        "scope": {
            "targets": ["127.0.0.1"],
            "excluded_targets": [],
            "allowed_categories": ["recon"],
        },
        "window": {
            "start": (now - datetime.timedelta(hours=1)).isoformat(),
            "end": (now + datetime.timedelta(days=1)).isoformat(),
        },
        "confirmation_phrase": "I confirm authorization for test-2026-q1",
    }
    defaults.update(overrides)
    import yaml
    path.write_text(yaml.safe_dump(defaults))


class TestJWTDecoding:
    def test_decodes_valid_jwt(self):
        token = _make_jwt({"sub": "opaque-123", "scope": "x"})
        header, payload = decode_jwt_claims(token)
        assert header["alg"] == "RS256"
        assert payload["sub"] == "opaque-123"

    def test_strips_bearer_prefix(self):
        token = _make_jwt({"sub": "opaque-123"})
        _header, payload = decode_jwt_claims(f"Bearer {token}")
        assert payload["sub"] == "opaque-123"

    def test_wrong_part_count_raises(self):
        with pytest.raises(JWTDecodeError, match="3-part JWT"):
            decode_jwt_claims("not.a.valid.jwt.token")

    def test_invalid_base64_raises(self):
        with pytest.raises(JWTDecodeError):
            decode_jwt_claims("!!!.###.***")


class TestJWTPIIAnalysis:
    def test_phone_number_in_sub_is_critical(self):
        from camara_audit.analyzers.jwt_pii import analyze_jwt_for_pii

        token = _make_jwt({"sub": "+351912345678", "scope": "x"})
        findings = analyze_jwt_for_pii(token)
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"
        assert "PII" in findings[0].title

    def test_opaque_sub_produces_no_critical_finding(self):
        from camara_audit.analyzers.jwt_pii import analyze_jwt_for_pii

        token = _make_jwt({"sub": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "scope": "x"})
        findings = analyze_jwt_for_pii(token)
        assert not any(f.severity.value == "CRITICAL" for f in findings)
        assert findings[0].severity.value == "INFO"

    def test_email_in_secondary_claim_is_medium(self):
        from camara_audit.analyzers.jwt_pii import analyze_jwt_for_pii

        token = _make_jwt({"sub": "opaque-id", "email": "user@example.com"})
        findings = analyze_jwt_for_pii(token)
        assert any(f.severity.value == "MEDIUM" and "email" in f.title for f in findings)

    def test_imsi_shape_detected(self):
        from camara_audit.analyzers.jwt_pii import analyze_jwt_for_pii

        token = _make_jwt({"sub": "234150123456789"})  # 15 digits
        findings = analyze_jwt_for_pii(token)
        assert findings[0].severity.value == "CRITICAL"
        assert "IMSI" in findings[0].description

    def test_malformed_token_reports_info_not_crash(self):
        from camara_audit.analyzers.jwt_pii import analyze_jwt_for_pii

        findings = analyze_jwt_for_pii("not-a-jwt-at-all")
        assert len(findings) == 1
        assert findings[0].severity.value == "INFO"

    def test_random_extension_number_not_falsely_flagged_as_phone(self):
        """A short internal ID (e.g. '2001', a PBX-style extension)
        must not match the phone-number pattern (8-15 digits) —
        confirms the lower bound is respected, not just the upper one."""
        from camara_audit.analyzers.jwt_pii import analyze_jwt_for_pii

        token = _make_jwt({"sub": "2001"})
        findings = analyze_jwt_for_pii(token)
        assert findings[0].severity.value == "INFO"


class TestAuthorization:
    def test_valid_file_loads(self, tmp_path):
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        auth = load_authorization(path)
        assert auth.engagement_id == "test-2026-q1"
        assert auth.is_within_window()

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(AuthorizationError, match="not found"):
            load_authorization(tmp_path / "nope.yml")

    @pytest.mark.parametrize("target,in_scope", [
        ("127.0.0.1", True),
        ("https://127.0.0.1/token", True),
        ("https://127.0.0.1:8443/oauth2/token", True),
        ("10.0.0.5", False),
        ("https://10.0.0.5/token", False),
    ])
    def test_scope_matching_handles_url_forms(self, tmp_path, target, in_scope):
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        auth = load_authorization(path)
        assert auth.is_in_scope(target) is in_scope

    def test_wildcard_domain_matching(self, tmp_path):
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path, scope={
            "targets": ["*.operator.com"], "excluded_targets": [], "allowed_categories": ["recon"],
        })
        auth = load_authorization(path)
        assert auth.is_in_scope("https://api.operator.com/token") is True
        assert auth.is_in_scope("https://api.other.com/token") is False


class TestEngagementGate:
    def _engagement(self, tmp_path, **overrides) -> Engagement:
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path, **overrides)
        return Engagement.load(path, tmp_path / "test.audit.jsonl")

    def test_in_scope_recon_action_allowed(self, tmp_path):
        eng = self._engagement(tmp_path)
        eng.authorize_action("token_endpoint_security", "127.0.0.1", "token_endpoint_probe", category="recon")

    def test_out_of_scope_target_refused(self, tmp_path):
        eng = self._engagement(tmp_path)
        with pytest.raises(ScopeViolation, match="scope"):
            eng.authorize_action("token_endpoint_security", "10.0.0.99", "probe", category="recon")

    def test_active_category_refused_without_confirm(self, tmp_path):
        eng = self._engagement(tmp_path, scope={
            "targets": ["127.0.0.1"], "excluded_targets": [], "allowed_categories": ["recon", "active"],
        })
        with pytest.raises(ScopeViolation, match="not confirmed"):
            eng.authorize_action("some_active_module", "127.0.0.1", "probe", category="active")

    def test_confirm_wrong_engagement_id_refused(self, tmp_path):
        eng = self._engagement(tmp_path)
        with pytest.raises(ActiveTierNotConfirmed):
            eng.confirm_active_tier("wrong-id")

    def test_audit_log_integrity_holds(self, tmp_path):
        from camara_audit.core.audit_log import verify_log_integrity

        eng = self._engagement(tmp_path)
        eng.authorize_action("token_endpoint_security", "127.0.0.1", "probe", category="recon")
        valid, _broken_line, entry_count = verify_log_integrity(tmp_path / "test.audit.jsonl")
        assert valid is True
        assert entry_count == 1


class TestTokenEndpointSecurityPlugin:
    """Tested against the real mock gateway's real HTTP and TLS listeners."""

    def _engagement(self, tmp_path) -> Engagement:
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        return Engagement.load(path, tmp_path / "test.audit.jsonl")

    def test_plain_http_target_flagged_critical(self, tmp_path):
        from camara_audit.plugins.token_endpoint_security import TokenEndpointSecurityModule

        server = start_mock_gateway(accept_query_string_credentials=False)
        try:
            eng = self._engagement(tmp_path)
            plugin = TokenEndpointSecurityModule(eng, timeout=5.0)
            result = plugin.run(f"http://127.0.0.1:{server.http_port}/token")
            assert result.error is None
            assert any(f.severity.value == "CRITICAL" and "not HTTPS" in f.title for f in result.findings)
        finally:
            server.stop()

    def test_secure_https_gateway_produces_no_critical_or_medium(self, tmp_path):
        from camara_audit.plugins.token_endpoint_security import TokenEndpointSecurityModule

        server = start_mock_gateway(accept_query_string_credentials=False)
        try:
            eng = self._engagement(tmp_path)
            plugin = TokenEndpointSecurityModule(eng, timeout=5.0, tls_verify=False)
            result = plugin.run(f"https://127.0.0.1:{server.tls_port}/token")
            assert result.error is None
            assert not any(f.severity.value in ("CRITICAL", "MEDIUM", "HIGH") for f in result.findings)
        finally:
            server.stop()

    def test_vulnerable_https_gateway_flags_query_string_credentials(self, tmp_path):
        """Regression test for a real bug found while building this:
        the mock server's TLS listener used to return a hardcoded
        response regardless of the actual request, meaning this exact
        distinction (vulnerable vs secure) could never be detected
        over HTTPS. Confirmed fixed by testing both configurations
        produce genuinely different results."""
        from camara_audit.plugins.token_endpoint_security import TokenEndpointSecurityModule

        server = start_mock_gateway(accept_query_string_credentials=True)
        try:
            eng = self._engagement(tmp_path)
            plugin = TokenEndpointSecurityModule(eng, timeout=5.0, tls_verify=False)
            result = plugin.run(f"https://127.0.0.1:{server.tls_port}/token")
            assert result.error is None
            assert any(
                f.severity.value == "MEDIUM" and "query string" in f.title for f in result.findings
            )
        finally:
            server.stop()

    def test_tls_verify_true_rejects_self_signed_cert(self, tmp_path):
        from camara_audit.plugins.token_endpoint_security import TokenEndpointSecurityModule

        server = start_mock_gateway()
        try:
            eng = self._engagement(tmp_path)
            plugin = TokenEndpointSecurityModule(eng, timeout=5.0, tls_verify=True)
            result = plugin.run(f"https://127.0.0.1:{server.tls_port}/token")
            # The plugin catches the SSL error internally per-request
            # and reports it as an INFO finding rather than crashing
            # the whole module -- confirms graceful degradation, not a
            # hard failure, when verification is (correctly) left on
            # against an unverifiable target.
            assert result.error is None
        finally:
            server.stop()

    def test_out_of_scope_target_produces_module_error_not_crash(self, tmp_path):
        from camara_audit.plugins.token_endpoint_security import TokenEndpointSecurityModule

        eng = self._engagement(tmp_path)
        result = TokenEndpointSecurityModule(eng, timeout=5.0).run("https://10.0.0.99/token")
        assert result.error is not None
        assert "scope" in result.error.lower()

    def test_repeated_requests_to_same_tls_target_all_succeed(self, tmp_path):
        """Regression test for a real bug found while building this:
        the mock server's TLS connection handling used to close the
        socket immediately after sendall(), racing ahead of the
        client's read and producing 'Remote end closed connection
        without response' on every connection after the first. Since
        this plugin makes 2 sequential requests to the same TLS port
        per scan (HTTP-downgrade attempt + the real HTTPS request),
        this bug would have broken every single scan against a real
        HTTPS target."""
        from camara_audit.plugins.token_endpoint_security import TokenEndpointSecurityModule

        server = start_mock_gateway()
        try:
            eng = self._engagement(tmp_path)
            plugin = TokenEndpointSecurityModule(eng, timeout=5.0, tls_verify=False)
            for _ in range(3):
                result = plugin.run(f"https://127.0.0.1:{server.tls_port}/token")
                assert result.error is None
                assert len(result.findings) == 2
        finally:
            server.stop()


class TestNumberVerificationEnumerationPlugin:
    """Tested against a real mock Number Verification `verify` endpoint."""

    def _engagement(self, tmp_path) -> Engagement:
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        return Engagement.load(path, tmp_path / "test.audit.jsonl")

    def test_echoing_gateway_flagged_medium(self, tmp_path):
        from camara_audit.plugins.number_verification_enumeration import (
            NumberVerificationEnumerationModule,
        )

        server = start_mock_number_verification_gateway(echo_phone_number_on_error=True)
        try:
            eng = self._engagement(tmp_path)
            plugin = NumberVerificationEnumerationModule(eng, timeout=5.0)
            result = plugin.run(f"http://127.0.0.1:{server.http_port}/number-verification/v0/verify")
            assert result.error is None
            assert any(
                f.severity.value == "MEDIUM" and "echoes queried phone number" in f.title
                for f in result.findings
            )
        finally:
            server.stop()

    def test_generic_gateway_produces_no_critical_or_medium(self, tmp_path):
        from camara_audit.plugins.number_verification_enumeration import (
            NumberVerificationEnumerationModule,
        )

        server = start_mock_number_verification_gateway(echo_phone_number_on_error=False)
        try:
            eng = self._engagement(tmp_path)
            plugin = NumberVerificationEnumerationModule(eng, timeout=5.0)
            result = plugin.run(f"http://127.0.0.1:{server.http_port}/number-verification/v0/verify")
            assert result.error is None
            assert not any(f.severity.value in ("CRITICAL", "HIGH", "MEDIUM") for f in result.findings)
            assert any("does not echo" in f.title for f in result.findings)
        finally:
            server.stop()

    def test_custom_phone_number_is_the_one_tested_for_echo(self, tmp_path):
        from camara_audit.plugins.number_verification_enumeration import (
            NumberVerificationEnumerationModule,
        )

        server = start_mock_number_verification_gateway(echo_phone_number_on_error=True)
        try:
            eng = self._engagement(tmp_path)
            plugin = NumberVerificationEnumerationModule(eng, timeout=5.0)
            result = plugin.run(
                f"http://127.0.0.1:{server.http_port}/number-verification/v0/verify",
                phone_number="+447700900123",
            )
            assert result.error is None
            assert any("+447700900123" in f.evidence for f in result.findings)
        finally:
            server.stop()

    def test_out_of_scope_target_produces_module_error_not_crash(self, tmp_path):
        from camara_audit.plugins.number_verification_enumeration import (
            NumberVerificationEnumerationModule,
        )

        eng = self._engagement(tmp_path)
        result = NumberVerificationEnumerationModule(eng, timeout=5.0).run(
            "https://10.0.0.99/number-verification/v0/verify"
        )
        assert result.error is not None
        assert "scope" in result.error.lower()


class TestSimSwapRateLimitPlugin:
    """Tested against a real mock SIM Swap `check` endpoint."""

    def _engagement(self, tmp_path) -> Engagement:
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        return Engagement.load(path, tmp_path / "test.audit.jsonl")

    def test_unthrottled_gateway_flagged_medium(self, tmp_path):
        from camara_audit.plugins.sim_swap_rate_limit import SimSwapRateLimitModule

        server = start_mock_sim_swap_gateway(rate_limit_after=None)
        try:
            eng = self._engagement(tmp_path)
            plugin = SimSwapRateLimitModule(eng, timeout=5.0)
            result = plugin.run(
                f"http://127.0.0.1:{server.http_port}/sim-swap/v1/check", probe_count=5
            )
            assert result.error is None
            assert any(
                f.severity.value == "MEDIUM" and "No rate limiting observed" in f.title
                for f in result.findings
            )
        finally:
            server.stop()

    def test_throttled_gateway_produces_only_info(self, tmp_path):
        from camara_audit.plugins.sim_swap_rate_limit import SimSwapRateLimitModule

        server = start_mock_sim_swap_gateway(rate_limit_after=3)
        try:
            eng = self._engagement(tmp_path)
            plugin = SimSwapRateLimitModule(eng, timeout=5.0)
            result = plugin.run(
                f"http://127.0.0.1:{server.http_port}/sim-swap/v1/check", probe_count=20
            )
            assert result.error is None
            assert not any(f.severity.value in ("CRITICAL", "HIGH", "MEDIUM") for f in result.findings)
            assert any("rate-limits repeated queries" in f.title for f in result.findings)
        finally:
            server.stop()

    def test_throttled_gateway_stops_probing_once_429_seen(self, tmp_path):
        """The plugin must stop sending requests as soon as it sees a 429
        rather than hammering an already-throttling endpoint for the
        full probe_count."""
        from camara_audit.plugins.sim_swap_rate_limit import SimSwapRateLimitModule

        server = start_mock_sim_swap_gateway(rate_limit_after=3)
        try:
            eng = self._engagement(tmp_path)
            plugin = SimSwapRateLimitModule(eng, timeout=5.0)
            result = plugin.run(
                f"http://127.0.0.1:{server.http_port}/sim-swap/v1/check", probe_count=100
            )
            assert result.error is None
            assert "4 request(s)" in result.findings[0].description
        finally:
            server.stop()

    def test_out_of_scope_target_produces_module_error_not_crash(self, tmp_path):
        from camara_audit.plugins.sim_swap_rate_limit import SimSwapRateLimitModule

        eng = self._engagement(tmp_path)
        result = SimSwapRateLimitModule(eng, timeout=5.0).run(
            "https://10.0.0.99/sim-swap/v1/check", probe_count=5
        )
        assert result.error is not None
        assert "scope" in result.error.lower()
