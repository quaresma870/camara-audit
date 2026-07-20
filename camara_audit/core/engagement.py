"""
Engagement — ties together a validated Authorization and the tamper-evident
audit log, and is the structural gate every module's network access must
pass through.

Adapted directly from the sibling voipaudit repo's own Engagement (itself
adapted from redteam-toolkit's, already audited across this whole
project's history).
"""

from __future__ import annotations

from pathlib import Path

from camara_audit.core.audit_log import AuditLog
from camara_audit.core.authorization import Authorization, load_authorization


class ScopeViolation(PermissionError):
    """Raised when a module attempts an action outside the validated
    scope, time window, or allowed categories. Always logged before raising."""


class ActiveTierNotConfirmed(ScopeViolation):
    """Raised when an active-tier module is invoked without the
    in-the-moment engagement-ID confirmation, even if 'active' is an
    authorized category."""


class Engagement:
    def __init__(self, authorization: Authorization, audit_log_path: str | Path):
        self.authorization = authorization
        self.audit_log = AuditLog(audit_log_path)
        self._active_tier_confirmed = False

        from camara_audit.core.rate_limit import (
            DEFAULT_MAX_PER_SECOND,
            DEFAULT_MAX_TOTAL_REQUESTS,
            GlobalRateBudget,
        )

        rl = authorization.rate_limits
        self.rate_budget = GlobalRateBudget(
            max_total_requests=rl.max_total_requests if rl else DEFAULT_MAX_TOTAL_REQUESTS,
            max_per_second=rl.max_per_second if rl else DEFAULT_MAX_PER_SECOND,
        )

    @classmethod
    def load(cls, authorization_path: str | Path, audit_log_path: str | Path | None = None) -> Engagement:
        auth = load_authorization(authorization_path)
        if audit_log_path is None:
            audit_log_path = Path(authorization_path).parent / f"{auth.engagement_id}.audit.jsonl"
        return cls(auth, audit_log_path)

    def confirm_active_tier(self, typed_engagement_id: str) -> None:
        if "active" not in self.authorization.scope.allowed_categories:
            self.audit_log.record(
                engagement_id=self.authorization.engagement_id, module="engagement", target="-",
                action="active_tier_confirmation", allowed=False,
                detail={"reason": "'active' is not in this authorization's allowed_categories"},
            )
            raise ActiveTierNotConfirmed(
                "Refused: 'active' is not in this authorization's allowed_categories."
            )

        if typed_engagement_id != self.authorization.engagement_id:
            self.audit_log.record(
                engagement_id=self.authorization.engagement_id, module="engagement", target="-",
                action="active_tier_confirmation", allowed=False,
                detail={"reason": "typed engagement ID did not match"},
            )
            raise ActiveTierNotConfirmed(
                "Refused: typed engagement ID does not match this authorization."
            )

        self._active_tier_confirmed = True
        self.audit_log.record(
            engagement_id=self.authorization.engagement_id, module="engagement", target="-",
            action="active_tier_confirmation", allowed=True, detail={},
        )

    def authorize_action(self, module: str, target: str, action: str, category: str | None = None) -> None:
        allowed = True
        reason = ""

        if not self.authorization.is_within_window():
            allowed = False
            reason = "outside authorized time window"
        elif not self.authorization.is_in_scope(target):
            allowed = False
            reason = "target not in authorized scope"
        elif category and not self.authorization.allows_category(category):
            allowed = False
            reason = f"category '{category}' not in allowed_categories"
        elif category == "active" and not self._active_tier_confirmed:
            allowed = False
            reason = "active-tier not confirmed for this session — call confirm_active_tier() first"

        detail = {"category": category} if allowed else {"category": category, "reason": reason}
        self.audit_log.record(
            engagement_id=self.authorization.engagement_id, module=module, target=target,
            action=action, allowed=allowed, detail=detail,
        )

        if not allowed:
            raise ScopeViolation(f"Refused: {action} against {target} — {reason}")
