"""Shared package-firewall entitlement defaults with no GuardStore dependency."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

PACKAGE_FIREWALL_PAID_TIERS = frozenset({"paid", "premium", "pro", "team", "enterprise", "guard_cloud", "guard-cloud"})
_OAUTH_ENTITLEMENT_FALLBACK_TTL = timedelta(days=30)


def _optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def build_guard_local_entitlement_defaults(
    record: dict[str, object],
    *,
    now: datetime | None = None,
) -> dict[str, object] | None:
    plan_id = _optional_string(record.get("plan_id")) or _optional_string(record.get("tier"))
    if plan_id is None:
        return None
    normalized_tier = plan_id.lower()
    allowed_value = record.get("supply_chain_firewall")
    allowed = allowed_value if isinstance(allowed_value, bool) else normalized_tier in PACKAGE_FIREWALL_PAID_TIERS
    expires_at = _optional_string(record.get("expires_at"))
    if expires_at is None:
        resolved_now = now or datetime.now(timezone.utc)
        expires_at = (resolved_now + _OAUTH_ENTITLEMENT_FALLBACK_TTL).isoformat()
    return {
        "plan_id": normalized_tier,
        "supply_chain_entitlement_expires_at": expires_at,
        "supply_chain_firewall": allowed,
        "supply_chain_plan_id": normalized_tier,
    }
