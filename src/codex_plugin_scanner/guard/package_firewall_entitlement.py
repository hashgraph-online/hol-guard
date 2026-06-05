"""Package-firewall entitlement helpers shared by CLI and daemon flows."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .store import GuardStore

PACKAGE_FIREWALL_PAID_TIERS = frozenset(
    {"paid", "premium", "pro", "team", "enterprise", "guard_cloud", "guard-cloud"}
)
PACKAGE_FIREWALL_RECONNECT_CTA = "Reconnect HOL Guard Cloud to refresh package firewall access."
PACKAGE_FIREWALL_UPGRADE_CTA = "Upgrade to HOL Guard Cloud to run package firewall actions."
_OAUTH_ENTITLEMENT_FALLBACK_TTL = timedelta(days=30)


def _optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _parse_iso_datetime(value: object) -> datetime | None:
    text = _optional_string(value)
    if text is None:
        return None
    normalized = f"{text[:-1]}+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def build_oauth_package_firewall_entitlement(
    payload: dict[str, object],
    *,
    now: datetime | None = None,
) -> dict[str, object] | None:
    record = payload.get("guard_local_entitlement")
    if not isinstance(record, dict):
        return None
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


def _bundle_entitlement(payload: object) -> dict[str, object] | None:
    if not isinstance(payload, dict):
        return None
    tier = _optional_string(payload.get("tier"))
    if tier is None:
        return None
    normalized_tier = tier.lower()
    allowed = normalized_tier in PACKAGE_FIREWALL_PAID_TIERS
    return {
        "allowed": allowed,
        "reason": "paid_entitlement_active" if allowed else "paid_guard_cloud_required",
        "tier": normalized_tier,
        "upgrade_cta": None if allowed else PACKAGE_FIREWALL_UPGRADE_CTA,
    }


def _oauth_entitlement(credentials: dict[str, object] | None, *, now: datetime) -> dict[str, object] | None:
    if not isinstance(credentials, dict):
        return None
    plan_id = _optional_string(credentials.get("supply_chain_plan_id"))
    if plan_id is None:
        return None
    normalized_tier = plan_id.lower()
    firewall_value = credentials.get("supply_chain_firewall")
    firewall_allowed = (
        firewall_value if isinstance(firewall_value, bool) else normalized_tier in PACKAGE_FIREWALL_PAID_TIERS
    )
    expires_at_raw = credentials.get("supply_chain_entitlement_expires_at")
    expires_at = _parse_iso_datetime(expires_at_raw)
    if firewall_allowed and expires_at is None:
        return {
            "allowed": False,
            "reason": "guard_cloud_reconnect_required",
            "tier": normalized_tier,
            "upgrade_cta": PACKAGE_FIREWALL_RECONNECT_CTA,
        }
    if expires_at is not None and expires_at <= now:
        return {
            "allowed": False,
            "reason": "guard_cloud_reconnect_required",
            "tier": normalized_tier,
            "upgrade_cta": PACKAGE_FIREWALL_RECONNECT_CTA,
        }
    if firewall_allowed:
        return {
            "allowed": True,
            "reason": "paid_oauth_entitlement_active",
            "tier": normalized_tier,
            "upgrade_cta": None,
        }
    return {
        "allowed": False,
        "reason": "paid_guard_cloud_required",
        "tier": normalized_tier,
        "upgrade_cta": PACKAGE_FIREWALL_UPGRADE_CTA,
    }


def resolve_package_firewall_entitlement(
    store: GuardStore,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    resolved_now = now or datetime.now(timezone.utc)
    bundle = _bundle_entitlement(store.get_sync_payload("supply_chain_bundle_entitlement"))
    oauth = _oauth_entitlement(store.get_oauth_local_credentials(), now=resolved_now)
    if bundle is not None and bool(bundle.get("allowed")):
        return bundle
    if oauth is not None and bool(oauth.get("allowed")):
        return oauth
    if oauth is not None and oauth.get("reason") == "guard_cloud_reconnect_required":
        return oauth
    if bundle is not None:
        return bundle
    if oauth is not None:
        return oauth
    return {
        "allowed": False,
        "reason": "paid_guard_cloud_required",
        "tier": "free",
        "upgrade_cta": PACKAGE_FIREWALL_UPGRADE_CTA,
    }


def package_firewall_block_details(entitlement: dict[str, object]) -> tuple[int, str, str]:
    if entitlement.get("reason") == "guard_cloud_reconnect_required":
        return (
            403,
            "guard_cloud_reconnect_required",
            "Reconnect HOL Guard Cloud to refresh package firewall access.",
        )
    return (
        402,
        "paid_guard_cloud_required",
        "HOL Guard Cloud paid access is required to run package firewall actions.",
    )
