"""Package-firewall entitlement helpers shared by CLI and daemon flows."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .store import GuardStore

PACKAGE_FIREWALL_PAID_TIERS = frozenset({"paid", "premium", "pro", "team", "enterprise", "guard_cloud", "guard-cloud"})
PACKAGE_FIREWALL_CONNECT_CTA = (
    "Connect HOL Guard Cloud to check package firewall access and run package firewall actions."
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


def _oauth_entitlement_fields_from_sync_payload(payload: object) -> dict[str, object] | None:
    if not isinstance(payload, dict):
        return None
    fields: dict[str, object] = {}
    for key in (
        "supply_chain_plan_id",
        "supply_chain_firewall",
        "supply_chain_entitlement_expires_at",
        "workspace_id",
    ):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            fields[key] = value.strip()
        elif key == "supply_chain_firewall" and isinstance(value, bool):
            fields[key] = value
    if _optional_string(fields.get("supply_chain_plan_id")) is None:
        return None
    return fields


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
    if firewall_allowed and expires_at is not None and expires_at <= now:
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


def _connect_state_entitlement(store: GuardStore, *, now: datetime) -> dict[str, object] | None:
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    oauth_fields = _oauth_entitlement_fields_from_sync_payload(oauth_payload)
    if isinstance(oauth_fields, dict):
        plan_id = _optional_string(oauth_fields.get("supply_chain_plan_id"))
        if plan_id is not None and plan_id.lower() not in PACKAGE_FIREWALL_PAID_TIERS:
            return None
    latest_state = store.get_effective_guard_connect_state(now=now.isoformat())
    if not isinstance(latest_state, dict):
        return None
    status = _optional_string(latest_state.get("status"))
    milestone = _optional_string(latest_state.get("milestone"))
    if status not in {"retry_required", "expired"} and milestone not in {
        "first_sync_failed",
        "expired",
        "sync_not_available",
    }:
        return None
    tier = "unknown"
    if isinstance(oauth_fields, dict):
        tier = _optional_string(oauth_fields.get("supply_chain_plan_id")) or tier
    return {
        "allowed": False,
        "reason": "guard_cloud_reconnect_required",
        "tier": tier,
        "upgrade_cta": PACKAGE_FIREWALL_RECONNECT_CTA,
    }


def _connect_required_entitlement(store: GuardStore) -> dict[str, object]:
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    tier = "unknown"
    if isinstance(oauth_payload, dict):
        plan_id = _optional_string(oauth_payload.get("supply_chain_plan_id"))
        if plan_id is not None:
            tier = plan_id.lower()
    return {
        "allowed": False,
        "reason": "guard_cloud_connect_required",
        "tier": tier,
        "upgrade_cta": PACKAGE_FIREWALL_CONNECT_CTA,
    }


def _requires_guard_cloud_connect(
    store: GuardStore,
    *,
    bundle: dict[str, object] | None,
    oauth: dict[str, object] | None,
) -> bool:
    oauth_health = store.get_oauth_local_credential_health()
    oauth_configured = bool(oauth_health.get("configured")) if isinstance(oauth_health, dict) else False
    oauth_state = _optional_string(oauth_health.get("state")) if isinstance(oauth_health, dict) else None
    cloud_profile = store.get_cloud_sync_profile()
    if oauth_configured and oauth_state == "healthy":
        return False
    if cloud_profile is not None:
        return False
    if oauth_configured:
        return True
    return not (bundle is not None and bool(bundle.get("allowed")))


def reconcile_connect_state_with_oauth_entitlement(
    store: GuardStore,
    *,
    now: str,
) -> dict[str, object] | None:
    """Clear stale sync_not_available when OAuth credentials reflect a paid plan."""
    latest_state = store.get_effective_guard_connect_state(now=now)
    if not isinstance(latest_state, dict):
        return None
    milestone = _optional_string(latest_state.get("milestone"))
    if milestone != "sync_not_available":
        return None
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    oauth_fields = _oauth_entitlement_fields_from_sync_payload(oauth_payload)
    if not isinstance(oauth_fields, dict):
        return None
    plan_id = _optional_string(oauth_fields.get("supply_chain_plan_id"))
    if plan_id is None or plan_id.lower() not in PACKAGE_FIREWALL_PAID_TIERS:
        return None
    return store.record_latest_guard_connect_sync_result(
        status="connected",
        milestone="first_sync_pending",
        now=now,
        reason=None,
    )


def resolve_package_firewall_entitlement(
    store: GuardStore,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    resolved_now = now or datetime.now(timezone.utc)
    bundle = _bundle_entitlement(store.get_sync_payload("supply_chain_bundle_entitlement"))
    oauth_health = store.get_oauth_local_credential_health()
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    oauth_fields = None
    if isinstance(oauth_health, dict) and oauth_health.get("state") == "healthy":
        oauth_fields = _oauth_entitlement_fields_from_sync_payload(oauth_payload)
    oauth = _oauth_entitlement(oauth_fields, now=resolved_now)
    connect_state = _connect_state_entitlement(store, now=resolved_now)
    if bundle is not None and bool(bundle.get("allowed")):
        return bundle
    if oauth is not None and bool(oauth.get("allowed")):
        return oauth
    if oauth is not None and oauth.get("reason") == "guard_cloud_reconnect_required":
        return oauth
    if connect_state is not None:
        return connect_state
    if _requires_guard_cloud_connect(store, bundle=bundle, oauth=oauth):
        return _connect_required_entitlement(store)
    if bundle is not None:
        return bundle
    if oauth is not None:
        return oauth
    return _connect_required_entitlement(store)


def package_firewall_action_states(
    entitlement: dict[str, object],
    *,
    has_installed_managers: bool,
) -> dict[str, str]:
    allowed = bool(entitlement.get("allowed"))
    reason = str(entitlement.get("reason") or "").strip().lower()
    if allowed:
        blocked_state = "available"
    elif reason == "guard_cloud_connect_required":
        blocked_state = "connect_required"
    elif reason == "guard_cloud_reconnect_required":
        blocked_state = "reconnect_required"
    else:
        blocked_state = "paid_required"
    local_recovery_state = "available" if has_installed_managers else "disabled"
    return {
        "install": blocked_state,
        "repair": local_recovery_state,
        "test": blocked_state,
        "audit": blocked_state,
        "sync": blocked_state,
        "remove": local_recovery_state,
    }


def package_firewall_available_actions(
    entitlement: dict[str, object],
    *,
    has_installed_managers: bool,
) -> list[str]:
    reason = str(entitlement.get("reason") or "").strip().lower()
    actions = ["status"]
    if reason in {"guard_cloud_connect_required", "guard_cloud_reconnect_required"}:
        actions.append("connect")
    if has_installed_managers:
        actions.extend(["repair", "remove"])
    actions.extend(["education", "cli_fallback"])
    return actions


def package_firewall_operation_allowed(
    entitlement: dict[str, object],
    operation: str,
    *,
    has_installed_managers: bool,
) -> bool:
    normalized_operation = operation.strip().lower()
    if normalized_operation in {"status", "connect", "open-shell"}:
        return True
    reason = str(entitlement.get("reason") or "").strip().lower()
    if reason == "guard_cloud_reconnect_required":
        return False
    if bool(entitlement.get("allowed")):
        return True
    if normalized_operation in {"repair", "remove"}:
        return has_installed_managers
    return False


def package_firewall_block_details(entitlement: dict[str, object]) -> tuple[int, str, str]:
    if entitlement.get("reason") == "guard_cloud_connect_required":
        return (
            403,
            "guard_cloud_connect_required",
            "Connect HOL Guard Cloud on this machine before running package firewall actions.",
        )
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
