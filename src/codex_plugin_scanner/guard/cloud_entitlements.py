"""Typed Guard Cloud entitlement and plan-boundary helpers.

This module deliberately lives outside the local enforcement path. It parses
optional Guard Cloud state so CLI/dashboard surfaces can explain Cloud limits
without ever treating billing or connectivity as a local protection verdict.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal, cast
from urllib.parse import urlparse

GuardPlanId = Literal["free", "solo", "pro", "team", "enterprise"]
GuardSubscriptionStatus = Literal[
    "free",
    "trialing",
    "active",
    "past_due",
    "canceled",
]
GuardCloudErrorCategory = Literal[
    "plan_limit",
    "billing",
    "trial",
    "sync_paused",
    "authentication",
    "cloud_error",
]

_GUARD_PLAN_IDS = frozenset({"free", "solo", "pro", "team", "enterprise"})
_GUARD_SUBSCRIPTION_STATUSES = frozenset({"free", "trialing", "active", "past_due", "canceled"})
_PLAN_LIMIT_CODES = frozenset(
    {
        "feature_not_in_plan",
        "device_limit_reached",
        "retention_limit_reached",
        "storage_limit_reached",
    }
)
_BILLING_CODES = frozenset({"subscription_past_due"})
_TRIAL_CODES = frozenset({"trial_expired"})
_SYNC_PAUSED_CODES = frozenset({"cloud_sync_paused_plan_limit"})
_KNOWN_PLAN_ERROR_CODES = _PLAN_LIMIT_CODES | _BILLING_CODES | _TRIAL_CODES | _SYNC_PAUSED_CODES
_ALLOWED_FEATURE_VALUE_TYPES = (bool, str, int, float, type(None))
_ALLOWED_ACTION_HOSTS = frozenset({"hol.org", "www.hol.org"})


@dataclass(frozen=True)
class GuardCloudEntitlements:
    """Forward-compatible subset of the Portal effective-entitlement contract."""

    plan_id: GuardPlanId
    plan_version: str | None = None
    subscription_status: GuardSubscriptionStatus | None = None
    current_period_end: str | None = None
    trial_end: str | None = None
    max_synced_devices: int | None = None
    active_synced_devices: int | None = None
    retention_days: int | None = None
    cloud_storage_bytes: int | None = None
    cloud_storage_used_bytes: int | None = None
    features: dict[str, bool | str | int | float | None] = field(default_factory=dict)


@dataclass(frozen=True)
class GuardCloudPlanError:
    """Normalized Cloud failure that is explicitly separate from local safety."""

    code: str
    category: GuardCloudErrorCategory
    message: str
    http_status: int | None = None
    plan_id: GuardPlanId | None = None
    limit: int | None = None
    current: int | None = None
    upgrade_plan_id: GuardPlanId | None = None
    manage_url: str | None = None
    upgrade_url: str | None = None
    local_protection_affected: bool = False


def _mapping(value: object) -> Mapping[str, object] | None:
    return value if isinstance(value, Mapping) else None


def _first_value(source: Mapping[str, object], *keys: str) -> object | None:
    """Return the first present non-None value without dropping 0/False."""

    for key in keys:
        value = source.get(key)
        if value is not None:
            return value
    return None


def _optional_string(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def _optional_nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value.is_integer() and value >= 0:
        return int(value)
    return None


def _plan_id(value: object) -> GuardPlanId | None:
    normalized = _optional_string(value)
    if normalized is None:
        return None
    lowered = normalized.lower()
    if lowered not in _GUARD_PLAN_IDS:
        return None
    return cast(GuardPlanId, lowered)


def _subscription_status(value: object) -> GuardSubscriptionStatus | None:
    normalized = _optional_string(value)
    if normalized is None:
        return None
    lowered = normalized.lower()
    if lowered not in _GUARD_SUBSCRIPTION_STATUSES:
        return None
    return cast(GuardSubscriptionStatus, lowered)


def _feature_values(value: object) -> dict[str, bool | str | int | float | None]:
    source = _mapping(value)
    if source is None:
        return {}
    result: dict[str, bool | str | int | float | None] = {}
    for raw_key, raw_value in source.items():
        if not isinstance(raw_key, str) or not raw_key.strip():
            continue
        if isinstance(raw_value, _ALLOWED_FEATURE_VALUE_TYPES):
            result[raw_key.strip()] = raw_value
    return result


def _safe_action_url(value: object) -> str | None:
    url = _optional_string(value)
    if url is None or "\\" in url:
        return None
    if url.startswith("/") and not url.startswith("//"):
        return url
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_ACTION_HOSTS:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port not in {None, 443}:
        return None
    return url


def parse_guard_cloud_entitlements(payload: object) -> GuardCloudEntitlements | None:
    """Parse Portal entitlement state while ignoring unknown additive fields.

    Supports both the full effective-entitlement response (camelCase) and the
    compact OAuth ``guard_local_entitlement`` response (snake_case). The compact
    response intentionally yields ``None`` for fields the server did not send;
    the client never invents plan limits locally.
    """

    root = _mapping(payload)
    if root is None:
        return None
    nested = _mapping(root.get("guard_local_entitlement"))
    source = nested or root

    plan_id = _plan_id(_first_value(source, "planId", "plan_id", "tier"))
    if plan_id is None:
        return None

    features = _feature_values(_first_value(source, "features"))
    if not features:
        features = _feature_values(_first_value(source, "cloudValueGates", "cloud_value_gates"))
    supply_chain_firewall = _first_value(source, "supplyChainFirewall", "supply_chain_firewall")
    if isinstance(supply_chain_firewall, bool):
        features.setdefault("guard.cloud.supply_chain_firewall", supply_chain_firewall)

    cloud_storage_bytes = _optional_nonnegative_int(_first_value(source, "cloudStorageBytes", "cloud_storage_bytes"))
    if cloud_storage_bytes is None:
        storage_gb = _first_value(source, "includedStorageGb", "included_storage_gb")
        if isinstance(storage_gb, (int, float)) and not isinstance(storage_gb, bool) and storage_gb >= 0:
            # Guard's canonical plan contract defines displayed GB storage in
            # binary byte units (Solo 1 GB == 1_073_741_824 bytes).
            cloud_storage_bytes = int(float(storage_gb) * 1024 * 1024 * 1024)

    return GuardCloudEntitlements(
        plan_id=plan_id,
        plan_version=_optional_string(_first_value(source, "planVersion", "plan_version")),
        subscription_status=_subscription_status(_first_value(source, "subscriptionStatus", "subscription_status")),
        current_period_end=_optional_string(_first_value(source, "currentPeriodEnd", "current_period_end")),
        trial_end=_optional_string(_first_value(source, "trialEnd", "trial_end")),
        max_synced_devices=_optional_nonnegative_int(
            _first_value(
                source,
                "maxSyncedDevices",
                "max_synced_devices",
                "deviceLimit",
                "device_limit",
            )
        ),
        active_synced_devices=_optional_nonnegative_int(
            _first_value(source, "activeSyncedDevices", "active_synced_devices")
        ),
        retention_days=_optional_nonnegative_int(_first_value(source, "retentionDays", "retention_days")),
        cloud_storage_bytes=cloud_storage_bytes,
        cloud_storage_used_bytes=_optional_nonnegative_int(
            _first_value(
                source,
                "cloudStorageUsedBytes",
                "cloud_storage_used_bytes",
                "storageUsedBytes",
                "storage_used_bytes",
            )
        ),
        features=features,
    )


def parse_guard_cloud_plan_error(
    payload: object,
    *,
    http_status: int | None = None,
) -> GuardCloudPlanError | None:
    """Normalize machine-actionable Portal plan errors without parsing prose."""

    root = _mapping(payload)
    if root is None:
        return None
    nested = _mapping(root.get("error"))
    source = nested or root
    code = _optional_string(source.get("code"))

    if code in _PLAN_LIMIT_CODES:
        category: GuardCloudErrorCategory = "plan_limit"
    elif code in _BILLING_CODES:
        category = "billing"
    elif code in _TRIAL_CODES:
        category = "trial"
    elif code in _SYNC_PAUSED_CODES:
        category = "sync_paused"
    elif http_status in {401, 403}:
        category = "authentication"
    elif code is not None or (http_status is not None and http_status >= 400):
        category = "cloud_error"
    else:
        return None

    message = _optional_string(source.get("message")) or "Guard Cloud request failed."
    return GuardCloudPlanError(
        code=code or "cloud_request_failed",
        category=category,
        message=message,
        http_status=http_status,
        plan_id=_plan_id(_first_value(source, "planId", "plan_id")),
        limit=_optional_nonnegative_int(source.get("limit")),
        current=_optional_nonnegative_int(source.get("current")),
        upgrade_plan_id=_plan_id(_first_value(source, "upgradePlanId", "upgrade_plan_id")),
        manage_url=_safe_action_url(_first_value(source, "manageUrl", "manage_url")),
        upgrade_url=_safe_action_url(_first_value(source, "upgradeUrl", "upgrade_url")),
    )


def guard_cloud_status_copy(error: GuardCloudPlanError) -> str:
    """Human copy that never implies a Cloud problem disabled local Guard."""

    if error.code == "device_limit_reached":
        upgrade_target = error.upgrade_plan_id.capitalize() if error.upgrade_plan_id is not None else None
        if error.plan_id == "solo" and error.limit == 2:
            upgrade_copy = f"upgrade to {upgrade_target}" if upgrade_target is not None else "change plans"
            return (
                "Your machine is still protected. Solo includes Cloud sync for two devices. "
                f"Choose a device to replace or {upgrade_copy} to sync more personal machines."
            )
        limit_copy = f" ({error.limit} devices)" if error.limit is not None else ""
        upgrade_copy = f"upgrade to {upgrade_target}" if upgrade_target is not None else "change plans"
        return (
            f"Your machine is still protected. Guard Cloud reached this plan's synced-device limit{limit_copy}. "
            f"Manage your synced devices or {upgrade_copy} to resume Cloud sync."
        )
    if error.code == "cloud_sync_paused_plan_limit":
        return "Cloud sync is paused by your plan limit. Local protection is active."
    if error.code == "storage_limit_reached":
        return "Cloud sync is paused because your Cloud storage limit was reached. Local protection continues."
    if error.code == "subscription_past_due":
        return "Guard Cloud billing needs attention. Local protection remains active."
    if error.code == "trial_expired":
        return "Your Guard Cloud trial ended. Local protection remains active."
    if error.category == "cloud_error":
        return "Guard Cloud is unavailable or the request failed. Local protection continues."
    return f"{error.message} Local protection remains active."


def guard_cloud_history_copy(entitlements: GuardCloudEntitlements) -> str | None:
    """Plan-aware Cloud history label with no embedded prices."""

    if entitlements.retention_days is None:
        return None
    if entitlements.retention_days <= 0:
        return "Cloud history is not included on this plan."
    return f"{entitlements.retention_days}-day Cloud history"


def is_known_guard_plan_error_code(code: str) -> bool:
    return code in _KNOWN_PLAN_ERROR_CODES
