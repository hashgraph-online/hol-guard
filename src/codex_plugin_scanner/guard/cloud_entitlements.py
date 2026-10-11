"""Typed Guard Cloud entitlement and plan-boundary helpers.

This module deliberately lives outside the local enforcement path. It parses
optional Guard Cloud state so CLI/dashboard surfaces can explain Cloud limits
without ever treating billing or connectivity as a local protection verdict.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Literal, cast

GuardPlanId = Literal["free", "solo", "pro", "team", "enterprise"]
GuardSubscriptionStatus = Literal[
    "free",
    "trialing",
    "active",
    "past_due",
    "canceled",
]

_GUARD_PLAN_IDS = frozenset({"free", "solo", "pro", "team", "enterprise"})
_GUARD_SUBSCRIPTION_STATUSES = frozenset({"free", "trialing", "active", "past_due", "canceled"})
_ALLOWED_FEATURE_VALUE_TYPES = (bool, str, int, float, type(None))


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
