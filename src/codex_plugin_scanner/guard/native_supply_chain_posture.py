"""Resident bridge for the ``package_posture`` op.

The resident owns the local supply-chain posture: the status, the health, the
refresh schedule, the bundle and the cloud-managed policy projection. This
module only hydrates the facts the resident cannot read (the sync payloads, the
configured risk actions and the package-manager shim status), transports one
request and strictly validates the reply. A missing, mismatched or malformed
answer raises :class:`NativePackagePostureError`; there is no Python fallback.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import GuardConfig, resolve_risk_action
from .native_context import _resolve_digest_home
from .native_package_approval_hash import _transport

_POSTURE_FEATURE = "package-posture-v1"
_POSTURE_KEYS = frozenset(
    {
        "status",
        "health_status",
        "detail",
        "connection",
        "bundle",
        "policy",
        "supported_ecosystems",
        "package_manager_protection",
    }
)


class NativePackagePostureError(RuntimeError):
    """No authoritative native supply-chain posture was available."""


def _dict_payload(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def _hydrate(store: Any, config: GuardConfig, *, now: str | None) -> dict[str, object]:
    from .synced_policy import synced_policy_payload

    workspace_id = store.get_cloud_workspace_id()
    cached_bundle = store.get_cached_supply_chain_bundle(workspace_id) if workspace_id else None
    request: dict[str, object] = {
        "credentials_present": store.get_cloud_sync_profile() is not None,
        "summary": _dict_payload(store.get_sync_payload("supply_chain_bundle_summary")),
        "entitlement": _dict_payload(store.get_sync_payload("supply_chain_bundle_entitlement")),
        "remote_policy": _dict_payload(synced_policy_payload(store)),
        "bundle_payload": _dict_payload(cached_bundle.get("bundle")) if isinstance(cached_bundle, dict) else {},
        "security_level": config.security_level,
    }
    for key, value in (
        ("now", now),
        ("workspace_id", workspace_id),
        ("config_cloud_advisory_action", resolve_risk_action(config, "cloud_advisory", harness=None)),
        ("config_package_script_action", resolve_risk_action(config, "package_script", harness=None)),
    ):
        if value is not None:
            request[key] = value
    return request


def native_local_supply_chain_posture(
    store: Any,
    config: GuardConfig,
    *,
    now: str | None,
    package_manager_protection: dict[str, object],
) -> dict[str, object]:
    """Return the resident-derived supply-chain posture for the stored Cloud state."""

    request = _hydrate(store, config, now=now)
    request["package_manager_protection"] = package_manager_protection
    guard_home = _resolve_digest_home(Path(store.guard_home) if getattr(store, "guard_home", None) else None)
    payload = _transport(
        request,
        guard_home,
        operation="package_posture",
        feature=_POSTURE_FEATURE,
        error=NativePackagePostureError,
    )
    if set(payload) != _POSTURE_KEYS or not all(isinstance(payload[key], str) for key in ("status", "health_status")):
        raise NativePackagePostureError("Native package posture invalid")
    return payload
