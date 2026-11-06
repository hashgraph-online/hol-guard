"""Sponsored discovery and commercial measurement preferences (Guard Local).

Two independent local gates (PRD SEC-02): sponsored discovery controls
whether the Discover view may show paid placements at all, and commercial
measurement defaults OFF for the newly introduced purpose — rendering works
unmeasured rather than silently tracking. A managed override can prohibit
discovery and/or measurement; it always wins over the user preference and
over any remote rollout flag. Changing either setting immediately stops the
corresponding work: the dashboard clears buffers and displayed content.
"""

from __future__ import annotations

from collections.abc import Mapping

from ..store import GuardStore

_SETTINGS_KEY = "guard_sponsored_discovery_settings_v1"
_MANAGED_KEY = "guard_sponsored_discovery_managed_policy_v1"

_DEFAULTS = {
    "sponsored_discovery_enabled": True,
    # Measurement is a new purpose: opt-in, never inherited from an existing
    # analytics consent that does not demonstrably cover it.
    "sponsored_discovery_measurement_enabled": False,
}


def _load_mapping(store: GuardStore, key: str) -> Mapping[str, object]:
    payload = store.get_sync_payload(key)
    return payload if isinstance(payload, dict) else {}


def sponsored_discovery_settings(store: GuardStore) -> dict[str, object]:
    """Effective settings: user preferences with the managed policy applied."""

    record = _load_mapping(store, _SETTINGS_KEY)
    managed = _load_mapping(store, _MANAGED_KEY)
    # Annotated as object so the bool defaults and the later bool flags share
    # one dict. A bare copy of _DEFAULTS is dict[str, bool], which is not
    # assignable to dict[str, object].
    effective: dict[str, object] = {}
    for name, default in _DEFAULTS.items():
        value = record.get(name)
        effective[name] = value if isinstance(value, bool) else default
    managed_discovery = managed.get("sponsored_discovery_enabled")
    if managed_discovery is False:
        effective["sponsored_discovery_enabled"] = False
    managed_measurement = managed.get("sponsored_discovery_measurement_enabled")
    if managed_measurement is False:
        effective["sponsored_discovery_measurement_enabled"] = False
    effective["managed_discovery_disabled"] = managed_discovery is False
    effective["managed_measurement_disabled"] = managed_measurement is False
    return effective


def sponsored_discovery_allowed(store: GuardStore) -> bool:
    settings = sponsored_discovery_settings(store)
    return settings["sponsored_discovery_enabled"] is True


def sponsored_discovery_measurement_allowed(store: GuardStore) -> bool:
    settings = sponsored_discovery_settings(store)
    return settings["sponsored_discovery_measurement_enabled"] is True


def update_sponsored_discovery_settings(
    store: GuardStore,
    *,
    sponsored_discovery_enabled: bool | None = None,
    sponsored_discovery_measurement_enabled: bool | None = None,
    now: str,
) -> dict[str, object]:
    record = dict(_load_mapping(store, _SETTINGS_KEY))
    if sponsored_discovery_enabled is not None:
        record["sponsored_discovery_enabled"] = sponsored_discovery_enabled
    if sponsored_discovery_measurement_enabled is not None:
        record["sponsored_discovery_measurement_enabled"] = sponsored_discovery_measurement_enabled
    store.set_sync_payload(_SETTINGS_KEY, record, now)
    return sponsored_discovery_settings(store)


__all__ = [
    "sponsored_discovery_allowed",
    "sponsored_discovery_measurement_allowed",
    "sponsored_discovery_settings",
    "update_sponsored_discovery_settings",
]
