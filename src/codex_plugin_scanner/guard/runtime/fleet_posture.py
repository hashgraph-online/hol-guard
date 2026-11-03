"""Build the ``fleet-posture/v1`` object that rides in ``syncContext.fleetPosture``.

The contract lives in ``contracts/fleet-posture/v1`` and is documented in
``docs/guard/fleet-posture.md``. This module collects the machine, AI-tool,
inventory and policy facts. The native runtime derives each tool's protection
state, decides whether the inventory goes out as ``full``, ``delta`` or
``digest_only``, and fits the payload under its byte cap
(``fleet_posture_inventory.rs``).

Building never writes inventory state. ``build_fleet_posture_state`` returns the
payload together with the next "last sent" snapshot, and the caller commits that
snapshot with ``commit_fleet_posture_sent`` only after Guard Cloud accepted the
request.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from ..native_runner_authority import native_runner_authority
from .fleet_posture_common import (
    CAPABILITY,
    FOLLOWUP_STATE_KEY,
    FORCE_FULL_STATE_KEY,
    HARNESS_IDS,
    HASH_KEY_STATE_KEY,
    LAST_SENT_STATE_KEY,
    MAX_PAYLOAD_BYTES,
    SCHEMA_VERSION,
    SETTINGS_STATE_KEY,
    clip,
    iso,
    load_hash_key,
    normalized_timestamp,
    utc,
)
from .fleet_posture_inventory import chunked_last, committed_state, projected_rows, store_home
from .fleet_posture_runtimes import RUNTIMES_TTL_SECONDS, runtimes_section
from .fleet_posture_tools import (
    AUTO_UPDATE_STATE_KEY,
    DIAGNOSTICS_TTL_SECONDS,
    DiagnosticsCache,
    client_facts,
    machine_section,
    tool_row,
)

if TYPE_CHECKING:
    from ..adapters.base import HarnessContext
    from ..config import GuardConfig
    from ..store import GuardStore


@dataclass(frozen=True)
class FleetPostureSettings:
    """Inputs the builder needs besides the store and the adapter list."""

    context: HarnessContext
    guard_config: GuardConfig | None = None
    now: datetime | None = None
    runtime: str = "python"
    # ``None`` reads the persisted opt-out from the store.
    reporting_enabled: bool | None = None
    force_full: bool | None = None
    extra: Mapping[str, object] = field(default_factory=dict)
    diagnostics_ttl_seconds: int = DIAGNOSTICS_TTL_SECONDS
    runtimes_ttl_seconds: int = RUNTIMES_TTL_SECONDS


@dataclass(frozen=True)
class FleetPostureBuild:
    """A built payload plus the snapshot to record once Guard Cloud accepts it."""

    payload: dict[str, object]
    next_state: dict[str, object]
    mode: str
    payload_bytes: int
    advanced_inventory: bool


# --------------------------------------------------------------------------- settings


def fleet_posture_managed(config: GuardConfig | None) -> bool:
    """MDM-managed installs always report; the opt-out is ignored for them."""

    return config is not None and getattr(config, "install_owner", "user") == "mdm"


def fleet_posture_opted_out(store: GuardStore) -> bool:
    """Whether the user ran ``hol-guard settings set fleet-posture off``."""

    raw = store.get_sync_payload(SETTINGS_STATE_KEY)
    return isinstance(raw, dict) and raw.get("enabled") is False


def set_fleet_posture_reporting(store: GuardStore, *, enabled: bool, now: str) -> dict[str, object]:
    """Persist the opt-out choice and return the new settings record."""

    record: dict[str, object] = {"enabled": enabled, "updatedAt": now}
    store.set_sync_payload(SETTINGS_STATE_KEY, record, now)
    return record


def fleet_posture_reporting_enabled(store: GuardStore, config: GuardConfig | None) -> bool:
    """Effective detail level: managed installs ignore the opt-out."""

    return fleet_posture_managed(config) or not fleet_posture_opted_out(store)


def request_full_inventory(store: GuardStore, *, source: str, now: str) -> None:
    """Make the next posture go out with ``inventory.mode = "full"``."""

    store.set_sync_payload(FORCE_FULL_STATE_KEY, {"requestedAt": now, "source": source}, now)


def full_inventory_requested(store: GuardStore) -> bool:
    raw = store.get_sync_payload(FORCE_FULL_STATE_KEY)
    return isinstance(raw, dict) and bool(raw)


def _clear_full_inventory_request(store: GuardStore, now: str) -> None:
    if full_inventory_requested(store):
        store.set_sync_payload(FORCE_FULL_STATE_KEY, {}, now)


# --------------------------------------------------------------------------- policy


def _int_or_none(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 1:
        return value
    return None


def policy_section(store: GuardStore, acknowledgement: Mapping[str, object] | None) -> dict[str, object]:
    """Mirror the acknowledgement Guard is sending in the same request."""

    section: dict[str, object] = {
        "appliedBundleVersion": None,
        "appliedBundleHash": None,
        "appliedPolicyVersionNumber": None,
        "status": "none",
        "errorCode": None,
        "appliedAt": None,
    }
    if isinstance(acknowledgement, Mapping) and acknowledgement:
        bundle_hash = acknowledgement.get("bundleHash")
        status = str(acknowledgement.get("status") or "")
        mapped = {"applied": "applied", "synced": "applied", "validated": "validated", "failed": "rejected"}.get(
            status, "none"
        )
        error_code = acknowledgement.get("errorCode") or acknowledgement.get("reason")
        section.update(
            {
                "appliedBundleVersion": _int_or_none(acknowledgement.get("bundleVersion")),
                "appliedBundleHash": clip(bundle_hash, 80) if isinstance(bundle_hash, str) else None,
                "appliedPolicyVersionNumber": _int_or_none(acknowledgement.get("policyRevision")),
                "status": mapped,
                "errorCode": clip(error_code, 80) if mapped == "rejected" and isinstance(error_code, str) else None,
                "appliedAt": normalized_timestamp(
                    acknowledgement.get("appliedAt") or acknowledgement.get("observedAt")
                ),
            }
        )
        return section
    last_error = store.get_sync_payload("policy_bundle_last_error")
    if isinstance(last_error, dict) and isinstance(last_error.get("reason"), str):
        section["status"] = "rejected"
        section["errorCode"] = clip(str(last_error["reason"]), 80)
    return section


# --------------------------------------------------------------------------- build


def build_fleet_posture_state(
    store: GuardStore,
    adapters: Iterable[Any],
    settings: FleetPostureSettings,
    *,
    acknowledgement: Mapping[str, object] | None = None,
) -> FleetPostureBuild:
    """Collect the posture and plan the inventory transmission."""

    now = utc(settings.now)
    config = settings.guard_config
    detail = (
        settings.reporting_enabled
        if settings.reporting_enabled is not None
        else fleet_posture_reporting_enabled(store, config)
    )
    if settings.reporting_enabled is not None:
        detail = bool(settings.reporting_enabled) or fleet_posture_managed(config)
    force_full = settings.force_full if settings.force_full is not None else full_inventory_requested(store)
    last_raw = store.get_sync_payload(LAST_SENT_STATE_KEY)
    last = last_raw if isinstance(last_raw, dict) else None

    now_text = iso(now)
    # Raises when the inventory cannot be read: the runner then omits this posture
    # rather than reporting an empty inventory.
    hash_key = load_hash_key(store, now_text)
    from .fleet_posture_aibom import fleet_inventory_rows

    rows = projected_rows(fleet_inventory_rows(store))
    diagnostics_cache = DiagnosticsCache(store, now=now, ttl_seconds=settings.diagnostics_ttl_seconds)
    tools: list[dict[str, object]] = []
    for adapter in adapters:
        harness = getattr(adapter, "harness", "")
        if harness not in HARNESS_IDS:
            continue
        diagnostics = diagnostics_cache.lookup(adapter, settings.context)
        if diagnostics is None:
            continue
        tools.append(tool_row(adapter=adapter, diagnostics=diagnostics, store=store, config=config))
    diagnostics_cache.save()

    # Runtime identities are detail: a minimal report leaves them out.
    runtimes = (
        runtimes_section(store, settings.context, hash_key=hash_key, now=now, ttl_seconds=settings.runtimes_ttl_seconds)
        if detail
        else None
    )
    built = native_runner_authority(
        "fleet_posture_build",
        {
            "rows": rows,
            "hash_key": hash_key.decode("utf-8"),
            "last": chunked_last(last),
            "now": now.isoformat(),
            "force_full": bool(force_full),
            "detail": bool(detail),
            "max_payload_bytes": MAX_PAYLOAD_BYTES,
            "client": client_facts(store, settings.runtime),
            "machine": machine_section(include_os_version=detail, hash_key=hash_key),
            "policy": policy_section(store, acknowledgement),
            "runtimes": runtimes,
            "tools": tools,
        },
        store_home(store),
    )
    return FleetPostureBuild(
        payload=built["payload"],
        next_state=committed_state(last, built["next_state"]),
        mode=built["mode"],
        payload_bytes=built["payload_bytes"],
        advanced_inventory=built["advanced_inventory"],
    )


def commit_fleet_posture_sent(store: GuardStore, built: FleetPostureBuild, *, now: str) -> None:
    """Record what Guard Cloud accepted so the next build can send a delta."""

    store.set_sync_payload(LAST_SENT_STATE_KEY, built.next_state, now)
    if built.advanced_inventory:
        _clear_full_inventory_request(store, now)


def last_sent_fleet_posture(store: GuardStore) -> dict[str, object] | None:
    raw = store.get_sync_payload(LAST_SENT_STATE_KEY)
    return raw if isinstance(raw, dict) and raw else None


__all__ = [
    "AUTO_UPDATE_STATE_KEY",
    "CAPABILITY",
    "FOLLOWUP_STATE_KEY",
    "HASH_KEY_STATE_KEY",
    "LAST_SENT_STATE_KEY",
    "MAX_PAYLOAD_BYTES",
    "SCHEMA_VERSION",
    "FleetPostureBuild",
    "FleetPostureSettings",
    "build_fleet_posture_state",
    "commit_fleet_posture_sent",
    "fleet_posture_managed",
    "fleet_posture_opted_out",
    "fleet_posture_reporting_enabled",
    "full_inventory_requested",
    "last_sent_fleet_posture",
    "policy_section",
    "request_full_inventory",
    "set_fleet_posture_reporting",
]
