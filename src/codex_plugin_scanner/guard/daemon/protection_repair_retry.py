"""Bounded confirmation retries for local containment repair."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping
from datetime import datetime, timezone

from ..runtime.containment_health import containment_health_signals
from ..runtime.protection_health import ProtectionCheckStatus

_CONTAINMENT_CHECK_IDS = (
    "decision_plane_compatibility",
    "containment_compatibility",
    "sandbox",
)


def confirmed_containment_repair_signals(
    load_health: Callable[[], Mapping[str, object] | None],
    *,
    attempts: int = 3,
) -> tuple[list[str], list[str]]:
    """Return confirmed pass/fail checks after bounded transient retries."""
    latest = None
    for _attempt in range(attempts):
        try:
            health = load_health()
            if health is None:
                continue
            latest = containment_health_signals(health, now=datetime.now(timezone.utc))
        except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
            continue
        if all(latest[check_id].status is ProtectionCheckStatus.PASS for check_id in _CONTAINMENT_CHECK_IDS):
            break
    if latest is None:
        return [], list(_CONTAINMENT_CHECK_IDS)
    repaired = [
        check_id for check_id in _CONTAINMENT_CHECK_IDS if latest[check_id].status is ProtectionCheckStatus.PASS
    ]
    failed = [check_id for check_id in _CONTAINMENT_CHECK_IDS if check_id not in repaired]
    return repaired, failed


def incomplete_protection_repair_payload(
    *,
    repaired_check_ids: list[str],
    failed_check_ids: list[str],
    failed_harnesses: list[str] | tuple[str, ...],
    pending_check_ids: list[str],
    has_active_hooks: bool,
    hook_failures: list[str] | tuple[str, ...],
    hook_repair_unknown: bool,
) -> dict[str, object]:
    """Describe an all-check repair that could not finish every local layer."""

    missing_connected_app = (
        "harness_hooks" in failed_check_ids and not has_active_hooks and not hook_failures and not hook_repair_unknown
    )
    return {
        "error": "protection_repair_incomplete",
        "repaired": False,
        "check_ids": repaired_check_ids,
        "failed_check_ids": failed_check_ids,
        "failed_harnesses": list(failed_harnesses),
        "pending_check_ids": pending_check_ids,
        "message": (
            "Connect an AI app to start local protection. Repair cannot finish until at least one app is connected."
            if missing_connected_app
            else ("Repair paused before every protection layer could be confirmed. Retry repair here.")
        ),
    }
