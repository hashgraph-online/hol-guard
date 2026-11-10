"""Guard library steps the native daemon's protection repair runs.

The native daemon owns ``POST /v1/protection/repair``: which checks run, in
what order, the confirmation retries, the reasons and the reply. Each call
here is one store step it cannot take natively yet, and reports its outcome
as data rather than raising for an expected failure.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from ..config import load_guard_config
from ..daemon.manager import current_guard_daemon_runtime_fingerprint
from ..daemon.server_control_connect_flow import _repair_command_activity_persistence_health
from ..models import GuardRuntimeRegistration
from ..runtime.containment_health import containment_health_signals, probe_containment_health
from ..runtime_artifact_reconciliation import repair_failing_managed_harness_hooks
from ..store import GuardStore

_EXPECTED_ERRORS = (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def daemon_registration(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Re-registers the serving daemon's runtime row.

    Returns the session the row names afterwards, or ``None`` when it could
    not be written or read. A row another live session owns is left alone.
    """

    from .request_host import load_runtime_identity

    port = args.get("port")
    if not isinstance(port, int):
        return {"session_id": None, "expected": None}
    identity = load_runtime_identity(store.guard_home)
    session_id = identity.get("session_id") or ""
    try:
        written = store.try_touch_runtime_state(
            session_id=session_id,
            last_heartbeat_at=_now(),
            timeout_seconds=1.0,
            registration=GuardRuntimeRegistration(
                daemon_host="127.0.0.1",
                daemon_port=port,
                started_at=identity.get("started_at") or "",
            ),
        )
        state = store.get_runtime_state() if written else None
    except _EXPECTED_ERRORS:
        state = None
    current = state.get("session_id") if isinstance(state, dict) else None
    return {"session_id": current if isinstance(current, str) else None, "expected": session_id}


def policy_integrity(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Sets up integrity protection, repairing it when it is not protected."""

    del args
    try:
        status = store.setup_policy_integrity(now=_now(), include_items=False)
        if status.get("mode") != "protected":
            status = store.repair_policy_integrity(clear_invalid=False, now=_now(), include_items=False)
    except _EXPECTED_ERRORS:
        return {"failed": True}
    reasons = status.get("degraded_reasons")
    mode = status.get("mode")
    return {
        "failed": False,
        "mode": mode if isinstance(mode, str) else None,
        "reason_count": len(reasons) if isinstance(reasons, list) else 0,
    }


def harness_hooks(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Repairs failing managed harness hooks and reports what stays broken."""

    del args
    unknown = False
    failures: list[str] = []
    try:
        _, failed = repair_failing_managed_harness_hooks(store)
        failures = [str(harness) for harness in failed]
    except _EXPECTED_ERRORS:
        unknown = True
    active = any(
        isinstance(install.get("harness"), str) and install.get("active") is True
        for install in store.list_managed_installs()
    )
    return {"failures": failures, "unknown": unknown, "has_active_hooks": active}


def containment_signals(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Probes containment health now and returns its per-check signals."""

    del args
    try:
        health = probe_containment_health(
            daemon_fingerprint=current_guard_daemon_runtime_fingerprint(),
            guard_home=store.guard_home,
        ).to_dict()
        signals = containment_health_signals(health, now=datetime.now(timezone.utc), guard_home=store.guard_home)
    except _EXPECTED_ERRORS:
        return {"signals": None}
    return {
        "signals": {
            check_id: {
                "status": signal.status.value,
                "reason_code": signal.reason_code,
            }
            for check_id, signal in signals.items()
        }
    }


def decision_stream(store: GuardStore, args: Mapping[str, Any]) -> dict[str, object]:
    """Proves the command-evidence write path, maintains it, and reads its health."""

    del args
    try:
        config = load_guard_config(store.guard_home)
        _repair_command_activity_persistence_health(store)
        store.maintain_command_activity(
            now=datetime.now(timezone.utc),
            detail_retain_days=config.evidence_retain_days,
        )
        health = store.get_command_activity_persistence_health()
    except _EXPECTED_ERRORS:
        return {"unavailable": True}
    return {"unavailable": False, "active_error_count": health.active_error_count}


REPAIR_CALLS = {
    "repair.daemon_registration": daemon_registration,
    "repair.policy_integrity": policy_integrity,
    "repair.harness_hooks": harness_hooks,
    "repair.containment_signals": containment_signals,
    "repair.decision_stream": decision_stream,
}
