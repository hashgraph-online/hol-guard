"""Repair stages and truthful per-check reasons for /v1/protection/repair."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from contextlib import suppress
from typing import Protocol

from ..models import GuardRuntimeRegistration

_INTEGRITY_CHECK_IDS = ("policy_engine", "rule_packs", "tamper_checks")


class RuntimeRegistrationStore(Protocol):
    def try_touch_runtime_state(
        self,
        *,
        session_id: str,
        last_heartbeat_at: str,
        timeout_seconds: float,
        registration: GuardRuntimeRegistration | None = None,
    ) -> bool: ...

    def get_runtime_state(self) -> dict[str, object] | None: ...


def repair_daemon_registration(
    store: RuntimeRegistrationStore,
    *,
    session_id: str,
    registration: GuardRuntimeRegistration,
    last_heartbeat_at: str,
) -> str | None:
    """Re-register the serving daemon's runtime row; return a reason or None.

    A row owned by another live session is never overwritten: the write is a
    no-op and the mismatch is reported as ``daemon_registration_foreign``.
    """
    try:
        written = store.try_touch_runtime_state(
            session_id=session_id,
            last_heartbeat_at=last_heartbeat_at,
            timeout_seconds=1.0,
            registration=registration,
        )
        state = store.get_runtime_state() if written else None
    except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error):
        return "daemon_registration_unavailable"
    if state is None:
        return "daemon_registration_unavailable"
    return None if state.get("session_id") == session_id else "daemon_registration_foreign"


def harness_hooks_repair_reason(
    *,
    has_active_hooks: bool,
    hook_failures: object,
    hook_repair_unknown: bool,
) -> str:
    if hook_repair_unknown:
        return "hook_repair_unknown"
    if hook_failures:
        return "hook_repair_failed"
    return "no_managed_harness"


def integrity_repair_reasons(*, restored: bool) -> dict[str, str]:
    if restored:
        return {}
    return {check_id: "local_integrity_unproven" for check_id in _INTEGRITY_CHECK_IDS}


def protection_repair_reason_detail(check_reasons: Mapping[str, str]) -> str:
    """Render stable `check:reason` tokens for diagnostics without payloads."""

    return " ".join(f"{check_id}:{reason}" for check_id, reason in sorted(check_reasons.items()))


class IncompleteRepairDiagnostics(Protocol):
    def record(self, event: str, *, detail: str | None = None) -> object: ...


def record_incomplete_protection_repair(
    diagnostics: IncompleteRepairDiagnostics | None,
    check_reasons: Mapping[str, str],
) -> None:
    """Log one incomplete repair attempt with stable per-check reasons."""

    detail = protection_repair_reason_detail(check_reasons)
    with suppress(Exception):
        if diagnostics is not None:
            _ = diagnostics.record("protection_repair_incomplete", detail=detail or None)


__all__ = (
    "RuntimeRegistrationStore",
    "harness_hooks_repair_reason",
    "integrity_repair_reasons",
    "protection_repair_reason_detail",
    "record_incomplete_protection_repair",
    "repair_daemon_registration",
)
