"""Collect the facts the native protection-health report is decided from."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Protocol

from ..native_protection_health import protection_health_report


class CommandActivityHealth(Protocol):
    @property
    def dropped_event_count(self) -> int: ...

    @property
    def persistence_error_count(self) -> int: ...

    @property
    def active_error_count(self) -> int: ...


class ProtectionHealthStore(Protocol):
    def count_command_activities(self) -> int: ...

    def get_command_activity_persistence_health(self) -> CommandActivityHealth: ...


def _decision_stream(store: ProtectionHealthStore) -> dict[str, int] | None:
    """The stream's live counters, or ``None`` when the store cannot say."""

    try:
        health = store.get_command_activity_persistence_health()
        return {
            "active_error_count": int(health.active_error_count),
            "activity_count": int(store.count_command_activities()),
        }
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return None


def build_runtime_protection_health(
    *,
    store: ProtectionHealthStore,
    guard_home: Path,
    runtime_state: Mapping[str, object] | None,
    managed_installs: Sequence[Mapping[str, object]],
    hook_verification: Mapping[str, bool] | None = None,
    trust_status: Mapping[str, object],
    now: datetime,
) -> dict[str, object]:
    """Send what this machine reports about itself and return the resident's verdict.

    What each fact proves, and whether that adds up to a protected machine, is
    the native runtime's answer. Only the fields a check reads leave this
    process: a managed install's harness and whether it is active, never its
    workspace or manifest. ``NativeProtectionHealthError`` reaches the caller
    rather than a verdict assembled here from an unreachable runtime.
    """

    facts: dict[str, object] = {
        "now": now.isoformat(),
        "managed_installs": [
            {"harness": install.get("harness"), "active": install.get("active")} for install in managed_installs
        ],
        "hook_verification": dict(hook_verification) if hook_verification is not None else None,
        "daemon": (
            {
                "registration_status": runtime_state.get("registration_status"),
                "last_heartbeat_at": runtime_state.get("last_heartbeat_at"),
                "containment_health": runtime_state.get("containment_health"),
            }
            if runtime_state is not None
            else None
        ),
        "remembered_rules": trust_status.get("remembered_rules"),
        "runtime_protection": trust_status.get("runtime_protection"),
        "decision_stream": _decision_stream(store),
    }
    return protection_health_report(facts, guard_home=guard_home)


__all__ = ("ProtectionHealthStore", "build_runtime_protection_health")
