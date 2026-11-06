"""Small side effects emitted after durable Guard configuration mutations."""

from __future__ import annotations

from pathlib import Path


def notify_native_policy_mutation(guard_home: Path) -> None:
    """Wake the native policy publisher after a config write succeeds.

    The import remains lazy because the policy publisher imports configuration
    types while the control-plane module is being initialized.
    """

    from .native_policy_snapshot import notify_native_policy_mutation as notify

    notify(guard_home)


def record_posture_change_if_needed(
    guard_home: Path,
    *,
    previous: str,
    next_posture: str,
    previous_explicit: bool,
    next_explicit: bool,
    selected: bool,
    event_source: str,
) -> None:
    if not (previous != next_posture or (selected and next_explicit and not previous_explicit)):
        return
    from .protection_events import record_posture_change

    record_posture_change(
        guard_home,
        previous=previous,
        next_posture=next_posture,
        source=event_source,
        auto=event_source == "auto-revert",
    )


__all__ = ["notify_native_policy_mutation", "record_posture_change_if_needed"]
