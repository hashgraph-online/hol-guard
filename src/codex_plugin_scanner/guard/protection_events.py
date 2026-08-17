"""Local protection-posture events for the hol-guard events timeline."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def record_protection_event(guard_home: Path, event_name: str, payload: dict[str, object]) -> None:
    from .store import GuardStore

    store = GuardStore(guard_home)
    store.add_event(
        event_name,
        payload,
        datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    )


def record_posture_change(
    guard_home: Path,
    *,
    previous: str,
    next_posture: str,
    source: str,
    auto: bool = False,
) -> None:
    record_protection_event(
        guard_home,
        "guard.protection.posture_selected",
        {"previous": previous, "value": next_posture, "source": source, "auto": auto},
    )
    if next_posture == "watch":
        record_protection_event(
            guard_home,
            "guard.protection.watch_entered",
            {"previous": previous, "source": source},
        )
        return
    if previous == "watch":
        record_protection_event(
            guard_home,
            "guard.protection.watch_auto_reverted" if auto else "guard.protection.watch_reverted",
            {"value": next_posture, "source": source},
        )
