"""Harness repair notes from ``hol-guard update``, and the failures among them."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

# Every repair step reports a harness it could not inspect, refresh, repair or
# verify with a note in this form. Such a harness is left without protection.
_REPAIR_FAILURE_PREFIX = "Could not "


def attach_repair_notes(payload: dict[str, object], repair_notes: list[str]) -> None:
    """Keep every repair note, and list failures that leave a harness unprotected separately."""
    if not repair_notes:
        return
    existing = payload.get("notes")
    notes = [item for item in existing if isinstance(item, str)] if isinstance(existing, list) else []
    payload["notes"] = [*notes, *repair_notes]
    failures = [note for note in repair_notes if note.startswith(_REPAIR_FAILURE_PREFIX)]
    if failures:
        payload["protection_repair_failures"] = failures


def render_protection_repair_failures(
    console: Any, payload: dict[str, object], bullet: str, panel: Callable[..., object]
) -> None:
    """Render with the caller's panel class, so render.py's no-rich fallback still applies."""
    value = payload.get("protection_repair_failures")
    failures = [item for item in value if isinstance(item, str) and item] if isinstance(value, list) else []
    if failures:
        console.print(
            panel(
                "\n".join(f"{bullet} {failure}" for failure in failures),
                title="Protection not restored",
                border_style="red",
            )
        )
