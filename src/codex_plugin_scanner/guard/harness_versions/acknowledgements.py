"""Local record of untested-version warnings the user has acknowledged.

An acknowledgement only collapses the expanded warning. It is keyed by the
installation, exact version, coverage revision, and Guard build, so any change
to those makes the warning eligible again. It is never read by enforcement.
The native runtime owns the bounded, owner-only store.
"""

from __future__ import annotations

from pathlib import Path

from .compatibility import runtime_request


def record_acknowledgement(guard_home: Path, *, harness: str, key: str) -> dict[str, object]:
    """Store one acknowledgement, replacing earlier ones for the harness."""

    answer = runtime_request("acknowledge", guard_home, harness, key=key)
    entry = answer.get("entry") if answer else None
    if not isinstance(entry, dict):
        raise OSError("harness version acknowledgement was not stored")
    return entry


def clear_acknowledgements(guard_home: Path, *, harness: str) -> int:
    answer = runtime_request("clear", guard_home, harness)
    cleared = answer.get("cleared") if answer else None
    if not isinstance(cleared, int):
        raise OSError("harness version acknowledgements were not cleared")
    return cleared
