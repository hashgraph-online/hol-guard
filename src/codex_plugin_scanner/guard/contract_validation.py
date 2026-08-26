"""Shared strict validators for Guard wire contracts."""

from __future__ import annotations

from uuid import UUID


def canonical_uuid(value: object, *, maximum_bytes: int = 128) -> str | None:
    """Return a bounded canonical UUID string or ``None``."""

    if not isinstance(value, str) or not value or value != value.strip():
        return None
    if len(value.encode("utf-8")) > maximum_bytes:
        return None
    try:
        parsed = UUID(value)
    except ValueError:
        return None
    return value if str(parsed) == value else None


def positive_integer(value: object) -> int | None:
    """Return a strict positive integer or ``None``."""

    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None
