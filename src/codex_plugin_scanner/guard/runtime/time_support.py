"""Shared timestamp parsing for Guard runtime contracts."""

from __future__ import annotations

from datetime import datetime, timezone


def parse_utc_timestamp(value: object) -> datetime | None:
    """Parse an ISO-8601 timestamp and normalize it to timezone-aware UTC."""

    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith(("Z", "z")):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
