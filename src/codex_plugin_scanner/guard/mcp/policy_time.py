"""Shared UTC timestamp formatting for MCP policy workflows."""

from __future__ import annotations

from datetime import datetime, timezone


def utc_now_iso() -> str:
    """Return the current UTC time in canonical ``Z`` notation."""

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = ["utc_now_iso"]
