"""Shared SQLite timing configuration for Guard local storage."""

from __future__ import annotations

SQLITE_CONNECT_TIMEOUT_SECONDS = 30.0
SQLITE_BUSY_TIMEOUT_MS = int(SQLITE_CONNECT_TIMEOUT_SECONDS * 1000)
SQLITE_WAL_BUSY_TIMEOUT_MS = 1000
