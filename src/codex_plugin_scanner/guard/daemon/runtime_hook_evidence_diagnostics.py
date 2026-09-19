"""Bounded categories for persistence failures; never retain exception text."""

from __future__ import annotations

import sqlite3

from ..sqlite_profile import sqlite_error_is_busy_locked
from ..store_storage_lock import StorageAccessTimeoutError


def receipt_failure_category(error: Exception) -> str:
    if isinstance(error, StorageAccessTimeoutError):
        return "storage-gate-timeout"
    if isinstance(error, sqlite3.DatabaseError):
        return "sqlite-busy-or-locked" if sqlite_error_is_busy_locked(error) else "sqlite-error"
    if isinstance(error, PermissionError):
        return "permission-denied"
    if isinstance(error, OSError):
        return "io-error"
    if isinstance(error, ValueError):
        return "invalid-receipt"
    return "other"
