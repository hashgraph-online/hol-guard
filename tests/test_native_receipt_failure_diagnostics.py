from __future__ import annotations

import json
import sqlite3

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_diagnostics import receipt_failure_category
from codex_plugin_scanner.guard.store_storage_lock import StorageAccessTimeoutError


@pytest.mark.parametrize(
    ("error", "category"),
    [
        (StorageAccessTimeoutError("private source"), "storage-gate-timeout"),
        (sqlite3.OperationalError("database is locked: private source"), "sqlite-busy-or-locked"),
        (sqlite3.DatabaseError("private source"), "sqlite-error"),
        (PermissionError("private source"), "permission-denied"),
        (OSError("private source"), "io-error"),
        (ValueError("private source"), "invalid-receipt"),
        (RuntimeError("private source"), "other"),
    ],
)
def test_receipt_failure_categories_are_bounded_and_do_not_retain_messages(error: Exception, category: str) -> None:
    result = receipt_failure_category(error)
    assert result == category
    assert "private" not in json.dumps(result)
