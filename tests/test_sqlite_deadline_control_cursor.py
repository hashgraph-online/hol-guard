from __future__ import annotations

import sqlite3
import time

import pytest

from codex_plugin_scanner.guard import sqlite_constants, sqlite_deadline, sqlite_tuning
from codex_plugin_scanner.guard.sqlite_deadline import DeadlineConnection, sqlite_maintenance_deadline


@pytest.mark.parametrize("operation", ["query", "begin-immediate"])
def test_internal_control_sql_never_reenters_or_resets_deadline_preparation(
    monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    with sqlite_maintenance_deadline(time.monotonic() + 1):
        connection = sqlite3.connect(":memory:", factory=DeadlineConnection)
        preparing = False
        preparation_waits: list[bool] = []
        original_prepare = connection._prepare

        def prepare(*, wait_for_lock: bool = False) -> None:
            nonlocal preparing
            assert not preparing, "Internal control SQL re-entered deadline preparation."
            preparing = True
            try:
                original_prepare(wait_for_lock=wait_for_lock)
            finally:
                preparing = False
            preparation_waits.append(wait_for_lock)

        monkeypatch.setattr(connection, "_prepare", prepare)
        try:
            if operation == "query":
                assert connection.execute("select 1").fetchone() == (1,)
                assert preparation_waits and not any(preparation_waits)
            else:
                connection.begin_immediate()
                assert connection.in_transaction
                assert preparation_waits == [True], "BEGIN lost its owned remaining-budget lock wait."
                connection.rollback()
                assert not connection.in_transaction
        finally:
            connection.close()


@pytest.mark.parametrize(
    ("constant", "pragma"),
    [("SQLITE_CACHE_SIZE_KIB", "cache_size"), ("SQLITE_MMAP_SIZE_BYTES", "mmap_size")],
)
def test_maintenance_tuning_allows_only_the_shared_configured_value(constant: str, pragma: str) -> None:
    from codex_plugin_scanner.guard.sqlite_deadline import SQLiteDeadlineUnsupportedError

    value = getattr(sqlite_constants, constant)
    assert type(value) is int
    assert getattr(sqlite_tuning, constant) == value
    assert getattr(sqlite_deadline, constant) == value
    sql_value = -value if pragma == "cache_size" else value
    with sqlite_maintenance_deadline(time.monotonic() + 1):
        connection = sqlite3.connect(":memory:", factory=DeadlineConnection)
        try:
            connection.execute(f"pragma {pragma}={sql_value}")
            with pytest.raises(SQLiteDeadlineUnsupportedError):
                connection.execute(f"pragma {pragma}={sql_value + 1}")
        finally:
            connection.close()
