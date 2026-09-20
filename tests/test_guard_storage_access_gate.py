from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.sqlite_tuning import sqlite_connect_timeout_override
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_storage_lock import StorageAccessTimeoutError, hold_storage_file_lock


def test_ordinary_store_connections_share_admission_within_the_existing_budget(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    entered = threading.Event()
    errors: list[Exception] = []
    values: list[int] = []

    def read() -> None:
        try:
            with sqlite_connect_timeout_override(0.05), store._connect() as connection:
                values.append(connection.execute("select 1").fetchone()[0])
                entered.set()
        except Exception as error:
            errors.append(error)

    with store._connect() as connection:
        assert connection.execute("select 1").fetchone()[0] == 1
        thread = threading.Thread(target=read)
        thread.start()
        try:
            assert entered.wait(timeout=2), errors
        finally:
            thread.join(timeout=2)
    assert not thread.is_alive()
    assert errors == []
    assert values == [1]


@pytest.mark.parametrize(
    ("parent_exclusive", "child_exclusive", "expected_exit"),
    [(False, False, 0), (False, True, 3), (True, False, 3), (True, True, 3)],
)
def test_actual_platform_lock_coordinates_separate_processes(
    tmp_path: Path,
    parent_exclusive: bool,
    child_exclusive: bool,
    expected_exit: int,
) -> None:
    path = tmp_path / "access.lock"
    child = """
import sys
from pathlib import Path
from codex_plugin_scanner.guard.store_storage_lock import StorageAccessTimeoutError, hold_storage_file_lock
try:
    with hold_storage_file_lock(Path(sys.argv[1]), exclusive=sys.argv[2] == 'True', timeout_seconds=0.05):
        pass
except StorageAccessTimeoutError:
    raise SystemExit(3)
"""
    with hold_storage_file_lock(path, exclusive=parent_exclusive, timeout_seconds=0.05):
        result = subprocess.run(
            [sys.executable, "-c", child, str(path), str(child_exclusive)],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
    assert result.returncode == expected_exit, result.stderr
    # Both successful and timed-out contenders release their file handles.
    with hold_storage_file_lock(path, exclusive=True, timeout_seconds=0.05):
        pass


def test_shared_admission_does_not_allow_recovery_until_every_reader_exits(tmp_path: Path) -> None:
    path = tmp_path / "access.lock"
    with hold_storage_file_lock(path, exclusive=False, timeout_seconds=0.05):
        with (
            hold_storage_file_lock(path, exclusive=False, timeout_seconds=0.05),
            pytest.raises(StorageAccessTimeoutError),
            hold_storage_file_lock(path, exclusive=True, timeout_seconds=0.05),
        ):
            pytest.fail("Recovery entered while two readers held access")
        with (
            pytest.raises(StorageAccessTimeoutError),
            hold_storage_file_lock(path, exclusive=True, timeout_seconds=0.05),
        ):
            pytest.fail("Recovery entered while the first reader held access")
    with hold_storage_file_lock(path, exclusive=True, timeout_seconds=0.05):
        pass


def test_storage_gate_releases_on_exception_and_retains_nested_upgrade_rejection(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    with pytest.raises(ValueError, match="fixture failure"), store._hold_storage_gate(exclusive=True):
        raise ValueError("fixture failure")
    with (
        store._hold_storage_gate(exclusive=False),
        store._hold_storage_gate(exclusive=False),
        pytest.raises(RuntimeError, match="Cannot upgrade"),
        store._hold_storage_gate(exclusive=True),
    ):
        pytest.fail("A nested read was upgraded")
    with store._hold_storage_gate(exclusive=True):
        pass
