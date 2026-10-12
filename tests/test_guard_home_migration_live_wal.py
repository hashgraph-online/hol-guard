"""Guard-home migration must not swap a database out from under a live log."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardHomeMigrationError, _migrate_guard_home_transactionally


def _database(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute("create table migration_probe (value text)")
        connection.execute("insert into migration_probe values (?)", (value,))


@pytest.mark.parametrize("companion", ["guard.db-wal", "guard.db-journal"])
def test_transactional_migration_refuses_a_destination_with_a_live_log(tmp_path: Path, companion: str) -> None:
    source = tmp_path / "source-home"
    destination = tmp_path / "guard-home"
    _database(source / "guard.db", "source")
    _database(destination / "guard.db", "destination")
    (destination / companion).write_bytes(b"live-log-frames")
    before = (destination / "guard.db").read_bytes()

    with pytest.raises(GuardHomeMigrationError):
        _migrate_guard_home_transactionally(source=source, destination=destination)

    assert (destination / "guard.db").read_bytes() == before
    assert (destination / companion).read_bytes() == b"live-log-frames"


def test_transactional_migration_still_replaces_a_destination_without_a_live_log(tmp_path: Path) -> None:
    source = tmp_path / "source-home"
    destination = tmp_path / "guard-home"
    _database(source / "guard.db", "source")
    _database(destination / "guard.db", "destination")

    _migrate_guard_home_transactionally(source=source, destination=destination)

    with sqlite3.connect(destination / "guard.db") as connection:
        assert connection.execute("select value from migration_probe").fetchone() == ("source",)
