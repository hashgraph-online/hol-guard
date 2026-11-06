"""Bind an in-memory approval database to a Guard home for queue identity tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from codex_plugin_scanner.guard.native_approval_queue_identity import _CONNECTION_HOME_FUNCTION


def bind_connection_guard_home(connection: sqlite3.Connection, guard_home: Path) -> None:
    """Address ``connection`` at ``guard_home`` when the database has no file path."""

    home = Path(guard_home)

    def read_home() -> str:
        return str(home)

    connection.create_function(_CONNECTION_HOME_FUNCTION, 0, read_home)
