"""Shared reads for the SQLite failure containment tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.store import GuardStore


def read_runtime_row(store: GuardStore) -> object:
    """Read one row through the Python connection, which owns SQLite recovery."""
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        return connection.execute("select session_id from guard_runtime_state where state_key = 'runtime'").fetchone()


def quarantined_databases(guard_home: Path) -> list[Path]:
    return sorted(path for path in guard_home.glob("guard.db.corrupt-*") if not path.name.endswith(".forensics.json"))
