"""The native ``ensure_schema`` op must build the same store Python builds.

One store is opened through the Python schema opener. A second home gets an
empty store file, which the native op fills. Both must hold the same schema
objects and record the same schema versions. Running the native op again over
the Python store must change nothing, so an upgrade of a current store is a
no-op on both sides.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from codex_plugin_scanner.guard import native_guard_store
from codex_plugin_scanner.guard.store import GuardStore

NOW = "2026-11-23T00:00:00+00:00"


def _ensure_schema(store: GuardStore) -> object:
    result: tuple[object, int | None] = native_guard_store.native_guard_store_call(
        store_path=store.path,
        guard_home=store.guard_home,
        source="local",
        method="ensure_schema",
        args={"now": NOW},
        deadline_monotonic=time.monotonic() + 60,
        prerequisite_store=store,
    )
    return result[0]


def _schema(path: Path) -> list[tuple[str, str, str | None]]:
    connection = sqlite3.connect(path)
    try:
        rows: list[tuple[str, str, str | None]] = connection.execute(
            "select type, name, sql from sqlite_master where name not like 'sqlite_%' order by type, name"
        ).fetchall()
        return rows
    finally:
        connection.close()


def _versions(path: Path) -> list[int]:
    connection = sqlite3.connect(path)
    try:
        rows: list[tuple[int]] = connection.execute("select version from schema_migrations order by version").fetchall()
        return [row[0] for row in rows]
    finally:
        connection.close()


def _empty(store: GuardStore) -> None:
    for suffix in ("", "-wal", "-shm"):
        Path(f"{store.path}{suffix}").unlink(missing_ok=True)
    store.path.touch(mode=0o600)


def test_a_native_store_matches_the_python_store(tmp_path: Path) -> None:
    python_store = GuardStore(tmp_path / "python-home")
    native_store = GuardStore(tmp_path / "native-home")
    _empty(native_store)

    assert _ensure_schema(native_store) == {"created": True}

    assert _schema(native_store.path) == _schema(python_store.path)
    assert _versions(native_store.path) == _versions(python_store.path)


def test_the_native_op_leaves_a_current_python_store_alone(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    before = (_schema(store.path), _versions(store.path))

    assert _ensure_schema(store) == {"created": False}

    assert (_schema(store.path), _versions(store.path)) == before
