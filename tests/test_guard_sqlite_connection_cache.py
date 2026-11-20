"""Store connections kept from one call to the next."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import sqlite_connection_cache as cache
from codex_plugin_scanner.guard.store import GuardStore

pytestmark = pytest.mark.skipif(os.name != "posix", reason="connections are kept on POSIX only")


@pytest.fixture(autouse=True)
def _empty_cache() -> Iterator[None]:
    cache.close_idle_store_connections()
    yield
    cache.close_idle_store_connections()


def _database(tmp_path: Path, name: str = "guard.db") -> Path:
    path = tmp_path / name
    sqlite3.connect(path).close()
    return path


def test_a_released_connection_is_reused_for_the_same_file(tmp_path: Path) -> None:
    path = _database(tmp_path)

    first, key = cache.open_store_connection(path, timeout=1, factory=sqlite3.Connection)
    assert key is not None
    cache.release_store_connection(first, key, reusable=True)
    second, second_key = cache.open_store_connection(path, timeout=1, factory=sqlite3.Connection)

    assert second is first
    assert second_key == key
    cache.release_store_connection(second, second_key, reusable=True)


def test_a_file_replaced_at_the_same_path_opens_fresh(tmp_path: Path) -> None:
    path = _database(tmp_path)
    first, key = cache.open_store_connection(path, timeout=1, factory=sqlite3.Connection)
    cache.release_store_connection(first, key, reusable=True)

    replacement = _database(tmp_path, "replacement.db")
    os.replace(replacement, path)
    second, second_key = cache.open_store_connection(path, timeout=1, factory=sqlite3.Connection)

    assert second is not first
    assert second_key != key
    # The connection to the replaced file was closed, not kept.
    with pytest.raises(sqlite3.ProgrammingError):
        first.execute("select 1")
    cache.release_store_connection(second, second_key, reusable=True)


@pytest.mark.parametrize("reason", ["failed", "open transaction"])
def test_a_connection_is_closed_after_a_failure_or_an_open_transaction(tmp_path: Path, reason: str) -> None:
    path = _database(tmp_path)
    connection, key = cache.open_store_connection(path, timeout=1, factory=sqlite3.Connection)
    if reason == "open transaction":
        connection.execute("create table t (x)")
        connection.execute("begin")
        connection.execute("insert into t values (1)")

    cache.release_store_connection(connection, key, reusable=reason != "failed")

    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("select 1")
    reopened, reopened_key = cache.open_store_connection(path, timeout=1, factory=sqlite3.Connection)
    assert reopened is not connection
    cache.release_store_connection(reopened, reopened_key, reusable=True)


def test_a_connection_with_another_factory_is_never_kept(tmp_path: Path) -> None:
    class ClockedConnection(sqlite3.Connection):
        pass

    path = _database(tmp_path)
    connection, key = cache.open_store_connection(path, timeout=1, factory=ClockedConnection)

    assert isinstance(connection, ClockedConnection)
    assert key is None
    cache.release_store_connection(connection, key, reusable=True)
    with pytest.raises(sqlite3.ProgrammingError):
        connection.execute("select 1")


def test_the_oldest_idle_connection_is_closed_past_the_cap(tmp_path: Path) -> None:
    paths = [_database(tmp_path, f"store-{index}.db") for index in range(cache.MAX_IDLE_CONNECTIONS + 1)]
    opened = [cache.open_store_connection(path, timeout=1, factory=sqlite3.Connection) for path in paths]
    for connection, key in opened:
        cache.release_store_connection(connection, key, reusable=True)

    oldest = opened[0][0]
    with pytest.raises(sqlite3.ProgrammingError):
        oldest.execute("select 1")
    for connection, _ in opened[1:]:
        assert connection.execute("select 1").fetchone() == (1,)


def test_store_calls_see_writes_made_through_another_connection(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    with sqlite3.connect(store.path) as outside:
        outside.execute("create table cache_probe (value integer)")
        outside.execute("insert into cache_probe values (1)")

    def read() -> int:
        with store._connect() as connection:
            return int(connection.execute("select value from cache_probe").fetchone()[0])

    assert read() == 1
    assert read() == 1
    # A writer outside the cache commits; the kept connection must see it.
    with sqlite3.connect(store.path) as outside:
        outside.execute("update cache_probe set value = 2")
    assert read() == 2


def test_a_forked_child_abandons_inherited_connections_without_closing_them(tmp_path: Path) -> None:
    path = _database(tmp_path)
    inherited, key = cache.open_store_connection(path, timeout=1, factory=sqlite3.Connection)
    cache.release_store_connection(inherited, key, reusable=True)

    cache._abandon_in_child()
    fresh, fresh_key = cache.open_store_connection(path, timeout=1, factory=sqlite3.Connection)

    assert fresh is not inherited
    # Still open: the child never closes a handle the parent owns.
    assert inherited.execute("select 1").fetchone() == (1,)
    cache.release_store_connection(fresh, fresh_key, reusable=True)
    cache._inherited.clear()
    inherited.close()
