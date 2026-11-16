"""``guard.db`` connections kept from one store call to the next.

Opening the store costs a file open, SQLite's full schema parse on the first
statement, and a close that frees the schema again: about a millisecond and a
quarter, against a few microseconds for the read most calls then make. A
single approval opens the store roughly a hundred times across the daemon's
threads, so most of the store's CPU went on opening it.

A connection a call hands back is kept for the next call on the same file: the
same resolved path, still naming the same file (its device and inode), so a
store replaced or recovered at that path opens fresh. The file must name the
same file just before and just after a connection opens, or the connection is
never kept. Only a connection whose call finished without an error and left no
transaction open is kept; every call still sets its own busy timeout and
pragmas and opens its own transaction, so it sees every commit made before it.

A connection made for an operation clock captures that clock, so it is never
kept. Off POSIX, where an open handle blocks the rename and delete recovery
relies on, every call opens fresh. The native resident keeps its own
connections the same way.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path

# Idle connections kept across every store; the oldest is closed for more.
# Enough for each review drain worker to find one while the sync worker,
# hook handlers and policy reconciler hold theirs.
MAX_IDLE_CONNECTIONS = 12

_CACHE_ENABLED = os.name == "posix"


@dataclass(frozen=True)
class StoreFileKey:
    path: str
    device: int
    inode: int


_lock = threading.Lock()
# Insertion order is age: the newest connection is taken first and the oldest
# is closed when the cache is full.
_idle: dict[int, tuple[StoreFileKey, sqlite3.Connection]] = {}
# A forked child never uses or closes a connection it inherited: SQLite
# handles must not cross a fork, and closing one can checkpoint the parent's
# write-ahead log. The child keeps them referenced, unused, until it exits.
_inherited: list[sqlite3.Connection] = []


def _abandon_in_child() -> None:
    _inherited.extend(connection for _, connection in _idle.values())
    _idle.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_abandon_in_child)


def _file_key(path: str | Path) -> StoreFileKey | None:
    try:
        resolved = os.path.realpath(path)
        metadata = os.stat(resolved)
    except OSError:
        return None
    if not os.path.isfile(resolved):
        return None
    return StoreFileKey(path=resolved, device=metadata.st_dev, inode=metadata.st_ino)


def open_store_connection(
    path: str | Path,
    *,
    timeout: float,
    factory: type[sqlite3.Connection],
) -> tuple[sqlite3.Connection, StoreFileKey | None]:
    """A connection to ``path`` and the key to keep it under, ``None`` if never kept."""

    if not _CACHE_ENABLED or factory is not sqlite3.Connection:
        return sqlite3.connect(path, timeout=timeout, factory=factory), None
    key = _file_key(path)
    if key is None:
        return sqlite3.connect(path, timeout=timeout), None
    reused = _take(key)
    if reused is not None:
        return reused, key
    connection = sqlite3.connect(path, timeout=timeout, check_same_thread=False)
    # A file replaced while the connection opened leaves it unkept.
    return connection, key if _file_key(path) == key else None


def release_store_connection(
    connection: sqlite3.Connection,
    key: StoreFileKey | None,
    *,
    reusable: bool,
) -> None:
    """Keep ``connection`` for a later call, or close it."""

    if key is None or not reusable or connection.in_transaction:
        connection.close()
        return
    evicted: list[sqlite3.Connection] = []
    with _lock:
        evicted.extend(_forget_replaced(key))
        while len(_idle) >= MAX_IDLE_CONNECTIONS:
            oldest = next(iter(_idle))
            evicted.append(_idle.pop(oldest)[1])
        _idle[id(connection)] = (key, connection)
    for stale in evicted:
        stale.close()


def close_idle_store_connections() -> None:
    """Close every kept connection, for a caller about to replace a store."""

    with _lock:
        idle = [connection for _, connection in _idle.values()]
        _idle.clear()
    for connection in idle:
        connection.close()


def _take(key: StoreFileKey) -> sqlite3.Connection | None:
    evicted: list[sqlite3.Connection] = []
    taken: sqlite3.Connection | None = None
    with _lock:
        evicted.extend(_forget_replaced(key))
        for identity in reversed(list(_idle)):
            held_key, connection = _idle[identity]
            if held_key == key:
                del _idle[identity]
                taken = connection
                break
    for stale in evicted:
        stale.close()
    return taken


def _forget_replaced(key: StoreFileKey) -> list[sqlite3.Connection]:
    """Drop kept connections to a file no longer at ``key``'s path. Caller holds the lock."""

    stale = [identity for identity, (held, _) in _idle.items() if held.path == key.path and held != key]
    return [_idle.pop(identity)[1] for identity in stale]
