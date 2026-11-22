"""The committed extension-control head and its transitions, read by the native store.

Callers run the schema check first, as the SQL reads this replaces did. A
row of the wrong shape raises the same error those reads raised, and an
answer outside the read's contract is refused.

An operation that already holds the store's shared connection scope (the
MCP tool-call decision does) runs the same reads on that connection, since a
native call there would add a resident round trip to a hot path whose budget
allows none. Those answers take the same checks as the native ones.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any, Final, cast

from .runtime.extension_control_authority import ExtensionControlAuthorityError
from .store_connection_scope import owns_scope

_HEAD: Final = "extension_control_snapshot_head"
_RECOVERY: Final = "extension_control_recovery_transition"
_COMMITTED: Final = "extension_control_transition_committed"
_HEAD_FIELDS: Final = frozenset({"revision", "snapshot_digest", "catalog_digest"})
_INVALID_ROW: Final = "invalid extension control authority row"
_COMMITTED_PHASE: Final = "committed"
_HEAD_FIELDS_ORDER: Final = ("revision", "snapshot_digest", "catalog_digest")
_SNAPSHOT_TABLE: Final = "extension_control_authority_snapshot"
_TRANSITION_TABLE: Final = "extension_control_authority_transition"
# The same reads the native store runs: a cell of the wrong type reads as
# null, and a missing table has no head and no transitions.
_TABLE_SQL: Final = "select 1 from sqlite_master where type = 'table' and name = ?"
_HEAD_SQL: Final = (
    "select case when typeof(revision) = 'integer' then revision end, "
    "case when typeof(snapshot_digest) = 'text' then snapshot_digest end, "
    "case when typeof(catalog_digest) = 'text' then catalog_digest end "
    f"from {_SNAPSHOT_TABLE} where singleton = 1"
)
_RECOVERY_SQL: Final = (
    f"select revision from {_TRANSITION_TABLE} "
    "where (revision = ? and phase != ?) or revision = ? order by revision limit 1"
)
_COMMITTED_SQL: Final = f"select 1 from {_TRANSITION_TABLE} where revision = ? and phase = ?"


@dataclass(frozen=True)
class SnapshotHead:
    revision: int
    snapshot_digest: str
    catalog_digest: str


def _refused(method: str) -> sqlite3.DatabaseError:
    return sqlite3.DatabaseError(f"native {method} returned no answer")


def _is_int(value: object) -> bool:
    return type(value) is int


def _has_table(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute(_TABLE_SQL, (table,)).fetchone() is not None


def _scoped_answer(connection: sqlite3.Connection, method: str, args: dict[str, object]) -> dict[str, object]:
    """The native answer for ``method``, read on the shared connection."""

    if method == _HEAD:
        if not _has_table(connection, _SNAPSHOT_TABLE):
            return {"snapshot": None}
        row = connection.execute(_HEAD_SQL).fetchone()
        snapshot = None if row is None else dict(zip(_HEAD_FIELDS_ORDER, row, strict=True))
        return {"snapshot": snapshot}
    revision = cast(int, args["revision"])
    has_transitions = _has_table(connection, _TRANSITION_TABLE)
    if method == _RECOVERY:
        if not has_transitions:
            return {"revision": None}
        row = connection.execute(_RECOVERY_SQL, (revision, _COMMITTED_PHASE, revision + 1)).fetchone()
        found = None if row is None else row[0]
        return {"revision": found if _is_int(found) else None}
    if not has_transitions:
        return {"committed": False}
    row = connection.execute(_COMMITTED_SQL, (revision, _COMMITTED_PHASE)).fetchone()
    return {"committed": row is not None}


def _single(store: Any, method: str, args: dict[str, object], field: str) -> object:
    if owns_scope(store):
        with store._connect() as connection:
            answer: object = _scoped_answer(connection, method, args)
    else:
        answer = store._native_store_call(method, args)
    if not isinstance(answer, dict) or set(answer) != {field}:
        raise _refused(method)
    return answer[field]


def extension_control_snapshot_head(store: Any) -> SnapshotHead | None:
    """The snapshot row's revision and digests, or None when there is no row."""

    snapshot = _single(store, _HEAD, {}, "snapshot")
    if snapshot is None:
        return None
    if not isinstance(snapshot, dict) or set(snapshot) != _HEAD_FIELDS:
        raise _refused(_HEAD)
    revision = snapshot["revision"]
    snapshot_digest = snapshot["snapshot_digest"]
    catalog_digest = snapshot["catalog_digest"]
    if not _is_int(revision) or not isinstance(snapshot_digest, str) or not isinstance(catalog_digest, str):
        raise ExtensionControlAuthorityError(_INVALID_ROW)
    return SnapshotHead(revision, snapshot_digest, catalog_digest)


def extension_control_recovery_transition(store: Any, revision: int) -> int | None:
    """The transition recovery resumes past ``revision``, or None when there is none."""

    found = _single(store, _RECOVERY, {"revision": revision}, "revision")
    if found is not None and not _is_int(found):
        raise _refused(_RECOVERY)
    return found if isinstance(found, int) else None


def extension_control_transition_committed(store: Any, revision: int) -> bool:
    """Whether the transition at ``revision`` committed."""

    committed = _single(store, _COMMITTED, {"revision": revision}, "committed")
    if not isinstance(committed, bool):
        raise _refused(_COMMITTED)
    return committed
