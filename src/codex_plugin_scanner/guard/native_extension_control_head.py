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
_HEAD_SQL: Final = (
    "select revision, snapshot_digest, catalog_digest from extension_control_authority_snapshot where singleton = 1"
)
_RECOVERY_SQL: Final = (
    "select revision from extension_control_authority_transition "
    "where (revision = ? and phase != ?) or revision = ? order by revision limit 1"
)
_COMMITTED_SQL: Final = "select 1 from extension_control_authority_transition where revision = ? and phase = ?"


@dataclass(frozen=True)
class SnapshotHead:
    revision: int
    snapshot_digest: str
    catalog_digest: str


def _refused(method: str) -> sqlite3.DatabaseError:
    return sqlite3.DatabaseError(f"native {method} returned no answer")


def _is_int(value: object) -> bool:
    return type(value) is int


def _scoped_answer(connection: sqlite3.Connection, method: str, args: dict[str, object]) -> dict[str, object]:
    """The native answer for ``method``, read on the shared connection."""

    if method == _HEAD:
        row = connection.execute(_HEAD_SQL).fetchone()
        snapshot = None if row is None else dict(zip(_HEAD_FIELDS_ORDER, row, strict=True))
        return {"snapshot": snapshot}
    revision = cast(int, args["revision"])
    if method == _RECOVERY:
        row = connection.execute(_RECOVERY_SQL, (revision, _COMMITTED_PHASE, revision + 1)).fetchone()
        return {"revision": None if row is None else row[0]}
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
