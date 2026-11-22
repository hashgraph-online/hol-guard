"""The committed extension-control head and its transitions, read by the native store.

Callers run the schema check first, as the SQL reads this replaces did. A
row of the wrong shape raises the same error those reads raised, and an
answer outside the read's contract is refused.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any, Final

from .runtime.extension_control_authority import ExtensionControlAuthorityError

_HEAD: Final = "extension_control_snapshot_head"
_RECOVERY: Final = "extension_control_recovery_transition"
_COMMITTED: Final = "extension_control_transition_committed"
_HEAD_FIELDS: Final = frozenset({"revision", "snapshot_digest", "catalog_digest"})
_INVALID_ROW: Final = "invalid extension control authority row"


@dataclass(frozen=True)
class SnapshotHead:
    revision: int
    snapshot_digest: str
    catalog_digest: str


def _refused(method: str) -> sqlite3.DatabaseError:
    return sqlite3.DatabaseError(f"native {method} returned no answer")


def _is_int(value: object) -> bool:
    return type(value) is int


def _single(store: Any, method: str, args: dict[str, object], field: str) -> object:
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
