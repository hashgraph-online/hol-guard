"""Legacy authority envelopes for the pack lifecycle migration, read by the native store.

Nothing here is authenticated: each record, digest and MAC is handed on as
stored, and the native lifecycle op authenticates it before the row gains any
authority. Any answer outside the read's contract is refused rather than
trimmed, because a dropped envelope changes what the migration can prove.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from ..native_policy_snapshot_constants import NativePolicySnapshotError

_EVIDENCE = "command_pack_legacy_evidence_rows"
_HISTORY = "command_pack_legacy_history_page"
_ENVELOPE = frozenset({"record", "digest", "mac"})
_EVIDENCE_FIELDS = frozenset({"state", "snapshot", "pending", "transition"})
_HISTORY_FIELDS = frozenset({"state", "items", "next"})


@dataclass(frozen=True)
class EvidenceRows:
    snapshot_revision: int | None
    snapshot: dict[str, str] | None
    pending: dict[str, dict[str, str]] | None
    transition: dict[str, str] | None
    next_snapshot: dict[str, str] | None


def _refused(method: str) -> NativePolicySnapshotError:
    return NativePolicySnapshotError(f"native {method} returned no answer")


def _is_revision(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _envelope(value: object, method: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != _ENVELOPE:
        raise _refused(method)
    if not all(isinstance(value[name], str) for name in _ENVELOPE):
        raise _refused(method)
    return {name: value[name] for name in ("record", "digest", "mac")}


def _answer(store, method: str, args: dict[str, object], fields: frozenset[str]) -> dict[str, object]:
    answer = store._native_store_call(method, args)
    if isinstance(answer, dict) and answer == {"state": "schema_missing"}:
        # The SQL reads this replaces failed on the missing table.
        raise sqlite3.OperationalError("extension control authority schema is missing")
    if not isinstance(answer, dict) or set(answer) != fields or answer.get("state") != "present":
        raise _refused(method)
    return answer


def evidence_rows(store, observed_revision: object) -> EvidenceRows:
    """The snapshot, and the pending row and transition at ``observed_revision``.

    The revision comes from the anchor before it is authenticated. One that
    is not a stored revision selects no pending row, as the SQL lookup did,
    and the lifecycle op then refuses the anchor itself.
    """
    selected = None
    if isinstance(observed_revision, int) and not isinstance(observed_revision, bool):
        selected = observed_revision if 0 <= observed_revision < 2**63 else None
    answer = _answer(store, _EVIDENCE, {"observed_revision": selected}, _EVIDENCE_FIELDS)
    snapshot = answer["snapshot"]
    revision = None
    envelope = None
    if snapshot is not None:
        if not isinstance(snapshot, dict) or not _is_revision(snapshot.get("revision")):
            raise _refused(_EVIDENCE)
        revision = snapshot["revision"]
        envelope = _envelope({name: snapshot[name] for name in snapshot if name != "revision"}, _EVIDENCE)
    pending = answer["pending"]
    if pending is not None:
        if not isinstance(pending, dict) or set(pending) != {"activation", "link"}:
            raise _refused(_EVIDENCE)
        pending = {name: _envelope(pending[name], _EVIDENCE) for name in ("activation", "link")}
    transition = answer["transition"]
    if transition is not None and (not isinstance(transition, dict) or set(transition) != {"transition", "snapshot"}):
        raise _refused(_EVIDENCE)
    return EvidenceRows(
        snapshot_revision=revision,
        snapshot=envelope,
        pending=pending,
        transition=None if transition is None else _envelope(transition["transition"], _EVIDENCE),
        next_snapshot=None if transition is None else _envelope(transition["snapshot"], _EVIDENCE),
    )


def history(store, below_revision: int) -> list[dict[str, str]]:
    """Snapshot envelopes of every transition below ``below_revision``, newest first."""
    items: list[dict[str, str]] = []
    before: int | None = None
    while True:
        answer = _answer(store, _HISTORY, {"below_revision": below_revision, "before": before}, _HISTORY_FIELDS)
        page = answer["items"]
        cursor = answer["next"]
        if not isinstance(page, list) or (cursor is not None and not _is_revision(cursor)):
            raise _refused(_HISTORY)
        items.extend(_envelope(item, _HISTORY) for item in page)
        if cursor is None:
            return items
        # A page must carry rows and move strictly down, or the walk cannot end.
        bound = below_revision if before is None else before
        if not page or not isinstance(cursor, int) or cursor >= bound:
            raise _refused(_HISTORY)
        before = cursor
