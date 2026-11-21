"""Tell a re-delivered policy bundle from one that changes enforcement.

Cloud signs a policy bundle each time it serves one, and RSA-PSS signatures are
randomised, so every sync delivers the same bundle with a new signature. Guard
used to treat each delivery as a new activation and close the native
command-control fence before writing it. Closing the fence forces every native
reader to republish the policy snapshot. With a sync every ~45 seconds, hooks
that arrived during each republish failed closed.

An activation whose rows and state equal what is stored, apart from the bundle
signature, the delivery acknowledgement and the write timestamps, cannot change
what Guard enforces. It still writes, so the new signature and acknowledgement
are kept, but it leaves the fence open. Any difference, including stored rows
that carry integrity fields this activation would clear, counts as a change.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping, Sequence

from .policy_integrity import REMOTE_POLICY_SOURCES

# Reported to Cloud only; for an unmanaged delivery the resident does not
# observe it and no reader enforces from it.
_REPORTING_ONLY_KEYS = frozenset({"policy_bundle_ack"})
_SIGNED_BUNDLE_KEYS = frozenset({"policy_bundle", "policy_bundle_last_good"})
# Column order of the rows the resident inserts; ``updated_at`` is the write time.
_ROW_COLUMNS = (
    "harness",
    "scope",
    "artifact_id",
    "artifact_hash",
    "workspace",
    "publisher",
    "action",
    "reason",
    "owner",
    "source",
    "expires_at",
    "updated_at",
    "integrity_version",
    "integrity_generation",
    "payload_hash",
    "payload_mac",
    "integrity_key_id",
    "signed_at",
)
_WRITE_TIME_COLUMN = _ROW_COLUMNS.index("updated_at")


def _without_signature(payload: str | None) -> object:
    if payload is None:
        return None
    try:
        bundle = json.loads(payload)
    except json.JSONDecodeError:
        return payload
    if not isinstance(bundle, dict):
        return bundle
    verifier = bundle.get("verifier")
    if isinstance(verifier, dict):
        bundle["verifier"] = {key: value for key, value in verifier.items() if key != "signature"}
    return bundle


def _comparable_rows(rows: Iterable[Sequence[object]]) -> list[tuple[str, ...]]:
    return sorted(
        tuple(json.dumps(value) for index, value in enumerate(row) if index != _WRITE_TIME_COLUMN) for row in rows
    )


def activation_changes_enforcement(
    connection: sqlite3.Connection,
    *,
    payloads: Mapping[str, str],
    rows: Sequence[Sequence[object]],
) -> bool:
    """Return False only when this activation would rewrite enforcement as it is.

    ``payloads`` are the ``sync_state`` values the activation writes, last-good
    copies included, and ``rows`` the remote policy rows that replace the
    stored ones. Call it inside the transaction that observed the state the
    activation is checked against.
    """

    for state_key, payload in payloads.items():
        if state_key in _REPORTING_ONLY_KEYS:
            continue
        stored_row = connection.execute(
            "select payload_json from sync_state where state_key = ?", (state_key,)
        ).fetchone()
        stored = None if stored_row is None else str(stored_row[0])
        if state_key in _SIGNED_BUNDLE_KEYS:
            if _without_signature(stored) != _without_signature(payload):
                return True
        elif stored != payload:
            return True
    sources = sorted(REMOTE_POLICY_SOURCES)
    placeholders = ",".join("?" for _ in sources)
    stored_rows = connection.execute(
        f"select {', '.join(_ROW_COLUMNS)} from policy_decisions where source in ({placeholders})",
        sources,
    ).fetchall()
    return _comparable_rows(tuple(row) for row in stored_rows) != _comparable_rows(rows)
