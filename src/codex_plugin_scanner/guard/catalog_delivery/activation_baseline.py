"""Authenticated legacy baseline retained while the first pack commit is pending."""

from __future__ import annotations

import sqlite3

from ..native_policy_snapshot_constants import NativePolicySnapshotError
from . import lifecycle
from .pack_store import decode

SCHEMA = "guard.command-pack-legacy-baseline.v1"
PURPOSE = "command-pack-legacy-baseline.v1"
_RETAINED = "command_pack_baseline_retained"


def is_baseline(data):
    if not isinstance(data, str) or not 0 < len(data.encode("utf-8")) <= 64 * 1024:
        raise ValueError("activation record exceeds byte budget")
    value = decode(data.encode())
    return isinstance(value, dict) and value.get("schema") == SCHEMA


def verify(row, key):
    """The authenticated baseline; the runtime checks it binds revision 0."""
    return lifecycle.record(
        "verify",
        "baseline",
        key=key,
        record=row["record_json"],
        digest=row["record_digest"],
        mac=row["record_mac"],
        revision=row["revision"],
    )["value"]


def baseline_request(store, metadata, *, recorded_at):
    """The legacy baseline the resident retains with a first activation.

    A store whose schema already activated packs keeps the baseline or
    activation it holds, and the resident authenticates that row when it
    reserves the draft. Otherwise the resident upgrades the schema and seals
    the baseline into the empty slot in the transaction that reserves the
    draft. A slot still empty after an upgraded schema means an earlier
    first activation was refused, so the baseline is sent again.
    """
    answer = store._native_store_call(_RETAINED, {})
    if answer == {"state": "schema_missing"}:
        # The SQL read this replaces failed on the missing table.
        raise sqlite3.OperationalError("extension control authority schema is missing")
    if not isinstance(answer, dict) or set(answer) != {"state", "retained"} or answer["state"] != "present":
        raise NativePolicySnapshotError(f"native {_RETAINED} returned no answer")
    retained = answer["retained"]
    if not isinstance(retained, bool):
        raise NativePolicySnapshotError(f"native {_RETAINED} returned no answer")
    if retained:
        return None
    return {
        **{name: getattr(metadata, name) for name in ("program_digest", "catalog_digest", "trust_digest")},
        "recorded_at": recorded_at,
    }
