"""Authenticated legacy baseline retained while the first pack commit is pending."""

from __future__ import annotations

from . import lifecycle
from .pack_store import decode

SCHEMA = "guard.command-pack-legacy-baseline.v1"
PURPOSE = "command-pack-legacy-baseline.v1"


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


def baseline_request(connection, metadata, *, recorded_at):
    """The legacy baseline the resident retains with a first activation.

    A store whose schema already activated packs keeps the baseline or
    activation it holds, and the resident authenticates that row when it
    reserves the draft. Otherwise the resident upgrades the schema and seals
    the baseline into the empty slot in the transaction that reserves the
    draft. A slot still empty after an upgraded schema means an earlier
    first activation was refused, so the baseline is sent again.
    """
    marker = connection.execute("select version from extension_control_schema_migration where singleton=1").fetchone()
    if marker is not None and marker["version"] in {5, 6}:
        slot = connection.execute("select 1 from extension_command_pack_activation where singleton=1").fetchone()
        if slot is not None:
            return None
    return {
        **{name: getattr(metadata, name) for name in ("program_digest", "catalog_digest", "trust_digest")},
        "recorded_at": recorded_at,
    }
