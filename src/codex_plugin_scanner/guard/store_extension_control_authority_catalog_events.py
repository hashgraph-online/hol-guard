"""The record a catalog migration leaves behind, and what it says about it.

The migration event used to record only the two digests. That is enough to see
a store flipping between catalogs and not enough to find out why, because the
digest does not name the install that wrote it. Several Guard versions can
share one ``~/.hol-guard``; each migrates the authority to its own packaged
catalog, so the newest install's controls are retired every time an older one
runs, and restored the next time the newer one does.

Provenance makes that visible, and a regression record makes the protection
loss loud instead of silent: a migration that moves to a catalog written by an
older Guard than the one that wrote the current catalog is recorded as such,
with the controls it retired.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Final

from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.generated_command_catalog_provenance import catalog_provenance, is_downgrade

MIGRATED_EVENT: Final = "extension_control_authority_catalog_migrated"
REGRESSED_EVENT: Final = "extension_control_authority_catalog_regressed"

# A store accumulates one migration event per revision, so the scan for the
# previous catalog's writer is bounded rather than reading the whole table.
_WRITER_LOOKUP_LIMIT: Final = 512


def _encode(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _decode(raw: object) -> dict[str, Any] | None:
    try:
        recorded = json.loads(str(raw))
    except (json.JSONDecodeError, TypeError):
        return None
    return recorded if isinstance(recorded, dict) else None


def recorded_writer_version(connection: sqlite3.Connection, catalog_digest: str) -> str | None:
    """The Guard version that produced the catalog ``catalog_digest`` names.

    The lookup is keyed on the catalog, not on the revision that last moved the
    store to it. A digest is its contents, so the install that wrote those
    contents is the one whose controls a migration away from them retires, even
    when the store arrived at that catalog again through an event nobody could
    attribute. Keying on the revision would read that backfill, find no writer,
    and drop the record that exists to make the loss loud.

    Returns None for a store whose events predate provenance, which is the
    normal case on an upgrade: the first migration after this ships has nothing
    to compare against and is not reported as a regression.

    Only an event written by the install performing that migration carries a
    writer version. An event backfilled by a later reader describes a revision
    it found rather than one it wrote, and reading the reader's version as the
    writer's would invent a downgrade on the next migration, or hide one.
    """

    rows = connection.execute(
        "select payload_json from guard_events where event_name = ? order by event_id desc limit ?",
        (MIGRATED_EVENT, _WRITER_LOOKUP_LIMIT),
    ).fetchall()
    for row in rows:
        recorded = _decode(row["payload_json"])
        if recorded is None or recorded.get("catalog_digest") != catalog_digest:
            continue
        provenance = recorded.get("provenance")
        if isinstance(provenance, dict):
            version = provenance.get("writer_version")
            if isinstance(version, str) and version:
                return version
    return None


def migration_provenance(
    previous_writer_version: str | None,
    catalog_digest: str,
    registry: CommandSafetyExtensionRegistry | None,
    *,
    trigger: str,
    writer: bool,
    guard_home: Path,
) -> tuple[dict[str, Any], str | None]:
    """The migration's provenance, and the newer writer it hands the store back from.

    Both come from the store home's native runtime, so callers settle them
    before a store transaction opens: a slow resident never holds the write lock.
    """

    provenance = catalog_provenance(
        catalog_digest=catalog_digest, catalog=registry, trigger=trigger, writer=writer, guard_home=guard_home
    )
    writer_version = provenance.get("writer_version")
    if previous_writer_version is None or not isinstance(writer_version, str):
        return provenance, None
    downgrade = is_downgrade(writer_version, previous_writer_version, guard_home=guard_home)
    return provenance, previous_writer_version if downgrade else None


def already_recorded(connection: sqlite3.Connection, revision: int) -> bool:
    """Whether this revision's migration event is already in the store."""

    rows = connection.execute(
        "select payload_json from guard_events where event_name = ?",
        (MIGRATED_EVENT,),
    ).fetchall()
    for row in rows:
        recorded = _decode(row["payload_json"])
        if recorded is not None and recorded.get("revision") == revision:
            return True
    return False


__all__ = [
    "MIGRATED_EVENT",
    "REGRESSED_EVENT",
    "already_recorded",
]
