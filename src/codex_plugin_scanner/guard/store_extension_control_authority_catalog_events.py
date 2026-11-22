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

import sqlite3
from pathlib import Path
from typing import Any, Final

from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.generated_command_catalog_provenance import catalog_provenance, is_downgrade

MIGRATED_EVENT: Final = "extension_control_authority_catalog_migrated"
REGRESSED_EVENT: Final = "extension_control_authority_catalog_regressed"

# The native store reads the migration events: it skips a payload that is not
# a JSON object and bounds the writer scan to the newest events.
_RECORDED: Final = "extension_control_migration_recorded"
_WRITER: Final = "extension_control_catalog_writer_version"


def recorded_writer_version(store: Any, catalog_digest: str) -> str | None:
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

    answer = store._native_store_call(_WRITER, {"catalog_digest": catalog_digest})
    version = answer.get("writer_version") if isinstance(answer, dict) and set(answer) == {"writer_version"} else ""
    if version is None:
        return None
    if not isinstance(version, str) or not version:
        raise sqlite3.DatabaseError(f"native {_WRITER} returned no answer")
    return version


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


def already_recorded(store: Any, revision: int) -> bool:
    """Whether this revision's migration event is already in the store."""

    answer = store._native_store_call(_RECORDED, {"revision": revision})
    recorded = answer.get("recorded") if isinstance(answer, dict) and set(answer) == {"recorded"} else None
    if not isinstance(recorded, bool):
        raise sqlite3.DatabaseError(f"native {_RECORDED} returned no answer")
    return recorded


__all__ = [
    "MIGRATED_EVENT",
    "REGRESSED_EVENT",
    "already_recorded",
]
