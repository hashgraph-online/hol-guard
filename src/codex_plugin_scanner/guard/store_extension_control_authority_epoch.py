"""A counter that moves whenever an extension-control authority input changes.

The resident's authority read depends on a handful of tables, and on two of
them only through a few rows. Triggers on exactly those rows bump one counter,
so a caller can tell the authority's inputs are unchanged while the rest of the
database (hook receipts, evidence, sessions) keeps committing. The triggers fire
for every connection that writes, whichever process or language it runs in.

A counter is only trusted while every trigger is present with the exact text
written here; a dropped or rewritten trigger reads as no counter at all.
"""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Final

# Every table the resident's ``extension_control_authority`` ops read, each with
# the rows that matter (``None`` is every row). ``guard_events`` holds one
# authority record kind among many, and ``sync_state`` holds two of its keys.
AUTHORITY_INPUT_TABLES: Final[tuple[tuple[str, str | None], ...]] = (
    ("extension_control_schema_migration", None),
    ("extension_control_authority_snapshot", None),
    ("extension_control_catalog_manifest", None),
    ("extension_control_authority_transition", None),
    ("extension_control_authority_proof", None),
    ("extension_command_pack_activation", None),
    ("guard_events", "{row}.event_name = 'extension_control_authority_catalog_migrated'"),
    ("sync_state", "{row}.state_key in ('managed_controls_active', 'managed_controls_revision')"),
)

_EPOCH_TABLE: Final = """
create table if not exists extension_control_authority_epoch (
    singleton integer primary key check (singleton = 1),
    epoch integer not null
)
"""


def _trigger_name(table: str, event: str) -> str:
    return f"trg_extension_control_epoch_{table}_{event}"


def _trigger_sql(table: str, event: str, rows: str | None) -> str:
    if rows is None:
        when = ""
    elif event == "insert":
        when = f" when {rows.format(row='new')}"
    elif event == "delete":
        when = f" when {rows.format(row='old')}"
    else:
        when = f" when ({rows.format(row='old')}) or ({rows.format(row='new')})"
    return (
        f"CREATE TRIGGER {_trigger_name(table, event)} after {event} on {table}{when} begin "
        "update extension_control_authority_epoch set epoch = epoch + 1 where singleton = 1; end"
    )


_TRIGGERS: Final[dict[str, tuple[str, str]]] = {
    _trigger_name(table, event): (table, _trigger_sql(table, event, rows))
    for table, rows in AUTHORITY_INPUT_TABLES
    for event in ("insert", "update", "delete")
}
_TRIGGERS_DIGEST: Final = hashlib.sha256(
    "\n".join(f"{name}\n{sql}" for name, (_table, sql) in sorted(_TRIGGERS.items())).encode()
).hexdigest()
_LEGACY_TRIGGERS_DIGEST: Final = hashlib.sha256(
    "\n".join(
        f"{name}\n{sql}"
        for name, (table, sql) in sorted(_TRIGGERS.items())
        if table != "extension_command_pack_activation"
    ).encode()
).hexdigest()


def ensure_extension_control_authority_epoch(connection: sqlite3.Connection) -> None:
    """Create the counter and its triggers for every input table that exists.

    Only what is missing is written, so a store that already has them takes no
    write lock here.
    """

    present = {
        (str(row[0]), str(row[1]))
        for row in connection.execute("select type, name from sqlite_master where type in ('table', 'trigger')")
    }
    if ("table", "extension_control_authority_epoch") not in present:
        _ = connection.execute(_EPOCH_TABLE)
    if connection.execute("select 1 from extension_control_authority_epoch where singleton = 1").fetchone() is None:
        _ = connection.execute(
            "insert or ignore into extension_control_authority_epoch (singleton, epoch) values (1, 0)"
        )
    for name, (table, sql) in _TRIGGERS.items():
        if ("table", table) in present and ("trigger", name) not in present:
            _ = connection.execute(sql)


def extension_control_authority_epoch(connection: sqlite3.Connection) -> int | None:
    """The counter, or None unless every trigger is in place exactly as written."""

    packs = (
        connection.execute(
            "select 1 from sqlite_master where type='table' and name='extension_command_pack_activation'"
        ).fetchone()
        is not None
    )
    if not packs:
        from .store_extension_control_authority_schema import (
            PACK_ACTIVATION_SCHEMA_VERSION,
            extension_control_schema_marker_is_compatible,
        )

        marker = connection.execute(
            "select version, checksum from extension_control_schema_migration where singleton=1"
        ).fetchone()
        if (
            marker is None
            or not extension_control_schema_marker_is_compatible(marker[0], marker[1])
            or marker[0] >= PACK_ACTIVATION_SCHEMA_VERSION
        ):
            return None
    rows = connection.execute(
        "select name, sql from sqlite_master where type = 'trigger' "
        "and name glob 'trg_extension_control_epoch_*' order by name"
    ).fetchall()
    found = hashlib.sha256("\n".join(f"{row[0]}\n{row[1]}" for row in rows).encode()).hexdigest()
    if found != (_TRIGGERS_DIGEST if packs else _LEGACY_TRIGGERS_DIGEST):
        return None
    row = connection.execute("select epoch from extension_control_authority_epoch where singleton = 1").fetchone()
    if row is None or type(row[0]) is not int:
        return None
    # Schema activation must change the memo token even if its migration did
    # not advance the counter. Never reuse a pre-pack reply for a pack store.
    return row[0] * 2 + int(packs)


__all__ = [
    "AUTHORITY_INPUT_TABLES",
    "ensure_extension_control_authority_epoch",
    "extension_control_authority_epoch",
]
