"""Connector setup context kept on a local-CLI observation.

An observation that Guard held for review because it did not recognise the
connector carries a little context about why: the first cause that blocked it,
and the scrubbed wording of the latest review row. The resident records these
columns; this module owns the schema and the checks every writer shares.

There is no stored resolution state. Whether a connector is still waiting on a
decision is read from ``local_cli_grant`` each time (``allowed``, ``blocked``,
otherwise ``unset``), so it can never disagree with the grant that decides.
"""

from __future__ import annotations

import sqlite3
from typing import Final

FIRST_BLOCKED_CAUSES: Final = (
    "exec_outside_roots",
    "connect_loopback",
    "read_home_state",
    "write_home_state",
    "unrecognised_tool",
)
CONTEXT_COLUMNS: Final = (
    "first_blocked_cause",
    "last_trigger_summary",
    "last_why_now",
    "last_harness",
    "last_workspace_label",
    "last_context_at",
)
# Caps the resident applies as well; the store never keeps more than this.
MAX_SUMMARY_CHARS: Final = 240
MAX_LABEL_CHARS: Final = 80
# The causes a grant capability resolves, and the capability each implies.
CAPABILITY_BY_CAUSE: Final = {
    "connect_loopback": "loopback-network",
    "read_home_state": "state-dir-read",
    "write_home_state": "state-dir-write",
}


def ensure_local_cli_context_columns(connection: sqlite3.Connection) -> None:
    """Add the context columns that are missing; every one is nullable."""

    columns = _column_names(connection, "local_cli_observation")
    if not columns:
        return
    for column in CONTEXT_COLUMNS:
        if column not in columns:
            connection.execute(f"alter table local_cli_observation add column {column} text")


def validated_first_blocked_cause(raw: object) -> str | None:
    """The cause when it is one of the known causes, ``None`` for an absent one."""

    if raw is None:
        return None
    if not isinstance(raw, str) or raw not in FIRST_BLOCKED_CAUSES:
        raise ValueError("invalid_first_blocked_cause")
    return raw


def note_capability_cause(connection: sqlite3.Connection, *, cli_id: str, identity_hash: str, cause: str) -> int:
    """Keep that an allowed CLI's contained run was denied what ``cause`` names.

    The newest denial wins, so the connector points at the capability the last
    run lacked. Nothing here turns a capability on. Returns how many rows
    changed.
    """

    if cause not in CAPABILITY_BY_CAUSE:
        raise ValueError("invalid_first_blocked_cause")
    cursor = connection.execute(
        """update local_cli_observation set first_blocked_cause = ?
            where cli_id = ? and identity_hash = ? and surface = 'cli'
              and first_blocked_cause is not ?""",
        (cause, cli_id, identity_hash, cause),
    )
    return cursor.rowcount


def _column_names(connection: sqlite3.Connection, table: str) -> set[str]:
    names: set[str] = set()
    for row in connection.execute(f"pragma table_info({table})").fetchall():
        names.add(str(row["name"] if isinstance(row, sqlite3.Row) else row[1]))
    return names


__all__ = [
    "CAPABILITY_BY_CAUSE",
    "CONTEXT_COLUMNS",
    "FIRST_BLOCKED_CAUSES",
    "MAX_LABEL_CHARS",
    "MAX_SUMMARY_CHARS",
    "ensure_local_cli_context_columns",
    "note_capability_cause",
    "validated_first_blocked_cause",
]
