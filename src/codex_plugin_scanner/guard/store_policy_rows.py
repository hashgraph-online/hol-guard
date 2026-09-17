"""Materialized policy row identity and source-scoped replacement operations."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence

from .policy_integrity import BUNDLE_OWNED_POLICY_SOURCES


def materialized_policy_row_identity(row: sqlite3.Row) -> tuple[object, ...]:
    return (
        row["harness"],
        row["scope"],
        row["artifact_id"],
        row["artifact_hash"],
        row["workspace"],
        row["publisher"],
        row["action"],
        row["reason"],
        row["owner"],
        row["source"],
        row["expires_at"],
    )


def replace_remote_policy_rows_locked(
    connection: sqlite3.Connection,
    rows: Sequence[tuple[object, ...]],
    *,
    sources: Sequence[str] | None = None,
) -> None:
    selected = tuple(sorted(sources if sources is not None else BUNDLE_OWNED_POLICY_SOURCES))
    placeholders = "(" + ",".join("?" for _ in selected) + ")"
    connection.execute(
        f"delete from policy_decisions where source in {placeholders}",
        selected,
    )
    connection.executemany(
        """
        insert into policy_decisions (
          harness, scope, artifact_id, artifact_hash, workspace, publisher, action, reason, owner, source,
          expires_at, updated_at, integrity_version, integrity_generation, payload_hash, payload_mac,
          integrity_key_id, signed_at
        )
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
