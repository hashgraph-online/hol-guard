"""Acknowledge and compact review events within the caller's transaction."""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence


def acknowledge_review_events(
    connection: sqlite3.Connection,
    *,
    source: str,
    sequences: Sequence[int],
    binding: tuple[str, str, str, str],
    acknowledged_at: str,
) -> int:
    acknowledged = sorted({int(sequence) for sequence in sequences if int(sequence) > 0})
    if not acknowledged:
        return 0
    placeholders = ",".join("?" for _ in acknowledged)
    _ = connection.execute(
        f"""
        update guard_review_outbox_events set acknowledged_at = ?
        where stream_sequence in ({placeholders})
          and oauth_source = ? and oauth_subject_hash = ? and workspace_id = ?
          and machine_id = ? and machine_installation_id = ?
          and binding_status = 'ready' and acknowledged_at is null
        """,
        (acknowledged_at, *acknowledged, source, *binding),
    )
    rows = connection.execute(
        """
        select stream_sequence, acknowledged_at from guard_review_outbox_events
        where oauth_source = ? and oauth_subject_hash = ? and workspace_id = ?
          and machine_id = ? and machine_installation_id = ?
          and binding_status = 'ready'
        order by stream_sequence
        """,
        (source, *binding),
    ).fetchall()
    prefix: list[int] = []
    for row in rows:
        if row["acknowledged_at"] is None:
            break
        prefix.append(int(row["stream_sequence"]))
    if not prefix:
        return 0
    placeholders = ",".join("?" for _ in prefix)
    cursor = connection.execute(
        f"""
        delete from guard_review_outbox_events
        where stream_sequence in ({placeholders}) and binding_status = 'ready'
        """,
        prefix,
    )
    _ = connection.execute(
        """
        insert into guard_review_outbox_cursors (
          oauth_source, oauth_subject_hash, workspace_id, machine_id,
          machine_installation_id, acknowledged_stream_sequence, updated_at
        ) values (?, ?, ?, ?, ?, ?, ?)
        on conflict(oauth_source, oauth_subject_hash, workspace_id, machine_id, machine_installation_id)
        do update set acknowledged_stream_sequence = max(
          guard_review_outbox_cursors.acknowledged_stream_sequence,
          excluded.acknowledged_stream_sequence
        ), updated_at = excluded.updated_at
        """,
        (source, *binding, prefix[-1], acknowledged_at),
    )
    return max(0, int(cursor.rowcount or 0))
