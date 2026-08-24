"""Idempotent upgrades for persisted Review event outbox state."""

from __future__ import annotations

import sqlite3

from .review_event_integrity import review_event_payload_digest

# pyright: reportAny=false, reportUnusedCallResult=false


def ensure_review_event_outbox_upgrade(connection: sqlite3.Connection, *, migration_version: int) -> None:
    rows = connection.execute("pragma table_info(guard_review_outbox_request_sequences)").fetchall()
    existing = {str(row["name"]) for row in rows}
    binding_columns = [
        "oauth_source",
        "oauth_subject_hash",
        "workspace_id",
        "machine_id",
        "machine_installation_id",
    ]
    for column in binding_columns:
        if column not in existing:
            connection.execute(f"alter table guard_review_outbox_request_sequences add column {column} text")

    migrations = connection.execute(
        "select 1 from sqlite_master where type = 'table' and name = 'schema_migrations'"
    ).fetchone()
    if migrations is not None:
        applied = connection.execute(
            "select 1 from schema_migrations where version = ?",
            (migration_version,),
        ).fetchone()
        if applied is not None:
            return
    events = connection.execute(
        """
        select stream_sequence, payload_json, oauth_source, oauth_subject_hash,
               workspace_id, machine_id, machine_installation_id
        from guard_review_outbox_events
        """
    ).fetchall()
    for event in events:
        connection.execute(
            "update guard_review_outbox_events set payload_hash = ? where stream_sequence = ?",
            (
                review_event_payload_digest(
                    str(event["payload_json"]),
                    oauth_source=event["oauth_source"],
                    oauth_subject_hash=event["oauth_subject_hash"],
                    workspace_id=event["workspace_id"],
                    machine_id=event["machine_id"],
                    machine_installation_id=event["machine_installation_id"],
                ),
                event["stream_sequence"],
            ),
        )
