"""Durable mutation generation for process-local Review outbox wake hints."""

from __future__ import annotations

import sqlite3


def review_event_wake_schema_statements() -> tuple[str, ...]:
    """Return schema objects that count every committed outbox row mutation."""
    return (
        """
        create table if not exists guard_review_outbox_wake_state (
          singleton integer primary key check(singleton = 1),
          generation integer not null
        )
        """,
        """
        insert or ignore into guard_review_outbox_wake_state (singleton, generation)
        values (1, 0)
        """,
        _row_generation_trigger("insert"),
        _update_generation_trigger(),
        _row_generation_trigger("delete"),
    )


def review_event_outbox_generation(connection: sqlite3.Connection) -> int:
    """Return the durable outbox mutation generation, or zero before setup."""
    table = connection.execute(
        "select 1 from sqlite_master where type = 'table' and name = 'guard_review_outbox_wake_state'"
    ).fetchone()
    if table is None:
        return 0
    row = connection.execute("select generation from guard_review_outbox_wake_state where singleton = 1").fetchone()
    return int(row[0]) if row is not None else 0


def _row_generation_trigger(operation: str) -> str:
    return f"""
        create trigger if not exists guard_review_outbox_wake_after_{operation}
        after {operation} on guard_review_outbox_events
        begin
          update guard_review_outbox_wake_state
          set generation = generation + 1 where singleton = 1;
        end
    """


def _update_generation_trigger() -> str:
    return """
        create trigger if not exists guard_review_outbox_wake_after_update
        after update on guard_review_outbox_events
        when old.binding_status is not new.binding_status
          or old.next_attempt_at is not new.next_attempt_at
          or old.acknowledged_at is not new.acknowledged_at
          or old.attempt_count is not new.attempt_count
          or old.payload_hash is not new.payload_hash
          or old.oauth_source is not new.oauth_source
          or old.oauth_subject_hash is not new.oauth_subject_hash
          or old.workspace_id is not new.workspace_id
          or old.machine_id is not new.machine_id
          or old.machine_installation_id is not new.machine_installation_id
        begin
          update guard_review_outbox_wake_state
          set generation = generation + 1 where singleton = 1;
        end
    """


__all__ = ["review_event_outbox_generation", "review_event_wake_schema_statements"]
