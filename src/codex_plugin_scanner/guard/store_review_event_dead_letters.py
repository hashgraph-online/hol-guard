"""Bounded, recoverable dead-letter storage for Review outbox events."""

# pyright: reportAttributeAccessIssue=false

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone

from .store_review_event_outbox_binding import normalized_delivery_binding

_MAX_DEAD_LETTERS_PER_BINDING = 1_000
_DEAD_LETTER_COLUMNS = (
    "stream_sequence",
    "event_id",
    "local_request_id",
    "request_sequence",
    "event_type",
    "event_schema_version",
    "payload_json",
    "payload_hash",
    "occurred_at",
    "oauth_source",
    "oauth_subject_hash",
    "workspace_id",
    "machine_id",
    "machine_installation_id",
    "attempt_count",
    "last_error",
)


def review_event_dead_letter_schema_statements() -> tuple[str, str]:
    """Return the durable Review dead-letter queue schema."""

    return (
        """
        create table if not exists guard_review_outbox_dead_letters (
          stream_sequence integer not null,
          event_id text primary key,
          local_request_id text not null,
          request_sequence integer not null,
          event_type text not null,
          event_schema_version integer not null,
          payload_json text not null,
          payload_hash text not null,
          occurred_at text not null,
          oauth_source text not null,
          oauth_subject_hash text not null,
          workspace_id text not null,
          machine_id text not null,
          machine_installation_id text not null,
          attempt_count integer not null,
          last_error text,
          dead_letter_reason text not null,
          dead_letter_error text not null,
          dead_lettered_at text not null
        )
        """,
        """
        create index if not exists idx_guard_review_outbox_dead_letters_binding
        on guard_review_outbox_dead_letters (
          oauth_source, oauth_subject_hash, workspace_id, machine_id,
          machine_installation_id, dead_lettered_at desc
        )
        """,
    )


class StoreReviewEventDeadLetterMixin:
    """Store API for manually recoverable permanent Review delivery failures."""

    def dead_letter_live_request_outbox_event(
        self,
        sequence: int,
        *,
        reason: str,
        error: str,
        oauth_subject_hash: str,
        workspace_id: str,
        machine_id: str,
        machine_installation_id: str,
        retain_outbox_event: bool = False,
    ) -> int:
        binding = normalized_delivery_binding(
            oauth_subject_hash=oauth_subject_hash,
            workspace_id=workspace_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
        )
        with self._connect() as connection:
            connection.execute("begin immediate")
            row = connection.execute(
                """
                select stream_sequence, event_id, local_request_id, request_sequence, event_type,
                       event_schema_version, payload_json, payload_hash, occurred_at, oauth_source,
                       oauth_subject_hash, workspace_id, machine_id, machine_installation_id,
                       attempt_count, last_error
                from guard_review_outbox_events
                where stream_sequence = ? and oauth_source = ? and oauth_subject_hash = ?
                  and workspace_id = ? and machine_id = ? and machine_installation_id = ?
                  and acknowledged_at is null
                """,
                (int(sequence), self._guard_source, *binding),
            ).fetchone()
            if row is None:
                return 0
            values = tuple(row[column] for column in _DEAD_LETTER_COLUMNS)
            connection.execute(
                f"""
                insert into guard_review_outbox_dead_letters (
                  {", ".join(_DEAD_LETTER_COLUMNS)}, dead_letter_reason, dead_letter_error, dead_lettered_at
                ) values ({", ".join("?" for _ in _DEAD_LETTER_COLUMNS)}, ?, ?, ?)
                on conflict(event_id) do update set
                  dead_letter_reason = excluded.dead_letter_reason,
                  dead_letter_error = excluded.dead_letter_error,
                  dead_lettered_at = excluded.dead_lettered_at
                """,
                (*values, reason[:128], error[:512], datetime.now(timezone.utc).isoformat()),
            )
            if retain_outbox_event:
                connection.execute(
                    """
                    update guard_review_outbox_events
                    set binding_status = 'quarantined', quarantine_reason = ?,
                        next_attempt_at = null, last_error = ?
                    where stream_sequence = ?
                    """,
                    (f"dead_letter:{reason}"[:128], error[:512], int(sequence)),
                )
            else:
                connection.execute(
                    "delete from guard_review_outbox_events where stream_sequence = ?",
                    (int(sequence),),
                )
            connection.execute(
                """
                delete from guard_review_outbox_dead_letters
                where event_id in (
                  select dead.event_id
                  from guard_review_outbox_dead_letters as dead
                  left join guard_review_outbox_events as pending on pending.event_id = dead.event_id
                  where dead.oauth_source = ? and dead.oauth_subject_hash = ?
                    and dead.workspace_id = ? and dead.machine_id = ?
                    and dead.machine_installation_id = ?
                  order by case when pending.event_id is null then 1 else 0 end,
                           dead.dead_lettered_at desc, dead.stream_sequence desc
                  limit -1 offset ?
                )
                """,
                (self._guard_source, *binding, _MAX_DEAD_LETTERS_PER_BINDING),
            )
        self.notify_review_event_outbox_wake()
        return 1

    def list_live_request_outbox_dead_letters(
        self,
        *,
        oauth_subject_hash: str,
        workspace_id: str,
        machine_id: str,
        machine_installation_id: str,
        limit: int = 100,
    ) -> list[dict[str, object]]:
        binding = normalized_delivery_binding(
            oauth_subject_hash=oauth_subject_hash,
            workspace_id=workspace_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
        )
        with self._connect() as connection:
            rows = connection.execute(
                """
                select stream_sequence, event_id, local_request_id, request_sequence, event_type,
                       occurred_at, attempt_count, dead_letter_reason, dead_letter_error, dead_lettered_at
                from guard_review_outbox_dead_letters where oauth_source = ?
                  and oauth_subject_hash = ? and workspace_id = ?
                  and machine_id = ? and machine_installation_id = ?
                order by dead_lettered_at desc, stream_sequence desc limit ?
                """,
                (self._guard_source, *binding, max(1, min(int(limit), _MAX_DEAD_LETTERS_PER_BINDING))),
            ).fetchall()
        return [dict(row) for row in rows]

    def retry_live_request_outbox_dead_letters(
        self,
        sequences: Sequence[int] | None = None,
        *,
        oauth_subject_hash: str,
        workspace_id: str,
        machine_id: str,
        machine_installation_id: str,
    ) -> int:
        binding = normalized_delivery_binding(
            oauth_subject_hash=oauth_subject_hash,
            workspace_id=workspace_id,
            machine_id=machine_id,
            machine_installation_id=machine_installation_id,
        )
        requested = tuple(sorted({int(sequence) for sequence in sequences or () if int(sequence) > 0}))
        if sequences is not None and not requested:
            return 0
        query = """
            select * from guard_review_outbox_dead_letters where oauth_source = ?
              and oauth_subject_hash = ? and workspace_id = ?
              and machine_id = ? and machine_installation_id = ?
        """
        parameters: list[object] = [self._guard_source, *binding]
        if requested:
            placeholders = ", ".join("?" for _ in requested)
            query += f" and stream_sequence in ({placeholders})"
            parameters.extend(requested)
        query += " order by stream_sequence asc"
        restored = 0
        with self._connect() as connection:
            connection.execute("begin immediate")
            rows = connection.execute(query, parameters).fetchall()
            for row in rows:
                cursor = connection.execute(
                    """
                    update guard_review_outbox_events
                    set binding_status = 'ready', quarantine_reason = null,
                        acknowledged_at = null, attempt_count = 0,
                        next_attempt_at = null, last_error = null
                    where event_id = ? and oauth_source = ? and oauth_subject_hash = ?
                      and workspace_id = ? and machine_id = ? and machine_installation_id = ?
                    """,
                    (row["event_id"], self._guard_source, *binding),
                )
                if not cursor.rowcount:
                    insert_columns = _DEAD_LETTER_COLUMNS[1:-2]
                    connection.execute(
                        f"""
                        insert into guard_review_outbox_events (
                          {", ".join(insert_columns)}, binding_status, quarantine_reason,
                          acknowledged_at, attempt_count, next_attempt_at, last_error
                        ) values ({", ".join("?" for _ in insert_columns)}, 'ready', null,
                                  null, 0, null, null)
                        """,
                        tuple(row[column] for column in insert_columns),
                    )
                connection.execute(
                    "delete from guard_review_outbox_dead_letters where event_id = ?",
                    (row["event_id"],),
                )
                restored += 1
        if restored:
            self.notify_review_event_outbox_wake()
        return restored
