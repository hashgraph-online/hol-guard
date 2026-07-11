"""Transactional outbox for cloud live-request projection."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false
import sqlite3
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone

_LIVE_REQUEST_OUTBOX_SEED_KEY = "guard_live_request_outbox_seeded_v1"


def live_request_outbox_schema_statements() -> tuple[str, ...]:
    return (
        """
        create table if not exists guard_live_request_outbox (
          sequence integer primary key autoincrement,
          local_request_id text not null,
          changed_at text not null,
          workspace_id text,
          attempt_count integer not null default 0,
          next_attempt_at text,
          last_error text
        )
        """,
        """
        create index if not exists idx_guard_live_request_outbox_ready
        on guard_live_request_outbox (next_attempt_at, sequence)
        """,
        """
        create index if not exists idx_guard_live_request_outbox_newest_ready
        on guard_live_request_outbox (
          workspace_id,
          next_attempt_at,
          changed_at desc,
          sequence desc
        )
        """,
        """
        create index if not exists idx_guard_live_request_outbox_request
        on guard_live_request_outbox (local_request_id, sequence)
        """,
        """
        create trigger if not exists guard_live_request_outbox_after_insert
        after insert on approval_requests
        begin
          delete from guard_live_request_outbox
          where local_request_id = new.request_id;
          insert into guard_live_request_outbox (local_request_id, changed_at, workspace_id)
          values (
            new.request_id,
            coalesce(new.last_seen_at, new.created_at),
            (
              select json_extract(payload_json, '$.workspace_id')
              from sync_state
              where state_key = 'oauth_local_credentials'
            )
          );
        end
        """,
        "drop trigger if exists guard_live_request_outbox_after_update",
        """
        create trigger if not exists guard_live_request_outbox_after_update
        after update on approval_requests
        begin
          insert into guard_live_request_outbox (
            local_request_id,
            changed_at,
            workspace_id,
            attempt_count,
            next_attempt_at,
            last_error
          )
          values (
            new.request_id,
            coalesce(new.resolved_at, new.last_seen_at, new.created_at),
            (
              select workspace_id
              from guard_live_request_outbox
              where local_request_id = new.request_id
              order by sequence desc
              limit 1
            ),
            coalesce((
              select attempt_count
              from guard_live_request_outbox
              where local_request_id = new.request_id
              order by sequence desc
              limit 1
            ), 0),
            (
              select next_attempt_at
              from guard_live_request_outbox
              where local_request_id = new.request_id
              order by sequence desc
              limit 1
            ),
            (
              select last_error
              from guard_live_request_outbox
              where local_request_id = new.request_id
              order by sequence desc
              limit 1
            )
          );
          delete from guard_live_request_outbox
          where local_request_id = new.request_id
            and sequence <> last_insert_rowid();
        end
        """,
        "drop trigger if exists guard_live_request_outbox_before_delete",
    )


def ensure_live_request_outbox_schema(connection: sqlite3.Connection) -> None:
    statements = live_request_outbox_schema_statements()
    connection.execute(statements[0])
    columns = {
        str(row["name"]) for row in connection.execute("pragma table_info(guard_live_request_outbox)").fetchall()
    }
    if "workspace_id" not in columns:
        connection.execute("alter table guard_live_request_outbox add column workspace_id text")
    for statement in statements[1:]:
        connection.execute(statement)


def seed_live_request_outbox(connection: sqlite3.Connection, now: str) -> None:
    row = connection.execute(
        "select 1 from sync_state where state_key = ?",
        (_LIVE_REQUEST_OUTBOX_SEED_KEY,),
    ).fetchone()
    if row is not None:
        return
    connection.execute(
        """
        insert into guard_live_request_outbox (local_request_id, changed_at, workspace_id)
        select
          request_id,
          coalesce(resolved_at, last_seen_at, created_at),
          (
            select json_extract(payload_json, '$.workspace_id')
            from sync_state
            where state_key = 'oauth_local_credentials'
          )
        from approval_requests
        order by coalesce(resolved_at, last_seen_at, created_at), request_id
        """
    )
    connection.execute(
        """
        insert into sync_state (state_key, payload_json, updated_at)
        values (?, '{"seeded":true}', ?)
        """,
        (_LIVE_REQUEST_OUTBOX_SEED_KEY, now),
    )


def _retry_at(now: str, attempt_count: int) -> str:
    try:
        base = datetime.fromisoformat(now.replace("Z", "+00:00"))
    except ValueError:
        base = datetime.now(timezone.utc)
    delay_seconds = min(300.0, 0.5 * (2 ** min(attempt_count, 10)))
    return (base + timedelta(seconds=delay_seconds)).isoformat()


class StoreLiveRequestOutboxMixin:
    def claim_unowned_live_request_outbox(self, workspace_id: str) -> int:
        normalized_workspace_id = workspace_id.strip()
        if not normalized_workspace_id:
            raise ValueError("workspace_id is required")
        with self._connect() as connection:
            cursor = connection.execute(
                """
                update guard_live_request_outbox
                set workspace_id = ?
                where workspace_id is null
                """,
                (normalized_workspace_id,),
            )
            return int(cursor.rowcount if cursor.rowcount is not None else 0)

    def list_ready_live_request_outbox(
        self,
        *,
        now: str,
        limit: int,
        workspace_id: str | None = None,
        newest_first: bool = False,
    ) -> list[dict[str, object]]:
        query = """
            select sequence, local_request_id, changed_at, attempt_count
            from guard_live_request_outbox
            where (next_attempt_at is null or next_attempt_at <= ?)
        """
        parameters: list[object] = [now]
        if workspace_id is not None:
            query += " and workspace_id = ?"
            parameters.append(workspace_id)
        order = "changed_at desc, sequence desc" if newest_first else "sequence"
        query += f" order by {order} limit ?"
        parameters.append(max(1, int(limit)))
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [
            {
                "sequence": int(row["sequence"]),
                "local_request_id": str(row["local_request_id"]),
                "changed_at": str(row["changed_at"]),
                "attempt_count": int(row["attempt_count"]),
            }
            for row in rows
        ]

    def acknowledge_live_request_outbox(self, sequences: Sequence[int]) -> int:
        normalized = tuple(sorted({int(sequence) for sequence in sequences if int(sequence) > 0}))
        if not normalized:
            return 0
        placeholders = ",".join("?" for _ in normalized)
        with self._connect() as connection:
            cursor = connection.execute(
                f"delete from guard_live_request_outbox where sequence in ({placeholders})",
                normalized,
            )
            return int(cursor.rowcount if cursor.rowcount is not None else 0)

    def retry_live_request_outbox(
        self,
        sequences: Sequence[int],
        *,
        now: str,
        error: str,
    ) -> int:
        normalized = tuple(sorted({int(sequence) for sequence in sequences if int(sequence) > 0}))
        if not normalized:
            return 0
        placeholders = ",".join("?" for _ in normalized)
        with self._connect() as connection:
            rows = connection.execute(
                f"""
                select sequence, attempt_count
                from guard_live_request_outbox
                where sequence in ({placeholders})
                """,
                normalized,
            ).fetchall()
            updated = 0
            for row in rows:
                attempt_count = int(row["attempt_count"]) + 1
                cursor = connection.execute(
                    """
                    update guard_live_request_outbox
                    set attempt_count = ?, next_attempt_at = ?, last_error = ?
                    where sequence = ?
                    """,
                    (
                        attempt_count,
                        _retry_at(now, attempt_count),
                        error[:512],
                        int(row["sequence"]),
                    ),
                )
                updated += int(cursor.rowcount if cursor.rowcount is not None else 0)
            return updated

    def live_request_outbox_status(
        self,
        *,
        now: str,
        workspace_id: str | None = None,
    ) -> dict[str, object]:
        query = """
            select count(*) as depth,
                   min(changed_at) as oldest_changed_at,
                   max(attempt_count) as max_attempt_count,
                   max(last_error) as last_error
            from guard_live_request_outbox
        """
        parameters: list[object] = []
        if workspace_id is not None:
            query += " where workspace_id = ?"
            parameters.append(workspace_id)
        with self._connect() as connection:
            row = connection.execute(query, parameters).fetchone()
        return {
            "depth": int(row["depth"] if row is not None else 0),
            "oldest_changed_at": row["oldest_changed_at"] if row is not None else None,
            "max_attempt_count": int(row["max_attempt_count"] or 0) if row is not None else 0,
            "last_error": row["last_error"] if row is not None else None,
            "checked_at": now,
        }
