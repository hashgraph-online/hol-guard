"""Request-level resume state helpers for Codex browser approval flows."""

from __future__ import annotations

import sqlite3


def resume_schema_statement() -> str:
    return """
        create table if not exists guard_request_resumes (
          request_id text primary key,
          operation_id text,
          harness text not null,
          resolution_action text,
          strategy text not null,
          supported integer not null default 0,
          status text not null,
          thread_id text,
          reason text,
          message text,
          last_error text,
          attempt_count integer not null default 0,
          created_at text not null,
          updated_at text not null,
          last_attempt_at text,
          sent_at text
        )
        """


def seed_request_resume(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    operation_id: str | None,
    harness: str,
    strategy: str,
    supported: bool,
    thread_id: str | None,
    now: str,
) -> None:
    connection.execute(
        """
        insert into guard_request_resumes (
          request_id, operation_id, harness, resolution_action, strategy, supported, status, thread_id, reason,
          message, last_error, attempt_count, created_at, updated_at, last_attempt_at, sent_at
        )
        values (?, ?, ?, null, ?, ?, 'pending', ?, null, null, null, 0, ?, ?, null, null)
        on conflict(request_id) do update set
          operation_id = excluded.operation_id,
          harness = excluded.harness,
          strategy = excluded.strategy,
          supported = excluded.supported,
          thread_id = coalesce(excluded.thread_id, guard_request_resumes.thread_id),
          updated_at = excluded.updated_at
        """,
        (
            request_id,
            operation_id,
            harness,
            strategy,
            1 if supported else 0,
            thread_id,
            now,
            now,
        ),
    )


def get_request_resume(connection: sqlite3.Connection, request_id: str) -> dict[str, object] | None:
    row = connection.execute(
        """
        select request_id, operation_id, harness, resolution_action, strategy, supported, status, thread_id, reason,
               message, last_error, attempt_count, created_at, updated_at, last_attempt_at, sent_at
        from guard_request_resumes
        where request_id = ?
        """,
        (request_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_payload(row)


def get_latest_request_resume(
    connection: sqlite3.Connection,
    *,
    harness: str | None = None,
) -> dict[str, object] | None:
    params: list[object] = []
    query = """
        select request_id, operation_id, harness, resolution_action, strategy, supported, status, thread_id, reason,
               message, last_error, attempt_count, created_at, updated_at, last_attempt_at, sent_at
        from guard_request_resumes
    """
    if harness is not None:
        query += " where harness = ?"
        params.append(harness)
    query += " order by coalesce(last_attempt_at, updated_at) desc, request_id desc limit 1"
    row = connection.execute(query, tuple(params)).fetchone()
    if row is None:
        return None
    return _row_to_payload(row)


def update_request_resume(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    resolution_action: str | None,
    strategy: str | None,
    supported: bool | None,
    status: str,
    reason: str | None,
    message: str | None,
    last_error: str | None,
    attempt_count: int,
    last_attempt_at: str | None,
    sent_at: str | None,
    now: str,
) -> None:
    connection.execute(
        """
        update guard_request_resumes
        set resolution_action = ?,
            strategy = coalesce(?, strategy),
            supported = coalesce(?, supported),
            status = ?,
            reason = ?,
            message = ?,
            last_error = ?,
            attempt_count = ?,
            updated_at = ?,
            last_attempt_at = ?,
            sent_at = ?
        where request_id = ?
        """,
        (
            resolution_action,
            strategy,
            None if supported is None else (1 if supported else 0),
            status,
            reason,
            message,
            last_error,
            attempt_count,
            now,
            last_attempt_at,
            sent_at,
            request_id,
        ),
    )


def delete_request_resumes(connection: sqlite3.Connection, request_ids: list[str]) -> None:
    if not request_ids:
        return
    placeholders = ", ".join("?" for _ in request_ids)
    connection.execute(
        f"delete from guard_request_resumes where request_id in ({placeholders})",
        tuple(request_ids),
    )


def _row_to_payload(row: sqlite3.Row) -> dict[str, object]:
    return {
        "request_id": str(row["request_id"]),
        "operation_id": str(row["operation_id"]) if row["operation_id"] is not None else None,
        "harness": str(row["harness"]),
        "resolution_action": str(row["resolution_action"]) if row["resolution_action"] is not None else None,
        "strategy": str(row["strategy"]),
        "supported": bool(row["supported"]),
        "status": str(row["status"]),
        "thread_id": str(row["thread_id"]) if row["thread_id"] is not None else None,
        "reason": str(row["reason"]) if row["reason"] is not None else None,
        "message": str(row["message"]) if row["message"] is not None else None,
        "last_error": str(row["last_error"]) if row["last_error"] is not None else None,
        "attempt_count": int(row["attempt_count"]),
        "created_at": str(row["created_at"]),
        "updated_at": str(row["updated_at"]),
        "last_attempt_at": str(row["last_attempt_at"]) if row["last_attempt_at"] is not None else None,
        "sent_at": str(row["sent_at"]) if row["sent_at"] is not None else None,
    }
