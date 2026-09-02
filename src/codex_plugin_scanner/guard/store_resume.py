"""Request-level resume state helpers for Codex browser approval flows."""

from __future__ import annotations

import json
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
          sent_at text,
          continuation_contract_version text,
          continuation_capability text,
          continuation_status text,
          continuation_reason text,
          continuation_evidence_json text not null default '[]',
          continuation_offer_hash text,
          continuation_action text,
          continuation_completed_at text,
          continuation_cancelled_at text
        )
        """


def ensure_resume_schema(connection: sqlite3.Connection) -> None:
    """Backfill continuation columns for existing Guard installations."""

    columns = {str(row["name"]) for row in connection.execute("pragma table_info(guard_request_resumes)").fetchall()}
    additions = {
        "continuation_contract_version": "text",
        "continuation_capability": "text",
        "continuation_status": "text",
        "continuation_reason": "text",
        "continuation_evidence_json": "text not null default '[]'",
        "continuation_offer_hash": "text",
        "continuation_action": "text",
        "continuation_completed_at": "text",
        "continuation_cancelled_at": "text",
    }
    for name, definition in additions.items():
        if name not in columns:
            connection.execute(f"alter table guard_request_resumes add column {name} {definition}")
    connection.execute(
        """
        create table if not exists guard_continuation_claims (
          request_id text not null,
          offer_hash text not null,
          action text not null,
          state text not null,
          claimed_at text not null,
          lease_expires_at text,
          claim_id text,
          evidence_id text,
          primary key (request_id, offer_hash, action)
        )
        """
    )
    claim_columns = {
        str(row["name"]) for row in connection.execute("pragma table_info(guard_continuation_claims)").fetchall()
    }
    for name in ("lease_expires_at", "claim_id"):
        if name not in claim_columns:
            connection.execute(f"alter table guard_continuation_claims add column {name} text")
    connection.execute(
        """
        create table if not exists guard_continuation_effects (
          effect_key text primary key,
          request_id text not null,
          evidence_id text not null,
          event_name text not null,
          created_at text not null
        )
        """
    )


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
               message, last_error, attempt_count, created_at, updated_at, last_attempt_at, sent_at,
               continuation_contract_version, continuation_capability, continuation_status, continuation_reason,
               continuation_evidence_json, continuation_offer_hash, continuation_action, continuation_completed_at,
               continuation_cancelled_at
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
               message, last_error, attempt_count, created_at, updated_at, last_attempt_at, sent_at,
               continuation_contract_version, continuation_capability, continuation_status, continuation_reason,
               continuation_evidence_json, continuation_offer_hash, continuation_action, continuation_completed_at,
               continuation_cancelled_at
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
    continuation_contract_version: str | None = None,
    continuation_capability: str | None = None,
    continuation_status: str | None = None,
    continuation_reason: str | None = None,
    continuation_evidence: list[dict[str, object]] | None = None,
    continuation_offer_hash: str | None = None,
    continuation_action: str | None = None,
    continuation_completed_at: str | None = None,
    continuation_cancelled_at: str | None = None,
) -> None:
    evidence_json = (
        json.dumps(continuation_evidence, separators=(",", ":")) if continuation_evidence is not None else None
    )
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
            sent_at = ?,
            continuation_contract_version = coalesce(?, continuation_contract_version),
            continuation_capability = coalesce(?, continuation_capability),
            continuation_status = coalesce(?, continuation_status),
            continuation_reason = coalesce(?, continuation_reason),
            continuation_evidence_json = coalesce(?, continuation_evidence_json),
            continuation_offer_hash = coalesce(?, continuation_offer_hash),
            continuation_action = coalesce(?, continuation_action),
            continuation_completed_at = coalesce(?, continuation_completed_at),
            continuation_cancelled_at = coalesce(?, continuation_cancelled_at)
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
            continuation_contract_version,
            continuation_capability,
            continuation_status,
            continuation_reason,
            evidence_json,
            continuation_offer_hash,
            continuation_action,
            continuation_completed_at,
            continuation_cancelled_at,
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
    evidence = _evidence_from_row(row)
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
        "continuation_contract_version": _optional_row_string(row, "continuation_contract_version"),
        "continuation_capability": _optional_row_string(row, "continuation_capability"),
        "continuation_status": _optional_row_string(row, "continuation_status"),
        "continuation_reason": _optional_row_string(row, "continuation_reason"),
        "continuation_evidence": evidence,
        "continuation_offer_hash": _optional_row_string(row, "continuation_offer_hash"),
        "continuation_action": _optional_row_string(row, "continuation_action"),
        "continuation_completed_at": _optional_row_string(row, "continuation_completed_at"),
        "continuation_cancelled_at": _optional_row_string(row, "continuation_cancelled_at"),
    }


def _evidence_from_row(row: sqlite3.Row) -> list[dict[str, object]]:
    encoded = _optional_row_string(row, "continuation_evidence_json")
    if encoded is None:
        return []
    try:
        value = json.loads(encoded)
    except json.JSONDecodeError:
        return []
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _optional_row_string(row: sqlite3.Row, name: str) -> str | None:
    try:
        value = row[name]
    except (IndexError, KeyError):
        return None
    return str(value) if value is not None else None
