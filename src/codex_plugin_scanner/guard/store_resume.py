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


def delete_request_resumes(connection: sqlite3.Connection, request_ids: list[str]) -> None:
    if not request_ids:
        return
    placeholders = ", ".join("?" for _ in request_ids)
    connection.execute(
        f"delete from guard_request_resumes where request_id in ({placeholders})",
        tuple(request_ids),
    )
