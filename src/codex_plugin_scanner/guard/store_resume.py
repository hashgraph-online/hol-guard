"""Request-level resume state helpers for Codex browser approval flows."""

from __future__ import annotations

import sqlite3

from .store_schema_columns import ensure_columns


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


# Continuation columns ``guard_request_resumes`` gained after it first shipped,
# in the order the store adds them. The native runtime keeps its own copy
# (``guard_store_schema_families.rs``), and a parity test holds the two equal.
RESUME_CONTINUATION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("continuation_contract_version", "text"),
    ("continuation_capability", "text"),
    ("continuation_status", "text"),
    ("continuation_reason", "text"),
    ("continuation_evidence_json", "text not null default '[]'"),
    ("continuation_offer_hash", "text"),
    ("continuation_action", "text"),
    ("continuation_completed_at", "text"),
    ("continuation_cancelled_at", "text"),
)

CONTINUATION_CLAIMS_TABLE = """
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

CONTINUATION_CLAIM_COLUMNS: tuple[tuple[str, str], ...] = (
    ("lease_expires_at", "text"),
    ("claim_id", "text"),
)

CONTINUATION_EFFECTS_TABLE = """
        create table if not exists guard_continuation_effects (
          effect_key text primary key,
          request_id text not null,
          evidence_id text not null,
          event_name text not null,
          created_at text not null
        )
        """


def ensure_resume_schema(connection: sqlite3.Connection) -> None:
    """Backfill continuation columns for existing Guard installations."""

    ensure_columns(connection, "guard_request_resumes", RESUME_CONTINUATION_COLUMNS)
    connection.execute(CONTINUATION_CLAIMS_TABLE)
    ensure_columns(connection, "guard_continuation_claims", CONTINUATION_CLAIM_COLUMNS)
    connection.execute(CONTINUATION_EFFECTS_TABLE)
