"""Crash-safe validated SQLite schema for dormant workflow capabilities."""

# pyright: reportAny=false, reportUnusedCallResult=false

from __future__ import annotations

import re
import sqlite3
from typing import Final

WORKFLOW_CAPABILITY_MIGRATION_VERSION: Final = 14

_SCHEMA_STATEMENTS: Final = (
    """create table if not exists guard_workflow_capabilities (
      capability_id text primary key,
      approval_provenance_id text not null,
      nonce text not null unique,
      signed_claim_json text not null,
      key_id text not null,
      issued_at text not null,
      not_before text not null,
      expires_at text not null,
      max_uses integer not null check (max_uses between 1 and 50),
      used_count integer not null default 0 check (used_count between 0 and max_uses),
      revoked_at text,
      revocation_code text,
      check ((revoked_at is null and revocation_code is null) or
             (revoked_at is not null and revocation_code is not null))
    ) strict""",
    """create table if not exists guard_workflow_capability_authority_state (
      capability_id text primary key,
      signed_state_json text not null,
      key_id text not null,
      revision integer not null check (revision >= 0),
      use_high_water integer not null check (use_high_water >= 0),
      observed_at text not null,
      revocation_id text
    ) strict""",
    """create table if not exists guard_workflow_capability_revocations (
      revocation_id text primary key,
      capability_id text not null unique,
      signed_revocation_json text not null,
      key_id text not null,
      revoked_at text not null
    ) strict""",
    """create table if not exists guard_workflow_capability_receipts (
      receipt_id text primary key,
      capability_id text not null references guard_workflow_capabilities(capability_id),
      task_id text not null,
      invocation_id text not null unique,
      approval_provenance_id text not null,
      signed_receipt_json text not null,
      claimed_at text not null,
      use_number integer not null check (use_number >= 1),
      event_id integer not null references guard_events(event_id),
      unique (capability_id, use_number)
    ) strict""",
    """create table if not exists guard_workflow_capability_authority_transitions (
      sequence integer primary key,
      capability_id text not null references guard_workflow_capabilities(capability_id),
      revision integer not null check (revision >= 0),
      transition_kind text not null,
      previous_transition_sha256 text not null,
      signed_transition_json text not null,
      key_id text not null,
      event_id integer not null unique references guard_events(event_id),
      unique (capability_id, revision)
    ) strict""",
    """create index if not exists idx_guard_workflow_capability_expiry
    on guard_workflow_capabilities (revoked_at, expires_at, capability_id)""",
    """create index if not exists idx_guard_workflow_receipt_capability
    on guard_workflow_capability_receipts (capability_id, use_number)""",
    """create trigger if not exists trg_guard_workflow_capability_claim_immutable
    before update of capability_id, approval_provenance_id, nonce, signed_claim_json, key_id,
      issued_at, not_before, expires_at, max_uses on guard_workflow_capabilities
    begin select raise(abort, 'workflow_capability_claim_immutable'); end""",
    """create trigger if not exists trg_guard_workflow_capability_no_delete
    before delete on guard_workflow_capabilities
    begin select raise(abort, 'workflow_capability_delete_forbidden'); end""",
    """create trigger if not exists trg_guard_workflow_receipt_immutable_update
    before update on guard_workflow_capability_receipts
    begin select raise(abort, 'workflow_capability_receipt_immutable'); end""",
    """create trigger if not exists trg_guard_workflow_receipt_immutable_delete
    before delete on guard_workflow_capability_receipts
    begin select raise(abort, 'workflow_capability_receipt_delete_forbidden'); end""",
    """create trigger if not exists trg_guard_workflow_receipt_require_parents
    before insert on guard_workflow_capability_receipts
    begin
      select case when not exists (
        select 1 from guard_workflow_capabilities where capability_id = new.capability_id
      ) then raise(abort, 'workflow_capability_parent_missing') end;
      select case when not exists (
        select 1 from guard_events where event_id = new.event_id
      ) then raise(abort, 'workflow_capability_event_missing') end;
    end""",
    """create trigger if not exists trg_guard_workflow_event_preserve_link
    before delete on guard_events when exists (
      select 1 from guard_workflow_capability_receipts where event_id = old.event_id
      union all
      select 1 from guard_workflow_capability_authority_transitions where event_id = old.event_id
    ) begin select raise(abort, 'workflow_capability_event_referenced'); end""",
    """create trigger if not exists trg_guard_workflow_authority_state_no_delete
    before delete on guard_workflow_capability_authority_state
    begin select raise(abort, 'workflow_capability_authority_state_delete_forbidden'); end""",
    """create trigger if not exists trg_guard_workflow_revocation_immutable_update
    before update on guard_workflow_capability_revocations
    begin select raise(abort, 'workflow_capability_revocation_immutable'); end""",
    """create trigger if not exists trg_guard_workflow_revocation_immutable_delete
    before delete on guard_workflow_capability_revocations
    begin select raise(abort, 'workflow_capability_revocation_delete_forbidden'); end""",
    """create trigger if not exists trg_guard_workflow_revocation_require_parent
    before insert on guard_workflow_capability_revocations when not exists (
      select 1 from guard_workflow_capabilities where capability_id = new.capability_id
    ) begin select raise(abort, 'workflow_capability_revocation_parent_missing'); end""",
    """create trigger if not exists trg_guard_workflow_transition_immutable_update
    before update on guard_workflow_capability_authority_transitions
    begin select raise(abort, 'workflow_capability_transition_immutable'); end""",
    """create trigger if not exists trg_guard_workflow_transition_immutable_delete
    before delete on guard_workflow_capability_authority_transitions
    begin select raise(abort, 'workflow_capability_transition_delete_forbidden'); end""",
    """create trigger if not exists trg_guard_workflow_transition_require_parents
    before insert on guard_workflow_capability_authority_transitions
    begin
      select case when not exists (
        select 1 from guard_workflow_capabilities where capability_id = new.capability_id
      ) then raise(abort, 'workflow_capability_transition_parent_missing') end;
      select case when new.event_id is not null and not exists (
        select 1 from guard_events where event_id = new.event_id
      ) then raise(abort, 'workflow_capability_transition_event_missing') end;
    end""",
)
_OBJECT_NAMES: Final = (
    ("table", "guard_workflow_capabilities"),
    ("table", "guard_workflow_capability_authority_state"),
    ("table", "guard_workflow_capability_revocations"),
    ("table", "guard_workflow_capability_receipts"),
    ("table", "guard_workflow_capability_authority_transitions"),
    ("index", "idx_guard_workflow_capability_expiry"),
    ("index", "idx_guard_workflow_receipt_capability"),
    ("trigger", "trg_guard_workflow_capability_claim_immutable"),
    ("trigger", "trg_guard_workflow_capability_no_delete"),
    ("trigger", "trg_guard_workflow_receipt_immutable_update"),
    ("trigger", "trg_guard_workflow_receipt_immutable_delete"),
    ("trigger", "trg_guard_workflow_receipt_require_parents"),
    ("trigger", "trg_guard_workflow_event_preserve_link"),
    ("trigger", "trg_guard_workflow_authority_state_no_delete"),
    ("trigger", "trg_guard_workflow_revocation_immutable_update"),
    ("trigger", "trg_guard_workflow_revocation_immutable_delete"),
    ("trigger", "trg_guard_workflow_revocation_require_parent"),
    ("trigger", "trg_guard_workflow_transition_immutable_update"),
    ("trigger", "trg_guard_workflow_transition_immutable_delete"),
    ("trigger", "trg_guard_workflow_transition_require_parents"),
)


def ensure_workflow_capability_schema(connection: sqlite3.Connection, *, applied_at: str) -> None:
    """Apply migration 14 atomically and validate every owned schema object."""
    connection.execute("savepoint workflow_capability_schema_v14")
    try:
        for statement in _SCHEMA_STATEMENTS:
            connection.execute(statement)
        _validate_schema_objects(connection)
        connection.execute(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            (WORKFLOW_CAPABILITY_MIGRATION_VERSION, applied_at),
        )
        version = connection.execute(
            "select applied_at from schema_migrations where version = ?",
            (WORKFLOW_CAPABILITY_MIGRATION_VERSION,),
        ).fetchone()
        if version is None or not str(version[0]):
            raise RuntimeError("workflow_capability_migration_not_recorded")
    except sqlite3.DatabaseError as error:
        connection.execute("rollback to workflow_capability_schema_v14")
        connection.execute("release workflow_capability_schema_v14")
        raise RuntimeError("invalid_workflow_capability_schema:migration") from error
    except Exception:
        connection.execute("rollback to workflow_capability_schema_v14")
        connection.execute("release workflow_capability_schema_v14")
        raise
    connection.execute("release workflow_capability_schema_v14")


def _validate_schema_objects(connection: sqlite3.Connection) -> None:
    expected = {
        (object_type, name): _normalized_sql(statement)
        for (object_type, name), statement in zip(_OBJECT_NAMES, _SCHEMA_STATEMENTS, strict=True)
    }
    rows = connection.execute(
        """
        select type, name, sql from sqlite_master
        where name like 'guard_workflow_capabilit%'
           or name like 'idx_guard_workflow_%'
           or name like 'trg_guard_workflow_%'
        """
    ).fetchall()
    actual = {
        (str(row[0]), str(row[1])): _normalized_sql(str(row[2]))
        for row in rows
        if row[2] is not None and not str(row[1]).startswith("sqlite_autoindex")
    }
    if set(actual) != set(expected):
        raise RuntimeError("invalid_workflow_capability_schema:owned_objects")
    for identity, expected_sql in expected.items():
        if actual.get(identity) != expected_sql:
            raise RuntimeError(f"invalid_workflow_capability_schema:{identity[0]}:{identity[1]}")


def _normalized_sql(statement: str) -> str:
    normalized = re.sub(r"\s+", " ", statement.strip().lower())
    return normalized.replace(" if not exists", "")
