"""Versioned schema steps the store runs when it opens.

The statements are module constants so the native runtime's copy
(``guard_store_schema_versions.rs``) can be held to them by a parity test.
"""

from __future__ import annotations

import sqlite3

from .store_base import _DEVICE_ROW_KEY

RECORD_SCHEMA_VERSION = """
insert or ignore into schema_migrations (version, applied_at)
values (?, ?)
"""

SCHEMA_VERSION_APPLIED = "select 1 from schema_migrations where version = ?"

RECEIPT_ENVELOPES_TABLE = """
create table if not exists runtime_receipt_envelopes (
  receipt_id text primary key references runtime_receipts(receipt_id) on delete cascade,
  envelope_full_json text,
  envelope_redacted_json text not null
)
"""

V5_RECEIPT_ENVELOPE_STEPS = (
    """
insert into runtime_receipt_envelopes (receipt_id, envelope_full_json, envelope_redacted_json)
select receipt_id, action_envelope_json, '{}'
from runtime_receipts
where action_envelope_json is not null
  and not exists (
    select 1 from runtime_receipt_envelopes
    where runtime_receipt_envelopes.receipt_id = runtime_receipts.receipt_id
  )
""",
    "drop table if exists runtime_receipts_new",
    """
create table runtime_receipts_new (
  receipt_id text primary key,
  harness text not null,
  artifact_id text not null,
  artifact_hash text not null,
  policy_decision text not null,
  capabilities_summary text not null default '',
  changed_capabilities_json text not null,
  provenance_summary text not null,
  user_override text,
  artifact_name text,
  source_scope text,
  scanner_evidence_json text not null default '[]',
  timestamp text not null,
  diff_summary text,
  approval_source text,
  approval_request_id text,
  raw_command_text text
)
""",
    """
insert into runtime_receipts_new (
  rowid, receipt_id, harness, artifact_id, artifact_hash, policy_decision,
  capabilities_summary, changed_capabilities_json, provenance_summary, user_override,
  artifact_name, source_scope, scanner_evidence_json, timestamp, diff_summary,
  approval_source, approval_request_id, raw_command_text
)
select
  rowid, receipt_id, harness, artifact_id, artifact_hash, policy_decision,
  capabilities_summary, changed_capabilities_json, provenance_summary, user_override,
  artifact_name, source_scope, scanner_evidence_json, timestamp, diff_summary,
  approval_source, null, null
from runtime_receipts
""",
    "drop table runtime_receipts",
    "alter table runtime_receipts_new rename to runtime_receipts",
)

# Version 9 replaced this index; a store that predates it drops the old one
# before the approval indexes are created.
DROP_RETIRED_APPROVAL_GROUP_INDEX = "drop index if exists idx_approval_group_status"

LOCAL_DEVICE_SELECT = "select device_key from guard_devices where device_key = ?"

LOCAL_DEVICE_INSERT = """
insert into guard_devices (device_key, installation_id, device_label, created_at, updated_at)
values (?, ?, ?, ?, ?)
"""

LOCAL_DEVICE_LABEL = "Local machine"

# Preserve the legacy wait-timeout recovery without reopening cards
# deliberately superseded by a fresh, canonically bound request.
# A reopened pending card must not retain a terminal expiry reason.
REOPEN_EXPIRED_APPROVALS = """
update approval_requests
set status = 'pending', reason = null, resolved_at = null
where status = 'expired' and reason = 'Expired after waiting for review.'
"""


def record_schema_version(connection: sqlite3.Connection, *, version: int, applied_at: str) -> None:
    connection.execute(RECORD_SCHEMA_VERSION, (version, applied_at))


def schema_version_applied(connection: sqlite3.Connection, *, version: int) -> bool:
    return connection.execute(SCHEMA_VERSION_APPLIED, (version,)).fetchone() is not None


def migrate_v5_receipt_envelopes(connection: sqlite3.Connection) -> None:
    """Move legacy inline receipt envelopes into their own table."""
    rows = connection.execute("pragma table_info(runtime_receipts)").fetchall()
    if "action_envelope_json" not in {str(row[1]) for row in rows}:
        return
    for statement in V5_RECEIPT_ENVELOPE_STEPS:
        connection.execute(statement)


def ensure_local_device(connection: sqlite3.Connection, *, installation_id: str, now: str) -> None:
    if connection.execute(LOCAL_DEVICE_SELECT, (_DEVICE_ROW_KEY,)).fetchone() is not None:
        return
    connection.execute(
        LOCAL_DEVICE_INSERT,
        (_DEVICE_ROW_KEY, installation_id, LOCAL_DEVICE_LABEL, now, now),
    )
