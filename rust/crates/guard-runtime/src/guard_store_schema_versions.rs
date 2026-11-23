//! Versioned schema steps the store runs when it opens.
//!
//! A mirror of `store_schema_versions.py` (and of the rollup rebuild request in
//! `store_receipt_rollup_schema.py`). A parity test on the Python side holds
//! each statement equal. Callers pass the clock and the new installation id,
//! so every step is deterministic under test.

use rusqlite::{params, Connection, OptionalExtension};

pub(super) const RECORD_SCHEMA_VERSION: &str = r##"insert or ignore into schema_migrations (version, applied_at)
values (?, ?)"##;

pub(super) const SCHEMA_VERSION_APPLIED: &str =
    r##"select 1 from schema_migrations where version = ?"##;

pub(super) const RECEIPT_ENVELOPES_TABLE: &str = r##"create table if not exists runtime_receipt_envelopes (
  receipt_id text primary key references runtime_receipts(receipt_id) on delete cascade,
  envelope_full_json text,
  envelope_redacted_json text not null
)"##;

pub(super) const V5_RECEIPT_ENVELOPE_STEPS: [&str; 6] = [
    r##"insert into runtime_receipt_envelopes (receipt_id, envelope_full_json, envelope_redacted_json)
select receipt_id, action_envelope_json, '{}'
from runtime_receipts
where action_envelope_json is not null
  and not exists (
    select 1 from runtime_receipt_envelopes
    where runtime_receipt_envelopes.receipt_id = runtime_receipts.receipt_id
  )"##,
    r##"drop table if exists runtime_receipts_new"##,
    r##"create table runtime_receipts_new (
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
)"##,
    r##"insert into runtime_receipts_new (
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
from runtime_receipts"##,
    r##"drop table runtime_receipts"##,
    r##"alter table runtime_receipts_new rename to runtime_receipts"##,
];

pub(super) const DROP_RETIRED_APPROVAL_GROUP_INDEX: &str =
    r##"drop index if exists idx_approval_group_status"##;

pub(super) const LOCAL_DEVICE_KEY: &str = "local-device";

pub(super) const LOCAL_DEVICE_LABEL: &str = "Local machine";

pub(super) const LOCAL_DEVICE_SELECT: &str =
    r##"select device_key from guard_devices where device_key = ?"##;

pub(super) const LOCAL_DEVICE_INSERT: &str = r##"insert into guard_devices (device_key, installation_id, device_label, created_at, updated_at)
values (?, ?, ?, ?, ?)"##;

pub(super) const REOPEN_EXPIRED_APPROVALS: &str = r##"update approval_requests
set status = 'pending', reason = null, resolved_at = null
where status = 'expired' and reason = 'Expired after waiting for review.'"##;

pub(super) const ROLLUP_REBUILD_PENDING_KEY: &str = "receipt_rollups_rebuild_pending";

pub(super) const REQUEST_ROLLUP_REBUILD: &str = r##"insert into sync_state (state_key, payload_json, updated_at) values (?, '{}', ?)
on conflict(state_key) do update set updated_at = excluded.updated_at"##;

pub(super) fn record(
    connection: &Connection,
    version: i64,
    applied_at: &str,
) -> rusqlite::Result<()> {
    connection.execute(RECORD_SCHEMA_VERSION, params![version, applied_at])?;
    Ok(())
}

pub(super) fn applied(connection: &Connection, version: i64) -> rusqlite::Result<bool> {
    let row = connection
        .query_row(SCHEMA_VERSION_APPLIED, params![version], |_| Ok(()))
        .optional()?;
    Ok(row.is_some())
}

/// Move legacy inline receipt envelopes into their own table. A store whose
/// receipts never carried an inline envelope is left as it is.
pub(super) fn migrate_v5_receipt_envelopes(connection: &Connection) -> rusqlite::Result<()> {
    if !super::columns::table_columns(connection, "runtime_receipts")?
        .contains("action_envelope_json")
    {
        return Ok(());
    }
    for statement in V5_RECEIPT_ENVELOPE_STEPS {
        connection.execute_batch(statement)?;
    }
    Ok(())
}

/// Ask the resident to rebuild every receipt rollup before its next read.
pub(super) fn request_rollup_rebuild(
    connection: &Connection,
    requested_at: &str,
) -> rusqlite::Result<()> {
    connection.execute(
        REQUEST_ROLLUP_REBUILD,
        params![ROLLUP_REBUILD_PENDING_KEY, requested_at],
    )?;
    Ok(())
}

/// Insert the local device row unless it is already there.
pub(super) fn ensure_local_device(
    connection: &Connection,
    installation_id: &str,
    now: &str,
) -> rusqlite::Result<()> {
    let existing = connection
        .query_row(LOCAL_DEVICE_SELECT, params![LOCAL_DEVICE_KEY], |_| Ok(()))
        .optional()?;
    if existing.is_some() {
        return Ok(());
    }
    connection.execute(
        LOCAL_DEVICE_INSERT,
        params![
            LOCAL_DEVICE_KEY,
            installation_id,
            LOCAL_DEVICE_LABEL,
            now,
            now
        ],
    )?;
    Ok(())
}
