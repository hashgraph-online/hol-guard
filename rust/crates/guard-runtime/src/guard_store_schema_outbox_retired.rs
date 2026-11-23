//! The retired outbox step of the Review outbox schema: a mirror of
//! `_migrate_retired_outbox` in `store_review_event_outbox_schema.py`.
//!
//! A store that still has the retired `guard_live_request_outbox` table gets
//! one `review.request.snapshot_migrated` event per retired row, built from
//! the current request row, and the retired table is dropped. Every store is
//! then marked so the step never runs again.

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::guard_store_db::{exec, query_all, query_one, Row, StoreError, StoreResult};
use crate::guard_store_json::{dumps_sorted, py_strip};
use crate::guard_store_outbox_append::{payload_json, uuid4_hex};
use crate::guard_store_outbox_decode::{EVENT_SCHEMA_NAME, EVENT_SCHEMA_VERSION, SNAPSHOT_COLUMNS};
use crate::guard_store_outbox_identity::payload_digest;

/// `_RETIRED_OUTBOX_MIGRATION_STATE_KEY`.
pub(super) const MIGRATED_KEY: &str = "guard_review_outbox_events_migrated";
const MIGRATED_EVENT: &str = "review.request.snapshot_migrated";
const UNREPRESENTABLE: StoreError = StoreError::Invalid("native_guard_store_value_unrepresentable");
const BINDING: [&str; 5] = [
    "oauth_source",
    "oauth_subject_hash",
    "workspace_id",
    "machine_id",
    "machine_installation_id",
];

const MARKER: &str = "select 1 from sync_state where state_key = ?";
const RETIRED_TABLE: &str =
    "select 1 from sqlite_master where type = 'table' and name = 'guard_live_request_outbox'";
const RETIRED_ROWS: &str = "select sequence, local_request_id, changed_at, oauth_source, \
     oauth_subject_hash, workspace_id, machine_id, machine_installation_id, \
     attempt_count, next_attempt_at, last_error \
     from guard_live_request_outbox order by sequence";
const INSERT_EVENT: &str = "insert or ignore into guard_review_outbox_events (\
     event_id, local_request_id, request_sequence, event_type, \
     event_schema_version, payload_json, payload_hash, occurred_at, \
     oauth_source, oauth_subject_hash, workspace_id, machine_id, \
     machine_installation_id, binding_status, quarantine_reason, \
     attempt_count, next_attempt_at, last_error\
     ) values (?, ?, ?, 'review.request.snapshot_migrated', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
const UPSERT_SEQUENCE: &str = "insert into guard_review_outbox_request_sequences (\
     local_request_id, last_sequence, updated_at, oauth_source, \
     oauth_subject_hash, workspace_id, machine_id, machine_installation_id\
     ) values (?, ?, ?, ?, ?, ?, ?, ?) \
     on conflict(local_request_id) do update set \
     last_sequence = max(last_sequence, excluded.last_sequence), updated_at = excluded.updated_at";
const MARK: &str =
    "insert into sync_state (state_key, payload_json, updated_at) values (?, '{\"migrated\":true}', ?)";

/// Python's `str(value)` for a cell.
fn py_str(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::String(text) => text.clone(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        other => other.to_string(),
    }
}

fn cell(row: &Row, name: &str) -> Value {
    row.get(name).cloned().unwrap_or(Value::Null)
}

/// Move every retired outbox row into the Review outbox once.
pub(super) fn migrate_retired_outbox(connection: &Connection, now: &str) -> StoreResult<()> {
    if query_one(connection, MARKER, &[Value::from(MIGRATED_KEY)])?.is_some() {
        return Ok(());
    }
    if query_one(connection, RETIRED_TABLE, &[])?.is_some() {
        for row in query_all(connection, RETIRED_ROWS, &[])? {
            migrate_row(connection, &row)?;
        }
        connection.execute_batch("drop table guard_live_request_outbox")?;
    }
    exec(
        connection,
        MARK,
        &[Value::from(MIGRATED_KEY), Value::from(now)],
    )?;
    Ok(())
}

fn migrate_row(connection: &Connection, row: &Row) -> StoreResult<()> {
    let (payload, source_quarantine) = retired_payload(connection, row)?;
    let identity = BINDING.map(|name| cell(row, name));
    let complete = identity.iter().all(|value| {
        value
            .as_str()
            .is_some_and(|text| !py_strip(text).is_empty())
    });
    let quarantine = source_quarantine.or((!complete).then_some("retired_identity_incomplete"));
    let digest = payload_digest(
        &payload,
        [
            &identity[0],
            &identity[1],
            &identity[2],
            &identity[3],
            &identity[4],
        ],
    );
    let status = if quarantine.is_none() {
        "ready"
    } else {
        "quarantined"
    };
    let mut params = vec![
        Value::from(uuid4_hex()?),
        cell(row, "local_request_id"),
        cell(row, "sequence"),
        Value::from(EVENT_SCHEMA_VERSION),
        Value::from(payload),
        Value::from(digest),
        cell(row, "changed_at"),
    ];
    params.extend(identity.iter().cloned());
    params.extend([
        Value::from(status),
        quarantine.map_or(Value::Null, Value::from),
        cell(row, "attempt_count"),
        cell(row, "next_attempt_at"),
        cell(row, "last_error"),
    ]);
    exec(connection, INSERT_EVENT, &params)?;
    let mut sequence = vec![
        cell(row, "local_request_id"),
        cell(row, "sequence"),
        cell(row, "changed_at"),
    ];
    sequence.extend(identity);
    exec(connection, UPSERT_SEQUENCE, &sequence)?;
    Ok(())
}

/// `_retired_outbox_payload`: the snapshot payload and any quarantine reason.
fn retired_payload(
    connection: &Connection,
    row: &Row,
) -> StoreResult<(String, Option<&'static str>)> {
    let request = query_one(
        connection,
        "select * from approval_requests where request_id = ?",
        &[cell(row, "local_request_id")],
    )?;
    let Some(request) = request else {
        return Ok((
            marker_payload(row)?,
            Some("retired_request_snapshot_missing"),
        ));
    };
    if SNAPSHOT_COLUMNS
        .iter()
        .any(|name| !request.contains_key(*name))
    {
        return Ok((
            marker_payload(row)?,
            Some("retired_request_snapshot_incomplete"),
        ));
    }
    let payload = payload_json(
        &request,
        MIGRATED_EVENT,
        &py_str(&cell(row, "changed_at")),
        false,
    )?;
    if cell(&request, "oauth_source") != cell(row, "oauth_source") {
        return Ok((payload, Some("retired_request_source_ambiguous")));
    }
    Ok((payload, None))
}

/// `_retired_outbox_marker_payload`.
fn marker_payload(row: &Row) -> StoreResult<String> {
    let sequence = cell(row, "sequence").as_i64().ok_or(UNREPRESENTABLE)?;
    let mut payload = Map::new();
    payload.insert("schema".into(), Value::from(EVENT_SCHEMA_NAME));
    payload.insert(
        "localRequestId".into(),
        Value::from(py_str(&cell(row, "local_request_id"))),
    );
    payload.insert("eventType".into(), Value::from(MIGRATED_EVENT));
    payload.insert(
        "occurredAt".into(),
        Value::from(py_str(&cell(row, "changed_at"))),
    );
    payload.insert("retiredSequence".into(), Value::from(sequence));
    dumps_sorted(&Value::Object(payload)).ok_or(UNREPRESENTABLE)
}
