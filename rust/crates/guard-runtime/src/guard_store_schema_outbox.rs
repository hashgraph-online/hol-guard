//! The Review outbox step of the store opener: a mirror of
//! `ensure_review_event_outbox_schema` in `store_review_event_outbox_schema.py`
//! and `ensure_review_event_outbox_upgrade` in
//! `store_review_event_outbox_upgrade.py`, followed by the version 9 record
//! `store_connection_schema.py` writes once the outbox exists.
//!
//! The retired `guard_live_request_outbox` migration runs between the upgrade
//! and the review triggers in Python; its native copy lands separately.

use rusqlite::Connection;
use serde_json::Value;

use super::outbox_insert_sql::INSERT_TRIGGER;
use super::outbox_sql::OUTBOX_STATEMENTS;
use super::outbox_update_sql::UPDATE_TRIGGER;
use crate::guard_store_db::{exec, query_all, StoreResult};
use crate::guard_store_outbox_identity::payload_digest;

/// `REVIEW_EVENT_OUTBOX_MIGRATION_VERSION`.
pub(super) const OUTBOX_VERSION: i64 = 25;
/// The version `store_connection_schema.py` records after the outbox step.
pub(super) const APPROVAL_INDEX_VERSION: i64 = 9;

/// The delivery binding columns the upgrade adds to the request sequences,
/// in its order.
pub(super) const SEQUENCE_BINDING_COLUMNS: [(&str, &str); 5] = [
    ("oauth_source", "text"),
    ("oauth_subject_hash", "text"),
    ("workspace_id", "text"),
    ("machine_id", "text"),
    ("machine_installation_id", "text"),
];

/// The triggers the step drops before it recreates the review triggers.
pub(super) const DROPPED_TRIGGERS: [&str; 4] = [
    "drop trigger if exists guard_live_request_outbox_after_insert",
    "drop trigger if exists guard_live_request_outbox_after_update",
    "drop trigger if exists guard_review_outbox_after_insert",
    "drop trigger if exists guard_review_outbox_after_update",
];

const EVENTS: &str = "select stream_sequence, payload_json, oauth_source, oauth_subject_hash, \
     workspace_id, machine_id, machine_installation_id from guard_review_outbox_events";
const SET_HASH: &str =
    "update guard_review_outbox_events set payload_hash = ? where stream_sequence = ?";

/// Create the outbox, upgrade its stored state, recreate the review triggers
/// and record versions 25 and 9, in one savepoint so a failure keeps none.
pub(super) fn ensure_review_outbox(connection: &Connection, now: &str) -> StoreResult<()> {
    super::tables::in_savepoint(connection, "review_outbox_schema", || {
        super::columns::ensure_columns(
            connection,
            "approval_requests",
            &[("oauth_source", "text")],
        )?;
        for statement in OUTBOX_STATEMENTS {
            connection.execute_batch(statement)?;
        }
        upgrade(connection)?;
        for statement in DROPPED_TRIGGERS {
            connection.execute_batch(statement)?;
        }
        connection.execute_batch(INSERT_TRIGGER)?;
        connection.execute_batch(UPDATE_TRIGGER)?;
        super::record_version(connection, OUTBOX_VERSION, now)?;
        super::record_version(connection, APPROVAL_INDEX_VERSION, now)?;
        Ok(())
    })
}

/// Add the binding columns, then, until version 25 is recorded, rewrite
/// every event's payload hash under its own delivery binding.
fn upgrade(connection: &Connection) -> StoreResult<()> {
    super::columns::ensure_columns(
        connection,
        "guard_review_outbox_request_sequences",
        &SEQUENCE_BINDING_COLUMNS,
    )?;
    if super::versions::applied(connection, OUTBOX_VERSION)? {
        return Ok(());
    }
    for event in query_all(connection, EVENTS, &[])? {
        let field = |name: &str| event.get(name).cloned().unwrap_or(Value::Null);
        let payload = match field("payload_json") {
            Value::String(text) => text,
            other => other.to_string(),
        };
        let binding = [
            field("oauth_source"),
            field("oauth_subject_hash"),
            field("workspace_id"),
            field("machine_id"),
            field("machine_installation_id"),
        ];
        let digest = payload_digest(
            &payload,
            [
                &binding[0],
                &binding[1],
                &binding[2],
                &binding[3],
                &binding[4],
            ],
        );
        exec(
            connection,
            SET_HASH,
            &[Value::from(digest), field("stream_sequence")],
        )?;
    }
    Ok(())
}
