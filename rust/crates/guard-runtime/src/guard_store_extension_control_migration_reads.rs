//! What a catalog migration needs to know before the resident commits it.
//!
//! Port of the SQL reads the authority migration and the first pack
//! activation ran on their own SQLite connection:
//!
//! - `extension_control_migration_recorded` answers whether a catalog
//!   migration event already names `revision`.
//! - `extension_control_catalog_writer_version` answers the Guard version
//!   that wrote the catalog `catalog_digest` names, read from the newest
//!   migration events that carry writer provenance, or `null`.
//! - `command_pack_baseline_retained` answers whether the store already holds
//!   the activation slot a pack schema keeps, so the first activation need
//!   not send the legacy baseline again. A store without the schema tables
//!   answers `{"state": "schema_missing"}`, as the SQL read failed there.
//!
//! An event payload that is not a JSON object is skipped, as before.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_each, query_one, StoreResult};
use crate::guard_store_local_cli_inventory::table_exists;

const RECORDED: &str = "extension_control_migration_recorded";
const WRITER: &str = "extension_control_catalog_writer_version";
const BASELINE: &str = "command_pack_baseline_retained";
const MIGRATED_EVENT: &str = "extension_control_authority_catalog_migrated";
const EVENTS_TABLE: &str = "guard_events";
const MARKER_TABLE: &str = "extension_control_schema_migration";
const SLOT_TABLE: &str = "extension_command_pack_activation";
/// A store keeps one migration event per revision, so the writer lookup
/// reads only the newest events.
const WRITER_LOOKUP_LIMIT: i64 = 512;

pub(crate) fn handles(method: &str) -> bool {
    matches!(method, RECORDED | WRITER | BASELINE)
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        RECORDED => recorded(connection, args.int("revision")?),
        WRITER => writer_version(connection, args.str("catalog_digest")?),
        _ => baseline_retained(connection),
    }
}

/// Visits each migration event payload that decodes to a JSON object,
/// newest first, until `visit` returns false.
fn each_payload(
    connection: &Connection,
    limit: Option<i64>,
    mut visit: impl FnMut(&Map<String, Value>) -> bool,
) -> StoreResult<()> {
    if !table_exists(connection, EVENTS_TABLE)? {
        return Ok(());
    }
    let sql = format!(
        "select case when typeof(payload_json) = 'text' then payload_json end as payload_json \
         from {EVENTS_TABLE} where event_name = ?1 order by event_id desc{}",
        if limit.is_some() { " limit ?2" } else { "" }
    );
    let mut params = vec![Value::from(MIGRATED_EVENT)];
    params.extend(limit.map(Value::from));
    query_each(connection, &sql, &params, |row| {
        let decoded = row
            .get("payload_json")
            .and_then(Value::as_str)
            .and_then(|raw| serde_json::from_str::<Value>(raw).ok());
        Ok(match decoded {
            Some(Value::Object(payload)) => visit(&payload),
            _ => true,
        })
    })
}

fn names_revision(value: Option<&Value>, revision: i64) -> bool {
    match value {
        Some(Value::Number(number)) => {
            number.as_i64() == Some(revision)
                || (!number.is_i64()
                    && !number.is_u64()
                    && number.as_f64() == Some(revision as f64))
        }
        _ => false,
    }
}

fn recorded(connection: &Connection, revision: i64) -> StoreResult<Value> {
    let mut found = false;
    each_payload(connection, None, |payload| {
        found = names_revision(payload.get("revision"), revision);
        !found
    })?;
    Ok(json!({"recorded": found}))
}

fn writer_version(connection: &Connection, catalog_digest: &str) -> StoreResult<Value> {
    let mut version = Value::Null;
    each_payload(connection, Some(WRITER_LOOKUP_LIMIT), |payload| {
        if payload.get("catalog_digest").and_then(Value::as_str) != Some(catalog_digest) {
            return true;
        }
        let writer = payload
            .get("provenance")
            .and_then(Value::as_object)
            .and_then(|provenance| provenance.get("writer_version"))
            .and_then(Value::as_str)
            .filter(|writer| !writer.is_empty());
        match writer {
            Some(writer) => {
                version = Value::from(writer);
                false
            }
            None => true,
        }
    })?;
    Ok(json!({"writer_version": version}))
}

fn baseline_retained(connection: &Connection) -> StoreResult<Value> {
    if !table_exists(connection, MARKER_TABLE)? {
        return Ok(json!({"state": "schema_missing"}));
    }
    let pack_schema = query_one(
        connection,
        &format!(
            "select 1 as found from {MARKER_TABLE} where singleton = 1 \
             and typeof(version) in ('integer', 'real') and version in (5, 6)"
        ),
        &[],
    )?
    .is_some();
    if !pack_schema {
        return Ok(json!({"state": "present", "retained": false}));
    }
    if !table_exists(connection, SLOT_TABLE)? {
        return Ok(json!({"state": "schema_missing"}));
    }
    let slot = query_one(
        connection,
        &format!("select 1 as found from {SLOT_TABLE} where singleton = 1"),
        &[],
    )?;
    Ok(json!({"state": "present", "retained": slot.is_some()}))
}

#[cfg(test)]
#[path = "guard_store_extension_control_migration_reads_tests.rs"]
mod tests;
