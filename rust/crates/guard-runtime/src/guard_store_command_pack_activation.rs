//! The command-pack activation slot, read for Python to authenticate.
//!
//! Port of the slot read `catalog_delivery.activation_store._row` and its
//! callers ran on their own SQLite connection. Nothing is authenticated here:
//! the record, its digest and its MAC go back as stored, and Python verifies
//! them with the key it holds. The answer names one state:
//!
//! - `absent`: no extension-control schema yet, or one older than the pack
//!   schema, so there is no slot to read;
//! - `schema_invalid`: the schema marker is missing or names no known schema;
//! - `missing`: the pack schema is in place but the slot is empty or holds a
//!   row whose sizes cannot be a record;
//! - `present`: the slot row, under `row`.
//!
//! `extension_control_schema_state` answers the marker check the authority
//! reader runs before it reads: `missing` when the schema tables or the
//! marker row are absent (the caller creates them), `compatible` when the
//! marker names a known schema with its checksum, `incompatible` otherwise.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::extension_control_authority_op::{compatible_marker, FIRST_PACK_SCHEMA_VERSION};
use crate::guard_store_args::Args;
use crate::guard_store_db::{query_one, StoreResult};
use crate::guard_store_local_cli_inventory::table_exists;

const SLOT_FIELDS: [&str; 5] = [
    "revision",
    "record_json",
    "record_digest",
    "record_mac",
    "recorded_at",
];

#[path = "guard_store_command_pack_legacy_evidence.rs"]
mod command_pack_legacy_evidence;
#[path = "guard_store_command_pack_pending.rs"]
mod command_pack_pending;
#[path = "guard_store_extension_control_head.rs"]
mod extension_control_head;
#[path = "guard_store_extension_control_snapshot.rs"]
mod extension_control_snapshot;

pub(crate) fn handles(method: &str) -> bool {
    extension_control_snapshot::handles(method)
        || command_pack_pending::handles(method)
        || command_pack_legacy_evidence::handles(method)
        || extension_control_head::handles(method)
        || matches!(
            method,
            "read_command_pack_activation" | "extension_control_schema_state"
        )
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        _ if extension_control_head::handles(method) => {
            extension_control_head::dispatch(connection, method, args)
        }
        _ if command_pack_legacy_evidence::handles(method) => {
            command_pack_legacy_evidence::dispatch(connection, method, args)
        }
        _ if extension_control_snapshot::handles(method) => {
            extension_control_snapshot::dispatch(connection)
        }
        _ if command_pack_pending::handles(method) => command_pack_pending::dispatch(connection),
        "extension_control_schema_state" => schema_state(connection),
        _ => read(connection),
    }
}

/// `require_compatible_extension_control_schema(require_compatible=False)`
/// without the write: whether the authority schema is there to read.
fn schema_state(connection: &Connection) -> StoreResult<Value> {
    for table in [
        "extension_control_schema_migration",
        "extension_control_authority_snapshot",
    ] {
        if !table_exists(connection, table)? {
            return Ok(state("missing"));
        }
    }
    let marker = query_one(
        connection,
        "select version, checksum from extension_control_schema_migration where singleton = 1",
        &[],
    )?;
    Ok(match marker {
        None => state("missing"),
        Some(marker) if compatible_version(&marker).is_some() => state("compatible"),
        Some(_) => state("incompatible"),
    })
}

fn read(connection: &Connection) -> StoreResult<Value> {
    if !table_exists(connection, "extension_control_schema_migration")? {
        return Ok(state("absent"));
    }
    let marker = query_one(
        connection,
        "select version, checksum from extension_control_schema_migration where singleton = 1",
        &[],
    )?;
    let Some(version) = marker.as_ref().and_then(compatible_version) else {
        return Ok(refused("native_command_pack_schema_invalid"));
    };
    if version < FIRST_PACK_SCHEMA_VERSION {
        return Ok(state("absent"));
    }
    let slot = query_one(
        connection,
        "select revision, record_json, record_digest, record_mac, recorded_at \
         from extension_command_pack_activation where singleton = 1 \
           and length(cast(record_json as blob)) between 1 and 65536 \
           and length(record_digest) = 64 and length(record_mac) = 64",
        &[],
    )?;
    let Some(slot) = slot else {
        return Ok(refused("native_command_pack_activation_missing"));
    };
    let row: Map<String, Value> = SLOT_FIELDS
        .iter()
        .map(|name| {
            (
                (*name).to_owned(),
                slot.get(*name).cloned().unwrap_or(Value::Null),
            )
        })
        .collect();
    Ok(json!({"state": "present", "row": row}))
}

fn state(name: &str) -> Value {
    json!({"state": name})
}

/// A slot the callers must refuse, named by the error code they raise.
fn refused(code: &str) -> Value {
    json!({"state": "refused", "code": code})
}

/// The marker's version when it carries an integer version and the checksum
/// of that version's schema, the same test the authority writer applies.
fn compatible_version(marker: &crate::guard_store_db::Row) -> Option<i64> {
    let version = marker.get("version").and_then(Value::as_i64)?;
    let checksum = marker.get("checksum").and_then(Value::as_str)?;
    compatible_marker(version, checksum).then_some(version)
}

#[cfg(test)]
#[path = "guard_store_command_pack_activation_tests.rs"]
mod tests;
