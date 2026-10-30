//! The local device row: the installation id and label that name this machine
//! to Guard Cloud, and the connected workspace.
//!
//! The schema creates the row, so reads stay lock-free; the writes recreate it
//! first when it is missing, as `_ensure_local_device` did.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_one, text, StoreResult};
use crate::guard_store_receipt_writes::{ensure_local_device, local_workspace_id, DEVICE_KEY};

fn metadata(connection: &Connection) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select installation_id, device_label from guard_devices where device_key = ?",
        &[Value::from(DEVICE_KEY)],
    )?;
    Ok(row.map_or(Value::Null, |row| {
        json!({
            "installation_id": text(&row, "installation_id"),
            "device_label": text(&row, "device_label"),
        })
    }))
}

/// `get_device_metadata`, or null when the row is missing.
pub(crate) fn get(connection: &Connection, _args: &Args<'_>) -> StoreResult<Value> {
    metadata(connection)
}

fn ensured(connection: &Connection, args: &Args<'_>) -> StoreResult<()> {
    ensure_local_device(
        connection,
        args.str("new_device_id")?,
        args.str("created_at")?,
    )
}

/// Recreate a missing device row and read it.
pub(crate) fn ensure(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    ensured(connection, args)?;
    metadata(connection)
}

/// `set_device_label`: the caller sends the label already normalized.
pub(crate) fn set_label(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    ensured(connection, args)?;
    exec(
        connection,
        "update guard_devices set device_label = ?, updated_at = ? where device_key = ?",
        &[
            Value::from(args.str("label")?),
            Value::from(args.str("now")?),
            Value::from(DEVICE_KEY),
        ],
    )?;
    metadata(connection)
}

/// `rotate_installation_id`.
pub(crate) fn rotate(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    ensured(connection, args)?;
    exec(
        connection,
        "update guard_devices set installation_id = ?, updated_at = ? where device_key = ?",
        &[
            Value::from(args.str("installation_id")?),
            Value::from(args.str("now")?),
            Value::from(DEVICE_KEY),
        ],
    )?;
    metadata(connection)
}

/// `get_cloud_workspace_id`: the workspace the stored OAuth pairing names.
pub(crate) fn cloud_workspace_id(connection: &Connection, _args: &Args<'_>) -> StoreResult<Value> {
    Ok(local_workspace_id(connection)?.map_or(Value::Null, Value::from))
}

#[cfg(test)]
#[path = "guard_store_devices_tests.rs"]
mod tests;
