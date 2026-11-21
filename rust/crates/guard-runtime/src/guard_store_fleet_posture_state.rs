//! `fleet_posture_state`, `set_fleet_posture_reporting`,
//! `request_full_fleet_inventory` and `commit_fleet_posture_sent`: the
//! `sync_state` rows that steer the fleet posture report.
//!
//! Port of the settings, full-inventory request and "last sent" bookkeeping
//! `runtime/fleet_posture.py` kept in Python. Python still collects the
//! posture and the native runner builds the payload; the store reads and
//! writes the rows that decide what the next report carries.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreError, StoreResult};
use crate::guard_store_sync_state::{read_payload, write_encoded};

/// `LAST_SENT_STATE_KEY`.
const LAST_SENT_KEY: &str = "fleet_posture_last";
/// `SETTINGS_STATE_KEY`.
const SETTINGS_KEY: &str = "fleet_posture_settings";
/// `FORCE_FULL_STATE_KEY`.
const FORCE_FULL_KEY: &str = "fleet_posture_force_full";

/// Whether `method` is one of the fleet posture state methods.
pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "fleet_posture_state"
            | "set_fleet_posture_reporting"
            | "request_full_fleet_inventory"
            | "commit_fleet_posture_sent"
            | "fleet_posture_cached_diagnostics"
            | "record_fleet_posture_diagnostics"
            | "fleet_posture_cached_runtimes"
            | "record_fleet_posture_runtimes"
    )
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "fleet_posture_state" => state_method(connection, args),
        "set_fleet_posture_reporting" => set_reporting_method(connection, args),
        "request_full_fleet_inventory" => request_full_method(connection, args),
        "commit_fleet_posture_sent" => commit_sent_method(connection, args),
        "fleet_posture_cached_diagnostics" => diagnostics::cached_method(connection, args),
        "record_fleet_posture_diagnostics" => diagnostics::record_method(connection, args),
        "fleet_posture_cached_runtimes" => runtimes::cached_method(connection, args),
        "record_fleet_posture_runtimes" => runtimes::record_method(connection, args),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

fn object_row(connection: &Connection, key: &str) -> StoreResult<Option<Map<String, Value>>> {
    Ok(match read_payload(connection, key)? {
        Some(Value::Object(row)) => Some(row),
        _ => None,
    })
}

fn write(connection: &Connection, key: &str, payload: &Value, now: &str) -> StoreResult<()> {
    let encoded =
        serde_json::to_string(payload).map_or_else(|_| value_error("invalid_payload"), Ok)?;
    write_encoded(connection, key, &encoded, now)
}

/// `full_inventory_requested`: the request row is a non-empty object.
fn full_inventory_requested(connection: &Connection) -> StoreResult<bool> {
    Ok(object_row(connection, FORCE_FULL_KEY)?.is_some_and(|row| !row.is_empty()))
}

/// `fleet_posture_state`: whether the user opted out of detailed reports,
/// whether a full inventory was requested, and the last accepted snapshot.
///
/// The opt-out holds only for a settings object whose `enabled` is `false`.
/// `last_sent` is the stored object, possibly empty, or `null`.
pub(crate) fn state_method(connection: &Connection, _args: &Args<'_>) -> StoreResult<Value> {
    let opted_out = object_row(connection, SETTINGS_KEY)?
        .is_some_and(|row| row.get("enabled") == Some(&Value::Bool(false)));
    let last_sent = object_row(connection, LAST_SENT_KEY)?.map_or(Value::Null, Value::Object);
    Ok(json!({
        "opted_out": opted_out,
        "full_inventory_requested": full_inventory_requested(connection)?,
        "last_sent": last_sent,
    }))
}

/// `set_fleet_posture_reporting`: store the opt-out choice and return the
/// new settings record.
pub(crate) fn set_reporting_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let enabled = args
        .raw("enabled")
        .and_then(Value::as_bool)
        .map_or_else(|| value_error("invalid_enabled"), Ok)?;
    let now = args.str("now")?;
    let record = json!({"enabled": enabled, "updatedAt": now});
    write(connection, SETTINGS_KEY, &record, now)?;
    Ok(json!({"record": record}))
}

/// `request_full_inventory`: make the next report carry the full inventory.
pub(crate) fn request_full_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let source = args
        .opt_str("source")?
        .filter(|source| !source.is_empty())
        .map_or_else(|| value_error("invalid_source"), Ok)?;
    let now = args.str("now")?;
    write(
        connection,
        FORCE_FULL_KEY,
        &json!({"requestedAt": now, "source": source}),
        now,
    )?;
    Ok(Value::Null)
}

/// `commit_fleet_posture_sent`: record the snapshot Guard Cloud accepted and,
/// when that report advanced the inventory, clear a pending full-inventory
/// request. Both rows change in the same store transaction.
pub(crate) fn commit_sent_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let Some(Value::Object(next_state)) = args.raw("next_state") else {
        return value_error("invalid_next_state");
    };
    let next_state = joined_items(next_state)?;
    let advanced = args.flag("advanced_inventory")?;
    let now = args.str("now")?;
    write(connection, LAST_SENT_KEY, &next_state, now)?;
    let cleared = advanced && full_inventory_requested(connection)?;
    if cleared {
        write(connection, FORCE_FULL_KEY, &json!({}), now)?;
    }
    Ok(json!({"cleared_full_inventory_request": cleared}))
}

/// The snapshot with its tracked `items` joined back into one object. The
/// request parser caps how many keys one object may hold, so Python sends a
/// large item map as a list of smaller objects.
fn joined_items(next_state: &Map<String, Value>) -> StoreResult<Value> {
    let mut state = next_state.clone();
    if let Some(Value::Array(chunks)) = next_state.get("items") {
        let mut items = Map::new();
        for chunk in chunks {
            let Value::Object(chunk) = chunk else {
                return value_error("invalid_next_state");
            };
            items.extend(chunk.clone());
        }
        state.insert("items".to_owned(), Value::Object(items));
    }
    Ok(Value::Object(state))
}

#[path = "guard_store_fleet_posture_diagnostics.rs"]
mod diagnostics;

#[path = "guard_store_fleet_posture_runtimes.rs"]
mod runtimes;

#[cfg(test)]
#[path = "guard_store_fleet_posture_state_tests.rs"]
mod tests;
