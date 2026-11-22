//! Small whole-store reads behind the command-activity API: the persisted
//! health counters, the number of recorded activities and the table names.

use rusqlite::Connection;
use serde_json::{json, Value};

use super::as_text;
use crate::guard_store_args::Args;
use crate::guard_store_db::{int, query_all, query_one, StoreError, StoreResult};

pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "get_command_activity_persistence_health" | "count_command_activities" | "list_table_names"
    )
}

pub(crate) fn dispatch(connection: &Connection, method: &str, args: &Args) -> StoreResult<Value> {
    match method {
        "get_command_activity_persistence_health" => persistence_health(connection, args),
        "count_command_activities" => activity_count(connection),
        _ => table_names(connection, args),
    }
}

/// `count_command_activities()`: how many activity rows the store holds.
fn activity_count(connection: &Connection) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select count(*) as total from command_activity",
        &[],
    )?;
    Ok(json!(row.map_or(0, |row| int(&row, "total"))))
}

/// `get_command_activity_persistence_health()`: the persisted counters, the
/// active error flags summed, and the last error, as the daemon's health
/// details report them.
fn persistence_health(connection: &Connection, _args: &Args) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select * from command_activity_health where singleton = 1",
        &[],
    )?;
    let active = query_one(
        connection,
        "select * from command_activity_health_active where singleton = 1",
        &[],
    )?;
    let (Some(row), Some(active)) = (row, active) else {
        return Err(StoreError::Invalid(
            "command_activity_persistence_health_unavailable",
        ));
    };
    let active_error_count: i64 = [
        "command_error_active",
        "shadow_error_active",
        "maintenance_error_active",
    ]
    .iter()
    .map(|column| int(&active, column))
    .sum();
    Ok(json!({
        "dropped_event_count": int(&row, "dropped_event_count"),
        "persistence_error_count": int(&row, "persistence_error_count"),
        "active_error_count": active_error_count,
        "last_error_code": as_text(row.get("last_error_code")),
        "last_error_at": as_text(row.get("last_error_at")),
        "schema_version": as_text(row.get("schema_version")),
    }))
}

/// `list_table_names()`: every table in the store, sorted.
fn table_names(connection: &Connection, _args: &Args) -> StoreResult<Value> {
    let rows = query_all(
        connection,
        "select name from sqlite_master where type = 'table'",
        &[],
    )?;
    let mut names: Vec<String> = rows
        .iter()
        .filter_map(|row| row.get("name").and_then(Value::as_str).map(str::to_owned))
        .collect();
    names.sort_unstable();
    Ok(json!(names))
}

#[cfg(test)]
#[path = "guard_store_cmd_store_reads_tests.rs"]
mod tests;
