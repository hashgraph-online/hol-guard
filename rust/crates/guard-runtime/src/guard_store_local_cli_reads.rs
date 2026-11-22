//! The single-value local CLI store reads, and the capability-cause note.
//!
//! Port of `read_local_cli_revision`, `read_local_cli_surface`,
//! `has_local_cli_block_rules`, `read_local_cli_capabilities` and
//! `note_local_cli_capability_cause`, which `store_local_cli.py` ran on its
//! own SQLite connection. A store that has not created a local CLI table yet
//! reads as empty: revision `0`, no surface, no block rules and every
//! capability off.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_one, value_error, StoreError, StoreResult};
use crate::guard_store_local_cli_inventory::{authority_revision, table_exists};
use crate::guard_store_local_cli_inventory_capabilities::{
    capabilities, capability_map, CAPABILITY_BY_CAUSE,
};

/// Whether `method` is one of these reads or the cause note.
pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "read_local_cli_revision"
            | "read_local_cli_surface"
            | "has_local_cli_block_rules"
            | "read_local_cli_capabilities"
            | "note_local_cli_capability_cause"
    )
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "read_local_cli_revision" => Ok(Value::from(authority_revision(connection)?)),
        "read_local_cli_surface" => read_surface(connection, args.str("cli_id")?),
        "has_local_cli_block_rules" => Ok(Value::from(has_block_rules(connection)?)),
        "read_local_cli_capabilities" => {
            let cli_id = args.str("cli_id")?;
            Ok(capability_map(capabilities(connection)?.get(cli_id)))
        }
        "note_local_cli_capability_cause" => note_cause(
            connection,
            args.str("cli_id")?,
            args.str("identity_hash")?,
            args.str("cause")?,
        ),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

/// The observed surface of `cli_id`, or `null` when it was never observed or
/// the stored surface is not text.
fn read_surface(connection: &Connection, cli_id: &str) -> StoreResult<Value> {
    if !table_exists(connection, "local_cli_observation")? {
        return Ok(Value::Null);
    }
    let row = query_one(
        connection,
        "select surface from local_cli_observation where cli_id = ?",
        &[Value::from(cli_id)],
    )?;
    Ok(row
        .and_then(|row| row.get("surface").and_then(Value::as_str).map(Value::from))
        .unwrap_or(Value::Null))
}

/// `local_cli_rules_exist(blocks_only=True)`: a blocked device grant or a
/// blocked command.
fn has_block_rules(connection: &Connection) -> StoreResult<bool> {
    for (table, sql) in [
        (
            "local_cli_grant",
            "select 1 as present from local_cli_grant where state = 'blocked' limit 1",
        ),
        (
            "local_cli_command_grant",
            "select 1 as present from local_cli_command_grant where state = 'block' limit 1",
        ),
    ] {
        if table_exists(connection, table)? && query_one(connection, sql, &[])?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `note_capability_cause`: keep that an allowed CLI's contained run was
/// denied what `cause` names. The newest denial wins; nothing here turns a
/// capability on. Returns how many rows changed.
fn note_cause(
    connection: &Connection,
    cli_id: &str,
    identity_hash: &str,
    cause: &str,
) -> StoreResult<Value> {
    if !CAPABILITY_BY_CAUSE.iter().any(|(known, _)| *known == cause) {
        return value_error("invalid_first_blocked_cause");
    }
    let changed = exec(
        connection,
        "update local_cli_observation set first_blocked_cause = ? \
         where cli_id = ? and identity_hash = ? and surface = 'cli' \
           and first_blocked_cause is not ?",
        &[
            Value::from(cause),
            Value::from(cli_id),
            Value::from(identity_hash),
            Value::from(cause),
        ],
    )?;
    Ok(Value::from(changed))
}

#[cfg(test)]
#[path = "guard_store_local_cli_reads_tests.rs"]
mod tests;
