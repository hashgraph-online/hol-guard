//! The local-CLI step of the store opener: a mirror of
//! `ensure_local_cli_schema`.
//!
//! A fresh store gets the current marker and every table. An older marker
//! walks the forward-only chain one version at a time, each step recording
//! its own marker, so a failure leaves the last finished version behind. A
//! marker this build does not recognize is refused, never rewritten.

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use super::columns::{ensure_columns, table_columns};
use super::local_cli_sql::{
    AUTHORITY_SEED, AUTHORITY_TABLE, CAPABILITY_TABLE, CATALOG_TABLE, COMMAND_TABLES,
    CONTEXT_COLUMNS, GRANT_TABLE, MARKER, MARKER_INSERT, MARKER_UPDATE, MIGRATION_TABLE,
    OBSERVATION_TABLE, PROVIDER_ACTION_TABLE, PROVIDER_AUTHORITY_TABLE, PROVIDER_GRANT_TABLE,
    TOOL_AUTHORITY_TABLE, V12_COLUMNS, V2_COLUMNS, V3_COLUMNS, V4_REBUILD, V5_COLUMNS, V7_COPY,
    V7_RENAME, WORKFLOW_PROPOSAL_TABLE,
};
use crate::guard_store_db::{StoreError, StoreResult};

/// `LOCAL_CLI_SCHEMA_VERSION`.
pub(super) const VERSION: i64 = 14;
const INVALID_MARKER: &str = "invalid local CLI schema marker";

/// The checksum the marker records for `version`.
pub(super) fn checksum(version: i64) -> String {
    let seed = format!("hol-guard.local-cli-allowlist.schema.v{version}");
    hex::encode(Sha256::digest(seed.as_bytes()))
}

/// `ensure_local_cli_schema(connection)`: create or migrate the marker, then
/// create every current table.
pub(super) fn ensure_local_cli(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(MIGRATION_TABLE)?;
    let row = connection
        .query_row(MARKER, [], |row| {
            Ok((row.get::<_, Value>(0)?, row.get::<_, Value>(1)?))
        })
        .optional()?;
    match row {
        None => {
            connection.execute(MARKER_INSERT, (VERSION, checksum(VERSION)))?;
        }
        Some(row) => migrate(connection, marker(row)?)?,
    }
    connection.execute_batch(OBSERVATION_TABLE)?;
    connection.execute_batch(GRANT_TABLE)?;
    connection.execute_batch(AUTHORITY_TABLE)?;
    connection.execute_batch(AUTHORITY_SEED)?;
    command_tables(connection)?;
    catalog_tables(connection)?;
    provider_tables(connection)?;
    connection.execute_batch(CAPABILITY_TABLE)?;
    context_columns(connection)
}

/// `_marker`: an integer version and a text checksum, nothing else.
fn marker((version, checksum): (Value, Value)) -> StoreResult<(i64, String)> {
    match (version, checksum) {
        (Value::Integer(version), Value::Text(checksum)) => Ok((version, checksum)),
        _ => Err(StoreError::Value(INVALID_MARKER.to_owned())),
    }
}

/// Walk the chain from `(version, checksum)` to the current marker.
fn migrate(connection: &Connection, (mut version, sum): (i64, String)) -> StoreResult<()> {
    let known = sum == checksum(version);
    while known && (1..VERSION).contains(&version) {
        // Each step and its marker commit together: a step that fails after
        // a rename rolls back to the previous version's tables and marker.
        let next = version + 1;
        super::tables::in_savepoint(connection, "local_cli_migration_step", || {
            step(connection, version)?;
            connection.execute(MARKER_UPDATE, (next, checksum(next)))?;
            Ok(())
        })?;
        version = next;
    }
    if known && version == VERSION {
        return Ok(());
    }
    if version > VERSION {
        return Err(StoreError::Value(format!(
            "local CLI state schema v{version} is newer than this Guard build \
             understands (v{VERSION}); update Guard and retry"
        )));
    }
    Err(StoreError::Value(format!(
        "local CLI state schema marker does not match this Guard build \
         (supports v{VERSION}); the store may be damaged or come from an unsupported build"
    )))
}

/// The one migration from `version` to the next.
fn step(connection: &Connection, version: i64) -> StoreResult<()> {
    match version {
        1 => {
            ensure_columns(connection, "local_cli_observation", &V2_COLUMNS)?;
            command_tables(connection)
        }
        2 => Ok(ensure_columns(
            connection,
            "local_cli_observation",
            &V3_COLUMNS,
        )?),
        3 => run_all(connection, &V4_REBUILD),
        4 => Ok(ensure_columns(
            connection,
            "local_cli_observation",
            &V5_COLUMNS,
        )?),
        5 => catalog_tables(connection),
        6 => {
            command_tables(connection)?;
            connection.execute_batch(V7_RENAME)?;
            command_tables(connection)?;
            run_all(connection, &V7_COPY)
        }
        7 => provider_tables(connection),
        8 => Ok(connection.execute_batch(PROVIDER_GRANT_TABLE)?),
        9 => {
            connection.execute_batch(PROVIDER_AUTHORITY_TABLE)?;
            super::local_cli_rebuild::provider_authorities(connection)
        }
        10 => {
            connection.execute_batch(TOOL_AUTHORITY_TABLE)?;
            connection.execute_batch(WORKFLOW_PROPOSAL_TABLE)?;
            super::local_cli_rebuild::tool_authorities(connection)
        }
        11 => Ok(ensure_columns(
            connection,
            "local_cli_observation",
            &V12_COLUMNS,
        )?),
        12 => Ok(connection.execute_batch(CAPABILITY_TABLE)?),
        13 => {
            // Setup context columns start null; the regroup is best effort
            // and never blocks the schema bump.
            context_columns(connection)?;
            let _moved = super::local_cli_regroup::regroup(connection);
            Ok(())
        }
        _ => Err(StoreError::Value(INVALID_MARKER.to_owned())),
    }
}

fn run_all(connection: &Connection, statements: &[&str]) -> StoreResult<()> {
    for statement in statements {
        connection.execute_batch(statement)?;
    }
    Ok(())
}

/// `_ensure_command_tables`.
fn command_tables(connection: &Connection) -> StoreResult<()> {
    run_all(connection, &COMMAND_TABLES)
}

/// `_ensure_mcp_catalog_table`: the tool authority and workflow proposal
/// tables come first.
fn catalog_tables(connection: &Connection) -> StoreResult<()> {
    run_all(
        connection,
        &[TOOL_AUTHORITY_TABLE, WORKFLOW_PROPOSAL_TABLE, CATALOG_TABLE],
    )
}

/// `_ensure_mcp_provider_catalog_table`: the grant and authority tables come
/// first.
fn provider_tables(connection: &Connection) -> StoreResult<()> {
    run_all(
        connection,
        &[
            PROVIDER_GRANT_TABLE,
            PROVIDER_AUTHORITY_TABLE,
            PROVIDER_ACTION_TABLE,
        ],
    )
}

/// `ensure_local_cli_context_columns`: nothing to add to a store with no
/// observation table.
fn context_columns(connection: &Connection) -> StoreResult<()> {
    if table_columns(connection, "local_cli_observation")?.is_empty() {
        return Ok(());
    }
    Ok(ensure_columns(
        connection,
        "local_cli_observation",
        &CONTEXT_COLUMNS,
    )?)
}
