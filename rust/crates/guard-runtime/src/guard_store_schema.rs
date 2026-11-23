//! The Guard store's schema, created by the native runtime.
//!
//! The Python store still creates and migrates the schema when it opens.
//! This module is the native copy of that chain, which a later change makes
//! the only one. It starts with the base statements: the tables, indexes and
//! triggers that exist before any migration runs. The upgrade steps then add
//! the columns and indexes older stores lack. Every step is idempotent, so
//! running it on an existing store changes nothing.

use rusqlite::Connection;

use crate::guard_store_db::StoreResult;

#[path = "guard_store_schema_base_a.rs"]
mod base_a;
#[path = "guard_store_schema_base_b.rs"]
mod base_b;
#[path = "guard_store_schema_columns.rs"]
mod columns;
#[path = "guard_store_schema_families.rs"]
mod families;
#[path = "guard_store_schema_indexes.rs"]
mod indexes;
#[path = "guard_store_schema_objects.rs"]
mod objects;
#[path = "guard_store_schema_versions.rs"]
mod versions;

/// The base statements, in the order the Python store runs them.
pub(crate) fn base_statements() -> impl Iterator<Item = &'static str> {
    base_a::FIRST.iter().chain(base_b::SECOND.iter()).copied()
}

/// Run every base statement on `connection`, in order, inside one savepoint:
/// a failure rolls every statement back, so no partial schema is left.
pub(crate) fn create_base(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch("savepoint guard_store_base")?;
    let outcome = base_statements()
        .try_for_each(|statement| connection.execute_batch(statement))
        // A failed outermost release (a busy reader, say) leaves the
        // transaction open, so it is undone like any other failure.
        .and_then(|()| connection.execute_batch("release guard_store_base"));
    outcome.inspect_err(|_| {
        // The original error is the one to report; a failed rollback
        // leaves nothing better to return.
        let _ = connection.execute_batch("rollback to guard_store_base; release guard_store_base");
    })
}

/// Add the policy columns older stores lack, then the policy lookup indexes
/// that read them.
pub(crate) fn upgrade_policy_decisions(connection: &Connection) -> rusqlite::Result<()> {
    columns::ensure_columns(connection, "policy_decisions", &columns::POLICY_COLUMNS)?;
    for statement in columns::POLICY_INDEXES {
        connection.execute_batch(statement)?;
    }
    columns::ensure_columns(
        connection,
        "guard_local_once_approvals",
        &columns::LOCAL_ONCE_COLUMNS,
    )?;
    connection.execute_batch(columns::LOCAL_ONCE_INDEX)
}

/// Add the receipt columns older stores lack.
pub(crate) fn upgrade_runtime_receipts(connection: &Connection) -> rusqlite::Result<()> {
    columns::ensure_columns(connection, "runtime_receipts", &columns::RECEIPT_COLUMNS)
}

/// Add the approval-queue columns older stores lack.
pub(crate) fn upgrade_approval_requests(connection: &Connection) -> rusqlite::Result<()> {
    columns::ensure_columns(connection, "approval_requests", &columns::APPROVAL_COLUMNS)
}

/// Add the client-attachment lease columns older stores lack.
pub(crate) fn upgrade_client_attachments(connection: &Connection) -> rusqlite::Result<()> {
    columns::ensure_columns(
        connection,
        "guard_client_attachments",
        &columns::ATTACHMENT_COLUMNS,
    )
}

fn run_all(connection: &Connection, statements: &[&str]) -> rusqlite::Result<()> {
    for statement in statements {
        connection.execute_batch(statement)?;
    }
    Ok(())
}

/// Create the supply-chain and threat-intel cache indexes.
pub(crate) fn create_cache_indexes(connection: &Connection) -> rusqlite::Result<()> {
    run_all(connection, &indexes::SUPPLY_CHAIN_INDEXES)?;
    run_all(connection, &indexes::THREAT_INTEL_INDEXES)
}

/// Create the approval-queue indexes. They read columns the approval upgrade
/// adds, so they run after it. A store from before version 9 first drops the
/// index that version replaced.
pub(crate) fn create_approval_indexes(connection: &Connection) -> rusqlite::Result<()> {
    if !versions::applied(connection, 9)? {
        connection.execute_batch(versions::DROP_RETIRED_APPROVAL_GROUP_INDEX)?;
    }
    run_all(connection, &indexes::APPROVAL_INDEXES)
}

/// Record `version` unless it is already recorded.
pub(crate) fn record_version(
    connection: &Connection,
    version: i64,
    now: &str,
) -> rusqlite::Result<()> {
    if versions::applied(connection, version)? {
        return Ok(());
    }
    versions::record(connection, version, now)
}

/// Create the receipt envelope table and, once, move legacy inline envelopes
/// into it (version 5).
pub(crate) fn upgrade_receipt_envelopes(
    connection: &Connection,
    now: &str,
) -> rusqlite::Result<()> {
    connection.execute_batch(versions::RECEIPT_ENVELOPES_TABLE)?;
    if versions::applied(connection, 5)? {
        return Ok(());
    }
    versions::migrate_v5_receipt_envelopes(connection)?;
    versions::record(connection, 5, now)
}

/// Once per listed version, ask the resident to rebuild the receipt rollups
/// (version 6 introduced them; version 16 changed how `warn` is bucketed).
pub(crate) fn request_rollup_rebuilds(connection: &Connection, now: &str) -> rusqlite::Result<()> {
    for version in [6, 16] {
        if versions::applied(connection, version)? {
            continue;
        }
        versions::request_rollup_rebuild(connection, now)?;
        versions::record(connection, version, now)?;
    }
    Ok(())
}

/// Insert the local device row unless it is already there.
pub(crate) fn ensure_local_device(
    connection: &Connection,
    installation_id: &str,
    now: &str,
) -> rusqlite::Result<()> {
    versions::ensure_local_device(connection, installation_id, now)
}

/// Reopen approvals the legacy wait timeout expired.
pub(crate) fn reopen_expired_approvals(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(versions::REOPEN_EXPIRED_APPROVALS)
}

/// Create the receipt indexes, then the receipt rollup tables and their
/// indexes.
pub(crate) fn create_receipt_rollups(connection: &Connection) -> rusqlite::Result<()> {
    run_all(connection, &indexes::RECEIPT_INDEXES)?;
    run_all(connection, &indexes::RECEIPT_ROLLUP_TABLES)?;
    run_all(connection, &indexes::RECEIPT_ROLLUP_INDEXES)
}

/// Create the storage-maintenance table and its single row.
pub(crate) fn create_storage_maintenance(connection: &Connection) -> rusqlite::Result<()> {
    run_all(connection, &indexes::STORAGE_MAINTENANCE)
}

/// Run the schema families the base statements do not cover, in the order
/// the Python store runs them.
pub(crate) fn ensure_families(connection: &Connection, now: &str) -> StoreResult<()> {
    families::ensure_receipt_binding(connection, now)?;
    families::ensure_resume(connection)?;
    families::ensure_bash_operations(connection, now)?;
    families::ensure_workflow_capabilities(connection, now)
}

#[cfg(test)]
#[path = "guard_store_schema_families_tests.rs"]
mod families_tests;

#[cfg(test)]
#[path = "guard_store_schema_versions_tests.rs"]
mod versions_tests;

#[cfg(test)]
#[path = "guard_store_schema_indexes_tests.rs"]
mod indexes_tests;

#[cfg(test)]
#[path = "guard_store_schema_columns_tests.rs"]
mod columns_tests;

#[cfg(test)]
#[path = "guard_store_schema_tests.rs"]
mod tests;
