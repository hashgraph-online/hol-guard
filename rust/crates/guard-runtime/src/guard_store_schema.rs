//! The Guard store's schema, created by the native runtime.
//!
//! The Python store still creates and migrates the schema when it opens.
//! This module is the native copy of that chain, which a later change makes
//! the only one. It starts with the base statements: the tables, indexes and
//! triggers that exist before any migration runs. The upgrade steps then add
//! the columns and indexes older stores lack. Every step is idempotent, so
//! running it on an existing store changes nothing.

use rusqlite::Connection;

#[path = "guard_store_schema_base_a.rs"]
mod base_a;
#[path = "guard_store_schema_base_b.rs"]
mod base_b;
#[path = "guard_store_schema_columns.rs"]
mod columns;
#[path = "guard_store_schema_indexes.rs"]
mod indexes;

/// The base statements, in the order the Python store runs them.
pub(crate) fn base_statements() -> impl Iterator<Item = &'static str> {
    base_a::FIRST.iter().chain(base_b::SECOND.iter()).copied()
}

/// Run every base statement on `connection`, in order, inside one savepoint:
/// a failure rolls every statement back, so no partial schema is left.
pub(crate) fn create_base(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch("savepoint guard_store_base")?;
    let outcome = base_statements().try_for_each(|statement| connection.execute_batch(statement));
    match outcome {
        Ok(()) => connection.execute_batch("release guard_store_base"),
        Err(error) => {
            // The original error is the one to report; a failed rollback
            // leaves nothing better to return.
            let _ =
                connection.execute_batch("rollback to guard_store_base; release guard_store_base");
            Err(error)
        }
    }
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
/// adds, so they run after it.
pub(crate) fn create_approval_indexes(connection: &Connection) -> rusqlite::Result<()> {
    run_all(connection, &indexes::APPROVAL_INDEXES)
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

#[cfg(test)]
#[path = "guard_store_schema_indexes_tests.rs"]
mod indexes_tests;

#[cfg(test)]
#[path = "guard_store_schema_columns_tests.rs"]
mod columns_tests;

#[cfg(test)]
#[path = "guard_store_schema_tests.rs"]
mod tests;
