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

/// The base statements, in the order the Python store runs them.
pub(crate) fn base_statements() -> impl Iterator<Item = &'static str> {
    base_a::FIRST.iter().chain(base_b::SECOND.iter()).copied()
}

/// Run every base statement on `connection`, in order.
pub(crate) fn create_base(connection: &Connection) -> rusqlite::Result<()> {
    for statement in base_statements() {
        connection.execute_batch(statement)?;
    }
    Ok(())
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

#[cfg(test)]
#[path = "guard_store_schema_columns_tests.rs"]
mod columns_tests;

#[cfg(test)]
#[path = "guard_store_schema_tests.rs"]
mod tests;
