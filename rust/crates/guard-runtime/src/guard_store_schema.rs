//! The Guard store's schema, created by the native runtime.
//!
//! The Python store still creates and migrates the schema when it opens.
//! This module is the native copy of that chain, which a later change makes
//! the only one. It starts with the base statements: the tables, indexes and
//! triggers that exist before any migration runs. Every statement is
//! idempotent, so running them on an existing store changes nothing.

use rusqlite::Connection;

#[path = "guard_store_schema_base_a.rs"]
mod base_a;
#[path = "guard_store_schema_base_b.rs"]
mod base_b;

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

#[cfg(test)]
#[path = "guard_store_schema_tests.rs"]
mod tests;
