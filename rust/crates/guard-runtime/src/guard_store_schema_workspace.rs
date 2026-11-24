//! The workspace assessment and fix proposal steps of the store opener: a
//! mirror of `ensure_workspace_assessment_schema` and
//! `ensure_workspace_fix_proposal_schema`.
//!
//! Each step creates its objects, checks every one against its declared SQL
//! and records its version, all inside its own savepoint, so a refused store
//! keeps none of the step's changes.

use rusqlite::Connection;

use super::workspace_sql::{
    ASSESSMENT_STATEMENTS, ASSESSMENT_VERSION, FIX_PROPOSAL_STATEMENTS, FIX_PROPOSAL_VERSION,
};
use crate::guard_store_db::StoreResult;

const RECORD: &str =
    "insert or ignore into schema_migrations (version, applied_at) values (?1, ?2)";

/// `ensure_workspace_assessment_schema`: the assessment tables may declare
/// unique indexes (one running and one queued run per worktree).
pub(super) fn ensure_assessment(connection: &Connection, now: &str) -> StoreResult<()> {
    super::tables::in_savepoint(connection, "workspace_assessment_schema_v1", || {
        family(
            connection,
            &ASSESSMENT_STATEMENTS,
            "workspace assessment ",
            true,
            (ASSESSMENT_VERSION, now),
        )
    })
}

/// `ensure_workspace_fix_proposal_schema`.
pub(super) fn ensure_fix_proposal(connection: &Connection, now: &str) -> StoreResult<()> {
    super::tables::in_savepoint(connection, "workspace_fix_proposal_schema_v1", || {
        family(
            connection,
            &FIX_PROPOSAL_STATEMENTS,
            "workspace fix proposal ",
            false,
            (FIX_PROPOSAL_VERSION, now),
        )
    })
}

fn family(
    connection: &Connection,
    statements: &[&str],
    label: &str,
    allow_unique: bool,
    record: (i64, &str),
) -> StoreResult<()> {
    for statement in statements {
        connection.execute_batch(statement)?;
    }
    super::objects::validate(connection, statements, label, allow_unique)?;
    connection.execute(RECORD, record)?;
    Ok(())
}

#[cfg(test)]
#[path = "guard_store_schema_workspace_tests.rs"]
mod tests;
