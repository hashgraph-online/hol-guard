//! The evidence step and the extension-control step of the store opener:
//! a mirror of `ensure_evidence_schema` and of
//! `ensure_extension_control_authority_schema(require_compatible=False)`.

use rusqlite::Connection;

use super::columns::ensure_columns;
use super::evidence_sql::{EVIDENCE_IDENTITY_COLUMN, EVIDENCE_INDEXES, EVIDENCE_TABLE};
use crate::extension_control_authority_op::ensure_startup_schema;
use crate::extension_control_authority_op::records::Fault;
use crate::guard_store_db::{StoreError, StoreResult};

/// Create the evidence table, add the identity column an older table lacks,
/// and create the evidence indexes. Every statement is idempotent.
pub(super) fn ensure_evidence(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(EVIDENCE_TABLE)?;
    ensure_columns(connection, "guard_evidence", &EVIDENCE_IDENTITY_COLUMN)?;
    for statement in EVIDENCE_INDEXES {
        connection.execute_batch(statement)?;
    }
    Ok(())
}

/// Create the extension-control authority schema at the base version. A
/// marker this build does not recognize is left alone, as the store opener
/// does: the authority's own readers and writers refuse it by name.
pub(super) fn ensure_extension_control(connection: &Connection) -> StoreResult<bool> {
    ensure_startup_schema(connection).map_err(|fault| match fault {
        Fault::Tampered(reason) | Fault::Degraded(reason) | Fault::Pack(reason) => {
            StoreError::Runtime(reason)
        }
    })
}
