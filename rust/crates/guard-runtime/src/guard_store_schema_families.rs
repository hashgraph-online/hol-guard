//! Schema families the store adds after the base schema: request resumes,
//! the native receipt command binding, the Bash operation journal and the
//! workflow-capability authority.
//!
//! A mirror of the matching Python `ensure_*_schema` steps. The resume lists
//! mirror `store_resume.py`, and a parity test on the Python side holds the
//! two copies equal. The Bash statements are the same `.sql` files the Python
//! store reads.

use rusqlite::Connection;

use super::columns::ensure_columns;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_wfcap_error::WfError;

pub(super) const RESUME_CONTINUATION_COLUMNS: [(&str, &str); 9] = [
    ("continuation_contract_version", "text"),
    ("continuation_capability", "text"),
    ("continuation_status", "text"),
    ("continuation_reason", "text"),
    ("continuation_evidence_json", "text not null default '[]'"),
    ("continuation_offer_hash", "text"),
    ("continuation_action", "text"),
    ("continuation_completed_at", "text"),
    ("continuation_cancelled_at", "text"),
];

pub(super) const CONTINUATION_CLAIMS_TABLE: &str = r##"create table if not exists guard_continuation_claims (
  request_id text not null,
  offer_hash text not null,
  action text not null,
  state text not null,
  claimed_at text not null,
  lease_expires_at text,
  claim_id text,
  evidence_id text,
  primary key (request_id, offer_hash, action)
)"##;

pub(super) const CONTINUATION_CLAIM_COLUMNS: [(&str, &str); 2] =
    [("lease_expires_at", "text"), ("claim_id", "text")];

pub(super) const CONTINUATION_EFFECTS_TABLE: &str = r##"create table if not exists guard_continuation_effects (
  effect_key text primary key,
  request_id text not null,
  evidence_id text not null,
  event_name text not null,
  created_at text not null
)"##;

/// The receipt column version 28 added, as the base schema declares it.
pub(super) const COMMAND_BINDING_COLUMN: &str = "command_extensions_json text check \
     (command_extensions_json is null or length(command_extensions_json) between 2 and 2048)";
pub(super) const COMMAND_BINDING_VERSION: i64 = 28;

pub(super) const BASH_STATEMENTS: [&str; 3] = [
    include_str!(
        "../../../../src/codex_plugin_scanner/guard/schemas/native_bash_operations_v1.sql"
    ),
    include_str!("../../../../src/codex_plugin_scanner/guard/schemas/native_bash_reviews_v1.sql"),
    include_str!(
        "../../../../src/codex_plugin_scanner/guard/schemas/native_bash_invocations_v1.sql"
    ),
];
pub(super) const BASH_VERSIONS: [i64; 3] = [30, 31, 32];
const BASH_SAVEPOINT: &str = "bash_operation_schema_v1";

const RECORD: &str =
    "insert or ignore into schema_migrations (version, applied_at) values (?1, ?2)";

/// `ensure_resume_schema`: the continuation columns, then the claim and
/// effect tables.
pub(super) fn ensure_resume(connection: &Connection) -> rusqlite::Result<()> {
    ensure_columns(
        connection,
        "guard_request_resumes",
        &RESUME_CONTINUATION_COLUMNS,
    )?;
    connection.execute_batch(CONTINUATION_CLAIMS_TABLE)?;
    ensure_columns(
        connection,
        "guard_continuation_claims",
        &CONTINUATION_CLAIM_COLUMNS,
    )?;
    connection.execute_batch(CONTINUATION_EFFECTS_TABLE)
}

/// `ensure_native_command_receipt_binding_schema`: add the command binding
/// column a legacy receipt table lacks, without inventing a value for old
/// rows, then record version 28.
pub(super) fn ensure_receipt_binding(connection: &Connection, now: &str) -> rusqlite::Result<()> {
    let present = super::columns::table_columns(connection, "native_hook_decision_receipts")?;
    if !present.contains("command_extensions_json") {
        connection.execute_batch(&format!(
            "alter table native_hook_decision_receipts add column {COMMAND_BINDING_COLUMN}"
        ))?;
    }
    connection.execute(RECORD, (COMMAND_BINDING_VERSION, now))?;
    Ok(())
}

/// `ensure_bash_operation_schema`: the three journal tables, checked against
/// their declared SQL, and versions 30 to 32, all inside one savepoint.
pub(super) fn ensure_bash_operations(connection: &Connection, now: &str) -> StoreResult<()> {
    super::tables::in_savepoint(connection, BASH_SAVEPOINT, || {
        bash_operations(connection, now)
    })
}

fn bash_operations(connection: &Connection, now: &str) -> StoreResult<()> {
    for statement in BASH_STATEMENTS {
        connection.execute_batch(statement)?;
    }
    super::objects::validate(connection, &BASH_STATEMENTS, "Bash operation ", false)?;
    for version in BASH_VERSIONS {
        connection.execute(RECORD, (version, now))?;
    }
    Ok(())
}

/// `ensure_workflow_capability_schema`, which the native capability store
/// already runs before each of its own operations.
pub(super) fn ensure_workflow_capabilities(connection: &Connection, now: &str) -> StoreResult<()> {
    crate::guard_store_wfcap_schema::ensure_schema(connection, now).map_err(|error| match error {
        WfError::Store(inner) => inner,
        WfError::Runtime(message) | WfError::Capability(message) => StoreError::Runtime(message),
    })
}
