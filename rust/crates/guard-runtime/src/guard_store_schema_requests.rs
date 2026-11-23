//! The policy-request step of the store opener and the steps that follow it
//! up to the approval columns: a mirror of `ensure_mcp_policy_request_schema`
//! in `mcp/policy_store.py`, the version 4 record, the cache indexes, the
//! policy and receipt columns, the version 5 receipt envelopes and the
//! approval columns, in the order `store_connection_schema.py` runs them.

use rusqlite::Connection;

use crate::guard_store_db::StoreResult;

/// `_MCP_POLICY_REQUEST_SCHEMA`, dedented. A parity test on the Python side
/// holds the copies equal.
pub(super) const MCP_POLICY_REQUEST_TABLE: &str = r##"create table if not exists mcp_policy_requests (
    request_id text primary key,
    idempotency_key_hash text not null unique,
    status text not null default 'pending',
    policy_document_id text not null,
    policy_document_digest text not null,
    expected_current_digest text,
    expected_policy_generation integer,
    mode text not null,
    canonical_policy_yaml text not null,
    plan_json text not null,
    created_at text not null,
    expires_at text not null,
    resolved_at text,
    result_json text,
    failure_code text
)"##;

/// `_MCP_POLICY_REQUEST_INDEXES`.
pub(super) const MCP_POLICY_REQUEST_INDEXES: [&str; 3] = [
    "create index if not exists idx_mcp_policy_requests_status on mcp_policy_requests (status)",
    "create index if not exists idx_mcp_policy_requests_expires on mcp_policy_requests (expires_at)",
    "create index if not exists idx_mcp_policy_requests_idempotency on mcp_policy_requests (idempotency_key_hash)",
];

/// Run the policy-request step and every step after it through the approval
/// columns. Each statement is idempotent and each version is recorded once,
/// so a second run changes nothing. A failure keeps none of the run.
pub(super) fn ensure_requests_through_approvals(
    connection: &Connection,
    now: &str,
) -> StoreResult<()> {
    super::tables::in_savepoint(connection, "mcp_policy_request_schema", || {
        connection.execute_batch(MCP_POLICY_REQUEST_TABLE)?;
        for statement in MCP_POLICY_REQUEST_INDEXES {
            connection.execute_batch(statement)?;
        }
        super::record_version(connection, 4, now)?;
        super::create_cache_indexes(connection)?;
        super::upgrade_policy_decisions(connection)?;
        super::upgrade_runtime_receipts(connection)?;
        super::upgrade_receipt_envelopes(connection, now)?;
        super::upgrade_approval_requests(connection)?;
        Ok(())
    })
}
