//! `list_policy_decision_rows`: the rows `GuardStore.list_policy_decisions`
//! shows, newest first.
//!
//! A temporary approval-gate grant (an `approval-gate` row with an expiry) is
//! never listed; it is a one-off allow, not a saved decision. The Python owner
//! still verifies each local row's integrity and shapes the listing.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, StoreResult};

const APPROVAL_GATE_POLICY_SOURCE: &str = "approval-gate";

const SELECT: &str = "select decision_id, harness, scope, artifact_id, artifact_hash, \
     workspace, publisher, action, reason, owner, source, expires_at, updated_at, \
     policy_document_schema_version, policy_document_id, policy_document_digest, \
     policy_rule_id, policy_provenance_json, integrity_version, integrity_generation, \
     payload_hash, payload_mac, integrity_key_id, signed_at from policy_decisions \
     where not (source = ? and expires_at is not null)";

pub(super) fn list_policy_decision_rows(
    connection: &Connection,
    args: &Args,
) -> StoreResult<Value> {
    let harness = args.opt_str("harness")?;
    let mut sql = SELECT.to_owned();
    let mut params = vec![json!(APPROVAL_GATE_POLICY_SOURCE)];
    if let Some(harness) = harness {
        sql.push_str(" and harness = ?");
        params.push(json!(harness));
    }
    sql.push_str(" order by updated_at desc");
    let rows = query_all(connection, &sql, &params)?;
    Ok(json!({ "rows": rows }))
}

#[cfg(test)]
#[path = "guard_store_policy_decision_list_tests.rs"]
mod tests;
