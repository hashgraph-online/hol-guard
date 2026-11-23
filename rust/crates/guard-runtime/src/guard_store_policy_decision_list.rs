//! `list_policy_decision_rows`: the rows `GuardStore.list_policy_decisions`
//! shows, newest first. `read_policy_decision_row`: the one row
//! `GuardStore.get_policy_decision` shows, by its id.
//! `list_local_policy_rows`: every locally owned row with its integrity
//! columns, newest first, for the integrity scan, repair and migration.
//!
//! A temporary approval-gate grant (an `approval-gate` row with an expiry) is
//! never listed; it is a one-off allow, not a saved decision. The Python owner
//! still verifies each local row's integrity and shapes the listing.

use guard_policy_snapshot::policy_integrity::REMOTE_POLICY_SOURCES;
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_all, query_one, StoreResult};

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

/// The saved decision `decision_id`, or `null` when no such row exists or it
/// is a temporary approval-gate grant, which is never shown as a decision.
pub(super) fn read_policy_decision_row(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let decision_id = args.int("decision_id")?;
    let sql = format!("{SELECT} and decision_id = ?");
    let params = [json!(APPROVAL_GATE_POLICY_SOURCE), json!(decision_id)];
    let row = query_one(connection, &sql, &params)?;
    Ok(json!({ "row": row }))
}

const LOCAL_SELECT: &str = "select decision_id, harness, scope, artifact_id, artifact_hash, \
     workspace, publisher, action, reason, owner, source, expires_at, updated_at, \
     integrity_version, integrity_generation, payload_hash, payload_mac, integrity_key_id, \
     signed_at from policy_decisions";

/// Every row this home owns (no remote-source row), optionally for one
/// harness, newest first. Unlike the listing it keeps a temporary
/// approval-gate grant: that row is signed like any other local row, so the
/// integrity scan must verify it.
pub(super) fn list_local_policy_rows(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let harness = args.opt_str("harness")?;
    let placeholders = vec!["?"; REMOTE_POLICY_SOURCES.len()].join(", ");
    let mut sql = format!("{LOCAL_SELECT} where source not in ({placeholders})");
    let mut params: Vec<Value> = REMOTE_POLICY_SOURCES
        .iter()
        .map(|source| json!(source))
        .collect();
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
