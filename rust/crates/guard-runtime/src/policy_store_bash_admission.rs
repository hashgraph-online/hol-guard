//! A quiet launch cannot sidestep saved authority by omitting a grant.

use guard_contracts::{PolicyDecisionLookupRequestV1, POLICY_DECISION_LOOKUP_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::json;

pub(super) fn require_no_saved_decision(
    connection: &Connection,
    artifact_hash: &str,
    harness: &str,
    project: &str,
) -> rusqlite::Result<()> {
    // Missing approval schema is an integrity failure, not absence of a deny.
    let tables: i64 = connection.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN
         ('policy_decisions','guard_local_once_approvals')",
        [],
        |row| row.get(0),
    )?;
    if tables != 2 || connection.is_autocommit() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let now: String = connection.query_row(
        "SELECT strftime('%Y-%m-%dT%H:%M:%f+00:00','now')",
        [],
        |row| row.get(0),
    )?;
    let request: PolicyDecisionLookupRequestV1 = serde_json::from_value(json!({
        "schema": POLICY_DECISION_LOOKUP_REQUEST_SCHEMA,
        "request_id": "native-bash-final-admission", "store_path": "", "guard_home": "",
        "harness": harness, "artifact_id": guard_contracts::NATIVE_BASH_ARTIFACT_ID,
        "artifact_hash": artifact_hash, "workspace": project, "now": now,
        "consume_one_shot": false,
    }))
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    // Reuse the authoritative selector and integrity-failure rules. This path
    // intentionally carries no keys and can never admit a saved allow: those
    // require the separate authenticated claim. A block, changed/malformed
    // local authority or concurrent new grant requires a fresh store lookup.
    let result = crate::policy_decision_lookup_op::evaluate_non_consuming(&request, connection)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    if result
        .get("decision")
        .is_some_and(serde_json::Value::is_null)
        && result
            .get("ignored_local_integrity")
            .is_some_and(serde_json::Value::is_null)
        && result
            .get("authority_revision")
            .and_then(serde_json::Value::as_i64)
            .is_some_and(|revision| revision >= 0)
    {
        Ok(())
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

#[cfg(test)]
#[path = "policy_store_bash_admission_tests.rs"]
mod tests;
