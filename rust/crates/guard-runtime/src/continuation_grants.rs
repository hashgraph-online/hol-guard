//! Continuation consumes purpose-bound exact or legacy authority in its write transaction.
use crate::guard_store_db::{query_one, StoreResult};
use guard_policy_snapshot::local_authority_integrity::{
    sign_local_authority_payload, verify_local_authority_payload,
};
use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};

const IDENTITY: &[&str] = &[
    "action",
    "approval_id",
    "artifact_hash",
    "artifact_id",
    "expires_at",
    "harness",
    "integrity_key_id",
    "integrity_status",
    "integrity_version",
    "publisher",
    "request_id",
    "source",
    "signed_at",
    "updated_at",
    "workspace",
    "authority_kind",
];

pub(crate) fn consume(
    connection: &Connection,
    request_id: &str,
    decision: &Value,
    now: &str,
    key: &[u8],
    key_id: &str,
) -> StoreResult<bool> {
    if crate::claim_reuse::approval_reuse_claim_disposition(decision) != Some("consumed") {
        return Ok(false);
    }
    spend(
        connection,
        request_id,
        decision,
        now,
        (key, key_id),
        &["legacy", "exact-cloud"],
    )
}

/// Spend the exact Cloud allow issued for a package install's own request.
///
/// A package once-approval saved locally is retained for reuse until it
/// expires, so `consume` would refuse it. An exact Cloud allow answers one
/// queue item only, so the install that waited on that item spends it.
pub(crate) fn consume_exact_cloud_package(
    connection: &Connection,
    request_id: &str,
    decision: &Value,
    now: &str,
    key: &[u8],
    key_id: &str,
) -> StoreResult<bool> {
    spend(
        connection,
        request_id,
        decision,
        now,
        (key, key_id),
        &["exact-cloud"],
    )
}

fn spend(
    connection: &Connection,
    request_id: &str,
    decision: &Value,
    now: &str,
    (key, key_id): (&[u8], &str),
    kinds: &[&str],
) -> StoreResult<bool> {
    let Some(id) = decision["approval_id"].as_str().filter(|s| !s.is_empty()) else {
        return Ok(false);
    };
    let Some(revision) = decision["_approval_authority_revision"]
        .as_i64()
        .filter(|r| *r >= 0)
    else {
        return Ok(false);
    };
    if decision["action"] != "allow"
        || crate::claim_reuse::approval_authority_revision(connection)? != revision
    {
        return Ok(false);
    }
    let kind = decision["authority_kind"].as_str().unwrap_or("");
    if !kinds.contains(&kind) {
        return Ok(false);
    }
    let now = guard_contracts::canonical_utc_timestamp(now).ok_or(
        crate::guard_store_db::StoreError::Invalid("continuation_time_invalid"),
    )?;
    let row = if kind == "exact-cloud" {
        crate::guard_store_exact_cloud_peek::exact_cloud_row(connection, request_id, &now)?
    } else {
        query_one(connection,"select * from guard_local_once_approvals where approval_id = ? and claimed_at is null and julianday(expires_at) > julianday(?)", &[json!(id),json!(now)])?
    };
    let Some(row) = row else {
        return Ok(false);
    };
    if row.get("authority_kind").and_then(Value::as_str) != Some(kind)
        || row.get("approval_id").and_then(Value::as_str) != Some(id)
    {
        return Ok(false);
    }
    let mut signed: Map<String, Value> = [
        "approval_id",
        "request_id",
        "harness",
        "artifact_id",
        "artifact_hash",
        "workspace",
        "publisher",
        "action",
        "created_at",
        "expires_at",
        "claimed_at",
        "authority_kind",
    ]
    .iter()
    .map(|k| ((*k).to_owned(), row.get(*k).cloned().unwrap_or(Value::Null)))
    .collect();
    let integrity: Map<String, Value> = [
        "integrity_version",
        "payload_hash",
        "payload_mac",
        "integrity_key_id",
        "signed_at",
    ]
    .iter()
    .map(|k| ((*k).to_owned(), row.get(*k).cloned().unwrap_or(Value::Null)))
    .collect();
    let purpose = if kind == "exact-cloud" {
        "guard-exact-cloud-local-once-v1"
    } else {
        "guard-local-once-approval"
    };
    if verify_local_authority_payload(
        &json!(signed),
        &json!(integrity),
        Some(key),
        Some(key_id),
        purpose,
    )
    .status
        != "valid"
    {
        return Ok(false);
    }
    let mut current = row.clone();
    current.insert("integrity_status".into(), json!("valid"));
    current.insert("source".into(), json!("approval-gate-once"));
    current.insert("updated_at".into(), row["created_at"].clone());
    if IDENTITY.iter().any(|k| current.get(*k) != decision.get(*k)) {
        return Ok(false);
    }
    signed.insert("claimed_at".into(), json!(now));
    let signature = sign_local_authority_payload(&json!(signed), key, key_id, purpose, &now)
        .map_err(crate::guard_store_db::StoreError::Invalid)?;
    let changed = connection.execute("update guard_local_once_approvals set claimed_at = ?, integrity_version = ?, payload_hash = ?, payload_mac = ?, integrity_key_id = ?, signed_at = ? where approval_id = ? and claimed_at is null",
        params![now,signature.integrity_version,signature.payload_hash,signature.payload_mac,signature.integrity_key_id,signature.signed_at,id])?;
    Ok(changed == 1)
}

#[cfg(test)]
#[path = "continuation_grants_tests.rs"]
mod tests;
