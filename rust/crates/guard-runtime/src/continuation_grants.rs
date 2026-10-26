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
        || crate::claim_reuse::approval_reuse_claim_disposition(decision) != Some("consumed")
        || crate::claim_reuse::approval_authority_revision(connection)? != revision
    {
        return Ok(false);
    }
    let kind = decision["authority_kind"].as_str().unwrap_or("");
    if !matches!(kind, "legacy" | "exact-cloud") {
        return Ok(false);
    }
    let now = guard_contracts::canonical_utc_timestamp(now).ok_or(
        crate::guard_store_db::StoreError::Invalid("continuation_time_invalid"),
    )?;
    let row = if kind == "exact-cloud" {
        let Some(request) = query_one(
            connection,
            "select * from approval_requests where request_id = ?",
            &[json!(request_id)],
        )?
        else {
            return Ok(false);
        };
        if request.get("status") != Some(&json!("resolved"))
            || request.get("resolution_action") != Some(&json!("allow"))
            || request.get("resolution_scope") != Some(&json!("artifact"))
            || !matches!(
                request.get("policy_action").and_then(Value::as_str),
                Some("review" | "require-reapproval")
            )
        {
            return Ok(false);
        }
        if ["request_id", "harness", "artifact_id", "artifact_hash"]
            .iter()
            .any(|k| {
                request
                    .get(*k)
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .is_none()
            })
        {
            return Ok(false);
        }
        let workspace = crate::policy_decision_lookup_op::computed_workspace_policy_key(
            request.get("workspace").and_then(Value::as_str),
        );
        let publisher = request
            .get("publisher")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        query_one(connection,"select * from guard_local_once_approvals where authority_kind = ? and request_id = ? and harness = ? and artifact_id = ? and artifact_hash = ? and claimed_at is null and julianday(expires_at) > julianday(?) and workspace is ? and publisher is ? order by created_at desc, approval_id desc limit 1",
            &[json!(kind),json!(request_id),request["harness"].clone(),request["artifact_id"].clone(),request["artifact_hash"].clone(),json!(now),json!(workspace),json!(publisher)])?
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
