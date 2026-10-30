//! `peek_exact_cloud_local_once_approval`: the unconsumed exact Cloud Review
//! allow issued for one resolved request, read without claiming it.
//!
//! The row is found through the request it answers - its harness, artifact,
//! hash, workspace scope and publisher - so an allow cannot be read back for
//! any other request. It is returned only when it verifies under the exact
//! Cloud purpose with the caller's key, together with the authority revision
//! a later claim must still observe. The caller keeps the key in the keyring
//! and ships it; a missing key reads as no authority.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_one, Row, StoreError, StoreResult};
use crate::guard_store_exact_cloud_apply::integrity_material;
use crate::local_once_store::{
    local_once_approval_payload, verify_local_once_approval, EXACT_CLOUD_AUTHORITY_KIND,
};
use crate::policy_decision_lookup_op::computed_workspace_policy_key;

/// The newest unclaimed, unexpired exact Cloud row bound to `request_id`,
/// when that request is a resolved artifact allow of a reviewable action.
/// `now` must already be canonical.
pub(crate) fn exact_cloud_row(
    connection: &Connection,
    request_id: &str,
    now: &str,
) -> StoreResult<Option<Row>> {
    let Some(request) = query_one(
        connection,
        "select * from approval_requests where request_id = ?",
        &[json!(request_id)],
    )?
    else {
        return Ok(None);
    };
    if request.get("status") != Some(&json!("resolved"))
        || request.get("resolution_action") != Some(&json!("allow"))
        || request.get("resolution_scope") != Some(&json!("artifact"))
        || !matches!(
            request.get("policy_action").and_then(Value::as_str),
            Some("review" | "require-reapproval")
        )
    {
        return Ok(None);
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
        return Ok(None);
    }
    let workspace = computed_workspace_policy_key(request.get("workspace").and_then(Value::as_str));
    let publisher = request
        .get("publisher")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    query_one(
        connection,
        "select * from guard_local_once_approvals where authority_kind = ? and request_id = ? \
         and harness = ? and artifact_id = ? and artifact_hash = ? and claimed_at is null \
         and julianday(expires_at) > julianday(?) and workspace is ? and publisher is ? \
         order by created_at desc, approval_id desc limit 1",
        &[
            json!(EXACT_CLOUD_AUTHORITY_KIND),
            json!(request_id),
            request["harness"].clone(),
            request["artifact_id"].clone(),
            request["artifact_hash"].clone(),
            json!(now),
            json!(workspace),
            json!(publisher),
        ],
    )
}

pub(crate) fn peek(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    let now = guard_contracts::canonical_utc_timestamp(args.str("now")?)
        .ok_or(StoreError::Invalid("exact_cloud_peek_time_invalid"))?;
    let Some((key, key_id)) = integrity_material(args)? else {
        return Ok(Value::Null);
    };
    let Some(row) = exact_cloud_row(connection, request_id, &now)? else {
        return Ok(Value::Null);
    };
    let row = Value::Object(row);
    if verify_local_once_approval(&row, Some(key.as_slice()), Some(key_id)).status != "valid" {
        return Ok(Value::Null);
    }
    let revision = crate::claim_reuse::approval_authority_revision(connection)?;
    let mut decision = local_once_approval_payload(&row);
    if let Some(map) = decision.as_object_mut() {
        // The exact Cloud decision is the stored row as verified, nothing
        // inferred about it; a claim checks it against these fields.
        map.remove("fresh_local_approval");
        map.insert(
            "authority_kind".to_owned(),
            json!(EXACT_CLOUD_AUTHORITY_KIND),
        );
        map.insert("_approval_authority_revision".to_owned(), json!(revision));
    }
    Ok(decision)
}

#[cfg(test)]
#[path = "guard_store_exact_cloud_peek_tests.rs"]
mod tests;
