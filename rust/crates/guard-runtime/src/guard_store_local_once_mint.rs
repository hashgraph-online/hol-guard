//! `store_local_once_authority.persist_local_once_approval` ported to
//! `rusqlite`: the one place that mints exact local one-shot authority.
//!
//! The row written here is the authority a later native review reads to allow
//! an execution without asking again, so its HMAC is signed where the verdict
//! is decided rather than in the caller. Python keeps the install key in the
//! keyring and ships it over the store call; it signs nothing itself.
//!
//! `guard_store_exact_cloud_apply` mints through the same helper inside its own
//! transaction, so a Cloud Review allow and a local approval write byte-equal
//! rows under their own integrity purposes.

use rusqlite::Connection;
use serde_json::{json, Value};

use guard_contracts::{canonical_utc_timestamp, timestamp_has_expired};
use guard_policy_snapshot::local_authority_integrity::sign_local_authority_payload;

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, value_error, StoreError, StoreResult};
use crate::guard_store_exact_cloud_apply::integrity_material;
use crate::local_once_store::{
    local_once_integrity_purpose, EXACT_CLOUD_AUTHORITY_KIND, LOCAL_ONCE_LEGACY_AUTHORITY_KIND,
};
use crate::policy_decision_lookup_op::computed_workspace_policy_key;

/// One approval to mint. `harness` and `publisher` arrive as the JSON the
/// caller sent so an empty string stays an empty string, exactly as Python
/// stored whatever it was handed.
pub(crate) struct LocalOnceMint<'a> {
    pub(crate) request_id: &'a str,
    pub(crate) harness: Value,
    pub(crate) artifact_id: Option<&'a str>,
    pub(crate) artifact_hash: Option<&'a str>,
    pub(crate) workspace: Option<&'a str>,
    pub(crate) publisher: Value,
    pub(crate) action: Value,
    pub(crate) created_at: &'a str,
    pub(crate) expires_at: &'a str,
    pub(crate) authority_kind: &'a str,
}

/// `uuid4().hex`.
fn approval_id(random_failed: &'static str) -> StoreResult<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| StoreError::Invalid(random_failed))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(hex::encode(bytes))
}

/// Insert exact one-shot authority inside the caller's transaction.
///
/// `None` is Python's `None`: the request names no exact artifact to bind the
/// authority to, which is not a failure. `time_invalid` and `random_failed`
/// are the caller's own failure codes, so each store method keeps the code it
/// already reported for a malformed timestamp.
pub(crate) fn mint_local_once_approval(
    connection: &Connection,
    mint: &LocalOnceMint<'_>,
    key: &[u8],
    key_id: &str,
    time_invalid: &'static str,
    random_failed: &'static str,
) -> StoreResult<Option<String>> {
    let (Some(artifact_id), Some(artifact_hash)) = (
        mint.artifact_id.filter(|text| !text.is_empty()),
        mint.artifact_hash.filter(|text| !text.is_empty()),
    ) else {
        return Ok(None);
    };
    if mint.authority_kind != LOCAL_ONCE_LEGACY_AUTHORITY_KIND
        && mint.authority_kind != EXACT_CLOUD_AUTHORITY_KIND
    {
        return value_error("local approval authority kind is unsupported");
    }
    let created_at =
        canonical_utc_timestamp(mint.created_at).ok_or(StoreError::Invalid(time_invalid))?;
    let expires_at =
        canonical_utc_timestamp(mint.expires_at).ok_or(StoreError::Invalid(time_invalid))?;
    if timestamp_has_expired(&expires_at, &created_at) {
        return value_error("local approval expiry must be after its creation time");
    }
    let workspace = Value::from(computed_workspace_policy_key(mint.workspace));
    let signed = json!({
        "approval_id": approval_id(random_failed)?,
        "request_id": mint.request_id,
        "harness": mint.harness.clone(),
        "artifact_id": artifact_id,
        "artifact_hash": artifact_hash,
        "workspace": workspace,
        "publisher": mint.publisher.clone(),
        "action": mint.action.clone(),
        "created_at": created_at,
        "expires_at": expires_at,
        "claimed_at": Value::Null,
        "authority_kind": mint.authority_kind,
    });
    let integrity = sign_local_authority_payload(
        &signed,
        key,
        key_id,
        local_once_integrity_purpose(Some(mint.authority_kind)),
        &created_at,
    )
    .map_err(StoreError::Invalid)?;
    exec(
        connection,
        "insert into guard_local_once_approvals (
           approval_id, request_id, harness, artifact_id, artifact_hash, workspace, publisher, action,
           created_at, expires_at, claimed_at, integrity_version, payload_hash, payload_mac,
           integrity_key_id, signed_at, authority_kind
         )
         values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, null, ?, ?, ?, ?, ?, ?)",
        &[
            signed["approval_id"].clone(),
            signed["request_id"].clone(),
            signed["harness"].clone(),
            signed["artifact_id"].clone(),
            signed["artifact_hash"].clone(),
            signed["workspace"].clone(),
            signed["publisher"].clone(),
            signed["action"].clone(),
            signed["created_at"].clone(),
            signed["expires_at"].clone(),
            Value::from(integrity.integrity_version),
            Value::from(integrity.payload_hash),
            Value::from(integrity.payload_mac),
            Value::from(integrity.integrity_key_id),
            Value::from(integrity.signed_at),
            Value::from(mint.authority_kind),
        ],
    )?;
    Ok(signed["approval_id"].as_str().map(str::to_owned))
}

/// `record_local_once_approval`: the store method behind an approval the user
/// granted here. The key material is required; Python answers `None` without
/// calling when the install has none, so a call that arrives without it is a
/// request outside the contract rather than an absent approval.
pub(crate) fn record_local_once_approval(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let Some((key, key_id)) = integrity_material(args)? else {
        return Err(StoreError::Invalid("local_once_mint_key_missing"));
    };
    let mint = LocalOnceMint {
        request_id: args.str("request_id")?,
        harness: args.raw("harness").cloned().unwrap_or(Value::Null),
        artifact_id: args.opt_str("artifact_id")?,
        artifact_hash: args.opt_str("artifact_hash")?,
        workspace: args.opt_str("workspace")?,
        publisher: args.raw("publisher").cloned().unwrap_or(Value::Null),
        action: args.raw("action").cloned().unwrap_or(Value::Null),
        created_at: args.str("created_at")?,
        expires_at: args.str("expires_at")?,
        authority_kind: args
            .opt_str("authority_kind")?
            .unwrap_or(LOCAL_ONCE_LEGACY_AUTHORITY_KIND),
    };
    let approval_id = mint_local_once_approval(
        connection,
        &mint,
        &key,
        key_id,
        "local_once_mint_time_invalid",
        "local_once_mint_random_failed",
    )?;
    Ok(approval_id.map_or(Value::Null, Value::from))
}

#[cfg(test)]
#[path = "guard_store_local_once_mint_tests.rs"]
mod tests;
