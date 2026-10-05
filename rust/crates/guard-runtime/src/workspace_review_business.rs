#![forbid(unsafe_code)]

//! Private frozen business material for the existing review snapshot.
//! Origin authentication proves local integrity, not provider identity or custody.

use super::workspace_review_claim_index::valid_digest;
use base64ct::{Base64, Encoding};
use guard_command::business_input::PreparedBusinessInputV1;
use guard_contracts::{
    BusinessActionV1, NativeHookDecisionReceiptV1, MAX_BUSINESS_ACTION_ITEMS,
    MAX_BUSINESS_INLINE_BYTES,
};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use serde::Deserialize;
use serde_json::Value;

const INVALID: &str = "native_workspace_review_business_invalid";
const DIRECTORY: &str = "workspace-review-business-inputs";
const MAX_PRIVATE_BYTES: u64 = 512 * 1024;
const DOMAIN: &[u8] = b"hol-guard.business-private-review.v1\0";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    schema: String,
    version: u16,
    prepared_input_binding: String,
    snapshot_digest: String,
}

// Deliberately lacks Debug/Serialize/Clone: private mail and attachments must
// stay out of generic diagnostics, receipts and review context responses.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateInput {
    schema: String,
    version: u16,
    facts: BusinessActionV1,
    primary_base64: String,
    attachments_base64: Vec<String>,
}

fn invalid() -> String {
    INVALID.to_owned()
}

fn prepare(value: Value) -> Result<PreparedBusinessInputV1, String> {
    let input: PrivateInput = serde_json::from_value(value).map_err(|_| invalid())?;
    if input.schema != "guard.private-business-input.v1"
        || input.version != 1
        || input.attachments_base64.len() > MAX_BUSINESS_ACTION_ITEMS
    {
        return Err(invalid());
    }
    let mut total = 0usize;
    let mut decode = |encoded: &str| -> Result<Vec<u8>, String> {
        let maximum = (MAX_BUSINESS_INLINE_BYTES as usize).div_ceil(3) * 4;
        if encoded.len() > maximum {
            return Err(invalid());
        }
        let bytes = Base64::decode_vec(encoded).map_err(|_| invalid())?;
        total = total.checked_add(bytes.len()).ok_or_else(invalid)?;
        if total as u64 > MAX_BUSINESS_INLINE_BYTES || Base64::encode_string(&bytes) != encoded {
            return Err(invalid());
        }
        Ok(bytes)
    };
    let primary = decode(&input.primary_base64)?;
    let attachments = input
        .attachments_base64
        .iter()
        .map(|s| decode(s))
        .collect::<Result<Vec<_>, _>>()?;
    let facts = serde_json::to_vec(&input.facts).map_err(|_| invalid())?;
    PreparedBusinessInputV1::prepare(&facts, primary, attachments).map_err(|_| invalid())
}

fn origin_binding(
    request_id: &str,
    context: &Context,
    receipt: &NativeHookDecisionReceiptV1,
) -> Result<String, String> {
    let value = serde_json::json!({
        "request_id": request_id, "prepared_input_binding": context.prepared_input_binding,
        "snapshot_digest": context.snapshot_digest, "policy_generation": receipt.policy_generation,
        "policy_digest": receipt.policy_digest, "rule_digest": receipt.rule_digest,
        "runtime_identity": receipt.runtime_identity,
    });
    let bytes = canonical_json_bytes(&value).map_err(|_| invalid())?;
    let mut preimage = Vec::with_capacity(DOMAIN.len() + bytes.len());
    preimage.extend_from_slice(DOMAIN);
    preimage.extend_from_slice(&bytes);
    Ok(digest_bytes(&preimage))
}

pub(super) fn load(
    store: &super::PolicySnapshotStore,
    request_id: &str,
    envelope: Option<&Value>,
    receipt: Option<&NativeHookDecisionReceiptV1>,
) -> Result<Option<PreparedBusinessInputV1>, String> {
    if !super::workspace_review_request::valid_request_id(request_id) {
        return Err(invalid());
    }
    let raw = envelope.and_then(|v| v.get("business_context"));
    let authenticated = receipt.and_then(|r| r.business_review_binding.as_deref());
    if raw.is_none() && authenticated.is_none() {
        return Ok(None);
    }
    let receipt = receipt.ok_or_else(invalid)?;
    let proof = authenticated
        .filter(|s| valid_digest(s))
        .ok_or_else(invalid)?;
    let context: Context =
        serde_json::from_value(raw.ok_or_else(invalid)?.clone()).map_err(|_| invalid())?;
    if context.schema != "guard.private-business-review.v1"
        || context.version != 1
        || !valid_digest(&context.prepared_input_binding)
        || !valid_digest(&context.snapshot_digest)
        || origin_binding(request_id, &context, receipt)? != proof
    {
        return Err(invalid());
    }
    let snapshot = store.current_snapshot()?;
    if snapshot.business_policy.is_none()
        || receipt.policy_generation != snapshot.generation
        || receipt.policy_digest.as_deref() != Some(snapshot.policy_digest.as_str())
        || receipt.rule_digest.as_deref() != Some(snapshot.rule_digest.as_str())
        || receipt.runtime_identity.as_deref() != Some(snapshot.runtime_identity.as_str())
    {
        return Err(invalid());
    }
    let directory = store.state_base().join(DIRECTORY);
    super::validate_private_directory(&directory).map_err(|_| invalid())?;
    let private_root = crate::resident_state::private_root_for_state_base(store.state_base())
        .map_err(|_| invalid())?;
    // Content-addressed names keep all caller-chosen IDs out of filesystem
    // syntax and let future producers retain separate immutable revisions.
    let path = directory.join(format!("{}.json", context.snapshot_digest));
    let (value, bytes) = super::policy_store_persistence::read_private_json(
        &path,
        MAX_PRIVATE_BYTES,
        "business_review_input",
        &private_root,
    )
    .map_err(|_| invalid())?
    .ok_or_else(invalid)?;
    if canonical_json_bytes(&value).map_err(|_| invalid())? != bytes
        || digest_bytes(&bytes) != context.snapshot_digest
    {
        return Err(invalid());
    }
    let prepared = prepare(value)?;
    if prepared.binding() != context.prepared_input_binding {
        return Err(invalid());
    }
    crate::policy_enforcement::ensure_business_review_permitted(
        &snapshot,
        prepared.facts(),
        receipt.policy_action.as_deref().ok_or_else(invalid)?,
    )?;
    Ok(Some(prepared))
}

#[cfg(test)]
#[path = "workspace_review_business_tests.rs"]
mod tests;
