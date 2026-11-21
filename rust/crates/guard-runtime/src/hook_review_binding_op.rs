//! Rust-owned validation and projection of the committed hook review binding.

use guard_contracts::NativePolicyBindingV1;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::resident_protocol::encode_response;

pub(crate) const HOOK_REVIEW_BINDING_FEATURE: &str = "hook-review-binding-v1";
const REQUEST_SCHEMA: &str = "guard-hook-review-binding-request.v1";
const RESULT_SCHEMA: &str = "guard-hook-review-binding-result.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookReviewPolicyBindingRequestV1 {
    pub(crate) harness: String,
    pub(crate) native_result: Value,
    pub(crate) verified_receipt: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookReviewBindingRequestV1 {
    pub(crate) schema: String,
    pub(crate) request_id: String,
    pub(crate) marker: Value,
    pub(crate) business_identity_hex: String,
    #[serde(default)]
    pub(crate) cli_revision: Option<u64>,
    #[serde(default)]
    pub(crate) policy_binding: Option<HookReviewPolicyBindingRequestV1>,
}

fn evaluate_policy_binding(
    request_id: &str,
    input: &HookReviewPolicyBindingRequestV1,
) -> Result<Vec<u8>, String> {
    if input.harness.is_empty() || input.harness.len() > 64 {
        return Err("hook_review_binding_payload_invalid".to_owned());
    }
    let Some(result) = input.native_result.as_object() else {
        return Err("hook_review_binding_payload_invalid".to_owned());
    };
    let Some(receipt) = input.verified_receipt.as_object() else {
        return Err("hook_review_binding_payload_invalid".to_owned());
    };
    let binding =
        crate::native_exact_action_op::policy_binding_value(&input.harness, result, Some(receipt));
    let value = match binding {
        NativePolicyBindingV1::Invalid => {
            return Err("hook_review_policy_binding_invalid".to_owned());
        }
        NativePolicyBindingV1::Unbound => Value::Null,
        NativePolicyBindingV1::Bound { value } => value,
    };
    encode_response(&json!({
        "schema": RESULT_SCHEMA,
        "result": {
            "request_id": request_id,
            "binding": value,
        },
    }))
}

pub(crate) fn evaluate(request: &HookReviewBindingRequestV1) -> Result<Vec<u8>, String> {
    if request.schema != REQUEST_SCHEMA
        || request.request_id.is_empty()
        || request.request_id.len() > 128
        || request.business_identity_hex.len() > 8192
        || request.business_identity_hex.len() % 2 != 0
    {
        return Err("hook_review_binding_payload_invalid".to_owned());
    }
    if let Some(policy_binding) = request.policy_binding.as_ref() {
        return evaluate_policy_binding(&request.request_id, policy_binding);
    }
    let identity = hex::decode(&request.business_identity_hex)
        .map_err(|_| "hook_review_binding_identity_invalid".to_owned())?;
    let marker = request
        .marker
        .as_object()
        .ok_or_else(|| "hook_review_binding_marker_invalid".to_owned())?;
    if !marker.is_empty() && marker.get("phase").and_then(Value::as_str) != Some("committed") {
        return Err("hook_review_binding_marker_not_committed".to_owned());
    }
    let token = json!([
        marker.get("epoch").cloned().unwrap_or(Value::Null),
        marker
            .get("mutation_revision")
            .cloned()
            .unwrap_or(Value::Null),
        marker.get("phase").cloned().unwrap_or(Value::Null),
        marker
            .get("effective_digest")
            .cloned()
            .unwrap_or(Value::Null),
        marker
            .get("authority_key_id")
            .cloned()
            .unwrap_or(Value::Null),
        marker
            .get("pack_program_digest")
            .cloned()
            .unwrap_or(Value::Null),
        request.business_identity_hex,
        request.cli_revision.map_or(Value::Null, Value::from),
    ]);
    let _ = identity;
    encode_response(&json!({
        "schema": RESULT_SCHEMA,
        "result": {"request_id": request.request_id, "token": token},
    }))
}

#[cfg(test)]
#[path = "hook_review_binding_op_tests.rs"]
mod tests;
