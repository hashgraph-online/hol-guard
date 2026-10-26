//! Sensitivity authority uses the existing admitted, request-bound resident.

use guard_contracts::RequestContextContentSensitivityV1;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::request_context_op::Budget;

#[cfg(test)]
#[path = "content_sensitivity_op_tests.rs"]
mod tests;

pub(crate) fn evaluate(
    body: &RequestContextContentSensitivityV1,
    budget: &Budget,
    store: Option<&crate::policy_store::PolicySnapshotStore>,
    guard_home: &std::path::Path,
) -> Result<Value, &'static str> {
    budget.check()?;
    let encoded = serde_json::to_vec(&body.input)
        .map_err(|_| "native_request_context_content_input_invalid")?;
    if encoded.len() > 6 * 1024 * 1024 || body.query.len() > 32 {
        return Err("native_request_context_content_input_invalid");
    }
    let input = guard_command::content_sensitivity::decode_input(&body.input)
        .map_err(|_| "native_request_context_content_input_invalid")?;
    budget.check()?;
    let result =
        guard_command::content_sensitivity::evaluate(&body.query, &input, budget.deadline())
            .map_err(|_| {
                if std::time::Instant::now() >= budget.deadline() {
                    "native_request_context_budget_exceeded"
                } else {
                    "native_request_context_content_unavailable"
                }
            })?;
    if result["ok"]["action"] == "forward" {
        // A Python-provided allow field is never a native forwarding grant.
        let receipt: guard_contracts::NativeHookDecisionReceiptV1 =
            serde_json::from_value(input["validated_receipt"].clone())
                .map_err(|_| "native_request_context_content_receipt_invalid")?;
        match store {
            Some(store) => crate::policy_store::native_review_origin::verify(store, &receipt),
            None => crate::policy_store::native_review_origin::verify_at_guard_home(
                guard_home, &receipt,
            ),
        }
        .map_err(|_| "native_request_context_content_receipt_invalid")?;
        let harness = input["binding"]["harness"]
            .as_str()
            .ok_or("native_request_context_content_receipt_invalid")?;
        let output = input["structured_output_json"]
            .as_str()
            .ok_or("native_request_context_content_receipt_invalid")?;
        let output_digest = format!("{:x}", Sha256::digest(output.as_bytes()));
        if receipt.harness != harness
            || receipt.reviewed_output_sha256.as_deref() != Some(output_digest.as_str())
            || receipt.event_name != "PostToolUse"
            || receipt.decision != "allow"
            || receipt.model_output_action != "allow_original"
            || receipt.observe_mode && input["allow_observe_mode"] != Value::Bool(true)
        {
            return Err("native_request_context_content_receipt_invalid");
        }
    }
    budget.check()?;
    Ok(json!({"kind":"content_sensitivity","query":body.query,"result":result}))
}
