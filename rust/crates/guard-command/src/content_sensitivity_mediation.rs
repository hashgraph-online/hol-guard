//! Forwarding authority is native, including the final binding recheck.

use std::time::Instant;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{policy, structured};

fn disposition(reason: &str, decision_id: &Value) -> Value {
    json!({"action":"withhold","reason_code":reason,"native_decision_id":decision_id,"content_sha256":null})
}

pub(super) fn prepare(body: &Value, deadline: Instant) -> Result<Value, &'static str> {
    let harness = policy::harness(body["harness"].as_str().ok_or("content_input_invalid")?);
    let native = &body["native_result"];
    let receipt = &body["validated_receipt"];
    let decision_id = receipt["decision_id"]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(|value| json!(value))
        .unwrap_or(Value::Null);
    if !matches!(harness.as_str(), "pi" | "omp")
        || body["event_name"] != "PostToolUse"
        || native["decision"] != "allow"
    {
        return Ok(Value::Null);
    }
    if native["observe_mode"] == Value::Bool(true)
        && body["allow_observe_mode"] != Value::Bool(true)
    {
        return Ok(Value::Null);
    }
    if native["model_output_action"] != "allow_original" {
        return Ok(disposition("structured_content_unproved", &decision_id));
    }
    if receipt["decision"] != "allow" || decision_id.is_null() {
        return Ok(disposition("structured_receipt_missing", &decision_id));
    }
    let binding = &body["binding"];
    if binding.is_null() {
        return Ok(body["required_reason_code"]
            .as_str()
            .map(|reason| disposition(reason, &decision_id))
            .unwrap_or(Value::Null));
    }
    if binding["harness"] != harness {
        return Ok(Value::Null);
    }
    if body["cancelled"] == Value::Bool(true) {
        return Ok(disposition("structured_review_cancelled", &decision_id));
    }
    if Instant::now() >= deadline {
        return Ok(disposition(
            "structured_review_deadline_exceeded",
            &decision_id,
        ));
    }
    let Some(candidate) = structured::canonical(&body["structured_output_json"]) else {
        return Ok(disposition("structured_content_unproved", &decision_id));
    };
    let fields = policy::field_list(&binding["policy"])?;
    let scan = structured::scan(&candidate, Some(&fields), deadline)?;
    if scan["status"] != "no_declared_match" || scan["complete"] != Value::Bool(true) {
        return Ok(disposition(
            &format!(
                "structured_{}",
                scan["reason_code"]
                    .as_str()
                    .ok_or("content_scan_unavailable")?
            ),
            &decision_id,
        ));
    }
    if Instant::now() >= deadline {
        return Ok(disposition(
            "structured_review_deadline_exceeded",
            &decision_id,
        ));
    }
    if body["recheck_available"] != Value::Bool(true) {
        return Ok(disposition(
            "structured_binding_recheck_missing",
            &decision_id,
        ));
    }
    Ok(json!({"recheck_required":true}))
}

pub(super) fn finish(body: &Value, deadline: Instant) -> Result<Value, &'static str> {
    let prepared = prepare(body, deadline)?;
    if prepared.get("recheck_required") != Some(&Value::Bool(true)) {
        return Ok(prepared);
    }
    let decision_id = &body["validated_receipt"]["decision_id"];
    if body["recheck_error"] == Value::Bool(true) {
        return Ok(disposition(
            "structured_binding_recheck_failed",
            decision_id,
        ));
    }
    let refreshed = &body["refreshed_binding"];
    if refreshed.is_null() || refreshed != &body["binding"] {
        return Ok(disposition("structured_binding_changed", decision_id));
    }
    if Instant::now() >= deadline {
        return Ok(disposition(
            "structured_review_deadline_exceeded",
            decision_id,
        ));
    }
    let candidate = body["structured_output_json"]
        .as_str()
        .ok_or("content_input_invalid")?;
    Ok(
        json!({"action":"forward","reason_code":"structured_clean_forward","native_decision_id":decision_id,
        "content_sha256":format!("{:x}",Sha256::digest(candidate.as_bytes()))}),
    )
}

#[cfg(test)]
pub(super) fn replay(body: &Value, deadline: Instant) -> Result<Value, &'static str> {
    let mut input = body.clone();
    input["required_reason_code"] = Value::Null;
    input["cancelled"] = Value::Bool(false);
    input["allow_observe_mode"] = Value::Bool(false);
    input["recheck_available"] = Value::Bool(body["recheck"] != "no_callback");
    // The recorded callback raises ValueError, which the old API treats as a
    // missing refreshed binding rather than an unexpected callback failure.
    input["recheck_error"] = Value::Bool(false);
    input["refreshed_binding"] = match body["recheck"].as_str() {
        Some("same") => body["binding"].clone(),
        Some("changed") => {
            let mut binding = body["binding"].clone();
            binding["harness"] = json!("omp");
            binding["managed_policy_hash"] = json!("b".repeat(64));
            binding
        }
        _ => Value::Null,
    };
    finish(&input, deadline)
}
