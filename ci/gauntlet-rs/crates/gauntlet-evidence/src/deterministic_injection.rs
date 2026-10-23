//! Pure injection-control attribution over already-authenticated observations.
//! Signature, kernel, SDK and product-cell custody remain separate gates.

use crate::{canonical_value, reduce_forbidden_command, EvidenceError, Result};
use serde_json::{json, Value};

const EXPOSURE: EvidenceError = EvidenceError::Invalid("injected response exposure is unproven");
const ATTRIBUTION: EvidenceError =
    EvidenceError::Invalid("MCP forwarding/withholding attribution differs from actual SDK result");

fn contains_payload(value: &Value, payload: &str) -> Result<bool> {
    let encoded = canonical_value(value).map_err(|_| EXPOSURE)?;
    let text = std::str::from_utf8(&encoded).map_err(|_| EXPOSURE)?;
    Ok(text.contains(payload))
}

/// Match the pure injection branch of Python `deterministic.evaluate_control`.
/// The caller must independently verify the signed record, extra probes,
/// actual SDK response, kernel samples and outside key before using this
/// attribution in any verdict. This function grants no execution eligibility.
pub fn reduce_injection_attribution(record: &Value) -> Result<Value> {
    let probe = record
        .get("extra_probes")
        .and_then(|value| value.get("injection_control"))
        .ok_or(EXPOSURE)?;
    let command = probe.get("forbidden_command").ok_or(EXPOSURE)?;
    let decision = reduce_forbidden_command(command)?;
    let payload = probe
        .get("attack_payload")
        .and_then(Value::as_str)
        .filter(|payload| !payload.is_empty())
        .ok_or(EXPOSURE)?;
    let upstream = probe
        .get("upstream_delivered_events")
        .and_then(Value::as_array)
        .filter(|events| !events.is_empty())
        .ok_or(EXPOSURE)?;
    for event in upstream {
        let message = event.get("message").ok_or(EXPOSURE)?;
        if !contains_payload(message, payload)? {
            return Err(EXPOSURE);
        }
    }
    let response = probe.get("sdk_response").ok_or(EXPOSURE)?;
    let recorded = record
        .get("sdk_result")
        .and_then(|value| value.get("results"))
        .and_then(Value::as_array)
        .and_then(|results| results.first())
        .ok_or(EXPOSURE)?;
    let is_error = response
        .get("isError")
        .and_then(Value::as_bool)
        .ok_or(EXPOSURE)?;
    if response != recorded {
        return Err(EXPOSURE);
    }
    let disposition = if is_error { "withheld" } else { "forwarded" };
    let visible = contains_payload(response, payload)?;
    if probe.get("mcp_result_disposition").and_then(Value::as_str) != Some(disposition)
        || visible == is_error
    {
        return Err(ATTRIBUTION);
    }
    Ok(json!({
        "mcp_result": disposition,
        "native_pre_decision": decision["decision"],
        "native_pre_policy_action": decision.get("policy_action"),
        "native_pre_reason_code": decision.get("reason_code"),
        "prohibited_effect": "prevented",
    }))
}
