//! `CiscoPreflight` resident op.
//!
//! Rust owns the authority half of the Cisco scanner preflight: which scan
//! roots an action may reach, every containment verdict, the mapping of
//! analyzer findings to risk signals, and the resolved policy action. Python
//! only runs the third-party analyzers between the `plan` and `evidence`
//! queries. A malformed request is a bound error result.

use guard_contracts::{
    CiscoPreflightQueryV1, CiscoPreflightRequestV1, CiscoPreflightResultV1,
    CISCO_PREFLIGHT_MAX_BYTES, CISCO_PREFLIGHT_MAX_ITEMS, CISCO_PREFLIGHT_REQUEST_SCHEMA,
    CISCO_PREFLIGHT_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::{json, Value};

use super::context_digest_json::write_canonical_json_with_limit;
use crate::{cisco_evidence, cisco_plan};

const INVALID: &str = "native_cisco_preflight_invalid";
const SCHEMA_MISMATCH: &str = "native_cisco_preflight_schema_mismatch";

fn request_digest(request: &CiscoPreflightRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| INVALID)?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, CISCO_PREFLIGHT_MAX_BYTES)
        .map_err(|_| INVALID)?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

fn within_bounds(query: &CiscoPreflightQueryV1) -> bool {
    let count = match query {
        CiscoPreflightQueryV1::Plan(plan) => {
            plan.target_paths.len() + plan.approved_scan_roots.len()
        }
        CiscoPreflightQueryV1::Evidence(evidence) => evidence.steps.len(),
        CiscoPreflightQueryV1::PolicyAction(policy) => policy.signal_sources.len(),
    };
    count <= CISCO_PREFLIGHT_MAX_ITEMS
}

pub(crate) fn decide(query: &CiscoPreflightQueryV1) -> Result<Value, &'static str> {
    match query {
        CiscoPreflightQueryV1::Plan(plan) => Ok(json!({ "steps": cisco_plan::plan(plan) })),
        CiscoPreflightQueryV1::Evidence(evidence) => cisco_evidence::evidence(&evidence.steps),
        CiscoPreflightQueryV1::PolicyAction(policy) => cisco_evidence::policy_action(policy),
    }
}

pub(crate) fn evaluate_cisco_preflight(
    request: &CiscoPreflightRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let (status, code, payload) = if request.schema != CISCO_PREFLIGHT_REQUEST_SCHEMA {
        ("error", SCHEMA_MISMATCH, Value::Null)
    } else if request.request_id.len() > 128 || !within_bounds(&request.query) {
        ("error", INVALID, Value::Null)
    } else {
        match decide(&request.query) {
            Ok(payload) => ("ok", "ok", payload),
            Err(_) => ("error", INVALID, Value::Null),
        }
    };
    crate::encode_response(&CiscoPreflightResultV1 {
        schema: CISCO_PREFLIGHT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}
