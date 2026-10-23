//! Python parity for reported SDK peer, Native hook and operation relations.
//! These rows still require independently authenticated process/effect custody.

use crate::crypto::sha256;
use crate::{canonical_value, EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const PEER: &str = "builtin review lacks exact authenticated SDK peer";
const CLASS: &str = "invalid builtin review classification";
const HOOK: &str = "transport review has no matching actual native hook response";
const PRE_INPUT: &str = "reused builtin call changed input";
const POST: &str = "native output review original input/output binding absent";
const OUTPUT: &str = "native original output digest differs from actual SDK output";
const BUDGET: &str = "controller operation budget differs from frozen limit";
const LIMIT: &str = "operation observations exceed frozen budget";
const EVENT: &str = "invalid controller operation observation";
const ACCOUNTING: &str = "operation counters do not match actual native ingress reviews/requests";

fn bounded<'a>(value: &'a Value, name: &'static str) -> Result<&'a Vec<Value>> {
    value
        .as_array()
        .filter(|rows| rows.len() <= 10_000)
        .ok_or(EvidenceError::Invalid(name))
}

fn str_field<'a>(value: &'a Value, field: &str, reason: &'static str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(EvidenceError::Invalid(reason))
}

fn count(map: &mut BTreeMap<(String, String), usize>, source: &str, digest: &str) {
    *map.entry((source.to_owned(), digest.to_owned()))
        .or_default() += 1;
}

fn digest(value: &Value) -> Result<String> {
    Ok(sha256(&canonical_value(value)?))
}

/// Recompute the Python `_reviews` and `_operations` relations. The caller
/// supplies all records, including the reported kernel-authenticated peer;
/// success here cannot prove that the peer or hook process actually existed.
pub fn verify_native_transport_relations(
    builtin: &Value,
    plane: &Value,
    runtime: &Value,
    sdk_pid: u64,
    sdk_identity: &Value,
    require_sdk: bool,
) -> Result<Value> {
    let events = bounded(&builtin["transport_observations"], CLASS)?;
    let actual: Vec<&Value> = events
        .iter()
        .filter(|row| row.get("kind") == Some(&json!("actual-hook-response")))
        .collect();
    let peers: Vec<&Value> = events
        .iter()
        .filter(|row| row.get("kind") == Some(&json!("peer-authenticated")))
        .collect();
    if require_sdk
        && (peers.len() < actual.len()
            || peers.iter().any(|row| {
                row.get("peer_pid") != Some(&json!(sdk_pid))
                    || row.get("peer_uid") != Some(&json!(10001))
                    || row.get("identity") != Some(sdk_identity)
            }))
    {
        return Err(EvidenceError::Invalid(PEER));
    }
    let hooks = bounded(&plane["hooks"], HOOK)?;
    let mut pairs = BTreeMap::new();
    for row in hooks {
        let payload = str_field(row, "payload_digest", HOOK)?;
        let response = str_field(row, "response_digest", HOOK)?;
        *pairs
            .entry((payload.to_owned(), response.to_owned()))
            .or_insert(0_usize) += 1;
    }
    let mut inputs = BTreeMap::new();
    for row in &actual {
        let event = str_field(row, "hook_event_name", CLASS)?;
        let tool = str_field(row, "tool_name", CLASS)?;
        if !matches!(event, "PreToolUse" | "PostToolUse")
            || !matches!(tool, "read" | "write" | "edit" | "bash")
        {
            return Err(EvidenceError::Invalid(CLASS));
        }
        let payload = str_field(row, "payload_digest", HOOK)?;
        let response = str_field(row, "response_digest", HOOK)?;
        let product_response = row
            .get("product_response")
            .ok_or(EvidenceError::Invalid(HOOK))?;
        let remaining = pairs
            .entry((payload.to_owned(), response.to_owned()))
            .or_insert(0);
        if *remaining == 0 || response != digest(product_response)? {
            return Err(EvidenceError::Invalid(HOOK));
        }
        *remaining -= 1;
        let call = str_field(row, "tool_call_id", PRE_INPUT)?;
        let original = str_field(row, "original_input_digest", PRE_INPUT)?;
        if event == "PreToolUse" {
            if inputs.get(call).is_some_and(|old| *old != original) {
                return Err(EvidenceError::Invalid(PRE_INPUT));
            }
            inputs.insert(call, original);
        } else {
            let output = row
                .get("actual_output_sha256")
                .and_then(Value::as_str)
                .ok_or(EvidenceError::Invalid(POST))?;
            if inputs.get(call) != Some(&original) || output.len() != 64 {
                return Err(EvidenceError::Invalid(POST));
            }
            if product_response.get("model_output_action") == Some(&json!("allow_original"))
                && product_response.get("reviewed_output_sha256") != Some(&json!(output))
            {
                return Err(EvidenceError::Invalid(OUTPUT));
            }
        }
    }
    let operations = runtime
        .get("operations")
        .ok_or(EvidenceError::Invalid(BUDGET))?;
    let fields = operations
        .as_object()
        .ok_or(EvidenceError::Invalid(BUDGET))?;
    if fields.len() != 3
        || !fields.contains_key("maximum")
        || !fields.contains_key("admitted")
        || !fields.contains_key("events")
    {
        return Err(EvidenceError::Invalid(BUDGET));
    }
    let maximum = operations["maximum"]
        .as_i64()
        .ok_or(EvidenceError::Invalid(BUDGET))?;
    let admitted = operations["admitted"]
        .as_i64()
        .ok_or(EvidenceError::Invalid(BUDGET))?;
    if operations["maximum"] != runtime["settings"]["max_tool_calls"]
        || admitted < 0
        || admitted > maximum
    {
        return Err(EvidenceError::Invalid(BUDGET));
    }
    let rows = bounded(&operations["events"], LIMIT)?;
    if maximum < 0 || rows.len() as i64 > maximum.saturating_add(1) {
        return Err(EvidenceError::Invalid(LIMIT));
    }
    let mut observed = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        let fields = row.as_object().ok_or(EvidenceError::Invalid(EVENT))?;
        let source = str_field(row, "source", EVENT)?;
        if fields.len() != 4
            || !fields.contains_key("sequence")
            || !fields.contains_key("request_digest")
            || !fields.contains_key("admitted")
            || row["sequence"].as_u64() != Some(index as u64 + 1)
            || !matches!(source, "sdk-builtin" | "native-mcp")
            || !row["admitted"].is_boolean()
        {
            return Err(EvidenceError::Invalid(EVENT));
        }
        if row["admitted"] == true {
            count(
                &mut observed,
                source,
                str_field(row, "request_digest", EVENT)?,
            );
        }
    }
    let mut expected = BTreeMap::new();
    for row in &actual {
        if row["hook_event_name"] == "PreToolUse" {
            count(
                &mut expected,
                "sdk-builtin",
                str_field(row, "payload_digest", ACCOUNTING)?,
            );
        }
    }
    let mcp = bounded(
        &runtime["native_mcp_audit"]["record"]["transport_observations"],
        ACCOUNTING,
    )?;
    for row in mcp {
        if row.get("kind") == Some(&json!("forwarded"))
            && row.get("message").and_then(|message| message.get("method"))
                == Some(&json!("tools/call"))
        {
            let request = json!({
                "family": row.get("family").ok_or(EvidenceError::Invalid(ACCOUNTING))?,
                "session_id": row.get("session_id").ok_or(EvidenceError::Invalid(ACCOUNTING))?,
                "message": row.get("message").ok_or(EvidenceError::Invalid(ACCOUNTING))?,
            });
            count(&mut expected, "native-mcp", &digest(&request)?);
        }
    }
    if observed != expected || observed.values().sum::<usize>() as i64 != admitted {
        return Err(EvidenceError::Invalid(ACCOUNTING));
    }
    Ok(json!({
        "native_review_count": actual.len(),
        "admitted_operations": admitted,
        "execution_eligible": false,
    }))
}
