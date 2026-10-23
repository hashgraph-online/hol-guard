//! Pure relation between a contained result, controller output binding and
//! reported Native Post. The records must still be independently bound to
//! their SDK/kernel producer before this relation can support a verdict.

use crate::crypto::is_sha256;
use crate::{captured_contained_output, EvidenceError, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const INVALID: EvidenceError = EvidenceError::Invalid("invalid contained output custody data");
const COVERAGE: EvidenceError =
    EvidenceError::Invalid("contained output binding coverage differs from sinks");
const RECORD: EvidenceError =
    EvidenceError::Invalid("invalid controller contained output binding record");
const TRANSPLANTED: EvidenceError =
    EvidenceError::Invalid("contained result transplanted to another SDK call");
const POST: EvidenceError =
    EvidenceError::Invalid("native Post output differs from actual contained result");
const CONSUMED: EvidenceError =
    EvidenceError::Invalid("consumed contained execution lacks its exact output binding");
const MAX_ROWS: usize = 4096;
const BINDING_KEYS: [&str; 9] = [
    "sequence",
    "kind",
    "tool_call_id",
    "pre_payload_digest",
    "payload_digest",
    "result_digest",
    "output_sha256",
    "sdk_output_sha256",
    "schema",
];

fn field<'a>(row: &'a Value, name: &str) -> Result<&'a str> {
    row.get(name).and_then(Value::as_str).ok_or(INVALID)
}

/// Match Python `contained_output_custody.verify_contained_outputs` over
/// supplied signed-builtin data. The return value is a relation count, never
/// evidence that the SDK, Native Post or kernel observations actually ran.
pub fn verify_contained_output_custody(builtin: &Value) -> Result<usize> {
    let events = builtin["transport_observations"]
        .as_array()
        .ok_or(INVALID)?;
    let contained = builtin["contained_transport_observations"]
        .as_array()
        .ok_or(INVALID)?;
    let results = builtin["product_plane"]["executions"]
        .as_array()
        .ok_or(INVALID)?;
    if events.len() > MAX_ROWS || contained.len() > MAX_ROWS || results.len() > MAX_ROWS {
        return Err(INVALID);
    }
    let mut pres = BTreeMap::new();
    let mut posts = BTreeMap::new();
    let mut bindings = Vec::new();
    for row in events {
        match row.get("kind").and_then(Value::as_str) {
            Some("actual-hook-response") if row["hook_event_name"] == "PreToolUse" => {
                pres.insert(field(row, "payload_digest")?, row);
            }
            Some("actual-hook-response") if row["hook_event_name"] == "PostToolUse" => {
                posts.insert(field(row, "tool_call_id")?, row);
            }
            Some("actual-contained-output-binding") => bindings.push(row),
            _ => {}
        }
    }
    let consumed: Vec<&Value> = contained
        .iter()
        .filter(|row| row["kind"] == "contained-route-consumed")
        .collect();
    if bindings.len() != consumed.len() || bindings.len() != results.len() {
        return Err(COVERAGE);
    }
    let mut by_payload: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
    for result in results {
        by_payload
            .entry(field(result, "payload_digest")?)
            .or_default()
            .push(result);
    }
    let mut seen = BTreeSet::new();
    for row in bindings {
        let object = row.as_object().ok_or(RECORD)?;
        if object.len() != BINDING_KEYS.len()
            || !BINDING_KEYS.iter().all(|key| object.contains_key(*key))
            || row["schema"] != "controller-contained-output.v1"
            || !row["sdk_output_sha256"].as_str().is_some_and(is_sha256)
        {
            return Err(RECORD);
        }
        let pre_digest = field(row, "pre_payload_digest")?;
        let call = field(row, "tool_call_id")?;
        let pre = pres.get(pre_digest).ok_or(TRANSPLANTED)?;
        let post = posts.get(call).ok_or(TRANSPLANTED)?;
        let matching = by_payload.get(pre_digest).ok_or(TRANSPLANTED)?;
        if matching.len() != 1 || pre["tool_call_id"] != call || !seen.insert(call) {
            return Err(TRANSPLANTED);
        }
        let expected = captured_contained_output(matching[0])?;
        if row["result_digest"] != expected["result_digest"]
            || row["output_sha256"] != expected["output_sha256"]
            || row["output_sha256"] != post["actual_output_sha256"]
            || row["payload_digest"] != post["payload_digest"]
        {
            return Err(POST);
        }
    }
    let mut consumed_calls = BTreeSet::new();
    for row in consumed {
        let pre = pres.get(field(row, "payload_digest")?).ok_or(CONSUMED)?;
        consumed_calls.insert(field(pre, "tool_call_id")?);
    }
    if seen != consumed_calls {
        return Err(CONSUMED);
    }
    Ok(seen.len())
}
