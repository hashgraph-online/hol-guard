//! Pure one-use contained-route/result accounting from the Python runtime
//! custody reader. Supplied events are not authenticated here.

use crate::crypto::sha256;
use crate::{canonical_value, EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const MISMATCH: &str = "contained authorization/result is missing, duplicated or transplanted";

fn required<'a>(row: &'a Value, field: &str) -> Result<&'a str> {
    row[field].as_str().ok_or(EvidenceError::Invalid(MISMATCH))
}

fn count(map: &mut BTreeMap<String, usize>, key: &str) {
    *map.entry(key.to_owned()).or_default() += 1;
}

/// Recompute the prepared, consumed and finished token relation and bind each
/// consumed payload and finished result to a supplied execution row. A caller
/// must separately authenticate the signed runtime and observe process effects.
pub fn verify_contained_route_accounting(builtin: &Value, plane: &Value) -> Result<Value> {
    let events = builtin["contained_transport_observations"]
        .as_array()
        .filter(|rows| rows.len() <= 4096)
        .ok_or(EvidenceError::Invalid(MISMATCH))?;
    let executions = plane["executions"]
        .as_array()
        .filter(|rows| rows.len() <= 128)
        .ok_or(EvidenceError::Invalid(MISMATCH))?;
    let mut prepared = BTreeSet::new();
    let mut consumed_tokens = BTreeMap::new();
    let mut finished_tokens = BTreeMap::new();
    let mut consumed_payloads = BTreeMap::new();
    let mut executed_payloads = BTreeMap::new();
    let mut finished_results = BTreeMap::new();
    let mut executed_results = BTreeMap::new();
    let mut consumed_count = 0;
    for event in events {
        match event["kind"].as_str() {
            Some("contained-route-prepared") => {
                prepared.insert(required(event, "token_digest")?.to_owned());
            }
            Some("contained-route-consumed") => {
                count(&mut consumed_tokens, required(event, "token_digest")?);
                count(&mut consumed_payloads, required(event, "payload_digest")?);
                consumed_count += 1;
            }
            Some("actual-contained-result") => {
                count(&mut finished_tokens, required(event, "token_digest")?);
                count(&mut finished_results, required(event, "result_digest")?);
            }
            _ => {}
        }
    }
    for execution in executions {
        count(
            &mut executed_payloads,
            required(execution, "payload_digest")?,
        );
        count(&mut executed_results, &sha256(&canonical_value(execution)?));
    }
    if consumed_tokens.values().any(|count| *count != 1)
        || !consumed_tokens.keys().all(|token| prepared.contains(token))
        || consumed_tokens != finished_tokens
        || consumed_payloads != executed_payloads
        || finished_results != executed_results
    {
        return Err(EvidenceError::Invalid(MISMATCH));
    }
    Ok(json!({"matched_routes": consumed_count, "execution_eligible": false}))
}
