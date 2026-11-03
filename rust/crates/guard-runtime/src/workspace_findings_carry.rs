//! `workspace_findings_carry` runner-authority kind: which earlier findings a
//! partial workspace assessment keeps listed because the detector that found
//! them did not finish (the loop in
//! `workspace_assessment_carry.carry_unchecked_findings` before it moved
//! here). Python keeps the store reads and builds the recorded outcome.
//!
//! The request carries the new run's `coverage` and `findings`, the earlier
//! run's `findings` and `run_id`, the `settled` flags for the earlier package
//! findings, and the store's `max_findings` and `byte_budget` bounds. The
//! answer is `{"carried": null}` when nothing changes; otherwise it lists the
//! carried findings, in order, and the coverage `reasons` the run records.
//!
//! A finding's size is its stored `json.dumps(sort_keys=True)` text plus one
//! separator byte, so the bound matches the stored findings array.

use serde_json::{json, Map, Value};

use crate::guard_store_json::{dumps_sorted, py_str};
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 7] = [
    "coverage",
    "findings",
    "earlier",
    "run_id",
    "settled",
    "max_findings",
    "byte_budget",
];
/// A detector in one of these states read the worktree again, so its
/// earlier findings are settled rather than carried.
const RECHECKED: [&str; 2] = ["complete", "no_inputs"];
const CARRIED_FINDING_CAP: &str = "carried_finding_cap";

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    if fields.len() != KEYS.len() || !KEYS.iter().all(|key| fields.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let coverage = fields
        .get("coverage")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let findings = objects(fields.get("findings"))?;
    let settled = fields
        .get("settled")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|flag| flag.as_bool().ok_or(ERR_INVALID))
        .collect::<Result<Vec<bool>, _>>()?;
    let max_findings = bound(fields.get("max_findings"))?;
    let byte_budget = bound(fields.get("byte_budget"))?;
    let (Some(detectors), Some(earlier)) = (
        coverage.get("detectors").and_then(Value::as_object),
        fields.get("earlier").and_then(Value::as_array),
    ) else {
        return Ok(json!({"carried": null}));
    };
    let run_id = fields.get("run_id").cloned().unwrap_or(Value::Null);
    let mut seen: Vec<Value> = findings.iter().map(|item| finding_id(item)).collect();
    let mut used = 0u64;
    for item in &findings {
        used = used.saturating_add(size(item)?);
    }
    let mut count = findings.len() as u64;
    let mut carried = Vec::new();
    let mut truncated = false;
    for (index, item) in earlier.iter().enumerate() {
        let Some(item) = item.as_object() else {
            continue;
        };
        if seen.contains(&finding_id(item)) || settled.get(index).copied().unwrap_or(false) {
            continue;
        }
        let status = item
            .get("detector")
            .and_then(Value::as_str)
            .and_then(|detector| detectors.get(coverage_key(detector)))
            .and_then(Value::as_str);
        if status.is_none_or(|status| RECHECKED.contains(&status)) {
            continue;
        }
        let mut entry = item.clone();
        let origin = item
            .get("carried_from_run_id")
            .filter(|origin| truthy(origin))
            .unwrap_or(&run_id)
            .clone();
        entry.insert("carried_from_run_id".to_owned(), origin);
        let entry_size = size(&entry)?;
        if count >= max_findings || used.saturating_add(entry_size) > byte_budget {
            truncated = true;
            continue;
        }
        seen.push(finding_id(&entry));
        used = used.saturating_add(entry_size);
        count = count.saturating_add(1);
        carried.push(Value::Object(entry));
    }
    if carried.is_empty() && !truncated {
        return Ok(json!({"carried": null}));
    }
    let mut reasons = match coverage.get("reasons") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|reason| py_str(reason).ok_or(ERR_INVALID))
            .collect::<Result<Vec<String>, _>>()?,
        _ => Vec::new(),
    };
    if truncated && !reasons.iter().any(|reason| reason == CARRIED_FINDING_CAP) {
        reasons.push(CARRIED_FINDING_CAP.to_owned());
    }
    Ok(json!({"carried": carried, "reasons": reasons}))
}

fn objects(value: Option<&Value>) -> Result<Vec<&Map<String, Value>>, &'static str> {
    value
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|item| item.as_object().ok_or(ERR_INVALID))
        .collect()
}

fn bound(value: Option<&Value>) -> Result<u64, &'static str> {
    value.and_then(Value::as_u64).ok_or(ERR_INVALID)
}

/// The supply chain detector's findings and coverage name it differently.
fn coverage_key(detector: &str) -> &str {
    if detector == "supply_chain_local_v1" {
        "supply_chain"
    } else {
        detector
    }
}

fn finding_id(item: &Map<String, Value>) -> Value {
    item.get("finding_id").cloned().unwrap_or(Value::Null)
}

fn size(item: &Map<String, Value>) -> Result<u64, &'static str> {
    let text = dumps_sorted(&Value::Object(item.clone())).ok_or(ERR_INVALID)?;
    Ok((text.len() as u64).saturating_add(1))
}

/// Python truthiness, for the `or` that picks a finding's original run.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

#[cfg(test)]
#[path = "workspace_findings_carry_tests.rs"]
mod tests;
