//! The `harness_mcp_discovery` `remote_scan` op: which harnesses a remote MCP
//! scan read in full, which `remote_scan_harnesses` in
//! `guard/adapters/harness_mcp_remote.py` decided before it moved here.
//!
//! Reconciliation forgets the remote declarations a scan did not list, so it
//! may only run for harnesses the scan covered. A list that reached its cap
//! may have stopped short of some declarations, so it covers none.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use super::super::{bounded_list, exact_keys};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const SCAN_KEYS: [&str; 4] = ["op", "harnesses", "remote_count", "limit"];

/// `remote_scan_harnesses`: the sorted distinct `harnesses` the detections
/// named, or null when `remote_count` reached `limit`.
pub(super) fn remote_scan(map: &Map<String, Value>) -> KindResult {
    exact_keys(map, &SCAN_KEYS)?;
    let count = number(map, "remote_count")?;
    let limit = number(map, "limit")?;
    let harnesses = bounded_list(map.get("harnesses").ok_or(ERR_INVALID)?)?
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or(ERR_INVALID))
        .collect::<Result<BTreeSet<String>, &'static str>>()?;
    if count >= limit {
        return Ok(json!({ "harnesses": Value::Null }));
    }
    // A UTF-8 string orders by code point, as Python's `sorted` does.
    Ok(json!({ "harnesses": harnesses }))
}

fn number(map: &Map<String, Value>, key: &str) -> Result<u64, &'static str> {
    map.get(key).and_then(Value::as_u64).ok_or(ERR_INVALID)
}

#[cfg(test)]
#[path = "harness_mcp_scan_tests.rs"]
mod tests;
