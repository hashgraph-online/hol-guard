//! The `harness_mcp_discovery` `remote` and `remote_rank` ops: the remote MCP
//! servers a harness config declares, which `_remote_servers` in
//! `guard/adapters/harness_mcp_remote.py` parsed before they moved here. Guard
//! never connects to them.
//!
//! `remote` answers, in order, each candidate's connector, or null: the origin
//! Guard records for its URL and the tool namespace a call to its tools
//! carries on its harness, so a configured server and a used one are the same
//! connector. The caller sends candidates in batches, so a config that
//! declares thousands of servers stays under the request size limit.
//!
//! `remote_rank` takes every server `remote` answered, keeps the first per
//! connector, and answers their indices ordered by source label and server
//! name, at most `limit` of them.

use std::collections::HashSet;

use guard_contracts::python_strip;
use serde_json::{json, Map, Value};

use super::super::{bounded_list, exact_keys, text};
use crate::guard_store_observed_mcp::observed_mcp_tool;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const REMOTE_KEYS: [&str; 2] = ["op", "candidates"];
const CANDIDATE_KEYS: [&str; 3] = ["harness", "name", "url"];
const RANK_KEYS: [&str; 3] = ["op", "servers", "limit"];
const RANKED_KEYS: [&str; 4] = ["harness", "namespace", "server_name", "source_label"];

pub(super) fn remote(map: &Map<String, Value>) -> KindResult {
    exact_keys(map, &REMOTE_KEYS)?;
    let servers = bounded_list(map.get("candidates").ok_or(ERR_INVALID)?)?
        .iter()
        .map(candidate)
        .collect::<Result<Vec<Value>, &'static str>>()?;
    Ok(json!({ "servers": servers }))
}

/// `_remote_server`: the connector one declared server names, or null.
fn candidate(value: &Value) -> Result<Value, &'static str> {
    let fields = value.as_object().ok_or(ERR_INVALID)?;
    exact_keys(fields, &CANDIDATE_KEYS)?;
    let harness = text(fields, "harness")?;
    let url = text(fields, "url")?;
    // Harnesses put the server name in the tool namespace with every
    // character outside [A-Za-z0-9_-] replaced by `_`.
    let name: String = python_strip(text(fields, "name")?)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let Some(origin) = guard_command::remote_mcp_origin(url) else {
        return Ok(Value::Null);
    };
    if name.trim_matches('_').is_empty() {
        return Ok(Value::Null);
    }
    // A name whose calls nest another server under it (`codex_apps`) names
    // no single connector, so it is left to the calls that use it.
    let tool = observed_mcp_tool(harness, &format!("mcp__{name}__tool"));
    let nested = observed_mcp_tool(harness, &format!("mcp__{name}__server__tool"));
    let (Some(tool), Some(nested)) = (tool, nested) else {
        return Ok(Value::Null);
    };
    if nested.namespace != tool.namespace {
        return Ok(Value::Null);
    }
    let server_name = &tool.namespace["mcp__".len()..tool.namespace.len() - "__".len()];
    Ok(json!({
        "origin": origin,
        "harness": tool.harness,
        "namespace": tool.namespace,
        "name": &tool.qualified_name[tool.namespace.len()..],
        "qualified_name": tool.qualified_name,
        "server_name": server_name,
    }))
}

pub(super) fn remote_rank(map: &Map<String, Value>) -> KindResult {
    exact_keys(map, &RANK_KEYS)?;
    let limit = map
        .get("limit")
        .and_then(Value::as_u64)
        .and_then(|limit| usize::try_from(limit).ok())
        .ok_or(ERR_INVALID)?;
    let mut connectors = HashSet::new();
    let mut kept = Vec::new();
    for (index, value) in bounded_list(map.get("servers").ok_or(ERR_INVALID)?)?
        .iter()
        .enumerate()
    {
        let fields = value.as_object().ok_or(ERR_INVALID)?;
        exact_keys(fields, &RANKED_KEYS)?;
        let connector = (text(fields, "harness")?, text(fields, "namespace")?);
        let label = text(fields, "source_label")?.to_lowercase();
        let server = text(fields, "server_name")?.to_lowercase();
        if connectors.insert(connector) {
            kept.push((label, server, index));
        }
    }
    kept.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
    let order: Vec<usize> = kept
        .into_iter()
        .take(limit)
        .map(|(_, _, index)| index)
        .collect();
    Ok(json!({ "order": order }))
}

#[cfg(test)]
#[path = "harness_mcp_remote_tests.rs"]
mod tests;
