//! `observed_mcp_discovery` — groups the MCP tools a harness was seen calling
//! into the connectors the dashboard offers for review.
//!
//! The scan reads the labels `observed_mcp_history` projects from paused
//! requests and receipts, parses each into a connector namespace and a tool
//! name, and answers at most `MAX_OBSERVED_MCP_SERVERS` connectors with at most
//! `MAX_OBSERVED_MCP_TOOLS` tools each, in the order the history first names
//! them. Each connector carries the newest history time it was seen at, so a
//! replayed connector ages out on its own clock. Recording the connectors
//! stays with the caller: discovery never grants authority.

use std::collections::{BTreeMap, HashMap, HashSet};

use guard_policy_snapshot::normalized_harness_selector;
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::{
    observed_mcp_history, observed_mcp_tool, token, ObservedTool, FLATTENED_NAME_HARNESSES,
    MAX_NAMESPACE_CHARS, MAX_NAME_CHARS, MAX_TOOL_NAME_CHARS,
};
use crate::cloud_request_text::py_truthy;
use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_local_cli::parse_utc;
use crate::guard_store_local_mcp_observation::later_timestamp;

/// `MAX_OBSERVED_MCP_RECEIPTS`: history rows read from each source.
const MAX_OBSERVED_MCP_RECEIPTS: i64 = 2000;
/// `MAX_OBSERVED_MCP_SERVERS`: connectors one scan offers.
const MAX_OBSERVED_MCP_SERVERS: usize = 40;
/// `MAX_OBSERVED_MCP_TOOLS`: `min(128, MAX_LOCAL_CLI_COMMANDS - 1)`, so the
/// catalog keeps room for its "other tools" fallback.
const MAX_OBSERVED_MCP_TOOLS: usize = 100;
const CODEX_APPS_NAMESPACE: &str = "mcp__codex_apps__";
const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");

/// The server names each harness is configured with, by canonical harness.
type Configured<'a> = HashMap<&'a str, Vec<&'a str>>;

/// One parsed tool: the connector it belongs to and the name it is listed by.
struct Tool {
    harness: String,
    namespace: String,
    name: String,
    qualified_name: String,
    server_name: String,
}

impl Tool {
    /// `observed_mcp_tool` keeps the boundary in the namespace, so the tool
    /// name is what follows it and the server is its last segment.
    fn parsed(tool: ObservedTool) -> Self {
        let name = tool.qualified_name[tool.namespace.len()..].to_owned();
        let inner = match tool.namespace.strip_prefix(CODEX_APPS_NAMESPACE) {
            Some(app) if !app.is_empty() => app,
            _ => &tool.namespace["mcp__".len()..],
        };
        let server = &inner[..inner.len() - "__".len()];
        let server_name = if server == "codex_apps" {
            "Codex Apps".to_owned()
        } else {
            server.to_owned()
        };
        Self {
            harness: tool.harness,
            namespace: tool.namespace,
            name,
            qualified_name: tool.qualified_name,
            server_name,
        }
    }
}

/// A connector in first-seen order, with its tools as `(name, qualified_name)`.
struct Connector {
    harness: String,
    namespace: String,
    server_name: String,
    tools: Vec<(String, String)>,
}

fn configured_servers<'a>(args: &Args<'a>) -> StoreResult<Configured<'a>> {
    let mut configured = HashMap::new();
    for (harness, names) in args.object("configured_servers")? {
        let names = names
            .as_array()
            .ok_or(INVALID)?
            .iter()
            .map(|name| name.as_str().ok_or(INVALID))
            .collect::<StoreResult<Vec<_>>>()?;
        configured.insert(harness.as_str(), names);
    }
    Ok(configured)
}

/// `str.strip().lower()`, then the canonical selector, as `observed_mcp_tool`
/// reads a harness.
fn canonical_harness(harness: &str) -> Option<String> {
    let harness = harness
        .trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c))
        .to_lowercase();
    if !token(&harness) {
        return None;
    }
    normalized_harness_selector(&harness)
}

/// `_flattened_tool`: Oh My Pi joins server and tool with one underscore
/// after turning the server's dashes into underscores, so only the servers the
/// harness is configured with say where the server ends. Names that flatten
/// alike cannot be told apart, so neither owns the call, and the longest
/// configured name is tried first.
fn configured_flattened(harness: &str, tool_name: &str, configured: &[&str]) -> Option<Tool> {
    let rest = tool_name.strip_prefix("mcp__")?;
    let mut owners: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for name in configured.iter().copied().filter(|name| token(name)) {
        let names = owners.entry(name.replace('-', "_")).or_default();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let mut candidates: Vec<(String, &str)> = owners
        .into_iter()
        .filter(|(flat, names)| names.len() == 1 && !flat.ends_with('_'))
        .map(|(flat, names)| (flat, names[0]))
        .collect();
    candidates.sort_by(|left, right| {
        right
            .0
            .len()
            .cmp(&left.0.len())
            .then_with(|| left.0.cmp(&right.0))
    });
    for (flat, name) in candidates {
        let Some(name_part) = rest
            .strip_prefix(flat.as_str())
            .and_then(|tail| tail.strip_prefix('_'))
        else {
            continue;
        };
        // The namespace keeps the configured spelling, as a configured remote
        // server's does, so both resolve to one connector.
        let namespace = format!("mcp__{name}__");
        if name_part.starts_with('_')
            || name_part.chars().count() > MAX_NAME_CHARS
            || namespace.chars().count() > MAX_NAMESPACE_CHARS
            || !token(name_part)
        {
            continue;
        }
        return Some(Tool {
            harness: harness.to_owned(),
            namespace,
            name: name_part.to_owned(),
            qualified_name: tool_name.to_owned(),
            server_name: name.to_owned(),
        });
    }
    None
}

/// `observed_mcp_tool(harness, label, configured)`.
fn observed_tool(harness: &str, tool_name: &str, configured: &Configured<'_>) -> Option<Tool> {
    let canonical = canonical_harness(harness)?;
    let rest = tool_name.strip_prefix("mcp__")?;
    if tool_name.chars().count() > MAX_TOOL_NAME_CHARS {
        return None;
    }
    // A `__` after the server is the boundary every harness marks itself, so
    // it keeps its established parse; only an unmarked name needs the servers.
    if FLATTENED_NAME_HARNESSES.contains(&canonical.as_str()) && !rest.contains("__") {
        let names = configured
            .get(canonical.as_str())
            .map_or(&[][..], Vec::as_slice);
        if let Some(tool) = configured_flattened(&canonical, tool_name, names) {
            return Some(tool);
        }
    }
    observed_mcp_tool(harness, tool_name).map(Tool::parsed)
}

/// `_receipt_tools`: the label is the command text without its `tool:` prefix
/// when it carries one, and the artifact name otherwise.
fn record_tool(record: &Value, configured: &Configured<'_>) -> Option<Tool> {
    let label = match record.get("raw_command_text").and_then(Value::as_str) {
        Some(raw) if raw.starts_with("tool:") => Some(&raw["tool:".len()..]),
        _ => record.get("artifact_name").and_then(Value::as_str),
    }?;
    observed_tool(record.get("harness")?.as_str()?, label, configured)
}

fn rows(history: &Value, key: &str) -> Vec<Value> {
    history
        .get(key)
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .take(MAX_OBSERVED_MCP_RECEIPTS as usize)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// `tools_from_receipts`: one tool per harness and qualified name, in the
/// order the batch first names it.
fn batch_tools(records: &[Value], configured: &Configured<'_>) -> Vec<Tool> {
    let mut seen = HashSet::new();
    let mut tools = Vec::new();
    for tool in records
        .iter()
        .filter_map(|record| record_tool(record, configured))
    {
        if seen.insert((tool.harness.clone(), tool.qualified_name.clone())) {
            tools.push(tool);
        }
    }
    tools
}

/// `_latest_seen_by_connector`: the newest history time for each connector.
/// A retried request refreshes `last_seen_at`, not `created_at`, so the first
/// non-empty key is the one read.
fn latest_seen(
    batches: [(&[Value], &[&str]); 2],
    configured: &Configured<'_>,
) -> HashMap<(String, String), Value> {
    let mut latest: HashMap<(String, String), Value> = HashMap::new();
    for (records, time_keys) in batches {
        for record in records {
            let Some(tool) = record_tool(record, configured) else {
                continue;
            };
            let stamp = time_keys
                .iter()
                .filter_map(|key| record.get(*key))
                .find(|value| py_truthy(value));
            let Some(stamp) = stamp.and_then(Value::as_str) else {
                continue;
            };
            if parse_utc(&Value::from(stamp)).is_none() {
                continue;
            }
            let key = (tool.harness, tool.namespace);
            let next = later_timestamp(latest.get(&key), stamp);
            latest.insert(key, next);
        }
    }
    latest
}

pub(crate) fn observed_mcp_discovery(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let configured = configured_servers(args)?;
    let mut limit = Map::new();
    limit.insert("limit".to_owned(), Value::from(MAX_OBSERVED_MCP_RECEIPTS));
    let history = observed_mcp_history(connection, &Args(&limit))?;
    let approvals = rows(&history, "approvals");
    let receipts = rows(&history, "receipts");
    let latest = latest_seen(
        [
            (approvals.as_slice(), &["last_seen_at", "created_at"][..]),
            (receipts.as_slice(), &["timestamp"][..]),
        ],
        &configured,
    );
    let mut connectors: Vec<Connector> = Vec::new();
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    let observed = batch_tools(&approvals, &configured)
        .into_iter()
        .chain(batch_tools(&receipts, &configured));
    for tool in observed {
        let key = (tool.harness.clone(), tool.namespace.clone());
        let slot = match index.get(&key) {
            Some(slot) => *slot,
            None if connectors.len() >= MAX_OBSERVED_MCP_SERVERS => continue,
            None => {
                index.insert(key, connectors.len());
                connectors.push(Connector {
                    harness: tool.harness.clone(),
                    namespace: tool.namespace.clone(),
                    server_name: tool.server_name.clone(),
                    tools: Vec::new(),
                });
                connectors.len() - 1
            }
        };
        let tools = &mut connectors[slot].tools;
        if tools.len() < MAX_OBSERVED_MCP_TOOLS
            && !tools
                .iter()
                .any(|(_, qualified)| *qualified == tool.qualified_name)
        {
            tools.push((tool.name, tool.qualified_name));
        }
    }
    let connectors: Vec<Value> = connectors
        .into_iter()
        .map(|connector| {
            let key = (connector.harness.clone(), connector.namespace.clone());
            json!({
                "harness": connector.harness,
                "namespace": connector.namespace,
                "server_name": connector.server_name,
                "seen_at": latest.get(&key).cloned().unwrap_or(Value::Null),
                "tools": connector
                    .tools
                    .into_iter()
                    .map(|(name, qualified_name)| json!({"name": name, "qualified_name": qualified_name}))
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(json!({ "connectors": connectors }))
}

#[cfg(test)]
#[path = "guard_store_observed_mcp_discovery_tests.rs"]
mod tests;
