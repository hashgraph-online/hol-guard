//! The Composio seam of the native hook evidence writer.
//!
//! Ports `runtime/observed_mcp_tools.py` (the `observed_mcp_tool` parser),
//! `runtime/composio_discovery.py` and `runtime/composio_workflows.py`: the
//! three readers the writer runs over an MCP tool response before any of it
//! reaches the store.
//!
//! All three are provider-result evidence, never an authenticated inventory.
//! A namespace parsed out of a tool name is an identity on one harness, not a
//! server endpoint, and neither a discovery schema nor a workflow proposal
//! grants a tool any authority it did not already have.
//!
//! The readers live here rather than beside the rest of the writer because
//! they need the resident's own Composio routing contract
//! ([`tool_role`]) and the canonical harness selector, and
//! `guard-command` cannot reach either.

use std::collections::BTreeSet;
use std::fmt;

use guard_command::hook_evidence_writer::{
    ComposioActionSchema, ComposioApi, ComposioWorkflowProposal, ObservedCliIdentity,
    ObservedMcpServerIdentity, ObservedMcpTool,
};
use guard_command::mcp_decision::build_mcp_server_identity;
use guard_policy_snapshot::normalized_harness_selector;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::mcp_tool_policy_composio::{tool_role, valid_slug, Role};

/// `observed_mcp_tools.OBSERVED_MCP_PREFIX` (:28).
const OBSERVED_MCP_PREFIX: &str = "observed-mcp:";
/// `composio_discovery._MAX_BYTES` (:18), shared with the workflow reader.
const MAX_BYTES: usize = 1_000_000;
/// `composio_discovery._MAX_ACTIONS` (:19).
const MAX_ACTIONS: usize = 1_000;
/// `composio_workflows` result, slug and step bounds (:36, :44, :50, :67).
const MAX_RESULTS: usize = 50;
/// `composio_workflows` step length bound (:50).
const MAX_STEP_CHARS: usize = 4_096;
/// `composio_discovery` description retention bound (:72).
const MAX_DESCRIPTION_CHARS: usize = 2_000;

/// The native Composio seam the evidence writer is built with.
pub(crate) struct NativeComposio;

impl ComposioApi for NativeComposio {
    fn observed_mcp_tool(&self, harness: &str, tool_name: &str) -> Option<ObservedMcpTool> {
        observed_mcp_tool(harness, tool_name)
    }

    fn composio_discovered_actions(
        &self,
        tool_name: &str,
        response: &Value,
    ) -> Option<Vec<ComposioActionSchema>> {
        composio_discovered_actions(tool_name, response)
    }

    fn composio_workflow_proposals(
        &self,
        tool_name: &str,
        response: &Value,
    ) -> Option<Vec<ComposioWorkflowProposal>> {
        composio_workflow_proposals(tool_name, response)
    }
}

/// `observed_mcp_tool` (:69): parse a fully qualified MCP name and keep the
/// connector boundary it names.
pub(crate) fn observed_mcp_tool(harness: &str, tool_name: &str) -> Option<ObservedMcpTool> {
    let lowered = harness.trim().to_lowercase();
    if !is_token(&lowered) || !tool_name.starts_with("mcp__") || tool_name.chars().count() > 160 {
        return None;
    }
    let harness = normalized_harness_selector(&lowered)?;
    let parts: Vec<&str> = tool_name[5..].split("__").collect();
    if parts.len() < 2 || parts.iter().any(|part| !is_token(part)) {
        return None;
    }
    // A Codex app carries its own server segment, so the connector boundary
    // sits one segment further in.
    let split = if parts[0] == "codex_apps" && parts.len() >= 3 {
        2
    } else {
        1
    };
    if parts[split..].join("__").chars().count() > 120 {
        return None;
    }
    let namespace = format!("mcp__{}__", parts[..split].join("__"));
    if namespace.chars().count() > 155 {
        return None;
    }
    let server_name = parts[split - 1].to_owned();
    let server = build_mcp_server_identity(
        "",
        &format!("{OBSERVED_MCP_PREFIX}{harness}:{namespace}"),
        &[],
        "observed",
        None::<&Map<String, Value>>,
        &[],
    );
    // `UnlistedCliIdentity` (:60-66) — the grant the connector binds.
    let identity = ObservedCliIdentity {
        cli_id: format!("local-cli.mcp-{}", &server.identity_hash[..16]),
        name: server_name,
        kind: "executable".to_owned(),
        identity_hash: server.identity_hash.clone(),
        example_label: namespace,
        interpreter_name: None,
    };
    Some(ObservedMcpTool {
        harness,
        qualified_name: tool_name.to_owned(),
        identity,
        server: ObservedMcpServerIdentity {
            identity_hash: server.identity_hash,
            command: Some(server.command),
            args_hash: server.args_hash,
        },
    })
}

/// `composio_discovered_actions` (:32): accept only the observed successful
/// response contract, never arbitrary nested JSON.
pub(crate) fn composio_discovered_actions(
    tool_name: &str,
    response: &Value,
) -> Option<Vec<ComposioActionSchema>> {
    if tool_role(tool_name) != Some(Role::Discovery) {
        return None;
    }
    let data = successful_data(&response_object(response)?)?;
    let schemas = data.get("tool_schemas")?.as_object()?;
    if schemas.is_empty() || schemas.len() > MAX_ACTIONS {
        return None;
    }
    let mut actions = Vec::with_capacity(schemas.len());
    let mut byte_count: usize = 0;
    for (key, entry) in schemas {
        let entry = entry.as_object()?;
        let slug = entry.get("tool_slug")?.as_str()?;
        let toolkit = entry.get("toolkit")?.as_str()?;
        let description = match entry.get("description") {
            None => "",
            Some(value) => value.as_str()?,
        };
        let full_schema = entry.get("hasFullSchema")?.as_bool()?;
        let raw_schema = entry.get("input_schema")?;
        let schema = raw_schema.as_object()?;
        if !valid_slug(slug)
            || key != slug
            || !valid_slug(toolkit)
            || !bounded_json_tree(raw_schema)
        {
            return None;
        }
        let mut encoded = Vec::new();
        guard_contracts::write_canonical_json(raw_schema, &mut encoded).ok()?;
        // Key order does not change the encoding's length, so the sorted
        // writer measures the same budget Python's insertion order does.
        let description: String = description.chars().take(MAX_DESCRIPTION_CHARS).collect();
        byte_count += encoded.len() + description.len() + slug.len() + toolkit.len();
        if byte_count > MAX_BYTES {
            return None;
        }
        actions.push(ComposioActionSchema {
            toolkit: toolkit.to_owned(),
            tool_slug: slug.to_owned(),
            description,
            input_schema: schema.clone(),
            full_schema,
        });
    }
    Some(actions)
}

/// `composio_workflow_proposals` (:21): suggested action dependencies from a
/// Composio search, never an MCP Skills declaration.
pub(crate) fn composio_workflow_proposals(
    tool_name: &str,
    response: &Value,
) -> Option<Vec<ComposioWorkflowProposal>> {
    if tool_role(tool_name) != Some(Role::Discovery) {
        return None;
    }
    let data = successful_data(&response_object(response)?)?;
    let empty = Vec::new();
    let results = match data.get("results") {
        None => &empty,
        Some(value) => value.as_array()?,
    };
    if results.len() > MAX_RESULTS {
        return None;
    }
    let mut proposals: Vec<ComposioWorkflowProposal> = Vec::new();
    for result in results {
        let result = result.as_object()?;
        let primary = slugs(result.get("primary_tool_slugs"))?;
        let supporting = slugs(result.get("related_tool_slugs"))?;
        let union: BTreeSet<&String> = primary.iter().chain(supporting.iter()).collect();
        if union.len() > MAX_RESULTS {
            return None;
        }
        let guidance_present = match result.get("recommended_plan_steps") {
            None | Some(Value::Null) => false,
            Some(steps) => {
                let steps = steps.as_array()?;
                if steps.len() > MAX_RESULTS
                    || steps.iter().any(|step| {
                        step.as_str()
                            .is_none_or(|step| step.chars().count() > MAX_STEP_CHARS)
                    })
                {
                    return None;
                }
                !steps.is_empty()
            }
        };
        // Do not retain use cases, plan text, account status, arguments or
        // session ids.
        if primary.is_empty() && supporting.is_empty() {
            continue;
        }
        let proposal = ComposioWorkflowProposal {
            supporting: supporting
                .iter()
                .filter(|slug| !primary.contains(slug))
                .cloned()
                .collect(),
            primary,
            guidance_present,
        };
        if !proposals.contains(&proposal) {
            proposals.push(proposal);
        }
    }
    Some(proposals)
}

/// The `data` object of a response both readers accept, or `None` for one
/// that reported an error or carried no result at all.
fn successful_data(value: &Value) -> Option<Map<String, Value>> {
    let value = value.as_object()?;
    if value.get("successful") != Some(&Value::Bool(true)) || !absent_or_null(value.get("error")) {
        return None;
    }
    let data = value.get("data")?.as_object()?;
    if data.contains_key("success") && data.get("success") != Some(&Value::Bool(true)) {
        return None;
    }
    if !absent_or_null(data.get("error")) {
        return None;
    }
    Some(data.clone())
}

fn absent_or_null(value: Option<&Value>) -> bool {
    matches!(value, None | Some(Value::Null))
}

/// `_slugs` (:65): deduplicated slugs in first-seen order, or `None` for a
/// list the contract does not accept. A missing key is an empty list.
fn slugs(value: Option<&Value>) -> Option<Vec<String>> {
    let Some(value) = value else {
        return Some(Vec::new());
    };
    let value = value.as_array()?;
    if value.len() > MAX_RESULTS {
        return None;
    }
    let mut kept: Vec<String> = Vec::with_capacity(value.len());
    for item in value {
        let slug = item.as_str()?;
        if !valid_slug(slug) {
            return None;
        }
        if !kept.iter().any(|seen| seen == slug) {
            kept.push(slug.to_owned());
        }
    }
    Some(kept)
}

/// `_response_object` (:83): the result envelope, unwrapped at most once.
fn response_object(response: &Value) -> Option<Value> {
    let response = response.as_object()?;
    if response.contains_key("isError") && response.get("isError") != Some(&Value::Bool(false)) {
        return None;
    }
    if response.contains_key("successful") {
        return Some(Value::Object(response.clone()));
    }
    if let Some(structured) = response.get("structuredContent") {
        if structured.is_object() {
            return Some(structured.clone());
        }
    }
    let content = response.get("content")?.as_array()?;
    if content.len() != 1 {
        return None;
    }
    let block = content.first()?.as_object()?;
    if block.get("type") != Some(&Value::String("text".to_owned())) {
        return None;
    }
    let text = block.get("text")?.as_str()?;
    if text.chars().count() > MAX_BYTES || text.len() > MAX_BYTES {
        return None;
    }
    parse_unique(text)
}

/// `_bounded_json_tree` (:112): bound the node count, depth, fan-out and
/// character total of a schema before anything is retained from it.
fn bounded_json_tree(value: &Value) -> bool {
    let mut pending: Vec<(&Value, usize)> = vec![(value, 0)];
    let mut nodes: usize = 0;
    let mut chars: usize = 0;
    while let Some((item, depth)) = pending.pop() {
        nodes += 1;
        if nodes > 20_000 || depth > 32 {
            return false;
        }
        match item {
            Value::Object(map) => {
                if map.len() > 2_000 {
                    return false;
                }
                chars += map.keys().map(|key| key.chars().count()).sum::<usize>();
                pending.extend(map.values().map(|child| (child, depth + 1)));
            }
            Value::Array(items) => {
                if items.len() > 2_000 {
                    return false;
                }
                pending.extend(items.iter().map(|child| (child, depth + 1)));
            }
            Value::String(text) => chars += text.chars().count(),
            Value::Number(number) => {
                if number.as_f64().is_none_or(|value| !value.is_finite()) {
                    return false;
                }
            }
            Value::Null | Value::Bool(_) => {}
        }
        if chars > MAX_BYTES {
            return false;
        }
    }
    true
}

/// `observed_mcp_tools._TOKEN` (:32).
fn is_token(value: &str) -> bool {
    (1..=120).contains(&value.chars().count())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

/// `json.loads(..., object_pairs_hook=_unique_object)` (:99): a document whose
/// objects reject a duplicate key, which `json.loads` would otherwise fold.
fn parse_unique(text: &str) -> Option<Value> {
    serde_json::from_str::<UniqueValue>(text)
        .ok()
        .map(|parsed| parsed.0)
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;

        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = Value;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
                Ok(Value::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
                Ok(Value::Number(value.into()))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
                Ok(Value::Number(value.into()))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
                Ok(Number::from_f64(value).map_or(Value::Null, Value::Number))
            }

            fn visit_str<E>(self, value: &str) -> Result<Value, E> {
                Ok(Value::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Value, E> {
                Ok(Value::String(value))
            }

            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }

            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
                let mut items = Vec::new();
                while let Some(UniqueValue(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Value::Array(items))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
                let mut kept = Map::new();
                while let Some((key, UniqueValue(value))) =
                    map.next_entry::<String, UniqueValue>()?
                {
                    if kept.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate metadata key"));
                    }
                    kept.insert(key, value);
                }
                Ok(Value::Object(kept))
            }
        }

        deserializer.deserialize_any(UniqueVisitor).map(UniqueValue)
    }
}

#[cfg(test)]
#[path = "hook_evidence_composio_tests.rs"]
mod tests;
