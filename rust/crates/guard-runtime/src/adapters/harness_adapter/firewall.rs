//! The MCP and skill firewall metadata a harness's `detect` answer carries.
//!
//! `enrich_artifact_with_mcp_skill_firewall` attached it in the Guard process
//! after every detection. The runtime now attaches it to the artifacts it
//! detected, so one answer carries the finished artifacts: a skill document is
//! read here as a text-mode read (invalid UTF-8 replaced, line endings folded
//! to `\n`), and an MCP server or tool call projects from its own fields.

use std::path::Path;

use guard_command::mcp_skill_firewall::evaluate_firewall_evidence;
use guard_contracts::McpFirewallInputV1;
use serde_json::{json, Map, Value};

use super::{Failure, Step};

fn text(item: &Map<String, Value>, key: &str) -> Step<String> {
    item.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Failure::Invalid)
}

fn optional(item: &Map<String, Value>, key: &str) -> Step<Value> {
    match item.get(key) {
        Some(Value::Null) | None => Ok(Value::Null),
        Some(Value::String(value)) => Ok(json!(value)),
        Some(_) => Err(Failure::Invalid),
    }
}

/// A text-mode read: invalid UTF-8 replaced, `\r\n` and `\r` folded to `\n`.
fn read_text(path: &str) -> Option<String> {
    let bytes = std::fs::read(Path::new(path)).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    Some(text.replace("\r\n", "\n").replace('\r', "\n"))
}

fn record(value: Option<&Value>) -> Value {
    match value {
        Some(Value::Object(record)) => Value::Object(record.clone()),
        _ => Value::Null,
    }
}

fn env_pairs(value: Option<&Value>) -> Value {
    let Some(Value::Object(env)) = value else {
        return json!([]);
    };
    Value::Array(
        env.iter()
            .filter_map(|(key, item)| item.as_str().map(|item| json!([key, item])))
            .collect(),
    )
}

fn input(item: &Map<String, Value>, metadata: &Map<String, Value>) -> Step<Value> {
    let server_name = match metadata.get("server_name") {
        None => Value::Null,
        Some(Value::String(name)) => json!(name),
        Some(_) => return Err(Failure::Invalid),
    };
    Ok(json!({
        "artifact_type": text(item, "artifact_type")?,
        "name": text(item, "name")?,
        "command": optional(item, "command")?,
        "config_path": text(item, "config_path")?,
        "transport": optional(item, "transport")?,
        "has_url": item.get("url").and_then(Value::as_str).is_some_and(|url| !url.is_empty()),
        "args": item.get("args").cloned().unwrap_or_else(|| json!([])),
        "publisher": optional(item, "publisher")?,
        "server_name": server_name,
        "env": env_pairs(metadata.get("env")),
        "mcp_server_identity": record(metadata.get("mcp_server_identity")),
        "mcp_tool_identity": record(metadata.get("mcp_tool_identity")),
        "tool_schema": metadata.get("tool_schema").cloned().unwrap_or(Value::Null),
        "tool_description": metadata.get("tool_description").cloned().unwrap_or(Value::Null),
        "tool_names": metadata.get("tool_names").cloned().unwrap_or(Value::Null),
        "tool_names_camel": metadata.get("toolNames").cloned().unwrap_or(Value::Null),
        "skill_content": Value::Null,
    }))
}

/// Whether the artifact has the fields a firewall projection reads.
fn can_carry(item: &Map<String, Value>, metadata: &Map<String, Value>) -> bool {
    let command = item.get("command").and_then(Value::as_str);
    if item.get("artifact_type").and_then(Value::as_str) == Some("mcp_server") {
        return command.is_some_and(|command| !command.trim().is_empty());
    }
    if !item.get("command").is_none_or(Value::is_null) {
        return true;
    }
    metadata
        .get("mcp_server_identity")
        .is_some_and(Value::is_object)
        && metadata
            .get("mcp_tool_identity")
            .is_some_and(Value::is_object)
}

fn patch(request: Value) -> Step<Option<Map<String, Value>>> {
    let input: McpFirewallInputV1 =
        serde_json::from_value(request).map_err(|_| Failure::Invalid)?;
    let answer =
        evaluate_firewall_evidence(&input).map_err(|code| Failure::Runtime(code.to_owned()))?;
    match answer.get("metadata_patch") {
        Some(Value::Null) => Ok(None),
        Some(Value::Object(patch)) => Ok(Some(patch.clone())),
        _ => Err(Failure::Runtime(
            "native_mcp_tool_evidence_invalid_result".to_owned(),
        )),
    }
}

fn enrich_one(artifact: &mut Value) -> Step<()> {
    let Value::Object(item) = artifact else {
        return Err(Failure::Invalid);
    };
    let metadata = match item.get("metadata") {
        Some(Value::Object(metadata)) => metadata.clone(),
        _ => return Err(Failure::Invalid),
    };
    let request = match item.get("artifact_type").and_then(Value::as_str) {
        Some("skill") => {
            // An unreadable document has no identity to project.
            let Some(content) = read_text(&text(item, "config_path")?) else {
                return Ok(());
            };
            json!({
                "artifact_type": "skill",
                "name": text(item, "name")?,
                "command": null,
                "config_path": text(item, "config_path")?,
                "transport": null,
                "has_url": false,
                "args": [],
                "publisher": optional(item, "publisher")?,
                "server_name": null,
                "env": [],
                "mcp_server_identity": null,
                "mcp_tool_identity": null,
                "tool_schema": null,
                "tool_description": null,
                "tool_names": null,
                "tool_names_camel": null,
                "skill_content": content,
            })
        }
        Some("mcp_server" | "tool_call") if can_carry(item, &metadata) => input(item, &metadata)?,
        _ => return Ok(()),
    };
    let Some(patch) = patch(request)? else {
        return Ok(());
    };
    let mut merged = metadata;
    merged.extend(patch);
    item.insert("metadata".to_owned(), Value::Object(merged));
    Ok(())
}

/// The answer with every artifact's firewall metadata attached.
pub(super) fn enrich(mut answer: Value) -> Step<Value> {
    let artifacts = answer
        .get_mut("artifacts")
        .and_then(Value::as_array_mut)
        .ok_or(Failure::Invalid)?;
    for artifact in artifacts {
        enrich_one(artifact)?;
    }
    Ok(answer)
}
