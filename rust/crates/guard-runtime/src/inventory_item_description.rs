//! `item_description` operation of the `inventory_export_redaction` kind: the
//! one-line description every exported inventory item carries
//! (`resolve_inventory_item_description`, before it moved here).
//!
//! The text an item supplies passes through the serializer rules and, when the
//! export knows the operator's home, the same command-text path redaction a
//! finding gets, so a description never carries what the rest of the export
//! masks. Text that redacts away entirely, or only to a redaction marker,
//! gives way to a sentence built from the item's kind.
//!
//! `{"op": "item_description", "harness": str, "item_kind": str,
//! "display_name": str, "publisher": str|null, "explicit_description":
//! str|null, "metadata_descriptions": [str|null; 4], "home_dir": str|null,
//! "workspace_dir": str|null, "cwd": str}` answers `{"description": str}`.
//! `metadata_descriptions` holds the item metadata's `description`,
//! `summary`, `pluginDescription` and `displayDescription` strings, in that
//! order of preference.

use std::path::Path;

use guard_command::inventory_path_redaction::safe_finding_text;
use guard_command::inventory_redaction::{is_safe_serialized_marker, sanitize_serializer_string};
use guard_contracts::{is_python_space, python_strip};
use serde_json::{json, Map, Value};

use super::{exact_keys, text};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 10] = [
    "op",
    "harness",
    "item_kind",
    "display_name",
    "publisher",
    "explicit_description",
    "metadata_descriptions",
    "home_dir",
    "workspace_dir",
    "cwd",
];
const METADATA_DESCRIPTIONS: usize = 4;
/// `_MAX_DESCRIPTION_LENGTH`, in code points.
const MAX_DESCRIPTION_CHARS: usize = 500;

pub(super) fn dispatch(fields: &Map<String, Value>) -> KindResult {
    exact_keys(fields, &KEYS)?;
    let harness = text(fields, "harness")?;
    let item_kind = text(fields, "item_kind")?;
    let display_name = text(fields, "display_name")?;
    let publisher = optional_text(fields, "publisher")?;
    let explicit = optional_text(fields, "explicit_description")?;
    let metadata = metadata_descriptions(fields)?;
    let home_dir = optional_text(fields, "home_dir")?;
    let workspace_dir = optional_text(fields, "workspace_dir")?;
    let cwd = text(fields, "cwd")?;
    // `explicit_description or _metadata_description(metadata)`: an empty
    // explicit description is falsy, a blank one is not.
    let candidate = explicit.filter(|value| !value.is_empty()).or_else(|| {
        metadata
            .into_iter()
            .flatten()
            .map(python_strip)
            .find(|value| !value.is_empty())
    });
    if let Some(candidate) = candidate {
        let mut sanitized = sanitize_serializer_string(candidate, "description", false);
        if let Some(home_dir) = home_dir {
            sanitized = safe_finding_text(
                &sanitized,
                Path::new(home_dir),
                workspace_dir.map(Path::new),
                Path::new(cwd),
            );
        }
        let cleaned = clean(&sanitized);
        if !cleaned.is_empty() && !is_safe_serialized_marker(&cleaned) {
            return Ok(json!({ "description": cleaned }));
        }
    }
    let sentence = fallback(harness, item_kind, display_name, publisher);
    Ok(json!({ "description": clean(&sentence) }))
}

fn optional_text<'a>(
    fields: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, &'static str> {
    match fields.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        _ => Err(ERR_INVALID),
    }
}

fn metadata_descriptions(
    fields: &Map<String, Value>,
) -> Result<[Option<&str>; METADATA_DESCRIPTIONS], &'static str> {
    let items = fields
        .get("metadata_descriptions")
        .and_then(Value::as_array)
        .filter(|items| items.len() == METADATA_DESCRIPTIONS)
        .ok_or(ERR_INVALID)?;
    let mut descriptions = [None; METADATA_DESCRIPTIONS];
    for (slot, item) in descriptions.iter_mut().zip(items) {
        *slot = match item {
            Value::Null => None,
            Value::String(value) => Some(value.as_str()),
            _ => return Err(ERR_INVALID),
        };
    }
    Ok(descriptions)
}

/// `_clean_description_text`: whitespace runs collapse to one space, and text
/// past the limit is cut to one character short of it and ends in `…`.
fn clean(value: &str) -> String {
    let mut collapsed = String::with_capacity(value.len());
    let mut in_space = false;
    for character in python_strip(value).chars() {
        if is_python_space(character) {
            in_space = true;
            continue;
        }
        if in_space {
            collapsed.push(' ');
            in_space = false;
        }
        collapsed.push(character);
    }
    if collapsed.chars().count() <= MAX_DESCRIPTION_CHARS {
        return collapsed;
    }
    let trimmed: String = collapsed.chars().take(MAX_DESCRIPTION_CHARS - 1).collect();
    format!("{}…", trimmed.trim_end_matches(is_python_space))
}

/// `_kind_fallback_description`.
fn fallback(harness: &str, item_kind: &str, display_name: &str, publisher: Option<&str>) -> String {
    let name = match python_strip(display_name) {
        "" => "This item",
        name => name,
    };
    let harness = harness.replace('_', " ");
    match item_kind {
        "agent" => format!("{name} configures agent behavior for {harness}."),
        "daemon_plugin" => format!("{name} is a Guard daemon plugin on this machine."),
        "harness" => format!("{name} is the protected harness runtime Guard monitors."),
        "model_provider" => format!("{name} is a model provider configured for {harness}."),
        "package" => format!("{name} is an installed package used by {harness}."),
        "prompt_pack" => format!("{name} is a prompt or command pack available to {harness}."),
        "skill" => format!("{name} is an agent skill with instructions {harness} can load."),
        "mcp_server" => format!("{name} is an MCP server connected to {harness}."),
        "mcp_tool" => format!("{name} is an MCP tool exposed by a connected server."),
        "plugin" => {
            let publisher = match publisher.map(python_strip) {
                Some(publisher) if !publisher.is_empty() => format!(" published by {publisher}"),
                _ => String::new(),
            };
            format!("{name} is an extension{publisher} installed for {harness}.")
        }
        "channel" => format!("{name} is a messaging channel configured for {harness}."),
        "hook" => format!("{name} is a lifecycle hook invoked by {harness}."),
        "overlay" => format!("{name} is workspace guidance or rules consumed by {harness}."),
        "repository" => format!("{name} is a repository context linked to {harness}."),
        "container_image" => format!("{name} is a container image referenced by {harness}."),
        "policy" => format!("{name} is a policy artifact governing {harness} behavior."),
        "secret_reference" => format!("{name} references credentials used by {harness}."),
        "network_endpoint" => format!("{name} is a network endpoint reachable from {harness}."),
        _ => format!("{name} is an inventory item detected for {harness}."),
    }
}

#[cfg(test)]
#[path = "inventory_item_description_tests.rs"]
mod tests;
