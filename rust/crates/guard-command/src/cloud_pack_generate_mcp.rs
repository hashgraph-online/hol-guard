//! Draft `remote-mcp` actions from an MCP tool list.
//!
//! A tool call reaches the provider with the caller's argument names, so a
//! draft keeps each name as the tool declares it rather than renaming it to
//! `snake_case`. A property the typed specs cannot describe (an object, or an
//! array of anything but strings) becomes a size-bounded `json` argument.

use crate::cloud_action_binding::valid_label;
use crate::cloud_action_classifier::classify;
use crate::cloud_pack::MAX_ARGUMENTS;
use crate::cloud_pack_generate::{
    argument, push_action, response, title, ActionParts, Draft, PLACEHOLDER_SCOPE,
};
use crate::cloud_pack_validate::mcp_name;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// Largest `json` argument a draft accepts when the schema states no bound.
const DEFAULT_JSON_BYTES: u64 = 16_384;
const DEFAULT_JSON_ITEMS: u64 = 100;
const MAX_JSON_ITEMS: u64 = 1_000;

pub(crate) fn build(tools: &[Value], provider: &str, mode: &str, draft: &mut Draft) {
    for (index, tool) in tools.iter().enumerate() {
        let at = format!("/mcpTools/{index}");
        let Some(name) = tool
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| valid_label(name) && name.len() <= 128)
        else {
            draft.note("tool_skipped", &at);
            continue;
        };
        let Some(action_id) = draft.action_id(provider, name) else {
            draft.note("actions_truncated", &at);
            break;
        };
        let schema = tool.get("inputSchema");
        let mut arguments = Map::new();
        if let Some(schema) = schema {
            let at = format!("{at}/inputSchema/properties");
            tool_arguments(schema, &mut arguments, draft, &at);
        }
        let response = response(tool.get("outputSchema"), false, draft, &at);
        let text = tool
            .get("title")
            .or_else(|| tool.get("description"))
            .and_then(Value::as_str);
        let scopes = if mode == "none" {
            BTreeSet::new()
        } else {
            BTreeSet::from([PLACEHOLDER_SCOPE.to_owned()])
        };
        push_action(
            draft,
            ActionParts {
                action_id,
                title: title(text, name),
                link: json!({ "tool": name }),
                executor: json!({ "kind": "remote-mcp", "tool": name }),
                arguments,
                proposal: classify(name, schema),
                response,
                scopes,
            },
        );
    }
}

fn tool_arguments(schema: &Value, into: &mut Map<String, Value>, draft: &mut Draft, at: &str) {
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return;
    };
    let required: BTreeSet<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    for (key, property) in properties {
        let wanted = required.contains(key.as_str());
        let spec = argument(property, wanted).or_else(|| json_spec(property, wanted));
        match spec {
            Some(spec) if mcp_name(key) && into.len() < MAX_ARGUMENTS => {
                into.insert(key.clone(), spec);
            }
            _ if wanted => draft.note("required_argument_unsupported", &format!("{at}/{key}")),
            _ => draft.note("argument_skipped", &format!("{at}/{key}")),
        }
    }
}

fn json_spec(schema: &Value, required: bool) -> Option<Value> {
    match schema.get("type").and_then(Value::as_str) {
        Some("object") => Some(json!({
            "type": "json",
            "required": required,
            "maxBytes": DEFAULT_JSON_BYTES,
        })),
        Some("array") => {
            let max = schema
                .get("maxItems")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_JSON_ITEMS)
                .clamp(1, MAX_JSON_ITEMS);
            Some(json!({
                "type": "json",
                "required": required,
                "maxBytes": DEFAULT_JSON_BYTES,
                "maxItems": max,
            }))
        }
        _ => None,
    }
}
