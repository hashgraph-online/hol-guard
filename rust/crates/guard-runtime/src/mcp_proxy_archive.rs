//! Rebinding a `tools/call` to the verified local copies of its external
//! archives. The resident decides whether and how the request is rewritten; the
//! caller applies the returned edits, so key order and number formatting of the
//! forwarded request stay exactly what the client sent.

use guard_contracts::McpExternalArchiveBindQueryV1;
use serde_json::{json, Value};

use crate::mcp_proxy_shlex as shlex;

const SHELL_KEYS: [&str; 4] = ["cmd", "command", "shellCommand", "shell_command"];

struct Binding<'a> {
    replacements: &'a [(String, String)],
    matched: Vec<bool>,
    edits: Vec<Value>,
}

fn bind_shell_command(binding: &mut Binding<'_>, command: &str) -> Option<String> {
    if !binding
        .replacements
        .iter()
        .any(|(source, _)| command.contains(source.as_str()))
    {
        return Some(command.to_owned());
    }
    if cfg!(windows) || command.contains(['`', '\n', '\r']) || command.contains("$(") {
        return None;
    }
    let tokens = shlex::split(command)?;
    if tokens.iter().any(|token| shlex::is_control(token)) {
        return None;
    }
    let bound: Vec<String> = tokens
        .into_iter()
        .map(|token| substitute(binding, token))
        .collect();
    Some(shlex::join(&bound))
}

fn substitute(binding: &mut Binding<'_>, mut text: String) -> String {
    for (position, (source, local)) in binding.replacements.iter().enumerate() {
        if text.contains(source.as_str()) {
            text = text.replace(source.as_str(), local);
            binding.matched[position] = true;
        }
    }
    text
}

fn walk(
    binding: &mut Binding<'_>,
    value: &Value,
    path: &mut Vec<Value>,
    shell_command: bool,
) -> Option<()> {
    match value {
        Value::String(text) => {
            let replaced = if shell_command {
                bind_shell_command(binding, text)?
            } else {
                substitute(binding, text.clone())
            };
            if replaced != *text {
                binding
                    .edits
                    .push(json!({ "path": path.clone(), "value": replaced }));
            }
        }
        Value::Array(items) => {
            for (position, item) in items.iter().enumerate() {
                path.push(json!(position));
                walk(binding, item, path, false)?;
                path.pop();
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                path.push(json!(key));
                let shell = SHELL_KEYS.contains(&key.as_str()) && item.is_string();
                walk(binding, item, path, shell)?;
                path.pop();
            }
        }
        _ => {}
    }
    Some(())
}

/// `unchanged`, `unbound` (fail closed) or `bound` with the edits to apply.
pub(crate) fn bind(query: &McpExternalArchiveBindQueryV1) -> Value {
    if query.replacements.is_empty() {
        let kind = if query.requires_binding {
            "unbound"
        } else {
            "unchanged"
        };
        return json!({ "kind": kind });
    }
    let mut binding = Binding {
        replacements: &query.replacements,
        matched: vec![false; query.replacements.len()],
        edits: Vec::new(),
    };
    if walk(&mut binding, &query.params, &mut Vec::new(), false).is_none() {
        return json!({ "kind": "unbound" });
    }
    // Every verified archive must have been found in the request.
    if !binding.matched.iter().all(|found| *found) {
        return json!({ "kind": "unbound" });
    }
    json!({ "kind": "bound", "edits": binding.edits })
}
