//! `runner_authority` kind `cline_plugin_render`: the Guard-managed Cline
//! AgentPlugin source. The template in `cline_plugin_render.v1.json` was
//! recorded from the original Python builder, so the rendered source matches
//! it byte for byte. Python resolves the Guard CLI, the hook argv and the state
//! paths; this kind only renders.
//!
//! Template lines carry `@@name@@` placeholders, each replaced by its value
//! spelled as Python's default `json.dumps` would. A value is never rescanned.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use guard_contracts::write_python_default_json;
use serde_json::{json, Value};

use super::runner_authority_op::{KindResult, ERR_INVALID};

const TEMPLATE: &str = include_str!("cline_plugin_render.v1.json");
const TEMPLATE_SCHEMA: &str = "guard-cline-plugin-render-template.v1";
const ERR_TEMPLATE: &str = "cline_plugin_render_template_invalid";

const LIST_FIELDS: [&str; 2] = ["guard_cli", "hook_argv"];
const STRING_FIELDS: [&str; 4] = [
    "adapter_state",
    "proof_loaded",
    "proof_pretool",
    "proof_posttool",
];

fn template() -> Result<&'static [String], &'static str> {
    static PARSED: OnceLock<Option<Vec<String>>> = OnceLock::new();
    PARSED
        .get_or_init(|| {
            let document: Value = serde_json::from_str(TEMPLATE).ok()?;
            if document.get("schema").and_then(Value::as_str) != Some(TEMPLATE_SCHEMA) {
                return None;
            }
            document
                .get("lines")?
                .as_array()?
                .iter()
                .map(|line| line.as_str().map(str::to_owned))
                .collect()
        })
        .as_deref()
        .ok_or(ERR_TEMPLATE)
}

fn json_text(value: &Value) -> Result<String, &'static str> {
    let mut out = Vec::new();
    write_python_default_json(value, &mut out).map_err(|_| ERR_INVALID)?;
    String::from_utf8(out).map_err(|_| ERR_INVALID)
}

fn placeholder_values(args: &Value) -> Result<BTreeMap<&'static str, String>, &'static str> {
    let fields = args.as_object().ok_or(ERR_INVALID)?;
    if fields.len() != LIST_FIELDS.len() + STRING_FIELDS.len() {
        return Err(ERR_INVALID);
    }
    let mut values = BTreeMap::new();
    for key in LIST_FIELDS {
        let value = fields
            .get(key)
            .filter(|value| {
                value
                    .as_array()
                    .is_some_and(|items| items.iter().all(Value::is_string))
            })
            .ok_or(ERR_INVALID)?;
        values.insert(key, json_text(value)?);
    }
    for key in STRING_FIELDS {
        let value = fields
            .get(key)
            .filter(|value| value.is_string())
            .ok_or(ERR_INVALID)?;
        values.insert(key, json_text(value)?);
    }
    Ok(values)
}

/// The plugin source as `{"source": <text>}`.
pub(crate) fn render(args: &Value) -> KindResult {
    let values = placeholder_values(args)?;
    let lines = template()?;
    let mut source = String::with_capacity(lines.iter().map(|line| line.len() + 1).sum());
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            source.push('\n');
        }
        let mut parts = line.split("@@");
        source.push_str(parts.next().unwrap_or_default());
        while let Some(name) = parts.next() {
            source.push_str(values.get(name).ok_or(ERR_TEMPLATE)?);
            source.push_str(parts.next().ok_or(ERR_TEMPLATE)?);
        }
    }
    Ok(json!({ "source": source }))
}
