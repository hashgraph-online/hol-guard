//! Narrow public entry points for the resident's request-benignity verdicts.
//!
//! Python gathers the raw tool call and host facts; the resident computes the
//! verdict here and Python never recomputes it.

use std::path::Path;

use serde_json::Value;

use crate::codex_output_env::Ctx;
use crate::extension_control::{ExtensionControlLayer, ResolverFailureCode};
use crate::hook_adapter_value::{OMap, OValue};
use crate::sfrs_benign_reads::is_explicitly_benign_native_file_read_request;

/// `is_explicitly_benign_native_file_read_request` over the payload's raw
/// `tool_name` and `tool_input`: one existing, non-sensitive native `Read`
/// target. Any other shape is not benign.
#[must_use]
pub fn is_benign_native_file_read(
    tool_name: &Value,
    tool_input: &Value,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    is_explicitly_benign_native_file_read_request(
        &ovalue_from_json(tool_name),
        &ovalue_from_json(tool_input),
        cwd,
        home_dir,
        ctx,
    )
}

/// The resident's extension-control snapshot for one decision
/// (`current_extension_control_snapshot()`): the composed layers and the
/// authority failure their health implies.
pub struct ToolActionControls {
    pub layers: Vec<ExtensionControlLayer>,
    pub authority_failure: Option<ResolverFailureCode>,
}

/// `is_explicitly_benign_tool_action_request` over the payload's raw
/// `tool_name` and `tool_input`: every candidate command is a recognized
/// benign routine. `controls` is `None` when no control snapshot is active.
/// Anything the resident cannot compute is not benign.
#[must_use]
pub fn is_benign_tool_action(
    tool_name: &Value,
    tool_input: &Value,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
    controls: Option<&ToolActionControls>,
) -> bool {
    let inputs = crate::sfrs_benign_tool_action::ToolActionInputs {
        cwd,
        home_dir,
        ctx,
        controls,
    };
    crate::sfrs_benign_tool_action::is_explicitly_benign_tool_action_request(
        &ovalue_from_json(tool_name),
        tool_input,
        &inputs,
    )
}

/// Plain JSON to a Python-faithful value, keeping number spelling.
pub(crate) fn ovalue_from_json(value: &Value) -> OValue {
    match value {
        Value::Null => OValue::Null,
        Value::Bool(flag) => OValue::Bool(*flag),
        Value::Number(number) => {
            let token = number.to_string();
            if token.bytes().any(|byte| matches!(byte, b'.' | b'e' | b'E')) {
                OValue::Float(token)
            } else {
                OValue::Int(token)
            }
        }
        Value::String(text) => OValue::Str(text.clone()),
        Value::Array(items) => OValue::List(items.iter().map(ovalue_from_json).collect()),
        Value::Object(map) => {
            let mut converted = OMap::new();
            for (key, item) in map {
                converted.insert(key, ovalue_from_json(item));
            }
            OValue::Map(converted)
        }
    }
}
