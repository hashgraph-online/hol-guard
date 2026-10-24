//! The post-tool command texts (`_codex_post_tool_command_texts`): which
//! commands produced a post-tool output, read from the hook's tool name and
//! tool input.
//!
//! Python used to derive them itself, with one resident round trip per
//! candidate list and another for the tool's own command text, and then sent
//! the list back for review. The review now reads them from the payload it
//! already carries, through the same list and command-text grammar those round
//! trips reached.

use guard_hook_payload::shlex_quote;
use serde_json::Value;

use crate::benign_request_api::ovalue_from_json;
use crate::codex_output_py::py_strip;
use crate::hook_adapter_envelope_text::command_text_from_tool_payload;
use crate::hook_adapter_pytext::{dedupe_preserving_order, py_lower};
use crate::hook_adapter_value::OValue;
use crate::sfrs_constants::{COMMAND_CANDIDATE_LIST_KEYS, COMMAND_SEQUENCE_KEYS};
use crate::sfrs_requests::command_list_candidate_texts;

/// Read tools whose path stands in for a `cat` of the file they read.
const READ_TOOL_NAMES: [&str; 6] = [
    "cat_file",
    "open_file",
    "read",
    "read_file",
    "view",
    "view_file",
];
const READ_TOOL_PATH_KEYS: [&str; 6] = [
    "path",
    "file_path",
    "filePath",
    "filepath",
    "file",
    "filename",
];

/// The distinct, non-empty command texts a post-tool payload names, in the
/// order the payload names them. A tool input that is not an object names
/// none.
pub(crate) fn post_tool_command_texts(tool_name: &Value, tool_input: &Value) -> Vec<String> {
    let Value::Object(input) = tool_input else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    if let Some(Value::String(command)) = input.get("command") {
        let stripped = py_strip(command);
        if !stripped.is_empty() {
            candidates.push(stripped.to_owned());
        }
    }
    for key in COMMAND_CANDIDATE_LIST_KEYS {
        if let Some(Value::Array(items)) = input.get(*key) {
            let values: Vec<OValue> = items.iter().map(ovalue_from_json).collect();
            candidates.extend(command_list_candidate_texts(
                &values,
                COMMAND_SEQUENCE_KEYS.contains(key),
            ));
        }
    }
    let name = tool_name.as_str();
    let read_tool =
        name.is_some_and(|name| READ_TOOL_NAMES.contains(&py_lower(py_strip(name)).as_str()));
    if candidates.is_empty() && read_tool {
        for key in READ_TOOL_PATH_KEYS {
            if let Some(Value::String(path)) = input.get(key) {
                let stripped = py_strip(path);
                if !stripped.is_empty() {
                    candidates.push(format!("cat -- {}", shlex_quote(stripped)));
                }
            }
        }
    }
    if candidates.is_empty() {
        if let OValue::Map(input) = ovalue_from_json(tool_input) {
            candidates.extend(command_text_from_tool_payload(name, &input));
        }
    }
    candidates.retain(|text| !text.is_empty());
    dedupe_preserving_order(candidates)
}

#[cfg(test)]
#[path = "codex_output_post_tool_commands_tests.rs"]
mod tests;
