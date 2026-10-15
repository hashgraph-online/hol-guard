//! The package check the proxy runs before the tool policy.
//!
//! The proxy asks `extract_package_intent_request` whether a call installs or
//! runs a package (`runtime_mcp.py` `_package_request_artifact`) and sends a
//! call that does through the package policy, which this operation does not
//! answer. A call the parser finds no intent in goes on with
//! `package_present: false`. The resident decides only such a call, asking
//! the same parser with the inputs the proxy hands it: the tool name and the
//! arguments as the host sent them, their `_command_argument`, the proxy's
//! workspace, no home directory and the proxy's own `PATH`
//! (`_resident_environment`). An input the two could read differently defers.
//!
//! The parser's answer does not depend on key order: it finds an intent when
//! any candidate command has one, and the candidates are the same set in any
//! order.

use std::collections::BTreeMap;
use std::path::Path;

use guard_command::mcp_tool_signals::risk_arguments;
use guard_command::package_intent_parser::extract_package_intent_request;
use serde_json::{Map, Value};

use super::McpRelayDecideRequestV1;
use crate::context_digest::python_strip;

/// The call installs or runs a package, which the proxy's package policy
/// answers.
pub(super) const PACKAGE_INTENT: &str = "mcp_relay_package_intent";
/// The proxy strips a name or a command the parser would read unstripped.
pub(super) const PACKAGE_AMBIGUOUS: &str = "mcp_relay_package_ambiguous";
/// The workspace is not in the form `str(Path(...).resolve())` prints, so the
/// proxy could hand the parser another path.
pub(super) const WORKSPACE_UNNORMALIZED: &str = "mcp_relay_workspace_unnormalized";

/// `_command_argument`: the argument keys the proxy reads as the command.
const COMMAND_KEYS: [&str; 4] = ["command", "cmd", "shell_command", "shellCommand"];

/// Whether the proxy would take the call past its package check.
pub(super) fn package_gate(request: &McpRelayDecideRequestV1) -> Result<(), &'static str> {
    let workspace = match request.workspace.as_deref() {
        Some(workspace) if !resolved_path_text(workspace) => {
            return Err(WORKSPACE_UNNORMALIZED);
        }
        workspace => workspace.map(Path::new),
    };
    let tool = request.build.tool_name.as_str();
    let arguments = risk_arguments(&request.arguments);
    // The proxy strips with `str.strip` and the parser with `str::trim`; they
    // differ only on the separators U+001C to U+001F.
    if python_strip(tool) != tool.trim() || !strips_agree(&arguments) {
        return Err(PACKAGE_AMBIGUOUS);
    }
    let environment = request
        .path
        .as_ref()
        .filter(|path| !path.is_empty())
        .map(|path| BTreeMap::from([("PATH".to_owned(), path.clone())]));
    let intent = extract_package_intent_request(
        tool,
        &arguments,
        command_argument(arguments.as_object()),
        workspace,
        None,
        environment.as_ref(),
    );
    match intent {
        Some(_) => Err(PACKAGE_INTENT),
        None => Ok(()),
    }
}

/// `_command_argument`: the first command key holding a non-blank string,
/// stripped.
fn command_argument(arguments: Option<&Map<String, Value>>) -> Option<&str> {
    let arguments = arguments?;
    COMMAND_KEYS.iter().find_map(|key| {
        let command = python_strip(arguments.get(*key)?.as_str()?);
        (!command.is_empty()).then_some(command)
    })
}

/// Whether both strips agree on every string in `value`.
fn strips_agree(value: &Value) -> bool {
    match value {
        Value::String(text) => python_strip(text) == text.trim(),
        Value::Array(items) => items.iter().all(strips_agree),
        Value::Object(map) => map.values().all(strips_agree),
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
    }
}

/// Whether `path` is an absolute path `str(Path(path))` prints unchanged and
/// `resolve()` leaves no `.` or `..` in: no empty component (`//`, a trailing
/// `/`), no `.`, no `..` and no NUL.
fn resolved_path_text(path: &str) -> bool {
    if path == "/" {
        return true;
    }
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    !path.contains('\0')
        && rest
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_tests.rs"]
mod tests;
