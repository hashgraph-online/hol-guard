//! Whether an allowed `PreToolUse` could meet a custom extension block rule.
//!
//! While any custom block rule exists, the daemon checks every `PreToolUse`
//! the edge allowed against the local CLI its command launches: it derives
//! the package-script identity, else the unlisted-CLI identity, and reads
//! that identity's grant. A command that launches no such CLI matches no
//! rule, and the daemon returns the edge response unchanged. This module
//! runs the same two identity steps the daemon asks this resident for; a
//! command with an identity, or one whose identity cannot be derived, still
//! defers so the daemon reads the grant and renders any block.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use super::workspace::python_strip;
use crate::context_digest_package_scripts::package_json_scripts;
use crate::local_cli_identify::{identify, Request};

const TOOL_INPUT_FIELDS: [&str; 2] = ["tool_input", "toolInput"];
const COMMAND_FIELDS: [&str; 4] = ["command", "cmd", "shell_command", "shellCommand"];
/// The budget the daemon gives the resident for one identity derivation.
const IDENTIFY_BUDGET_MS: u64 = 2_000;

/// Whether a custom rule check must send `answered` to the daemon. The
/// daemon checks its rules only against a `PreToolUse` the edge allowed
/// outright, so any other answer, or a hook without rules, stands.
pub(super) fn defers_for_custom_rule(
    answered: &Value,
    rule_payload: Option<&Map<String, Value>>,
    workspace: &str,
    home_dir: &str,
) -> bool {
    rule_payload.is_some_and(|payload| {
        answered["result"]["minimum_action"].as_str() == Some("allow")
            && may_meet_custom_rule(payload, workspace, home_dir)
    })
}

/// `false` only when the command provably launches no local CLI a custom
/// rule could name. A command without text or a launch directory matches no
/// rule, as on the daemon path.
pub(super) fn may_meet_custom_rule(
    payload: &Map<String, Value>,
    workspace: &str,
    home_dir: &str,
) -> bool {
    let Ok(command) = pre_tool_command(payload) else {
        return true;
    };
    let Some(command) = command else {
        return false;
    };
    let Ok(cwd) = launch_cwd(payload, workspace) else {
        return true;
    };
    let Some(cwd) = cwd else {
        return false;
    };
    launches_local_cli(command, &cwd, home_dir).unwrap_or(true)
}

fn launches_local_cli(command: &str, cwd: &str, home_dir: &str) -> Result<bool, &'static str> {
    if package_json_scripts(command, cwd, home_dir)?.is_some_and(|found| found.identity.is_some()) {
        return Ok(true);
    }
    // The resident inherits the daemon's `PATH` and home; the daemon resolves
    // the launch against its own environment.
    let user_home = std::env::var("HOME").map_err(|_| "home_unavailable")?;
    let env: BTreeMap<String, String> = std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .collect();
    let identities = identify(&Request {
        command_text: command,
        cwd,
        home_dir: Some(home_dir),
        user_home: &user_home,
        compound: false,
        env: &env,
        budget_ms: IDENTIFY_BUDGET_MS,
    })?;
    Ok(!identities.is_empty())
}

/// The daemon's command rule: the first non-blank command field of the tool
/// input, then the arguments, then the payload itself.
fn pre_tool_command(payload: &Map<String, Value>) -> Result<Option<&str>, ()> {
    let tool_input = TOOL_INPUT_FIELDS
        .iter()
        .find_map(|field| payload.get(*field).and_then(Value::as_object));
    let arguments = payload.get("arguments").and_then(Value::as_object);
    for candidate in [tool_input, arguments, Some(payload)].into_iter().flatten() {
        for field in COMMAND_FIELDS {
            let Some(value) = candidate.get(field).and_then(Value::as_str) else {
                continue;
            };
            if python_strip(value).map_err(|_| ())?.is_some() {
                return Ok(Some(value));
            }
        }
    }
    Ok(None)
}

/// The daemon's launch directory: the payload's non-blank `cwd`, else the
/// workspace, when absolute and an existing directory once resolved.
fn launch_cwd(payload: &Map<String, Value>, workspace: &str) -> Result<Option<String>, ()> {
    let raw = match payload.get("cwd").and_then(Value::as_str) {
        Some(raw) if python_strip(raw).map_err(|_| ())?.is_some() => raw,
        _ => workspace,
    };
    if !Path::new(raw).is_absolute() {
        return Ok(None);
    }
    let Ok(resolved) = fs::canonicalize(raw) else {
        return Ok(None);
    };
    if !resolved.is_dir() {
        return Ok(None);
    }
    resolved
        .into_os_string()
        .into_string()
        .map(Some)
        .map_err(|_| ())
}

#[cfg(test)]
#[path = "hook_direct_local_cli_tests.rs"]
mod tests;
