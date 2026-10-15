//! The daemon's custom extension block for an allowed `PreToolUse`.
//!
//! While any custom block rule exists, the daemon checks every `PreToolUse`
//! the edge allowed against the local CLI its command launches: it derives
//! the package-script identity, else the unlisted-CLI identity, reads that
//! identity's grant, and blocks the command when the grant blocks it. This
//! module runs the same identity steps and grant read in the resident and
//! renders the same block, including the unverified block when the grant
//! answer cannot be trusted. A launch the daemon rejects as malformed, a
//! catalog read failure, a command id the daemon resolves from its own shell
//! model while some command of that CLI is blocked, and a block for a harness
//! whose answer the resident shapes itself, still defer.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use super::workspace::python_strip;
use crate::context_digest_package_scripts::package_json_scripts;
use crate::local_cli_identify::{identify, Request};
use block::{CommandSelector, Launch, Verdict};

const TOOL_INPUT_FIELDS: [&str; 2] = ["tool_input", "toolInput"];
const COMMAND_FIELDS: [&str; 4] = ["command", "cmd", "shell_command", "shellCommand"];
/// The budget the daemon gives the resident for one identity derivation.
const IDENTIFY_BUDGET_MS: u64 = 2_000;

/// The request state a custom rule check reads.
pub(super) struct RuleCheck<'a> {
    /// The `PreToolUse` payload, present only while custom rules exist.
    pub(super) payload: Option<&'a Map<String, Value>>,
    pub(super) harness: &'a str,
    pub(super) workspace: &'a str,
    pub(super) home_dir: &'a str,
    pub(super) guard_home: &'a str,
    pub(super) recording_only: bool,
    /// The resident shapes this harness's answer itself, so a block defers.
    pub(super) own_shape: bool,
}

/// The harness response the daemon returns for `answered` once it checked
/// its custom rules: `Ok(None)` keeps the edge response, `Ok(Some(_))` is the
/// block the daemon returns instead, and `Err(())` defers. The daemon checks
/// its rules only against a `PreToolUse` the edge allowed (in Watch, one the
/// edge also decided to allow), so any other answer stands.
pub(super) fn custom_rule_response(
    answered: &Value,
    check: &RuleCheck<'_>,
) -> Result<Option<Value>, ()> {
    let Some(payload) = check.payload else {
        return Ok(None);
    };
    let result = &answered["result"];
    if result["minimum_action"].as_str() != Some("allow")
        || (check.recording_only && result["decision"].as_str() != Some("allow"))
    {
        return Ok(None);
    }
    let Some(launch) = launch_for(payload, check.workspace, check.home_dir)? else {
        return Ok(None);
    };
    match grant(&launch, check.guard_home)? {
        Verdict::Unchanged => Ok(None),
        Verdict::Unverified | Verdict::Blocked(_) if check.own_shape => Err(()),
        Verdict::Unverified => {
            let result = result.as_object().ok_or(())?;
            block::unverified_response(check.harness, result, check.recording_only)
                .map(Some)
                .ok_or(())
        }
        Verdict::Blocked(name) => {
            let result = result.as_object().ok_or(())?;
            block::block_response(check.harness, result, &name, check.recording_only)
                .map(Some)
                .ok_or(())
        }
    }
}

/// Whether the daemon would read a custom grant for this `PreToolUse`: the
/// payload names a command and a launch directory, and the command launches a
/// local CLI. `Err` is any failure the daemon could still resolve to a launch.
pub(super) fn launches_local_cli(
    payload: &Map<String, Value>,
    workspace: &str,
    home_dir: &str,
) -> Result<bool, ()> {
    launch_for(payload, workspace, home_dir).map(|launch| launch.is_some())
}

/// The local CLI the daemon reads a grant for, or `None` when the payload
/// names no command or launch directory or the command launches none.
fn launch_for(
    payload: &Map<String, Value>,
    workspace: &str,
    home_dir: &str,
) -> Result<Option<Launch>, ()> {
    let Some(command) = pre_tool_command(payload)? else {
        return Ok(None);
    };
    let Some(cwd) = launch_cwd(payload, workspace)? else {
        return Ok(None);
    };
    local_launch(command, &cwd, home_dir)
}

/// The launch identity the daemon derives: the package script's, else the
/// first unlisted CLI's. `Err` is any failure the daemon blocks as
/// unverified.
fn local_launch(command: &str, cwd: &str, home_dir: &str) -> Result<Option<Launch>, ()> {
    let package = package_json_scripts(command, cwd, home_dir).map_err(|_| ())?;
    block::launch(package, || {
        // The resident inherits the daemon's `PATH` and home; the daemon
        // resolves the launch against its own environment.
        let user_home = std::env::var("HOME").map_err(|_| ())?;
        let env: BTreeMap<String, String> = std::env::vars_os()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        identify(&Request {
            command_text: command,
            cwd,
            home_dir: Some(home_dir),
            user_home: &user_home,
            compound: false,
            env: &env,
            budget_ms: IDENTIFY_BUDGET_MS,
        })
        .map_err(|_| ())
    })
}

/// The grant read the daemon asks the resident for, with the command id it
/// resolves from the CLI's catalog. Only a blocked command can change an
/// allowed `PreToolUse`, so a command id the daemon resolves from its own
/// shell model matters only while some command of the CLI is blocked.
fn grant(launch: &Launch, guard_home: &str) -> Result<Verdict, ()> {
    let (catalog, command_blocked) =
        crate::local_cli_grant_op::command_catalog(guard_home, &launch.cli_id).map_err(|_| ())?;
    let command_id = match block::command_selector(&catalog, launch.tokens.as_deref()) {
        CommandSelector::Known(command_id) => command_id,
        CommandSelector::Unresolved if command_blocked => return Err(()),
        // No blocked command: every command id the daemon could resolve
        // reads the same grant outcome as the CLI-level one.
        CommandSelector::Unresolved => Some(block::OTHER_COMMAND_ID.to_owned()),
    };
    let answer = crate::local_cli_grant_op::decide_allowed_launch(
        guard_home,
        &launch.source,
        command_id.as_deref(),
    )
    .ok();
    Ok(block::grant_verdict(launch, answer.as_ref()))
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

#[path = "hook_direct_local_cli_block.rs"]
mod block;

#[cfg(test)]
#[path = "hook_direct_local_cli_tests.rs"]
mod tests;
