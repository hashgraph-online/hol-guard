//! The daemon's custom extension block for an allowed `PreToolUse`.
//!
//! While any custom block rule exists, the daemon checks every `PreToolUse`
//! the edge allowed against the local CLI its command launches: it derives
//! the package-script identity, else the unlisted-CLI identity, reads that
//! identity's grant, and blocks the command when the grant blocks it. This
//! module runs the same identity steps and grant read in the resident and
//! renders the same block, including the unverified block when the grant
//! answer cannot be trusted. The command id comes from the package script
//! tokens, else from the same shell model the daemon reads the invocation
//! with. A launch the daemon rejects as malformed and a catalog read failure
//! still defer.
//!
//! `review_grant` reads the same rule for a review the daemon paused
//! (`native_local_cli_grant_response`), where a block applies to any review
//! and an allow lifts only one the caller may override. That lane blocks
//! nothing it could not check, so a failed identity or grant read leaves the
//! review standing instead of deferring.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::{Map, Value};

use super::workspace::python_strip;
use crate::context_digest_package_scripts::package_json_scripts;
use crate::local_cli_identify::{identify, Request};
use block::{Launch, ReviewVerdict, Verdict};

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
    /// The daemon's home and environment, when the caller is not the process
    /// the launch runs under.
    pub(super) launch_env: Option<LaunchEnv<'a>>,
}

/// The home and environment a launch resolves against.
#[derive(Clone, Copy)]
pub(super) struct LaunchEnv<'a> {
    pub(super) user_home: &'a str,
    pub(super) env: &'a BTreeMap<String, String>,
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
    let Some(launched) = launch_for(payload, check.workspace, check.home_dir, check.launch_env)?
    else {
        return Ok(None);
    };
    match grant(&launched, check.home_dir, check.guard_home)? {
        Verdict::Unchanged => Ok(None),
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

/// A local CLI launch with the invocation the daemon derives its command
/// tokens from.
struct Launched<'a> {
    launch: Launch,
    command: &'a str,
    cwd: String,
}

impl Launched<'_> {
    /// `command_tokens_for_invocation` past the package script branch: the
    /// first segment's arguments after the runner or the script's own path.
    fn invocation_tokens(&self, home_dir: &str) -> Vec<String> {
        crate::local_cli_hook_op::invocation_command_tokens(
            self.command,
            &self.cwd,
            Some(home_dir),
            &self.launch.name,
            &self.launch.kind,
            self.launch.runner.as_deref(),
        )
    }
}

/// The local CLI the daemon reads a grant for, or `None` when the payload
/// names no command or launch directory or the command launches none.
fn launch_for<'a>(
    payload: &'a Map<String, Value>,
    workspace: &str,
    home_dir: &str,
    launch_env: Option<LaunchEnv<'_>>,
) -> Result<Option<Launched<'a>>, ()> {
    let Some(command) = pre_tool_command(payload)? else {
        return Ok(None);
    };
    let Some(cwd) = launch_cwd(payload, workspace)? else {
        return Ok(None);
    };
    Ok(
        local_launch(command, &cwd, home_dir, launch_env)?.map(|launch| Launched {
            launch,
            command,
            cwd,
        }),
    )
}

/// The launch identity the daemon derives: the package script's, else the
/// first unlisted CLI's. `Err` is any failure the daemon blocks as
/// unverified.
fn local_launch(
    command: &str,
    cwd: &str,
    home_dir: &str,
    launch_env: Option<LaunchEnv<'_>>,
) -> Result<Option<Launch>, ()> {
    let package = package_json_scripts(command, cwd, home_dir).map_err(|_| ())?;
    block::launch(package, || {
        let identify_in = |user_home: &str, env: &BTreeMap<String, String>| {
            identify(&Request {
                command_text: command,
                cwd,
                home_dir: Some(home_dir),
                user_home,
                compound: false,
                env,
                budget_ms: IDENTIFY_BUDGET_MS,
            })
            .map_err(|_| ())
        };
        // The daemon resolves the launch against its own environment. The
        // direct lane runs inside it; the resident is told it.
        if let Some(launch_env) = launch_env {
            return identify_in(launch_env.user_home, launch_env.env);
        }
        let user_home = std::env::var("HOME").map_err(|_| ())?;
        let env: BTreeMap<String, String> = std::env::vars_os()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        identify_in(&user_home, &env)
    })
}

/// The grant read the daemon asks the resident for, with the command id it
/// resolves from the CLI's catalog: the package script tokens select it, and
/// any other invocation's tokens come from the shell model.
fn grant_answer(
    launched: &Launched<'_>,
    current_action: &str,
    home_dir: &str,
    guard_home: &str,
) -> Result<Option<Value>, ()> {
    let launch = &launched.launch;
    let catalog =
        crate::local_cli_grant_op::command_catalog(guard_home, &launch.cli_id).map_err(|_| ())?;
    let command_id = if catalog.is_empty() {
        None
    } else {
        let tokens = match launch.tokens.clone() {
            Some(tokens) => tokens,
            None => launched.invocation_tokens(home_dir),
        };
        block::command_selector(&catalog, &tokens)
    };
    Ok(crate::local_cli_grant_op::decide_launch(
        guard_home,
        current_action,
        &launch.source,
        command_id.as_deref(),
    )
    .ok())
}

fn grant(launched: &Launched<'_>, home_dir: &str, guard_home: &str) -> Result<Verdict, ()> {
    let answer = grant_answer(launched, "allow", home_dir, guard_home)?;
    Ok(block::grant_verdict(&launched.launch, answer.as_ref()))
}

/// `native_local_cli_grant_response`: the custom rule the daemon reads for a
/// reviewed `PreToolUse`, or `None` when no rule applies to the command and
/// the review stands. Every failure the allowed lane blocks as unverified
/// leaves the review standing here, as the daemon's own lane does.
pub(super) fn review_grant(check: &RuleCheck<'_>) -> Option<ReviewVerdict> {
    let payload = check.payload?;
    let launched =
        launch_for(payload, check.workspace, check.home_dir, check.launch_env).ok()??;
    let answer = grant_answer(&launched, "review", check.home_dir, check.guard_home).ok()?;
    match block::review_verdict(&launched.launch, answer.as_ref()) {
        ReviewVerdict::Unchanged => None,
        verdict => Some(verdict),
    }
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
pub(super) fn launch_cwd(
    payload: &Map<String, Value>,
    workspace: &str,
) -> Result<Option<String>, ()> {
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
pub(crate) mod block;
#[path = "hook_direct_local_cli_rule_op.rs"]
pub(crate) mod rule_op;

#[cfg(test)]
#[path = "hook_direct_local_cli_tests.rs"]
mod tests;
