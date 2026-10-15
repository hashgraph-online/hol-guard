//! Codex sandbox-required answers, settled natively: a port of
//! `route_codex_containment` (`codex_contained_tests.py`) and the
//! `contained_zcode_response` rewrite it runs for Codex.
//!
//! A contained-run denial becomes an allow whose `updatedInput` runs Guard's
//! execution sink on a private snapshot of the call, but only once the Codex
//! process that launched the hook reports a stable release that applies
//! `updatedInput` (0.131.0 or later). An older or unknown Codex keeps the
//! denial with an update hint; anything this module cannot reproduce keeps
//! the denial unchanged. Native authority is rechecked by the sink.

use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::{Digest, Sha256};

#[cfg(unix)]
use self::codex::user_home;
use self::codex::{codex_applies_updated_input, launching_codex_executable};
use super::approval::pending_pretool_approval;
use super::{BridgeConfig, Prepared, Route, STATE_FILE};
use crate::codex_hook_bridge_direct::unquote_plus;
use crate::codex_hook_response::{codex_hook_response, fail_closed, PRE_TOOL_USE};
use crate::hook_env_stamp::dumps;
use crate::pyjson::{self, PyVal};

pub(crate) const UPDATE_HINT: &str =
    "Update Codex to 0.131 or later so HOL Guard can run this command inside its contained runner.";
const SANDBOX_REQUIRED: &str = "sandbox-required";
const ROUTED_REASON: &str = "native_contained_execution_routed";
const RECEIPT_ONLY_FIELD: &str = "guard_containment_receipt_only";
const REQUEST_SCHEMA: &str = "guard-contained-test-request.v1";
const MAX_REQUEST_BYTES: usize = 1_048_576;
const PRE_TOOL_EVENTS: [&str; 2] = ["PreToolUse", "pre_tool_use"];
const SHELL_TOOLS: [&str; 4] = ["Bash", "bash", "run_terminal_command", "run_command"];

/// What `route_codex_containment` made of a sandbox requirement.
#[derive(Debug, PartialEq)]
enum Contained {
    /// The answer stands as the daemon gave it.
    Unchanged,
    /// The launching Codex cannot apply the rewrite: keep the denial and
    /// say how to get the contained run.
    Hint,
    /// The sink runs the call; the answer's strings came from the hook
    /// input, rendered with its surrogate mapping.
    Routed(PyVal, bool),
}

/// `_bridge_output` for a `PreToolUse` sandbox requirement: the contained
/// rewrite, then the browser approval wait on whatever answer stands.
pub(super) fn settle(
    config: &BridgeConfig,
    prepared: &Prepared,
    response: PyVal,
    mapped: bool,
    deadline: Instant,
) -> Route {
    let (settled, unmap) = match contain(config, prepared, &response, deadline) {
        Contained::Unchanged => (response, mapped),
        Contained::Hint => (with_update_hint(response), mapped),
        Contained::Routed(routed, unmap) => (routed, unmap),
    };
    let PyVal::Dict(entries) = &settled else {
        return Route::Respond(fail_closed(&prepared.event_name));
    };
    let mut rendered = String::new();
    dumps(
        &codex_hook_response(entries, &prepared.event_name),
        true,
        unmap,
        &mut rendered,
    );
    match pending_pretool_approval(&settled, &prepared.event_name) {
        Some(pending) => Route::AwaitApproval(pending, rendered),
        None => Route::Respond(rendered),
    }
}

fn text<'a>(value: &'a PyVal, name: &str) -> Option<&'a str> {
    value.get(name).and_then(PyVal::as_str)
}

#[cfg(test)]
thread_local! {
    /// Whether the launching Codex applies `updatedInput`, as a test fixes
    /// it, in place of probing the processes that launched the test runner.
    pub(super) static FIXED_CODEX_APPLIES: std::cell::Cell<Option<bool>> =
        const { std::cell::Cell::new(None) };
}

/// Whether the Codex process that launched the hook applies `updatedInput`.
fn launching_codex_applies(deadline: Instant) -> bool {
    #[cfg(test)]
    if let Some(applies) = FIXED_CODEX_APPLIES.with(std::cell::Cell::get) {
        return applies;
    }
    launching_codex_executable()
        .is_some_and(|executable| codex_applies_updated_input(&executable, deadline))
}

fn contain(
    config: &BridgeConfig,
    prepared: &Prepared,
    response: &PyVal,
    deadline: Instant,
) -> Contained {
    let (Some(guard_home), Some(home)) = (guard_home(&config.state_path), hook_home(&config.query))
    else {
        return Contained::Unchanged;
    };
    if prepared.event_name != PRE_TOOL_USE
        || !platform_contains(text(response, "required_execution_profile"))
        || text(response, "policy_action") != Some(SANDBOX_REQUIRED)
        || text(response, "decision") != Some("deny")
    {
        return Contained::Unchanged;
    }
    let Ok(payload) = pyjson::parse_mapping_lone_surrogates(&prepared.data) else {
        return Contained::Unchanged;
    };
    if !matches!(payload.value, PyVal::Dict(_))
        || payload.value.get(RECEIPT_ONLY_FIELD) == Some(&PyVal::Bool(true))
    {
        return Contained::Unchanged;
    }
    if !launching_codex_applies(deadline) {
        return Contained::Hint;
    }
    if payload.mapped && payload.collision {
        return Contained::Unchanged;
    }
    let target = Target {
        prefix: &config.fallback_command,
        guard_home: &guard_home,
        home: &home,
    };
    match routed(response, &payload.value, payload.mapped, &target) {
        Some(routed) => Contained::Routed(routed, payload.mapped),
        None => Contained::Unchanged,
    }
}

/// `platform_contains(response)`: macOS runs every contained profile, Linux
/// the workspace sandbox, Windows installed Python in an AppContainer.
fn platform_contains(profile: Option<&str>) -> bool {
    if cfg!(target_os = "macos") {
        return true;
    }
    if cfg!(target_os = "linux") {
        return profile == Some("workspace-contained-v1");
    }
    cfg!(windows) && profile == Some("python-eval-readonly-v1")
}

/// `str(state.parent)` when the state path is an absolute
/// `daemon-state.json`, as `_bridge_output` names the Guard home.
#[cfg(unix)]
fn guard_home(state_path: &str) -> Option<String> {
    let normalized = crate::daemon_lifecycle_text::norm_path(state_path);
    let rest = normalized.trim_start_matches('/');
    let root = &normalized[..normalized.len() - rest.len()];
    if root.is_empty() {
        return None;
    }
    let (parent, name) = match rest.rsplit_once('/') {
        Some((parent, name)) => (format!("{root}{parent}"), name),
        None => (root.to_owned(), rest),
    };
    (name == STATE_FILE).then_some(parent)
}

#[cfg(not(unix))]
fn guard_home(state_path: &str) -> Option<String> {
    let path = Path::new(state_path);
    if !path.is_absolute() || path.file_name().is_none_or(|name| name != STATE_FILE) {
        return None;
    }
    path.parent()?.to_str().map(str::to_owned)
}

/// `_installed_hook_home(query)`: the one `home` value of
/// `parse_qs(query, keep_blank_values=True)`, absolute and without NUL.
fn hook_home(query: &str) -> Option<String> {
    let mut values = query
        .split('&')
        .filter(|field| !field.is_empty())
        .map(|field| field.split_once('=').unwrap_or((field, "")))
        .filter(|(name, _)| unquote_plus(name).as_deref() == Some("home"))
        .map(|(_, value)| value);
    let (Some(value), None) = (values.next(), values.next()) else {
        return None;
    };
    let value = unquote_plus(value)?;
    if value.contains('\0') {
        return None;
    }
    absolute_text(&value)
}

#[cfg(unix)]
fn absolute_text(value: &str) -> Option<String> {
    value
        .starts_with('/')
        .then(|| crate::daemon_lifecycle_text::norm_path(value))
}

#[cfg(not(unix))]
fn absolute_text(value: &str) -> Option<String> {
    Path::new(value).is_absolute().then(|| value.to_owned())
}

/// Where the sink is run from and on whose behalf.
struct Target<'a> {
    /// The bridge's isolated fallback command; its interpreter and
    /// bootstrap are the sink's command prefix.
    prefix: &'a [String],
    guard_home: &'a str,
    home: &'a str,
}

/// `isolated_guard_cli_command(python, package_root, ())`, read from the
/// isolated fallback command the bridge was installed with.
fn sink_prefix(fallback: &[String]) -> Option<&[String]> {
    let isolated = fallback.len() > 4
        && Path::new(&fallback[0]).is_absolute()
        && fallback[1] == "-I"
        && fallback[2] == "-c"
        && fallback[3].starts_with("import sys;sys.path.insert(0, ")
        && fallback[4] == "guard";
    isolated.then(|| &fallback[..4])
}

/// The value of the first of `names` the payload carries, as a chained
/// `get` reads it.
fn first<'a>(payload: &'a PyVal, names: &[&str]) -> Option<&'a PyVal> {
    names.iter().find_map(|name| payload.get(name))
}

fn string(text: &str) -> PyVal {
    PyVal::Str(text.to_owned())
}

/// `contained_zcode_response` for the Codex harness.
fn routed(response: &PyVal, payload: &PyVal, mapped: bool, target: &Target<'_>) -> Option<PyVal> {
    let profile = text(response, "reason_code")
        .and_then(guard_command::hook_responses::contained_execution_profile)?;
    // The sink command is POSIX-quoted; Windows runs it only for Claude Code.
    if cfg!(windows)
        || response.get("observe_mode") == Some(&PyVal::Bool(true))
        || text(response, "required_execution_profile") != Some(profile)
    {
        return None;
    }
    let prefix = sink_prefix(target.prefix)?;
    let event = first(payload, &["hook_event_name", "hookEventName"])?.as_str()?;
    let tool = first(payload, &["tool_name", "toolName"])?.as_str()?;
    if !PRE_TOOL_EVENTS.contains(&event) || !SHELL_TOOLS.contains(&tool) {
        return None;
    }
    let original = first(payload, &["tool_input", "toolInput"])?;
    original.as_dict()?;
    original.get("command")?.as_str()?;
    let workspace = resolved_workspace(first(payload, &["cwd", "workspace"])?.as_str()?)?;
    let snapshot = PyVal::Dict(vec![
        ("schema".to_owned(), string(REQUEST_SCHEMA)),
        ("workspace".to_owned(), string(&workspace)),
        (
            "payload".to_owned(),
            PyVal::Dict(vec![
                ("hook_event_name".to_owned(), string(PRE_TOOL_USE)),
                ("tool_name".to_owned(), string("bash")),
                ("tool_input".to_owned(), original.clone()),
                ("cwd".to_owned(), string(&workspace)),
                (
                    "session_id".to_owned(),
                    first(payload, &["session_id", "sessionId"])
                        .cloned()
                        .unwrap_or(PyVal::Null),
                ),
                (
                    "tool_call_id".to_owned(),
                    first(payload, &["tool_call_id", "toolCallId", "tool_use_id"])
                        .cloned()
                        .unwrap_or(PyVal::Null),
                ),
            ]),
        ),
    ]);
    let mut serialized = String::new();
    dumps(&snapshot, true, mapped, &mut serialized);
    if serialized.len() > MAX_REQUEST_BYTES {
        return None;
    }
    let request = write_snapshot(serialized.as_bytes())?;
    let Some(request_text) = request.to_str().map(str::to_owned) else {
        discard(&request);
        return None;
    };
    let digest = hex::encode(Sha256::digest(serialized.as_bytes()));
    let mut command = prefix.to_vec();
    command.extend(
        [
            "guard",
            "execute-contained-test",
            "--harness",
            "codex",
            "--guard-home",
            target.guard_home,
            "--workspace",
            &workspace,
            "--request-file",
            &request_text,
            "--request-sha256",
            &digest,
            "--home",
            target.home,
        ]
        .map(str::to_owned),
    );
    Some(routed_response(original, &command))
}

/// The allow that runs `command` in place of the original call.
fn routed_response(original: &PyVal, command: &[String]) -> PyVal {
    let mut updated = match original {
        PyVal::Dict(entries) => entries.clone(),
        _ => Vec::new(),
    };
    let joined = string(&crate::mcp_proxy_shlex::join(command));
    match updated.iter_mut().find(|(name, _)| name == "command") {
        Some(slot) => slot.1 = joined,
        None => updated.push(("command".to_owned(), joined)),
    }
    PyVal::Dict(vec![
        ("policy_action".to_owned(), string("allow")),
        ("reason_code".to_owned(), string(ROUTED_REASON)),
        (
            "hookSpecificOutput".to_owned(),
            PyVal::Dict(vec![
                ("hookEventName".to_owned(), string(PRE_TOOL_USE)),
                ("permissionDecision".to_owned(), string("allow")),
                ("updatedInput".to_owned(), PyVal::Dict(updated)),
            ]),
        ),
    ])
}

/// `_with_update_hint(response)`.
fn with_update_hint(response: PyVal) -> PyVal {
    let PyVal::Dict(mut entries) = response else {
        return response;
    };
    let output = entries
        .iter_mut()
        .find(|(name, _)| name == "hookSpecificOutput")
        .map(|(_, value)| value);
    if let Some(PyVal::Dict(output)) = output {
        let reason = output
            .iter()
            .find(|(name, _)| name == "permissionDecisionReason")
            .and_then(|(_, value)| value.as_str())
            .filter(|reason| !reason.is_empty());
        let hinted = string(&match reason {
            Some(reason) => format!("{reason} {UPDATE_HINT}"),
            None => UPDATE_HINT.to_owned(),
        });
        match output
            .iter_mut()
            .find(|(name, _)| name == "permissionDecisionReason")
        {
            Some(slot) => slot.1 = hinted,
            None => output.push(("permissionDecisionReason".to_owned(), hinted)),
        }
    }
    PyVal::Dict(entries)
}

/// `Path(value).expanduser().resolve(strict=True)`, when it is a directory
/// named in UTF-8.
#[cfg(unix)]
fn resolved_workspace(value: &str) -> Option<String> {
    let expanded = match value.strip_prefix('~') {
        Some(rest) => {
            let (user, tail) = rest.split_once('/').unwrap_or((rest, ""));
            let home = user_home(user)?;
            format!("{home}/{tail}")
        }
        None if value.is_empty() => ".".to_owned(),
        None => value.to_owned(),
    };
    let resolved = std::fs::canonicalize(expanded).ok()?;
    resolved.is_dir().then_some(())?;
    resolved.to_str().map(str::to_owned)
}

#[cfg(not(unix))]
fn resolved_workspace(_value: &str) -> Option<String> {
    None
}

#[cfg(unix)]
fn write_snapshot(serialized: &[u8]) -> Option<PathBuf> {
    crate::hook_direct::contained::request::write_snapshot(&std::env::temp_dir(), serialized)
}

#[cfg(not(unix))]
fn write_snapshot(_serialized: &[u8]) -> Option<PathBuf> {
    None
}

fn discard(request: &Path) {
    let _ = std::fs::remove_file(request);
    if let Some(directory) = request.parent() {
        let _ = std::fs::remove_dir(directory);
    }
}

#[path = "codex_hook_bridge_contain_codex.rs"]
mod codex;
#[cfg(all(test, unix))]
#[path = "codex_hook_bridge_contain_tests.rs"]
mod tests;
