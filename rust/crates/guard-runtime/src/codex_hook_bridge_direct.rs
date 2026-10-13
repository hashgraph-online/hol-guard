//! Direct resident answers for Codex, Claude Code and Cursor tool hooks.
//!
//! For a `PreToolUse` hook the edge allows or blocks outright, and for every
//! reviewed `PostToolUse` and `UserPromptSubmit` hook the daemon does not
//! restyle, of either harness the daemon forwards the payload to its resident
//! and returns the edge's harness response unchanged. When a live resident
//! of this runtime holds a direct-lane binding, the bridge asks it first
//! with `hook_direct` and skips the daemon round trip. The resident answers
//! only those hooks and queues the evidence the daemon drains and records;
//! it defers everything else.
//!
//! This path never decides a verdict the resident did not answer. A defer,
//! a resident that cannot be reached or proven to run this executable, and
//! a hook whose daemon context the bridge cannot reproduce exactly all take
//! the daemon path unchanged.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::claude_hook_bridge_http::remaining;
use crate::claude_hook_bridge_render::py_strip;
use crate::codex_hook_response::{POST_TOOL_USE, PRE_TOOL_USE};

const STATE_DIRECTORY: &str = "native-runtime";
const DIRECT_RESULT_SCHEMA: &str = "guard-hook-direct-result.v1";
const USER_PROMPT_SUBMIT: &str = "UserPromptSubmit";

/// A harness whose passed-through `PreToolUse` hook the daemon answers with
/// the edge's own response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectHarness {
    name: &'static str,
    /// `0` turns the direct path off; the daemon then answers every hook.
    switch: &'static str,
}

pub(crate) const CODEX: DirectHarness = DirectHarness {
    name: "codex",
    switch: "HOL_GUARD_CODEX_DIRECT_HOOK",
};
pub(crate) const CLAUDE_CODE: DirectHarness = DirectHarness {
    name: "claude-code",
    switch: "HOL_GUARD_CLAUDE_DIRECT_HOOK",
};
pub(crate) const CURSOR: DirectHarness = DirectHarness {
    name: "cursor",
    switch: "HOL_GUARD_CURSOR_DIRECT_HOOK",
};
/// A resident answers an allow well inside this. A slower resident leaves
/// the daemon most of the hook's budget.
const DIRECT_TIMEOUT: Duration = Duration::from_millis(1_000);
const MINIMUM_DIRECT_TIMEOUT: Duration = Duration::from_millis(50);

/// The query parameters the daemon reads, as `parse_qs(query)[name][-1]`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct HookQuery {
    pub(crate) guard_home: Option<String>,
    pub(crate) home: Option<String>,
    pub(crate) workspace: Option<String>,
    pub(crate) runtime_harness: Option<String>,
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// `unquote(text.replace("+", " "))`. Python replaces bytes that are not
/// UTF-8; this returns `None` instead, so such a query takes the daemon path.
fn unquote_plus(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                decoded.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        decoded.push(if byte == b'+' { b' ' } else { byte });
        index += 1;
    }
    String::from_utf8(decoded).ok()
}

/// `parse_qs` with its defaults: `&`-separated fields, fields without `=`
/// and blank values skipped, and the last value of a repeated name kept.
pub(crate) fn parse_hook_query(query: &str) -> Option<HookQuery> {
    let mut parsed = HookQuery::default();
    for field in query.split('&') {
        let Some((name, value)) = field.split_once('=') else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        let name = unquote_plus(name)?;
        let value = unquote_plus(value)?;
        match name.as_str() {
            "guard-home" => parsed.guard_home = Some(value),
            "home" => parsed.home = Some(value),
            "workspace" => parsed.workspace = Some(value),
            "runtime-harness" => parsed.runtime_harness = Some(value),
            _ => {}
        }
    }
    Some(parsed)
}

/// The resolved absolute directory the daemon would use for a query value.
/// Relative and `~` paths, and paths that do not resolve, return `None`.
fn resolved_directory(value: &str) -> Option<PathBuf> {
    let stripped = py_strip(value);
    if !stripped.starts_with('/') {
        return None;
    }
    std::fs::canonicalize(stripped).ok()
}

fn path_text(path: &Path) -> Option<String> {
    path.to_str().map(str::to_owned)
}

/// The `hook_direct` request for one hook, or `None` when the daemon would
/// see a context the bridge cannot reproduce: the daemon then answers.
///
/// The daemon accepts `guard-home` only when it resolves to its own guard
/// home, and `home` only inside its trusted roots; otherwise it replaces
/// both and drops the workspace. The bridge sends a request only when they
/// resolve where the daemon would keep them: `guard-home` to the guard home
/// holding the daemon state, and `home`, when present, at or under that
/// guard home's parent, which is always one of the daemon's roots. Without
/// `home` the daemon uses its own, which the resident holds in its binding.
pub(crate) fn direct_request(
    harness: DirectHarness,
    guard_home: &Path,
    query: &str,
    data: &str,
    budget: Duration,
) -> Option<Vec<u8>> {
    let query = parse_hook_query(query)?;
    // The daemon reviews the hook as this harness instead.
    if query
        .runtime_harness
        .as_deref()
        .is_some_and(|harness| !py_strip(harness).is_empty())
    {
        return None;
    }
    let resolved_guard_home = std::fs::canonicalize(guard_home).ok()?;
    if resolved_directory(query.guard_home.as_deref()?)? != resolved_guard_home {
        return None;
    }
    let home = match query.home.as_deref() {
        Some(home) => Some(resolved_directory(home)?),
        None => None,
    };
    if home.as_ref().is_some_and(|home| {
        resolved_guard_home
            .parent()
            .is_none_or(|parent| !home.starts_with(parent))
    }) {
        return None;
    }
    let payload: Value = serde_json::from_str(data).ok()?;
    if !payload.is_object() {
        return None;
    }
    let budget_ms = u64::try_from(budget.as_millis()).ok()?.max(1);
    let mut request = json!({
        "harness": harness.name,
        "guard_home": path_text(&resolved_guard_home)?,
        "deadline_budget_ms": budget_ms,
        "payload": payload,
    });
    if let Some(home) = home {
        request["home_dir"] = Value::String(path_text(&home)?);
    }
    if let Some(workspace) = query.workspace {
        request["workspace"] = Value::String(workspace);
    }
    serde_json::to_vec(&json!({ "operation": "hook_direct", "request": request })).ok()
}

/// The harness response of an `answer`, or `None` for a defer or anything
/// that is not a well-formed `hook_direct` result.
pub(crate) fn answered_response(output: &[u8]) -> Option<String> {
    let result: Value = serde_json::from_slice(output).ok()?;
    if result.get("schema")?.as_str()? != DIRECT_RESULT_SCHEMA
        || result.get("outcome")?.as_str()? != "answer"
    {
        return None;
    }
    let response = result.get("edge")?.get("harness_response")?;
    if !response.is_object() {
        return None;
    }
    serde_json::to_string(response).ok()
}

fn direct_enabled(harness: DirectHarness) -> bool {
    std::env::var_os(harness.switch).is_none_or(|value| value != "0")
}

/// Send the request to a live resident that runs this very executable.
fn send_to_live_resident(state_base: &Path, request: &[u8], deadline: Instant) -> Option<Vec<u8>> {
    // Discovery checks the directory's privacy; it must already exist.
    if !std::fs::symlink_metadata(state_base).is_ok_and(|metadata| metadata.is_dir()) {
        return None;
    }
    let states = crate::resident_state::discover_home_states_prefer(state_base, None).ok()?;
    for (_scope, _digest, state) in states {
        if crate::resident_state::validate_same_executable_process_identity(
            state.process_id,
            &state.process_start_marker,
        )
        .is_err()
        {
            continue;
        }
        let token = crate::resident_state::token_from_state(&state).ok()?;
        let timeout = remaining(deadline);
        if timeout < MINIMUM_DIRECT_TIMEOUT {
            return None;
        }
        let identity = crate::resident_client::ExpectedProcessIdentity {
            process_id: state.process_id,
            start_marker: &state.process_start_marker,
            digest: None,
        };
        // One live resident serves a home; any failure goes to the daemon.
        return crate::resident_client::send_request_for_digest_detailed(
            &state.transport,
            &state.endpoint,
            &token,
            request,
            timeout,
            &identity,
        )
        .ok();
    }
    None
}

/// The harness response a live resident answered for this hook, or `None`
/// to take the daemon path.
pub(crate) fn direct_answer(
    harness: DirectHarness,
    guard_home: &Path,
    query: &str,
    event_name: &str,
    data: &str,
    rpc_deadline: Instant,
) -> Option<String> {
    if ![PRE_TOOL_USE, POST_TOOL_USE, USER_PROMPT_SUBMIT].contains(&event_name)
        || !direct_enabled(harness)
    {
        return None;
    }
    let deadline = Instant::now() + remaining(rpc_deadline).min(DIRECT_TIMEOUT);
    let request = direct_request(harness, guard_home, query, data, remaining(deadline))?;
    let output = send_to_live_resident(&guard_home.join(STATE_DIRECTORY), &request, deadline)?;
    answered_response(&output)
}

#[cfg(test)]
#[path = "codex_hook_bridge_direct_tests.rs"]
mod tests;
