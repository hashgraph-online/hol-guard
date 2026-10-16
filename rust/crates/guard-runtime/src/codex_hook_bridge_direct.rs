//! Direct resident answers for Codex, Claude Code, Cursor and bounded
//! harness tool hooks.
//!
//! For a `PreToolUse` hook the edge allows or blocks outright, and for every
//! reviewed `PostToolUse` and `UserPromptSubmit` hook the daemon does not
//! restyle, of these harnesses the daemon forwards the payload to its resident
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
use crate::codex_hook_bridge_direct_resident::send_to_live_resident;
use crate::codex_hook_response::{POST_TOOL_USE, PRE_TOOL_USE};

const STATE_DIRECTORY: &str = "native-runtime";
const DIRECT_RESULT_SCHEMA: &str = "guard-hook-direct-result.v1";
const USER_PROMPT_SUBMIT: &str = "UserPromptSubmit";
/// Claude Code's permission dialog, which the resident answers from the
/// session's permission notice, and Codex's, which it leaves to Codex.
const PERMISSION_REQUEST: &str = "PermissionRequest";
const NOTIFICATION: &str = "Notification";

/// A harness whose passed-through `PreToolUse` hook the daemon answers with
/// the edge's own response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectHarness {
    pub(crate) name: &'static str,
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
/// Oh My Pi and its `omp` install, whose generated extension runs the native
/// Pi bridge. `HOL_GUARD_PI_DIRECT_HOOK=0` keeps their hooks on the daemon,
/// which then asks the resident itself unless the same switch is set.
pub(crate) const PI: DirectHarness = DirectHarness {
    name: "pi",
    switch: "HOL_GUARD_PI_DIRECT_HOOK",
};
pub(crate) const OMP: DirectHarness = DirectHarness {
    name: "omp",
    switch: "HOL_GUARD_PI_DIRECT_HOOK",
};
/// The bounded bridge harnesses the resident answers. The resident routes a
/// ZCode sandbox requirement to contained execution as the daemon does.
/// Grok runs its own client, which asks through [`grok_direct_answer`].
const BOUNDED_DIRECT_HARNESSES: [&str; 8] = [
    "copilot", "kimi", "devin", "zcode", "openclaw", "hermes", "cline", "opencode",
];
const BOUNDED_DIRECT_SWITCH: &str = "HOL_GUARD_BOUNDED_DIRECT_HOOK";
const GROK: &str = "grok";
/// A resident answers an allow well inside this. A slower resident leaves
/// the daemon most of the hook's budget.
const DIRECT_TIMEOUT: Duration = Duration::from_millis(1_000);

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
pub(crate) fn unquote_plus(text: &str) -> Option<String> {
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
    request_body(
        harness.name,
        &resolved_guard_home,
        home.as_deref(),
        query.workspace,
        data,
        budget,
    )
}

/// The `hook_direct` request for a bounded bridge hook, which reaches the
/// daemon without a query: the daemon then reviews it under its own guard
/// home and home, and takes the workspace from the payload alone.
///
/// The daemon names its guard home as the store holds it, which is the
/// resolved path for any configured home and the user's home joined with
/// the Guard directory otherwise. The install writes that same path into the
/// bridge config, so the request is sent only when the config's guard home
/// already is its resolved path; the edge then sees the daemon's spelling.
pub(crate) fn bounded_direct_request(
    harness: &str,
    guard_home: &Path,
    data: &str,
    budget: Duration,
) -> Option<Vec<u8>> {
    let name = BOUNDED_DIRECT_HARNESSES
        .iter()
        .find(|name| **name == harness)?;
    let resolved_guard_home = std::fs::canonicalize(guard_home).ok()?;
    if resolved_guard_home.as_path() != guard_home {
        return None;
    }
    request_body(name, &resolved_guard_home, None, None, data, budget)
}

/// The `hook_direct` request for a Grok hook, which reaches the daemon with
/// only `?home=`: the daemon reviews it under its own guard home and takes
/// the workspace from the payload. The request is sent only when the
/// config's guard home is its resolved path, as for the other bounded
/// bridge harnesses, and a non-blank `home` resolves at or under that guard
/// home's parent, where the daemon keeps it. A blank `home` is dropped from
/// the query, so the daemon uses its own, as the resident does.
pub(crate) fn grok_direct_request(
    guard_home: &Path,
    home: &str,
    data: &str,
    budget: Duration,
) -> Option<Vec<u8>> {
    let resolved_guard_home = std::fs::canonicalize(guard_home).ok()?;
    if resolved_guard_home.as_path() != guard_home {
        return None;
    }
    let home = if home.is_empty() {
        None
    } else {
        let home = resolved_directory(home)?;
        if !home.starts_with(resolved_guard_home.parent()?) {
            return None;
        }
        Some(home)
    };
    request_body(
        GROK,
        &resolved_guard_home,
        home.as_deref(),
        None,
        data,
        budget,
    )
}

fn request_body(
    harness: &str,
    guard_home: &Path,
    home: Option<&Path>,
    workspace: Option<String>,
    data: &str,
    budget: Duration,
) -> Option<Vec<u8>> {
    let payload: Value = serde_json::from_str(data).ok()?;
    if !payload.is_object() {
        return None;
    }
    let budget_ms = u64::try_from(budget.as_millis()).ok()?.max(1);
    let mut request = json!({
        "harness": harness,
        "guard_home": path_text(guard_home)?,
        "deadline_budget_ms": budget_ms,
        "payload": payload,
    });
    if let Some(home) = home {
        request["home_dir"] = Value::String(path_text(home)?);
    }
    if let Some(workspace) = workspace {
        request["workspace"] = Value::String(workspace);
    }
    serde_json::to_vec(&json!({
        "operation": "hook_direct",
        // Without a budget the resident client falls back to 750 ms.
        "deadline_budget_ms": budget_ms,
        "request": request,
    }))
    .ok()
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

fn direct_enabled(switch: &str) -> bool {
    std::env::var_os(switch).is_none_or(|value| value != "0")
}

/// Whether the resident may answer a hook the bridge names `event_name`: a
/// tool or prompt hook it reviews, or a lifecycle hook it answers with the
/// daemon's constant. Permission and notification hooks, and the `before*`
/// hooks the daemon denies, go to the daemon without asking the resident;
/// `direct_answer` asks it about Claude Code's `PermissionRequest` and
/// `Notification`, and Codex's `PermissionRequest`; `bounded_direct_answer`
/// asks it about Copilot's, Devin's and ZCode's `PermissionRequest`.
fn direct_event(event_name: &str) -> bool {
    if [PRE_TOOL_USE, POST_TOOL_USE, USER_PROMPT_SUBMIT].contains(&event_name) {
        return true;
    }
    let compact = event_name.replace(['_', '-'], "").to_ascii_lowercase();
    !(compact.is_empty()
        || compact.contains("permission")
        || compact.contains("notification")
        || compact.starts_with("before"))
}

/// Bounded harnesses whose `PermissionRequest` the resident passes through
/// to the harness's own approval prompt.
const PASSTHROUGH_PERMISSION_HARNESSES: [&str; 3] = ["copilot", "devin", "zcode"];

/// `direct_event`, plus the `PermissionRequest` of a bounded harness the
/// resident leaves to the harness's own approval prompt.
fn bounded_event(harness: &str, event_name: &str) -> bool {
    direct_event(event_name)
        || (PASSTHROUGH_PERMISSION_HARNESSES.contains(&harness)
            && ["permissionrequest", "permissionrequestv2"].contains(
                &event_name
                    .replace(['_', '-'], "")
                    .to_ascii_lowercase()
                    .as_str(),
            ))
}

/// `direct_event`, plus Claude Code's `PermissionRequest` and
/// `Notification`, and Codex's `PermissionRequest`.
fn harness_event(harness: &DirectHarness, event_name: &str) -> bool {
    direct_event(event_name)
        || (harness.name == CLAUDE_CODE.name
            && [PERMISSION_REQUEST, NOTIFICATION].contains(&event_name))
        || (harness.name == CODEX.name && event_name == PERMISSION_REQUEST)
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
    if !harness_event(&harness, event_name) || !direct_enabled(harness.switch) {
        return None;
    }
    let deadline = Instant::now() + remaining(rpc_deadline).min(DIRECT_TIMEOUT);
    let request = direct_request(harness, guard_home, query, data, remaining(deadline))?;
    let output = send_to_live_resident(&guard_home.join(STATE_DIRECTORY), &request, deadline)?;
    answered_response(&output)
}

/// The harness response a live resident answered for a bounded bridge hook,
/// or `None` to take the daemon path.
pub(crate) fn bounded_direct_answer(
    harness: &str,
    guard_home: &Path,
    event_name: &str,
    data: &str,
    rpc_deadline: Instant,
) -> Option<String> {
    if !bounded_event(harness, event_name) || !direct_enabled(BOUNDED_DIRECT_SWITCH) {
        return None;
    }
    let deadline = Instant::now() + remaining(rpc_deadline).min(DIRECT_TIMEOUT);
    let request = bounded_direct_request(harness, guard_home, data, remaining(deadline))?;
    let output = send_to_live_resident(&guard_home.join(STATE_DIRECTORY), &request, deadline)?;
    answered_response(&output)
}

/// The harness response a live resident answered for a Grok hook, or `None`
/// to take the daemon path. The bridge asks for a prompt only once the
/// daemon reports its workspace ready, with the time left stamped, as the
/// daemon would receive it.
pub(crate) fn grok_direct_answer(
    guard_home: &Path,
    home: &str,
    event_name: &str,
    data: &str,
    rpc_deadline: Instant,
) -> Option<String> {
    if !direct_event(event_name) || !direct_enabled(BOUNDED_DIRECT_SWITCH) {
        return None;
    }
    let deadline = Instant::now() + remaining(rpc_deadline).min(DIRECT_TIMEOUT);
    let request = grok_direct_request(guard_home, home, data, remaining(deadline))?;
    let output = send_to_live_resident(&guard_home.join(STATE_DIRECTORY), &request, deadline)?;
    answered_response(&output)
}

/// The harness response a live resident answered for `data` as `harness`
/// would send it from `workspace`, or `None` when no resident answered.
/// The contained-workspace sink asks this way for the receipt it runs under.
#[cfg(unix)]
pub(crate) fn resident_hook_answer(
    harness: &str,
    guard_home: &Path,
    home: &Path,
    workspace: &str,
    data: &str,
    deadline: Instant,
) -> Option<String> {
    let request = request_body(
        harness,
        guard_home,
        Some(home),
        Some(workspace.to_owned()),
        data,
        remaining(deadline),
    )?;
    let output = send_to_live_resident(&guard_home.join(STATE_DIRECTORY), &request, deadline)?;
    answered_response(&output)
}

#[cfg(all(test, unix))]
#[path = "codex_hook_bridge_direct_tests.rs"]
mod tests;
