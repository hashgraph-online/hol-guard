//! Route a Claude Code or ZCode sandbox requirement to Guard's contained
//! execution sink, as the daemon's containment router does.
//!
//! The edge answers a contained test, eval, build or workspace run with a
//! denial that names the execution profile the call needs. The daemon turns
//! that denial into Guard's `execute-contained-test` sink: it writes a
//! private snapshot of the call and allows the harness to run the sink in
//! place of the original command through `updatedInput`. The sink reruns
//! native authority on the snapshot, so the rewrite grants nothing by
//! itself. This module repeats that rewrite with the sink command the daemon
//! published in the direct-lane binding.

use super::HookDirectDefer;
use serde_json::{json, Map, Value};

const ROUTED_REASON: &str = "native_contained_execution_routed";
const RECEIPT_ONLY_FIELD: &str = "guard_containment_receipt_only";
#[cfg(any(target_os = "linux", all(unix, test)))]
const WORKSPACE_PROFILE: &str = "workspace-contained-v1";
/// Set to `0` to keep every workspace sandbox on the daemon's sink.
#[cfg(target_os = "macos")]
const NATIVE_SINK_SWITCH: &str = "HOL_GUARD_NATIVE_CONTAINED_SINK";
/// Command text whose meaning depends on what the native sink does not yet
/// replay: pipes, stderr folding, exit-status reads, home expansion, and
/// tool flags that move the working directory.
#[cfg(any(target_os = "macos", all(unix, test)))]
const NATIVE_SINK_UNSUPPORTED: [&str; 8] =
    ["|", "2>&1", "$?", "~", "--cwd", "--prefix", "--dir", " -C"];
const PRE_TOOL_EVENTS: [&str; 2] = ["PreToolUse", "pre_tool_use"];
const SHELL_TOOLS: [&str; 4] = ["Bash", "bash", "run_terminal_command", "run_command"];

/// Where the rewritten call runs, as the daemon would name it.
pub(super) struct SinkTarget<'a> {
    /// The argv prefix that starts the daemon's Guard CLI.
    pub(super) command: &'a [String],
    pub(super) harness: &'a str,
    pub(super) guard_home: &'a str,
    pub(super) home_dir: &'a str,
    pub(super) workspace: &'a str,
}

/// A routed harness response and the request snapshot it runs.
pub(super) type Routed = (Value, Snapshot);

/// A written request snapshot. It is removed when dropped, so a direct
/// answer that defers after routing leaves nothing behind for the daemon,
/// which writes its own; `keep` hands it to the sink the answer runs.
pub(super) struct Snapshot {
    request: Option<std::path::PathBuf>,
}

impl Snapshot {
    #[cfg_attr(not(unix), allow(dead_code))]
    fn new(request: std::path::PathBuf) -> Self {
        Self {
            request: Some(request),
        }
    }

    pub(super) fn keep(mut self) {
        self.request = None;
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        if let Some(request) = self.request.take() {
            let _ = std::fs::remove_file(&request);
            if let Some(directory) = request.parent() {
                let _ = std::fs::remove_dir(directory);
            }
        }
    }
}

/// The routed harness response for the edge's `response`, or `None` when the
/// daemon would return `response` unchanged. A request the resident cannot
/// write defers, so the daemon takes the call.
pub(super) fn route(
    response: &Value,
    payload: &Map<String, Value>,
    target: &SinkTarget<'_>,
) -> Result<Option<Routed>, HookDirectDefer> {
    route_on(
        response,
        payload,
        target,
        Host {
            platform: platform_contains,
            native: native_sink,
        },
        &std::env::temp_dir(),
    )
}

/// What the host runs: the contained profiles `platform` accepts, and the
/// runtime's own sink for the calls `native` names it for.
struct Host {
    platform: fn(&str) -> bool,
    native: fn(&Value, &Map<String, Value>) -> Option<String>,
}

/// `route` on `host`, with request snapshots under `temp`.
fn route_on(
    response: &Value,
    payload: &Map<String, Value>,
    target: &SinkTarget<'_>,
    host: Host,
    temp: &std::path::Path,
) -> Result<Option<Routed>, HookDirectDefer> {
    let platform = host.platform;
    // The sink asks for the receipt alone; an untrusted caller setting this
    // only keeps its own call denied.
    if payload.get(RECEIPT_ONLY_FIELD) == Some(&Value::Bool(true)) || !routable(response, platform)
    {
        return Ok(None);
    }
    let Some(original) = shell_input(payload) else {
        return Ok(None);
    };
    let native = (host.native)(response, original);
    request::write_and_route(temp, payload, original, target, native.as_deref())
}

/// The runtime executable, when it runs this call's sink itself: a macOS
/// workspace sandbox of a shape the native sink reproduces. Any other call
/// keeps the daemon's sink.
#[cfg(target_os = "macos")]
fn native_sink(response: &Value, original: &Map<String, Value>) -> Option<String> {
    if !native_shape(response, original)
        || std::env::var_os(NATIVE_SINK_SWITCH).is_some_and(|value| value == "0")
    {
        return None;
    }
    let executable = std::env::current_exe().ok()?;
    executable
        .is_file()
        .then(|| executable.to_str().map(str::to_owned))
        .flatten()
}

#[cfg(not(target_os = "macos"))]
fn native_sink(_response: &Value, _original: &Map<String, Value>) -> Option<String> {
    None
}

/// Whether the native sink reproduces this workspace sandbox: a plain
/// workspace run, not a chain whose Git steps follow the checks, started in
/// the workspace itself, with no pipe, redirection of stderr, exit-status
/// read, home expansion or directory change the sink does not yet replay.
#[cfg(any(target_os = "macos", all(unix, test)))]
fn native_shape(response: &Value, original: &Map<String, Value>) -> bool {
    use crate::contained_workspace_sink::{PUBLISH_REASON, WORKSPACE_PROFILE, WORKSPACE_REASON};
    let text = |name: &str| response.get(name).and_then(Value::as_str);
    let Some(command) = original.get("command").and_then(Value::as_str) else {
        return false;
    };
    text("reason_code") == Some(WORKSPACE_REASON)
        && text("required_execution_profile") == Some(WORKSPACE_PROFILE)
        && text("reason") != Some(PUBLISH_REASON)
        && !original.contains_key("cwd")
        && !command.trim_start().starts_with("cd")
        && !NATIVE_SINK_UNSUPPORTED
            .iter()
            .any(|fragment| command.contains(fragment))
}

/// Whether the daemon routes this edge response: a contained-run denial
/// outside Watch whose profile matches its reason and runs on this platform.
fn routable(response: &Value, platform: fn(&str) -> bool) -> bool {
    let text = |name: &str| response.get(name).and_then(Value::as_str);
    let Some(profile) =
        text("reason_code").and_then(guard_command::hook_responses::contained_execution_profile)
    else {
        return false;
    };
    platform(profile)
        && text("decision") == Some("deny")
        && text("policy_action") == Some("sandbox-required")
        && response.get("observe_mode") != Some(&Value::Bool(true))
        && text("required_execution_profile") == Some(profile)
}

/// macOS runs every contained profile; Linux runs the workspace sandbox.
fn platform_contains(profile: &str) -> bool {
    #[cfg(target_os = "macos")]
    {
        let _ = profile;
        true
    }
    #[cfg(target_os = "linux")]
    {
        profile == WORKSPACE_PROFILE
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = profile;
        false
    }
}

/// The value of the first of `names` the payload carries, as the daemon's
/// chained `get` reads it.
fn first<'a>(payload: &'a Map<String, Value>, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| payload.get(*name))
}

/// The tool input of a shell `PreToolUse` call with a string command.
fn shell_input(payload: &Map<String, Value>) -> Option<&Map<String, Value>> {
    let event = first(payload, &["hook_event_name", "hookEventName"])?.as_str()?;
    let tool = first(payload, &["tool_name", "toolName"])?.as_str()?;
    if !PRE_TOOL_EVENTS.contains(&event) || !SHELL_TOOLS.contains(&tool) {
        return None;
    }
    let original = first(payload, &["tool_input", "toolInput"])?.as_object()?;
    original.get("command")?.as_str()?;
    Some(original)
}

/// The harness response that runs `command` in place of the original call.
fn routed_response(original: &Map<String, Value>, command: &[String]) -> Value {
    let mut updated = original.clone();
    updated.insert(
        "command".to_owned(),
        Value::String(crate::mcp_proxy_shlex::join(command)),
    );
    json!({
        "policy_action": "allow",
        "reason_code": ROUTED_REASON,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "updatedInput": updated,
        },
    })
}

#[cfg(unix)]
#[path = "hook_direct_contained_request.rs"]
pub(crate) mod request;

#[cfg(not(unix))]
mod request {
    use super::{HookDirectDefer, Routed, SinkTarget};
    use serde_json::{Map, Value};

    pub(super) fn write_and_route(
        _temp: &std::path::Path,
        _payload: &Map<String, Value>,
        _original: &Map<String, Value>,
        _target: &SinkTarget<'_>,
        _native: Option<&str>,
    ) -> Result<Option<Routed>, HookDirectDefer> {
        Err(HookDirectDefer::ContainedRouteFailed)
    }
}

#[cfg(test)]
#[path = "hook_direct_contained_tests.rs"]
mod tests;
