//! The Cursor `PreToolUse` the resident answers.
//!
//! A Cursor `PostToolUse` (the client's `afterShellExecution` and
//! `afterMCPExecution` observers) takes the shared `PostToolUse` lane: the
//! daemon has no Cursor step for it and records the edge's response, as the
//! drain does. A Cursor prompt takes the shared prompt lane: the daemon
//! accepts its receipt and returns the edge's response, with no notice.
//! Outside Watch, a review this module leaves takes the shared saved
//! decision, approve-once and approval inbox path, which keeps a pause the
//! Cursor client would rewrite with the daemon.
//!
//! Cursor sends a shell call to two hooks. Its `preToolUse` for `Shell` may
//! rewrite the call through `updated_input`; `beforeShellExecution`, which
//! runs next with the rewritten command, cannot rewrite anything. Guard's
//! Cursor hook names the first one a route probe. The resident answers the
//! probe with the contained sink command when the edge routes the call to
//! the sink, and with a plain allow otherwise, and it admits the sink command
//! that probe wrote when `beforeShellExecution` runs it. Neither is recorded:
//! `beforeShellExecution` stays the one check the user sees, and the sink
//! re-authorizes the saved call before it runs anything. A workspace sandbox
//! the runtime's own sink reproduces runs there instead, on the direct lane
//! and on the daemon path when the daemon admits that sink too; its command
//! is admitted only when it names this runtime's executable. On Windows, and
//! for any other shell call naming the probe or the sink, the daemon reviews
//! the call as usual.

use super::{reviewed_edge, HookDirectDefer, CURSOR, PRE_TOOL_USE};
use crate::hook_decision_containment_rewrite::{containment_rewrite_with, Native};
use crate::hook_decision_containment_route::{edge_route, host_platform};
use admission::admitted;
use guard_command::hook_responses::pre_tool;
use guard_contracts::{ContainmentRewriteInputsV1, GuardHookSourceMetadataV2};
use serde_json::{json, Map, Value};
use std::path::Path;

/// The runtime's own sink verb (`contained_workspace_sink::SINK_COMMAND`),
/// spelled here because that module is built only on Unix.
const NATIVE_SINK_VERB: &str = "contained-workspace-sink";

const SHELL_TOOL: &str = "Shell";
const SOURCE_HOOK_FIELD: &str = "cursor_source_hook_event";
const PROBE_FIELD: &str = "cursor_route_probe";
const BEFORE_SHELL: &str = "beforeShellExecution";
const RECEIPT_ONLY_FIELD: &str = "guard_containment_receipt_only";
const SINK_VERB: &str = "execute-contained-test";
const ROUTED_REASON: &str = "native_contained_execution_routed";
/// The sink rewrite reads a Claude-shaped receipt (policy fields beside
/// `hookSpecificOutput`). Cursor's own rendering has neither, so the probe
/// renders the verdict in ZCode's shape; the hook copies only the rewritten
/// input back to Cursor.
const RECEIPT_FORMAT: &str = "zcode";

/// How the resident takes a Cursor `PreToolUse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Route {
    /// Any call that is neither the probe nor the sink: the shared review.
    Review,
    /// Cursor's `preToolUse` for `Shell`, named by Guard's hook.
    Probe,
    /// A `beforeShellExecution` that names the contained sink.
    Sink,
}

/// Why the resident hands a Cursor route probe or sink command to the
/// daemon. Each reason counts under its own code, so the diagnostics show
/// which check a deferred probe or sink failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CursorDefer {
    /// Windows, where the daemon reviews every probe and sink.
    Platform,
    /// A call that carries `guard_containment_receipt_only`.
    ReceiptOnly,
    /// A `Shell` call Guard's hook did not name as its route probe.
    ProbeUnnamed,
    /// A command naming the sink outside `beforeShellExecution`.
    SinkSource,
    /// A sink command that is not the argv a probe writes for this Guard
    /// home, or whose digest is not one.
    SinkArgv,
    /// A sink command naming another home than the hook's.
    SinkHome,
    /// A sink command naming another workspace than the hook's.
    SinkWorkspace,
    /// A sink command whose request is not a snapshot under the temporary
    /// directory.
    SinkSnapshot,
}

impl CursorDefer {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Platform => "direct_hook_cursor_platform",
            Self::ReceiptOnly => "direct_hook_cursor_receipt_only",
            Self::ProbeUnnamed => "direct_hook_cursor_probe_unnamed",
            Self::SinkSource => "direct_hook_cursor_sink_source",
            Self::SinkArgv => "direct_hook_cursor_sink_argv",
            Self::SinkHome => "direct_hook_cursor_sink_home",
            Self::SinkWorkspace => "direct_hook_cursor_sink_workspace",
            Self::SinkSnapshot => "direct_hook_cursor_sink_snapshot",
        }
    }
}

/// Where the probe's sink command runs, as the binding names it.
pub(super) struct Scope {
    workspace: String,
    home_dir: String,
    guard_home: String,
    sink_command: Vec<String>,
    native: bool,
}

impl Scope {
    pub(super) fn new(
        workspace: &str,
        home_dir: &str,
        guard_home: &str,
        sink_command: Option<&[String]>,
    ) -> Result<Self, HookDirectDefer> {
        Ok(Self {
            workspace: workspace.to_owned(),
            home_dir: home_dir.to_owned(),
            guard_home: guard_home.to_owned(),
            sink_command: sink_command
                .ok_or(HookDirectDefer::BindingIncomplete)?
                .to_vec(),
            native: false,
        })
    }

    /// The scope a probe may route to the runtime's own sink, when the
    /// caller admits that sink's command on `beforeShellExecution` too.
    pub(super) fn with_native_sink(mut self) -> Self {
        self.native = true;
        self
    }
}

/// The route for a Cursor `PreToolUse`. A `Shell` call Guard's hook did not
/// name as a probe, a sink command outside `beforeShellExecution`, a
/// receipt-only call and every probe or sink on Windows keep the daemon's
/// ordinary review.
pub(super) fn route(payload: &Map<String, Value>) -> Result<Route, HookDirectDefer> {
    let text = |name: &str| payload.get(name).and_then(Value::as_str);
    let probe = text("tool_name") == Some(SHELL_TOOL) && !payload.contains_key(SOURCE_HOOK_FIELD);
    let sink = command(payload)
        .is_some_and(|command| command.contains(SINK_VERB) || command.contains(NATIVE_SINK_VERB));
    if !probe && !sink {
        return Ok(Route::Review);
    }
    let receipt_only = payload
        .get(RECEIPT_ONLY_FIELD)
        .is_some_and(|value| !value.is_null());
    let route = if cfg!(windows) {
        Err(CursorDefer::Platform)
    } else if receipt_only {
        Err(CursorDefer::ReceiptOnly)
    } else if probe {
        (text("hook_event_name") == Some(PRE_TOOL_USE)
            && payload.get(PROBE_FIELD) == Some(&Value::Bool(true)))
        .then_some(Route::Probe)
        .ok_or(CursorDefer::ProbeUnnamed)
    } else {
        (text(SOURCE_HOOK_FIELD) == Some(BEFORE_SHELL))
            .then_some(Route::Sink)
            .ok_or(CursorDefer::SinkSource)
    };
    route.map_err(HookDirectDefer::Cursor)
}

/// The probe's plain allow when the sink cannot take the call, before the
/// edge reviews it: a call with no command text, one that names a directory
/// other than the workspace the sink runs in, or any call in Watch, which
/// never routes.
pub(super) fn unreviewed_probe(
    payload: &Map<String, Value>,
    scope: &Scope,
    recording_only: bool,
) -> Option<Value> {
    let Some(input) = tool_input(payload).filter(|_| command(payload).is_some()) else {
        return Some(allow());
    };
    // Cursor names the directory at the top level and may repeat it in the call.
    let elsewhere = [
        payload.get("cwd"),
        input.get("cwd"),
        input.get("working_directory"),
    ]
    .into_iter()
    .flatten()
    .filter(|value| !value.is_null() && value.as_str() != Some(""))
    .any(|value| {
        !value
            .as_str()
            .is_some_and(|text| same_directory(text, scope))
    });
    (elsewhere || recording_only).then(allow)
}

/// The probe's answer once the edge reviewed it: the sink command when the
/// edge routes the call to the sink and the rewrite wrote its snapshot, and
/// a plain allow for anything else, since `beforeShellExecution` still
/// reviews the call that runs.
pub(super) fn probe_answer(edge: &[u8], payload: &Map<String, Value>, scope: &Scope) -> Value {
    serde_json::from_slice(edge).map_or_else(
        |_| allow(),
        |parsed| reviewed_probe(&parsed, payload, scope),
    )
}

/// `probe_answer` for an edge answer already read.
fn reviewed_probe(edge: &Value, payload: &Map<String, Value>, scope: &Scope) -> Value {
    routed(edge, payload, scope)
        .map_or_else(allow, |response| json!({ "harness_response": response }))
}

/// The edge's own answer to Cursor's route probe, when the daemon sent the
/// argv that starts Guard's CLI: the response `daemon_answer` gives for the
/// edge just produced, so the daemon makes one resident call instead of two.
/// With `native_sink` the daemon admits the runtime's own sink as well, so
/// a call that sink reproduces routes there. `None` for any call that is not
/// the probe.
pub(crate) fn edge_probe_answer(
    payload: &Map<String, Value>,
    edge: &Value,
    source: &GuardHookSourceMetadataV2,
    sink_command: &[String],
    native_sink: bool,
    recording_only: bool,
) -> Option<Value> {
    if !matches!(route(payload), Ok(Route::Probe)) {
        return None;
    }
    let scope = Scope::new(
        source.cwd.as_deref()?,
        &source.home_dir,
        &source.guard_home,
        Some(sink_command),
    )
    .ok()?;
    let scope = if native_sink {
        scope.with_native_sink()
    } else {
        scope
    };
    let answer = unreviewed_probe(payload, &scope, recording_only)
        .unwrap_or_else(|| reviewed_probe(edge, payload, &scope));
    answer.get("harness_response").cloned()
}

/// The sink's admission: the allow the daemon returns for the exact argv
/// the probe wrote, for this Guard home and home, a workspace that matches
/// the hook's, and a private snapshot under the temporary directory. The
/// sink itself opens the request owner-only, checks its digest and
/// re-authorizes the command, so admitting the command never widens what
/// runs. Any other command naming the sink takes the daemon's review.
pub(super) fn admit_sink(
    payload: &Map<String, Value>,
    scope: &Scope,
) -> Result<Value, HookDirectDefer> {
    admitted(payload, scope).map_err(HookDirectDefer::Cursor)?;
    Ok(json!({
        "harness_response": { "policy_action": "allow", "reason_code": ROUTED_REASON },
    }))
}

/// The daemon path's answer to Cursor's route probe or a call naming the
/// sink, for the `hook_render` op's `cursor_shell_route` kind.
///
/// The daemon reviews a probe through its own edge call and ships that edge
/// here with the call; the resident reads the rest, as the direct lane does.
/// A probe always gets a response: the sink command when the edge routes the
/// call to the sink and the rewrite wrote its snapshot, and a plain allow
/// otherwise. A `beforeShellExecution` gets the routed allow only for the
/// exact command a probe wrote. `None` keeps the daemon's ordinary review.
pub(crate) fn daemon_answer(params: &Map<String, Value>) -> Result<Option<Value>, &'static str> {
    const INVALID: &str = "native_hook_render_invalid";
    let text = |name: &str| params.get(name).and_then(Value::as_str).ok_or(INVALID);
    let payload = params
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    let sink_command = params
        .get("sink_command")
        .and_then(Value::as_array)
        .ok_or(INVALID)?
        .iter()
        .map(|part| part.as_str().map(str::to_owned).ok_or(INVALID))
        .collect::<Result<Vec<_>, _>>()?;
    let scope = Scope::new(
        text("workspace")?,
        text("home_dir")?,
        text("guard_home")?,
        Some(&sink_command),
    )
    .map_err(|_| INVALID)?;
    // A daemon that admits the runtime's own sink says so; an older one
    // reviews that command, so its probes keep Guard's sink.
    let scope = if params.get("native_sink") == Some(&Value::Bool(true)) {
        scope.with_native_sink()
    } else {
        scope
    };
    let answer = match route(payload) {
        Ok(Route::Probe) => {
            let edge = params.get("edge").ok_or(INVALID)?;
            unreviewed_probe(payload, &scope, false)
                .unwrap_or_else(|| reviewed_probe(edge, payload, &scope))
        }
        Ok(Route::Sink) => match admit_sink(payload, &scope) {
            Ok(admitted) => admitted,
            Err(_) => return Ok(None),
        },
        Ok(Route::Review) | Err(_) => return Ok(None),
    };
    Ok(answer.get("harness_response").cloned())
}

fn allow() -> Value {
    json!({ "harness_response": { "policy_action": "allow" } })
}

fn tool_input(payload: &Map<String, Value>) -> Option<&Map<String, Value>> {
    payload.get("tool_input").and_then(Value::as_object)
}

fn command(payload: &Map<String, Value>) -> Option<&str> {
    tool_input(payload)?.get("command")?.as_str()
}

/// The first of `names` the payload holds, as Python's chained `get` reads it.
fn first<'a>(payload: &'a Map<String, Value>, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| payload.get(*name))
}

fn routed(parsed: &Value, payload: &Map<String, Value>, scope: &Scope) -> Option<Value> {
    let edge_text = |name: &str| parsed.get(name).and_then(Value::as_str);
    if edge_text("harness") != Some(CURSOR) || edge_text("event_name") != Some(PRE_TOOL_USE) {
        return None;
    }
    let result = parsed.get("result")?;
    let route = match edge_text("containment_route") {
        Some(stamped @ ("none" | "sink" | "grant")) => stamped.to_owned(),
        _ => edge_route(PRE_TOOL_USE, result, false),
    };
    if route != "sink" {
        return None;
    }
    let receipt = pre_tool(RECEIPT_FORMAT, result.as_object()?);
    let receipt_text = |name: &str| receipt.get(name).and_then(Value::as_str).map(str::to_owned);
    let payload_text = |names: &[&str]| {
        first(payload, names)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let payload_value = |names: &[&str]| first(payload, names).cloned().unwrap_or(Value::Null);
    let inputs = ContainmentRewriteInputsV1 {
        harness: CURSOR.to_owned(),
        platform: host_platform().to_owned(),
        bridge: true,
        receipt_only: payload.get(RECEIPT_ONLY_FIELD) == Some(&Value::Bool(true)),
        event_name: payload_text(&["hook_event_name", "hookEventName"]),
        tool_name: payload_text(&["tool_name", "toolName"]),
        tool_input: payload_value(&["tool_input", "toolInput"]),
        decision: receipt_text("decision"),
        policy_action: receipt_text("policy_action"),
        reason_code: receipt_text("reason_code"),
        required_execution_profile: receipt_text("required_execution_profile"),
        observe_mode: receipt.get("observe_mode") == Some(&Value::Bool(true)),
        workspace: Some(scope.workspace.clone()),
        session_id: payload_value(&["session_id", "sessionId"]),
        tool_call_id: payload_value(&["tool_call_id", "toolCallId", "tool_use_id"]),
        guard_home: scope.guard_home.clone(),
        home: scope.home_dir.clone(),
        sink_command: scope.sink_command.clone(),
    };
    let native = receipt
        .get("reason")
        .filter(|_| scope.native)
        .map(|reason| Native {
            reason,
            sink: native_sink,
        });
    let response = containment_rewrite_with(&inputs, native).ok()?.response?;
    let text = |name: &str| response.get(name).and_then(Value::as_str);
    (text("policy_action") == Some("allow") && text("reason_code") == Some(ROUTED_REASON))
        .then_some(response)
}

/// The runtime's own sink for a Cursor call. Cursor may repeat the directory
/// in the call; the probe only reaches the sink when that names the
/// workspace, which the sink runs in anyway, so the repeat is set aside once
/// it still resolves there. Any other spelling keeps Guard's sink.
fn native_sink(response: &Value, original: &Map<String, Value>, workspace: &str) -> Option<String> {
    let mut call = original.clone();
    let root = std::fs::canonicalize(workspace).ok()?;
    for key in ["cwd", "working_directory"] {
        match call.remove(key) {
            None | Some(Value::Null) => {}
            Some(Value::String(text)) if text.is_empty() => {}
            Some(Value::String(text)) if std::fs::canonicalize(&text).ok()? == root => {}
            Some(_) => return None,
        }
    }
    super::contained::native_sink(response, &call, workspace)
}

/// Whether `value` names the workspace itself, after `~` expansion against
/// the hook's home. A relative or unreadable path never does.
fn same_directory(value: &str, scope: &Scope) -> bool {
    let expanded = match value.strip_prefix('~') {
        None => value.to_owned(),
        Some("") => scope.home_dir.clone(),
        Some(rest) if rest.starts_with('/') => format!("{}{rest}", scope.home_dir),
        Some(_) => return false,
    };
    if !Path::new(&expanded).is_absolute() {
        return false;
    }
    match (
        std::fs::canonicalize(&expanded),
        std::fs::canonicalize(&scope.workspace),
    ) {
        (Ok(named), Ok(workspace)) => named == workspace,
        _ => false,
    }
}

/// The edge result for a Cursor `PreToolUse`, when the daemon would return
/// it unchanged and the Cursor client renders it without Guard's Python:
/// a response the edge rendered as an allow or warn, for an allow with an
/// allow or warn floor or, in Watch, for any verdict; and outside Watch a
/// response the edge rendered as a block or sandbox requirement, for a
/// terminal block or sandbox floor. The daemon may pause a review and repair
/// an authority block, so neither of those is answered here; the caller
/// hands a review to the saved decision path.
pub(super) fn answer(edge: &[u8], recording_only: bool) -> Result<Value, HookDirectDefer> {
    let parsed = reviewed_edge(edge, PRE_TOOL_USE)?;
    let text = |value: Option<&Value>, name: &str| {
        value
            .and_then(|value| value.get(name))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let result = parsed.get("result");
    let field = |name: &str| text(result, name);
    let rendered = text(parsed.get("harness_response"), "policy_action");
    let rendered_allow = matches!(rendered.as_deref(), Some("allow" | "warn"));
    let rendered_deny = matches!(rendered.as_deref(), Some("block" | "sandbox-required"));
    let passed_through = if recording_only {
        rendered_allow
    } else {
        match (
            field("decision").as_deref(),
            field("minimum_action").as_deref(),
        ) {
            (Some("allow"), Some("allow" | "warn")) => rendered_allow,
            (Some("deny" | "block"), Some("block")) => rendered_deny,
            (Some("deny" | "block"), Some("sandbox-required")) => rendered_deny,
            _ => false,
        }
    };
    if !passed_through {
        return Err(HookDirectDefer::NotAllow);
    }
    Ok(parsed)
}

#[path = "hook_direct_cursor_admission.rs"]
mod admission;

#[cfg(all(test, unix))]
#[path = "hook_direct_cursor_route_tests.rs"]
mod tests;
