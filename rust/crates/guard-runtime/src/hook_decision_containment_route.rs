//! `HookDecide` `containment_route` and `containment_sink` — whether a native
//! PreToolUse answer is rewritten into Guard's contained execution sink.
//!
//! Both hook paths ask the same two questions, so the CLI fallback and the
//! daemon route a call identically:
//!
//! * `containment_route` reads the native result. A `sandbox-required`
//!   result goes to the sink; anything else keeps its answer, so an
//!   outside-roots review an allowed CLI covers is left to the edge's custom
//!   rule, which allows it.
//! * `containment_sink` reads the rendered receipt, the harness, the host and
//!   the shape of the call, and names the profile the sink runs it under, or
//!   why the receipt stands.
//!
//! The host table is explicit: macOS runs every contained profile, Linux the
//! workspace sandbox, Windows installed Python and Node scripts, a project's
//! own pytest, Vite builds and local tool checks, and only for Claude Code and
//! Codex. Any other host has no sink and says so; nothing here allows a call.
//!
//! The approval invariant holds: a review that is not routed keeps its card
//! with Allow once and Always allow, and a review an allowed CLI lifts runs
//! as that Always allow would. A malformed query is an error the transport
//! reports as a resident outage, never a default route.

use guard_contracts::{
    ContainmentRouteInputsV1, ContainmentRouteV1, ContainmentSinkInputsV1, ContainmentSinkV1,
    NATIVE_BASH_DELIVERY_REASON,
};
use serde_json::Value;

const PRE_TOOL_USE: &str = "PreToolUse";
const SANDBOX_REQUIRED: &str = "sandbox-required";
const PRE_TOOL_EVENTS: [&str; 2] = ["PreToolUse", "pre_tool_use"];
const SHELL_TOOLS: [&str; 5] = [
    "Bash",
    "bash",
    "run_terminal_command",
    "run_command",
    "Shell",
];
/// Harnesses whose hook applies `updatedInput` on its own. Codex is routed
/// only by its bridge, which first confirms the running Codex applies it,
/// and Cursor only by its silent `preToolUse` probe for `Shell`, whose
/// `updated_input` Cursor applies before `beforeShellExecution` runs.
const ROUTED_HARNESSES: [&str; 2] = ["zcode", "claude-code"];
const BRIDGE_HARNESSES: [&str; 2] = ["codex", "cursor"];
/// The sink command is quoted for Git Bash, or PowerShell for Codex; any
/// other harness on Windows keeps its single review.
const WINDOWS_SINK_HARNESSES: [&str; 2] = ["claude-code", "codex"];
const LINUX_PROFILES: [&str; 1] = ["workspace-contained-v1"];
const WINDOWS_PROFILES: [&str; 5] = [
    "python-eval-readonly-v1",
    "node-eval-readonly-v1",
    "node-build-output-v1",
    "node-tool-readonly-v1",
    "pytest-readonly-v2",
];

/// The host a hook runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Host {
    MacOs,
    Linux,
    Windows,
    Other,
}

impl Host {
    fn parse(platform: &str) -> Option<Self> {
        Some(match platform {
            "macos" => Self::MacOs,
            "linux" => Self::Linux,
            "windows" => Self::Windows,
            "other" => Self::Other,
            _ => return None,
        })
    }

    /// Whether this host's sink runs `profile`.
    fn runs(self, profile: &str) -> bool {
        match self {
            Self::MacOs => true,
            Self::Linux => LINUX_PROFILES.contains(&profile),
            Self::Windows => WINDOWS_PROFILES.contains(&profile),
            Self::Other => false,
        }
    }
}

pub(crate) fn containment_route(
    inputs: &ContainmentRouteInputsV1,
) -> Result<ContainmentRouteV1, String> {
    Ok(ContainmentRouteV1 {
        route: route(inputs).to_owned(),
    })
}

/// The `containment_route` answer for an edge `result`, stamped on
/// the edge so a hook does not spend a second round trip asking for it. It
/// reads the same fields the decision query sends.
pub(crate) fn edge_route(event_name: &str, result: &Value, recording_only: bool) -> String {
    let text = |key: &str| result.get(key).and_then(Value::as_str).map(str::to_owned);
    let inputs = ContainmentRouteInputsV1 {
        event_name: Some(event_name.to_owned()),
        recording_only,
        minimum_action: text("minimum_action"),
        policy_action: text("policy_action"),
        reason_code: text("reason_code"),
        action_type: result
            .get("action")
            .and_then(|action| action.get("action_type"))
            .cloned(),
    };
    route(&inputs).to_owned()
}

/// The host as the resident's containment decisions name it.
pub(crate) fn host_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(windows) {
        "windows"
    } else {
        "other"
    }
}

fn route(inputs: &ContainmentRouteInputsV1) -> &'static str {
    if inputs.recording_only || inputs.event_name.as_deref() != Some(PRE_TOOL_USE) {
        return "none";
    }
    let is = |field: &Option<String>, value: &str| field.as_deref() == Some(value);
    if is(&inputs.minimum_action, SANDBOX_REQUIRED) || is(&inputs.policy_action, SANDBOX_REQUIRED) {
        return "sink";
    }
    "none"
}

pub(crate) fn containment_sink(
    inputs: &ContainmentSinkInputsV1,
) -> Result<ContainmentSinkV1, String> {
    let host = Host::parse(&inputs.platform)
        .ok_or_else(|| "native_hook_decision_payload_invalid".to_owned())?;
    Ok(match sink(inputs, host) {
        Ok(profile) => ContainmentSinkV1 {
            profile: Some(profile.to_owned()),
            kept_because: None,
        },
        Err(kept_because) => ContainmentSinkV1 {
            profile: None,
            kept_because: Some(kept_because.to_owned()),
        },
    })
}

fn sink(inputs: &ContainmentSinkInputsV1, host: Host) -> Result<&'static str, &'static str> {
    // The sink re-authorizing wants the receipt itself; an untrusted caller
    // setting the flag only keeps its own call denied.
    if inputs.receipt_only {
        return Err("receipt_only");
    }
    let harness = inputs.harness.as_str();
    if !(ROUTED_HARNESSES.contains(&harness)
        || (inputs.bridge && BRIDGE_HARNESSES.contains(&harness)))
    {
        return Err("harness_not_routed");
    }
    if text(&inputs.decision) != Some("deny")
        || text(&inputs.policy_action) != Some(SANDBOX_REQUIRED)
    {
        return Err("not_sandbox_required");
    }
    if inputs.observe_mode {
        return Err("observe_mode");
    }
    let Some(profile) = text(&inputs.reason_code).and_then(sink_profile) else {
        return Err("profile_mismatch");
    };
    if text(&inputs.required_execution_profile) != Some(profile) {
        return Err("profile_mismatch");
    }
    if !host.runs(profile) || (host == Host::Windows && !WINDOWS_SINK_HARNESSES.contains(&harness))
    {
        return Err("platform_has_no_sink");
    }
    let event = text(&inputs.event_name).is_some_and(|event| PRE_TOOL_EVENTS.contains(&event));
    let tool = text(&inputs.tool_name).is_some_and(|tool| SHELL_TOOLS.contains(&tool));
    if !(event && tool && inputs.command_is_text) {
        return Err("not_shell_call");
    }
    Ok(profile)
}

fn text(field: &Option<String>) -> Option<&str> {
    field.as_deref()
}

/// The profile the sink runs a containment reason under. A native bash owner
/// is delivered by its own launcher, never rewritten into this sink.
fn sink_profile(reason_code: &str) -> Option<&'static str> {
    if reason_code == NATIVE_BASH_DELIVERY_REASON {
        return None;
    }
    guard_command::hook_responses::contained_execution_profile(reason_code)
}

#[cfg(test)]
#[path = "hook_decision_containment_route_tests.rs"]
mod tests;
