//! `HookDecide` `containment_route` and `containment_sink` — wire contract for
//! routing a native PreToolUse answer into Guard's contained execution sink.
//!
//! The transport sends facts: the native result's actions and reason, the
//! harness, the host platform and the shape of the call. The resident answers
//! whether the result is routed at all (`containment_route`), and whether a
//! rendered receipt is rewritten into the sink (`containment_sink`). The
//! transport only renders, writes the request snapshot and quotes the sink
//! command. No answer is a resident outage the transport reports as one, never
//! a route it picks.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Advertised when the resident answers `containment_route` and
/// `containment_sink`; a resident that predates them rejects both queries.
pub const HOOK_DECISION_CONTAINMENT_ROUTE_FEATURE: &str = "hook-decision-containment-route-v1";

/// The native PreToolUse result a hook answers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContainmentRouteInputsV1 {
    /// The edge's event name, when it is text.
    pub event_name: Option<String>,
    /// Watch records the call; it is never rewritten.
    pub recording_only: bool,
    /// The result's `minimum_action`, when it is text.
    pub minimum_action: Option<String>,
    /// The result's `policy_action`, when it is text.
    pub policy_action: Option<String>,
    /// The result's `reason_code`, when it is text.
    pub reason_code: Option<String>,
    /// The result's `action.action_type` as the result carries it: a Guard
    /// control or package action, or one that is not a scalar, is never
    /// routed through the grant.
    pub action_type: Option<Value>,
}

/// Which containment step the result takes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContainmentRouteV1 {
    /// `none` keeps the ordinary answer; `sink` renders the receipt and asks
    /// `containment_sink`; `grant` first asks this device's local CLI grant,
    /// which turns an outside-roots review into a sandbox requirement.
    pub route: String,
}

/// A rendered PreToolUse receipt and the call it answers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContainmentSinkInputsV1 {
    /// The harness the receipt is rendered for, as the hook names it.
    pub harness: String,
    /// The host: `macos`, `linux`, `windows` or `other`.
    pub platform: String,
    /// The Codex hook bridge, which has confirmed the running Codex applies
    /// `updatedInput`. Only the bridge routes Codex.
    pub bridge: bool,
    /// The call carries `guard_containment_receipt_only: true`: the sink is
    /// re-authorizing and wants the receipt itself.
    pub receipt_only: bool,
    /// The payload's hook event name, when it is text.
    pub event_name: Option<String>,
    /// The payload's tool name, when it is text.
    pub tool_name: Option<String>,
    /// The payload's tool input is an object whose `command` is text.
    pub command_is_text: bool,
    /// The receipt's `decision`, when it is text.
    pub decision: Option<String>,
    /// The receipt's `policy_action`, when it is text.
    pub policy_action: Option<String>,
    /// The receipt's `reason_code`, when it is text.
    pub reason_code: Option<String>,
    /// The receipt's `required_execution_profile`, when it is text.
    pub required_execution_profile: Option<String>,
    /// The receipt carries `observe_mode: true`.
    pub observe_mode: bool,
}

/// Whether the receipt is rewritten into the sink.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContainmentSinkV1 {
    /// The execution profile the sink runs the call under; `None` keeps the
    /// receipt as rendered.
    pub profile: Option<String>,
    /// Why the receipt stands, when it does: `receipt_only`,
    /// `harness_not_routed`, `not_sandbox_required`, `observe_mode`,
    /// `profile_mismatch`, `platform_has_no_sink` or `not_shell_call`.
    pub kept_because: Option<String>,
}
