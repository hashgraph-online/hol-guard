//! `HookDecide` `hook_route` — wire contract for the hook pipeline's dispatch route.
//!
//! Once a hook payload is prepared, the pipeline still has to decide which
//! handlers answer it and in what order: the Claude guard question, the native
//! edge decision, the edge outage, the containment route, the Copilot flows,
//! the runtime artifact, the Claude permission handlers, then the artifact or
//! generic flow. The transport gathers the facts below and runs the plan the
//! resident returns, through a fixed table of handlers; it branches on nothing
//! itself. A plan the transport cannot run means no route, and the caller
//! fails closed.

use serde::{Deserialize, Serialize};

/// Advertised when the resident answers `hook_route`, the order the hook
/// pipeline's handlers run in; a resident that predates it rejects the query.
pub const HOOK_DECISION_HOOK_ROUTE_FEATURE: &str = "hook-decision-hook-route-v1";

/// Facts the hook pipeline's route depends on. The transport gathers them;
/// which handlers run, and in what order, is the resident's answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookRouteInputsV1 {
    /// The harness name as the hook was invoked.
    pub harness: String,
    /// The canonical adapter name the transport resolved for `harness`.
    pub canonical_harness: String,
    /// The runtime event name of the payload as it arrived, before preparation.
    pub invoked_event: String,
    /// The hook event name of the prepared payload; empty when it names none.
    pub hook_event: String,
    /// The runtime event name of the prepared payload.
    pub runtime_event: String,
    /// The prepared payload's notification type; empty when it names none.
    pub notification_type: String,
    /// The lower-cased Copilot hook stage preparation read; empty when none.
    pub copilot_stage: String,
    /// Preparation resolved a Copilot tool call for the payload.
    pub copilot_tool_call_present: bool,
    /// The prepared payload is a Copilot permission request.
    pub copilot_permission_request: bool,
}

/// The handlers to run, in order, and the event name outage responses carry.
/// The transport runs each handler until one answers; the last handler of a
/// plan always does.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HookRouteV1 {
    /// Handler names, from `passthrough`, `claude_guard_question`,
    /// `native_edge`, `edge_unavailable`, `containment`, `copilot_pretool`,
    /// `copilot_permission_request`, `runtime_artifact`,
    /// `claude_permission_request`, `claude_permission_prompt`, `claude_stop`,
    /// `artifact_flow` and `generic_flow`.
    pub plan: Vec<String>,
    /// The prepared payload's hook event, else its runtime event.
    pub event_name: String,
}
