//! `HookDecide` `hook_route` — the hook pipeline's dispatch route.
//!
//! The Python pipeline used to walk a ladder to decide which handler answered
//! a prepared hook payload. This returns that order as a plan of handler
//! names; the transport runs each handler until one answers, through a fixed
//! table, and decides nothing itself.
//!
//! Handlers that cannot know whether they apply before their effects run (the
//! containment route, the Copilot permission resolution, the runtime artifact)
//! stay in the plan and decline when they do not. A plan therefore ends at the
//! first handler that always answers: `passthrough`, `copilot_pretool`, the
//! Claude permission handlers and turn stop, or `generic_flow`.
//!
//! The approval invariant holds here: every plan that reaches the artifact or
//! generic flow keeps the edge outage check ahead of them for each tool and
//! prompt event, so a hook the edge could not decide fails closed instead of
//! being routed on; no route drops a review that offers Allow once and Always
//! allow, because the flows that offer it are the ones a plan ends in. Only
//! Devin and Zcode permission requests are answered with no decision, and only
//! because their pre-tool hook already sent that call to Guard.

use guard_contracts::{HookRouteInputsV1, HookRouteV1};

/// Events the native edge decides; a hook the edge cannot decide is an outage.
const EDGE_EVENTS: [&str; 3] = ["PreToolUse", "PostToolUse", "UserPromptSubmit"];
/// Harnesses whose permission request gets no decision, as on the daemon path:
/// each raises it only for a call its pre-tool hook already sent to Guard.
const PASSTHROUGH_HARNESSES: [&str; 2] = ["devin", "zcode"];

fn plan(inputs: &HookRouteInputsV1, event_name: &str) -> Vec<&'static str> {
    if inputs.invoked_event == "PermissionRequest"
        && PASSTHROUGH_HARNESSES.contains(&inputs.canonical_harness.as_str())
    {
        return vec!["passthrough"];
    }
    let claude = inputs.canonical_harness == "claude-code";
    let hook_event = inputs.hook_event.as_str();
    let mut steps = Vec::new();
    if claude && hook_event == "PostToolUse" {
        steps.push("claude_guard_question");
    }
    steps.push("native_edge");
    if EDGE_EVENTS.contains(&event_name) {
        steps.push("edge_unavailable");
    }
    steps.push("containment");
    if inputs.copilot_tool_call_present && inputs.copilot_stage == "pretooluse" {
        steps.push("copilot_pretool");
        return steps;
    }
    if inputs.harness == "copilot" && inputs.copilot_permission_request {
        steps.push("copilot_permission_request");
    }
    steps.push("runtime_artifact");
    if claude {
        let terminal = match hook_event {
            "PermissionRequest" => Some("claude_permission_request"),
            "Notification" if inputs.notification_type == "permission_prompt" => {
                Some("claude_permission_prompt")
            }
            "Stop" => Some("claude_stop"),
            _ => None,
        };
        if let Some(handler) = terminal {
            steps.push(handler);
            return steps;
        }
    }
    steps.extend(["artifact_flow", "generic_flow"]);
    steps
}

pub(crate) fn hook_route(inputs: &HookRouteInputsV1) -> Result<HookRouteV1, String> {
    if inputs.canonical_harness.is_empty()
        || inputs.invoked_event.is_empty()
        || inputs.runtime_event.is_empty()
    {
        return Err("native_hook_decision_route_invalid".to_owned());
    }
    let event_name = if inputs.hook_event.is_empty() {
        &inputs.runtime_event
    } else {
        &inputs.hook_event
    };
    Ok(HookRouteV1 {
        plan: plan(inputs, event_name)
            .into_iter()
            .map(str::to_owned)
            .collect(),
        event_name: event_name.clone(),
    })
}

#[cfg(test)]
#[path = "hook_decision_hook_route_tests.rs"]
mod tests;
