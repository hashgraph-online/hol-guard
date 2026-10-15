//! Routing of one MCP `tools/call`: which of stored-block, terminal, package,
//! allow-and-forward, observe-forward, inline-denied or approval-queue applies.
//!
//! Facts only a collaborator can supply (the package policy resolution, the
//! native prompt answer and the inline approval) are requested lazily, in the
//! order the proxy consults them, through the `need` reply.

use guard_contracts::{
    GuardAction, McpInlineApprovalV1, McpObserveToolForwardQueryV1, McpRouteToolCallQueryV1,
    McpToolFactsV1,
};
use serde_json::{json, Value};

use crate::local_mcp_grant_identity::composio_requires_action_review;
use crate::mcp_proxy_actions::{
    decision_source, enforcement, observe_mode_item, permitted, terminal, truthy_or,
};

fn need(name: &str) -> Value {
    json!({ "need": name })
}

struct Routed {
    override_decision: Option<Value>,
    tool_policy_action: Option<GuardAction>,
    route: Value,
}

fn package_route(source: Option<&str>, inline: bool, remember: Option<bool>) -> Value {
    json!({
        "kind": "package",
        "tool_source": source,
        "inline_record": inline,
        "remember": remember,
    })
}

fn forward_route(
    source: String,
    policy: GuardAction,
    remember: bool,
    pass_decision: bool,
) -> Value {
    json!({
        "kind": "allow_and_forward",
        "decision_source": source,
        "policy_action": policy.as_str(),
        "remember": remember,
        "pass_approval_decision": pass_decision,
    })
}

fn queue_route(policy: GuardAction) -> Value {
    json!({ "kind": "queue", "policy_action": policy.as_str() })
}

/// The observe-mode downgrade: with no package in play, a pending saved
/// approval is ignored and the current policy applies.
fn observe_override(query: &McpRouteToolCallQueryV1) -> Option<McpToolFactsV1> {
    let decision = &query.decision;
    let current = decision.current_action.as_ref()?;
    if query.package_present || query.mode != "observe" || !decision.has_pending {
        return None;
    }
    Some(McpToolFactsV1 {
        action: current.clone(),
        source: "observe-current-policy".to_owned(),
        has_pending: false,
        ..decision.clone()
    })
}

fn route(query: &McpRouteToolCallQueryV1) -> Result<Routed, Value> {
    let overridden = observe_override(query);
    let decision = overridden.as_ref().unwrap_or(&query.decision);
    let override_decision = overridden
        .as_ref()
        .map(|d| json!({ "action": d.action, "source": d.source }));
    let done = |tool_policy_action: Option<GuardAction>, route: Value| {
        Ok(Routed {
            override_decision: override_decision.clone(),
            tool_policy_action,
            route,
        })
    };
    if decision.saved_action.as_deref() == Some("block") {
        return done(None, json!({ "kind": "stored_block" }));
    }
    let policy = enforcement(&decision.action, decision);
    if terminal(policy) {
        return done(
            Some(policy),
            json!({ "kind": "terminal", "policy_action": policy.as_str() }),
        );
    }
    let executable = matches!(decision.action.as_str(), "allow" | "warn");
    let remember = !composio_requires_action_review(&query.tool_name);
    if query.package_present {
        let Some(saved) = query.package_saved_policy_blocks else {
            return Err(need("package_policy"));
        };
        if saved || executable {
            return done(Some(policy), package_route(None, false, None));
        }
        if query.asks_for_approval {
            let Some(allowed) = query.native_prompt_allows else {
                return Err(need("native_prompt"));
            };
            if allowed {
                return done(
                    Some(policy),
                    package_route(Some("native-approved"), false, None),
                );
            }
            if query.inline_available {
                match query.inline_approval {
                    None => return Err(need("inline_approval")),
                    Some(McpInlineApprovalV1::Allow) => {
                        return done(
                            Some(policy),
                            package_route(Some("inline-approved"), true, Some(remember)),
                        )
                    }
                    Some(McpInlineApprovalV1::Denied) => {
                        return done(Some(policy), json!({ "kind": "inline_denied" }))
                    }
                    Some(McpInlineApprovalV1::Fallthrough) => {}
                }
            }
        }
        if query.mode == "observe" {
            return done(
                Some(policy),
                package_route(Some("policy-allow"), false, None),
            );
        }
        return done(Some(policy), queue_route(policy));
    }
    if executable {
        let source = decision_source(&decision.action, &decision.source);
        return done(Some(policy), forward_route(source, policy, false, true));
    }
    if query.asks_for_approval {
        let Some(allowed) = query.native_prompt_allows else {
            return Err(need("native_prompt"));
        };
        if allowed {
            let source = "native-approved".to_owned();
            return done(
                Some(policy),
                forward_route(source, GuardAction::Allow, false, false),
            );
        }
        if query.inline_available {
            match query.inline_approval {
                None => return Err(need("inline_approval")),
                Some(McpInlineApprovalV1::Allow) => {
                    let source = "inline-approved".to_owned();
                    return done(
                        Some(policy),
                        forward_route(source, GuardAction::Allow, remember, false),
                    );
                }
                Some(McpInlineApprovalV1::Denied) => {
                    return done(Some(policy), json!({ "kind": "inline_denied" }))
                }
                Some(McpInlineApprovalV1::Fallthrough) => {}
            }
        }
    }
    if query.mode == "observe" {
        return done(Some(policy), json!({ "kind": "observe_forward" }));
    }
    done(Some(policy), queue_route(policy))
}

pub(crate) fn route_tool_call(query: &McpRouteToolCallQueryV1) -> Value {
    match route(query) {
        // The caller consults its collaborators about the decision that
        // applies after the observe-mode downgrade, so a need carries it.
        Err(mut request) => {
            request["decision_override"] = observe_override(query)
                .map(|d| json!({ "action": d.action, "source": d.source }))
                .unwrap_or(Value::Null);
            request
        }
        Ok(routed) => json!({
            "need": null,
            "decision_override": routed.override_decision,
            "tool_policy_action": routed.tool_policy_action.map(GuardAction::as_str),
            "route": routed.route,
        }),
    }
}

/// The observed-then-forwarded outcome of a tool call that needed approval
/// under observe mode: it executes, and an override is recorded as evidence.
pub(crate) fn observe_tool_forward(query: &McpObserveToolForwardQueryV1) -> Value {
    let fresh = &query.fresh;
    let observed = enforcement(
        truthy_or(fresh.current_action.as_deref(), &fresh.action),
        fresh,
    );
    let overridden = !permitted(observed);
    let executed = if overridden {
        GuardAction::Allow
    } else {
        observed
    };
    json!({
        "observe_override": overridden,
        "executed_action": executed.as_str(),
        "observed_policy_action": overridden.then(|| observed.as_str()),
        "evidence_append": if overridden {
            vec![observe_mode_item(observed, executed)]
        } else {
            Vec::new()
        },
    })
}
