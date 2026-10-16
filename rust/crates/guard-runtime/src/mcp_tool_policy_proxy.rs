//! Saved-allow gate and route selection folded into the decide result.
//!
//! Both checks are pure functions of the final decision plus caller-supplied
//! route inputs, so the resident evaluates them in the same call instead of
//! costing the caller two more round trips. The `mcp_proxy_decide` op stays the
//! owner of the logic; this module only converts the decision into the facts
//! those checks take and applies the gate before routing, exactly as the caller
//! does when it asks separately.
//!
//! `route_tool_call` asks for the facts only a collaborator can supply through
//! its `need` reply, and the proxy answers each one about the decision that
//! applies at that point: the gated decision, with the route's own
//! observe-mode downgrade on top. The one such fact the resident can answer
//! itself is the native prompt, so this module runs the same two-step the
//! proxy's `_route_tool_call` runs for it: route, then answer the need and
//! route again.

use guard_contracts::{
    McpRouteToolCallQueryV1, McpSavedAllowGateQueryV1, McpToolFactsV1, McpToolPolicyProxyInputV1,
};
use serde_json::{json, Value};

use crate::mcp_proxy_catalog::saved_allow_gate;
use crate::mcp_proxy_route::route_tool_call;
use crate::mcp_tool_policy_decision::Decision;

/// The fact `_allow_after_native_prompt` answers.
const NATIVE_PROMPT: &str = "native_prompt";

pub(crate) fn facts(decision: &Decision) -> McpToolFactsV1 {
    McpToolFactsV1 {
        action: decision.action.as_str().to_owned(),
        source: decision.source.clone(),
        current_action: decision.current_action.map(|a| a.as_str().to_owned()),
        saved_action: decision.saved_action.map(|a| a.as_str().to_owned()),
        approval_reuse_status: decision.approval_reuse_status.map(str::to_owned),
        approval_reuse_reason_code: decision.approval_reuse_reason_code.clone(),
        has_pending: decision.pending.is_some(),
    }
}

fn text(gate: &Value, key: &str) -> Option<String> {
    gate.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// `_apply_decision_override`: the decision a need is answered about.
fn overridden(tool: &McpToolFactsV1, route: &Value) -> McpToolFactsV1 {
    let Some(override_decision) = route.get("decision_override") else {
        return tool.clone();
    };
    let (Some(action), Some(source)) = (
        override_decision.get("action").and_then(Value::as_str),
        override_decision.get("source").and_then(Value::as_str),
    ) else {
        return tool.clone();
    };
    McpToolFactsV1 {
        action: action.to_owned(),
        source: source.to_owned(),
        has_pending: false,
        ..tool.clone()
    }
}

/// `{gate, route}` for a final decision, as the separate proxy checks answer.
///
/// `native_prompt_allows` is `_allow_after_native_prompt` for this call's
/// harness, asked about the decision the route names, and `None` for a
/// harness that answers it from its client's inline elicitation instead.
pub(crate) fn proxy_payload(
    input: &McpToolPolicyProxyInputV1,
    decision: &Decision,
    native_prompt_allows: impl FnOnce(&McpToolFactsV1) -> Option<bool>,
) -> Value {
    let mut tool = facts(decision);
    let gate = saved_allow_gate(&McpSavedAllowGateQueryV1 {
        catalog_state: input.catalog_state.clone(),
        decision: tool.clone(),
    });
    if gate.get("disable") == Some(&Value::Bool(true)) {
        // Mirror the caller's replacement of a gated decision before routing.
        tool.action = text(&gate, "action").unwrap_or(tool.action);
        tool.source = text(&gate, "source").unwrap_or(tool.source);
        tool.approval_reuse_status = text(&gate, "approval_reuse_status");
        tool.approval_reuse_reason_code = text(&gate, "approval_reuse_reason_code");
        tool.has_pending = false;
    }
    let mut query = McpRouteToolCallQueryV1 {
        mode: input.mode.clone(),
        package_present: input.package_present,
        asks_for_approval: input.asks_for_approval,
        inline_available: input.inline_available,
        tool_name: input.tool_name.clone(),
        decision: tool,
        package_saved_policy_blocks: None,
        native_prompt_allows: None,
        // The answer to the inline prompt, when the caller has already raised
        // it. Left out, the route names the `inline_approval` fact it needs.
        inline_approval: input.inline_approval,
    };
    let mut route = route_tool_call(&query);
    if route.get("need").and_then(Value::as_str) == Some(NATIVE_PROMPT) {
        if let Some(allowed) = native_prompt_allows(&overridden(&query.decision, &route)) {
            query.native_prompt_allows = Some(allowed);
            route = route_tool_call(&query);
        }
    }
    json!({ "gate": gate, "route": route })
}

#[cfg(test)]
#[path = "mcp_tool_policy_proxy_tests.rs"]
mod tests;
