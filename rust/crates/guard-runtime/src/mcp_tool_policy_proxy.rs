//! Saved-allow gate and route selection folded into the decide result.
//!
//! Both checks are pure functions of the final decision plus caller-supplied
//! route inputs, so the resident evaluates them in the same call instead of
//! costing the caller two more round trips. The `mcp_proxy_decide` op stays the
//! owner of the logic; this module only converts the decision into the facts
//! those checks take and applies the gate before routing, exactly as the caller
//! does when it asks separately.

use guard_contracts::{
    McpRouteToolCallQueryV1, McpSavedAllowGateQueryV1, McpToolFactsV1, McpToolPolicyProxyInputV1,
};
use serde_json::{json, Value};

use crate::mcp_proxy_catalog::saved_allow_gate;
use crate::mcp_proxy_route::route_tool_call;
use crate::mcp_tool_policy_decision::Decision;

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

/// `{gate, route}` for a final decision, as the separate proxy checks answer.
pub(crate) fn proxy_payload(input: &McpToolPolicyProxyInputV1, decision: &Decision) -> Value {
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
    let route = route_tool_call(&McpRouteToolCallQueryV1 {
        mode: input.mode.clone(),
        package_present: input.package_present,
        asks_for_approval: input.asks_for_approval,
        inline_available: input.inline_available,
        tool_name: input.tool_name.clone(),
        decision: tool,
        package_saved_policy_blocks: None,
        native_prompt_allows: None,
        inline_approval: None,
    });
    json!({ "gate": gate, "route": route })
}
