//! Package-request composition: how a package policy and the tool policy that
//! carries it combine into one outcome before anything executes.

use guard_contracts::{GuardAction, McpPackageComposeQueryV1, McpPackagePrecheckQueryV1};
use serde_json::{json, Value};

use crate::mcp_proxy_actions::{
    enforcement, most_restrictive, norm, observe_mode_item, permitted, terminal, truthy_or,
};

fn terminal_kind(kind: &str, action: GuardAction) -> Value {
    json!({ "kind": kind, "policy_action": action.as_str() })
}

/// The decision on the package policy resolved before the tool is re-resolved.
pub(crate) fn package_precheck(query: &McpPackagePrecheckQueryV1) -> Value {
    if query.saved_policy_blocks {
        return json!({ "kind": "stored_package_block" });
    }
    let action = norm(&query.policy_action, GuardAction::Review);
    if terminal(action) {
        return terminal_kind("terminal", action);
    }
    if !permitted(action) && query.mode != "observe" {
        return terminal_kind("queue", action);
    }
    json!({ "kind": "proceed" })
}

/// The decision on the freshly re-resolved tool and package policies.
pub(crate) fn package_compose(query: &McpPackageComposeQueryV1) -> Value {
    let tool = &query.tool;
    let package = &query.package;
    if tool.saved_action.as_deref() == Some("block") {
        return json!({ "kind": "stored_tool_block" });
    }
    if package.saved_policy_blocks {
        return json!({ "kind": "stored_package_block" });
    }
    if query.mode == "observe" {
        return observe_compose(query);
    }
    let tool_action = enforcement(&tool.action, tool);
    let package_action = norm(&package.policy_action, GuardAction::Review);
    let authoritative = most_restrictive(tool_action, package_action);
    if terminal(authoritative) {
        return terminal_kind("terminal_package", authoritative);
    }
    if !permitted(authoritative) {
        if !permitted(tool_action) {
            return terminal_kind("queue_tool", tool_action);
        }
        return terminal_kind("queue_package", package_action);
    }
    json!({
        "kind": "proceed",
        "pending_claims": tool.has_pending || package.has_pending,
        "authoritative_action": authoritative.as_str(),
    })
}

fn observe_compose(query: &McpPackageComposeQueryV1) -> Value {
    let tool = &query.tool;
    let tool_observed = enforcement(
        truthy_or(tool.current_action.as_deref(), &tool.action),
        tool,
    );
    let package_observed = norm(
        query.package.current_action.as_deref().unwrap_or(""),
        GuardAction::Review,
    );
    if terminal(tool_observed) {
        return terminal_kind("terminal_tool", tool_observed);
    }
    if terminal(package_observed) {
        return terminal_kind("terminal_package", package_observed);
    }
    let effective = |action: GuardAction| {
        if permitted(action) {
            action
        } else {
            GuardAction::Allow
        }
    };
    let observed = most_restrictive(tool_observed, package_observed);
    let executed = most_restrictive(effective(tool_observed), effective(package_observed));
    let overridden = effective(tool_observed) != tool_observed
        || effective(package_observed) != package_observed;
    let mut evidence = Vec::new();
    if overridden {
        let mut item = observe_mode_item(observed, executed);
        item["observed_tool_policy_action"] = json!(tool_observed.as_str());
        item["observed_package_policy_action"] = json!(package_observed.as_str());
        evidence.push(item);
    }
    json!({
        "kind": "observe_forward",
        "executed_action": executed.as_str(),
        "observe_override": overridden,
        "observed_policy_action": observed.as_str(),
        "observed_tool_policy_action": tool_observed.as_str(),
        "observed_package_policy_action": package_observed.as_str(),
        "queue_observed_tool": (!permitted(tool_observed)).then(|| tool_observed.as_str()),
        "queue_observed_package": (!permitted(package_observed)).then(|| package_observed.as_str()),
        "evidence_append": evidence,
    })
}
