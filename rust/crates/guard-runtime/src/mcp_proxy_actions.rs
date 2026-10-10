//! Action arithmetic shared by the MCP proxy decision modules.
//!
//! Every helper mirrors one lattice rule the Python proxy used to apply: the
//! enforced action of a tool decision, the postclaim action, the evidence the
//! execution boundary appends, and the Composio remember rule.

use guard_contracts::{most_restrictive_of, GuardAction, McpToolFactsV1, McpToolPostclaimQueryV1};
use serde_json::{json, Value};

pub(crate) const APPROVAL_REUSE_NO_SAVED_DECISION: &str = "approval_reuse_no_saved_decision";
pub(crate) const APPROVAL_REUSE_CLAIM_FAILED: &str = "approval_reuse_claim_failed";
pub(crate) const TOOL_CATALOG_INCOMPLETE: &str = "approval_reuse_tool_catalog_incomplete";
pub(crate) const TOOL_CATALOG_EXECUTION_BOUNDARY_CHANGED: &str =
    "tool_catalog_changed_at_execution_boundary";
pub(crate) const CONTEXT_CHANGED_AFTER_CLAIM: &str = "approval_reuse_context_changed_after_claim";
pub(crate) const CONFIG_REFRESH_FAILED: &str = "approval_reuse_current_config_refresh_failed";
pub(crate) const REQUIRE_REAPPROVAL: &str = "require-reapproval";

/// `normalize_guard_action` over a string: known actions pass, `ask` aliases
/// to review, anything else takes the caller's fallback.
pub(crate) fn norm(value: &str, unknown: GuardAction) -> GuardAction {
    if value == "ask" {
        return GuardAction::Review;
    }
    GuardAction::from_canonical(value).unwrap_or(unknown)
}

pub(crate) fn norm_opt(value: Option<&str>, unknown: GuardAction) -> GuardAction {
    value.map_or(unknown, |text| norm(text, unknown))
}

/// Python `a or b` over optional strings: an empty string is falsy.
pub(crate) fn truthy_or<'a>(first: Option<&'a str>, second: &'a str) -> &'a str {
    match first {
        Some(text) if !text.is_empty() => text,
        _ => second,
    }
}

/// `is_execution_permitted` over a normalized action.
pub(crate) fn permitted(action: GuardAction) -> bool {
    matches!(action, GuardAction::Allow | GuardAction::Warn)
}

pub(crate) fn terminal(action: GuardAction) -> bool {
    matches!(action, GuardAction::Block | GuardAction::SandboxRequired)
}

pub(crate) fn most_restrictive(a: GuardAction, b: GuardAction) -> GuardAction {
    most_restrictive_of(a, b)
}

/// `_enforcement_action(action, approval_decision=decision)`: a first-time
/// review stays review, but a review that follows a rejected attempt to reuse
/// prior authority is a fresh-approval boundary.
pub(crate) fn enforcement(action: &str, facts: &McpToolFactsV1) -> GuardAction {
    let normalized = norm(action, GuardAction::Review);
    let stale = facts.approval_reuse_status.as_deref() == Some("rejected")
        && !matches!(
            facts.approval_reuse_reason_code.as_deref(),
            None | Some(APPROVAL_REUSE_NO_SAVED_DECISION)
        );
    if normalized == GuardAction::Review && stale {
        GuardAction::RequireReapproval
    } else {
        normalized
    }
}

/// `_postclaim_tool_action`.
pub(crate) fn postclaim_tool_action(facts: &McpToolFactsV1) -> GuardAction {
    let current = norm(
        facts.current_action.as_deref().unwrap_or(&facts.action),
        GuardAction::Block,
    );
    match facts.saved_action.as_deref() {
        None | Some("allow") => current,
        Some(_) => most_restrictive(current, norm(&facts.action, GuardAction::Block)),
    }
}

/// `_postclaim_authority_evidence`.
pub(crate) fn authority_evidence(context_matches: bool, current: GuardAction) -> Vec<Value> {
    if context_matches {
        return Vec::new();
    }
    vec![json!({
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": CONTEXT_CHANGED_AFTER_CLAIM,
        "context_matches": false,
        "current_action": current.as_str(),
        "effective_action": current.as_str(),
    })]
}

/// `_postclaim_claim_evidence`: a retained-row revocation at an unchanged boundary.
pub(crate) fn claim_evidence(current: GuardAction, claim_authorizes_review: bool) -> Vec<Value> {
    if current != GuardAction::Review || claim_authorizes_review {
        return Vec::new();
    }
    vec![json!({
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": CONTEXT_CHANGED_AFTER_CLAIM,
        "context_matches": true,
        "claimed_authority_matches": false,
        "current_action": current.as_str(),
        "effective_action": REQUIRE_REAPPROVAL,
    })]
}

pub(crate) fn claim_failed_item() -> Value {
    json!({
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": APPROVAL_REUSE_CLAIM_FAILED,
        "effective_action": REQUIRE_REAPPROVAL,
    })
}

pub(crate) fn config_refresh_failed_item() -> Value {
    json!({
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": CONFIG_REFRESH_FAILED,
        "effective_action": REQUIRE_REAPPROVAL,
    })
}

pub(crate) fn boundary_failure_item(phase: &str) -> Value {
    json!({
        "source": "tool_catalog",
        "status": "rejected",
        "reason_code": TOOL_CATALOG_EXECUTION_BOUNDARY_CHANGED,
        "phase": phase,
        "effective_action": REQUIRE_REAPPROVAL,
    })
}

pub(crate) fn observe_mode_item(observed: GuardAction, executed: GuardAction) -> Value {
    json!({
        "source": "observe_mode",
        "observed_policy_action": observed.as_str(),
        "authoritative_action": executed.as_str(),
    })
}

/// `composio_requires_action_review`: meta-tools that route or execute other
/// tools never inherit a remembered approval.
pub(crate) fn composio_requires_action_review(tool_name: &str) -> bool {
    let suffix = tool_name
        .rsplit("__")
        .next()
        .unwrap_or(tool_name)
        .to_lowercase();
    match suffix.as_str() {
        "composio_search_tools" | "composio_get_tool_schemas" => false,
        "composio_multi_execute_tool"
        | "composio_remote_workbench"
        | "composio_remote_bash_tool"
        | "composio_manage_connections" => true,
        other => other.starts_with("composio_"),
    }
}

/// `_decision_source`.
pub(crate) fn decision_source(action: &str, source: &str) -> String {
    if source == "policy" {
        format!("policy-{action}")
    } else {
        format!("{source}-{action}")
    }
}

pub(crate) fn same_context(query: &McpToolPostclaimQueryV1) -> bool {
    query.artifact_id == query.expected_artifact_id
        && query.artifact_hash == query.expected_artifact_hash
}
