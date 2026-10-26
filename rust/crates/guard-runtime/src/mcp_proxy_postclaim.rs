//! Execution-boundary revalidation after a saved approval was claimed.
//!
//! Once a claim is spent the proxy re-resolves the tool (and package)
//! authority. These checks decide whether the claimed approval still covers
//! what would run now, and which evidence the refreshed decision carries.

use guard_contracts::{
    GuardAction, McpBoundaryFailureQueryV1, McpEvidenceItemKindV1, McpEvidenceItemQueryV1,
    McpPackagePostclaimQueryV1, McpToolPostclaimQueryV1,
};
use serde_json::{json, Value};

use crate::mcp_proxy_actions::{
    authority_evidence, boundary_failure_item, claim_evidence, claim_failed_item,
    config_refresh_failed_item, enforcement, most_restrictive, norm, norm_opt,
    postclaim_tool_action, same_context, terminal, REQUIRE_REAPPROVAL,
};

fn need(name: &str) -> Value {
    json!({ "need": name })
}

fn terminal_kind(kind: &str, action: GuardAction) -> Value {
    json!({ "kind": kind, "policy_action": action.as_str() })
}

pub(crate) fn evidence_item(query: &McpEvidenceItemQueryV1) -> Value {
    let item = match query.kind {
        McpEvidenceItemKindV1::ClaimFailed => claim_failed_item(),
        McpEvidenceItemKindV1::ConfigRefreshFailed => config_refresh_failed_item(),
    };
    json!({ "item": item })
}

/// The catalog changed (or could not be proven unchanged) at an execution boundary.
pub(crate) fn boundary_failure(query: &McpBoundaryFailureQueryV1) -> Value {
    let fresh = &query.fresh;
    let action = enforcement(&fresh.action, fresh);
    let evidence = vec![boundary_failure_item(&query.phase)];
    if fresh.saved_action.as_deref() == Some("block") {
        return json!({ "kind": "stored_block", "evidence_append": evidence });
    }
    if terminal(action) {
        let mut reply = terminal_kind("terminal", action);
        reply["evidence_append"] = Value::Array(evidence);
        return reply;
    }
    json!({
        "kind": "queue",
        "policy_action": REQUIRE_REAPPROVAL,
        "evidence_append": evidence,
    })
}

pub(crate) fn tool_postclaim(query: &McpToolPostclaimQueryV1) -> Value {
    let fresh = &query.fresh;
    let action = postclaim_tool_action(fresh);
    let context_matches = same_context(query);
    let mut evidence = authority_evidence(context_matches, action);
    evidence.extend(claim_evidence(action, query.claim_authorizes_review));
    let finish = |disposition: Value| {
        json!({
            "need": null,
            "fresh_action": action.as_str(),
            "context_matches": context_matches,
            "disposition": disposition,
            "evidence_append": evidence,
        })
    };
    if fresh.saved_action.as_deref() == Some("block") {
        return finish(json!({ "kind": "stored_block" }));
    }
    if terminal(action) {
        return finish(terminal_kind("terminal", action));
    }
    let mut revalidate = !context_matches;
    if !revalidate && action == GuardAction::RequireReapproval {
        match query.fresh_claim_allows_reapproval {
            None => return need("fresh_claim_allows_reapproval"),
            Some(allows) => revalidate = !allows,
        }
    }
    if !revalidate && action == GuardAction::Review && !query.claim_authorizes_review {
        revalidate = true;
    }
    if revalidate {
        return finish(json!({ "kind": "queue_reapproval", "policy_action": REQUIRE_REAPPROVAL }));
    }
    finish(json!({ "kind": "forward" }))
}

/// Revalidate a package request after both of its claims were spent.
pub(crate) fn package_postclaim(query: &McpPackagePostclaimQueryV1) -> Value {
    let tool_action = postclaim_tool_action(&query.tool);
    let context = &query.tool_context;
    let tool_context_matches = context.artifact_id == context.expected_artifact_id
        && context.artifact_hash == context.expected_artifact_hash;
    let tool_authority = authority_evidence(tool_context_matches, tool_action);
    let tool_only = |kind: &str, evidence: &[Value]| json!({ "need": null, "disposition": { "kind": kind }, "tool_evidence_append": evidence });
    if query.tool.saved_action.as_deref() == Some("block") {
        return tool_only("stored_tool_block", &tool_authority);
    }
    if terminal(tool_action) {
        let mut reply = tool_only("terminal_tool", &tool_authority);
        reply["disposition"]["policy_action"] = json!(tool_action.as_str());
        return reply;
    }
    if !query.package_artifact_present {
        return tool_only("queue_tool", &tool_authority);
    }
    let Some(package) = &query.package else {
        return need("postclaim_package");
    };
    let facts = &package.facts;
    let package_action = most_restrictive(
        norm_opt(facts.current_action.as_deref(), GuardAction::Block),
        norm(&facts.policy_action, GuardAction::Block),
    );
    let package_context_matches = package.artifact_id == package.expected_artifact_id
        && package.digest == package.expected_digest;
    let mut tool_evidence = tool_authority;
    tool_evidence.extend(claim_evidence(
        tool_action,
        package.tool_claim_authorizes_review,
    ));
    let mut package_evidence = authority_evidence(package_context_matches, package_action);
    package_evidence.extend(claim_evidence(
        package_action,
        package.package_claim_authorizes_review,
    ));
    let package_reply = |disposition: Value| json!({ "need": null, "disposition": disposition, "package_evidence_append": package_evidence });
    if facts.saved_policy_blocks {
        return package_reply(json!({ "kind": "stored_package_block" }));
    }
    if terminal(package_action) {
        return package_reply(terminal_kind("terminal_package", package_action));
    }
    if !tool_context_matches
        || tool_action == GuardAction::RequireReapproval
        || (tool_action == GuardAction::Review && !package.tool_claim_authorizes_review)
    {
        return tool_only("queue_tool", &tool_evidence);
    }
    if !package_context_matches
        || package_action == GuardAction::RequireReapproval
        || (package_action == GuardAction::Review && !package.package_claim_authorizes_review)
    {
        return package_reply(json!({ "kind": "queue_package" }));
    }
    let executed = |action: GuardAction| {
        if action == GuardAction::Review {
            GuardAction::Allow
        } else {
            action
        }
    };
    let authoritative = most_restrictive(executed(tool_action), executed(package_action));
    package_reply(json!({ "kind": "forward", "authoritative_action": authoritative.as_str() }))
}
