//! The tail of the artifact hook's policy stack: the decisions the hook made
//! around `policy_stack` that Python used to compute from the artifact.
//!
//! `local_eligibility_required` rides on the `policy_stack` answer: a local
//! tool grant can only name a command, so the grant evidence is gathered for a
//! pre-tool request that carries one. `policy_composition` answers once saved
//! approvals, the trusted-request override and the claim have settled the
//! verdict: it writes the `policy_composition` trace every consumer of the
//! decision reads and names the receipt's `approval_source`.
//!
//! `approval_source` is a receipt label. It never changes which choices an
//! approval offers: a review or require-reapproval verdict offers Allow once
//! and Always allow whichever source it is recorded under.
//!
//! Whether the native command floor is skipped is the artifact facts' answer
//! (`skip_native_floor` in `hook_artifact_facts_op`), because the floor runs
//! before the stack is composed.

use guard_contracts::{PolicyCompositionQueryV1, PolicyStackQueryV1};
use serde_json::{json, Map, Value};

/// The artifact types a local tool grant can be matched against.
const GRANT_ARTIFACT_TYPES: [&str; 2] = ["tool_action_request", "package_request"];

/// Whether the hook gathers local tool-grant evidence for this request.
pub(crate) fn local_eligibility_required(query: &PolicyStackQueryV1) -> bool {
    query.event_name == "PreToolUse"
        && GRANT_ARTIFACT_TYPES.contains(&query.artifact_type.as_str())
        && query.has_raw_command
}

/// The receipt label for how the settled verdict was approved: `inline` when
/// the user approved in the harness's own prompt or sent an override with the
/// request, `approval_center` when the verdict is waiting on the approval
/// center, `policy` otherwise.
pub(crate) fn approval_source(query: &PolicyCompositionQueryV1) -> &'static str {
    if query.claude_native_approval_observed || query.user_override_present {
        "inline"
    } else if query.authoritative_action == "require-reapproval" {
        "approval_center"
    } else {
        "policy"
    }
}

/// The `policy_composition` trace, the evidence entry that carries it, and the
/// receipt's `approval_source`.
pub(crate) fn policy_composition(query: &PolicyCompositionQueryV1) -> Value {
    let composition = json!({
        "current_config_action": query.current_config_action,
        "current_action_override": query.current_action_override,
        "trusted_cli_override": query.trusted_cli_action,
        "untrusted_hook_payload_hint": query.untrusted_payload_action,
        "package_action": query.package_policy_action,
        "data_flow_action": query.data_flow_action,
        "scanner_action": query.scanner_action,
        "current_composed_action": query.current_composed_action,
        "saved_policy_action": query.saved_policy_action,
        "approval_reuse_source": query.approval_reuse_source,
        "trusted_request_override": query.trusted_request_override,
        "trusted_request_override_reason": query.trusted_request_override_reason,
        "authoritative_action": query.authoritative_action,
    });
    let mut evidence = Map::new();
    evidence.insert("source".to_owned(), json!("policy_composition"));
    if let Some(fields) = composition.as_object() {
        evidence.extend(fields.clone());
    }
    json!({
        "policy_composition": composition,
        "evidence": evidence,
        "approval_source": approval_source(query),
    })
}

#[cfg(test)]
#[path = "hook_artifact_compose_policy_tail_tests.rs"]
mod tests;
