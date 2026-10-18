//! A live MCP `tools/call` held only because this device was never set up for
//! its server.
//!
//! A review whose only cause is non-recognition (no risk signal, no floor, no
//! provider action review, no explicit per-tool or per-publisher choice, no
//! grant row and no catalog contribution deciding the tool) is a setup
//! decision, not a per-action one. The decision keeps its action and every
//! field it had; the payload only gains `connector_setup`, naming the server so
//! the queued row joins the connector's `connector:<identity_hash>` group.
//! Allowing a connector stays with a local admin through the existing
//! extension-control path: nothing here writes or implies a grant.

use guard_command::approval_reuse::APPROVAL_REUSE_NO_SAVED_DECISION;
use guard_command::effect_decision::GuardAction;
use guard_contracts::McpToolPolicySubjectV1;
use serde_json::{json, Map, Value};

use crate::connector_setup::CONNECTOR_SETUP_REQUIRED;
use crate::mcp_tool_policy_composio::requires_action_review;
use crate::mcp_tool_policy_decision::Decision;
use crate::mcp_tool_policy_extension::unset_connector;

/// Sources a recommendation keeps when no extension, grant or provider rule
/// replaced it. Any other source means something on this device decided.
const BASE_SOURCES: [&str; 2] = ["policy", "heuristic"];

fn explicit_choice(config: &Map<String, Value>, key: &str, id: Option<&str>) -> bool {
    id.and_then(|id| config.get(key)?.as_object()?.get(id))
        .is_some_and(|value| !value.is_null())
}

/// Whether `decision` is a review due only to Guard not recognising the server.
fn non_recognition(subject: &McpToolPolicySubjectV1, decision: &Decision) -> bool {
    let command = subject.artifact.command.as_deref().unwrap_or("");
    decision.action == GuardAction::Review
        && decision.policy_action() == GuardAction::Review
        && decision.signals.is_empty()
        && decision.risk_categories.is_empty()
        && BASE_SOURCES.contains(&decision.source.as_str())
        && matches!(
            decision.approval_reuse_reason_code.as_deref(),
            None | Some(APPROVAL_REUSE_NO_SAVED_DECISION)
        )
        && decision.pending.is_none()
        && decision.claim_disposition.is_none()
        && !decision.post_claim_revalidated
        && !requires_action_review(command)
        && !explicit_choice(
            &subject.config,
            "artifact_actions",
            Some(&subject.artifact_id),
        )
        && !explicit_choice(
            &subject.config,
            "publisher_actions",
            subject.publisher.as_deref(),
        )
}

fn display_name(subject: &McpToolPolicySubjectV1) -> Value {
    let from_extension = subject
        .extension
        .as_ref()
        .and_then(|ext| ext.server_name.as_ref())
        .and_then(Value::as_str);
    subject
        .artifact
        .metadata
        .get("server_name")
        .and_then(Value::as_str)
        .or(from_extension)
        .map_or(Value::Null, |name| Value::String(name.to_owned()))
}

/// `{reason_code, identity_hash, surface, name, queue_group_id}` for a
/// non-recognition review of a server with no answer on this device.
pub(crate) fn connector_setup(
    subject: &McpToolPolicySubjectV1,
    decision: &Decision,
) -> Option<Value> {
    if !non_recognition(subject, decision) {
        return None;
    }
    let identity_hash = unset_connector(subject.extension.as_ref()?)?;
    Some(json!({
        "reason_code": CONNECTOR_SETUP_REQUIRED,
        "identity_hash": identity_hash,
        "surface": "mcp",
        "name": display_name(subject),
        // The queue appends the row's own action digest, so identical calls
        // merge and distinct calls keep their own rows.
        "queue_group_id": format!("connector:{identity_hash}"),
    }))
}

#[cfg(test)]
#[path = "mcp_tool_policy_connector_tests.rs"]
mod tests;
