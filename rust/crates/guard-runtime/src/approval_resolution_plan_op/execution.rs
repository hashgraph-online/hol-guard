//! Execution delivery required before a resolution plan may save consent.

use guard_contracts::ApprovalResolutionPlanRequestV1;
use serde_json::{json, Value};

use crate::context_digest::parse_context_token;
use crate::guard_store_json::add_seconds_isoformat;
use crate::guard_store_native_review_consume::binding_pattern;

/// `_APPROVAL_ONCE_POLICY_TTL`: 15 minutes.
const ONCE_TTL_MICROS: i64 = 15 * 60 * 1_000_000;

pub(super) fn operation_only(
    request: &ApprovalResolutionPlanRequestV1,
    context_bound: bool,
) -> bool {
    let approval = &request.approval;
    request.scope == "artifact"
        && (request.action != "allow" || context_bound)
        && crate::native_bash_review_descriptor::reserved(
            approval.artifact_type.as_deref(),
            approval.artifact_id.as_deref(),
            approval
                .envelope
                .as_ref()
                .and_then(|envelope| envelope.native_bash.as_ref()),
        )
}

pub(super) fn once_expires_at(resolved_at: &str) -> Result<String, String> {
    add_seconds_isoformat(resolved_at, ONCE_TTL_MICROS).ok_or_else(|| super::INVALID.to_owned())
}

pub(super) fn wrapper_strings(chain: &[Option<String>]) -> Vec<Value> {
    chain
        .iter()
        .filter_map(|item| item.as_deref())
        .filter(|item| !item.is_empty())
        .map(|item| json!(item))
        .collect()
}

pub(super) fn require_binding(request: &ApprovalResolutionPlanRequestV1) -> Result<(), String> {
    let approval = &request.approval;
    let descriptor = approval
        .envelope
        .as_ref()
        .and_then(|envelope| envelope.native_bash.as_ref());
    if (request.action == "allow" || request.persist_policy == Some(true))
        && crate::native_bash_review_descriptor::reserved(
            approval.artifact_type.as_deref(),
            approval.artifact_id.as_deref(),
            descriptor,
        )
    {
        return if request.scope == "artifact"
            && crate::native_bash_review_descriptor::eligible(
                approval.artifact_type.as_deref(),
                approval.artifact_id.as_deref(),
                approval.artifact_hash.as_deref(),
                approval.harness.as_deref(),
                approval.raw_command_text.as_deref(),
                approval.config_path.as_deref(),
                descriptor,
            ) {
            Ok(())
        } else {
            Err("execution_binding_unavailable".into())
        };
    }
    if request.action != "allow"
        || !approval
            .artifact_id
            .as_deref()
            .is_some_and(|id| id.contains(":native-pretool:"))
        || approval
            .artifact_hash
            .as_deref()
            .is_some_and(|hash| binding_pattern().is_match(hash))
    {
        return Ok(());
    }
    // Older clients cannot save an unbound once decision. A persistent exact
    // token is a separate delivery path and needs explicit artifact duration.
    let persistent = request.scope == "artifact"
        && request.persist_policy == Some(true)
        && [&approval.artifact_hash, &request.native_exact_token]
            .iter()
            .any(|token| {
                token.as_ref().is_some_and(|token| {
                    parse_context_token(&Value::String(token.clone())).is_some()
                })
            });
    if persistent {
        Ok(())
    } else {
        Err("execution_binding_unavailable".to_owned())
    }
}
