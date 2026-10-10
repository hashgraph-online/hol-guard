//! Post-claim revalidation of an exact saved approval.
//!
//! The claim closes the one-shot race, but it does not freeze configuration,
//! tool identity, arguments, or a concurrently inserted saved block. Every one
//! of those inputs is re-read before an executable allow can be returned.

use guard_command::approval_reuse::{
    APPROVAL_REUSE_ACCEPTED, APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
};
use guard_command::effect_decision::GuardAction;
use guard_contracts::McpToolPolicySubjectV1;
use serde_json::{json, Map, Value};

use crate::approval_proof_op::{
    fresh_tool_approval, lookup_preserves_claim, postclaim_review_authorized, Disposition,
};
use crate::mcp_tool_policy_decision::{with_reuse, Current, Decision};
use crate::mcp_tool_policy_flow::{
    compose, evaluate_current, evaluate_pass, most_restrictive, Ctx, Flow, Pass, Phase, Stop,
    ERR_OBSERVATION,
};

const INTEGRITY_FAILURE: &str = "approval_reuse_integrity_failure";
const ERR_INTERNAL: &str = "native_mcp_tool_policy_decide_internal";

/// The authority the caller refreshed after the claim, or the initial one when
/// the refresh failed (which always floors the decision).
fn fresh_subject(
    ctx: &Ctx,
    initial: &McpToolPolicySubjectV1,
) -> Flow<(McpToolPolicySubjectV1, bool)> {
    let answer = ctx.ask(json!({"kind": "fresh_authority"}))?;
    let status = answer.get("status").and_then(Value::as_str);
    match status {
        Some("failed") => Ok((initial.clone(), true)),
        Some("provided") => {
            let subject = answer.get("subject").cloned().unwrap_or(Value::Null);
            serde_json::from_value(subject)
                .map(|subject| (subject, false))
                .map_err(|_| Stop::Fail(ERR_OBSERVATION))
        }
        _ => Err(Stop::Fail(ERR_OBSERVATION)),
    }
}

pub(crate) fn revalidate(
    ctx: &Ctx,
    initial: &McpToolPolicySubjectV1,
    claimed: &Map<String, Value>,
    disposition: Option<Disposition>,
) -> Flow<Decision> {
    let (fresh, refresh_failed) = fresh_subject(ctx, initial)?;
    let fresh_current = evaluate_current(&fresh)?;
    let Pass::Final(fresh_decision) = evaluate_pass(ctx, &fresh, Phase::Fresh, false)? else {
        return Err(Stop::Fail(ERR_INTERNAL));
    };
    let changed = || Some(APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM.to_owned());
    let mut validation_reason: Option<String> =
        if refresh_failed || fresh.artifact_id != initial.artifact_id {
            changed()
        } else {
            crate::context_digest::validate_context_tokens(
                &Value::String(initial.artifact_hash.clone()),
                &Value::String(fresh.artifact_hash.clone()),
            )
            .and_then(|_| changed())
        };
    let reason = fresh_decision.approval_reuse_reason_code.as_deref();
    if reason == Some(INTEGRITY_FAILURE) {
        validation_reason = Some(INTEGRITY_FAILURE.to_owned());
    } else if fresh_decision.approval_reuse_status == Some("rejected")
        && !lookup_preserves_claim(reason)
    {
        validation_reason = changed();
    }
    // A fresh unclaimed allow is not launch authority. Reuse the freshly
    // computed current action, while preserving a newly observed saved block
    // or another terminal result from the second lookup.
    let mut action = fresh_decision.action;
    if fresh_decision.saved_action == Some(GuardAction::Allow)
        && reason == Some(APPROVAL_REUSE_ACCEPTED)
    {
        action = fresh_current.action;
    }
    if action == GuardAction::Review
        && !postclaim_review_authorized(disposition, Some(claimed), fresh_decision.pending.as_ref())
    {
        validation_reason = changed();
    }
    let mut summary = fresh_current.summary.clone();
    if validation_reason.is_some() {
        action = most_restrictive(action, GuardAction::RequireReapproval);
        summary =
            "Current tool-call authority changed after the saved approval was claimed.".to_owned();
    }
    let post_claim = Current {
        action,
        summary,
        ..fresh_current
    };
    let fresh_local = disposition == Some(Disposition::Consumed)
        && fresh_tool_approval(
            Some(claimed),
            &fresh.harness,
            &fresh.artifact_id,
            &fresh.artifact_hash,
        );
    let reuse = compose(
        post_claim.action,
        &Value::String("allow".to_owned()),
        validation_reason.as_deref(),
        fresh_local,
    );
    let mut decision = with_reuse(&post_claim, &reuse, None);
    decision.claim_disposition = disposition;
    decision.post_claim_revalidated = true;
    Ok(decision)
}
