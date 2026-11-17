//! Current output policy remains authoritative after native owner execution.
use super::policy_enforcement_helpers::policy_floor_with_cause_and_delivery;
use super::*;
use crate::bash_post_delivery::VerifiedBashDelivery;

#[path = "policy_enforcement_post_action.rs"]
mod post_action;

/// Native scanner denials that Watch keeps: output that matched
/// credential-shaped text, read a sensitive path, or was never fully scanned.
const WATCH_KEPT_DENIAL_CODES: [&str; 6] = [
    "output_secret_match",
    "source_secret_match",
    "sensitive_path",
    "scanner_budget_exhausted",
    "output_too_large",
    "no_output_to_review",
];

fn plain_inline_output(payload: &Value) -> bool {
    match payload.get("tool_response") {
        Some(Value::String(_)) => true,
        Some(Value::Array(parts)) if parts.len() <= 1024 => parts.iter().all(|part| {
            part.as_object().is_some_and(|record| {
                record.len() == 2
                    && record.get("type").and_then(Value::as_str) == Some("text")
                    && record.get("text").is_some_and(Value::is_string)
            })
        }),
        _ => false,
    }
}

#[cfg(test)]
pub(crate) fn apply_post_tool_policy(
    snapshot: &AdmittedPolicySnapshot,
    request: &NativeHookRequestV1,
    payload_kind: GuardHookPayloadKindV2,
    response: HookReviewResponseV1,
) -> Result<HookReviewResponseV1, String> {
    apply_post_tool_policy_with_delivery(snapshot, request, payload_kind, response, None, false)
}

#[cfg(test)]
pub(crate) fn apply_post_tool_policy_with_delivery(
    snapshot: &AdmittedPolicySnapshot,
    request: &NativeHookRequestV1,
    payload_kind: GuardHookPayloadKindV2,
    response: HookReviewResponseV1,
    delivery: Option<&VerifiedBashDelivery>,
    recording_only: bool,
) -> Result<HookReviewResponseV1, String> {
    apply_post_tool_policy_with_witness(
        snapshot,
        request,
        payload_kind,
        response,
        delivery,
        || false,
        recording_only,
    )
}

/// `PostToolUse` policy for a hook whose envelope the policy store
/// authenticated. That store's Guard home holds both the owner's verified
/// delivery and the witness that this exact call ran on the user's approval.
pub(crate) fn apply_post_tool_policy_for_hook(
    snapshot: &AdmittedPolicySnapshot,
    request: &NativeHookRequestV1,
    payload_kind: GuardHookPayloadKindV2,
    response: HookReviewResponseV1,
    origin_store: Option<&crate::policy_store::PolicySnapshotStore>,
    recording_only: bool,
) -> Result<HookReviewResponseV1, String> {
    let delivery = origin_store.and_then(|store| crate::bash_post_delivery::verify(request, store));
    // Guard's own approval wait on this hook's Guard home passed `PreToolUse`
    // on the same proof, so its result is not held either.
    let admitted_call = || {
        origin_store.is_some_and(|store| store.require_guard_home(&request.guard_home).is_ok())
            && (own_approval_wait(request)
                || request.payload.as_object().is_some_and(|payload| {
                    crate::native_admitted_call::admitted_for_post(
                        &request.guard_home,
                        &request.harness,
                        payload,
                    )
                }))
    };
    apply_post_tool_policy_with_witness(
        snapshot,
        request,
        payload_kind,
        response,
        delivery.as_ref(),
        admitted_call,
        recording_only,
    )
}

/// Whether this output is Guard's own approval wait on the hook's Guard
/// home, the same proof that let its `PreToolUse` through.
pub(crate) fn own_approval_wait(request: &NativeHookRequestV1) -> bool {
    super::guard_approval_inspection(
        &request.payload,
        &request.guard_home,
        request.cwd.as_deref(),
    )
}

/// `apply_post_tool_policy_with_delivery`, plus `admitted_call`: whether the
/// call's `PreToolUse` ran it on the user's Allow once or Always allow
/// (`native_admitted_call`). Asked only when an overridable execution floor
/// would hold a clean, fully scanned output, so ordinary calls never read
/// the store.
pub(crate) fn apply_post_tool_policy_with_witness(
    snapshot: &AdmittedPolicySnapshot,
    request: &NativeHookRequestV1,
    payload_kind: GuardHookPayloadKindV2,
    mut response: HookReviewResponseV1,
    delivery: Option<&VerifiedBashDelivery>,
    admitted_call: impl FnOnce() -> bool,
    recording_only: bool,
) -> Result<HookReviewResponseV1, String> {
    if !matches!(snapshot.mode.as_str(), "enforce" | "observe") {
        return Err("native_policy_mode_invalid".to_owned());
    }
    // Only a complete native output scan may reuse the execution admission.
    // A host-supplied marker alone cannot construct this opaque witness.
    // The approval witness needs the same complete scan of this exact output,
    // but not the plain text shape the owner delivery ACK requires: a shell
    // result object such as `{"stdout": ..., "exit_code": 0}` is scanned whole.
    let scanned_output = response.decision == "allow"
        && response.model_output_action == "allow_original"
        && matches!(
            response.reason_code.as_str(),
            "output_scan_allow" | "output_empty_allow" | "source_full_scan_allow"
        )
        && response.reviewed_output_sha256.is_some()
        && response.reviewed_output_sha256
            == guard_hook_core::canonical_observed_output_sha256(&request.payload);
    let clean_scan = payload_kind == GuardHookPayloadKindV2::Inline
        && scanned_output
        && plain_inline_output(&request.payload);
    // A digest the host declared for an excerpt proves less than the whole
    // output, so it never carries the witness. A file read qualifies only
    // when Guard read and scanned that whole file itself.
    let full_scan = scanned_output
        && match payload_kind {
            GuardHookPayloadKindV2::Inline => {
                request.payload.get("tool_response_summary").is_none()
            }
            GuardHookPayloadKindV2::SourceFileRef => {
                response.reason_code == "source_full_scan_allow"
            }
            GuardHookPayloadKindV2::EncryptedPayloadRef => false,
        };
    let verified_delivery = delivery.is_some() && clean_scan;
    let task_metadata = payload_kind == GuardHookPayloadKindV2::Inline
        && guard_command::pretool::bounded_task_metadata_output(&request.payload, &request.harness);
    let omp_output_action = (payload_kind == GuardHookPayloadKindV2::Inline)
        .then(|| eval_output::bounded_output_action(request))
        .flatten();
    let classified_action = post_action::post_action_type(request, payload_kind)?;
    let action_type = if task_metadata {
        PreToolActionTypeV1::Harness
    } else {
        omp_output_action.unwrap_or(classified_action)
    };
    let intrinsic = response
        .observed_policy_action
        .as_deref()
        .or(response.policy_action.as_deref())
        .unwrap_or(if response.decision == "deny" {
            "block"
        } else if response.model_output_action == "replace_with_reviewed_excerpt" {
            "review"
        } else {
            "allow"
        })
        .to_owned();
    if action_rank(&intrinsic).is_none() {
        return Err("native_post_tool_policy_invalid_result".to_owned());
    }
    let harness = normalized_harness(&request.harness);
    let mut facts = payload_facts(
        &request.payload,
        &harness,
        action_type,
        &response.reason_code,
    )?;
    // The operator's exact-tool allow answers the unreviewed-tool setting for
    // the call's output as it does for the call.
    let operator_allowed_mcp_tool = action_type == PreToolActionTypeV1::McpTool
        && !facts.sensitive_target
        && !facts.changed_hash
        && super::policy_enforcement_mcp_provider::outer_tool_name(&request.payload)?.is_some_and(
            |tool| {
                super::policy_enforcement_mcp_provider::operator_allows_tool(
                    &snapshot.effective_policy.mcp_tool_actions,
                    &harness,
                    &tool,
                )
            },
        );
    // As on the call, the allow is the review a `review` unknown-publisher
    // setting asks for; a stronger setting still holds.
    if operator_allowed_mcp_tool
        && facts.publisher.is_none()
        && snapshot.effective_policy.unknown_publisher_action == "review"
    {
        facts.publisher_relevant = false;
    }
    let floor_reason = if (task_metadata || omp_output_action == Some(PreToolActionTypeV1::Harness))
        && matches!(
            response.reason_code.as_str(),
            "output_scan_allow" | "source_full_scan_allow"
        ) {
        "native_agent_task_metadata"
    } else {
        response.reason_code.as_str()
    };
    let floor_for = |verified: bool| {
        policy_floor_with_cause_and_delivery(
            &snapshot.effective_policy,
            &snapshot.compiled,
            &harness,
            action_type,
            &FloorInput {
                facts: &facts,
                reason_code: floor_reason,
                prompt_classes: &[],
                benign_prompt: false,
                package_scripts_disabled: false,
                operator_allowed_mcp_tool,
            },
            verified,
        )
    };
    let (mut floor, mut floor_cause) = floor_for(verified_delivery)?;
    // The user approved this exact call before it ran. The floor that sent it
    // to review may not withhold its clean output; only the execution floors
    // `delivery_floor` lowers are lifted, so a secret, a network or a risk
    // floor on the output still holds.
    if !verified_delivery
        && full_scan
        && action_rank(&floor) > action_rank(&intrinsic)
        && admitted_call()
    {
        (floor, floor_cause) = floor_for(true)?;
    }
    let effective = join_action(&intrinsic, &floor)?;
    response.policy_action = Some(effective.clone());
    // Mark only an actual clean completion, after every independent policy
    // floor has joined. Control replies and prior generations cannot ACK.
    let mark_delivery = verified_delivery
        && snapshot.mode == "enforce"
        && matches!(effective.as_str(), "allow" | "warn")
        && delivery.is_some_and(VerifiedBashDelivery::clean_completion);
    // Watch is the snapshot's observe mode or this harness's own Watch
    // override, which reaches the edge as `recording_only`. PreToolUse already
    // continues on either, so a review here would wait on an inbox row that
    // Watch never writes.
    if snapshot.mode == "observe" || recording_only {
        let canonical_digest = guard_hook_core::canonical_observed_output_sha256(&request.payload);
        if response.decision == "allow" && response.model_output_action == "allow_original" {
            response.reviewed_output_sha256 = canonical_digest;
            return Ok(response);
        }
        // The action has already run, so withholding output that may carry a
        // credential stops nothing. A reviewed excerpt is all the scanner
        // vouched for. Watch records every other verdict.
        if (response.decision == "deny"
            && WATCH_KEPT_DENIAL_CODES.contains(&response.reason_code.as_str()))
            || (response.decision == "allow"
                && response.model_output_action == "replace_with_reviewed_excerpt")
        {
            if response.decision == "deny" {
                response.observe_mode = true;
            }
            return Ok(response);
        }
        response.decision = "allow".to_owned();
        response.model_output_action = "allow_original".to_owned();
        response.policy_action = Some("warn".to_owned());
        response.reviewed_output_sha256 = canonical_digest;
        response.observed_policy_action = Some(intrinsic);
        response.observe_mode = true;
        return Ok(response);
    }
    if mark_delivery {
        response.reason_code = "native_bash_owner_result_allow".to_owned();
        response.reason = None;
    }
    if effective == "allow" {
        return Ok(response);
    }
    if effective == "warn" && response.decision == "allow" {
        if intrinsic != "warn" && !mark_delivery {
            response.reason_code = "native_policy_warning".to_owned();
            response.reason = None;
        }
        return Ok(response);
    }
    if intrinsic == "review"
        && effective == "review"
        && response.decision == "allow"
        && response.model_output_action == "replace_with_reviewed_excerpt"
    {
        return Ok(response);
    }
    if intrinsic == "block" && response.decision == "deny" {
        return Ok(response);
    }
    let cause = (action_rank(&floor) > action_rank(&intrinsic)).then_some(floor_cause);
    let (reason_code, reason) = policy_override_reason(&effective, cause, PromptStop::NotPrompt);
    let mut denied = HookReviewResponseV1::deny(reason_code, reason);
    denied.policy_action = Some(effective);
    Ok(denied)
}
