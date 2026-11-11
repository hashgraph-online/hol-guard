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
/// Static notice delivered as the reviewed excerpt when Watch withholds
/// output. It carries no tool output bytes, so it is model-safe by
/// construction; the original output stays hidden and the turn continues.
const WATCH_REDACTED_OUTPUT_NOTICE: &str =
    "HOL Guard withheld this tool output in Watch mode because it may contain sensitive content.";

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

pub(crate) fn apply_post_tool_policy_with_delivery(
    snapshot: &AdmittedPolicySnapshot,
    request: &NativeHookRequestV1,
    payload_kind: GuardHookPayloadKindV2,
    mut response: HookReviewResponseV1,
    delivery: Option<&VerifiedBashDelivery>,
    recording_only: bool,
) -> Result<HookReviewResponseV1, String> {
    if !matches!(snapshot.mode.as_str(), "enforce" | "observe") {
        return Err("native_policy_mode_invalid".to_owned());
    }
    // Only a complete native output scan may reuse the execution admission.
    // A host-supplied marker alone cannot construct this opaque witness.
    let verified_delivery = delivery.is_some()
        && payload_kind == GuardHookPayloadKindV2::Inline
        && plain_inline_output(&request.payload)
        && response.decision == "allow"
        && response.model_output_action == "allow_original"
        && matches!(
            response.reason_code.as_str(),
            "output_scan_allow" | "output_empty_allow" | "source_full_scan_allow"
        )
        && response.reviewed_output_sha256.is_some()
        && response.reviewed_output_sha256
            == guard_hook_core::canonical_observed_output_sha256(&request.payload);
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
    let facts = payload_facts(
        &request.payload,
        &harness,
        action_type,
        &response.reason_code,
    )?;
    let (floor, floor_cause) = policy_floor_with_cause_and_delivery(
        &snapshot.effective_policy,
        &snapshot.compiled,
        &harness,
        action_type,
        &FloorInput {
            facts: &facts,
            reason_code: if (task_metadata
                || omp_output_action == Some(PreToolActionTypeV1::Harness))
                && matches!(
                    response.reason_code.as_str(),
                    "output_scan_allow" | "source_full_scan_allow"
                ) {
                "native_agent_task_metadata"
            } else {
                &response.reason_code
            },
            prompt_classes: &[],
            benign_prompt: false,
            package_scripts_disabled: false,
        },
        verified_delivery,
    )?;
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
        // The action has already run, so the harness verdict must continue:
        // a deny here queues an approval Watch never writes and fails the
        // call. What Watch keeps is the masking, not the block. A kept
        // denial becomes an allow carrying a redaction notice as its
        // reviewed excerpt: the receipt records the block via
        // `observed_policy_action`, the original output never reaches the
        // model, and the turn continues. A reviewed excerpt the scanner
        // already vouched for passes through unchanged.
        if response.decision == "deny"
            && WATCH_KEPT_DENIAL_CODES.contains(&response.reason_code.as_str())
        {
            let excerpt = match response.reviewed_excerpt.take() {
                Some(text) if !text.is_empty() => text,
                _ => WATCH_REDACTED_OUTPUT_NOTICE.to_owned(),
            };
            let kept_reason = response.reason_code.clone();
            response = HookReviewResponseV1::reviewed_excerpt(
                kept_reason,
                response
                    .reason
                    .take()
                    .unwrap_or_else(|| WATCH_REDACTED_OUTPUT_NOTICE.to_owned()),
                excerpt,
            );
            response.policy_action = Some("warn".to_owned());
            response.observed_policy_action = Some(intrinsic);
            response.observe_mode = true;
            return Ok(response);
        }
        if response.decision == "allow"
            && response.model_output_action == "replace_with_reviewed_excerpt"
        {
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
