//! Scoped resident evaluation with an exact immutable source commitment.

use crate::edge::{authoritative_event, canonical_harness, payload_kind, request_identity};
use crate::native_hook_receipt::{receipt_from_post_tool, receipt_from_scoped_pre_tool};
use crate::policy_enforcement::AdmittedScopedPolicySnapshot;
use guard_contracts::{
    GuardHookEnvelopeV2, GuardHookPayloadKindV2, HookReviewResponseV1, NativeHookDecisionReceiptV1,
    NativeHookRequestV1, PreToolResultV1, NATIVE_PROTOCOL_VERSION,
};
#[cfg(test)]
use guard_policy_snapshot::PolicySnapshotV4;
use serde::Serialize;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ScopedDecisionBinding<'a> {
    policy_generation: u64,
    policy_digest: &'a str,
    source_input_digest: &'a str,
    runtime_identity: &'a str,
    resident_generation: u64,
    selected_decision_id: Option<u64>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ScopedEdgeResult<'a> {
    schema: &'static str,
    authority: &'static str,
    request_id: String,
    harness: String,
    event_name: String,
    payload_kind: GuardHookPayloadKindV2,
    result: ScopedHookResult,
    observed_policy_action: Option<String>,
    receipt: NativeHookDecisionReceiptV1,
    policy_binding: ScopedDecisionBinding<'a>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum ScopedHookResult {
    Pre(Box<PreToolResultV1>),
    Post(Box<HookReviewResponseV1>),
}

/// Only the versioned resident store may provide the authenticated snapshot.
pub(crate) fn evaluate_admitted(
    envelope: GuardHookEnvelopeV2,
    snapshot: &AdmittedScopedPolicySnapshot,
    resident_generation: u64,
) -> Result<Vec<u8>, String> {
    let harness = canonical_harness(&envelope.harness)?;
    let event_name = authoritative_event(&envelope)?;
    let kind = payload_kind(&envelope.raw_payload)?;
    let defaults_only = snapshot.scoped_authority.is_defaults_only();
    if (!defaults_only && (event_name != "PreToolUse" || kind != GuardHookPayloadKindV2::Inline))
        || kind == GuardHookPayloadKindV2::EncryptedPayloadRef
        || !matches!(event_name.as_str(), "PreToolUse" | "PostToolUse")
    {
        return Err("native_scoped_hook_route_unsupported".to_owned());
    }
    let (request_id, request_digest) = request_identity(&envelope)?;
    // The receipt uses the verified full snapshot, never unverified fields
    // supplied beside a compact request reference.
    let mut receipt_envelope = envelope;
    receipt_envelope.policy_snapshot = serde_json::to_value(snapshot.snapshot())
        .map_err(|_| "native_hook_edge_response_invalid".to_owned())?;
    let (result, observed_policy_action, selected_decision_id, receipt) =
        if event_name == "PreToolUse" {
            let (result, observed, selected) =
                evaluate_pre_tool(&receipt_envelope, snapshot, &harness, &kind, defaults_only)?;
            let receipt = receipt_from_scoped_pre_tool(
                &receipt_envelope,
                &request_id,
                &request_digest,
                &harness,
                &kind,
                &result,
                observed.as_deref(),
            )?;
            (
                ScopedHookResult::Pre(Box::new(result)),
                observed,
                selected,
                receipt,
            )
        } else {
            // Only a fully authenticated, empty scoped authority reaches this
            // branch. A scoped row or managed origin cannot be silently ignored.
            let request = NativeHookRequestV1 {
                protocol_version: NATIVE_PROTOCOL_VERSION,
                request_id: receipt_envelope.request_id.clone(),
                harness: harness.clone(),
                event_name: event_name.clone(),
                payload: receipt_envelope.raw_payload.clone(),
                cwd: receipt_envelope.source.cwd.clone(),
                home_dir: receipt_envelope.source.home_dir.clone(),
                guard_home: receipt_envelope.source.guard_home.clone(),
                source_ref_external_allowed: receipt_envelope.source.source_ref_external_allowed,
                observe_mode: false,
                deadline_budget_ms: receipt_envelope.deadline_budget_ms,
            };
            let intrinsic = guard_hook_core::review_post_tool(&request);
            let mut result = crate::policy_enforcement::apply_post_tool_defaults(
                &snapshot.effective_policy,
                &snapshot.compiled,
                &snapshot.mode,
                &request,
                kind.clone(),
                intrinsic,
            )?;
            // The existing default routine owns decision/excerpt semantics. Bind
            // its observation metadata to the authenticated V4 mode as well.
            result.observe_mode = snapshot.mode == "observe";
            result.observed_policy_action = result
                .observe_mode
                .then(|| result.policy_action.clone())
                .flatten();
            let observed = result.observed_policy_action.clone();
            let receipt = receipt_from_post_tool(
                &receipt_envelope,
                None,
                &request_id,
                &request_digest,
                &harness,
                &kind,
                &result,
            )?;
            (
                ScopedHookResult::Post(Box::new(result)),
                observed,
                None,
                receipt,
            )
        };
    crate::encode_response(&ScopedEdgeResult {
        schema: "guard-hook-edge-result.v3",
        authority: "rust",
        request_id,
        harness,
        event_name,
        payload_kind: kind,
        result,
        observed_policy_action,
        receipt,
        policy_binding: ScopedDecisionBinding {
            policy_generation: snapshot.generation,
            policy_digest: &snapshot.policy_digest,
            source_input_digest: &snapshot.source_input_digest,
            runtime_identity: &snapshot.runtime_identity,
            resident_generation,
            selected_decision_id,
        },
    })
}

fn evaluate_pre_tool(
    envelope: &GuardHookEnvelopeV2,
    snapshot: &AdmittedScopedPolicySnapshot,
    harness: &str,
    kind: &GuardHookPayloadKindV2,
    defaults_only: bool,
) -> Result<(PreToolResultV1, Option<String>, Option<u64>), String> {
    let deadline = Some(
        Instant::now()
            + Duration::from_millis(envelope.deadline_budget_ms.unwrap_or(9_000).min(9_000)),
    );
    let scoped_request = *kind == GuardHookPayloadKindV2::Inline
        && crate::policy_scoped_request::derive_scoped_policy_request(envelope, harness).is_ok();
    if defaults_only && !scoped_request {
        // Preserve the existing V3 ordering and Observe behavior for defaults.
        let intrinsic = guard_command::pretool::evaluate_pre_tool_envelope_with_extensions(
            harness,
            "PreToolUse",
            &envelope.raw_payload,
            snapshot.command_extensions.as_ref(),
            deadline,
        );
        let observed = if snapshot.mode == "observe" {
            Some(
                crate::policy_enforcement::apply_pre_tool_defaults(
                    &snapshot.effective_policy,
                    &snapshot.compiled,
                    "enforce",
                    &envelope.raw_payload,
                    intrinsic.clone(),
                )?
                .policy_action,
            )
        } else {
            None
        };
        let result = crate::policy_enforcement::apply_pre_tool_defaults(
            &snapshot.effective_policy,
            &snapshot.compiled,
            &snapshot.mode,
            &envelope.raw_payload,
            intrinsic,
        )?;
        return Ok((result, observed, None));
    }
    // Scoped composition may satisfy the classifier's fallback review. Join
    // independent command floors afterwards, including an equal review floor.
    let (result, (observed, selected, composed_action)) =
        guard_command::pretool::evaluate_pre_tool_envelope_with_composition(
            harness,
            "PreToolUse",
            &envelope.raw_payload,
            snapshot.command_extensions.as_ref(),
            deadline,
            |intrinsic| {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "native_policy_clock_invalid".to_owned())?
                    .as_millis();
                let now_ms =
                    u64::try_from(now).map_err(|_| "native_policy_clock_invalid".to_owned())?;
                let evaluated =
                    crate::policy_scoped_enforcement::apply_scoped_pre_tool_policy_compiled(
                        snapshot,
                        &snapshot.compiled,
                        envelope,
                        harness,
                        intrinsic,
                        now_ms,
                    )?;
                let composed_action = evaluated.result.minimum_action.clone();
                Ok((
                    evaluated.result,
                    (
                        evaluated.observed_policy_action.map(str::to_owned),
                        evaluated.selected_decision_id,
                        composed_action,
                    ),
                ))
            },
        )?;
    crate::policy_enforcement::validate_pre_tool_result_matrix(&result)?;
    let selected = selected.filter(|_| result.minimum_action == composed_action);
    Ok((result, observed, selected))
}

#[cfg(test)]
pub(crate) fn evaluate(
    envelope: GuardHookEnvelopeV2,
    snapshot: &PolicySnapshotV4,
    resident_generation: u64,
) -> Result<Vec<u8>, String> {
    let admitted = AdmittedScopedPolicySnapshot::new(snapshot.clone())?;
    evaluate_admitted(envelope, &admitted, resident_generation)
}
