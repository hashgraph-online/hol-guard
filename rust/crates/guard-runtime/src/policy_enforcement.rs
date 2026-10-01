#![forbid(unsafe_code)]

//! Apply the authenticated effective policy to native hook results.
//!
//! The hook classifiers establish an intrinsic minimum action from the raw
//! request.  This module only joins that result with the already-installed
//! policy snapshot.  It never replaces a stronger native result with a
//! weaker policy value and it never reads configuration or request content
//! outside the native edge.
//!
//! `warn` is an allow-with-warning action, not a deny. In `observe` mode no
//! post-tool outcome stops the harness: the response is rewritten to an
//! allow-original warn that records the canonical output digest and the
//! observed intrinsic action.

use guard_contracts::{
    GuardHookPayloadKindV2, HookReviewResponseV1, NativeHookRequestV1, PreToolActionTypeV1,
    PreToolResultV1,
};
use guard_policy_snapshot::PolicySnapshotV3;
use serde_json::Value;

#[path = "policy_enforcement_facts.rs"]
mod policy_enforcement_facts;
#[path = "policy_enforcement_helpers.rs"]
mod policy_enforcement_helpers;
#[path = "policy_enforcement_matrix.rs"]
mod policy_enforcement_matrix;
#[path = "policy_enforcement_mcp_provider.rs"]
mod policy_enforcement_mcp_provider;
#[path = "policy_enforcement_policy.rs"]
mod policy_enforcement_policy;
pub(crate) use policy_enforcement_matrix::{validate_pre_tool_result_matrix, ActionFloor};

use policy_enforcement_facts::{
    classify_tool_name, collect_fact_maps, payload_facts, preferred_tool_name, PATH_KEYS,
};
use policy_enforcement_helpers::{
    action_rank, join_action, normalized_harness, policy_floor, FloorInput,
};
use policy_enforcement_policy::CompiledEffectivePolicy;

#[path = "policy_enforcement_admission.rs"]
mod policy_enforcement_admission;
pub(crate) use policy_enforcement_admission::AdmittedPolicySnapshot;

#[cfg(test)]
#[path = "policy_enforcement_tests.rs"]
mod tests;
const VALID_ACTIONS: &[&str] = &[
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];

const VALID_RISK_KEYS: &[&str] = &[
    "local_secret_read",
    "credential_exfiltration",
    "data_flow_exfiltration",
    "destructive_shell",
    "encoded_execution",
    "network_egress",
    "prompt_injection",
    "mcp_dangerous_tool",
    "malicious_skill",
    "package_script",
    "persistence",
    "guard_bypass",
    "cloud_advisory",
    "encoded_exfiltration",
    "execution",
    "supply_chain",
    "policy_bypass",
];

const MAX_SELECTOR_VALUE_BYTES: usize = 4 * 1024;
const MAX_FACT_DEPTH: usize = 32;
const MAX_FACT_NODES: usize = 2_048;

fn policy_override_reason(action: &str) -> (&'static str, &'static str) {
    match action {
        "block" => (
            "native_policy_block",
            "HOL Guard blocked this hook action under the installed native policy.",
        ),
        "sandbox-required" => (
            "native_policy_sandbox_required",
            "HOL Guard requires sandbox enforcement under the installed native policy.",
        ),
        "require-reapproval" => (
            "native_policy_reapproval_required",
            "HOL Guard requires fresh approval under the installed native policy.",
        ),
        "review" => (
            "native_policy_review_required",
            "HOL Guard requires review under the installed native policy.",
        ),
        _ => (
            "native_policy_warning",
            "HOL Guard raised this action under the installed native policy.",
        ),
    }
}

/// Apply the authenticated policy to a generic native PreTool result.
pub(crate) fn apply_pre_tool_policy(
    snapshot: &AdmittedPolicySnapshot,
    payload: &Value,
    mut result: PreToolResultV1,
) -> Result<PreToolResultV1, String> {
    if !matches!(snapshot.mode.as_str(), "enforce" | "observe") {
        return Err("native_policy_mode_invalid".to_owned());
    }
    validate_pre_tool_result_matrix(&result)?;
    let harness = normalized_harness(&result.action.harness);
    let mut facts = payload_facts(
        payload,
        &harness,
        result.action.action_type,
        &result.reason_code,
    )?;
    facts.sensitive_target |= result.action.sensitive_target;
    let benign_prompt = result.action.event == "UserPromptSubmit"
        && result.action.action_type == PreToolActionTypeV1::Prompt
        && result.explicitly_benign
        && result.reason_code == "native_prompt_benign"
        && !facts.sensitive_target;
    if result.action.action_type == PreToolActionTypeV1::McpTool {
        // Tool arguments can themselves contain `tool_name` (dispatchers are
        // common). They are data, never the outer tool's authority selector.
        let tool = match payload.as_object() {
            Some(record) => {
                let mut envelopes = vec![record];
                for key in ["tool_call", "toolCall", "preToolUse", "pre_tool_use"] {
                    if let Some(envelope) = record.get(key).and_then(Value::as_object) {
                        envelopes.push(envelope);
                    }
                }
                preferred_tool_name(&envelopes)?.or_else(|| {
                    ["action", "operation"]
                        .into_iter()
                        .find_map(|key| record.get(key).and_then(Value::as_str).map(str::to_owned))
                })
            }
            None => None,
        };
        if let Some(tool) = tool {
            let composio_name = tool
                .rsplit("__")
                .next()
                .unwrap_or(&tool)
                .to_ascii_lowercase();
            let composio_execution = composio_name.starts_with("composio_")
                && !matches!(
                    composio_name.as_str(),
                    "composio_search_tools" | "composio_get_tool_schemas"
                );
            if composio_execution && action_rank(&result.minimum_action) < action_rank("review") {
                result.minimum_action = "review".into();
                result.policy_action = "review".into();
                result.decision = "deny".into();
                result.explicitly_benign = false;
                result.reason_code = "native_composio_action_review".into();
                result.reason =
                    "Review the underlying Composio actions and account before execution.".into();
            }
            if let Some(reason) = policy_enforcement_mcp_provider::denied_provider_execution(
                &snapshot.effective_policy.mcp_provider_actions,
                &harness,
                &tool,
                payload,
            ) {
                result.minimum_action = "block".into();
                result.policy_action = "block".into();
                result.decision = "deny".into();
                result.explicitly_benign = false;
                result.reason_code = reason.into();
                result.reason = if reason == "native_composio_denied_batch_member" {
                    "This batch includes an action denied for this connection. No batch member may execute."
                } else {
                    "Guard cannot enforce this connection's action denies inside opaque execution. Use an explicit batch."
                }.into();
            }
            let choice = guard_policy_snapshot::observed_mcp_tool_action(
                &snapshot.effective_policy.mcp_tool_actions,
                &harness,
                &tool,
            );
            if choice == Some("block") && result.minimum_action != "block" {
                result.minimum_action = "block".into();
                result.policy_action = "block".into();
                result.decision = "deny".into();
                result.explicitly_benign = false;
                result.reason_code = "native_custom_mcp_tool_block".into();
                result.reason =
                    "This MCP tool is blocked by a custom extension on this device.".into();
            } else if choice == Some("review")
                && action_rank(&result.minimum_action) < action_rank("review")
            {
                result.minimum_action = "review".into();
                result.policy_action = "review".into();
                result.decision = "deny".into();
                result.explicitly_benign = false;
                result.reason_code = "native_custom_mcp_tool_review".into();
                result.reason =
                    "This MCP tool requires approval under its custom extension settings.".into();
            } else if choice == Some("allow")
                && !composio_execution
                && result.minimum_action == "review"
                && result.reason_code == "native_mcp_tool_review"
                && result.action.bounded
                && !facts.sensitive_target
                && !facts.changed_hash
                && result.command_extensions.as_ref().is_none_or(|evidence| {
                    evidence.binding.observation_count == 0 && evidence.evaluation_error.is_none()
                })
            {
                // Only explicit operator authority in the admitted, authenticated
                // snapshot can replace the unknown-tool review. Independent
                // native findings and every installed policy floor still apply.
                result.minimum_action = "allow".into();
                result.policy_action = "allow".into();
                result.decision = "allow".into();
                result.explicitly_benign = true;
                result.reason_code = "native_custom_mcp_tool_allow".into();
                result.reason =
                    "This exact MCP tool is allowed by a custom extension on this device.".into();
                // The explicit operator choice satisfies the generic unknown
                // publisher review for this namespace. Stronger publisher
                // actions and independent MCP risk policies remain floors.
                if facts.publisher.is_none()
                    && snapshot.effective_policy.unknown_publisher_action == "review"
                {
                    facts.publisher_relevant = false;
                }
            }
        }
    }
    let policy_floor = policy_floor(
        &snapshot.effective_policy,
        &snapshot.compiled,
        &harness,
        result.action.action_type,
        &FloorInput {
            facts: &facts,
            reason_code: &result.reason_code,
            prompt_classes: &result.prompt_risk_classes,
            benign_prompt,
        },
    )?;
    let effective = join_action(&result.minimum_action, &policy_floor)?;
    let policy_raised = action_rank(&effective) > action_rank(&result.minimum_action);
    let mut output = result;

    if snapshot.mode == "observe" {
        // Observe suppresses only an escalation introduced by the installed
        // policy. Every intrinsic review, reapproval, sandbox, block, and
        // malformed/unknown result remains authoritative. A native block
        // paired with an inconsistent allow decision is repaired fail-closed.
        let intrinsic_rank = action_rank(&output.minimum_action)
            .ok_or_else(|| "native_policy_action_invalid".to_owned())?;
        let policy_only_warning = policy_raised
            && intrinsic_rank <= action_rank("warn").unwrap_or(1)
            && output.decision == "allow";
        if policy_only_warning {
            output.reason_code = "native_policy_warning".to_owned();
            output.reason =
                "HOL Guard observed a stricter installed native policy floor.".to_owned();
            output.policy_action = "warn".to_owned();
            output.minimum_action = "warn".to_owned();
            output.decision = "allow".to_owned();
            output.explicitly_benign = false;
        } else {
            output.policy_action = effective.clone();
            output.minimum_action = effective.clone();
            output.decision =
                if action_rank(&effective).unwrap_or(5) <= action_rank("warn").unwrap_or(1) {
                    "allow".to_owned()
                } else {
                    "deny".to_owned()
                };
            output.explicitly_benign = effective == "allow";
        }
        validate_pre_tool_result_matrix(&output)?;
        return Ok(output);
    }

    if policy_raised {
        let (reason_code, reason) = policy_override_reason(&effective);
        output.reason_code = reason_code.to_owned();
        output.reason = reason.to_owned();
    }
    output.policy_action = effective.clone();
    output.minimum_action = effective.clone();
    output.decision = if matches!(effective.as_str(), "allow" | "warn") {
        "allow".to_owned()
    } else {
        "deny".to_owned()
    };
    output.explicitly_benign = effective == "allow";
    validate_pre_tool_result_matrix(&output)?;
    Ok(output)
}

fn post_action_type(
    request: &NativeHookRequestV1,
    payload_kind: GuardHookPayloadKindV2,
) -> Result<PreToolActionTypeV1, String> {
    if payload_kind == GuardHookPayloadKindV2::SourceFileRef {
        return Ok(PreToolActionTypeV1::FileRead);
    }
    let mut maps = Vec::new();
    let mut nodes = 0usize;
    collect_fact_maps(&request.payload, 0, &mut nodes, &mut maps)?;
    if let Some(tool) = preferred_tool_name(&maps)? {
        return Ok(classify_tool_name(&tool));
    }
    for record in maps {
        if record.keys().any(|key| {
            matches!(
                key.as_str(),
                "command" | "cmd" | "shell_command" | "shellCommand"
            )
        }) {
            return Ok(PreToolActionTypeV1::Command);
        }
        if record
            .keys()
            .any(|key| matches!(key.as_str(), "package" | "package_name" | "packageName"))
        {
            return Ok(PreToolActionTypeV1::Package);
        }
        if record.keys().any(|key| PATH_KEYS.contains(&key.as_str())) {
            return Ok(PreToolActionTypeV1::FileRead);
        }
        if record
            .keys()
            .any(|key| matches!(key.as_str(), "url" | "uri" | "href" | "endpoint"))
        {
            return Ok(PreToolActionTypeV1::Network);
        }
    }
    Ok(PreToolActionTypeV1::Unknown)
}

/// Apply the authenticated policy to a Rust-owned PostTool result. The
/// source/content decision is intrinsic and therefore remains strongest even
/// when the configured policy says `allow`.
pub(crate) fn apply_post_tool_policy(
    snapshot: &AdmittedPolicySnapshot,
    request: &NativeHookRequestV1,
    payload_kind: GuardHookPayloadKindV2,
    mut response: HookReviewResponseV1,
) -> Result<HookReviewResponseV1, String> {
    if !matches!(snapshot.mode.as_str(), "enforce" | "observe") {
        return Err("native_policy_mode_invalid".to_owned());
    }
    let action_type = post_action_type(request, payload_kind)?;
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
    let floor = policy_floor(
        &snapshot.effective_policy,
        &snapshot.compiled,
        &harness,
        action_type,
        &FloorInput {
            facts: &facts,
            reason_code: &response.reason_code,
            prompt_classes: &[],
            benign_prompt: false,
        },
    )?;
    let effective = join_action(&intrinsic, &floor)?;
    response.policy_action = Some(effective.clone());
    if snapshot.mode == "observe" {
        // Observe never stops the harness: every outcome is rewritten to an
        // allow-original response carrying the canonical proof digest (or none
        // when the output is truncated or excerpt-only). Intrinsic
        // allow-original responses keep their decision and effective floor;
        // anything else is recorded as a warn with the intrinsic action kept in
        // observed_policy_action.
        let canonical_digest = guard_hook_core::canonical_observed_output_sha256(&request.payload);
        if response.decision == "allow" && response.model_output_action == "allow_original" {
            response.reviewed_output_sha256 = canonical_digest;
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
    if effective == "allow" {
        return Ok(response);
    }
    if effective == "warn" && response.decision == "allow" {
        if intrinsic != "warn" {
            response.reason_code = "native_policy_warning".to_owned();
            response.reason = Some(
                "HOL Guard raised a non-blocking warning under the installed native policy."
                    .to_owned(),
            );
            response.notice = "warning".to_owned();
        }
        return Ok(response);
    }
    if intrinsic == "review"
        && effective == "review"
        && response.decision == "allow"
        && response.model_output_action == "replace_with_reviewed_excerpt"
    {
        // A reviewed excerpt already satisfies the intrinsic review floor.
        return Ok(response);
    }
    if intrinsic == "block" && response.decision == "deny" {
        return Ok(response);
    }
    let (reason_code, reason) = policy_override_reason(&effective);
    let mut denied = HookReviewResponseV1::deny(reason_code, reason);
    denied.policy_action = Some(effective);
    Ok(denied)
}
