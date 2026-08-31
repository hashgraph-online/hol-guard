#![forbid(unsafe_code)]

//! Apply the authenticated effective policy to native hook results.
//!
//! The hook classifiers establish an intrinsic minimum action from the raw
//! request.  This module only joins that result with the already-installed
//! policy snapshot.  It never replaces a stronger native result with a
//! weaker policy value and it never reads configuration or request content
//! outside the native edge.
//!
//! `warn` is an allow-with-warning action, not a deny. In `observe` mode a
//! policy-only floor is surfaced as a warning (so it cannot deny execution),
//! while an intrinsic native floor is preserved. Intrinsic `block` remains
//! hard in every mode.

use guard_contracts::{
    GuardHookPayloadKindV2, HookReviewResponseV1, NativeHookRequestV1, PreToolActionTypeV1,
    PreToolResultV1,
};
use guard_policy_snapshot::{EffectiveNativePolicyV3, PolicySnapshotV3};
use serde_json::Value;

#[path = "policy_enforcement_facts.rs"]
mod policy_enforcement_facts;
#[path = "policy_enforcement_policy.rs"]
mod policy_enforcement_policy;

use policy_enforcement_facts::{
    classify_tool_name, collect_fact_maps, payload_facts, preferred_tool_name, risk_classes,
    PolicyFacts, PATH_KEYS,
};
use policy_enforcement_policy::{
    canonical_harness_action, canonical_harness_risk_actions, policy_map_action,
    validate_effective_policy,
};

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

fn action_rank(action: &str) -> Option<u8> {
    Some(match action {
        "allow" => 0,
        "warn" => 1,
        "review" => 2,
        "require-reapproval" => 3,
        "sandbox-required" => 4,
        "block" => 5,
        _ => return None,
    })
}

fn join_action(left: &str, right: &str) -> Result<String, String> {
    let left_rank = action_rank(left).ok_or_else(|| "native_policy_action_invalid".to_owned())?;
    let right_rank = action_rank(right).ok_or_else(|| "native_policy_action_invalid".to_owned())?;
    Ok(if left_rank >= right_rank {
        left.to_owned()
    } else {
        right.to_owned()
    })
}

fn canonical_harness(value: &str) -> Option<&str> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "claude" => Some("claude-code"),
        "cline-cli" | "cline-vscode" => Some("cline"),
        "kimi-code" | "kimi-cli" => Some("kimi"),
        "grok-build" | "grok-build-cli" | "xai-grok" => Some("grok"),
        "pi-agent" | "pi-coding-agent" => Some("pi"),
        "oh-my-pi" => Some("omp"),
        "zai" | "z-code" | "zai-zcode" => Some("zcode"),
        _ => None,
    }
}

fn normalized_harness(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    canonical_harness(&normalized)
        .unwrap_or(normalized.as_str())
        .to_owned()
}

fn policy_floor(
    policy: &EffectiveNativePolicyV3,
    harness: &str,
    action_type: PreToolActionTypeV1,
    facts: &PolicyFacts,
    reason_code: &str,
) -> Result<String, String> {
    validate_effective_policy(policy)?;
    let mut floor = policy.default_action.clone();
    if let Some(action) = canonical_harness_action(&policy.harness_actions, harness)? {
        floor = join_action(&floor, &action)?;
    }
    if matches!(
        action_type,
        PreToolActionTypeV1::Command | PreToolActionTypeV1::ProcessService
    ) {
        floor = join_action(&floor, &policy.subprocess_action)?;
    }
    if matches!(
        action_type,
        PreToolActionTypeV1::Network | PreToolActionTypeV1::Browser
    ) {
        floor = join_action(&floor, &policy.new_network_domain_action)?;
    }
    if action_type == PreToolActionTypeV1::Unknown {
        // An unknown PostToolUse operation has no safe automatic allow
        // proof, even when the configured default is permissive.
        floor = join_action(&floor, "review")?;
    }
    if facts.changed_hash {
        floor = join_action(&floor, &policy.changed_hash_action)?;
    }
    if facts.publisher_relevant && facts.publisher.is_none() {
        floor = join_action(&floor, &policy.unknown_publisher_action)?;
    }
    if let Some(artifact) = facts.artifact.as_deref() {
        if let Some(action) = policy_map_action(&policy.artifact_actions, artifact)? {
            floor = join_action(&floor, &action)?;
        }
    }
    if let Some(publisher) = facts.publisher.as_deref() {
        if let Some(action) = policy_map_action(&policy.publisher_actions, publisher)? {
            floor = join_action(&floor, &action)?;
        }
    }
    let harness_risks = canonical_harness_risk_actions(&policy.harness_risk_actions, harness)?;
    for risk in risk_classes(action_type, facts.sensitive_target, reason_code) {
        if let Some(action) = policy_map_action(&policy.risk_actions, risk)? {
            floor = join_action(&floor, &action)?;
        }
        if let Some(harness_map) = harness_risks {
            if let Some(action) = policy_map_action(harness_map, risk)? {
                floor = join_action(&floor, &action)?;
            }
        }
    }
    Ok(floor)
}

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
    snapshot: &PolicySnapshotV3,
    payload: &Value,
    result: PreToolResultV1,
) -> Result<PreToolResultV1, String> {
    if !matches!(snapshot.mode.as_str(), "enforce" | "observe") {
        return Err("native_policy_mode_invalid".to_owned());
    }
    let harness = normalized_harness(&result.action.harness);
    let mut facts = payload_facts(payload, result.action.action_type, &result.reason_code)?;
    facts.sensitive_target |= result.action.sensitive_target;
    let policy_floor = policy_floor(
        &snapshot.effective_policy,
        &harness,
        result.action.action_type,
        &facts,
        &result.reason_code,
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
            output.policy_action = effective;
            if intrinsic_rank >= action_rank("block").unwrap_or(5) && output.decision == "allow" {
                output.decision = "deny".to_owned();
                output.explicitly_benign = false;
            }
        }
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
    snapshot: &PolicySnapshotV3,
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
    let facts = payload_facts(&request.payload, action_type, &response.reason_code)?;
    let floor = policy_floor(
        &snapshot.effective_policy,
        &normalized_harness(&request.harness),
        action_type,
        &facts,
        &response.reason_code,
    )?;
    let effective = join_action(&intrinsic, &floor)?;
    response.policy_action = Some(effective.clone());
    if snapshot.mode == "observe" && intrinsic != "block" {
        return Ok(response);
    }
    if snapshot.mode == "observe" && intrinsic == "block" && response.decision == "allow" {
        // Observe suppresses policy-only floors, but it cannot turn an
        // intrinsic native source/content block into an allow.
        let mut denied = HookReviewResponseV1::deny(
            response.reason_code.clone(),
            "HOL Guard retained an intrinsic native block in observe mode.",
        );
        denied.policy_action = Some("block".to_owned());
        denied.observed_policy_action = Some("block".to_owned());
        denied.observe_mode = true;
        return Ok(denied);
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
