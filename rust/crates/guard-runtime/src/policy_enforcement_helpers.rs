use super::policy_enforcement_facts::{risk_classes, PolicyFacts};
use super::policy_enforcement_policy::{policy_map_action, CompiledEffectivePolicy};
use super::ActionFloor;
use guard_contracts::{NativePromptRiskClassV1, PreToolActionTypeV1};
use guard_policy_snapshot::EffectiveNativePolicyV3;

/// The intrinsic-result inputs a policy floor can consult.  Grouped so the
/// floor signature stays small and so a caller cannot accidentally swap the
/// reason code for a different result's class list.
pub(super) struct FloorInput<'a> {
    pub(super) facts: &'a PolicyFacts,
    pub(super) reason_code: &'a str,
    pub(super) prompt_classes: &'a [NativePromptRiskClassV1],
    pub(super) benign_prompt: bool,
}

pub(super) fn policy_floor(
    policy: &EffectiveNativePolicyV3,
    compiled: &CompiledEffectivePolicy,
    harness: &str,
    action_type: PreToolActionTypeV1,
    input: &FloorInput<'_>,
) -> Result<String, String> {
    let facts = input.facts;
    let mut floor = if input.benign_prompt
        && matches!(
            policy.default_action.as_str(),
            "review" | "require-reapproval"
        ) {
        "warn".to_owned()
    } else {
        policy.default_action.clone()
    };
    if let Some(action) = compiled.harness_actions.get(harness) {
        floor = join_action(&floor, action)?;
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
    let harness_risks = compiled.harness_risk_actions.get(harness);
    for risk in risk_classes(
        action_type,
        facts.sensitive_target,
        input.reason_code,
        input.prompt_classes,
    ) {
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

pub(super) fn action_rank(action: &str) -> Option<u8> {
    ActionFloor::parse(action).map(|floor| floor as u8)
}

pub(super) fn join_action(left: &str, right: &str) -> Result<String, String> {
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
        "devin-cli" | "cognition-devin" => Some("devin"),
        _ => None,
    }
}

pub(super) fn normalized_harness(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    canonical_harness(&normalized)
        .unwrap_or(normalized.as_str())
        .to_owned()
}
