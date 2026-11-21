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
    /// The command is a proven install that runs no lifecycle scripts.
    pub(super) package_scripts_disabled: bool,
    /// The operator allowed this exact MCP tool in a custom extension, so it
    /// is no longer an unreviewed tool.
    pub(super) operator_allowed_mcp_tool: bool,
}

/// The setting that set a policy floor, so a raised result can say why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FloorCause {
    Default,
    Harness,
    Subprocess,
    Network,
    Unknown,
    ChangedHash,
    UnknownPublisher,
    Artifact,
    Publisher,
    Risk(&'static str),
}

/// An already admitted owner invocation satisfies only duplicate, overridable
/// execution-review floors. Hard actions and independent output risks remain.
pub(super) fn policy_floor_with_cause_and_delivery(
    policy: &EffectiveNativePolicyV3,
    compiled: &CompiledEffectivePolicy,
    harness: &str,
    action_type: PreToolActionTypeV1,
    input: &FloorInput<'_>,
    verified_delivery: bool,
    guard_inspection: bool,
) -> Result<(String, FloorCause), String> {
    let facts = input.facts;
    let mut floor = if input.benign_prompt
        && matches!(
            policy.default_action.as_str(),
            "review" | "require-reapproval"
        ) {
        "warn".to_owned()
    } else {
        delivery_floor(
            &policy.default_action,
            FloorCause::Default,
            verified_delivery,
            guard_inspection,
        )
        .to_owned()
    };
    let mut cause = FloorCause::Default;
    let mut raise = |floor: &mut String, action: &str, by: FloorCause| -> Result<(), String> {
        let action = delivery_floor(action, by, verified_delivery, guard_inspection);
        let joined = join_action(floor, action)?;
        if joined != *floor {
            *floor = joined;
            cause = by;
        }
        Ok(())
    };
    if let Some(action) = compiled.harness_actions.get(harness) {
        raise(&mut floor, action, FloorCause::Harness)?;
    }
    if matches!(
        action_type,
        PreToolActionTypeV1::Command | PreToolActionTypeV1::ProcessService
    ) {
        raise(
            &mut floor,
            &policy.subprocess_action,
            FloorCause::Subprocess,
        )?;
    }
    if matches!(
        action_type,
        PreToolActionTypeV1::Network | PreToolActionTypeV1::Browser
    ) {
        raise(
            &mut floor,
            &policy.new_network_domain_action,
            FloorCause::Network,
        )?;
    }
    if action_type == PreToolActionTypeV1::Unknown {
        // An unknown PostToolUse operation has no safe automatic allow
        // proof, even when the configured default is permissive.
        raise(&mut floor, "review", FloorCause::Unknown)?;
    }
    if facts.changed_hash {
        raise(
            &mut floor,
            &policy.changed_hash_action,
            FloorCause::ChangedHash,
        )?;
    }
    if facts.publisher_relevant && facts.publisher.is_none() {
        raise(
            &mut floor,
            &policy.unknown_publisher_action,
            FloorCause::UnknownPublisher,
        )?;
    }
    if let Some(artifact) = facts.artifact.as_deref() {
        if let Some(action) = policy_map_action(&policy.artifact_actions, artifact)? {
            raise(&mut floor, &action, FloorCause::Artifact)?;
        }
    }
    if let Some(publisher) = facts.publisher.as_deref() {
        if let Some(action) = policy_map_action(&policy.publisher_actions, publisher)? {
            raise(&mut floor, &action, FloorCause::Publisher)?;
        }
    }
    let harness_risks = compiled.harness_risk_actions.get(harness);
    for risk in risk_classes(
        action_type,
        facts.sensitive_target,
        input.reason_code,
        input.prompt_classes,
    ) {
        if risk == "package_script" && input.package_scripts_disabled {
            continue;
        }
        // The operator's own allow for the exact tool is the review that the
        // unreviewed-tool setting asks for. A block setting still blocks.
        let reviewed = |action: &str| {
            !(input.operator_allowed_mcp_tool
                && risk == "mcp_dangerous_tool"
                && matches!(action, "review" | "require-reapproval"))
        };
        if let Some(action) = policy_map_action(&policy.risk_actions, risk)? {
            if reviewed(&action) {
                raise(&mut floor, &action, FloorCause::Risk(risk))?;
            }
        }
        if let Some(harness_map) = harness_risks {
            if let Some(action) = policy_map_action(harness_map, risk)? {
                if reviewed(&action) {
                    raise(&mut floor, &action, FloorCause::Risk(risk))?;
                }
            }
        }
    }
    Ok((floor, cause))
}

fn delivery_floor(
    action: &str,
    cause: FloorCause,
    verified_delivery: bool,
    guard_inspection: bool,
) -> &str {
    // A user-approved call may clear duplicate review floors on that call.
    // Guard's own inspection command is not an approved tool invocation:
    // only generic execution floors may be waived for that narrow proof.
    let owner_admitted = verified_delivery
        && matches!(
            cause,
            FloorCause::Default
                | FloorCause::Harness
                | FloorCause::Subprocess
                | FloorCause::ChangedHash
                | FloorCause::UnknownPublisher
                | FloorCause::Artifact
                | FloorCause::Publisher
                | FloorCause::Risk("execution")
        );
    let inspecting_guard = guard_inspection
        && matches!(
            cause,
            FloorCause::Default | FloorCause::Harness | FloorCause::Subprocess
        );
    if (owner_admitted || inspecting_guard) && matches!(action, "review" | "require-reapproval") {
        "allow"
    } else {
        action
    }
}

/// The configured action for one risk key, global and per-harness settings
/// joined to the stronger. `None` when neither sets it.
pub(crate) fn risk_action(
    snapshot: &super::AdmittedPolicySnapshot,
    harness: &str,
    risk: &str,
) -> Result<Option<String>, String> {
    let harness = normalized_harness(harness);
    let global = policy_map_action(&snapshot.effective_policy.risk_actions, risk)?;
    let scoped = match snapshot.compiled.harness_risk_actions.get(&harness) {
        Some(map) => policy_map_action(map, risk)?,
        None => None,
    };
    match (global, scoped) {
        (Some(left), Some(right)) => join_action(&left, &right).map(Some),
        (left, right) => Ok(left.or(right)),
    }
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

#[cfg(test)]
mod inspection_floor_tests {
    use super::{delivery_floor, FloorCause};

    #[test]
    fn own_inspection_only_lifts_execution_review_floors() {
        for cause in [
            FloorCause::Default,
            FloorCause::Harness,
            FloorCause::Subprocess,
        ] {
            assert_eq!(delivery_floor("review", cause, false, true), "allow");
            assert_eq!(
                delivery_floor("require-reapproval", cause, false, true),
                "allow"
            );
            assert_eq!(delivery_floor("block", cause, false, true), "block");
        }

        for cause in [
            FloorCause::ChangedHash,
            FloorCause::UnknownPublisher,
            FloorCause::Artifact,
            FloorCause::Publisher,
            FloorCause::Risk("execution"),
            FloorCause::Risk("sensitive"),
            FloorCause::Network,
        ] {
            assert_eq!(delivery_floor("review", cause, false, true), "review");
            assert_eq!(
                delivery_floor("require-reapproval", cause, false, true),
                "require-reapproval"
            );
        }
        assert_eq!(
            delivery_floor("review", FloorCause::ChangedHash, true, false),
            "allow"
        );
        assert_eq!(
            delivery_floor("review", FloorCause::Default, false, false),
            "review"
        );
    }
}
