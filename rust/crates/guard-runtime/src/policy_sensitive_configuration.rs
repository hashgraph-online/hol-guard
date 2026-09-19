//! Configuration semantics for the proven sensitive-read runtime producer.
//!
//! This computes policy inputs only. The caller must derive the actual request
//! identity and retain independent intrinsic, source and managed restrictions.

use super::policy_enforcement_policy::{
    canonical_harness_action, canonical_harness_risk_actions, policy_map_action,
    validate_effective_policy,
};
use super::{join_action, ActionFloor};
use guard_policy_snapshot::managed_configuration::ManagedConfiguration;
use guard_policy_snapshot::EffectiveNativePolicyV3;

pub(crate) struct SensitiveReadConfiguration {
    pub(crate) evaluated_action: String,
    pub(crate) observe_action: String,
    configured_override: Option<String>,
    default_action: String,
}

/// Match the actual Python runtime artifact policy and Observe recomposition.
/// A file-read artifact has no publisher, changed-content or subprocess input.
/// Its resolved risk map already contains the authenticated posture defaults.
pub(crate) fn sensitive_read_configuration(
    policy: &EffectiveNativePolicyV3,
    canonical_harness: &str,
    artifact_id: &str,
) -> Result<SensitiveReadConfiguration, String> {
    validate_effective_policy(policy)?;
    if !matches!(
        canonical_harness,
        "codex" | "claude-code" | "cline" | "cursor"
    ) {
        return Err("native_sensitive_read_policy_unsupported".to_owned());
    }
    if policy
        .harness_actions
        .keys()
        .chain(policy.harness_risk_actions.keys())
        .any(|key| key != canonical_harness && super::normalized_harness(key) == canonical_harness)
    {
        return Err("native_sensitive_read_policy_unsupported".to_owned());
    }
    let harness_action = canonical_harness_action(&policy.harness_actions, canonical_harness)?;
    let configured_override =
        policy_map_action(&policy.artifact_actions, artifact_id)?.or(harness_action);
    let configured = configured_override
        .clone()
        .unwrap_or_else(|| policy.default_action.clone());
    let harness_risks =
        canonical_harness_risk_actions(&policy.harness_risk_actions, canonical_harness)?;
    let risk = harness_risks
        .and_then(|actions| actions.get("local_secret_read"))
        .or_else(|| policy.risk_actions.get("local_secret_read"))
        .ok_or_else(|| "native_sensitive_read_policy_unsupported".to_owned())?;
    let evaluated_action = join_action(&configured, risk)?;
    // Python removes policy-only review/terminal gates in Observe. An already
    // executable warning, or a separate explicit override warning, remains.
    let evaluated = ActionFloor::parse(&evaluated_action)
        .ok_or_else(|| "native_policy_action_invalid".to_owned())?;
    let observe_action = if evaluated <= ActionFloor::Warn {
        evaluated_action.clone()
    } else if configured_override.as_deref() == Some("warn") {
        "warn".to_owned()
    } else {
        "allow".to_owned()
    };
    Ok(SensitiveReadConfiguration {
        evaluated_action,
        observe_action,
        configured_override,
        default_action: policy.default_action.clone(),
    })
}

/// Each source resolves its own selector hierarchy before the action join.
/// Observe recomposes the combined evaluated action and explicit override;
/// separately projecting each source would invent a warning lost by Python.
pub(crate) fn sensitive_read_configuration_with_origin(
    policy: &EffectiveNativePolicyV3,
    origin: Option<&ManagedConfiguration>,
    canonical_harness: &str,
    artifact_id: &str,
) -> Result<SensitiveReadConfiguration, String> {
    let mut local = sensitive_read_configuration(policy, canonical_harness, artifact_id)?;
    let Some(origin) = origin else {
        return Ok(local);
    };
    let managed =
        sensitive_read_configuration(origin.effective_policy(), canonical_harness, artifact_id)?;
    let managed_override = managed.configured_override.or_else(|| {
        origin
            .default_action_present()
            .then_some(managed.default_action)
    });
    let local_override = local.configured_override.or_else(|| {
        managed_override
            .as_ref()
            .map(|_| local.default_action.clone())
    });
    local.configured_override = match (local_override, managed_override) {
        (Some(left), Some(right)) => Some(join_action(&left, &right)?),
        (left, right) => left.or(right),
    };
    local.evaluated_action = join_action(&local.evaluated_action, &managed.evaluated_action)?;
    let evaluated = ActionFloor::parse(&local.evaluated_action)
        .ok_or_else(|| "native_policy_action_invalid".to_owned())?;
    local.observe_action = if evaluated <= ActionFloor::Warn {
        local.evaluated_action.clone()
    } else if local.configured_override.as_deref() == Some("warn") {
        "warn".to_owned()
    } else {
        "allow".to_owned()
    };
    Ok(local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_scoped_sensitive_read::derive_sensitive_read_artifact;
    use guard_contracts::GuardHookEnvelopeV2;
    use serde_json::{json, Value};

    fn envelope(case: &Value) -> GuardHookEnvelopeV2 {
        serde_json::from_value(json!({
            "schema":"guard-hook-envelope.v2", "harness":case["harness"],
            "event":"PreToolUse", "raw_payload":case["payload"],
            "policy_generation":1, "policy_snapshot":{}, "source":case["source"]
        }))
        .unwrap()
    }

    #[test]
    fn matches_all_actual_python_evaluation_and_observe_vectors() {
        let values = crate::policy_scoped_enforcement::policy_vector_ordinary::vectors();
        let cases = values["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 133);
        for case in cases {
            let source = envelope(case);
            let artifact = derive_sensitive_read_artifact(&source, &source.harness).unwrap();
            assert_eq!(artifact.artifact_id, case["artifactId"].as_str().unwrap());
            let policy = serde_json::from_value(case["effectivePolicy"].clone()).unwrap();
            let result =
                sensitive_read_configuration(&policy, &source.harness, &artifact.artifact_id)
                    .unwrap();
            assert_eq!(
                result.evaluated_action,
                case["expected"]["evaluatedPolicyAction"].as_str().unwrap(),
                "{} evaluated",
                case["name"]
            );
            if case["mode"] == "observe" {
                assert_eq!(
                    result.observe_action,
                    case["expected"]["finalPolicyAction"].as_str().unwrap(),
                    "{} Observe",
                    case["name"]
                );
            }
        }
    }

    fn sample_source() -> GuardHookEnvelopeV2 {
        serde_json::from_value(json!({
            "schema": "guard-hook-envelope.v2",
            "harness": "claude-code",
            "event": "PreToolUse",
            "raw_payload": {
                "hook_event_name": "PreToolUse",
                "tool_input": {"file_path": ".npmrc"},
                "tool_name": "Read"
            },
            "policy_generation": 1,
            "policy_snapshot": {},
            "source": {
                "cwd": "/synthetic/native-sensitive/home/project",
                "guard_home": "/synthetic/native-sensitive/state",
                "home_dir": "/synthetic/native-sensitive/home"
            }
        }))
        .unwrap()
    }

    fn sample_policy() -> EffectiveNativePolicyV3 {
        serde_json::from_value(json!({
            "artifact_actions": {},
            "changed_hash_action": "require-reapproval",
            "default_action": "allow",
            "harness_actions": {},
            "harness_risk_actions": {},
            "new_network_domain_action": "warn",
            "protection_posture": "protected",
            "publisher_actions": {},
            "receipt_redaction_level": "full",
            "risk_actions": {
                "cloud_advisory": "warn",
                "credential_exfiltration": "require-reapproval",
                "data_flow_exfiltration": "require-reapproval",
                "destructive_shell": "require-reapproval",
                "encoded_execution": "require-reapproval",
                "encoded_exfiltration": "require-reapproval",
                "guard_bypass": "block",
                "local_secret_read": "allow",
                "malicious_skill": "require-reapproval",
                "mcp_dangerous_tool": "require-reapproval",
                "network_egress": "warn",
                "package_script": "warn",
                "persistence": "require-reapproval",
                "prompt_injection": "require-reapproval"
            },
            "sandbox_analysis": "off",
            "security_level": "balanced",
            "subprocess_action": "warn",
            "unknown_publisher_action": "review"
        }))
        .unwrap()
    }

    #[test]
    fn incomplete_or_invalid_sensitive_configuration_cannot_invent_a_default() {
        let source = sample_source();
        let artifact = derive_sensitive_read_artifact(&source, &source.harness).unwrap();
        let mut policy = sample_policy();
        policy.risk_actions.remove("local_secret_read");
        assert!(
            sensitive_read_configuration(&policy, &source.harness, &artifact.artifact_id).is_err()
        );
        policy
            .risk_actions
            .insert("local_secret_read".to_owned(), "permit".to_owned());
        assert!(
            sensitive_read_configuration(&policy, &source.harness, &artifact.artifact_id).is_err()
        );
        policy
            .risk_actions
            .insert("local_secret_read".to_owned(), "allow".to_owned());
        assert!(sensitive_read_configuration(&policy, "unmodeled", &artifact.artifact_id).is_err());
    }
}
