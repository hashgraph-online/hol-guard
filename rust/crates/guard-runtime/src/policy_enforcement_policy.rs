use super::{
    action_rank, normalized_harness, MAX_SELECTOR_VALUE_BYTES, VALID_ACTIONS, VALID_RISK_KEYS,
};
use guard_policy_snapshot::{EffectiveNativePolicyV3, ExactCommandPolicyV1};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

type ExactCommandActions = BTreeMap<String, BTreeMap<[u8; 32], Vec<CompiledExactCommandAction>>>;

#[derive(Debug)]
struct CompiledExactCommandAction {
    action: &'static str,
    expires_at_nanos: i128,
}

/// Generation-owned indexes. The signed policy is retained unchanged; only
/// derived selector keys are canonicalized here, before snapshot publication.
#[derive(Debug)]
pub(crate) struct CompiledEffectivePolicy {
    pub(super) harness_actions: BTreeMap<String, String>,
    pub(super) harness_risk_actions: BTreeMap<String, BTreeMap<String, String>>,
    exact_command_actions: ExactCommandActions,
}

impl CompiledEffectivePolicy {
    pub(crate) fn new(policy: &EffectiveNativePolicyV3) -> Result<Self, String> {
        validate_effective_policy(policy)?;
        Ok(Self {
            harness_actions: canonical_map(&policy.harness_actions)?,
            harness_risk_actions: canonical_map(&policy.harness_risk_actions)?,
            exact_command_actions: compile_exact_command_actions(policy)?,
        })
    }

    pub(super) fn exact_command_action(
        &self,
        payload: &Value,
        harness: &str,
    ) -> Result<Option<&'static str>, String> {
        let Some(actions) = self.exact_command_actions.get(harness) else {
            return Ok(None);
        };
        let context = guard_command::pretool::generic::extract_untrusted_command_context(payload)?;
        let Some(command) = context.command else {
            return Ok(None);
        };
        let digest: [u8; 32] = Sha256::digest(command.as_bytes()).into();
        let Some(matches) = actions.get(&digest) else {
            return Ok(None);
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i128::try_from(duration.as_nanos()).ok())
            .ok_or_else(|| "native_policy_clock_unavailable".to_owned())?;
        Ok(matches
            .iter()
            .filter(|rule| now < rule.expires_at_nanos)
            .max_by_key(|rule| action_rank(rule.action))
            .map(|rule| rule.action))
    }
}

fn compile_exact_command_actions(
    policy: &EffectiveNativePolicyV3,
) -> Result<ExactCommandActions, String> {
    if policy.exact_command_actions.len() > guard_policy_snapshot::POLICY_SNAPSHOT_MAX_MAP_ENTRIES
        || (policy.exact_command_actions.is_empty() != policy.cloud_workspace_id.is_none())
    {
        return Err("native_policy_exact_command_invalid".into());
    }
    let mut compiled: ExactCommandActions = BTreeMap::new();
    for rule in &policy.exact_command_actions {
        validate_exact_command_rule(rule, policy.cloud_workspace_id.as_deref())?;
        let mut digest = [0_u8; 32];
        hex::decode_to_slice(&rule.command_sha256, &mut digest)
            .map_err(|_| "native_policy_exact_command_invalid".to_owned())?;
        let action = match rule.action.as_str() {
            "allow" => "allow",
            "block" => "block",
            "review" => "review",
            "require-reapproval" => "require-reapproval",
            _ => return Err("native_policy_exact_command_invalid".into()),
        };
        let expires_at_nanos = guard_contracts::canonical_policy_timestamp_nanos(&rule.expires_at)
            .ok_or_else(|| "native_policy_exact_command_invalid".to_owned())?;
        compiled
            .entry(normalized_harness(&rule.harness))
            .or_default()
            .entry(digest)
            .or_default()
            .push(CompiledExactCommandAction {
                action,
                expires_at_nanos,
            });
    }
    Ok(compiled)
}

fn validate_exact_command_rule(
    rule: &ExactCommandPolicyV1,
    cloud_workspace_id: Option<&str>,
) -> Result<(), String> {
    if !valid_selector_key(&rule.harness, true)
        || !valid_selector_key(&rule.cloud_workspace_id, false)
        || Some(rule.cloud_workspace_id.as_str()) != cloud_workspace_id
        || rule.command_sha256.len() != 64
        || !rule
            .command_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("native_policy_exact_command_invalid".into());
    }
    Ok(())
}

fn canonical_map<T: Clone + PartialEq>(
    map: &BTreeMap<String, T>,
) -> Result<BTreeMap<String, T>, String> {
    let mut canonical = BTreeMap::new();
    for (configured, action) in map {
        let normalized = normalized_harness(configured);
        if let Some(previous) = canonical.get(&normalized) {
            if previous != action {
                return Err("native_policy_harness_selector_conflict".to_owned());
            }
        } else {
            canonical.insert(normalized, action.clone());
        }
    }
    Ok(canonical)
}

pub(super) fn policy_map_action(
    map: &std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<Option<String>, String> {
    let Some(value) = map.get(key) else {
        return Ok(None);
    };
    if !VALID_ACTIONS.contains(&value.as_str()) {
        return Err("native_policy_action_invalid".to_owned());
    }
    Ok(Some(value.clone()))
}

pub(super) fn valid_selector_key(value: &str, harness: bool) -> bool {
    if value.trim().is_empty() || value.len() > MAX_SELECTOR_VALUE_BYTES {
        return false;
    }
    if harness {
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    } else {
        true
    }
}

pub(super) fn validate_action_map(
    map: &BTreeMap<String, String>,
    risk_keys: bool,
    harness_keys: bool,
) -> Result<(), String> {
    for (key, action) in map {
        if !valid_selector_key(key, harness_keys) || !VALID_ACTIONS.contains(&action.as_str()) {
            return Err("native_policy_invalid".to_owned());
        }
        if risk_keys && !VALID_RISK_KEYS.contains(&key.as_str()) {
            return Err("native_policy_unknown_risk_selector".to_owned());
        }
    }
    Ok(())
}

pub(super) fn validate_effective_policy(policy: &EffectiveNativePolicyV3) -> Result<(), String> {
    for action in [
        &policy.default_action,
        &policy.unknown_publisher_action,
        &policy.changed_hash_action,
        &policy.new_network_domain_action,
        &policy.subprocess_action,
    ] {
        if !VALID_ACTIONS.contains(&action.as_str()) {
            return Err("native_policy_action_invalid".to_owned());
        }
    }
    if !matches!(
        policy.protection_posture.as_str(),
        "protected" | "extra_careful" | "watch"
    ) || !matches!(
        policy.security_level.as_str(),
        "relaxed" | "gentle" | "balanced" | "strict" | "paranoid" | "custom"
    ) || !matches!(
        policy.sandbox_analysis.as_str(),
        "off" | "suspicious" | "strict"
    ) || !matches!(
        policy.receipt_redaction_level.as_str(),
        "full" | "partial" | "none"
    ) {
        return Err("native_policy_invalid".to_owned());
    }
    validate_action_map(&policy.risk_actions, true, false)?;
    validate_action_map(&policy.harness_actions, false, true)?;
    validate_action_map(&policy.publisher_actions, false, false)?;
    validate_action_map(&policy.artifact_actions, false, false)?;
    for (harness, actions) in &policy.harness_risk_actions {
        if !valid_selector_key(harness, true) {
            return Err("native_policy_invalid".to_owned());
        }
        validate_action_map(actions, true, false)?;
    }
    Ok(())
}
