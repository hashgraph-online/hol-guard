use super::{normalized_harness, MAX_SELECTOR_VALUE_BYTES, VALID_ACTIONS, VALID_RISK_KEYS};
use guard_policy_snapshot::EffectiveNativePolicyV3;
use std::collections::BTreeMap;

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

pub(super) fn canonical_harness_action(
    map: &std::collections::BTreeMap<String, String>,
    harness: &str,
) -> Result<Option<String>, String> {
    let mut selected: Option<(&str, &str)> = None;
    for (configured, action) in map {
        if !VALID_ACTIONS.contains(&action.as_str()) {
            return Err("native_policy_action_invalid".to_owned());
        }
        let normalized = normalized_harness(configured);
        if normalized != harness {
            continue;
        }
        if let Some((_, previous_action)) = selected {
            if previous_action != action {
                return Err("native_policy_harness_selector_conflict".to_owned());
            }
        } else {
            selected = Some((configured.as_str(), action.as_str()));
        }
    }
    Ok(selected.map(|(_, action)| action.to_owned()))
}

pub(super) fn canonical_harness_risk_actions<'a>(
    map: &'a BTreeMap<String, BTreeMap<String, String>>,
    harness: &str,
) -> Result<Option<&'a BTreeMap<String, String>>, String> {
    let mut selected: Option<&'a BTreeMap<String, String>> = None;
    for (configured, actions) in map {
        if normalized_harness(configured) != harness {
            continue;
        }
        if let Some(previous) = selected {
            if previous != actions {
                return Err("native_policy_harness_selector_conflict".to_owned());
            }
        } else {
            selected = Some(actions);
        }
    }
    Ok(selected)
}
