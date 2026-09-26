use super::{normalized_harness, PreToolResultV1, MAX_SELECTOR_VALUE_BYTES, VALID_ACTIONS, VALID_RISK_KEYS};
use guard_policy_snapshot::EffectiveNativePolicyV3;
use std::collections::BTreeMap;

/// The native action lattice is intentionally typed at the enforcement
/// boundary.  String values remain the wire representation for compatibility
/// with existing hook contracts, but no decision is made by comparing raw
/// strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
enum ActionFloor {
    Allow,
    Warn,
    Review,
    RequireReapproval,
    SandboxRequired,
    Block,
}

impl ActionFloor {
    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "allow" => Self::Allow,
            "warn" => Self::Warn,
            "review" => Self::Review,
            "require-reapproval" => Self::RequireReapproval,
            "sandbox-required" => Self::SandboxRequired,
            "block" => Self::Block,
            _ => return None,
        })
    }

    fn is_non_overridable(self) -> bool {
        matches!(self, Self::SandboxRequired | Self::Block)
    }

    fn decision(self) -> &'static str {
        if matches!(self, Self::Allow | Self::Warn) {
            "allow"
        } else {
            "deny"
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActionFloorMatrix {
    policy: ActionFloor,
    minimum: ActionFloor,
}

impl ActionFloorMatrix {
    fn from_result(result: &PreToolResultV1) -> Result<Self, String> {
        Ok(Self {
            policy: ActionFloor::parse(&result.policy_action)
                .ok_or_else(|| "native_policy_action_invalid".to_owned())?,
            minimum: ActionFloor::parse(&result.minimum_action)
                .ok_or_else(|| "native_policy_action_invalid".to_owned())?,
        })
    }

    fn validate(self, result: &PreToolResultV1) -> Result<(), String> {
        if self.policy < self.minimum
            || (self.policy.is_non_overridable() && self.policy != self.minimum)
            || result.decision != self.minimum.decision()
            || result.explicitly_benign != (self.minimum == ActionFloor::Allow)
        {
            return Err("native_policy_decision_inconsistent".to_owned());
        }
        Ok(())
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

/// Validate the typed relationship between the effective action fields.  The
/// policy action is not a second, weaker authority: it must describe the same
/// or stronger floor, and a terminal policy block must be reflected by the
/// minimum floor before any approval path can inspect the result.
pub(crate) fn validate_pre_tool_result_matrix(result: &PreToolResultV1) -> Result<(), String> {
    ActionFloorMatrix::from_result(result)?.validate(result)
}

/// Generation-owned indexes. The signed policy is retained unchanged; only
/// derived selector keys are canonicalized here, before snapshot publication.
#[derive(Debug)]
pub(crate) struct CompiledEffectivePolicy {
    pub(super) harness_actions: BTreeMap<String, String>,
    pub(super) harness_risk_actions: BTreeMap<String, BTreeMap<String, String>>,
}

impl CompiledEffectivePolicy {
    pub(crate) fn new(policy: &EffectiveNativePolicyV3) -> Result<Self, String> {
        validate_effective_policy(policy)?;
        Ok(Self {
            harness_actions: canonical_map(&policy.harness_actions)?,
            harness_risk_actions: canonical_map(&policy.harness_risk_actions)?,
        })
    }
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
