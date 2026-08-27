#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const POLICY_SNAPSHOT_SCHEMA: &str = "hol-guard-native-policy.v2";
pub const MAX_EXTENSION_CONTROLS: usize = 1_024;
pub const MAX_MANAGED_RESTRICTIONS: usize = 256;
pub const MAX_ID_BYTES: usize = 192;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtensionControlV2 {
    pub target_kind: String,
    pub target_id: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySnapshotV2 {
    pub schema: String,
    pub generation: u64,
    pub scope_digest: String,
    pub policy_digest: String,
    pub config_digest: String,
    pub rule_digest: String,
    pub mode: String,
    pub security_level: String,
    #[serde(default)]
    pub global_lockdown: bool,
    #[serde(default)]
    pub managed_restrictions: Vec<String>,
    #[serde(default)]
    pub extension_controls: Vec<ExtensionControlV2>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SnapshotError {
    #[error("snapshot_schema_mismatch")]
    Schema,
    #[error("snapshot_generation_downgrade")]
    Downgrade,
    #[error("snapshot_digest_invalid")]
    Digest,
    #[error("snapshot_rule_digest_mismatch")]
    RuleDigest,
    #[error("snapshot_mode_invalid")]
    Mode,
    #[error("snapshot_security_level_invalid")]
    SecurityLevel,
    #[error("snapshot_bounds_exceeded")]
    Bounds,
    #[error("snapshot_control_invalid")]
    Control,
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
        })
}

pub fn validate(
    snapshot: &PolicySnapshotV2,
    minimum_generation: u64,
    expected_rule_digest: &str,
) -> Result<(), SnapshotError> {
    if snapshot.schema != POLICY_SNAPSHOT_SCHEMA {
        return Err(SnapshotError::Schema);
    }
    if snapshot.generation < minimum_generation {
        return Err(SnapshotError::Downgrade);
    }
    for digest in [
        &snapshot.scope_digest,
        &snapshot.policy_digest,
        &snapshot.config_digest,
        &snapshot.rule_digest,
    ] {
        if !valid_digest(digest) {
            return Err(SnapshotError::Digest);
        }
    }
    if snapshot.rule_digest != expected_rule_digest {
        return Err(SnapshotError::RuleDigest);
    }
    if !matches!(snapshot.mode.as_str(), "enforce" | "observe") {
        return Err(SnapshotError::Mode);
    }
    if !matches!(
        snapshot.security_level.as_str(),
        "relaxed" | "gentle" | "balanced" | "strict" | "paranoid" | "custom"
    ) {
        return Err(SnapshotError::SecurityLevel);
    }
    if snapshot.extension_controls.len() > MAX_EXTENSION_CONTROLS
        || snapshot.managed_restrictions.len() > MAX_MANAGED_RESTRICTIONS
    {
        return Err(SnapshotError::Bounds);
    }
    if snapshot
        .managed_restrictions
        .iter()
        .any(|item| !valid_id(item))
    {
        return Err(SnapshotError::Bounds);
    }
    for control in &snapshot.extension_controls {
        if !matches!(control.target_kind.as_str(), "extension" | "permission")
            || !valid_id(&control.target_id)
            || !matches!(control.state.as_str(), "recommended" | "allow" | "block")
        {
            return Err(SnapshotError::Control);
        }
    }
    Ok(())
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn canonical_digest(snapshot: &PolicySnapshotV2) -> Result<String, SnapshotError> {
    let mut canonical = snapshot.clone();
    canonical.managed_restrictions.sort();
    canonical.managed_restrictions.dedup();
    canonical.extension_controls.sort_by(|left, right| {
        (&left.target_kind, &left.target_id, &left.state).cmp(&(
            &right.target_kind,
            &right.target_id,
            &right.state,
        ))
    });
    canonical.extension_controls.dedup();
    let encoded = serde_json::to_vec(&canonical).map_err(|_| SnapshotError::Control)?;
    Ok(digest_bytes(&encoded))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(generation: u64) -> PolicySnapshotV2 {
        let digest = "a".repeat(64);
        PolicySnapshotV2 {
            schema: POLICY_SNAPSHOT_SCHEMA.into(),
            generation,
            scope_digest: digest.clone(),
            policy_digest: digest.clone(),
            config_digest: digest.clone(),
            rule_digest: digest,
            mode: "enforce".into(),
            security_level: "balanced".into(),
            global_lockdown: false,
            managed_restrictions: Vec::new(),
            extension_controls: Vec::new(),
        }
    }

    #[test]
    fn rejects_generation_downgrade() {
        assert_eq!(
            validate(&snapshot(1), 2, &"a".repeat(64)),
            Err(SnapshotError::Downgrade)
        );
    }

    #[test]
    fn rejects_wrong_rule_digest() {
        assert_eq!(
            validate(&snapshot(2), 2, &"b".repeat(64)),
            Err(SnapshotError::RuleDigest)
        );
    }

    #[test]
    fn canonical_digest_is_order_independent_for_set_like_fields() {
        let mut first = snapshot(3);
        first.managed_restrictions = vec!["network".into(), "packages".into()];
        first.extension_controls = vec![
            ExtensionControlV2 {
                target_kind: "extension".into(),
                target_id: "git".into(),
                state: "block".into(),
            },
            ExtensionControlV2 {
                target_kind: "permission".into(),
                target_id: "git.read".into(),
                state: "allow".into(),
            },
        ];
        let mut second = first.clone();
        second.managed_restrictions.reverse();
        second.extension_controls.reverse();
        assert_eq!(canonical_digest(&first), canonical_digest(&second));
    }
}
