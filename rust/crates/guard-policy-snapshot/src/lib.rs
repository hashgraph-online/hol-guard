#![forbid(unsafe_code)]

//! Authenticated, bounded policy snapshots shared by the Python control plane
//! and the native hook resident.
//!
//! The snapshot is deliberately a complete value rather than a reference to
//! Python configuration. A resident can therefore make a hook decision from
//! its in-memory snapshot and does not need to read configuration on the hot
//! path. The verifier key is handed to the resident through an owner-private
//! file by the launcher; it is never part of a request or snapshot.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[path = "policy_snapshot_canonical.rs"]
mod canonical;
#[path = "policy_snapshot_crypto.rs"]
mod crypto;

pub use canonical::{canonical_json_bytes, snapshot_bytes, snapshot_signing_bytes};
pub use crypto::{
    config_digest, derive_verifier_key, digest_bytes, generation_floor_mac, integrity_mac,
    policy_digest, verifier_key_id,
};

#[cfg(test)]
#[path = "policy_snapshot_tests.rs"]
mod tests;
pub const POLICY_SNAPSHOT_SCHEMA: &str = "hol-guard-native-policy.v3";
pub const POLICY_SNAPSHOT_PUSH_SCHEMA: &str = "guard-policy-snapshot-push.v1";
pub const POLICY_SNAPSHOT_VERSION: u16 = 3;
pub const POLICY_SNAPSHOT_PROTOCOL_VERSION: u16 = 1;
pub const POLICY_SNAPSHOT_MAX_BYTES: usize = 256 * 1024;
pub const POLICY_SNAPSHOT_MAX_STRING_BYTES: usize = 4 * 1024;
pub const POLICY_SNAPSHOT_MAX_MAP_ENTRIES: usize = 256;
pub const POLICY_SNAPSHOT_MAX_HARNESS_ENTRIES: usize = 64;
pub const POLICY_SNAPSHOT_MAX_EXPIRY_MS: u64 = 24 * 60 * 60 * 1000;
pub const POLICY_SNAPSHOT_INTEGRITY_ALGORITHM: &str = "hmac-sha256";
pub const POLICY_SNAPSHOT_INTEGRITY_DOMAIN: &[u8] = b"hol-guard-native-policy-snapshot-v3\0";
pub const POLICY_SNAPSHOT_VERIFIER_DERIVATION_DOMAIN: &[u8] =
    b"hol-guard-native-policy-verifier-v1\0";
pub const POLICY_SNAPSHOT_FLOOR_DOMAIN: &[u8] = b"hol-guard-native-policy-floor-v1\0";
/// Typed resident response used when a trusted floor survived without a
/// usable snapshot.  The publisher must materialize a strictly newer
/// generation; this is not an error that permits replacing the floor.
pub const POLICY_SNAPSHOT_ACK_REQUIRES_NEW_GENERATION: &str =
    "native_policy_snapshot_requires_new_generation";

const VALID_ACTIONS: &[&str] = &[
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];
const VALID_PROTECTION_POSTURES: &[&str] = &["protected", "extra_careful", "watch"];
const VALID_SECURITY_LEVELS: &[&str] = &[
    "relaxed", "gentle", "balanced", "strict", "paranoid", "custom",
];
const VALID_SANDBOX_ANALYSIS: &[&str] = &["off", "suspicious", "strict"];
const VALID_RECEIPT_REDACTION_LEVELS: &[&str] = &["full", "partial", "none"];
const VALID_RISK_ACTION_KEYS: &[&str] = &[
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
    // Native-only classifications used to preserve a strong intrinsic floor
    // even when a future policy snapshot elects to tune a broader action
    // class.
    "execution",
    "supply_chain",
    "policy_bypass",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeContractV3 {
    pub schema: String,
    pub kind: String,
    pub scope_digest: String,
    pub workspace_binding: String,
}

/// Effective policy fields consumed by all supported hook action classes.
/// Maps are bounded and keys remain opaque identifiers; raw request content is
/// never copied into a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectiveNativePolicyV3 {
    pub protection_posture: String,
    pub security_level: String,
    pub default_action: String,
    pub unknown_publisher_action: String,
    pub changed_hash_action: String,
    pub new_network_domain_action: String,
    pub subprocess_action: String,
    pub risk_actions: BTreeMap<String, String>,
    pub harness_risk_actions: BTreeMap<String, BTreeMap<String, String>>,
    pub harness_actions: BTreeMap<String, String>,
    pub publisher_actions: BTreeMap<String, String>,
    pub artifact_actions: BTreeMap<String, String>,
    pub sandbox_analysis: String,
    pub receipt_redaction_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotIntegrityV3 {
    pub algorithm: String,
    pub key_id: String,
    pub mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshotV3 {
    pub schema: String,
    pub version: u16,
    pub generation: u64,
    pub policy_digest: String,
    pub config_digest: String,
    pub rule_digest: String,
    pub runtime_identity: String,
    pub protocol_version: u16,
    pub mode: String,
    pub scope_contract: ScopeContractV3,
    pub effective_policy: EffectiveNativePolicyV3,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub integrity: SnapshotIntegrityV3,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshotPushV1 {
    pub schema: String,
    pub snapshot: PolicySnapshotV3,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshotAckV1 {
    pub status: String,
    pub generation: u64,
    pub policy_digest: String,
    pub idempotent: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SnapshotError {
    #[error("snapshot_schema_mismatch")]
    Schema,
    #[error("snapshot_version_mismatch")]
    Version,
    #[error("snapshot_generation_invalid")]
    Generation,
    #[error("snapshot_generation_downgrade")]
    Downgrade,
    #[error("snapshot_generation_reused")]
    GenerationReused,
    #[error("snapshot_digest_invalid")]
    Digest,
    #[error("snapshot_digest_mismatch")]
    DigestMismatch,
    #[error("snapshot_runtime_identity_mismatch")]
    RuntimeIdentity,
    #[error("snapshot_rule_digest_mismatch")]
    RuleDigest,
    #[error("snapshot_protocol_mismatch")]
    Protocol,
    #[error("snapshot_mode_invalid")]
    Mode,
    #[error("snapshot_scope_invalid")]
    Scope,
    #[error("snapshot_policy_invalid")]
    Policy,
    #[error("snapshot_expired")]
    Expired,
    #[error("snapshot_expiry_invalid")]
    Expiry,
    #[error("snapshot_integrity_invalid")]
    Integrity,
    #[error("snapshot_integrity_mismatch")]
    IntegrityMismatch,
    #[error("snapshot_too_large")]
    TooLarge,
    #[error("snapshot_serialization_failed")]
    Serialization,
}

/// The legacy v1 shape remains available for explicit differential tests. It
/// is not accepted by the resident v3 hook path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySnapshotV1 {
    pub schema: String,
    pub generation: u64,
    pub policy_digest: String,
    pub config_digest: String,
    pub rule_digest: String,
    pub mode: String,
}

pub fn validate(snapshot: &PolicySnapshotV1, minimum_generation: u64) -> Result<(), SnapshotError> {
    if snapshot.schema != "hol-guard-native-policy.v1" {
        return Err(SnapshotError::Schema);
    }
    if snapshot.generation < minimum_generation {
        return Err(SnapshotError::Downgrade);
    }
    for digest in [
        &snapshot.policy_digest,
        &snapshot.config_digest,
        &snapshot.rule_digest,
    ] {
        if !valid_hex(digest, 64) {
            return Err(SnapshotError::Digest);
        }
    }
    Ok(())
}

pub fn validate_v3(
    snapshot: &PolicySnapshotV3,
    minimum_generation: u64,
    expected_runtime_identity: &str,
    expected_rule_digest: &str,
    verifier_key: &[u8],
    now_ms: u64,
) -> Result<(), SnapshotError> {
    if snapshot.schema != POLICY_SNAPSHOT_SCHEMA {
        return Err(SnapshotError::Schema);
    }
    if snapshot.version != POLICY_SNAPSHOT_VERSION {
        return Err(SnapshotError::Version);
    }
    if snapshot.generation == 0 {
        return Err(SnapshotError::Generation);
    }
    if snapshot.generation < minimum_generation {
        return Err(SnapshotError::Downgrade);
    }
    if !valid_hex(&snapshot.policy_digest, 64)
        || !valid_hex(&snapshot.config_digest, 64)
        || !valid_hex(&snapshot.rule_digest, 64)
        || !valid_hex(&snapshot.runtime_identity, 64)
        || !valid_hex(expected_runtime_identity, 64)
        || !valid_hex(expected_rule_digest, 64)
    {
        return Err(SnapshotError::Digest);
    }
    if snapshot.runtime_identity != expected_runtime_identity {
        return Err(SnapshotError::RuntimeIdentity);
    }
    if snapshot.rule_digest != expected_rule_digest {
        return Err(SnapshotError::RuleDigest);
    }
    if snapshot.protocol_version != POLICY_SNAPSHOT_PROTOCOL_VERSION {
        return Err(SnapshotError::Protocol);
    }
    if !matches!(snapshot.mode.as_str(), "enforce" | "observe") {
        return Err(SnapshotError::Mode);
    }
    validate_scope(&snapshot.scope_contract)?;
    validate_effective_policy(&snapshot.effective_policy)?;
    if snapshot.expires_at_ms <= snapshot.issued_at_ms
        || snapshot.expires_at_ms - snapshot.issued_at_ms > POLICY_SNAPSHOT_MAX_EXPIRY_MS
    {
        return Err(SnapshotError::Expiry);
    }
    if snapshot.expires_at_ms <= now_ms {
        return Err(SnapshotError::Expired);
    }
    if snapshot.integrity.algorithm != POLICY_SNAPSHOT_INTEGRITY_ALGORITHM
        || snapshot.integrity.key_id != verifier_key_id(verifier_key)
        || !valid_hex(&snapshot.integrity.mac, 64)
    {
        return Err(SnapshotError::Integrity);
    }
    if snapshot.config_digest != config_digest(&snapshot.effective_policy)?
        || snapshot.policy_digest != policy_digest(snapshot)?
    {
        return Err(SnapshotError::DigestMismatch);
    }
    let expected_mac = integrity_mac(snapshot, verifier_key)?;
    if !crypto::constant_time_eq(expected_mac.as_bytes(), snapshot.integrity.mac.as_bytes()) {
        return Err(SnapshotError::IntegrityMismatch);
    }
    Ok(())
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_bounded_string(value: &str, allow_empty: bool) -> bool {
    (allow_empty || !value.trim().is_empty()) && value.len() <= POLICY_SNAPSHOT_MAX_STRING_BYTES
}

fn validate_scope(scope: &ScopeContractV3) -> Result<(), SnapshotError> {
    if scope.schema != "guard-native-scope.v1"
        || scope.kind != "guard-home"
        || scope.workspace_binding != "request-source"
        || !valid_bounded_string(&scope.schema, false)
        || !valid_bounded_string(&scope.kind, false)
        || !valid_bounded_string(&scope.workspace_binding, false)
        || !valid_hex(&scope.scope_digest, 64)
    {
        return Err(SnapshotError::Scope);
    }
    Ok(())
}

fn validate_action(value: &str) -> bool {
    VALID_ACTIONS.contains(&value)
}

fn validate_action_map(map: &BTreeMap<String, String>, maximum: usize) -> bool {
    map.len() <= maximum
        && map
            .iter()
            .all(|(key, value)| valid_bounded_string(key, false) && validate_action(value))
}

fn valid_selector_key(value: &str) -> bool {
    valid_bounded_string(value, false)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn normalized_harness_selector(value: &str) -> Option<String> {
    if !valid_selector_key(value) {
        return None;
    }
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    let canonical = match normalized.as_str() {
        "claude" => "claude-code",
        "cline-cli" | "cline-vscode" => "cline",
        "kimi-code" | "kimi-cli" => "kimi",
        "grok-build" | "grok-build-cli" | "xai-grok" => "grok",
        "pi-agent" | "pi-coding-agent" => "pi",
        "oh-my-pi" => "omp",
        "zai" | "z-code" | "zai-zcode" => "zcode",
        _ => normalized.as_str(),
    };
    Some(canonical.to_owned())
}

fn validate_harness_action_map(map: &BTreeMap<String, String>, maximum: usize) -> bool {
    if !validate_action_map(map, maximum) {
        return false;
    }
    let mut canonical: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in map {
        let Some(key) = normalized_harness_selector(key) else {
            return false;
        };
        if let Some(previous) = canonical.insert(key, value.clone()) {
            if previous != *value {
                return false;
            }
        }
    }
    true
}

fn validate_risk_action_map(map: &BTreeMap<String, String>, maximum: usize) -> bool {
    validate_action_map(map, maximum)
        && map
            .keys()
            .all(|key| VALID_RISK_ACTION_KEYS.contains(&key.as_str()))
}

fn validate_effective_policy(policy: &EffectiveNativePolicyV3) -> Result<(), SnapshotError> {
    for action in [
        &policy.default_action,
        &policy.unknown_publisher_action,
        &policy.changed_hash_action,
        &policy.new_network_domain_action,
        &policy.subprocess_action,
    ] {
        if !validate_action(action) {
            return Err(SnapshotError::Policy);
        }
    }
    if !valid_bounded_string(&policy.protection_posture, false)
        || !VALID_PROTECTION_POSTURES.contains(&policy.protection_posture.as_str())
        || !valid_bounded_string(&policy.security_level, false)
        || !VALID_SECURITY_LEVELS.contains(&policy.security_level.as_str())
        || !valid_bounded_string(&policy.sandbox_analysis, false)
        || !VALID_SANDBOX_ANALYSIS.contains(&policy.sandbox_analysis.as_str())
        || !valid_bounded_string(&policy.receipt_redaction_level, false)
        || !VALID_RECEIPT_REDACTION_LEVELS.contains(&policy.receipt_redaction_level.as_str())
        || !validate_risk_action_map(&policy.risk_actions, POLICY_SNAPSHOT_MAX_MAP_ENTRIES)
        || !validate_harness_action_map(&policy.harness_actions, POLICY_SNAPSHOT_MAX_MAP_ENTRIES)
        || !validate_action_map(&policy.publisher_actions, POLICY_SNAPSHOT_MAX_MAP_ENTRIES)
        || !validate_action_map(&policy.artifact_actions, POLICY_SNAPSHOT_MAX_MAP_ENTRIES)
        || policy.harness_risk_actions.len() > POLICY_SNAPSHOT_MAX_HARNESS_ENTRIES
        || !policy.harness_risk_actions.iter().all(|(key, value)| {
            valid_selector_key(key)
                && validate_risk_action_map(value, POLICY_SNAPSHOT_MAX_MAP_ENTRIES)
        })
    {
        return Err(SnapshotError::Policy);
    }
    let mut canonical_harness_risks: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (key, value) in &policy.harness_risk_actions {
        let Some(key) = normalized_harness_selector(key) else {
            return Err(SnapshotError::Policy);
        };
        if let Some(previous) = canonical_harness_risks.insert(key, value.clone()) {
            if previous != *value {
                return Err(SnapshotError::Policy);
            }
        }
    }
    Ok(())
}
