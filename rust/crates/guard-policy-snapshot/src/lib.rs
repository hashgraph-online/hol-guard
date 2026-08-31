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
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

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

pub fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn derive_verifier_key(policy_integrity_key: &[u8]) -> [u8; 32] {
    hmac_sha256(
        policy_integrity_key,
        POLICY_SNAPSHOT_VERIFIER_DERIVATION_DOMAIN,
        &[],
    )
}

pub fn verifier_key_id(verifier_key: &[u8]) -> String {
    digest_bytes(verifier_key)
}

/// Authenticate the monotonic generation floor kept by the resident. The
/// floor prevents a damaged snapshot from resetting the resident to an older
/// generation after restart.
pub fn generation_floor_mac(generation: u64, policy_digest: &str, verifier_key: &[u8]) -> String {
    let mut message = generation.to_be_bytes().to_vec();
    message.push(0);
    message.extend_from_slice(policy_digest.as_bytes());
    hex::encode(hmac_sha256(
        verifier_key,
        POLICY_SNAPSHOT_FLOOR_DOMAIN,
        &message,
    ))
}

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, SnapshotError> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output).map_err(|_| SnapshotError::Serialization)?;
    Ok(output)
}

pub fn snapshot_bytes(snapshot: &PolicySnapshotV3) -> Result<Vec<u8>, SnapshotError> {
    let value = serde_json::to_value(snapshot).map_err(|_| SnapshotError::Serialization)?;
    let bytes = canonical_json_bytes(&value)?;
    if bytes.len() > POLICY_SNAPSHOT_MAX_BYTES {
        return Err(SnapshotError::TooLarge);
    }
    Ok(bytes)
}

pub fn snapshot_signing_bytes(snapshot: &PolicySnapshotV3) -> Result<Vec<u8>, SnapshotError> {
    let mut value = serde_json::to_value(snapshot).map_err(|_| SnapshotError::Serialization)?;
    let object = value.as_object_mut().ok_or(SnapshotError::Serialization)?;
    object.remove("integrity");
    canonical_json_bytes(&value)
}

pub fn config_digest(effective_policy: &EffectiveNativePolicyV3) -> Result<String, SnapshotError> {
    let value = serde_json::to_value(effective_policy).map_err(|_| SnapshotError::Serialization)?;
    Ok(digest_bytes(&canonical_json_bytes(&value)?))
}

pub fn policy_digest(snapshot: &PolicySnapshotV3) -> Result<String, SnapshotError> {
    let value = serde_json::json!({
        "config_digest": snapshot.config_digest,
        "effective_policy_digest": config_digest(&snapshot.effective_policy)?,
        "mode": snapshot.mode,
        "protocol_version": snapshot.protocol_version,
        "rule_digest": snapshot.rule_digest,
        "runtime_identity": snapshot.runtime_identity,
        "scope_digest": snapshot.scope_contract.scope_digest,
        "version": snapshot.version,
    });
    Ok(digest_bytes(&canonical_json_bytes(&value)?))
}

pub fn integrity_mac(
    snapshot: &PolicySnapshotV3,
    verifier_key: &[u8],
) -> Result<String, SnapshotError> {
    Ok(hex::encode(hmac_sha256(
        verifier_key,
        POLICY_SNAPSHOT_INTEGRITY_DOMAIN,
        &snapshot_signing_bytes(snapshot)?,
    )))
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
    if !constant_time_eq(expected_mac.as_bytes(), snapshot.integrity.mac.as_bytes()) {
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

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), std::fmt::Error> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => {
            let encoded = serde_json::to_string(value).map_err(|_| std::fmt::Error)?;
            output.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical_json(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                let encoded = serde_json::to_string(key).map_err(|_| std::fmt::Error)?;
                output.extend_from_slice(encoded.as_bytes());
                output.push(b':');
                write_canonical_json(values.get(*key).ok_or(std::fmt::Error)?, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn hmac_sha256(key: &[u8], label: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    let mut key_block = [0u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK_BYTES];
    let mut outer_pad = [0x5cu8; BLOCK_BYTES];
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(label);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> EffectiveNativePolicyV3 {
        EffectiveNativePolicyV3 {
            protection_posture: "protected".into(),
            security_level: "balanced".into(),
            default_action: "warn".into(),
            unknown_publisher_action: "review".into(),
            changed_hash_action: "require-reapproval".into(),
            new_network_domain_action: "warn".into(),
            subprocess_action: "warn".into(),
            risk_actions: BTreeMap::new(),
            harness_risk_actions: BTreeMap::new(),
            harness_actions: BTreeMap::new(),
            publisher_actions: BTreeMap::new(),
            artifact_actions: BTreeMap::new(),
            sandbox_analysis: "off".into(),
            receipt_redaction_level: "full".into(),
        }
    }

    fn snapshot(generation: u64, key: &[u8]) -> PolicySnapshotV3 {
        let effective_policy = policy();
        let mut result = PolicySnapshotV3 {
            schema: POLICY_SNAPSHOT_SCHEMA.into(),
            version: 3,
            generation,
            policy_digest: String::new(),
            config_digest: config_digest(&effective_policy).unwrap(),
            rule_digest: "b".repeat(64),
            runtime_identity: "a".repeat(64),
            protocol_version: 1,
            mode: "enforce".into(),
            scope_contract: ScopeContractV3 {
                schema: "guard-native-scope.v1".into(),
                kind: "guard-home".into(),
                scope_digest: "c".repeat(64),
                workspace_binding: "request-source".into(),
            },
            effective_policy,
            issued_at_ms: 100,
            expires_at_ms: 1_000,
            integrity: SnapshotIntegrityV3 {
                algorithm: POLICY_SNAPSHOT_INTEGRITY_ALGORITHM.into(),
                key_id: verifier_key_id(key),
                mac: String::new(),
            },
        };
        result.policy_digest = policy_digest(&result).unwrap();
        result.integrity.mac = integrity_mac(&result, key).unwrap();
        result
    }

    #[test]
    fn validates_authenticated_v3_snapshot() {
        let key = [7u8; 32];
        let snapshot = snapshot(1, &key);
        assert!(validate_v3(&snapshot, 1, &"a".repeat(64), &"b".repeat(64), &key, 200).is_ok());
    }

    #[test]
    fn rejects_mutated_effective_policy_and_mac() {
        let key = [7u8; 32];
        let mut snapshot = snapshot(1, &key);
        snapshot.effective_policy.default_action = "block".into();
        assert_eq!(
            validate_v3(&snapshot, 1, &"a".repeat(64), &"b".repeat(64), &key, 200),
            Err(SnapshotError::DigestMismatch)
        );
    }

    #[test]
    fn rejects_expired_and_replayed_generation() {
        let key = [7u8; 32];
        let snapshot = snapshot(1, &key);
        assert_eq!(
            validate_v3(&snapshot, 1, &"a".repeat(64), &"b".repeat(64), &key, 1_000),
            Err(SnapshotError::Expired)
        );
        assert_eq!(
            validate_v3(&snapshot, 2, &"a".repeat(64), &"b".repeat(64), &key, 200),
            Err(SnapshotError::Downgrade)
        );
    }

    #[test]
    fn rejects_runtime_rule_and_protocol_mismatch() {
        let key = [7u8; 32];
        let snapshot = snapshot(1, &key);
        assert_eq!(
            validate_v3(&snapshot, 1, &"c".repeat(64), &"b".repeat(64), &key, 200),
            Err(SnapshotError::RuntimeIdentity)
        );
        assert_eq!(
            validate_v3(&snapshot, 1, &"a".repeat(64), &"c".repeat(64), &key, 200),
            Err(SnapshotError::RuleDigest)
        );
        let mut incompatible = snapshot;
        incompatible.protocol_version = 2;
        assert_eq!(
            validate_v3(
                &incompatible,
                1,
                &"a".repeat(64),
                &"b".repeat(64),
                &key,
                200,
            ),
            Err(SnapshotError::Protocol)
        );
    }

    #[test]
    fn rejects_unknown_risk_selector_and_conflicting_harness_aliases() {
        let key = [7u8; 32];
        let mut unknown = snapshot(1, &key);
        unknown
            .effective_policy
            .risk_actions
            .insert("future-risk".into(), "allow".into());
        assert_eq!(
            validate_v3(&unknown, 1, &"a".repeat(64), &"b".repeat(64), &key, 200),
            Err(SnapshotError::Policy)
        );

        let mut conflicting = snapshot(1, &key);
        conflicting
            .effective_policy
            .harness_actions
            .insert("claude".into(), "allow".into());
        conflicting
            .effective_policy
            .harness_actions
            .insert("claude-code".into(), "block".into());
        conflicting.policy_digest = policy_digest(&conflicting).unwrap();
        conflicting.integrity.mac = integrity_mac(&conflicting, &key).unwrap();
        assert_eq!(
            validate_v3(&conflicting, 1, &"a".repeat(64), &"b".repeat(64), &key, 200,),
            Err(SnapshotError::Policy)
        );
    }

    #[test]
    fn canonical_json_sorts_object_keys() {
        let value = serde_json::json!({"z": 1, "a": {"b": true, "a": null}});
        assert_eq!(
            String::from_utf8(canonical_json_bytes(&value).unwrap()).unwrap(),
            r#"{"a":{"a":null,"b":true},"z":1}"#
        );
    }
}
