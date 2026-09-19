//! Authenticated complete scoped policy transport. Validation is not an application ACK.

use crate::scoped_authority::NativePolicyAuthority;
use crate::{
    canonical_json_bytes, config_digest, crypto, digest_bytes, valid_hex,
    validate_effective_policy, validate_scope, verifier_key_id, EffectiveNativePolicyV3,
    ScopeContractV3, SnapshotError, SnapshotIntegrityV3, POLICY_SNAPSHOT_INTEGRITY_ALGORITHM,
    POLICY_SNAPSHOT_MAX_BYTES, POLICY_SNAPSHOT_MAX_EXPIRY_MS, POLICY_SNAPSHOT_PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};

pub const POLICY_SNAPSHOT_V4_SCHEMA: &str = "hol-guard-native-policy.v4";
pub const POLICY_SNAPSHOT_V4_PUSH_SCHEMA: &str = "guard-policy-snapshot-push.v2";
pub const POLICY_SNAPSHOT_V4_ACK_SCHEMA: &str = "guard-policy-snapshot-ack.v2";
const INTEGRITY_DOMAIN: &[u8] = b"hol-guard-native-policy-snapshot-v4\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshotV4 {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_extensions: Option<guard_contracts::NativeCommandControlBindingV1>,
    pub scoped_authority: NativePolicyAuthority,
    pub source_input_digest: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub integrity: SnapshotIntegrityV3,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshotPushV2 {
    pub schema: String,
    pub snapshot: PolicySnapshotV4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicySnapshotAckV2 {
    pub schema: String,
    pub status: String,
    pub generation: u64,
    pub policy_digest: String,
    pub source_input_digest: String,
    pub idempotent: bool,
    pub resident_generation: u64,
}

pub fn policy_digest_v4(snapshot: &PolicySnapshotV4) -> Result<String, SnapshotError> {
    let authority_digest = snapshot
        .scoped_authority
        .content_digest()
        .map_err(|_| SnapshotError::Policy)?;
    let mut value = serde_json::json!({
        "config_digest": snapshot.config_digest,
        "effective_policy_digest": config_digest(&snapshot.effective_policy)?,
        "mode": snapshot.mode,
        "protocol_version": snapshot.protocol_version,
        "rule_digest": snapshot.rule_digest,
        "runtime_identity": snapshot.runtime_identity,
        "scope_digest": snapshot.scope_contract.scope_digest,
        "scoped_authority_digest": authority_digest,
        "source_input_digest": snapshot.source_input_digest,
        "version": snapshot.version,
    });
    if let Some(binding) = &snapshot.command_extensions {
        value["command_extensions_digest"] =
            serde_json::Value::String(digest_bytes(&canonical_json_bytes(
                &serde_json::to_value(binding).map_err(|_| SnapshotError::Serialization)?,
            )?));
    }
    Ok(digest_bytes(&canonical_json_bytes(&value)?))
}

pub fn snapshot_signing_bytes_v4(snapshot: &PolicySnapshotV4) -> Result<Vec<u8>, SnapshotError> {
    let mut value = serde_json::to_value(snapshot).map_err(|_| SnapshotError::Serialization)?;
    value
        .as_object_mut()
        .ok_or(SnapshotError::Serialization)?
        .remove("integrity");
    canonical_json_bytes(&value)
}

pub fn snapshot_bytes_v4(snapshot: &PolicySnapshotV4) -> Result<Vec<u8>, SnapshotError> {
    let value = serde_json::to_value(snapshot).map_err(|_| SnapshotError::Serialization)?;
    let bytes = canonical_json_bytes(&value)?;
    if bytes.len() > POLICY_SNAPSHOT_MAX_BYTES {
        return Err(SnapshotError::TooLarge);
    }
    Ok(bytes)
}

pub fn integrity_mac_v4(snapshot: &PolicySnapshotV4, key: &[u8]) -> Result<String, SnapshotError> {
    if key.len() != 32 {
        return Err(SnapshotError::Integrity);
    }
    Ok(hex::encode(crypto::hmac_sha256(
        key,
        INTEGRITY_DOMAIN,
        &snapshot_signing_bytes_v4(snapshot)?,
    )))
}

pub fn validate_v4(
    snapshot: &PolicySnapshotV4,
    minimum_generation: u64,
    expected_runtime_identity: &str,
    expected_rule_digest: &str,
    verifier_key: &[u8],
    now_ms: u64,
) -> Result<(), SnapshotError> {
    if snapshot.schema != POLICY_SNAPSHOT_V4_SCHEMA {
        return Err(SnapshotError::Schema);
    }
    if snapshot.version != 4 {
        return Err(SnapshotError::Version);
    }
    if snapshot.generation == 0 {
        return Err(SnapshotError::Generation);
    }
    if snapshot.generation < minimum_generation {
        return Err(SnapshotError::Downgrade);
    }
    for digest in [
        snapshot.policy_digest.as_str(),
        &snapshot.config_digest,
        &snapshot.rule_digest,
        &snapshot.runtime_identity,
        &snapshot.source_input_digest,
        expected_runtime_identity,
        expected_rule_digest,
    ] {
        if !valid_hex(digest, 64) {
            return Err(SnapshotError::Digest);
        }
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
    if snapshot
        .scoped_authority
        .managed_config()
        .is_some_and(|origin| origin.mode() != snapshot.mode)
    {
        return Err(SnapshotError::Mode);
    }
    validate_scope(&snapshot.scope_contract)?;
    validate_effective_policy(&snapshot.effective_policy)?;
    if let Some(binding) = &snapshot.command_extensions {
        binding.validate().map_err(|_| SnapshotError::Policy)?;
    }
    if snapshot.expires_at_ms <= snapshot.issued_at_ms
        || snapshot.expires_at_ms - snapshot.issued_at_ms > POLICY_SNAPSHOT_MAX_EXPIRY_MS
    {
        return Err(SnapshotError::Expiry);
    }
    if snapshot.expires_at_ms <= now_ms {
        return Err(SnapshotError::Expired);
    }
    if verifier_key.len() != 32
        || snapshot.integrity.algorithm != POLICY_SNAPSHOT_INTEGRITY_ALGORITHM
        || snapshot.integrity.key_id != verifier_key_id(verifier_key)
        || !valid_hex(&snapshot.integrity.mac, 64)
    {
        return Err(SnapshotError::Integrity);
    }
    if snapshot.config_digest != config_digest(&snapshot.effective_policy)?
        || snapshot.policy_digest != policy_digest_v4(snapshot)?
    {
        return Err(SnapshotError::DigestMismatch);
    }
    let expected_mac = integrity_mac_v4(snapshot, verifier_key)?;
    if !crypto::constant_time_eq(expected_mac.as_bytes(), snapshot.integrity.mac.as_bytes()) {
        return Err(SnapshotError::IntegrityMismatch);
    }
    snapshot_bytes_v4(snapshot)?;
    Ok(())
}
