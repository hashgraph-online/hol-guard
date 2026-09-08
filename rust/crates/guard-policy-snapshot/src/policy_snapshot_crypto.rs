use super::{
    canonical_json_bytes, snapshot_signing_bytes, EffectiveNativePolicyV3, PolicySnapshotV3,
    SnapshotError, POLICY_SNAPSHOT_FLOOR_DOMAIN, POLICY_SNAPSHOT_INTEGRITY_DOMAIN,
    POLICY_SNAPSHOT_VERIFIER_DERIVATION_DOMAIN,
};
use sha2::{Digest, Sha256};

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
pub(super) fn hmac_sha256(key: &[u8], label: &[u8], message: &[u8]) -> [u8; 32] {
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

pub(super) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}
