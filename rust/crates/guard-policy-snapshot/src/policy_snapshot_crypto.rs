use super::{
    canonical_json_bytes, snapshot_signing_bytes, EffectiveNativePolicyV3, PolicySnapshotV3,
    SnapshotError, POLICY_SNAPSHOT_FLOOR_DOMAIN, POLICY_SNAPSHOT_INTEGRITY_DOMAIN,
    POLICY_SNAPSHOT_VERIFIER_DERIVATION_DOMAIN,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

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
    let mut value = serde_json::json!({
        "config_digest": snapshot.config_digest,
        "effective_policy_digest": config_digest(&snapshot.effective_policy)?,
        "mode": snapshot.mode,
        "protocol_version": snapshot.protocol_version,
        "rule_digest": snapshot.rule_digest,
        "runtime_identity": snapshot.runtime_identity,
        "scope_digest": snapshot.scope_contract.scope_digest,
        "version": snapshot.version,
    });
    if let Some(binding) = &snapshot.command_extensions {
        value["command_extensions_digest"] =
            serde_json::Value::String(digest_bytes(&canonical_json_bytes(
                &serde_json::to_value(binding).map_err(|_| SnapshotError::Serialization)?,
            )?));
    }
    if let Some(binding) = &snapshot.business_policy {
        value["business_policy_digest"] =
            serde_json::Value::String(digest_bytes(&canonical_json_bytes(
                &serde_json::to_value(binding).map_err(|_| SnapshotError::Serialization)?,
            )?));
    }
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
/// Standard RFC-2104 HMAC-SHA256 over a message (no domain label injection).
/// Used by `local_authority_integrity` for both `_purpose_key` derivation and
/// the final payload MAC, where Python calls `hmac.new(key, msg, sha256)`.
pub(crate) fn hmac_sha256_raw(key: &[u8], message: &[u8]) -> [u8; 32] {
    hmac_sha256(key, b"", message)
}

pub(super) fn hmac_sha256(key: &[u8], label: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    let mut key_block = Zeroizing::new([0u8; BLOCK_BYTES]);
    if key.len() > BLOCK_BYTES {
        let mut digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
        digest.as_mut_slice().zeroize();
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = Zeroizing::new([0x36u8; BLOCK_BYTES]);
    let mut outer_pad = Zeroizing::new([0x5cu8; BLOCK_BYTES]);
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }
    let mut inner = Sha256::new();
    inner.update(&inner_pad[..]);
    inner.update(label);
    inner.update(message);
    let mut inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&outer_pad[..]);
    outer.update(inner_digest.as_slice());
    inner_digest.as_mut_slice().zeroize();
    let digest = outer.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
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

    #[test]
    fn cleared_scratch_preserves_independent_short_and_long_key_hmac_vectors() {
        // Expected digests computed independently with Python stdlib HMAC.
        for (key, expected) in [
            (
                vec![7u8; 32],
                "ecacb2077000c38ea511853fa51e99358878ca2f68e9844ae1a6537777a26db8",
            ),
            (
                vec![b'k'; 131],
                "0f7e060a08c42d9d6e9e98ff49277f5a5e950de80a2d9f531dd214704d7e6df1",
            ),
        ] {
            assert_eq!(
                hex::encode(hmac_sha256(&key, b"publisher\0", b"payload")),
                expected
            );
        }
    }
}
