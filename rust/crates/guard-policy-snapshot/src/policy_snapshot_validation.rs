use super::*;

// Shared shape/semantic checks; callers supply their own context. This helper
// cannot authenticate a snapshot without the separate key/MAC checks below.
fn validate_content(
    snapshot: &PolicySnapshotV3,
    minimum_generation: u64,
    expected_runtime_identity: &str,
    expected_rule_digest: &str,
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
    if let Some(binding) = &snapshot.business_policy {
        binding.validate()?;
    }
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
    if snapshot.integrity.algorithm != POLICY_SNAPSHOT_INTEGRITY_ALGORITHM
        || !valid_hex(&snapshot.integrity.key_id, 64)
        || !valid_hex(&snapshot.integrity.mac, 64)
    {
        return Err(SnapshotError::Integrity);
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
    validate_content(
        snapshot,
        minimum_generation,
        expected_runtime_identity,
        expected_rule_digest,
        now_ms,
    )?;
    if snapshot.integrity.key_id != verifier_key_id(verifier_key) {
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

/// Inspect typed content and recompute digests without authenticating it.
/// The snapshot supplies its own context; no clock, generation floor, trusted
/// runtime/rule identity, scope ownership or MAC verification is established.
/// Returned strings are diagnostic metadata, never an admission proof.
pub fn inspect_unverified_content(
    snapshot: &PolicySnapshotV3,
) -> Result<(String, String), SnapshotError> {
    snapshot_bytes(snapshot)?;
    validate_content(
        snapshot,
        1,
        &snapshot.runtime_identity,
        &snapshot.rule_digest,
        snapshot.issued_at_ms,
    )?;
    Ok((
        config_digest(&snapshot.effective_policy)?,
        policy_digest(snapshot)?,
    ))
}
