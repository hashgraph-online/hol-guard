#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const POLICY_SNAPSHOT_SCHEMA: &str = "hol-guard-native-policy.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySnapshotV1 {
    pub schema: String,
    pub generation: u64,
    pub policy_digest: String,
    pub config_digest: String,
    pub rule_digest: String,
    pub mode: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SnapshotError {
    #[error("snapshot_schema_mismatch")]
    Schema,
    #[error("snapshot_generation_downgrade")]
    Downgrade,
    #[error("snapshot_digest_invalid")]
    Digest,
}

pub fn validate(snapshot: &PolicySnapshotV1, minimum_generation: u64) -> Result<(), SnapshotError> {
    if snapshot.schema != POLICY_SNAPSHOT_SCHEMA {
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
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_generation_downgrade() {
        let digest = "a".repeat(64);
        let snapshot = PolicySnapshotV1 {
            schema: POLICY_SNAPSHOT_SCHEMA.into(),
            generation: 1,
            policy_digest: digest.clone(),
            config_digest: digest.clone(),
            rule_digest: digest,
            mode: "enforce".into(),
        };
        assert_eq!(validate(&snapshot, 2), Err(SnapshotError::Downgrade));
    }
}
