//! A complete separately resolved managed origin inside authenticated V4 authority.

use crate::{
    canonical_json_bytes, valid_hex, validate_effective_policy, EffectiveNativePolicyV3,
    SnapshotError,
};
use serde::{Deserialize, Serialize};

pub const MANAGED_CONFIGURATION_FEATURE: &str = "policy-managed-config-floor-v1";
const SCHEMA: &str = "guard-native-managed-config.v1";

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RawManagedConfiguration {
    schema: String,
    source_digest: String,
    mode: String,
    effective_policy: EffectiveNativePolicyV3,
    default_action_present: bool,
}

/// Validated projection only; the containing snapshot supplies authentication.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(try_from = "RawManagedConfiguration", into = "RawManagedConfiguration")]
pub struct ManagedConfiguration(RawManagedConfiguration);

impl TryFrom<RawManagedConfiguration> for ManagedConfiguration {
    type Error = SnapshotError;
    fn try_from(raw: RawManagedConfiguration) -> Result<Self, Self::Error> {
        if raw.schema != SCHEMA || !valid_hex(&raw.source_digest, 64) {
            return Err(SnapshotError::Policy);
        }
        if !matches!(raw.mode.as_str(), "enforce" | "observe") {
            return Err(SnapshotError::Mode);
        }
        validate_effective_policy(&raw.effective_policy)?;
        let policy = serde_json::to_value(&raw.effective_policy)
            .map_err(|_| SnapshotError::Serialization)?;
        if canonical_json_bytes(&policy)?.len() > 128 * 1024 {
            return Err(SnapshotError::TooLarge);
        }
        Ok(Self(raw))
    }
}

impl From<ManagedConfiguration> for RawManagedConfiguration {
    fn from(value: ManagedConfiguration) -> Self {
        value.0
    }
}

impl ManagedConfiguration {
    pub fn default_action_present(&self) -> bool {
        self.0.default_action_present
    }
    pub fn mode(&self) -> &str {
        &self.0.mode
    }
    pub fn effective_policy(&self) -> &EffectiveNativePolicyV3 {
        &self.0.effective_policy
    }
    pub fn source_digest(&self) -> &str {
        &self.0.source_digest
    }
}
