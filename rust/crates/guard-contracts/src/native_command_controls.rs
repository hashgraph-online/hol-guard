//! Compact authenticated binding to a packaged native command program.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const NATIVE_COMMAND_CONTROL_BINDING_SCHEMA: &str = "guard.native-command-control-binding.v1";
pub const NATIVE_COMMAND_PROGRAM_CAPABILITY: &str = "native-command-program-v1";
pub const NATIVE_COMMAND_CONTROL_FENCE_CAPABILITY: &str = "native-command-control-fence-v1";

/// Fixed public failure identities. These contain no paths, keys, revisions,
/// command text or raw OS errors; unknown codes remain redacted by transport.
pub const NATIVE_COMMAND_CONTROL_ERROR_CODES: &[&str] = &[
    "native_command_control_authority_downgrade",
    "native_command_control_authority_epoch_reused",
    "native_command_control_authority_invalid",
    "native_command_control_authority_mac_invalid",
    "native_command_control_authority_missing",
    "native_command_control_authority_noncanonical",
    "native_command_control_authority_not_current",
    "native_command_control_authority_path_invalid",
    "native_command_control_authority_removed",
    "native_command_control_binding_invalid",
    "native_command_control_binding_removed",
    "native_command_control_digest_mismatch",
    "native_command_control_encoding_failed",
    "native_command_control_floor_invalid",
    "native_command_control_layer_invalid",
    "native_command_control_mutation_in_progress",
    "native_command_control_mutation_lock_invalid",
    "native_command_control_mutation_lock_missing",
    "native_command_control_mutation_lock_unsupported",
    "native_command_control_mutation_reused",
    "native_command_control_recovery_context_mismatch",
    "native_command_control_recovery_invalid",
    "native_command_control_recovery_missing",
    "native_command_control_revision_downgrade",
    "native_command_control_revision_reused",
    "native_command_control_target_invalid",
    "native_command_control_target_unknown",
    "native_policy_snapshot_command_authority_invalid",
    "native_policy_snapshot_command_authority_not_private",
    "native_policy_snapshot_command_authority_read_failed",
    "native_policy_snapshot_command_authority_stat_failed",
    "native_policy_snapshot_command_authority_too_large",
    "native_resident_command_mutation_lock_invalid",
    "native_resident_command_mutation_lock_read_failed",
];
const RUNTIME_SCHEMA: &str = "guard.extension-control-runtime-snapshot.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeExtensionControlV1 {
    pub target_kind: String,
    pub target_id: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeExtensionControlLayerV1 {
    pub schema_version: String,
    pub kind: String,
    pub catalog_digest: String,
    pub global_lockdown: bool,
    pub controls: Vec<NativeExtensionControlV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeCommandControlRecoveryV1 {
    pub schema: String,
    pub previous_epoch: u64,
    pub previous_mutation_revision: u64,
    pub previous_authority_key_id: String,
    pub previous_floor_digest: String,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeCommandControlAuthorityV1 {
    pub epoch: u64,
    pub mutation_revision: u64,
    pub authority_key_id: String,
    pub recovery: Option<NativeCommandControlRecoveryV1>,
}

impl NativeCommandControlAuthorityV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.epoch == 0 || self.mutation_revision == 0 || !valid_digest(&self.authority_key_id) {
            return Err("native_command_control_authority_invalid");
        }
        if let Some(recovery) = &self.recovery {
            if recovery.schema != "guard.native-command-control-recovery.v1"
                || self.epoch <= recovery.previous_epoch
                || self.mutation_revision <= recovery.previous_mutation_revision
                || !valid_digest(&recovery.previous_authority_key_id)
                || !valid_digest(&recovery.previous_floor_digest)
                || !valid_digest(&recovery.nonce)
            {
                return Err("native_command_control_recovery_invalid");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeCommandControlBindingV1 {
    pub schema: String,
    pub program_digest: String,
    pub catalog_digest: String,
    pub trust_digest: String,
    pub health: String,
    pub revision: u64,
    pub managed_revision: u64,
    pub effective_digest: String,
    pub layers: Vec<NativeExtensionControlLayerV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<NativeCommandControlAuthorityV1>,
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_target(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("command.") else {
        return false;
    };
    value.len() <= 256
        && suffix.split(['.', '-']).all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

impl NativeCommandControlBindingV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != NATIVE_COMMAND_CONTROL_BINDING_SCHEMA
            || [
                &self.program_digest,
                &self.catalog_digest,
                &self.trust_digest,
                &self.effective_digest,
            ]
            .iter()
            .any(|digest| !valid_digest(digest))
            || !matches!(
                self.health.as_str(),
                "unenrolled"
                    | "protected"
                    | "degraded-unacknowledged"
                    | "degraded-acknowledged"
                    | "tampered"
                    | "recovery-required"
            )
            || self.layers.len() > 2
        {
            return Err("native_command_control_binding_invalid");
        }
        if let Some(authority) = &self.authority {
            authority.validate()?;
        }
        let mut kinds = BTreeSet::new();
        for layer in &self.layers {
            if layer.schema_version != "1.0.0"
                || !matches!(layer.kind.as_str(), "local-admin" | "signed-cloud")
                || !kinds.insert(&layer.kind)
                || layer.catalog_digest != self.catalog_digest
                || layer.controls.len() > 512
            {
                return Err("native_command_control_layer_invalid");
            }
            let mut targets = BTreeSet::new();
            for control in &layer.controls {
                if !matches!(control.target_kind.as_str(), "extension" | "permission")
                    || !matches!(control.state.as_str(), "enabled" | "disabled")
                    || !valid_target(&control.target_id)
                    || control.target_id.contains(".permission.")
                        != (control.target_kind == "permission")
                    || !targets.insert((&control.target_kind, &control.target_id))
                {
                    return Err("native_command_control_target_invalid");
                }
            }
        }
        if self.effective_digest != self.compute_effective_digest()? {
            return Err("native_command_control_digest_mismatch");
        }
        Ok(())
    }

    pub fn compute_effective_digest(&self) -> Result<String, &'static str> {
        // This reproduces the existing Python runtime snapshot digest. Every
        // accepted identifier is ASCII, so canonical UTF-8 and ensure_ascii
        // encodings coincide and their framed lengths are identical.
        let mut layers = self.layers.clone();
        layers.sort_by(|left, right| left.kind.cmp(&right.kind));
        for layer in &mut layers {
            layer.controls.sort_by(|left, right| {
                (&left.target_kind, &left.target_id).cmp(&(&right.target_kind, &right.target_id))
            });
        }
        let value = serde_json::json!({
            "catalog_digest": self.catalog_digest,
            "health": self.health,
            "layers": layers,
            "managed_revision": self.managed_revision,
            "revision": self.revision,
            "schema_version": RUNTIME_SCHEMA,
        });
        let canonical =
            serde_json::to_vec(&value).map_err(|_| "native_command_control_encoding_failed")?;
        let mut digest = Sha256::new();
        digest.update(RUNTIME_SCHEMA.as_bytes());
        digest.update(b"\0");
        digest.update(canonical.len().to_string().as_bytes());
        digest.update(b"\0");
        digest.update(canonical);
        Ok(hex::encode(digest.finalize()))
    }
}
