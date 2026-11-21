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
    "native_active_pack_security_binding_mismatch",
    "native_active_pack_security_invalid",
    "native_active_pack_security_program_mismatch",
    "native_command_compatibility_context_unsupported",
    "native_command_compatibility_deadline",
    "native_command_compatibility_inventory_mismatch",
    "native_command_compatibility_limit",
    "native_command_compatibility_model_unsupported",
    "native_command_compatibility_owner_invalid",
    "native_command_compatibility_permission_invalid",
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
    "native_command_encoding_failed",
    "native_command_extension_contract_invalid",
    "native_command_extension_dependency_unknown",
    "native_command_extension_duplicate",
    "native_command_matcher_digest_mismatch",
    "native_command_node_missing",
    "native_command_pack_budget_exceeded",
    "native_command_pack_cache_identity_invalid",
    "native_command_pack_cache_invalid",
    "native_command_pack_cache_noncanonical",
    "native_command_pack_cache_read_failed",
    "native_command_pack_index_invalid",
    "native_command_pack_inventory_invalid",
    "native_command_pack_link_invalid",
    "native_command_pack_rule_owner_invalid",
    "native_command_pack_selection_invalid",
    "native_command_pack_selection_missing",
    "native_command_pack_transition_mismatch",
    "native_command_permission_contract_invalid",
    "native_command_permission_dependency_invalid",
    "native_command_permission_dependency_unknown",
    "native_command_permission_duplicate",
    "native_command_program_binding_mismatch",
    "native_command_program_bounds_invalid",
    "native_command_program_bytes_exceeded",
    "native_command_program_contract_invalid",
    "native_command_program_digest_mismatch",
    "native_command_program_digest_missing",
    "native_command_program_json_invalid",
    "native_command_program_noncanonical",
    "native_command_program_shape_invalid",
    "native_command_program_version_unsupported",
    "native_command_required_forbidden_flag_conflict",
    "native_command_required_option_duplicated",
    "native_command_required_option_values_empty",
    "native_command_required_pack_missing",
    "native_command_rule_candidate_invalid",
    "native_command_rule_coverage_invalid",
    "native_command_rule_duplicate",
    "native_command_rule_owner_missing",
    "native_command_variant_coverage_invalid",
    "native_policy_snapshot_command_authority_invalid",
    "native_policy_snapshot_command_authority_not_private",
    "native_policy_snapshot_command_authority_parent_missing",
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
    /// The authority a device starts with: the first epoch, the all-zero key
    /// and no recovery pending.
    pub fn is_initial(&self) -> bool {
        self.epoch == 1 && self.authority_key_id == "0".repeat(64) && self.recovery.is_none()
    }

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_security_digest: Option<String>,
}

/// The extension-control state a runtime snapshot digest covers.
pub struct RuntimeSnapshot<'a> {
    pub catalog_digest: &'a str,
    pub health: &'a str,
    pub revision: u64,
    pub managed_revision: u64,
    pub layers: &'a [NativeExtensionControlLayerV1],
    pub active_security_digest: Option<&'a str>,
}

/// The digest that identifies one extension-control runtime snapshot: layers
/// ordered by kind and controls by target, framed as
/// `schema NUL length NUL canonical-json`. It is the same digest the Python
/// runtime snapshot carried. Every accepted identifier is ASCII, so the
/// canonical UTF-8 and `ensure_ascii` encodings, and their lengths, coincide;
/// a snapshot naming anything else is refused rather than digested differently.
pub fn runtime_snapshot_digest(snapshot: &RuntimeSnapshot<'_>) -> Result<String, &'static str> {
    let mut layers = snapshot.layers.to_vec();
    layers.sort_by(|left, right| left.kind.cmp(&right.kind));
    for layer in &mut layers {
        layer.controls.sort_by(|left, right| {
            (&left.target_kind, &left.target_id).cmp(&(&right.target_kind, &right.target_id))
        });
    }
    let mut value = serde_json::json!({
        "catalog_digest": snapshot.catalog_digest,
        "health": snapshot.health,
        "layers": layers,
        "managed_revision": snapshot.managed_revision,
        "revision": snapshot.revision,
        "schema_version": RUNTIME_SCHEMA,
    });
    if let Some(security) = snapshot.active_security_digest {
        value["active_security_digest"] = security.into();
    }
    let canonical =
        serde_json::to_vec(&value).map_err(|_| "native_command_control_encoding_failed")?;
    if !canonical.is_ascii() {
        return Err("native_command_control_encoding_failed");
    }
    let mut digest = Sha256::new();
    digest.update(RUNTIME_SCHEMA.as_bytes());
    digest.update(b"\0");
    digest.update(canonical.len().to_string().as_bytes());
    digest.update(b"\0");
    digest.update(canonical);
    Ok(hex::encode(digest.finalize()))
}

/// Checks the layers a runtime snapshot or binding carries: a valid catalog
/// digest, at most one layer per kind, every layer on that catalog, and
/// bounded, unique, well-formed controls. A snapshot that fails here could
/// never be bound, so it is not given a digest either.
pub fn validate_snapshot_layers(
    catalog_digest: &str,
    layers: &[NativeExtensionControlLayerV1],
) -> Result<(), &'static str> {
    if !valid_digest(catalog_digest) || layers.len() > 2 {
        return Err("native_command_control_binding_invalid");
    }
    let mut kinds = BTreeSet::new();
    for layer in layers {
        if layer.schema_version != "1.0.0"
            || !matches!(layer.kind.as_str(), "local-admin" | "signed-cloud")
            || !kinds.insert(&layer.kind)
            || layer.catalog_digest != catalog_digest
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
    Ok(())
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
    /// The binding a device has before it ever enrolls: unenrolled, nothing
    /// saved, no layers, and the initial authority with no recovery pending.
    /// Enforcement keeps packaged protection for it instead of a global
    /// block, and the advisory allow hint judges it as it will be once
    /// enrolled. Any other unenrolled binding is a lost authority.
    pub fn is_initial_defaults(&self) -> bool {
        self.has_first_install_shape()
            && self
                .authority
                .as_ref()
                .is_some_and(NativeCommandControlAuthorityV1::is_initial)
    }

    /// Unenrolled with nothing saved and no layers. It names a first install
    /// only together with the initial authority, see
    /// [`Self::is_initial_defaults`].
    pub fn has_first_install_shape(&self) -> bool {
        self.health == "unenrolled"
            && self.revision == 0
            && self.managed_revision == 0
            && self.layers.is_empty()
    }

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
        if self
            .active_security_digest
            .as_ref()
            .is_some_and(|v| !valid_digest(v))
        {
            return Err("native_command_control_binding_invalid");
        }
        validate_snapshot_layers(&self.catalog_digest, &self.layers)?;
        if self.effective_digest != self.compute_effective_digest()? {
            return Err("native_command_control_digest_mismatch");
        }
        Ok(())
    }

    pub fn compute_effective_digest(&self) -> Result<String, &'static str> {
        runtime_snapshot_digest(&RuntimeSnapshot {
            catalog_digest: &self.catalog_digest,
            health: &self.health,
            revision: self.revision,
            managed_revision: self.managed_revision,
            layers: &self.layers,
            active_security_digest: self.active_security_digest.as_deref(),
        })
    }
}
