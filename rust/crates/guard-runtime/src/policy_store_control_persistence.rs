//! Preserve the authenticated command floor when persisting a raw snapshot.

use super::{is_lower_hex, persist_private_bytes, snapshot_error};
use crate::policy_store::{
    policy_store_command_floor, AuthenticatedPolicySnapshot, PolicyAuthorityRecord,
    AUTHORITY_RECORD_MAX_BYTES, AUTHORITY_RECORD_SCHEMA, AUTHORITY_RECORD_V4_SCHEMA,
    VERIFIER_KEY_BYTES,
};
use guard_policy_snapshot::canonical_json_bytes;
use std::path::Path;

pub(in crate::policy_store) fn persist_authority(
    path: &Path,
    generation_floor: u64,
    policy_digest: &str,
    snapshot: Option<&AuthenticatedPolicySnapshot>,
    verifier_key: &[u8; VERIFIER_KEY_BYTES],
) -> Result<(), String> {
    let floor = policy_store_command_floor::floor_for_binding(
        snapshot.and_then(|value| value.command_extensions().as_ref()),
    );
    persist_authority_with_control_floor(
        path,
        generation_floor,
        policy_digest,
        snapshot,
        verifier_key,
        floor.as_ref(),
    )
}

pub(in crate::policy_store) fn persist_authority_with_control_floor(
    path: &Path,
    generation_floor: u64,
    policy_digest: &str,
    snapshot: Option<&AuthenticatedPolicySnapshot>,
    verifier_key: &[u8; VERIFIER_KEY_BYTES],
    command_control_floor: Option<&policy_store_command_floor::CommandControlFloor>,
) -> Result<(), String> {
    let private_root = path
        .parent()
        .ok_or_else(|| "native_policy_snapshot_authority_parent_missing".to_owned())
        .and_then(crate::resident_state::private_root_for_state_base)?;
    if generation_floor == 0
        || !is_lower_hex(policy_digest, 64)
        || snapshot.is_some_and(|candidate| {
            *candidate.generation() != generation_floor
                || candidate.policy_digest() != policy_digest
        })
    {
        return Err("native_policy_snapshot_authority_invalid".to_owned());
    }
    let record = PolicyAuthorityRecord {
        schema: if snapshot.is_some_and(|candidate| candidate.source_input_digest().is_some()) {
            AUTHORITY_RECORD_V4_SCHEMA.to_owned()
        } else {
            AUTHORITY_RECORD_SCHEMA.to_owned()
        },
        generation_floor,
        policy_digest: policy_digest.to_owned(),
        snapshot: snapshot.cloned(),
        floor_mac: policy_store_command_floor::authority_floor_mac(
            generation_floor,
            policy_digest,
            command_control_floor,
            verifier_key,
        )?,
        command_control_floor: command_control_floor.cloned(),
    };
    let value = serde_json::to_value(record)
        .map_err(|_| "native_policy_snapshot_authority_encode_failed".to_owned())?;
    let bytes = canonical_json_bytes(&value).map_err(snapshot_error)?;
    persist_private_bytes(
        path,
        &bytes,
        AUTHORITY_RECORD_MAX_BYTES,
        "authority",
        &private_root,
    )
}
