//! Persist independent control revisions even when the current snapshot expires
//! or is quarantined. The optional floor extends the existing authenticated
//! authority record while retaining the base generation-floor MAC when it is absent.

use guard_policy_snapshot::{canonical_json_bytes, generation_floor_mac, PolicySnapshotV3};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct CommandControlFloor {
    revision: u64,
    managed_revision: u64,
    effective_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority: Option<guard_contracts::NativeCommandControlAuthorityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_floor_digest: Option<String>,
}

pub(super) fn snapshot_floor(snapshot: Option<&PolicySnapshotV3>) -> Option<CommandControlFloor> {
    let binding = snapshot?.command_extensions.as_ref()?;
    (binding.health == "protected").then(|| CommandControlFloor {
        revision: binding.revision,
        managed_revision: binding.managed_revision,
        effective_digest: binding.effective_digest.clone(),
        authority: binding.authority.clone(),
        previous_floor_digest: binding
            .authority
            .as_ref()
            .and_then(|authority| authority.recovery.as_ref())
            .map(|recovery| recovery.previous_floor_digest.clone()),
    })
}

pub(super) fn next_floor(
    current: Option<&CommandControlFloor>,
    snapshot: &PolicySnapshotV3,
) -> Result<Option<CommandControlFloor>, String> {
    if current.is_some() && snapshot.command_extensions.is_none() {
        return Err("native_command_control_binding_removed".to_owned());
    }
    if current.is_some()
        && snapshot
            .command_extensions
            .as_ref()
            .is_some_and(|binding| binding.health == "unenrolled")
    {
        // Losing protected SQL/key state is not a fresh installation. Retained
        // native authority must never downgrade to permissive first-use defaults.
        return Err("native_command_control_authority_downgrade".to_owned());
    }
    let Some(candidate) = snapshot_floor(Some(snapshot)) else {
        return Ok(current.cloned());
    };
    let recovery = validate_authority_transition(current, &candidate)?;
    if let Some(current) = current.filter(|_| !recovery) {
        if candidate.revision < current.revision
            || candidate.managed_revision < current.managed_revision
        {
            return Err("native_command_control_revision_downgrade".to_owned());
        }
        if candidate.revision == current.revision
            && candidate.managed_revision == current.managed_revision
            && candidate.effective_digest != current.effective_digest
        {
            return Err("native_command_control_revision_reused".to_owned());
        }
    }
    Ok(Some(candidate))
}

pub(super) fn floor_link_digest(floor: Option<&CommandControlFloor>) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let value = serde_json::to_value(floor)
        .map_err(|_| "native_command_control_floor_invalid".to_owned())?;
    let canonical = canonical_json_bytes(&value).map_err(|error| error.to_string())?;
    let mut digest = Sha256::new();
    digest.update(b"hol-guard.native-command-control-floor-link.v1\0");
    digest.update(canonical);
    Ok(hex::encode(digest.finalize()))
}

fn validate_authority_transition(
    current: Option<&CommandControlFloor>,
    candidate: &CommandControlFloor,
) -> Result<bool, String> {
    let previous = current.and_then(|floor| floor.authority.as_ref());
    let Some(authority) = candidate.authority.as_ref() else {
        return if previous.is_some() {
            Err("native_command_control_authority_removed".into())
        } else {
            Ok(false)
        };
    };
    authority.validate().map_err(str::to_owned)?;
    if let Some(previous) = previous {
        if authority.epoch < previous.epoch
            || authority.mutation_revision < previous.mutation_revision
        {
            return Err("native_command_control_authority_downgrade".into());
        }
        if authority.epoch == previous.epoch {
            if authority.authority_key_id != previous.authority_key_id
                || authority.recovery != previous.recovery
            {
                return Err("native_command_control_authority_epoch_reused".into());
            }
            if authority.mutation_revision == previous.mutation_revision
                && current.is_some_and(|floor| candidate != floor)
            {
                return Err("native_command_control_mutation_reused".into());
            }
            return Ok(false);
        }
        if authority.mutation_revision <= previous.mutation_revision {
            return Err("native_command_control_authority_downgrade".into());
        }
    } else if authority.epoch == 1 && authority.recovery.is_none() {
        return Ok(false);
    }
    let recovery = authority
        .recovery
        .as_ref()
        .ok_or_else(|| "native_command_control_recovery_missing".to_owned())?;
    if recovery.previous_floor_digest != floor_link_digest(current)?
        || recovery.previous_epoch != previous.map_or(0, |value| value.epoch)
        || recovery.previous_mutation_revision
            != previous.map_or(0, |value| value.mutation_revision)
        || recovery.previous_authority_key_id
            != previous.map_or("0".repeat(64), |value| value.authority_key_id.clone())
        || candidate.previous_floor_digest.as_ref() != Some(&recovery.previous_floor_digest)
    {
        return Err("native_command_control_recovery_context_mismatch".into());
    }
    Ok(true)
}

pub(super) fn authority_floor_mac(
    generation: u64,
    policy_digest: &str,
    controls: Option<&CommandControlFloor>,
    verifier_key: &[u8],
) -> Result<String, String> {
    let Some(controls) = controls else {
        return Ok(generation_floor_mac(
            generation,
            policy_digest,
            verifier_key,
        ));
    };
    if !super::policy_store_persistence::is_lower_hex(&controls.effective_digest, 64) {
        return Err("native_command_control_floor_invalid".to_owned());
    }
    if let Some(authority) = &controls.authority {
        authority.validate().map_err(str::to_owned)?;
    }
    if controls
        .previous_floor_digest
        .as_ref()
        .is_some_and(|digest| !super::policy_store_persistence::is_lower_hex(digest, 64))
    {
        return Err("native_command_control_floor_invalid".to_owned());
    }
    let recovery_floor = controls
        .authority
        .as_ref()
        .and_then(|authority| authority.recovery.as_ref())
        .map(|recovery| recovery.previous_floor_digest.as_str());
    if controls.previous_floor_digest.as_deref() != recovery_floor {
        return Err("native_command_control_floor_invalid".to_owned());
    }
    let value = serde_json::json!({ "policy_digest": policy_digest, "command_controls": controls });
    let canonical = canonical_json_bytes(&value).map_err(|error| error.to_string())?;
    let mut bound = "guard-native-policy-command-control-floor.v1\0".to_owned();
    bound.push_str(
        std::str::from_utf8(&canonical)
            .map_err(|_| "native_command_control_floor_invalid".to_owned())?,
    );
    Ok(generation_floor_mac(generation, &bound, verifier_key))
}
