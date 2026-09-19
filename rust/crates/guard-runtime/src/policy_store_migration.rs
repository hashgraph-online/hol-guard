use super::policy_store_persistence::read_generation_floor;
use super::*;
use guard_policy_snapshot::canonical_json_bytes;
use serde_json::Value;
use std::path::Path;

impl PolicySnapshotStore {
    /// Migrate legacy policy files only on an explicit upgrade command.
    pub(crate) fn migrate_legacy_state(
        state_base: &Path,
        runtime_identity: &str,
    ) -> Result<(), String> {
        validate_private_directory(state_base)?;
        let _writer = policy_store_mutation::acquire_writer(state_base)?;
        let verifier_key = read_verifier_key(state_base)?;
        let authority_path = state_base.join(SNAPSHOT_FILE_NAME);
        let legacy_floor_path = state_base.join(GENERATION_FLOOR_FILE_NAME);
        recover_authority_replacement(&authority_path)?;
        let (_, expected_scope_digest) = scope_binding_for_state_base(state_base);
        let expected_rule_digest = guard_rule_contract::rule_digest();
        let loaded = load_authority(
            &authority_path,
            &legacy_floor_path,
            runtime_identity,
            &expected_rule_digest,
            &expected_scope_digest,
            &verifier_key,
        )?;
        if loaded.migrate {
            if let Some(digest) = loaded.policy_digest.as_deref() {
                persist_authority(
                    &authority_path,
                    loaded.generation_floor,
                    digest,
                    loaded.snapshot.as_ref(),
                    &verifier_key,
                )?;
            }
        }
        Ok(())
    }
}

pub(super) fn load_legacy_authority(
    legacy_snapshot: Option<(Value, Vec<u8>)>,
    legacy_floor_path: &Path,
    expected_runtime_identity: &str,
    expected_rule_digest: &str,
    expected_scope_digest: &str,
    verifier_key: &[u8; VERIFIER_KEY_BYTES],
) -> Result<LoadedAuthority, String> {
    let floor = read_generation_floor(legacy_floor_path, verifier_key)?;
    let parsed_snapshot = legacy_snapshot
        .map(|(value, bytes)| parse_legacy_snapshot(&value, &bytes))
        .transpose();
    let parsed_snapshot = match parsed_snapshot {
        Ok(snapshot) => snapshot,
        Err(error) => {
            if let Some(floor) = floor {
                return Ok(LoadedAuthority {
                    snapshot: None,
                    canonical_bytes: Vec::new(),
                    generation_floor: floor.generation,
                    policy_digest: Some(floor.policy_digest),
                    invalid_on_startup: true,
                    migrate: true,
                    command_control_floor: None,
                });
            }
            return Err(error);
        }
    };
    let Some((legacy_snapshot, legacy_bytes)) = parsed_snapshot else {
        let Some(floor) = floor else {
            return Ok(LoadedAuthority {
                snapshot: None,
                canonical_bytes: Vec::new(),
                generation_floor: 0,
                policy_digest: None,
                invalid_on_startup: false,
                migrate: false,
                command_control_floor: None,
            });
        };
        return Ok(LoadedAuthority {
            snapshot: None,
            canonical_bytes: Vec::new(),
            generation_floor: floor.generation,
            policy_digest: Some(floor.policy_digest),
            invalid_on_startup: false,
            migrate: true,
            command_control_floor: None,
        });
    };

    let floor_generation = floor.as_ref().map_or(0, |item| item.generation);
    let floor_digest = floor.as_ref().map(|item| item.policy_digest.as_str());
    let mut generation_floor = floor_generation.max(legacy_snapshot.generation);
    let mut invalid_on_startup = false;
    let mut snapshot = None;
    let mut canonical_bytes = Vec::new();
    if legacy_snapshot.generation < floor_generation
        || (legacy_snapshot.generation == floor_generation
            && floor_digest.is_some_and(|digest| digest != legacy_snapshot.policy_digest))
    {
        // Retain the highest authenticated floor and discard a stale or
        // same-generation-conflicting candidate. A newer push can recover the
        // missing current snapshot without reusing the floor.
        invalid_on_startup = true;
    } else if validate_v3(
        &legacy_snapshot,
        floor_generation.max(1),
        expected_runtime_identity,
        expected_rule_digest,
        verifier_key,
        now_ms()?,
    )
    .is_ok()
        && legacy_snapshot.scope_contract.scope_digest == expected_scope_digest
    {
        generation_floor = generation_floor.max(legacy_snapshot.generation);
        canonical_bytes = legacy_bytes;
        snapshot = Some(legacy_snapshot);
    } else {
        // Expired, incompatible, or damaged snapshot data cannot authorize a
        // hook. A trusted old floor still permits only a strictly newer push.
        invalid_on_startup = floor.is_none();
    }
    let policy_digest = snapshot
        .as_ref()
        .map(|candidate| candidate.policy_digest.clone())
        .or_else(|| floor.map(|item| item.policy_digest));
    Ok(LoadedAuthority {
        snapshot: snapshot.map(AuthenticatedPolicySnapshot::V3),
        canonical_bytes,
        generation_floor,
        policy_digest,
        invalid_on_startup,
        migrate: true,
        // Command-control authority starts only from a current bound snapshot.
        command_control_floor: None,
    })
}

pub(super) fn parse_legacy_snapshot(
    value: &Value,
    bytes: &[u8],
) -> Result<(PolicySnapshotV3, Vec<u8>), String> {
    let snapshot: PolicySnapshotV3 = serde_json::from_value(value.clone())
        .map_err(|_| "native_policy_snapshot_state_invalid".to_owned())?;
    let canonical = canonical_json_bytes(value).map_err(snapshot_error)?;
    if bytes != canonical {
        return Err("native_policy_snapshot_state_noncanonical".to_owned());
    }
    Ok((snapshot, canonical))
}
