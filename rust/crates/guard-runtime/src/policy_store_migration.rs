use super::policy_store_persistence::read_generation_floor;
use super::*;
use guard_policy_snapshot::canonical_json_bytes;
use serde_json::Value;
use std::path::Path;

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
            });
        };
        return Ok(LoadedAuthority {
            snapshot: None,
            canonical_bytes: Vec::new(),
            generation_floor: floor.generation,
            policy_digest: Some(floor.policy_digest),
            invalid_on_startup: false,
            migrate: true,
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
        snapshot,
        canonical_bytes,
        generation_floor,
        policy_digest,
        invalid_on_startup,
        migrate: true,
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
