//! An admitted business binding cannot disappear through ordinary publication.
//! This retained floor does not authenticate source activation or grant removal.

use super::policy_store_command_floor::CommandControlFloor;
use guard_policy_snapshot::{
    canonical_json_bytes, digest_bytes, generation_floor_mac, PolicySnapshotV3,
};

pub(super) fn present_floor<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    use serde::Deserialize;
    // Presence cannot mean a nullable removal of retained authority metadata.
    String::deserialize(deserializer).map(Some)
}

pub(super) fn snapshot_floor(
    snapshot: Option<&PolicySnapshotV3>,
) -> Result<Option<String>, String> {
    snapshot
        .and_then(|snapshot| snapshot.business_policy.as_ref())
        .map(|binding| {
            let value = serde_json::to_value(binding)
                .map_err(|_| "native_business_policy_floor_invalid".to_owned())?;
            Ok(digest_bytes(
                &canonical_json_bytes(&value).map_err(|error| error.to_string())?,
            ))
        })
        .transpose()
}

pub(super) fn next_floor(
    current: Option<&str>,
    snapshot: &PolicySnapshotV3,
) -> Result<Option<String>, String> {
    let candidate = snapshot_floor(Some(snapshot))?;
    if current.is_some() && candidate.is_none() {
        return Err("native_business_policy_removal_requires_authority".to_owned());
    }
    Ok(candidate)
}

pub(super) fn authority_floor_mac(
    generation: u64,
    policy_digest: &str,
    controls: Option<&CommandControlFloor>,
    business: Option<&str>,
    verifier_key: &[u8],
) -> Result<String, String> {
    let base = super::policy_store_command_floor::authority_floor_mac(
        generation,
        policy_digest,
        controls,
        verifier_key,
    )?;
    let Some(business) = business else {
        return Ok(base);
    };
    if !super::policy_store_persistence::is_lower_hex(business, 64) {
        return Err("native_business_policy_floor_invalid".to_owned());
    }
    let bound = format!("guard-native-policy-business-floor.v1\0{base}\0{business}");
    Ok(generation_floor_mac(generation, &bound, verifier_key))
}
