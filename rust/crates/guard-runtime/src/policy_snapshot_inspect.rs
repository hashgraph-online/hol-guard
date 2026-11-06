//! Offline content projection only; never an authenticated admission result.
use super::read_request;
use guard_policy_snapshot::{
    digest_bytes, inspect_unverified_content, snapshot_bytes, PolicySnapshotV3,
};
use serde::Serialize;
use std::io::Read;

const ERROR: &str = "native_policy_snapshot_inspect_invalid";

#[derive(Serialize)]
struct Inspection {
    schema: &'static str,
    version: u16,
    authenticity: &'static str,
    currentness: &'static str,
    snapshot_digest: String,
    config_digest: String,
    policy_digest: String,
    business_policy_present: bool,
}

pub(super) fn inspect_from_reader(reader: impl Read) -> Result<Vec<u8>, String> {
    let (bytes, filled) = read_request(reader).map_err(|_| ERROR.to_owned())?;
    let snapshot: PolicySnapshotV3 =
        serde_json::from_slice(&bytes[..filled]).map_err(|_| ERROR.to_owned())?;
    let (config_digest, policy_digest) =
        inspect_unverified_content(&snapshot).map_err(|_| ERROR.to_owned())?;
    let canonical = snapshot_bytes(&snapshot).map_err(|_| ERROR.to_owned())?;
    serde_json::to_vec(&Inspection {
        schema: "guard-native-policy-content-inspection.v1",
        version: 1,
        authenticity: "not_checked",
        currentness: "not_checked",
        snapshot_digest: digest_bytes(&canonical),
        config_digest,
        policy_digest,
        business_policy_present: snapshot.business_policy.is_some(),
    })
    .map_err(|_| ERROR.to_owned())
}

#[cfg(test)]
#[path = "policy_snapshot_inspect_tests.rs"]
mod tests;
