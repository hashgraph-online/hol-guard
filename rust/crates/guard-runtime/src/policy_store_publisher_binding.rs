//! The runtime the home's policy publisher last published for.
//!
//! The publisher retains each signed snapshot in its own file before it
//! pushes it to a resident, so that file names the runtime the home publishes
//! for even while a resident of another runtime rejects the push. The
//! resident's own authority file only records snapshots it admitted.

use super::policy_store_persistence::read_private_json;
use super::{PolicySnapshotStore, VERIFIER_KEY_BYTES};
use guard_policy_snapshot::{
    integrity_mac, verifier_key_id, PolicySnapshotV3, POLICY_SNAPSHOT_MAX_BYTES,
};
use std::path::Path;

/// Mirrors `NATIVE_POLICY_SNAPSHOT_CACHE_NAME` in the Python publisher.
pub(super) const PUBLISHER_SNAPSHOT_FILE_NAME: &str = "policy-snapshot-publisher-v3.json";

impl PolicySnapshotStore {
    /// The runtime digest this store admits snapshots for.
    pub(crate) fn runtime_identity(&self) -> &str {
        &self.expected_runtime_identity
    }

    /// The runtime the home's publisher last bound a snapshot to. `None`
    /// whenever that cannot be shown: a missing, unreadable, malformed or
    /// unauthenticated publisher snapshot.
    pub(crate) fn published_runtime_identity(&self) -> Option<String> {
        published_runtime_identity(&self.state_base, &self.verifier_key)
    }
}

/// Read the runtime binding of the publisher's latest snapshot. Only the MAC
/// is checked, not expiry or generation: the answer names whom the home
/// publishes for and never admits the snapshot.
pub(super) fn published_runtime_identity(
    state_base: &Path,
    verifier_key: &[u8; VERIFIER_KEY_BYTES],
) -> Option<String> {
    let private_root = crate::resident_state::private_root_for_state_base(state_base).ok()?;
    let (value, _bytes) = read_private_json(
        &state_base.join(PUBLISHER_SNAPSHOT_FILE_NAME),
        POLICY_SNAPSHOT_MAX_BYTES as u64,
        "cache",
        &private_root,
    )
    .ok()??;
    let snapshot: PolicySnapshotV3 = serde_json::from_value(value).ok()?;
    let mac = integrity_mac(&snapshot, verifier_key).ok()?;
    (snapshot.integrity.key_id == verifier_key_id(verifier_key)
        && crate::constant_time_eq(mac.as_bytes(), snapshot.integrity.mac.as_bytes()))
    .then_some(snapshot.runtime_identity)
}

#[cfg(test)]
#[path = "policy_store_publisher_binding_tests.rs"]
mod tests;
