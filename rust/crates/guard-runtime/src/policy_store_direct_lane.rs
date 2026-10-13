//! Freshness admission for the direct resident hook lane.
//!
//! The daemon path waits for the publisher's ACK, which Python withdraws as
//! soon as it observes a policy input change. A hook that bypasses the daemon
//! needs the same guarantee from the resident alone. Each push may carry the
//! state its snapshot was compiled against; the resident keeps that binding in
//! memory and, before every direct use, requires that:
//!
//! - the publisher's ACK file still names this generation and digest, with an
//!   unexpired lease (the publisher unlinks it whenever it withdraws its ACK);
//! - the request workspace was settled by this snapshot;
//! - every watched non-database input still has the stat identity the
//!   publisher observed before compiling.
//!
//! Any failure defers to the daemon path, which is unchanged.

use super::*;
use guard_policy_snapshot::{DirectLaneBindingV1, DirectLaneInputV1, DirectLaneStatV1};
use std::collections::{BTreeMap, BTreeSet};

/// The ACK lives in its own directory so that writing, renewing or unlinking
/// it never changes the state directory identity the publisher fences on.
pub(crate) const DIRECT_LANE_ACK_DIRECTORY: &str = "direct-lane";
pub(crate) const DIRECT_LANE_ACK_FILE_NAME: &str = "ack.json";
const DIRECT_LANE_ACK_SCHEMA: &str = "guard-direct-lane-ack.v1";
const DIRECT_LANE_ACK_MAX_BYTES: u64 = 1024;
/// A lease further ahead than this is not one the publisher would write.
const DIRECT_LANE_ACK_MAX_LEASE_MS: u64 = 120_000;

pub(crate) struct DirectLaneBinding {
    generation: u64,
    policy_digest: String,
    workspaces: BTreeSet<String>,
    inputs: Vec<DirectLaneInputV1>,
    pub(crate) home_dir: Option<String>,
    pub(crate) harness_postures: Option<BTreeMap<String, String>>,
    pub(crate) local_cli_block_rules: Option<bool>,
    pub(crate) evidence_drain: Option<bool>,
    pub(crate) contained_sink_command: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectLaneDefer {
    Unsupported,
    Unbound,
    SnapshotUnavailable,
    AckMissing,
    AckMismatch,
    AckExpired,
    WorkspaceUnknown,
    InputChanged,
}

impl DirectLaneDefer {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Unsupported => "direct_lane_unsupported",
            Self::Unbound => "direct_lane_unbound",
            Self::SnapshotUnavailable => "direct_lane_snapshot_unavailable",
            Self::AckMissing => "direct_lane_ack_missing",
            Self::AckMismatch => "direct_lane_ack_mismatch",
            Self::AckExpired => "direct_lane_ack_expired",
            Self::WorkspaceUnknown => "direct_lane_workspace_unknown",
            Self::InputChanged => "direct_lane_input_changed",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectLaneAckV1 {
    schema: String,
    generation: u64,
    policy_digest: String,
    lease_expires_at_ms: u64,
}

impl PolicySnapshotStore {
    /// Replace the binding with the one pushed for the accepted snapshot.
    /// A push without a binding clears it, closing the lane.
    pub(super) fn bind_direct_lane(
        &self,
        generation: u64,
        policy_digest: &str,
        binding: Option<DirectLaneBindingV1>,
    ) {
        let next = binding.map(|binding| {
            Arc::new(DirectLaneBinding {
                generation,
                policy_digest: policy_digest.to_owned(),
                workspaces: binding.workspaces.into_iter().collect(),
                inputs: binding.inputs,
                home_dir: binding.home_dir,
                harness_postures: binding.harness_postures,
                local_cli_block_rules: binding.local_cli_block_rules,
                evidence_drain: binding.evidence_drain,
                contained_sink_command: binding.contained_sink_command,
            })
        });
        match self.direct_lane.lock() {
            Ok(mut current) => *current = next,
            // A poisoned binding can never be read again, so the lane stays
            // closed; recover the lock only to drop what it held.
            Err(poisoned) => *poisoned.into_inner() = None,
        }
    }

    /// Admit the current snapshot for a direct hook in `workspace`, or name
    /// why the hook must take the daemon path.
    #[cfg(test)]
    pub(crate) fn admit_direct_lane(
        &self,
        workspace: &str,
    ) -> Result<Arc<AdmittedPolicySnapshot>, DirectLaneDefer> {
        self.admit_direct_hook(workspace)
            .map(|(snapshot, _binding)| snapshot)
    }

    /// The home the bound daemon gives a hook that names none.
    pub(crate) fn direct_lane_home_dir(&self) -> Option<String> {
        self.direct_lane.lock().ok().and_then(|binding| {
            binding
                .as_ref()
                .and_then(|binding| binding.home_dir.clone())
        })
    }

    /// Admission that also returns the binding, whose daemon state the
    /// direct hook operation checks next.
    pub(crate) fn admit_direct_hook(
        &self,
        workspace: &str,
    ) -> Result<(Arc<AdmittedPolicySnapshot>, Arc<DirectLaneBinding>), DirectLaneDefer> {
        if !cfg!(unix) {
            // Stat identity parity with the publisher is only established
            // for Unix filesystems.
            return Err(DirectLaneDefer::Unsupported);
        }
        let binding = self
            .direct_lane
            .lock()
            .ok()
            .and_then(|binding| binding.clone())
            .ok_or(DirectLaneDefer::Unbound)?;
        if !binding.workspaces.contains(workspace) {
            return Err(DirectLaneDefer::WorkspaceUnknown);
        }
        let snapshot = self
            .current_admitted_snapshot()
            .map_err(|_| DirectLaneDefer::SnapshotUnavailable)?;
        if snapshot.generation != binding.generation
            || snapshot.policy_digest != binding.policy_digest
        {
            return Err(DirectLaneDefer::Unbound);
        }
        let now = now_ms().map_err(|_| DirectLaneDefer::SnapshotUnavailable)?;
        let ack = self.read_direct_lane_ack()?;
        if ack.schema != DIRECT_LANE_ACK_SCHEMA
            || ack.generation != binding.generation
            || ack.policy_digest != binding.policy_digest
            || ack.lease_expires_at_ms > now.saturating_add(DIRECT_LANE_ACK_MAX_LEASE_MS)
        {
            return Err(DirectLaneDefer::AckMismatch);
        }
        if ack.lease_expires_at_ms <= now {
            return Err(DirectLaneDefer::AckExpired);
        }
        if binding
            .inputs
            .iter()
            .any(|input| observe_input(&input.path) != input.stat)
        {
            return Err(DirectLaneDefer::InputChanged);
        }
        Ok((snapshot, binding))
    }

    fn read_direct_lane_ack(&self) -> Result<DirectLaneAckV1, DirectLaneDefer> {
        let directory = self.state_base.join(DIRECT_LANE_ACK_DIRECTORY);
        match std::fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(DirectLaneDefer::AckMissing)
            }
            _ => {
                validate_private_directory(&directory).map_err(|_| DirectLaneDefer::AckMismatch)?
            }
        }
        let path = directory.join(DIRECT_LANE_ACK_FILE_NAME);
        let (value, _) = read_private_json(
            &path,
            DIRECT_LANE_ACK_MAX_BYTES,
            "direct_lane_ack",
            &self.state_base,
        )
        .map_err(|_| DirectLaneDefer::AckMismatch)?
        .ok_or(DirectLaneDefer::AckMissing)?;
        serde_json::from_value(value).map_err(|_| DirectLaneDefer::AckMismatch)
    }
}

/// Mirror the publisher's `Path.stat()` observation: symlinks are followed
/// and any error reads as absent.
#[cfg(unix)]
fn observe_input(path: &str) -> Option<DirectLaneStatV1> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).ok()?;
    Some(DirectLaneStatV1 {
        mtime_ns: metadata
            .mtime()
            .checked_mul(1_000_000_000)?
            .checked_add(metadata.mtime_nsec())?,
        size: metadata.size(),
        ino: metadata.ino(),
        ctime_ns: metadata
            .ctime()
            .checked_mul(1_000_000_000)?
            .checked_add(metadata.ctime_nsec())?,
    })
}

#[cfg(not(unix))]
fn observe_input(_path: &str) -> Option<DirectLaneStatV1> {
    None
}

#[cfg(all(test, unix))]
#[path = "policy_store_direct_lane_tests.rs"]
pub(crate) mod tests;
