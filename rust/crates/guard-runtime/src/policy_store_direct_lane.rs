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
//! - the request workspace was settled by this snapshot, or, for a hook, is a
//!   file-less canonical subdirectory of one
//!   (`policy_store_direct_lane_subdirectory.rs`);
//! - every watched non-database input still has the stat identity the
//!   publisher observed before compiling.
//!
//! Any failure defers to the daemon path, which is unchanged.

use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use guard_policy_snapshot::{
    DirectLaneBindingV1, DirectLaneEnvironmentV1, DirectLaneInputV1,
    DirectLanePolicyIntegrityStateV1, DirectLaneSecretV1, DirectLaneStatV1,
};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// The ACK lives in its own directory so that writing, renewing or unlinking
/// it never changes the state directory identity the publisher fences on.
pub(crate) const DIRECT_LANE_ACK_DIRECTORY: &str = "direct-lane";
pub(crate) const DIRECT_LANE_ACK_FILE_NAME: &str = "ack.json";
const DIRECT_LANE_ACK_SCHEMA: &str = "guard-direct-lane-ack.v1";
const DIRECT_LANE_ACK_MAX_BYTES: u64 = 1024;
/// A lease further ahead than this is not one the publisher would write.
const DIRECT_LANE_ACK_MAX_LEASE_MS: u64 = 120_000;
/// How long a hook waits for the ACK of a snapshot the resident has already
/// bound. The publisher writes the ACK as soon as the resident accepts the
/// push, so this covers one ACK write, not a publish.
const DIRECT_LANE_ACK_SETTLE: Duration = Duration::from_millis(100);
const DIRECT_LANE_ACK_SETTLE_POLL: Duration = Duration::from_millis(5);

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
    pub(crate) integrity_key: Option<DirectLaneIntegrityKey>,
    /// The daemon's process environment for exact-action proofs.
    pub(crate) exact_action_environment: Option<DirectLaneEnvironmentV1>,
    /// The daemon's extension-control digest for exact-action proofs.
    pub(crate) exact_action_control_digest: Option<String>,
    /// The policy-integrity state the daemon refreshed when it published.
    pub(crate) policy_integrity_state: Option<DirectLanePolicyIntegrityStateV1>,
    /// What the daemon queues a reviewed `PreToolUse` for approval with.
    pub(crate) review: DirectLaneReviewFacts,
    /// The managed-policy view the daemon resolves Pi structured output
    /// mediation from.
    pub(crate) structured_output_config: Option<serde_json::Value>,
    /// The tool-call view the daemon decides a relayed MCP tool call with.
    pub(crate) mcp_relay: Option<serde_json::Value>,
}

/// The daemon's policy-integrity key, held only in memory.
pub(crate) struct DirectLaneIntegrityKey {
    pub(crate) key: Zeroizing<Vec<u8>>,
    pub(crate) key_id: String,
}

impl DirectLaneIntegrityKey {
    /// The bound key, or `None` when it does not decode; the hooks that need
    /// it then stay with the daemon.
    fn decode(key_b64: Option<DirectLaneSecretV1>, key_id: Option<String>) -> Option<Self> {
        let encoded = Zeroizing::new(key_b64?.0);
        let key = Zeroizing::new(Base64UrlUnpadded::decode_vec(&encoded).ok()?);
        if key.is_empty() {
            return None;
        }
        Some(Self {
            key,
            key_id: key_id?,
        })
    }
}

#[cfg(test)]
impl DirectLaneBinding {
    /// A binding with no admitted inputs and no optional state, for tests of
    /// the hooks that read its state.
    pub(crate) fn empty_for_tests() -> Self {
        Self {
            generation: 1,
            policy_digest: String::new(),
            workspaces: BTreeSet::new(),
            inputs: Vec::new(),
            home_dir: None,
            harness_postures: None,
            local_cli_block_rules: None,
            evidence_drain: None,
            contained_sink_command: None,
            integrity_key: None,
            exact_action_environment: None,
            exact_action_control_digest: None,
            policy_integrity_state: None,
            review: DirectLaneReviewFacts::default(),
            structured_output_config: None,
            mcp_relay: None,
        }
    }
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
                integrity_key: DirectLaneIntegrityKey::decode(
                    binding.integrity_key_b64,
                    binding.integrity_key_id,
                ),
                exact_action_environment: binding.exact_action_environment,
                exact_action_control_digest: binding.exact_action_control_digest,
                policy_integrity_state: binding.policy_integrity_state,
                review: DirectLaneReviewFacts::parse(
                    binding.blocked_request_mode,
                    binding.approval_center_origin,
                    binding.review_oauth_source,
                    binding.review_host_cwd,
                ),
                structured_output_config: binding.structured_output_config,
                mcp_relay: binding.mcp_relay,
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
    #[cfg(all(test, unix))]
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
    /// direct operation checks next.
    pub(crate) fn admit_direct_hook(
        &self,
        workspace: &str,
    ) -> Result<(Arc<AdmittedPolicySnapshot>, Arc<DirectLaneBinding>), DirectLaneDefer> {
        self.admit_direct(workspace, false)
    }

    /// Hook admission, which also covers a file-less subdirectory of a
    /// settled workspace on the current ACK, as the daemon's hook readiness
    /// does (`policy_store_direct_lane_subdirectory.rs`).
    pub(crate) fn admit_direct_hook_or_subdirectory(
        &self,
        workspace: &str,
    ) -> Result<(Arc<AdmittedPolicySnapshot>, Arc<DirectLaneBinding>), DirectLaneDefer> {
        self.admit_direct(workspace, true)
    }

    fn admit_direct(
        &self,
        workspace: &str,
        file_less_subdirectory: bool,
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
        let known = binding.workspaces.contains(workspace)
            || (file_less_subdirectory
                && subdirectory::file_less_subdirectory(&binding.workspaces, workspace));
        if !known {
            return Err(DirectLaneDefer::WorkspaceUnknown);
        }
        let snapshot = self.admit_binding_lease(&binding)?;
        if binding
            .inputs
            .iter()
            .any(|input| observe_input(&input.path) != input.stat)
        {
            return Err(DirectLaneDefer::InputChanged);
        }
        Ok((snapshot, binding))
    }

    /// The bound binding while its lease holds, for a hook that reads no
    /// policy input, such as the Claude permission notice lane.
    pub(crate) fn admit_direct_binding(&self) -> Result<Arc<DirectLaneBinding>, DirectLaneDefer> {
        if !cfg!(unix) {
            return Err(DirectLaneDefer::Unsupported);
        }
        let binding = self
            .direct_lane
            .lock()
            .ok()
            .and_then(|binding| binding.clone())
            .ok_or(DirectLaneDefer::Unbound)?;
        self.admit_binding_lease(&binding)?;
        Ok(binding)
    }

    /// The admitted snapshot when `binding` matches it and the publisher's
    /// ACK lease for it is current.
    fn admit_binding_lease(
        &self,
        binding: &DirectLaneBinding,
    ) -> Result<Arc<AdmittedPolicySnapshot>, DirectLaneDefer> {
        let snapshot = self
            .current_admitted_snapshot()
            .map_err(|_| DirectLaneDefer::SnapshotUnavailable)?;
        if snapshot.generation != binding.generation
            || snapshot.policy_digest != binding.policy_digest
        {
            return Err(DirectLaneDefer::Unbound);
        }
        let (ack, waited) = self.settled_direct_lane_ack(binding.generation)?;
        // The settle wait can sleep, so the lease is judged against the clock
        // after it, and after a wait the snapshot must still be the bound one.
        let now = now_ms().map_err(|_| DirectLaneDefer::SnapshotUnavailable)?;
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
        if waited {
            let current = self
                .current_admitted_snapshot()
                .map_err(|_| DirectLaneDefer::SnapshotUnavailable)?;
            if current.generation != binding.generation
                || current.policy_digest != binding.policy_digest
            {
                return Err(DirectLaneDefer::Unbound);
            }
            return Ok(current);
        }
        Ok(snapshot)
    }

    /// The ACK file, re-read briefly while it still names a generation older
    /// than the bound one. The publisher pushes the binding before it writes
    /// the ACK, so a hook in that window would otherwise take the daemon
    /// path and wait there for the same ACK. Only a live ACK from the
    /// publisher is worth waiting on, and the first hook to see a generation
    /// claims its wait: an ACK that never catches up delays one hook, and
    /// hooks that arrive meanwhile defer at once.
    fn settled_direct_lane_ack(
        &self,
        generation: u64,
    ) -> Result<(DirectLaneAckV1, bool), DirectLaneDefer> {
        let mut ack = self.read_direct_lane_ack()?;
        if ack.generation >= generation
            || !live_publisher_ack(&ack)
            || self
                .direct_lane_ack_wait_claimed
                .fetch_max(generation, Ordering::AcqRel)
                >= generation
        {
            return Ok((ack, false));
        }
        let deadline = Instant::now() + DIRECT_LANE_ACK_SETTLE;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok((ack, true));
            }
            std::thread::sleep(DIRECT_LANE_ACK_SETTLE_POLL.min(deadline - now));
            ack = self.read_direct_lane_ack()?;
            if ack.generation >= generation {
                return Ok((ack, true));
            }
        }
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

/// Whether `ack` is one the publisher wrote and still renews.
fn live_publisher_ack(ack: &DirectLaneAckV1) -> bool {
    let Ok(now) = now_ms() else {
        return false;
    };
    ack.schema == DIRECT_LANE_ACK_SCHEMA
        && ack.lease_expires_at_ms > now
        && ack.lease_expires_at_ms <= now.saturating_add(DIRECT_LANE_ACK_MAX_LEASE_MS)
}

#[path = "policy_store_direct_lane_subdirectory.rs"]
mod subdirectory;

#[path = "policy_store_direct_lane_review.rs"]
mod review;
pub(crate) use review::{DirectLaneReviewFacts, HOOK_DIRECT_REVIEW_FACTS_FEATURE};

#[cfg(all(test, unix))]
#[path = "policy_store_direct_lane_tests.rs"]
pub(crate) mod tests;
