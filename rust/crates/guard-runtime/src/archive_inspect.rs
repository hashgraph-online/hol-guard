//! `archive-inspect --stdin`: bounded offline archive inspection.
//!
//! Reads one `ArchiveInspectionRequestV1` from stdin, applies the process
//! containment Python used to establish in a child interpreter (resource
//! limits, platform sandbox verification, no network/process capability),
//! then hands the digest-bound blob to `guard_archive`. Every inspection
//! outcome is a typed result on stdout with exit code 0; transport-level
//! failures exit nonzero so the caller fails closed.
//!
//! Admission, limits, sandbox application, and capability probes live in
//! `archive_inspect_containment`; this module owns request handling,
//! lifecycle supervision, and result binding.

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::sync::atomic::Ordering;
#[cfg(unix)]
use std::time::Duration;
use std::time::Instant;

use guard_archive::{ArchiveCaps, ArchiveOutcome, ArchiveStatus};
use guard_contracts::{
    ArchiveInspectionCountersV1, ArchiveInspectionRequestV1, ArchiveInspectionResultV1,
    ARCHIVE_CAP_ARCHIVE_BYTES, ARCHIVE_CAP_DECOMPRESSION_RATIO, ARCHIVE_CAP_EXPANDED_BYTES,
    ARCHIVE_CAP_FILES, ARCHIVE_CAP_MEMBER_BYTES, ARCHIVE_CAP_MEMORY_BYTES,
    ARCHIVE_CAP_NESTED_ARCHIVES, ARCHIVE_CAP_PACKAGE_JSON_BYTES, ARCHIVE_CAP_PATH_DEPTH,
    ARCHIVE_CAP_TIMEOUT_MS, ARCHIVE_INSPECTION_REQUEST_SCHEMA, ARCHIVE_INSPECTION_RESULT_SCHEMA,
};
use sha2::{Digest, Sha256};

use crate::archive_inspect_containment::sandbox_unavailable;
#[cfg(target_os = "macos")]
use crate::archive_inspect_containment::warm_allocator_regions;
#[cfg(unix)]
use crate::archive_inspect_containment::{
    acquire_archive_lease, apply_capability_deny, apply_child_limits, network_capability_denied,
    spawn_capability_denied, write_capability_denied,
};

const MAX_ARCHIVE_PATH_BYTES: usize = 16 * 1024;

/// Arm parent-death termination and capture the spawning process identity.
/// On Linux the kernel delivers SIGKILL when the parent thread dies — even
/// for a parent that exits while this worker is mid-parse. Darwin has no
/// equivalent, so `run_inspection` also watches the inherited liveness pipe
/// and polls `getppid` for a reparent onto init.
#[cfg(unix)]
fn arm_parent_death_guard() -> i32 {
    #[cfg(target_os = "linux")]
    {
        let _ = nix::sys::prctl::set_pdeathsig(Some(nix::sys::signal::Signal::SIGKILL));
    }
    nix::unistd::getppid().as_raw()
}

pub(crate) fn evaluate_archive_inspection_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    #[cfg(unix)]
    let original_parent = arm_parent_death_guard();
    #[cfg(not(unix))]
    let original_parent = 0i32;
    let value = crate::strict_json_value(bytes)?;
    let request: ArchiveInspectionRequestV1 = serde_json::from_value(value)
        .map_err(|_| "archive_inspection_request_invalid".to_owned())?;
    let request_sha256 = hex::encode(Sha256::digest(bytes));
    // Self-hash up front, inside the caller's budget: hashing the runtime
    // binary after inspection could push the result write past the kill, and
    // a contender that loses the lease should not wait on it either.
    let runtime_sha256 = crate::resident_state::runtime_digest()?;
    let outcome = match validated_caps(&request) {
        Some(caps) => run_inspection(&request, caps, original_parent, started),
        None => ArchiveOutcome::incomplete(
            "external_archive_inspection_policy_invalid",
            "External archive inspection policy is invalid.",
            None,
        ),
    };
    let result = ArchiveInspectionResultV1 {
        schema: ARCHIVE_INSPECTION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: match outcome.status {
            ArchiveStatus::Clean => "clean",
            ArchiveStatus::Blocked => "blocked",
            ArchiveStatus::Incomplete | ArchiveStatus::Halted => "incomplete",
        }
        .to_owned(),
        code: outcome.code.to_owned(),
        message: outcome.message.to_owned(),
        severity: outcome.severity.to_owned(),
        sha256: outcome.sha256,
        runtime_sha256,
        counters: ArchiveInspectionCountersV1 {
            members: outcome.members_seen,
            expanded_bytes: outcome.expanded_bytes,
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
    };
    serde_json::to_vec(&result).map_err(|_| "archive_inspection_encode_failed".to_owned())
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validated_caps(request: &ArchiveInspectionRequestV1) -> Option<ArchiveCaps> {
    let caps = &request.caps;
    let valid = request.schema == ARCHIVE_INSPECTION_REQUEST_SCHEMA
        && is_lower_hex(&request.request_id, 32)
        && !request.archive_path.is_empty()
        && request.archive_path.len() <= MAX_ARCHIVE_PATH_BYTES
        && is_lower_hex(&request.expected_sha256, 64)
        && !request.state_dir.is_empty()
        && request.state_dir.len() <= MAX_ARCHIVE_PATH_BYTES
        && request.timeout_ms > 0
        && request.timeout_ms <= ARCHIVE_CAP_TIMEOUT_MS
        && caps.max_archive_bytes > 0
        && caps.max_archive_bytes <= ARCHIVE_CAP_ARCHIVE_BYTES
        && caps.max_files > 0
        && caps.max_files <= ARCHIVE_CAP_FILES
        && caps.max_expanded_bytes > 0
        && caps.max_expanded_bytes <= ARCHIVE_CAP_EXPANDED_BYTES
        && caps.max_member_bytes > 0
        && caps.max_member_bytes <= ARCHIVE_CAP_MEMBER_BYTES
        && caps.max_package_json_bytes > 0
        && caps.max_package_json_bytes <= ARCHIVE_CAP_PACKAGE_JSON_BYTES
        && caps.max_memory_bytes > 0
        && caps.max_memory_bytes <= ARCHIVE_CAP_MEMORY_BYTES
        && caps.max_decompression_ratio.is_finite()
        && caps.max_decompression_ratio > 0.0
        && caps.max_decompression_ratio <= ARCHIVE_CAP_DECOMPRESSION_RATIO
        && caps.max_nested_archives <= ARCHIVE_CAP_NESTED_ARCHIVES
        && caps.max_path_depth > 0
        && caps.max_path_depth <= ARCHIVE_CAP_PATH_DEPTH;
    if !valid {
        return None;
    }
    Some(ArchiveCaps {
        max_archive_bytes: caps.max_archive_bytes,
        max_files: caps.max_files,
        max_expanded_bytes: caps.max_expanded_bytes,
        max_member_bytes: caps.max_member_bytes,
        max_package_json_bytes: caps.max_package_json_bytes,
        max_decompression_ratio: caps.max_decompression_ratio,
        max_nested_archives: caps.max_nested_archives,
        max_path_depth: caps.max_path_depth,
    })
}

#[cfg(not(unix))]
fn run_inspection(
    _request: &ArchiveInspectionRequestV1,
    _caps: ArchiveCaps,
    _original_parent: i32,
    _started: Instant,
) -> ArchiveOutcome {
    sandbox_unavailable()
}

#[cfg(unix)]
fn run_inspection(
    request: &ArchiveInspectionRequestV1,
    caps: ArchiveCaps,
    original_parent: i32,
    started: Instant,
) -> ArchiveOutcome {
    // Warm the allocator before measuring address space: Darwin's malloc
    // creates size-class zones lazily and each zone reserves hundreds of MB
    // of VM. Measuring first would set RLIMIT_AS below those reservations
    // and turn ordinary post-limit allocations into sporadic aborts.
    #[cfg(target_os = "macos")]
    warm_allocator_regions();
    // Arm the inherited liveness channel before containment: the watcher
    // thread it spawns would itself be denied by the clone/exec deny rules.
    // When the supervising caller dies the pipe write-end closes and the
    // flag flips — including a death that landed before this worker started.
    let parent_alive = match crate::resident_transport_service::resident_parent_liveness() {
        Ok(flag) => flag,
        Err(_) => {
            return ArchiveOutcome::incomplete(
                "external_archive_inspection_orphaned",
                "External archive inspection lost its supervising process.",
                None,
            );
        }
    };
    let has_liveness_channel = std::env::var_os(crate::PARENT_LIVENESS_FD_ENV).is_some();
    // Lease next: it needs a writable open, so it must happen before the
    // capability deny turns off file-write*. Holding the `File` keeps the
    // kernel lock until this process exits, covering crash paths.
    let lease = match acquire_archive_lease(&request.state_dir) {
        Ok(Some(lease)) => lease,
        Ok(None) => {
            return ArchiveOutcome::incomplete(
                "external_archive_inspection_overloaded",
                "External archive inspection capacity is currently saturated.",
                None,
            );
        }
        Err(outcome) => return outcome,
    };
    let (_lease_file, lease_path) = lease;
    if !apply_child_limits(request.timeout_ms, request.caps.max_memory_bytes) {
        return sandbox_unavailable();
    }
    if !apply_capability_deny() {
        return sandbox_unavailable();
    }
    // Containment is proven, not assumed: network egress, file writes, and
    // child creation must all observably fail before untrusted bytes are
    // parsed. Any surviving capability means no sandbox is active.
    if !network_capability_denied()
        || !write_capability_denied(&lease_path)
        || !spawn_capability_denied()
    {
        return sandbox_unavailable();
    }
    // Orphaned workers have no caller left to answer. A closed liveness pipe
    // is authoritative; a ppid that changed since capture means init adopted
    // us. When no channel was supplied, a PID-1 parent cannot be proven
    // alive, so it is refused — adapters always pass the channel.
    if !parent_alive.load(Ordering::Acquire)
        || nix::unistd::getppid().as_raw() != original_parent
        || (!has_liveness_channel && original_parent <= 1)
    {
        return ArchiveOutcome::incomplete(
            "external_archive_inspection_orphaned",
            "External archive inspection lost its supervising process.",
            None,
        );
    }
    // The granted timeout covers this worker's whole in-process run —
    // request parsing, the runtime self-hash, lease acquisition, and
    // containment all happened since `started`, so the deadline anchors
    // there rather than restarting the budget at the inspection loop.
    let deadline = started + Duration::from_millis(request.timeout_ms);
    // If the spawning parent disappears the inspection is orphaned: stop
    // rather than burn the budget unattributed.
    let halt = move || {
        !parent_alive.load(Ordering::Acquire) || nix::unistd::getppid().as_raw() != original_parent
    };
    guard_archive::inspect_path(
        Path::new(&request.archive_path),
        &request.expected_sha256,
        &caps,
        deadline,
        &halt,
    )
}
