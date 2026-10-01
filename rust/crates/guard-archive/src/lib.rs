#![forbid(unsafe_code)]
//! Digest-bound, resource-bounded offline archive inspection.
//!
//! This crate owns the archive semantics retired from
//! `codex_plugin_scanner.guard.runtime.offline_archive_*`. It never extracts,
//! executes, or performs I/O beyond the descriptor-bound immutable blob it is
//! handed a path to. All limits are caller-supplied and hard-fail; there is no
//! ambient authority.

use std::path::Path;
use std::time::Instant;

mod manifest;
mod posix_path;
mod tar_policy;

/// Numeric inspection bounds supplied by the caller. Every bound is enforced
/// inside the inspection; exceeding any of them produces a typed result, never
/// an unchecked allocation.
#[derive(Debug, Clone, PartialEq)]
pub struct ArchiveCaps {
    pub max_archive_bytes: u64,
    pub max_files: u64,
    pub max_expanded_bytes: u64,
    pub max_member_bytes: u64,
    pub max_package_json_bytes: u64,
    pub max_decompression_ratio: f64,
    pub max_nested_archives: u64,
    pub max_path_depth: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveStatus {
    Clean,
    Blocked,
    Incomplete,
    /// The caller's liveness predicate asked inspection to stop. Consumers map
    /// this to their own cancelled surface; it is not user-visible.
    Halted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveOutcome {
    pub status: ArchiveStatus,
    pub code: &'static str,
    pub message: &'static str,
    pub severity: &'static str,
    /// The verified digest when hashing completed; `None` before that point.
    pub sha256: Option<String>,
    pub members_seen: u64,
    pub expanded_bytes: u64,
}

impl ArchiveOutcome {
    pub fn blocked(code: &'static str, message: &'static str, sha256: Option<String>) -> Self {
        Self {
            status: ArchiveStatus::Blocked,
            code,
            message,
            severity: "high",
            sha256,
            members_seen: 0,
            expanded_bytes: 0,
        }
    }

    pub fn incomplete(code: &'static str, message: &'static str, sha256: Option<String>) -> Self {
        Self {
            status: ArchiveStatus::Incomplete,
            code,
            message,
            severity: "high",
            sha256,
            members_seen: 0,
            expanded_bytes: 0,
        }
    }

    pub fn timeout(sha256: Option<String>) -> Self {
        Self::incomplete(
            "external_archive_inspection_timeout",
            "External archive inspection exceeded Guard's time limit.",
            sha256,
        )
    }

    fn clean(sha256: String, members_seen: u64, expanded_bytes: u64) -> Self {
        Self {
            status: ArchiveStatus::Clean,
            code: "external_archive_inspection_clean",
            message: "External archive completed bounded offline inspection.",
            severity: "low",
            sha256: Some(sha256),
            members_seen,
            expanded_bytes,
        }
    }

    pub fn halted() -> Self {
        Self {
            status: ArchiveStatus::Halted,
            code: "external_archive_inspection_incomplete",
            message: "External archive inspection was halted.",
            severity: "high",
            sha256: None,
            members_seen: 0,
            expanded_bytes: 0,
        }
    }
}

/// Inspect `path` as a digest-bound immutable archive.
///
/// Admission, hashing, decompression bounds, member policy, and manifest risk
/// evaluation all live here; `halt` is polled alongside `deadline` so the
/// runtime can stop inspection when its parent lease disappears.
pub fn inspect_path(
    path: &Path,
    expected_sha256: &str,
    caps: &ArchiveCaps,
    deadline: Instant,
    halt: &dyn Fn() -> bool,
) -> ArchiveOutcome {
    match tar_policy::inspect(path, expected_sha256, caps, deadline, halt) {
        Ok(stats) => ArchiveOutcome::clean(stats.sha256, stats.members, stats.expanded_bytes),
        Err(outcome) => outcome,
    }
}

// Blob admission is a Unix-only contract (descriptor walk, nlink/mode
// checks); the retired Python path also refused non-POSIX platforms, so the
// behavioral suite only runs there.
#[cfg(all(test, unix))]
#[path = "lib_tests.rs"]
mod tests;
