//! A file-less subdirectory of a settled workspace, admitted as the daemon
//! admits it.
//!
//! After a `cd` into a subdirectory the daemon does not wait for a publish
//! that names it: `workspace_admissible_without_overlay`
//! (`native_policy_snapshot_workspace_readiness.py`) covers the request on the
//! current ACK when the subdirectory
//!
//! - lies strictly under a workspace that snapshot settled, by path
//!   component (`_under_settled_workspace_locked`), and
//! - is its own realpath and holds neither workspace overlay file, where any
//!   `lstat` failure other than a missing file counts as an overlay
//!   (`_file_less_canonical_workspace`).
//!
//! The daemon reads only the subdirectory's own overlay files, so an overlay
//! in an intermediate directory does not stop it; this check reads the same
//! files. Any other shape defers to the daemon path.

use crate::package_authority_config::WORKSPACE_CONFIG_FILENAMES;
use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::Path;

/// Whether `workspace` is a file-less canonical subdirectory of one of the
/// settled `workspaces`.
pub(super) fn file_less_subdirectory(workspaces: &BTreeSet<String>, workspace: &str) -> bool {
    let candidate = Path::new(workspace);
    under_settled(workspaces, candidate) && file_less_canonical(candidate)
}

/// `any(candidate != parent and candidate.is_relative_to(parent))`: a strict
/// ancestor by path component, never by string prefix.
fn under_settled(workspaces: &BTreeSet<String>, candidate: &Path) -> bool {
    candidate.is_absolute()
        && candidate.ancestors().skip(1).any(|parent| {
            parent
                .to_str()
                .is_some_and(|parent| workspaces.contains(parent))
        })
}

/// The candidate is its own realpath, byte for byte, and every overlay file
/// name is absent.
fn file_less_canonical(candidate: &Path) -> bool {
    match std::fs::canonicalize(candidate) {
        Ok(real) if real.as_os_str() == candidate.as_os_str() => {}
        _ => return false,
    }
    WORKSPACE_CONFIG_FILENAMES.iter().all(|name| {
        matches!(
            std::fs::symlink_metadata(candidate.join(name)),
            Err(error) if error.kind() == ErrorKind::NotFound
        )
    })
}

#[cfg(all(test, unix))]
#[path = "policy_store_direct_lane_subdirectory_tests.rs"]
mod tests;
