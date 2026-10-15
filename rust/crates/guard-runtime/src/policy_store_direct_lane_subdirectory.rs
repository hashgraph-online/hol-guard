//! A file-less directory the current ACK already covers, admitted as the
//! daemon admits it.
//!
//! On the first hook in a directory the daemon does not wait for a publish
//! that names it: `workspace_admissible_without_overlay`
//! (`native_policy_snapshot_workspace_readiness.py`) covers the request on the
//! current ACK when the directory
//!
//! - is its own realpath and holds neither workspace overlay file, where any
//!   `lstat` failure other than a missing file counts as an overlay
//!   (`_file_less_canonical_workspace`), and
//! - lies strictly under a workspace that snapshot settled, by path
//!   component (`_under_settled_workspace_locked`), or has no ancestor that
//!   holds an overlay file (`_overlay_free_ancestors`).
//!
//! A workspace config reads only that directory's own overlay files, so a
//! file-less directory compiles to the home config the snapshot already
//! holds. An ancestor's overlay never applies to it either, but once that
//! ancestor settles the snapshot merges it strictest-first, so a directory
//! below an unsettled overlay still waits for it. Any other shape defers to
//! the daemon path.

use crate::package_authority_config::WORKSPACE_CONFIG_FILENAMES;
use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::Path;

/// Whether `workspace` is a file-less canonical directory that is a
/// subdirectory of one of the settled `workspaces` or has no ancestor overlay.
pub(super) fn file_less_covered(workspaces: &BTreeSet<String>, workspace: &str) -> bool {
    let candidate = Path::new(workspace);
    file_less_canonical(candidate)
        && (under_settled(workspaces, candidate) || overlay_free_ancestors(candidate))
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
    overlay_absent(candidate)
}

/// No strict ancestor of the canonical candidate holds an overlay file.
fn overlay_free_ancestors(candidate: &Path) -> bool {
    candidate.is_absolute() && candidate.ancestors().skip(1).all(overlay_absent)
}

/// Every overlay file name is absent from `directory`.
fn overlay_absent(directory: &Path) -> bool {
    WORKSPACE_CONFIG_FILENAMES.iter().all(|name| {
        matches!(
            std::fs::symlink_metadata(directory.join(name)),
            Err(error) if error.kind() == ErrorKind::NotFound
        )
    })
}

#[cfg(all(test, unix))]
#[path = "policy_store_direct_lane_subdirectory_tests.rs"]
mod tests;
