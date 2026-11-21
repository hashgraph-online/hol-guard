//! A file-less directory the current ACK already covers, admitted as the
//! daemon admits it.
//!
//! On the first hook in a directory the daemon does not wait for a publish
//! that names it: `workspace_admissible_without_overlay`
//! (`native_policy_snapshot_workspace_readiness.py`) covers the request on the
//! current ACK when the directory
//!
//! - is its own realpath and holds neither workspace overlay file, where any
//!   metadata failure other than a missing file counts as an overlay, and
//! - lies strictly under a workspace that snapshot settled, by path
//!   component, or has no ancestor that holds an overlay file.
//!
//! A workspace config reads only that directory's own overlay files, so a
//! file-less directory compiles to the home config the snapshot already
//! holds. An ancestor's overlay never applies to it either, but once that
//! ancestor settles the snapshot merges it strictest-first, so a directory
//! below an unsettled overlay still waits for it. Any other shape defers to
//! the daemon path.

use crate::package_authority_config::WORKSPACE_CONFIG_FILENAMES;
use guard_contracts::WorkspaceOverlayReadinessV1;
use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::{Component, Path};

/// Whether `workspace` is a file-less canonical directory that is a
/// subdirectory of one of the settled `workspaces` or has no ancestor overlay.
pub(super) fn file_less_covered(workspaces: &BTreeSet<String>, workspace: &str) -> bool {
    let candidate = Path::new(workspace);
    file_less_canonical(candidate)
        && (under_settled(workspaces, candidate) || overlay_free_ancestors(candidate))
}

/// Inspect the publisher's workspace spelling, without following links or
/// caching the absence of an overlay.
pub(crate) fn workspace_overlay_readiness(candidate: &Path) -> WorkspaceOverlayReadinessV1 {
    use WorkspaceOverlayReadinessV1::{DirectoryAndAncestors, DirectoryOnly, Unproven};

    if !candidate.is_absolute()
        || candidate
            .components()
            .any(|part| part == Component::ParentDir)
        || !publisher_spelling_without_links(candidate)
        || !overlay_absent(candidate)
    {
        return Unproven;
    }
    if overlay_free_ancestors(candidate) {
        DirectoryAndAncestors
    } else {
        DirectoryOnly
    }
}

#[cfg(not(windows))]
fn publisher_spelling_without_links(candidate: &Path) -> bool {
    candidate
        .ancestors()
        .all(|path| match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata.is_dir() && !metadata.is_symlink(),
            // A missing leaf can be covered by the ACK. Keep walking up to check
            // the spelling and overlay entries of its existing ancestors.
            Err(error) => error.kind() == ErrorKind::NotFound,
        })
}

#[cfg(windows)]
fn publisher_spelling_without_links(candidate: &Path) -> bool {
    use crate::daemon_edge_serve::plain_path_text;
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let mut existing = candidate.ancestors().skip_while(|path| {
        matches!(
            std::fs::symlink_metadata(path),
            Err(error) if error.kind() == ErrorKind::NotFound
        )
    });
    let Some(first_existing) = existing.next() else {
        return false;
    };
    let Ok(resolved) = std::fs::canonicalize(first_existing) else {
        return false;
    };
    let (Some(spelled), Some(resolved)) = (first_existing.to_str(), resolved.to_str()) else {
        return false;
    };
    let spelled = plain_path_text(spelled);
    let resolved = plain_path_text(resolved);
    let mut spelled_parts = Path::new(&spelled).components();
    let mut resolved_parts = Path::new(&resolved).components();
    // Case and 8.3 aliases can legitimately change the resolved spelling.
    // A different volume or a change in depth cannot be such an alias.
    let (Some(Component::Prefix(spelled_root)), Some(Component::Prefix(resolved_root))) =
        (spelled_parts.next(), resolved_parts.next())
    else {
        return false;
    };
    let same_root = spelled_root
        .as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&resolved_root.as_os_str().to_string_lossy());
    same_root
        && spelled_parts.count() == resolved_parts.count()
        && std::iter::once(first_existing).chain(existing).all(|path| {
            std::fs::symlink_metadata(path).is_ok_and(|metadata| {
                metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
            })
        })
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
