//! Whether an operand of a command that only lists directories names
//! nothing but committed names.
//!
//! `ls app/security/secret-exfiltration` raises the credential-word signal
//! through the directory's name alone. `ls` prints names and never reads a
//! file, so a directory of the session's repository, or of one of its linked
//! worktrees, whose every entry that repository tracks shows only names
//! already committed. A path there that does not exist shows nothing at all.
//! A directory holding an untracked entry, a credential store, a `.git`
//! directory, a repository root, a checkout outside the session's
//! repository, or a recursive listing keeps the review.

use super::{read_index, TrackedFiles, MAX_ANCESTORS, STORE_DIRECTORIES};
use crate::CanonicalCommandV1;
use std::collections::HashSet;
use std::path::{Component, Path};

/// Entries one listed directory may hold for the proof to run.
const MAX_ENTRIES: usize = 512;

/// Whether every segment of `model` is a plain `ls` that lists no tree
/// below its operands.
pub(in crate::pretool) fn listing_only(model: &CanonicalCommandV1) -> bool {
    model.confidence == "exact"
        && !model.path_overridden
        && model.wrapper_chain.is_empty()
        && !model.segments.is_empty()
        && model.segments.iter().all(|segment| {
            segment.executable.as_deref() == Some("ls")
                && segment.environment_names.is_empty()
                && segment.wrapper_chain.is_empty()
                && !segment.path_overridden
                && !segment.arguments.iter().any(|argument| recursive(argument))
        })
}

/// `-R`, `--recursive`, or a short-option cluster holding `R`.
fn recursive(argument: &str) -> bool {
    argument == "--recursive"
        || (argument.starts_with('-') && !argument.starts_with("--") && argument[1..].contains('R'))
}

/// Whether `value`, an `ls` operand as the command spelled it, is a
/// directory of the session's repository family whose every entry the
/// repository tracks, or a path under such a family that does not exist.
pub(in crate::pretool) fn resolves_to_listed_directory(value: &str, cwd: Option<&str>) -> bool {
    let supplied = Path::new(value);
    if supplied
        .components()
        .any(|part| matches!(part, Component::ParentDir))
    {
        return false;
    }
    let target = match cwd {
        _ if supplied.is_absolute() => supplied.to_path_buf(),
        Some(cwd) => Path::new(cwd).join(supplied),
        None => return false,
    };
    let Some(workspace) = cwd.and_then(|root| std::fs::canonicalize(root).ok()) else {
        return false;
    };
    match std::fs::canonicalize(&target) {
        Ok(canonical) => in_family(&workspace, &canonical) && committed_directory(&canonical, true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // The nearest directory that exists must itself be a checkout
            // directory the listing proof would accept as a place, though
            // its entries need not all be committed: nothing under it is
            // listed.
            target
                .ancestors()
                .skip(1)
                .find(|ancestor| std::fs::symlink_metadata(ancestor).is_ok())
                .and_then(|ancestor| std::fs::canonicalize(ancestor).ok())
                .is_some_and(|ancestor| {
                    in_family(&workspace, &ancestor) && committed_directory(&ancestor, false)
                })
        }
        Err(_) => false,
    }
}

/// The session's repository, a linked worktree of it, or the primary
/// checkout a session running from a worktree was cut from.
fn in_family(workspace: &Path, path: &Path) -> bool {
    let root = |path: &Path| -> Option<std::path::PathBuf> {
        path.ancestors()
            .find(|directory| std::fs::symlink_metadata(directory.join(".git")).is_ok())
            .map(Path::to_path_buf)
    };
    root(workspace).is_some_and(|workspace_root| root(path) == Some(workspace_root))
        || super::super::worktree_writes::same_repository_worktree(workspace, path)
        || super::super::worktree_writes::primary_checkout_of_worktree(workspace, path)
}

/// Whether `directory` is a real directory below the root of the repository
/// holding it, outside `.git` and every credential store, and, when
/// `entries` is set, whether that repository tracks every entry it holds.
fn committed_directory(directory: &Path, entries: bool) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(directory) else {
        return false;
    };
    if !metadata.is_dir()
        || directory
            .components()
            .any(|part| part.as_os_str().eq_ignore_ascii_case(".git"))
    {
        return false;
    }
    let Some(repository) = directory
        .ancestors()
        .skip(1)
        .take(MAX_ANCESTORS)
        .find(|ancestor| std::fs::symlink_metadata(ancestor.join(".git")).is_ok())
    else {
        return false;
    };
    let Ok(relative) = directory.strip_prefix(repository) else {
        return false;
    };
    let store_part = |path: &Path| {
        path.components().any(|part| {
            part.as_os_str()
                .to_str()
                .is_none_or(|part| STORE_DIRECTORIES.contains(&part.to_ascii_lowercase().as_str()))
        })
    };
    if store_part(relative)
        || store_part(repository)
        || guard_secure_fs::credential_directory_path(relative)
        || guard_secure_fs::credential_directory_path(repository)
    {
        return false;
    }
    if !entries {
        return true;
    }
    let Some(prefix) = relative
        .components()
        .map(|part| part.as_os_str().to_str())
        .collect::<Option<Vec<_>>>()
        .map(|parts| format!("{}/", parts.join("/")).into_bytes())
    else {
        return false;
    };
    let mut tracked = TrackedFiles::default();
    let Some(index) = tracked
        .indexes
        .entry(repository.to_path_buf())
        .or_insert_with(|| read_index(repository))
        .as_ref()
    else {
        return false;
    };
    // The first component below the directory of every tracked name in it.
    let committed: HashSet<&[u8]> = index
        .iter()
        .filter_map(|name| name.strip_prefix(prefix.as_slice()))
        .map(|rest| rest.split(|byte| *byte == b'/').next().unwrap_or(rest))
        .collect();
    let Ok(listing) = std::fs::read_dir(directory) else {
        return false;
    };
    let mut seen = 0;
    for entry in listing {
        seen += 1;
        if seen > MAX_ENTRIES {
            return false;
        }
        let Ok(entry) = entry else {
            return false;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return false;
        };
        if !committed.contains(name.as_bytes()) {
            return false;
        }
    }
    true
}
