//! The sweep of temporary files that interrupted atomic writes left behind.
//!
//! Guard writes a state file by creating `.<name>.<suffix>.tmp` beside it,
//! filling it and renaming it over the target. A process killed between the
//! create and the write leaves an empty temporary file that nothing reads or
//! removes. A completed maintenance pass deletes those that are:
//!
//! - in the Guard home, `native-runtime` or `native-runtime/direct-lane`,
//!   reached through no linked path component;
//! - named with a leading dot, the `.tmp` extension and a suffix between the
//!   target name and the extension;
//! - regular files (never links), still empty, unchanged for a day, and on
//!   Unix owned by the user the daemon runs as.
//!
//! A file with content is never deleted: it may be a write that is still in
//! flight or the only copy of state a crash interrupted.

use std::fs;
use std::path::Path;

use super::{components_unlinked, modified_seconds};

/// The directories whose atomic writes leave temporary files.
const SWEPT_DIRECTORIES: [&str; 3] = ["", "native-runtime", "native-runtime/direct-lane"];

/// How long an empty temporary file must stay unchanged before it counts as
/// abandoned.
pub(super) const ABANDONED_AFTER_SECONDS: f64 = 24.0 * 60.0 * 60.0;

/// Delete the abandoned empty temporary files under `guard_home` and answer
/// how many were removed.
pub(super) fn prune_abandoned_temp_files(guard_home: &Path, now: f64) -> u64 {
    let cutoff = now - ABANDONED_AFTER_SECONDS;
    SWEPT_DIRECTORIES
        .iter()
        .map(|relative| {
            let directory = if relative.is_empty() {
                guard_home.to_path_buf()
            } else {
                guard_home.join(relative)
            };
            prune_directory(&directory, cutoff)
        })
        .sum()
}

fn prune_directory(directory: &Path, cutoff: f64) -> u64 {
    if !components_unlinked(directory) {
        return 0;
    }
    let Ok(children) = fs::read_dir(directory) else {
        return 0;
    };
    let mut removed = 0;
    for child in children {
        let Ok(child) = child else {
            break;
        };
        let name = child.file_name();
        if !name.to_str().is_some_and(is_temp_name) {
            continue;
        }
        let path = child.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.file_type().is_file()
            || metadata.len() != 0
            || modified_seconds(&metadata) > cutoff
            || !owned_by_this_user(&metadata)
        {
            continue;
        }
        if fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// `.<target>.<suffix>.tmp`, with a non-empty target and suffix.
fn is_temp_name(name: &str) -> bool {
    let Some(inner) = name
        .strip_prefix('.')
        .and_then(|rest| rest.strip_suffix(".tmp"))
    else {
        return false;
    };
    match inner.rsplit_once('.') {
        Some((target, suffix)) => !target.is_empty() && !suffix.is_empty(),
        None => false,
    }
}

#[cfg(unix)]
fn owned_by_this_user(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.uid() == nix::unistd::geteuid().as_raw()
}

#[cfg(not(unix))]
fn owned_by_this_user(_metadata: &fs::Metadata) -> bool {
    true
}

#[cfg(test)]
#[path = "storage_retention_temp_tests.rs"]
mod tests;
