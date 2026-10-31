//! The coverage walk for `release_manifest_verify`: every regular file under
//! a machine runtime, within the traversal budget.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use super::files::is_reparse_point;
use super::{Invalid, Limits};

pub(super) enum Coverage {
    /// `unnameable` when a file's name is not UTF-8, so no listed path names it.
    Files {
        paths: BTreeSet<String>,
        unnameable: bool,
    },
    Refused(&'static str),
}

/// Every regular file under the runtime but the manifest, as a `/`-joined
/// relative path. A link, a reparse point or any other non-regular entry is an
/// escape.
pub(super) fn runtime_file_paths(
    runtime_root: &Path,
    manifest_path: &Path,
    limits: &Limits,
) -> Result<Coverage, Invalid> {
    let manifest_relative = manifest_path
        .strip_prefix(runtime_root)
        .map_err(|_| Invalid)?;
    let deadline = Instant::now() + limits.traversal;
    let mut files = BTreeSet::new();
    let mut unnameable = false;
    let mut directory_count = 1_usize;
    let mut entry_count = 0_usize;
    let mut pending: Vec<PathBuf> = vec![runtime_root.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in std::fs::read_dir(&current)? {
            let entry = entry?;
            entry_count += 1;
            if entry_count > limits.runtime_entries || Instant::now() > deadline {
                return Ok(Coverage::Refused("release_manifest_file_limit_exceeded"));
            }
            let metadata = entry.metadata()?;
            if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
                return Ok(Coverage::Refused("release_manifest_path_escape"));
            }
            let candidate = entry.path();
            if metadata.is_dir() {
                directory_count += 1;
                if directory_count > limits.runtime_directories {
                    return Ok(Coverage::Refused("release_manifest_file_limit_exceeded"));
                }
                pending.push(candidate);
                continue;
            }
            if !metadata.is_file() {
                return Ok(Coverage::Refused("release_manifest_path_escape"));
            }
            let relative = candidate.strip_prefix(runtime_root).map_err(|_| Invalid)?;
            if relative == manifest_relative {
                continue;
            }
            let Some(relative) = posix_relative(relative) else {
                unnameable = true;
                continue;
            };
            files.insert(relative);
            if files.len() > limits.runtime_files {
                return Ok(Coverage::Refused("release_manifest_file_limit_exceeded"));
            }
        }
    }
    Ok(Coverage::Files {
        paths: files,
        unnameable,
    })
}

fn posix_relative(relative: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?),
            _ => return None,
        }
    }
    Some(parts.join("/"))
}
