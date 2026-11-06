//! Bounded, symlink-free discovery of the files a plugin source declares.
//!
//! The Kit reads repositories it did not write, so every walk is capped by
//! depth, entry count and file size, never follows a symlink, and skips the
//! directories that hold dependencies or build output.

use std::fs;
use std::path::{Path, PathBuf};

use crate::config::Excludes;

pub(crate) const MAX_DEPTH: usize = 5;
pub(crate) const MAX_ENTRIES: usize = 20_000;
pub(crate) const MAX_TEXT_BYTES: u64 = 1024 * 1024;

const SKIPPED_DIRECTORIES: &[&str] = &[
    ".git",
    ".hg",
    ".next",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
    "vendor",
    "venv",
];

/// Every regular file under `root`, relative to it, sorted. Hidden plugin
/// manifest directories (`.claude-plugin`, `.codex-plugin`) are walked.
/// `prefix` is `root` relative to the repository, so `excludes` can match
/// repository paths; an excluded directory is skipped without counting its
/// entries toward the walk's limit.
pub(crate) fn files(
    root: &Path,
    prefix: &str,
    excludes: &Excludes,
) -> Result<Vec<PathBuf>, String> {
    let repository_path = |relative: &Path| {
        let relative = display(relative);
        if prefix.is_empty() {
            relative
        } else {
            format!("{prefix}/{relative}")
        }
    };
    let mut found = Vec::new();
    let mut visited = 0usize;
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((directory, depth)) = stack.pop() {
        // A folder the Kit packaged earlier is output, not source.
        if depth > 0 && fs::symlink_metadata(directory.join(crate::PROVENANCE_FILE)).is_ok() {
            continue;
        }
        let entries = fs::read_dir(&directory).map_err(|_| "plugin_kit_root_unreadable")?;
        for entry in entries {
            let entry = entry.map_err(|_| "plugin_kit_root_unreadable")?;
            visited += 1;
            if visited > MAX_ENTRIES {
                return Err("plugin_kit_repository_too_large".to_owned());
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            let Ok(relative) = path.strip_prefix(root) else {
                continue;
            };
            if file_type.is_dir() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if depth < MAX_DEPTH
                    && !SKIPPED_DIRECTORIES.contains(&name.as_ref())
                    && !excludes.directory(&repository_path(relative))
                {
                    stack.push((path, depth + 1));
                }
            } else if file_type.is_file() && !excludes.file(&repository_path(relative)) {
                found.push(relative.to_path_buf());
            }
        }
    }
    found.sort();
    Ok(found)
}

/// The UTF-8 text of a regular file no larger than [`MAX_TEXT_BYTES`].
pub(crate) fn read_text(path: &Path) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_TEXT_BYTES {
        return None;
    }
    String::from_utf8(fs::read(path).ok()?).ok()
}

/// The bytes of a regular file no larger than `limit`.
pub(crate) fn read_bytes(path: &Path, limit: u64) -> Option<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > limit {
        return None;
    }
    fs::read(path).ok()
}

/// A path relative to the root, written with `/` on every platform.
pub(crate) fn display(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}
