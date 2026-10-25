//! The bounded, no-follow directory walk behind `workspace-snapshot`.

use std::ffi::OsStr;

use guard_command::local_supply_chain::is_audit_sensitive_basename;
use sha2::{Digest, Sha256};

use super::{Limits, SnapshotMode, SKIP_DIRS};
use crate::workspace_snapshot_file::{hash_stable, DirHandle, HashError, Kind, Node};

/// Directories nested deeper than this below the root are recorded, not
/// listed.
pub(super) const MAX_WALK_DEPTH: usize = 64;

/// Basenames whose content detectors read for dependency risk. An oversize
/// file in this set leaves the snapshot partial instead of merely excluded.
const DETECTOR_INPUT_BASENAMES: [&str; 25] = [
    "package.json",
    "requirements.txt",
    "constraints.txt",
    "pyproject.toml",
    "Pipfile",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "composer.json",
    "Gemfile",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
    "poetry.lock",
    "uv.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "gradle.lockfile",
    "composer.lock",
    "Gemfile.lock",
];

#[derive(Default)]
pub(super) struct Walk {
    /// `path\0size\0sha256` (content) or `path\0size\0mtime\0ino` (stat).
    pub(super) entries: Vec<String>,
    /// Exclusion records are digested in walk order, which is deterministic
    /// because each directory is visited in sorted name order; none is ever
    /// dropped from the identity.
    pub(super) exclusions: Sha256,
    pub(super) exclusion_count: usize,
    pub(super) visited: usize,
    pub(super) hashed_bytes: u64,
    pub(super) counts: ExclusionCounts,
    pub(super) unreadable: usize,
    pub(super) unstable: usize,
    pub(super) entry_cap_hit: bool,
    pub(super) byte_cap_hit: bool,
    pub(super) oversize_detector_input: bool,
    pub(super) depth_cap_hit: bool,
    pub(super) visit_cap_hit: bool,
}

#[derive(Default)]
pub(super) struct ExclusionCounts {
    pub(super) directories: usize,
    pub(super) sensitive: usize,
    pub(super) oversize: usize,
    pub(super) symlinks: usize,
    pub(super) special: usize,
}

impl Walk {
    pub(super) fn exclude(&mut self, record: String) {
        self.exclusions.update(b"\nexclude\0");
        self.exclusions.update(record.as_bytes());
        self.exclusion_count += 1;
    }

    fn stopped(&self) -> bool {
        self.entry_cap_hit || self.visit_cap_hit
    }
}

fn join(relative: &str, name: &str) -> String {
    if relative.is_empty() {
        name.to_owned()
    } else {
        format!("{relative}/{name}")
    }
}

pub(super) fn walk_directory(
    directory: &mut DirHandle,
    relative: &str,
    depth: usize,
    mode: SnapshotMode,
    limits: &Limits,
    walk: &mut Walk,
) {
    let mut names: Vec<(String, std::ffi::OsString)> = Vec::new();
    for entry in directory.names() {
        let Some(os_name) = entry else {
            walk.unreadable += 1;
            walk.exclude(format!("{relative}\0unreadable_entry"));
            continue;
        };
        match os_name.to_str() {
            Some(name) => names.push((name.to_owned(), os_name.clone())),
            None => {
                walk.unreadable += 1;
                walk.exclude(format!("{relative}\0non_utf8_name"));
            }
        }
    }
    // Readdir order is filesystem specific; the walk visits names in order so
    // the entry cap always keeps the same prefix.
    names.sort();
    for (name, os_name) in names {
        if walk.stopped() {
            return;
        }
        if walk.visited >= limits.visits {
            walk.visit_cap_hit = true;
            return;
        }
        walk.visited += 1;
        let child = join(relative, &name);
        let Some(node) = directory.stat(&os_name) else {
            walk.unreadable += 1;
            walk.exclude(format!("{child}\0unreadable"));
            continue;
        };
        match node.kind {
            Kind::Symlink => {
                walk.counts.symlinks += 1;
                let target = directory
                    .read_link(&os_name)
                    .map(|target| hex::encode(Sha256::digest(target.as_encoded_bytes())))
                    .unwrap_or_else(|| "-".to_owned());
                walk.exclude(format!("{child}\0symlink\0{target}"));
            }
            Kind::Directory if SKIP_DIRS.contains(&name.as_str()) => {
                walk.counts.directories += 1;
                walk.exclude(format!("{child}\0policy_directory"));
            }
            Kind::Directory if depth >= MAX_WALK_DEPTH => {
                walk.depth_cap_hit = true;
                walk.exclude(format!("{child}\0depth_cap"));
            }
            Kind::Directory => match directory.open_dir(&os_name, &node) {
                Ok(mut handle) => {
                    walk_directory(&mut handle, &child, depth + 1, mode, limits, walk)
                }
                Err(HashError::Unstable) => {
                    walk.unstable += 1;
                    walk.exclude(format!("{child}\0unstable_directory"));
                }
                Err(HashError::Unreadable) => {
                    walk.unreadable += 1;
                    walk.exclude(format!("{child}\0unreadable_directory"));
                }
            },
            Kind::Special => {
                walk.counts.special += 1;
                walk.exclude(format!("{child}\0special"));
            }
            Kind::File if is_audit_sensitive_basename(&name) => {
                walk.counts.sensitive += 1;
                walk.exclude(format!("{child}\0sensitive"));
            }
            Kind::File => admit_file(
                directory, &os_name, &child, &name, &node, mode, limits, walk,
            ),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn admit_file(
    directory: &DirHandle,
    os_name: &OsStr,
    child: &str,
    name: &str,
    node: &Node,
    mode: SnapshotMode,
    limits: &Limits,
    walk: &mut Walk,
) {
    if walk.entries.len() >= limits.entries {
        walk.entry_cap_hit = true;
        return;
    }
    let size = node.len;
    if size > limits.file_bytes {
        walk.counts.oversize += 1;
        if DETECTOR_INPUT_BASENAMES.contains(&name) {
            walk.oversize_detector_input = true;
        }
        walk.exclude(format!("{child}\0oversize\0{size}"));
        return;
    }
    if mode == SnapshotMode::Stat {
        walk.entries
            .push(format!("{child}\0{size}\0{}\0{}", node.mtime_ns, node.ino));
        return;
    }
    if walk.hashed_bytes.saturating_add(size) > limits.total_bytes {
        walk.byte_cap_hit = true;
        walk.exclude(format!("{child}\0byte_budget\0{size}"));
        return;
    }
    let Some(file) = directory.open_file(os_name) else {
        walk.unreadable += 1;
        walk.exclude(format!("{child}\0unreadable"));
        return;
    };
    match hash_stable(file, node, limits.file_bytes) {
        Ok((digest, read)) => {
            walk.hashed_bytes += read;
            walk.entries.push(format!("{child}\0{read}\0{digest}"));
        }
        Err(HashError::Unstable) => {
            walk.unstable += 1;
            walk.exclude(format!("{child}\0unstable"));
        }
        Err(HashError::Unreadable) => {
            walk.unreadable += 1;
            walk.exclude(format!("{child}\0unreadable"));
        }
    }
}
