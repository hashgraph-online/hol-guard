//! `workspace-snapshot --stdin`: the bounded content snapshot that binds a
//! background workspace assessment to the exact files it read.
//!
//! The walk never follows a symlink, never executes Git and never reads a
//! sensitive basename. On Unix it descends through directory descriptors
//! opened without following symlinks, so swapping a directory for a symlink
//! mid-walk cannot lead it outside the root. Every admitted regular file contributes its relative
//! path, size and SHA-256 to a sorted manifest; directories skipped by policy,
//! symlinks, oversize files and unreadable entries contribute an exclusion
//! record instead, so a change to what was left out still changes the digest.
//! Depth and the number of entries visited are bounded; hitting either bound
//! leaves the snapshot partial.
//! A file whose identity changed while it was read is reported as unstable and
//! the snapshot is partial: callers must not treat it as a consistent view.
//!
//! `stat` mode reads no file content. It digests path, size, mtime and inode
//! only and exists to notice that something changed between content
//! snapshots; it is never an assessment identity.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::workspace_snapshot_file::DirHandle;
use crate::workspace_snapshot_git::{git_identity, GitIdentity};

#[path = "workspace_snapshot_walk.rs"]
mod walk;
use walk::{walk_directory, Walk, MAX_WALK_DEPTH};

pub(crate) const COMMAND: &str = "workspace-snapshot";
pub(crate) const FEATURE: &str = "workspace-snapshot-v1";
const RESULT_SCHEMA: &str = "guard.workspace-snapshot.v1";
const CONTRACT_VERSION: u32 = 1;

pub(crate) const DEFAULT_MAX_ENTRIES: usize = 10_000;
pub(crate) const DEFAULT_MAX_TOTAL_BYTES: u64 = 50 * 1024 * 1024;
pub(crate) const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const HARD_MAX_ENTRIES: usize = 100_000;
const HARD_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const HARD_MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Every directory entry the walk looks at counts against this budget, so a
/// tree of empty or excluded entries cannot keep the walk running.
const DEFAULT_MAX_VISITED_ENTRIES: usize = 250_000;
const HARD_MAX_VISITED_ENTRIES: usize = 1_000_000;
/// Vendored, generated and dependency directories. Their content is owned by
/// a lockfile or a build, not by the developer's edits.
pub(crate) const SKIP_DIRS: [&str; 22] = [
    ".git",
    ".hg",
    ".svn",
    ".jj",
    "node_modules",
    "bower_components",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".next",
    ".turbo",
    "target",
    ".guard",
    ".worktrees",
    "worktrees",
];

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SnapshotMode {
    Content,
    Stat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotRequest {
    pub(crate) root: String,
    pub(crate) mode: SnapshotMode,
    #[serde(default)]
    pub(crate) max_entries: usize,
    #[serde(default)]
    pub(crate) max_total_bytes: u64,
    #[serde(default)]
    pub(crate) max_file_bytes: u64,
    #[serde(default)]
    pub(crate) max_visited_entries: usize,
}

struct Limits {
    entries: usize,
    total_bytes: u64,
    file_bytes: u64,
    visits: usize,
}

impl Limits {
    fn from_request(request: &SnapshotRequest) -> Self {
        fn bounded<T: Ord + Copy + Default>(value: T, default: T, hard: T) -> T {
            if value == T::default() {
                default
            } else {
                value.min(hard)
            }
        }
        Self {
            entries: bounded(request.max_entries, DEFAULT_MAX_ENTRIES, HARD_MAX_ENTRIES),
            total_bytes: bounded(
                request.max_total_bytes,
                DEFAULT_MAX_TOTAL_BYTES,
                HARD_MAX_TOTAL_BYTES,
            ),
            file_bytes: bounded(
                request.max_file_bytes,
                DEFAULT_MAX_FILE_BYTES,
                HARD_MAX_FILE_BYTES,
            ),
            visits: bounded(
                request.max_visited_entries,
                DEFAULT_MAX_VISITED_ENTRIES,
                HARD_MAX_VISITED_ENTRIES,
            ),
        }
    }

    fn policy_line(&self) -> String {
        format!(
            "policy\0v{CONTRACT_VERSION}\0{}\0{}\0{}\0{MAX_WALK_DEPTH}\0{}\0{}",
            self.entries,
            self.total_bytes,
            self.file_bytes,
            self.visits,
            SKIP_DIRS.join(",")
        )
    }
}

pub(crate) fn run_command(bytes: &[u8]) -> Result<Value, String> {
    let request: SnapshotRequest = serde_json::from_slice(bytes)
        .map_err(|_| "workspace_snapshot_request_invalid".to_owned())?;
    Ok(match snapshot(&request) {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => json!({"ok": false, "error": error}),
    })
}

pub(crate) fn snapshot(request: &SnapshotRequest) -> Result<Value, String> {
    let requested = PathBuf::from(&request.root);
    if !requested.is_absolute() {
        return Err("workspace_snapshot_root_not_absolute".to_owned());
    }
    let root = fs::canonicalize(&requested).map_err(|_| "workspace_snapshot_root_missing")?;
    if !fs::metadata(&root).is_ok_and(|meta| meta.is_dir()) {
        return Err("workspace_snapshot_root_not_directory".to_owned());
    }
    let root_text = root
        .to_str()
        .ok_or("workspace_snapshot_root_not_utf8")?
        .to_owned();
    let mut handle = DirHandle::open_root(&root).ok_or("workspace_snapshot_root_unreadable")?;
    let limits = Limits::from_request(request);
    let git = git_identity(&root);
    let mut walk = Walk::default();
    walk_directory(&mut handle, "", 0, request.mode, &limits, &mut walk);
    walk.entries.sort();

    let worktree_key = keyed_digest("worktree", &root_text);
    let codebase_key = keyed_digest(
        "codebase",
        git.common_dir.as_deref().unwrap_or(root_text.as_str()),
    );
    let input_manifest_digest = input_manifest_digest(&limits, &walk);
    let snapshot_digest = snapshot_digest(
        request.mode,
        &worktree_key,
        &codebase_key,
        &git,
        &input_manifest_digest,
        &walk,
    );
    let mut partial_reasons: Vec<&str> = Vec::new();
    if walk.entry_cap_hit {
        partial_reasons.push("entry_cap");
    }
    if walk.byte_cap_hit {
        partial_reasons.push("byte_cap");
    }
    if walk.oversize_detector_input {
        partial_reasons.push("oversize_detector_input");
    }
    if walk.unreadable > 0 {
        partial_reasons.push("unreadable");
    }
    if walk.unstable > 0 {
        partial_reasons.push("unstable");
    }
    if walk.depth_cap_hit {
        partial_reasons.push("depth_cap");
    }
    if walk.visit_cap_hit {
        partial_reasons.push("visit_cap");
    }
    Ok(json!({
        "schema": RESULT_SCHEMA,
        "contract_version": CONTRACT_VERSION,
        "mode": match request.mode {
            SnapshotMode::Content => "content",
            SnapshotMode::Stat => "stat",
        },
        "root": root_text,
        "worktree_key": worktree_key,
        "codebase_key": codebase_key,
        "git": {
            "head_commit": git.head_commit,
            "head_ref": git.head_ref,
            "linked_worktree": git.linked_worktree,
        },
        "snapshot_digest": snapshot_digest,
        "input_manifest_digest": input_manifest_digest,
        "entry_count": walk.entries.len(),
        "hashed_bytes": walk.hashed_bytes,
        "excluded": {
            "directories": walk.counts.directories,
            "sensitive": walk.counts.sensitive,
            "oversize": walk.counts.oversize,
            "symlinks": walk.counts.symlinks,
            "special": walk.counts.special,
        },
        "unreadable_count": walk.unreadable,
        "unstable_count": walk.unstable,
        "coverage": if partial_reasons.is_empty() { "complete" } else { "partial" },
        "partial_reasons": partial_reasons,
        "limits": {
            "max_entries": limits.entries,
            "max_total_bytes": limits.total_bytes,
            "max_file_bytes": limits.file_bytes,
            "max_depth": MAX_WALK_DEPTH,
            "max_visited_entries": limits.visits,
        },
    }))
}

fn keyed_digest(domain: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("guard.workspace-snapshot.{domain}.v1\0").as_bytes());
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

fn input_manifest_digest(limits: &Limits, walk: &Walk) -> String {
    let mut hasher = Sha256::new();
    hasher.update(limits.policy_line().as_bytes());
    hasher.update(
        format!(
            "\nexclusions\0{}\0{}",
            walk.exclusion_count,
            hex::encode(walk.exclusions.clone().finalize())
        )
        .as_bytes(),
    );
    hex::encode(hasher.finalize())
}

fn snapshot_digest(
    mode: SnapshotMode,
    worktree_key: &str,
    codebase_key: &str,
    git: &GitIdentity,
    input_manifest_digest: &str,
    walk: &Walk,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(
        format!(
            "{RESULT_SCHEMA}\0{CONTRACT_VERSION}\0{mode:?}\0{worktree_key}\0{codebase_key}\0{}\0{}\0{input_manifest_digest}",
            git.head_commit.as_deref().unwrap_or("-"),
            git.head_ref.as_deref().unwrap_or("-"),
        )
        .as_bytes(),
    );
    for entry in &walk.entries {
        hasher.update(b"\nentry\0");
        hasher.update(entry.as_bytes());
    }
    hasher.update(
        format!(
            "\nstate\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            walk.unreadable,
            walk.unstable,
            walk.entry_cap_hit,
            walk.byte_cap_hit,
            walk.oversize_detector_input,
            walk.depth_cap_hit,
            walk.visit_cap_hit
        )
        .as_bytes(),
    );
    hex::encode(hasher.finalize())
}

#[cfg(test)]
#[path = "workspace_snapshot_tests.rs"]
mod tests;
