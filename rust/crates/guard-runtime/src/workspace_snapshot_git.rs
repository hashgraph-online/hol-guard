//! Read-only Git identity for a workspace snapshot.
//!
//! The snapshot must not run Git: a repository's config can name hooks,
//! filters and fsmonitor commands. This module reads `HEAD`, the linked
//! worktree `gitdir` pointer, `commondir`, loose refs and `packed-refs` as
//! bounded plain files and never follows a symlink. Anything it cannot read
//! leaves the field unset; an unknown commit is reported as unknown, not
//! guessed.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_POINTER_BYTES: u64 = 4 * 1024;
const MAX_PACKED_REFS_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct GitIdentity {
    /// Canonical common Git directory shared by every linked worktree of a
    /// repository; the codebase identity input when present.
    pub(crate) common_dir: Option<String>,
    pub(crate) head_commit: Option<String>,
    pub(crate) head_ref: Option<String>,
    pub(crate) linked_worktree: bool,
}

pub(crate) fn git_identity(root: &Path) -> GitIdentity {
    let dot_git = root.join(".git");
    let Ok(metadata) = fs::symlink_metadata(&dot_git) else {
        return GitIdentity::default();
    };
    let (git_dir, linked) = if metadata.is_dir() {
        (dot_git, false)
    } else if metadata.is_file() {
        let Some(pointer) = read_small(&dot_git, MAX_POINTER_BYTES) else {
            return GitIdentity::default();
        };
        let Some(target) = pointer.trim().strip_prefix("gitdir:") else {
            return GitIdentity::default();
        };
        let target = PathBuf::from(target.trim());
        let target = if target.is_absolute() {
            target
        } else {
            root.join(target)
        };
        (target, true)
    } else {
        return GitIdentity::default();
    };
    let Ok(git_dir) = fs::canonicalize(&git_dir) else {
        return GitIdentity::default();
    };
    let common_dir = match read_small(&git_dir.join("commondir"), MAX_POINTER_BYTES) {
        Some(text) => {
            let pointer = PathBuf::from(text.trim());
            let joined = if pointer.is_absolute() {
                pointer
            } else {
                git_dir.join(pointer)
            };
            fs::canonicalize(joined).unwrap_or_else(|_| git_dir.clone())
        }
        None => git_dir.clone(),
    };
    let mut identity = GitIdentity {
        common_dir: common_dir.to_str().map(str::to_owned),
        linked_worktree: linked,
        ..GitIdentity::default()
    };
    let Some(head) = read_small(&git_dir.join("HEAD"), MAX_POINTER_BYTES) else {
        return identity;
    };
    let head = head.trim();
    if let Some(reference) = head.strip_prefix("ref:") {
        let reference = reference.trim();
        if !is_safe_ref(reference) {
            return identity;
        }
        identity.head_ref = Some(reference.to_owned());
        identity.head_commit = resolve_ref(&common_dir, &git_dir, reference);
    } else if is_object_id(head) {
        identity.head_commit = Some(head.to_owned());
    }
    identity
}

fn resolve_ref(common_dir: &Path, git_dir: &Path, reference: &str) -> Option<String> {
    for base in [git_dir, common_dir] {
        if let Some(text) = read_small(&base.join(reference), MAX_POINTER_BYTES) {
            let value = text.trim();
            return is_object_id(value).then(|| value.to_owned());
        }
    }
    let packed = read_small(&common_dir.join("packed-refs"), MAX_PACKED_REFS_BYTES)?;
    packed.lines().find_map(|line| {
        let (object_id, name) = line.split_once(' ')?;
        (name.trim() == reference && is_object_id(object_id)).then(|| object_id.to_owned())
    })
}

fn is_safe_ref(reference: &str) -> bool {
    reference.starts_with("refs/")
        && !reference.contains("..")
        && !reference.contains('\\')
        && reference
            .split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.'))
}

fn is_object_id(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Read a small regular file without following a leaf symlink.
fn read_small(path: &Path, limit: u64) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > limit {
        return None;
    }
    let mut text = String::new();
    fs::File::open(path)
        .ok()?
        .take(limit + 1)
        .read_to_string(&mut text)
        .ok()?;
    (text.len() as u64 <= limit).then_some(text)
}
