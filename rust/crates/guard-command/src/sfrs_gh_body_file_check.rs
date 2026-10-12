//! Descriptor-level validation of a GitHub pull-request body file
//! (`github_pr_body_file.py`: `github_pr_body_file_is_safe`, the ancestor
//! chain and private-directory checks).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::fs;
use std::path::Path;

use crate::codex_output_env::Ctx;
use crate::codex_output_py::PyPath;
use crate::sfrs_gh_body_file::{
    authored_location_root, is_pr_body_markdown_name, path_looks_sensitive, resolve_operand,
};
use crate::sfrs_gh_pyshim::current_uid;
use crate::shell_secret_read_support::classify_request_secret_path;

const MAX_PR_BODY_BYTES: u64 = 128 * 1024;
const MAX_PR_BODY_AGE_SECONDS: f64 = 24.0 * 60.0 * 60.0;
const GROUP_OR_OTHER_WRITE: u32 = 0o022;
const WORLD_WRITE: u32 = 0o002;
const STICKY: u32 = 0o1000;

/// `github_pr_body_file_is_safe`: validate locally authored PR text without
/// retaining its contents.
pub(crate) fn github_pr_body_file_is_safe(
    operand: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    let (Some(cwd), Some(home_dir)) = (cwd, home_dir) else {
        return false;
    };
    let cwd_path = PyPath::new(&cwd.to_string_lossy());
    let home_path = PyPath::new(&home_dir.to_string_lossy());
    let Some(candidate) = resolve_operand(operand, &cwd_path, &home_path) else {
        return false;
    };
    if classify_request_secret_path(&candidate.to_string(), Some(cwd), Some(home_dir)).is_some()
        || path_looks_sensitive(&candidate)
        || !is_pr_body_markdown_name(candidate.name())
    {
        return false;
    }
    let Some(authored_root) = authored_location_root(&candidate, &cwd_path, &home_path, ctx) else {
        return false;
    };
    if !ancestor_chain_is_controlled(&candidate, &authored_root, ctx) {
        return false;
    }
    let Some(payload) = read_controlled_body(&candidate, ctx) else {
        return false;
    };
    match String::from_utf8(payload) {
        Ok(content) => !ctx.host.secret_content_found(&content, false),
        Err(_) => false,
    }
}

/// `_ancestor_chain_is_controlled`.
pub(crate) fn ancestor_chain_is_controlled(candidate: &PyPath, root: &PyPath, ctx: &Ctx) -> bool {
    // Windows workspaces and per-user temporary directories are ACL-bound;
    // there is no portable stdlib UID or ACL-owner API to duplicate here.
    if cfg!(windows) {
        return true;
    }
    let Some(uid) = current_uid(ctx) else {
        return false;
    };
    ancestor_chain_for_uid(candidate, root, uid)
}

#[cfg(unix)]
fn ancestor_chain_for_uid(candidate: &PyPath, root: &PyPath, uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;

    let mut current = candidate.parent();
    while &current != root {
        if !private_directory_owned_by_current_user(&current, uid, None) {
            return false;
        }
        let parent = current.parent();
        if parent == current || current.relative_to(root).is_none() {
            return false;
        }
        current = parent;
    }
    let Ok(metadata) = fs::metadata(root.to_string()) else {
        return false;
    };
    if private_directory_owned_by_current_user(root, uid, Some(&metadata)) {
        return true;
    }
    metadata.is_dir()
        && (metadata.uid() == 0 || metadata.uid() == uid)
        && metadata.mode() & STICKY != 0
        && metadata.mode() & WORLD_WRITE != 0
}

#[cfg(not(unix))]
fn ancestor_chain_for_uid(_: &PyPath, _: &PyPath, _: u32) -> bool {
    true
}

/// `_private_directory_owned_by_current_user`.
#[cfg(unix)]
pub(crate) fn private_directory_owned_by_current_user(
    path: &PyPath,
    uid: u32,
    metadata: Option<&fs::Metadata>,
) -> bool {
    use std::os::unix::fs::MetadataExt;

    let owned;
    let metadata = match metadata {
        Some(metadata) => metadata,
        None => {
            let Ok(found) = fs::metadata(path.to_string()) else {
                return false;
            };
            owned = found;
            &owned
        }
    };
    metadata.is_dir() && metadata.uid() == uid && metadata.mode() & GROUP_OR_OTHER_WRITE == 0
}

#[cfg(not(unix))]
pub(crate) fn private_directory_owned_by_current_user(
    _: &PyPath,
    _: u32,
    _: Option<&fs::Metadata>,
) -> bool {
    false
}

/// Open the body without following links and read it while re-checking that
/// the path, descriptor and bytes describe one unchanged regular file.
#[cfg(unix)]
fn read_controlled_body(candidate: &PyPath, ctx: &Ctx) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::sfrs_file_identity::full_stat_identity;

    let path = candidate.to_string();
    let path_metadata = fs::symlink_metadata(&path).ok()?;
    // A non-regular entry can never pass the checks below; refusing it here
    // keeps a FIFO from blocking the open.
    if !path_metadata.file_type().is_file() {
        return None;
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if (metadata.dev(), metadata.ino()) != (path_metadata.dev(), path_metadata.ino()) {
        return None;
    }
    if full_stat_identity(&metadata) != full_stat_identity(&path_metadata) {
        return None;
    }
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return None;
    }
    if metadata.size() == 0 || metadata.size() > MAX_PR_BODY_BYTES {
        return None;
    }
    let uid = current_uid(ctx)?;
    if metadata.uid() != uid || metadata.mode() & GROUP_OR_OTHER_WRITE != 0 {
        return None;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs_f64();
    let modified = metadata.mtime() as f64 + metadata.mtime_nsec() as f64 / 1e9;
    let age_seconds = now - modified;
    if !(-60.0..=MAX_PR_BODY_AGE_SECONDS).contains(&age_seconds) {
        return None;
    }
    let mut payload = vec![0u8; usize::try_from(MAX_PR_BODY_BYTES).ok()? + 1];
    let read = file.read(&mut payload).ok()?;
    payload.truncate(read);
    if u64::try_from(payload.len()).ok()? != metadata.size() {
        return None;
    }
    if full_stat_identity(&file.metadata().ok()?) != full_stat_identity(&metadata) {
        return None;
    }
    let after = fs::symlink_metadata(&path).ok()?;
    if full_stat_identity(&after) != full_stat_identity(&path_metadata) {
        return None;
    }
    Some(payload)
}

/// Windows reads the bytes through a handle that denies write and delete
/// sharing. Stable `std` cannot report the file index or the hard-link count
/// that the Python check compares, so the body is refused rather than
/// trusted on a weaker identity.
#[cfg(windows)]
fn read_controlled_body(_candidate: &PyPath, _ctx: &Ctx) -> Option<Vec<u8>> {
    None
}
