//! Group write that gives no account more than it already has, ported from
//! `group_write_trust.writable_only_by_owner`.
//!
//! With a 0002 umask, pip installs Guard's package files at 0664 and the
//! bundled native runtime at 0775. The code that runs a trust check ships in
//! the same package, owned by the same user with the same group write, so any
//! account that could use the group bit to change the runtime or its manifest
//! could already rewrite the checker. Rejecting the bit there protects
//! nothing, so group write is accepted only on a file the current user owns
//! whose group is the group of the checker and its folder, while both are
//! group-writable, and only while the group can reach the checker from every
//! folder it shares with the file. World write is always rejected.
//!
//! The checker is the interpreter's own package file, a fact only the asking
//! interpreter has, so the caller names it.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const GROUP_WRITE: u32 = 0o020;
const WORLD_WRITE: u32 = 0o002;
const GROUP_SEARCH: u32 = 0o010;
const WORLD_SEARCH: u32 = 0o001;

/// Whether every member of `gid` can enter this folder: a member gets the
/// group bits and anyone else the other bits, and a folder owned by another
/// account is not relied on because its owner can restore search.
fn group_can_search(metadata: &fs::Metadata, gid: u32, uid: u32) -> bool {
    let mode = metadata.mode();
    if metadata.uid() != uid {
        return false;
    }
    if metadata.gid() == gid {
        return mode & GROUP_SEARCH != 0;
    }
    mode & GROUP_SEARCH != 0 && mode & WORLD_SEARCH != 0
}

/// Whether the checker and its folder are already writable through `gid`.
fn checker_shares_group_write(checker: &Path, target: &Path, gid: u32, uid: u32) -> bool {
    let Ok(module) = checker.canonicalize() else {
        return false;
    };
    let Some(folder) = module.parent() else {
        return false;
    };
    let Some(target_folder) = target
        .canonicalize()
        .ok()
        .and_then(|resolved| resolved.parent().map(Path::to_path_buf))
    else {
        return false;
    };
    let shared: PathBuf = folder
        .components()
        .zip(target_folder.components())
        .take_while(|(left, right)| left == right)
        .map(|(left, _)| left)
        .collect();
    let owned = |path: &Path, wanted: fn(&fs::Metadata) -> bool| {
        fs::metadata(path).is_ok_and(|metadata| {
            wanted(&metadata)
                && metadata.uid() == uid
                && metadata.gid() == gid
                && metadata.mode() & GROUP_WRITE != 0
        })
    };
    if !owned(&module, fs::Metadata::is_file) || !owned(folder, fs::Metadata::is_dir) {
        return false;
    }
    for ancestor in folder.ancestors() {
        if ancestor == shared {
            break;
        }
        match fs::metadata(ancestor) {
            Ok(metadata) if group_can_search(&metadata, gid, uid) => {}
            _ => return false,
        }
    }
    true
}

/// Whether the mode bits of the file at `path` give no account more than it
/// already has. Owner checks stay with the caller.
pub(crate) fn writable_only_by_owner(
    metadata: &fs::Metadata,
    current_uid: u32,
    path: &Path,
    checker: Option<&Path>,
) -> bool {
    let mode = metadata.mode();
    if mode & WORLD_WRITE != 0 {
        return false;
    }
    if mode & GROUP_WRITE == 0 {
        return true;
    }
    metadata.uid() == current_uid
        && checker.is_some_and(|checker| {
            checker_shares_group_write(checker, path, metadata.gid(), current_uid)
        })
}

#[cfg(test)]
#[path = "group_write_trust_tests.rs"]
mod tests;
