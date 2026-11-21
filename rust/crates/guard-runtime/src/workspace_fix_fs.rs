//! Root-confined, symlink-refusing file access for reviewed manifest fixes.
//!
//! A manifest path is a relative path under the admitted root. Every directory
//! on the way is opened without following links relative to the descriptor of
//! its parent (on Windows each component is checked for a reparse point), and
//! the manifest itself must be a regular file that was not swapped between the
//! inspection and the open.
//!
//! Replacing a manifest only when it is unchanged cannot be a single atomic
//! step with the primitives a filesystem offers, so it is done by moving the
//! current file aside, hashing what was moved, and hard-linking the new file
//! into the vacated name without replacing anything:
//!
//! * a writer that replaced the file by rename before the move is detected by
//!   the hash of the moved-aside file, which is then put back;
//! * a writer that creates the name after the move makes the final link fail,
//!   so its file is kept and nothing is overwritten;
//! * a writer that still holds the old file open and writes to it after the
//!   hash was taken is not detected. That window, from the hash to the final
//!   link, and the moments the name is absent, are the remaining exposure.
//!
//! Off Unix the walk is by path, which a directory-to-junction swap can
//! redirect, so manifests are read there but never replaced.

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

#[cfg(unix)]
#[path = "workspace_fix_fs_unix.rs"]
mod platform;
#[cfg(not(unix))]
#[path = "workspace_fix_fs_portable.rs"]
mod platform;

use platform::{file_entry, Dir};

pub(crate) type Code = &'static str;

pub(crate) const MANIFEST_NAME: &str = "package.json";
pub(crate) const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
pub(crate) const LOCKFILE_NAMES: [&str; 6] = [
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    File,
    Directory,
    Symlink,
    Other,
}

/// What a directory entry is, without following it.
#[derive(Debug, Clone, Copy)]
pub(super) struct Entry {
    pub(super) kind: Kind,
    pub(super) len: u64,
    pub(super) mode: u32,
    pub(super) id: (u64, u64),
}

pub(crate) struct Manifest {
    pub(crate) bytes: Vec<u8>,
    pub(crate) mode: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Replaced {
    Applied,
    /// Nothing was written. `preserved` names a file that holds content the
    /// operation moved but could not put back because the name was taken.
    Stale {
        reason: Code,
        preserved: Option<String>,
    },
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn checked_parts(relative: &str) -> Result<Vec<&str>, Code> {
    let parts: Vec<&str> = relative.split('/').collect();
    let invalid = relative.contains('\\')
        || relative.contains('\0')
        || parts
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
        || parts.last() != Some(&MANIFEST_NAME);
    if invalid {
        return Err("manifest_path_invalid");
    }
    Ok(parts)
}

/// The directories from the root down to the manifest's parent, and the
/// manifest's name.
fn open_chain<'a>(root: &Path, relative: &'a str) -> Result<(Vec<Dir>, &'a str), Code> {
    let parts = checked_parts(relative)?;
    let (name, parents) = parts.split_last().ok_or("manifest_path_invalid")?;
    let mut chain = vec![Dir::open_root(root)?];
    for part in parents {
        let child = chain
            .last()
            .ok_or("manifest_path_invalid")?
            .open_child(part)?;
        chain.push(child);
    }
    Ok((chain, name))
}

fn read_in(dir: &Dir, name: &str) -> Result<Manifest, Code> {
    let seen = dir.stat(name).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            "manifest_missing"
        } else {
            "manifest_unreadable"
        }
    })?;
    match seen.kind {
        Kind::Symlink => return Err("manifest_is_symlink"),
        Kind::File => {}
        _ => return Err("manifest_not_regular"),
    }
    if seen.len > MAX_MANIFEST_BYTES {
        return Err("manifest_too_large");
    }
    let mut file = dir.open_read(name).map_err(|_| "manifest_unreadable")?;
    let opened = file_entry(&file).map_err(|_| "manifest_unreadable")?;
    if opened.kind != Kind::File || opened.id != seen.id {
        return Err("manifest_changed");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "manifest_unreadable")?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("manifest_too_large");
    }
    Ok(Manifest {
        bytes,
        mode: seen.mode,
    })
}

/// The manifest's bytes and permission bits, read without following links.
pub(crate) fn read_manifest(root: &Path, relative: &str) -> Result<Manifest, Code> {
    let (chain, name) = open_chain(root, relative)?;
    read_in(chain.last().ok_or("manifest_path_invalid")?, name)
}

/// Lockfiles beside the manifest, else the nearest ones in a parent up to the root.
pub(crate) fn lockfiles_for(root: &Path, relative: &str) -> Vec<String> {
    let Ok((chain, _)) = open_chain(root, relative) else {
        return Vec::new();
    };
    let parts: Vec<&str> = relative.split('/').collect();
    for depth in (0..chain.len()).rev() {
        let found: Vec<String> = LOCKFILE_NAMES
            .iter()
            .filter(|name| chain[depth].stat(name).is_ok())
            .map(|name| {
                let mut path: Vec<&str> = parts[..depth].to_vec();
                path.push(name);
                path.join("/")
            })
            .collect();
        if !found.is_empty() {
            return found;
        }
    }
    Vec::new()
}

fn unique_suffix() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!(
        "{}-{nanos:x}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn write_temp(dir: &Dir, name: &str, bytes: &[u8], mode: u32) -> io::Result<()> {
    let mut file = dir.create_new(name)?;
    let written = (|| {
        file.write_all(bytes)?;
        dir.set_mode(&file, mode)?;
        file.sync_all()
    })();
    if written.is_err() {
        let _ = dir.unlink(name);
    }
    written
}

fn relative_sibling(relative: &str, sibling: &str) -> String {
    match relative.rsplit_once('/') {
        Some((parent, _)) => format!("{parent}/{sibling}"),
        None => sibling.to_owned(),
    }
}

/// Put `bytes` in place of the manifest only if it still hashes to `base_sha256`.
pub(crate) fn replace_if_unchanged(
    root: &Path,
    relative: &str,
    base_sha256: &str,
    bytes: &[u8],
) -> Result<Replaced, Code> {
    // Without directory descriptors a parent swapped for a junction after the
    // hash check would send the write outside the root, so nothing is written.
    if !platform::REPLACE_SUPPORTED {
        return Err("fix_apply_unsupported");
    }
    replace_with_hooks(root, relative, base_sha256, bytes, || {}, || {})
}

/// `after_check` runs between the first hash check and the move aside, and
/// `after_move` between the move aside and the final link; tests use them to
/// stand in for a concurrent writer.
fn replace_with_hooks(
    root: &Path,
    relative: &str,
    base_sha256: &str,
    bytes: &[u8],
    after_check: impl FnOnce(),
    after_move: impl FnOnce(),
) -> Result<Replaced, Code> {
    let (chain, name) = open_chain(root, relative)?;
    let dir = chain.last().ok_or("manifest_path_invalid")?;
    let current = match read_in(dir, name) {
        Ok(current) => current,
        Err(reason) => {
            return Ok(Replaced::Stale {
                reason,
                preserved: None,
            })
        }
    };
    if sha256_hex(&current.bytes) != base_sha256 {
        return Ok(Replaced::Stale {
            reason: "manifest_changed",
            preserved: None,
        });
    }
    let suffix = unique_suffix();
    let temp = format!(".{name}.guard-new-{suffix}");
    let aside = format!(".{name}.guard-old-{suffix}");
    write_temp(dir, &temp, bytes, current.mode).map_err(|_| "fix_apply_failed")?;
    after_check();
    if dir.rename(name, &aside).is_err() {
        let _ = dir.unlink(&temp);
        return Err("fix_apply_failed");
    }
    after_move();
    let moved_is_base =
        read_in(dir, &aside).is_ok_and(|moved| sha256_hex(&moved.bytes) == base_sha256);
    if !moved_is_base {
        // Whatever was at the name is not what was reviewed; give it back.
        let _ = dir.unlink(&temp);
        let preserved = match dir.link_new(&aside, name) {
            Ok(()) => {
                let _ = dir.unlink(&aside);
                None
            }
            Err(_) => Some(relative_sibling(relative, &aside)),
        };
        dir.sync();
        return Ok(Replaced::Stale {
            reason: "manifest_changed",
            preserved,
        });
    }
    let outcome = match dir.link_new(&temp, name) {
        Ok(()) => Ok(Replaced::Applied),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(Replaced::Stale {
            reason: "manifest_changed",
            preserved: None,
        }),
        Err(_) => Err("fix_apply_failed"),
    };
    let _ = dir.unlink(&temp);
    if outcome.is_err() && dir.link_new(&aside, name).is_err() {
        // The original could not be put back; leave the moved-aside copy.
        dir.sync();
        return Err("fix_apply_failed");
    }
    let _ = dir.unlink(&aside);
    dir.sync();
    outcome
}

#[cfg(test)]
#[path = "workspace_fix_fs_tests.rs"]
mod tests;
