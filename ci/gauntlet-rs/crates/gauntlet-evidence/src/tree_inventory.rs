//! Inert Python-compatible SDK and installed-prefix inventories.
//!
//! Directory and file enumeration is descriptor-relative. Symlink containment
//! still uses host path resolution and needs Linux race/parity proof before
//! this reader can participate in execution admission.

use crate::crypto::sha256;
use crate::io::open_absolute_directory;
use crate::{canonical_value, EvidenceError, Result};
use gauntlet_contracts::canonical_relative_asset_path;
use rustix::fs::{fstat, openat, readlinkat, statat, AtFlags, Dir, FileType, Mode, OFlags, Stat};
use rustix::process::getuid;
use serde_json::{json, Map, Value};
use sha2::Digest;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::Path;

const MAX_ENTRIES: usize = 100_000;
const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_DEPTH: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeKind {
    Sdk,
    InstalledPrefix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeInventory {
    pub digest: String,
    pub entries: usize,
    pub bytes: u64,
}

fn unchanged(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn hash_file(descriptor: OwnedFd, before: &Stat) -> Result<String> {
    if before.st_size < 0 || before.st_size as u64 > MAX_BYTES {
        return Err(EvidenceError::Invalid("tree file exceeds byte budget"));
    }
    let mut file = File::from(descriptor);
    let mut hasher = sha2::Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| EvidenceError::Io(error.to_string()))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .filter(|size| *size <= MAX_BYTES)
            .ok_or(EvidenceError::Invalid("tree exceeds two GiB"))?;
        sha2::Digest::update(&mut hasher, &buffer[..count]);
    }
    let after = fstat(&file).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if total != before.st_size as u64 || !unchanged(before, &after) {
        return Err(EvidenceError::Invalid("tree file changed while hashing"));
    }
    Ok(format!("{:x}", sha2::Digest::finalize(hasher)))
}

fn inspect_one(
    parent: &OwnedFd,
    root: &Path,
    name: &str,
    relative: &str,
    kind: TreeKind,
) -> Result<(Value, u64, Option<OwnedFd>)> {
    if !canonical_relative_asset_path(relative) {
        return Err(EvidenceError::Invalid("noncanonical tree entry"));
    }
    let before = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
    let file_kind = FileType::from_raw_mode(before.st_mode);
    let mode = before.st_mode & 0o7777;
    match kind {
        TreeKind::Sdk => {
            let user = getuid().as_raw();
            if ![0, 501, user].contains(&before.st_uid)
                || before.st_uid == 10001
                || (file_kind != FileType::Symlink
                    && (mode & 0o002 != 0 || (before.st_gid == 10001 && mode & 0o020 != 0)))
            {
                return Err(EvidenceError::Invalid(
                    "unsafe public SDK ownership or mode",
                ));
            }
        }
        TreeKind::InstalledPrefix => {
            if before.st_uid != 0 || (file_kind != FileType::Symlink && mode & 0o022 != 0) {
                return Err(EvidenceError::Invalid(
                    "unsafe installed prefix ownership or mode",
                ));
            }
        }
    }
    let mut row = match kind {
        TreeKind::Sdk => {
            json!({"path":relative,"uid":before.st_uid,"gid":before.st_gid,"mode":mode})
        }
        TreeKind::InstalledPrefix => json!({"uid":before.st_uid,"mode":mode}),
    };
    let mut child = None;
    let mut bytes = 0;
    match file_kind {
        FileType::Symlink => {
            let target = readlinkat(parent, name, Vec::new())
                .map_err(|error| EvidenceError::Io(error.to_string()))?;
            let resolved = root
                .join(relative)
                .canonicalize()
                .map_err(|_| EvidenceError::Invalid("unresolved tree symlink"))?;
            let allowed = resolved.starts_with(root)
                || (kind == TreeKind::InstalledPrefix
                    && [
                        Path::new("/usr/bin/python3"),
                        Path::new("/usr/bin/python3.12"),
                    ]
                    .contains(&resolved.as_path()));
            if !allowed {
                return Err(EvidenceError::Invalid("tree symlink escapes its root"));
            }
            let target = target
                .to_str()
                .map_err(|_| EvidenceError::Invalid("non-UTF8 symlink target"))?;
            row[if kind == TreeKind::Sdk {
                "symlink"
            } else {
                "link"
            }] = json!(target);
        }
        FileType::RegularFile => {
            let descriptor = openat(
                parent,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| EvidenceError::Io(error.to_string()))?;
            let opened =
                fstat(&descriptor).map_err(|error| EvidenceError::Io(error.to_string()))?;
            if !unchanged(&before, &opened) {
                return Err(EvidenceError::Invalid("tree file changed before opening"));
            }
            bytes = before
                .st_size
                .try_into()
                .map_err(|_| EvidenceError::Invalid("negative tree file size"))?;
            row["sha256"] = json!(hash_file(descriptor, &before)?);
            if kind == TreeKind::Sdk {
                row["size"] = json!(bytes);
            }
        }
        FileType::Directory => {
            let descriptor = openat(
                parent,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| EvidenceError::Io(error.to_string()))?;
            let opened =
                fstat(&descriptor).map_err(|error| EvidenceError::Io(error.to_string()))?;
            if !unchanged(&before, &opened) {
                return Err(EvidenceError::Invalid(
                    "tree directory changed before opening",
                ));
            }
            child = Some(descriptor);
        }
        _ => return Err(EvidenceError::Invalid("tree contains a nonregular object")),
    }
    let after = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
    if !unchanged(&before, &after) {
        return Err(EvidenceError::Invalid(
            "tree entry changed during inventory",
        ));
    }
    Ok((row, bytes, child))
}

fn scan(
    descriptor: &OwnedFd,
    root: &Path,
    prefix: &str,
    depth: usize,
    kind: TreeKind,
    rows: &mut Map<String, Value>,
    total: &mut u64,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(EvidenceError::Invalid("tree exceeds depth budget"));
    }
    let entries =
        Dir::read_from(descriptor).map_err(|error| EvidenceError::Io(error.to_string()))?;
    let mut names = Vec::new();
    for item in entries {
        let item = item.map_err(|error| EvidenceError::Io(error.to_string()))?;
        let name = item
            .file_name()
            .to_str()
            .map_err(|_| EvidenceError::Invalid("non-UTF8 tree entry"))?;
        if name != "." && name != ".." {
            names.push(name.to_owned());
        }
        if names.len() > MAX_ENTRIES {
            return Err(EvidenceError::Invalid("tree exceeds entry budget"));
        }
    }
    names.sort();
    for name in names {
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let (row, bytes, child) = inspect_one(descriptor, root, &name, &relative, kind)?;
        *total = total
            .checked_add(bytes)
            .filter(|size| *size <= MAX_BYTES)
            .ok_or(EvidenceError::Invalid("tree exceeds two GiB"))?;
        if rows.insert(relative.clone(), row).is_some() || rows.len() > MAX_ENTRIES {
            return Err(EvidenceError::Invalid("tree exceeds entry budget"));
        }
        if let Some(child) = child {
            scan(&child, root, &relative, depth + 1, kind, rows, total)?;
            let current = statat(descriptor, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| EvidenceError::Io(error.to_string()))?;
            let opened = fstat(&child).map_err(|error| EvidenceError::Io(error.to_string()))?;
            if !unchanged(&current, &opened) {
                return Err(EvidenceError::Invalid(
                    "tree directory changed while scanning",
                ));
            }
        }
    }
    Ok(())
}

/// Hash inert tree bytes and metadata. This is not an execution authorization.
pub fn inventory_tree(root: &Path, kind: TreeKind) -> Result<TreeInventory> {
    let descriptor = open_absolute_directory(root)?;
    let metadata = fstat(&descriptor).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if root.canonicalize().ok().as_deref() != Some(root) {
        return Err(EvidenceError::Invalid("tree root must be canonical"));
    }
    if kind == TreeKind::InstalledPrefix && (metadata.st_uid != 0 || metadata.st_mode & 0o022 != 0)
    {
        return Err(EvidenceError::Invalid(
            "installed prefix root is not root-owned",
        ));
    }
    let mut rows = Map::new();
    let mut total = 0_u64;
    scan(&descriptor, root, "", 0, kind, &mut rows, &mut total)?;
    let after = fstat(&descriptor).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if !unchanged(&metadata, &after) {
        return Err(EvidenceError::Invalid("tree root changed during inventory"));
    }
    let entries = rows.len();
    let shape = match kind {
        TreeKind::Sdk => Value::Array(rows.into_values().collect()),
        TreeKind::InstalledPrefix => {
            rows.insert(
                ".".to_owned(),
                json!({"mode":metadata.st_mode & 0o7777,"uid":metadata.st_uid}),
            );
            Value::Object(rows)
        }
    };
    let digest = sha256(&canonical_value(&shape)?);
    Ok(TreeInventory {
        digest,
        entries,
        bytes: total,
    })
}
