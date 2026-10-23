//! Inert Python-compatible SDK and installed-prefix inventories.
//!
//! Directory and file enumeration is descriptor-relative. Linux symlink
//! containment uses openat2, but complete race/parity proof is still required
//! before this reader can participate in execution admission.

use crate::crypto::sha256;
use crate::io::open_absolute_directory;
use crate::{canonical_value, EvidenceError, Result};
use gauntlet_contracts::canonical_relative_asset_path;
use rustix::fs::{fstat, openat, readlinkat, statat, AtFlags, Dir, FileType, Mode, OFlags, Stat};
#[cfg(target_os = "linux")]
use rustix::fs::{open, openat2, ResolveFlags};
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
    Controller,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeInventory {
    pub digest: String,
    pub entries: usize,
    pub bytes: u64,
}

struct TreeContext<'a> {
    #[cfg(not(target_os = "linux"))]
    root: &'a Path,
    #[cfg(target_os = "linux")]
    root_fd: &'a OwnedFd,
    kind: TreeKind,
}

#[cfg(target_os = "linux")]
fn symlink_contained(context: &TreeContext<'_>, relative: &str) -> Result<()> {
    if context.kind == TreeKind::Controller {
        return Err(EvidenceError::Invalid("controller tree contains a symlink"));
    }
    let flags = OFlags::PATH | OFlags::CLOEXEC;
    if openat2(
        context.root_fd,
        relative,
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS,
    )
    .is_ok()
    {
        return Ok(());
    }
    if context.kind == TreeKind::InstalledPrefix {
        let resolved = openat2(
            context.root_fd,
            relative,
            flags,
            Mode::empty(),
            ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| EvidenceError::Invalid("tree symlink escapes its root"))?;
        let observed = fstat(&resolved).map_err(|error| EvidenceError::Io(error.to_string()))?;
        for path in ["/usr/bin/python3", "/usr/bin/python3.12"] {
            let allowed = open(path, flags, Mode::empty())
                .map_err(|error| EvidenceError::Io(error.to_string()))?;
            let trusted = fstat(&allowed).map_err(|error| EvidenceError::Io(error.to_string()))?;
            if FileType::from_raw_mode(trusted.st_mode) == FileType::RegularFile
                && trusted.st_uid == 0
                && trusted.st_mode & 0o022 == 0
                && observed.st_dev == trusted.st_dev
                && observed.st_ino == trusted.st_ino
            {
                return Ok(());
            }
        }
    }
    Err(EvidenceError::Invalid("tree symlink escapes its root"))
}

#[cfg(not(target_os = "linux"))]
fn symlink_contained(context: &TreeContext<'_>, relative: &str) -> Result<()> {
    if context.kind == TreeKind::Controller {
        return Err(EvidenceError::Invalid("controller tree contains a symlink"));
    }
    let resolved = context
        .root
        .join(relative)
        .canonicalize()
        .map_err(|_| EvidenceError::Invalid("unresolved tree symlink"))?;
    if resolved.starts_with(context.root)
        || (context.kind == TreeKind::InstalledPrefix
            && [
                Path::new("/usr/bin/python3"),
                Path::new("/usr/bin/python3.12"),
            ]
            .contains(&resolved.as_path()))
    {
        Ok(())
    } else {
        Err(EvidenceError::Invalid("tree symlink escapes its root"))
    }
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

fn hash_file_after_chunk(
    descriptor: OwnedFd,
    before: &Stat,
    after_first_chunk: impl FnOnce(),
) -> Result<String> {
    if before.st_size < 0 || before.st_size as u64 > MAX_BYTES {
        return Err(EvidenceError::Invalid("tree file exceeds byte budget"));
    }
    let mut file = File::from(descriptor);
    let mut hasher = sha2::Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    let mut after_first_chunk = Some(after_first_chunk);
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
        if let Some(callback) = after_first_chunk.take() {
            callback();
        }
    }
    let after = fstat(&file).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if total != before.st_size as u64 || !unchanged(before, &after) {
        return Err(EvidenceError::Invalid("tree file changed while hashing"));
    }
    Ok(format!("{:x}", sha2::Digest::finalize(hasher)))
}

fn hash_file(descriptor: OwnedFd, before: &Stat) -> Result<String> {
    hash_file_after_chunk(descriptor, before, || {})
}

fn stable_symlink_target(
    parent: &OwnedFd,
    context: &TreeContext<'_>,
    name: &str,
    relative: &str,
    after_initial_read: impl FnOnce(),
) -> Result<String> {
    let target = readlinkat(parent, name, Vec::new())
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
    after_initial_read();
    symlink_contained(context, relative)?;
    let after_target = readlinkat(parent, name, Vec::new())
        .map_err(|_| EvidenceError::Invalid("tree symlink changed during inventory"))?;
    if target != after_target {
        return Err(EvidenceError::Invalid(
            "tree symlink changed during inventory",
        ));
    }
    target
        .to_str()
        .map(str::to_owned)
        .map_err(|_| EvidenceError::Invalid("non-UTF8 symlink target"))
}

fn inspect_one(
    parent: &OwnedFd,
    context: &TreeContext<'_>,
    name: &str,
    relative: &str,
) -> Result<(Value, u64, Option<OwnedFd>, Stat)> {
    if !canonical_relative_asset_path(relative) {
        return Err(EvidenceError::Invalid("noncanonical tree entry"));
    }
    let before = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
    let file_kind = FileType::from_raw_mode(before.st_mode);
    let mode = before.st_mode & 0o7777;
    let kind = context.kind;
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
        TreeKind::InstalledPrefix | TreeKind::Controller => {
            if before.st_uid != 0
                || (file_kind != FileType::Symlink && mode & 0o022 != 0)
                || (kind == TreeKind::Controller
                    && (file_kind == FileType::Symlink
                        || file_kind == FileType::RegularFile && before.st_nlink != 1))
            {
                return Err(EvidenceError::Invalid(
                    "unsafe installed tree ownership, mode or link",
                ));
            }
        }
    }
    let mut row = match kind {
        TreeKind::Sdk => {
            json!({"path":relative,"uid":before.st_uid,"gid":before.st_gid,"mode":mode})
        }
        TreeKind::InstalledPrefix | TreeKind::Controller => {
            json!({"uid":before.st_uid,"mode":mode})
        }
    };
    let mut child = None;
    let mut bytes = 0;
    match file_kind {
        FileType::Symlink => {
            let target = stable_symlink_target(parent, context, name, relative, || {})?;
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
    Ok((row, bytes, child, before))
}

fn directory_names(descriptor: &OwnedFd) -> Result<Vec<String>> {
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
    Ok(names)
}

fn scan<F: FnMut(&str)>(
    descriptor: &OwnedFd,
    context: &TreeContext<'_>,
    prefix: &str,
    depth: usize,
    rows: &mut Map<String, Value>,
    total: &mut u64,
    after_directory_scan: &mut F,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(EvidenceError::Invalid("tree exceeds depth budget"));
    }
    let names = directory_names(descriptor)?;
    for name in &names {
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let (row, bytes, child, before) = inspect_one(descriptor, context, name, &relative)?;
        *total = total
            .checked_add(bytes)
            .filter(|size| *size <= MAX_BYTES)
            .ok_or(EvidenceError::Invalid("tree exceeds two GiB"))?;
        if rows.insert(relative.clone(), row).is_some() || rows.len() > MAX_ENTRIES {
            return Err(EvidenceError::Invalid("tree exceeds entry budget"));
        }
        if let Some(child) = child {
            scan(
                &child,
                context,
                &relative,
                depth + 1,
                rows,
                total,
                after_directory_scan,
            )?;
            let current = statat(descriptor, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|error| EvidenceError::Io(error.to_string()))?;
            let opened = fstat(&child).map_err(|error| EvidenceError::Io(error.to_string()))?;
            if !unchanged(&before, &current) || !unchanged(&before, &opened) {
                return Err(EvidenceError::Invalid(
                    "tree directory changed while scanning",
                ));
            }
        }
    }
    after_directory_scan(prefix);
    if names != directory_names(descriptor)? {
        return Err(EvidenceError::Invalid(
            "tree directory changed while scanning",
        ));
    }
    Ok(())
}

/// Hash inert tree bytes and metadata. This is not an execution authorization.
pub fn inventory_tree(root: &Path, kind: TreeKind) -> Result<TreeInventory> {
    inventory_tree_with_after_scan(root, kind, || {})
}

fn inventory_tree_with_after_scan(
    root: &Path,
    kind: TreeKind,
    after_scan: impl FnOnce(),
) -> Result<TreeInventory> {
    let mut no_directory_change = |_: &str| {};
    inventory_tree_with_hooks(root, kind, after_scan, &mut no_directory_change)
}

fn inventory_tree_with_hooks<F: FnMut(&str)>(
    root: &Path,
    kind: TreeKind,
    after_scan: impl FnOnce(),
    after_directory_scan: &mut F,
) -> Result<TreeInventory> {
    let descriptor = open_absolute_directory(root)?;
    let metadata = fstat(&descriptor).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if root.canonicalize().ok().as_deref() != Some(root) {
        return Err(EvidenceError::Invalid("tree root must be canonical"));
    }
    if matches!(kind, TreeKind::InstalledPrefix | TreeKind::Controller)
        && (metadata.st_uid != 0 || metadata.st_mode & 0o022 != 0)
    {
        return Err(EvidenceError::Invalid(
            "installed prefix root is not root-owned",
        ));
    }
    let mut rows = Map::new();
    let mut total = 0_u64;
    let context = TreeContext {
        #[cfg(not(target_os = "linux"))]
        root,
        #[cfg(target_os = "linux")]
        root_fd: &descriptor,
        kind,
    };
    scan(
        &descriptor,
        &context,
        "",
        0,
        &mut rows,
        &mut total,
        after_directory_scan,
    )?;
    after_scan();
    let after = fstat(&descriptor).map_err(|error| EvidenceError::Io(error.to_string()))?;
    if !unchanged(&metadata, &after) {
        return Err(EvidenceError::Invalid("tree root changed during inventory"));
    }
    let visible = open_absolute_directory(root)
        .map_err(|_| EvidenceError::Invalid("tree root changed during inventory"))?;
    let visible = fstat(&visible)
        .map_err(|_| EvidenceError::Invalid("tree root changed during inventory"))?;
    if !unchanged(&metadata, &visible) {
        return Err(EvidenceError::Invalid("tree root changed during inventory"));
    }
    let entries = rows.len();
    let shape = match kind {
        TreeKind::Sdk => Value::Array(rows.into_values().collect()),
        TreeKind::InstalledPrefix | TreeKind::Controller => {
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

#[cfg(all(test, target_os = "linux"))]
#[path = "tree_inventory_tests.rs"]
mod linux_tests;
