//! Policy files on Unix: the folder is reached one component at a time from
//! `/` without following a link, and every file operation is relative to
//! that folder's descriptor.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{open, openat, renameat, AtFlags, OFlag};
use nix::sys::stat::{fchmod, fstat, fstatat, FileStat, Mode, SFlag};
use nix::unistd::{fsync, geteuid, unlinkat, UnlinkatFlags};

use super::Failure;

/// Replaces the temporary file with the policy file inside one folder.
pub(super) type Rename<'a> = &'a dyn Fn(&OwnedFd, &OsStr, &OsStr) -> nix::Result<()>;

pub(super) fn path_from_bytes(bytes: Vec<u8>) -> Option<PathBuf> {
    Some(PathBuf::from(OsString::from_vec(bytes)))
}

pub(super) fn read_trusted(path: &Path, limit: usize) -> Result<Vec<u8>, Failure> {
    let parent = open_trusted_parent(path)?;
    let name = path.file_name().ok_or("policy_file_unavailable")?;
    let before = fstatat(&parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|_| "policy_file_unavailable")?;
    check_file(&before)?;
    let flags = OFlag::O_RDONLY
        | OFlag::O_CLOEXEC
        | OFlag::O_NOFOLLOW
        | OFlag::O_NONBLOCK
        | OFlag::O_NOCTTY;
    let file: File = openat(&parent, name, flags, Mode::empty())
        .map_err(|_| "policy_file_open_failed")?
        .into();
    let opened = fstat(&file).map_err(|_| "policy_file_open_failed")?;
    check_file(&opened)?;
    if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) {
        return Err("policy_file_changed");
    }
    let mut payload = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut payload)
        .map_err(|_| "policy_file_open_failed")?;
    if payload.len() > limit {
        return Err("policy_file_too_large");
    }
    Ok(payload)
}

pub(super) fn write_private(path: &Path, payload: &[u8]) -> Result<(), Failure> {
    write_private_with(path, payload, &|directory, from, to| {
        renameat(directory, from, directory, to)
    })
}

/// Write `payload` to a new owner-only file beside `path` and rename it over
/// `path`; the temporary file never outlives the call.
pub(super) fn write_private_with(
    path: &Path,
    payload: &[u8],
    rename: Rename<'_>,
) -> Result<(), Failure> {
    let parent = open_trusted_parent(path)?;
    let name = path.file_name().ok_or("policy_output_unavailable")?;
    match fstatat(&parent, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(existing) => check_file(&existing)?,
        Err(Errno::ENOENT) => {}
        Err(_) => return Err("policy_output_unavailable"),
    }
    let temporary = temporary_name()?;
    let written = publish(&parent, OsStr::new(&temporary), name, payload, rename);
    let _ = unlinkat(&parent, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    written.map_err(|_| "policy_output_write_failed")
}

fn publish(
    parent: &OwnedFd,
    temporary: &OsStr,
    name: &OsStr,
    payload: &[u8],
    rename: Rename<'_>,
) -> std::io::Result<()> {
    let flags =
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW;
    let private = Mode::S_IRUSR | Mode::S_IWUSR;
    let mut file: File = openat(parent, temporary, flags, private)?.into();
    fchmod(&file, private)?;
    file.write_all(payload)?;
    fsync(&file)?;
    drop(file);
    rename(parent, temporary, name)?;
    fsync(parent).map_err(std::io::Error::from)
}

/// An opaque name, so the temporary file fits wherever the policy file does
/// whatever the policy file's name is.
fn temporary_name() -> Result<String, Failure> {
    let mut token = [0_u8; 12];
    getrandom::fill(&mut token).map_err(|_| "policy_output_write_failed")?;
    Ok(format!(".policy-{}.tmp", hex::encode(token)))
}

/// Open the folder holding `path` without following a link at any step,
/// then require that the effective user owns it and alone may write it.
fn open_trusted_parent(path: &Path) -> Result<OwnedFd, Failure> {
    let parent = path.parent().ok_or("policy_parent_unavailable")?;
    let flags = OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW;
    let mut components = parent.components();
    if components.next() != Some(std::path::Component::RootDir) {
        return Err("policy_parent_unavailable");
    }
    let mut directory = open("/", flags, Mode::empty()).map_err(|_| "policy_parent_unavailable")?;
    for component in components {
        directory = openat(&directory, component.as_os_str(), flags, Mode::empty())
            .map_err(|_| "policy_parent_unavailable")?;
    }
    let metadata = fstat(&directory).map_err(|_| "policy_parent_unavailable")?;
    if file_type(&metadata) != SFlag::S_IFDIR {
        return Err("policy_parent_not_directory");
    }
    if metadata.st_uid != geteuid().as_raw() {
        return Err("policy_parent_not_owned");
    }
    if writable_by_others(&metadata) {
        return Err("policy_parent_insecure_mode");
    }
    Ok(directory)
}

fn check_file(metadata: &FileStat) -> Result<(), Failure> {
    if file_type(metadata) != SFlag::S_IFREG {
        return Err("policy_file_not_regular");
    }
    if metadata.st_uid != geteuid().as_raw() {
        return Err("policy_file_not_owned");
    }
    if writable_by_others(metadata) {
        return Err("policy_file_insecure_mode");
    }
    if metadata.st_nlink != 1 {
        return Err("policy_file_link_count");
    }
    Ok(())
}

fn file_type(metadata: &FileStat) -> SFlag {
    SFlag::from_bits_truncate(metadata.st_mode) & SFlag::S_IFMT
}

fn writable_by_others(metadata: &FileStat) -> bool {
    Mode::from_bits_truncate(metadata.st_mode).intersects(Mode::S_IWGRP | Mode::S_IWOTH)
}
