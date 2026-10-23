//! Passive, bounded reader for Python's private host job files. The returned
//! records are historical data, not execution authority or a coherent lease.

use crate::load_operations_bytes;
use rustix::fs::{
    flock, fstat, open, openat, statat, AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, Stat,
};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::Value;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

const MAX_JOB_COUNT: usize = 4096;
const MAX_JOB_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateJobError {
    InvalidPath,
    UnsafeDirectory,
    UnsafeJob,
    UnsafeLock,
    ObserverBusy,
    InvalidConfig,
    Changed,
    TooLarge,
    Io,
}

impl fmt::Display for PrivateJobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPath => "invalid host state path",
            Self::UnsafeDirectory => "private host state directory is unsafe",
            Self::UnsafeJob => "private host job record is unsafe or malformed",
            Self::UnsafeLock => "Python observer lock is unsafe",
            Self::ObserverBusy => "Python observer owns the host state",
            Self::InvalidConfig => "private host operations config is malformed",
            Self::Changed => "private host jobs changed during read",
            Self::TooLarge => "private host job inventory exceeds bounds",
            Self::Io => "private host job I/O failed",
        })
    }
}

impl std::error::Error for PrivateJobError {}

fn private_directory(stat: &Stat, owner: u32) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == owner
        && stat.st_mode & 0o077 == 0
}

pub(crate) fn state_root(path: &Path, owner: u32) -> Result<OwnedFd, PrivateJobError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(PrivateJobError::InvalidPath);
    }
    let mut dir = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PrivateJobError::Io)?;
    let mut saw_component = false;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                saw_component = true;
                dir = openat(
                    &dir,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| PrivateJobError::Io)?;
            }
            _ => return Err(PrivateJobError::InvalidPath),
        }
    }
    if !saw_component || !private_directory(&fstat(&dir).map_err(|_| PrivateJobError::Io)?, owner) {
        return Err(PrivateJobError::UnsafeDirectory);
    }
    Ok(dir)
}

pub(crate) fn child_directory(
    parent: &OwnedFd,
    name: &str,
    owner: u32,
) -> Result<OwnedFd, PrivateJobError> {
    let dir = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PrivateJobError::Io)?;
    if !private_directory(&fstat(&dir).map_err(|_| PrivateJobError::Io)?, owner) {
        return Err(PrivateJobError::UnsafeDirectory);
    }
    Ok(dir)
}

pub(crate) fn job_name(name: &str) -> bool {
    let Some(id) = name.strip_suffix(".json") else {
        return false;
    };
    id.len() == 16
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn list_names(dir: &OwnedFd) -> Result<Vec<String>, PrivateJobError> {
    let mut stream = Dir::read_from(dir).map_err(|_| PrivateJobError::Io)?;
    let mut names = Vec::new();
    for entry in &mut stream {
        let entry = entry.map_err(|_| PrivateJobError::Io)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        let name = std::str::from_utf8(name).map_err(|_| PrivateJobError::UnsafeJob)?;
        if !job_name(name) {
            return Err(PrivateJobError::UnsafeJob);
        }
        names.push(name.to_owned());
        if names.len() > MAX_JOB_COUNT {
            return Err(PrivateJobError::TooLarge);
        }
    }
    names.sort();
    Ok(names)
}

pub(crate) fn same_file(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_nlink == right.st_nlink
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

fn read_regular_bytes(dir: &OwnedFd, name: &str, owner: u32) -> Result<Vec<u8>, PrivateJobError> {
    let descriptor = openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PrivateJobError::Io)?;
    let before = fstat(&descriptor).map_err(|_| PrivateJobError::Io)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != owner
        || before.st_mode & 0o777 != 0o600
        || before.st_nlink != 1
        || before.st_size < 0
    {
        return Err(PrivateJobError::UnsafeJob);
    }
    if before.st_size as u64 > MAX_JOB_BYTES {
        return Err(PrivateJobError::TooLarge);
    }
    let path_before =
        statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| PrivateJobError::Changed)?;
    if !same_file(&before, &path_before) {
        return Err(PrivateJobError::Changed);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_JOB_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PrivateJobError::Io)?;
    if bytes.len() as u64 > MAX_JOB_BYTES {
        return Err(PrivateJobError::TooLarge);
    }
    let after = fstat(&file).map_err(|_| PrivateJobError::Io)?;
    let path_after =
        statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| PrivateJobError::Changed)?;
    if bytes.len() as i64 != before.st_size
        || !same_file(&before, &after)
        || !same_file(&before, &path_after)
    {
        return Err(PrivateJobError::Changed);
    }
    Ok(bytes)
}

fn read_one(dir: &OwnedFd, name: &str, owner: u32) -> Result<(Value, u64), PrivateJobError> {
    let bytes = read_regular_bytes(dir, name, owner)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| PrivateJobError::UnsafeJob)?;
    let expected_id = name
        .strip_suffix(".json")
        .ok_or(PrivateJobError::UnsafeJob)?;
    if !value.is_object()
        || value.get("id").and_then(Value::as_str) != Some(expected_id)
        || !value.get("state").is_some_and(Value::is_string)
    {
        return Err(PrivateJobError::UnsafeJob);
    }
    Ok((value, bytes.len() as u64))
}

/// Privately read the Python host's operator config through the same stable
/// descriptor custody as a job record, then apply the pinned Python-compatible
/// merge/validation. The returned data is not source authority by itself.
pub fn read_private_operations(state: &Path) -> Result<Value, PrivateJobError> {
    let owner = geteuid().as_raw();
    let root = state_root(state, owner)?;
    let bytes = read_regular_bytes(&root, "config.json", owner)?;
    load_operations_bytes(&bytes).map_err(|_| PrivateJobError::InvalidConfig)
}

/// Read every historical Python job through private descriptor-relative paths.
/// A changed or unsafe file makes the entire observation unavailable. The
/// result is for diagnosis only: it does not own Python's lease or authorize a
/// Rust queue decision, VM request, status write or automatic reconciliation.
pub fn read_private_jobs(state: &Path) -> Result<Vec<Value>, PrivateJobError> {
    let owner = geteuid().as_raw();
    let root = state_root(state, owner)?;
    let private = child_directory(&root, "private", owner)?;
    read_jobs_from_private(&private, owner)
}

fn read_jobs_from_private(private: &OwnedFd, owner: u32) -> Result<Vec<Value>, PrivateJobError> {
    let jobs = child_directory(private, "jobs", owner)?;
    let jobs_before = fstat(&jobs).map_err(|_| PrivateJobError::Io)?;
    let names = list_names(&jobs)?;
    let mut records = Vec::with_capacity(names.len());
    let mut total = 0u64;
    for name in &names {
        let (record, bytes) = read_one(&jobs, name, owner)?;
        total = total.checked_add(bytes).ok_or(PrivateJobError::TooLarge)?;
        if total > MAX_TOTAL_BYTES {
            return Err(PrivateJobError::TooLarge);
        }
        records.push(record);
    }
    let visible_jobs =
        statat(private, "jobs", AtFlags::SYMLINK_NOFOLLOW).map_err(|_| PrivateJobError::Changed)?;
    if names != list_names(&jobs)? || !same_file(&jobs_before, &visible_jobs) {
        return Err(PrivateJobError::Changed);
    }
    Ok(records)
}

/// Take a nonblocking shared snapshot only while Python's `agent.lock` has no
/// exclusive owner. This is a read-only cutover diagnostic, not a Rust observer
/// lease or permission to write, reconcile, dispatch, or publish state.
pub fn read_private_jobs_if_idle(state: &Path) -> Result<Vec<Value>, PrivateJobError> {
    let owner = geteuid().as_raw();
    let root = state_root(state, owner)?;
    let root_before = fstat(&root).map_err(|_| PrivateJobError::Io)?;
    let private = child_directory(&root, "private", owner)?;
    let private_before = fstat(&private).map_err(|_| PrivateJobError::Io)?;
    let lock = openat(
        &private,
        "agent.lock",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| PrivateJobError::UnsafeLock)?;
    let lock_before = fstat(&lock).map_err(|_| PrivateJobError::Io)?;
    if FileType::from_raw_mode(lock_before.st_mode) != FileType::RegularFile
        || lock_before.st_uid != owner
        || lock_before.st_mode & 0o777 != 0o600
        || lock_before.st_nlink != 1
        || lock_before.st_size != 0
    {
        return Err(PrivateJobError::UnsafeLock);
    }
    let visible_before = statat(&private, "agent.lock", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| PrivateJobError::Changed)?;
    if !same_file(&lock_before, &visible_before) {
        return Err(PrivateJobError::Changed);
    }
    match flock(&lock, FlockOperation::NonBlockingLockShared) {
        Ok(()) => {}
        Err(Errno::AGAIN) => return Err(PrivateJobError::ObserverBusy),
        Err(_) => return Err(PrivateJobError::Io),
    }
    let records = read_jobs_from_private(&private, owner)?;
    let lock_after = fstat(&lock).map_err(|_| PrivateJobError::Io)?;
    let visible_after = statat(&private, "agent.lock", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| PrivateJobError::Changed)?;
    let private_after = fstat(&private).map_err(|_| PrivateJobError::Io)?;
    let visible_private = statat(&root, "private", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| PrivateJobError::Changed)?;
    let reopened_root = state_root(state, owner).map_err(|_| PrivateJobError::Changed)?;
    let root_after = fstat(&reopened_root).map_err(|_| PrivateJobError::Io)?;
    if !same_file(&lock_before, &lock_after)
        || !same_file(&lock_before, &visible_after)
        || !same_file(&private_before, &private_after)
        || !same_file(&private_before, &visible_private)
        || !same_file(&root_before, &root_after)
    {
        return Err(PrivateJobError::Changed);
    }
    Ok(records)
}
