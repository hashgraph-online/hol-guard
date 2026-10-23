//! Read-only custody snapshot of idle Python controller invocation files.
//!
//! A live caller must be Linux Root. This never creates a lock, modifies
//! records, resumes a job or asserts a benchmark verdict.

use crate::controller_invocations::ControllerInvocationBytes;
use crate::io::open_absolute_directory;
use crate::{EvidenceError, Result};
use gauntlet_contracts::MAX_RECORD_BYTES;
use rustix::fs::{fstat, openat, statat, AtFlags, Dir, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use rustix::process::geteuid;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MAX_INVOCATIONS: usize = 10_000;
const MAX_FILES_PER_INVOCATION: usize = 16;
const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;

fn invalid(message: &'static str) -> EvidenceError {
    EvidenceError::Invalid(message)
}

fn io(error: impl std::fmt::Display) -> EvidenceError {
    EvidenceError::Io(error.to_string())
}

fn unchanged(before: &Stat, after: &Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid
        && before.st_gid == after.st_gid
        && before.st_nlink == after.st_nlink
        && before.st_size == after.st_size
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn private_directory(fd: &OwnedFd, owner: u32) -> Result<Stat> {
    let status = fstat(fd).map_err(io)?;
    if FileType::from_raw_mode(status.st_mode) != FileType::Directory
        || status.st_uid != owner
        || status.st_mode & 0o7777 != 0o700
    {
        return Err(invalid("controller invocation directory is not private"));
    }
    Ok(status)
}

fn safe_ancestry(path: &Path, owner: u32) -> Result<()> {
    if path.canonicalize().ok().as_deref() != Some(path) {
        return Err(invalid("canonical controller state path required"));
    }
    for parent in path.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(parent).map_err(io)?;
        let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || ![0, owner].contains(&metadata.uid())
            || (metadata.mode() & 0o022 != 0 && !sticky_root)
        {
            return Err(invalid("controller state ancestry is mutable"));
        }
    }
    Ok(())
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn list_names(fd: &OwnedFd, maximum: usize) -> Result<Vec<String>> {
    let entries = Dir::read_from(fd).map_err(io)?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(io)?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| invalid("non-UTF-8 controller invocation entry"))?;
        if matches!(name, "." | "..") {
            continue;
        }
        if !safe_name(name) || names.len() == maximum {
            return Err(invalid("controller invocation inventory exceeds bound"));
        }
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

fn read_private_file(dir: &OwnedFd, name: &str, owner: u32) -> Result<Vec<u8>> {
    let descriptor = openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io)?;
    let before = fstat(&descriptor).map_err(io)?;
    let named = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != owner
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != 0o600
        || before.st_size < 0
        || before.st_size as u64 > MAX_RECORD_BYTES as u64
        || !unchanged(&before, &named)
    {
        return Err(invalid("controller invocation file lacks private custody"));
    }
    let mut file = File::from(descriptor);
    let mut raw = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take((MAX_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(io)?;
    let after = fstat(&file).map_err(io)?;
    let named = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if raw.len() != before.st_size as usize
        || raw.len() > MAX_RECORD_BYTES
        || !unchanged(&before, &after)
        || !unchanged(&before, &named)
    {
        return Err(invalid("controller invocation file changed while reading"));
    }
    Ok(raw)
}

fn refuse_active_controller(state: &OwnedFd) -> Result<()> {
    match statat(state, "ci-controller.lock", AtFlags::SYMLINK_NOFOLLOW) {
        Err(Errno::NOENT) => Ok(()),
        Ok(_) => Err(invalid(
            "controller invocation journal is active or uncertain",
        )),
        Err(error) => Err(io(error)),
    }
}

fn read_for_owner(state_path: &Path, owner: u32) -> Result<Option<Vec<ControllerInvocationBytes>>> {
    let state = open_absolute_directory(state_path)?;
    safe_ancestry(state_path, owner)?;
    let state_before = private_directory(&state, owner)?;
    refuse_active_controller(&state)?;
    let attempts = match openat(
        &state,
        "controller-attempts",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => {
            refuse_active_controller(&state)?;
            let state_after = fstat(&state).map_err(io)?;
            if !unchanged(&state_before, &state_after) {
                return Err(invalid(
                    "controller invocation inventory changed while reading",
                ));
            }
            return Ok(None);
        }
        Err(error) => return Err(io(error)),
    };
    let attempts_before = private_directory(&attempts, owner)?;
    let names = list_names(&attempts, MAX_INVOCATIONS)?;
    let mut total_bytes = 0_usize;
    let mut records = Vec::with_capacity(names.len());
    for name in names {
        let invocation = openat(
            &attempts,
            name.as_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io)?;
        let before = private_directory(&invocation, owner)?;
        let named = statat(&attempts, name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
        if !unchanged(&before, &named) {
            return Err(invalid("controller invocation directory changed"));
        }
        let file_names = list_names(&invocation, MAX_FILES_PER_INVOCATION)?;
        let mut files = BTreeMap::new();
        for file_name in file_names {
            let raw = read_private_file(&invocation, &file_name, owner)?;
            total_bytes = total_bytes
                .checked_add(raw.len())
                .filter(|sum| *sum <= MAX_TOTAL_BYTES)
                .ok_or(invalid(
                    "controller invocation byte inventory exceeds bound",
                ))?;
            files.insert(file_name, raw);
        }
        let after = fstat(&invocation).map_err(io)?;
        let named = statat(&attempts, name.as_str(), AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
        if !unchanged(&before, &after) || !unchanged(&before, &named) {
            return Err(invalid("controller invocation directory changed"));
        }
        records.push(ControllerInvocationBytes { name, files });
    }
    let attempts_after = fstat(&attempts).map_err(io)?;
    let attempts_named =
        statat(&state, "controller-attempts", AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    refuse_active_controller(&state)?;
    let state_after = fstat(&state).map_err(io)?;
    if !unchanged(&attempts_before, &attempts_after)
        || !unchanged(&attempts_before, &attempts_named)
        || !unchanged(&state_before, &state_after)
    {
        return Err(invalid(
            "controller invocation inventory changed while reading",
        ));
    }
    Ok(Some(records))
}

/// Snapshot an idle, Root-owned retained Python controller journal on Linux.
/// This is diagnostic evidence only and cannot establish a completed run.
pub fn read_controller_invocations_root_owned(
    state_path: &Path,
) -> Result<Option<Vec<ControllerInvocationBytes>>> {
    if !cfg!(target_os = "linux") || geteuid().as_raw() != 0 {
        return Err(invalid("Linux Root controller custody required"));
    }
    read_for_owner(state_path, 0)
}

#[cfg(test)]
#[path = "controller_invocation_files_tests.rs"]
mod tests;
