//! Read-only custody of one retained Python VM worker receipt and report.
//! This cannot authenticate the worker program or recompute its controls.

use crate::worker_receipt::{verify_python_worker_terminal, PythonWorkerTerminal};
use crate::{EvidenceError, Result};
use rustix::fs::{fstat, open, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use rustix::process::geteuid;
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;

const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;
const MAX_REPORT_BYTES: u64 = 16 * 1024 * 1024;
const OUTPUTS: &[&str] = &["var", "lib", "hol-gauntlet", "outputs"];

fn invalid(message: &'static str) -> EvidenceError {
    EvidenceError::Invalid(message)
}

fn io(error: impl std::fmt::Display) -> EvidenceError {
    EvidenceError::Io(error.to_string())
}

pub(crate) fn unchanged(before: &Stat, after: &Stat) -> bool {
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

pub(crate) fn private_directory(fd: &OwnedFd, owner: u32) -> Result<Stat> {
    let stat = fstat(fd).map_err(io)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != owner
        || stat.st_mode & 0o7777 != 0o700
    {
        return Err(invalid("Python worker directory lacks private custody"));
    }
    Ok(stat)
}

pub(crate) fn open_private_directory(
    parent: &OwnedFd,
    name: &str,
    owner: u32,
) -> Result<Option<(OwnedFd, Stat)>> {
    let fd = match openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(io(error)),
    };
    let stat = private_directory(&fd, owner)?;
    let named = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if !unchanged(&stat, &named) {
        return Err(invalid("Python worker directory changed while reading"));
    }
    Ok(Some((fd, stat)))
}

pub(crate) fn read_private_file(
    parent: &OwnedFd,
    name: &str,
    owner: u32,
    limit: u64,
) -> Result<Option<Vec<u8>>> {
    let descriptor = match openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(io(error)),
    };
    let before = fstat(&descriptor).map_err(io)?;
    let named = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != owner
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != 0o600
        || before.st_size < 0
        || before.st_size as u64 > limit
        || !unchanged(&before, &named)
    {
        return Err(invalid("Python worker file lacks private custody"));
    }
    let mut file = File::from(descriptor);
    let mut raw = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take(limit + 1)
        .read_to_end(&mut raw)
        .map_err(io)?;
    let after = fstat(&file).map_err(io)?;
    let named = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if raw.len() as u64 != before.st_size as u64
        || raw.len() as u64 > limit
        || !unchanged(&before, &after)
        || !unchanged(&before, &named)
    {
        return Err(invalid("Python worker file changed while reading"));
    }
    Ok(Some(raw))
}

fn read_report(outputs: &OwnedFd, job_id: &str, owner: u32) -> Result<Option<Vec<u8>>> {
    let Some((job, job_before)) = open_private_directory(outputs, job_id, owner)? else {
        return Ok(None);
    };
    let report_raw =
        if let Some((report, report_before)) = open_private_directory(&job, "report", owner)? {
            let raw = read_private_file(&report, "result.json", owner, MAX_REPORT_BYTES)?;
            let after = fstat(&report).map_err(io)?;
            let named = statat(&job, "report", AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
            if !unchanged(&report_before, &after) || !unchanged(&report_before, &named) {
                return Err(invalid("Python worker report directory changed"));
            }
            raw
        } else {
            None
        };
    let after = fstat(&job).map_err(io)?;
    let named = statat(outputs, job_id, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if !unchanged(&job_before, &after) || !unchanged(&job_before, &named) {
        return Err(invalid("Python worker job directory changed"));
    }
    Ok(report_raw)
}

fn valid_job_id(job_id: &str) -> bool {
    job_id.len() == 16
        && job_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn read_for_owner(
    outputs: &OwnedFd,
    job_id: &str,
    expected_source_sha: &str,
    expected_deployment_digest: &str,
    expected_config_digest: &str,
    owner: u32,
) -> Result<PythonWorkerTerminal> {
    if !valid_job_id(job_id) {
        return Err(invalid("invalid independent worker job ID"));
    }
    let before = private_directory(outputs, owner)?;
    let receipt_name = format!("{job_id}.json");
    let receipt = read_private_file(outputs, &receipt_name, owner, MAX_RECEIPT_BYTES)?
        .ok_or(invalid("Python worker terminal receipt is missing"))?;
    let report = read_report(outputs, job_id, owner)?;
    let result = verify_python_worker_terminal(
        &receipt,
        report.as_deref(),
        expected_source_sha,
        job_id,
        expected_deployment_digest,
        expected_config_digest,
    )?;
    let receipt_after = read_private_file(outputs, &receipt_name, owner, MAX_RECEIPT_BYTES)?
        .ok_or(invalid("Python worker terminal receipt disappeared"))?;
    let report_after = read_report(outputs, job_id, owner)?;
    if receipt_after != receipt || report_after != report {
        return Err(invalid("Python worker terminal changed across snapshot"));
    }
    let after = fstat(outputs).map_err(io)?;
    if !unchanged(&before, &after) {
        return Err(invalid("Python worker output directory changed"));
    }
    Ok(result)
}

fn open_root_outputs() -> Result<OwnedFd> {
    let mut directory = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io)?;
    for component in OUTPUTS {
        let parent = fstat(&directory).map_err(io)?;
        if parent.st_uid != 0 || parent.st_mode & 0o022 != 0 {
            return Err(invalid("Python worker output ancestry is mutable"));
        }
        directory = openat(
            &directory,
            *component,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io)?;
    }
    private_directory(&directory, 0)?;
    Ok(directory)
}

/// Read one fixed Root-owned Python worker terminal from the retained Linux
/// outputs tree. A consistent receipt is diagnostic only: the Python worker
/// generation and the six deterministic controls remain unauthenticated here.
pub fn read_python_worker_terminal_root_owned(
    job_id: &str,
    expected_source_sha: &str,
    expected_deployment_digest: &str,
    expected_config_digest: &str,
) -> Result<PythonWorkerTerminal> {
    if !cfg!(target_os = "linux") || geteuid().as_raw() != 0 {
        return Err(invalid("Linux Root worker-output custody required"));
    }
    let outputs = open_root_outputs()?;
    let original = fstat(&outputs).map_err(io)?;
    let terminal = read_for_owner(
        &outputs,
        job_id,
        expected_source_sha,
        expected_deployment_digest,
        expected_config_digest,
        0,
    )?;
    let reopened = open_root_outputs()?;
    let visible = fstat(&reopened).map_err(io)?;
    if !unchanged(&original, &visible) {
        return Err(invalid("Python worker output root was replaced"));
    }
    Ok(terminal)
}

/// Read only the fixed `<job>/report/result.json` bytes under the existing
/// private Root-owned output root. A missing report remains missing; no
/// producer status is inferred from this filesystem observation.
pub(crate) fn read_root_owned_report_bytes(job_id: &str) -> Result<Option<Vec<u8>>> {
    if !cfg!(target_os = "linux") || geteuid().as_raw() != 0 {
        return Err(invalid("Linux Root worker-output custody required"));
    }
    if !valid_job_id(job_id) {
        return Err(invalid("invalid independent worker job ID"));
    }
    let outputs = open_root_outputs()?;
    let original = fstat(&outputs).map_err(io)?;
    let first = read_report(&outputs, job_id, 0)?;
    let second = read_report(&outputs, job_id, 0)?;
    if first != second {
        return Err(invalid("deterministic report changed across snapshot"));
    }
    let reopened = open_root_outputs()?;
    let visible = fstat(&reopened).map_err(io)?;
    if !unchanged(&original, &visible) {
        return Err(invalid("Python worker output root was replaced"));
    }
    Ok(first)
}

#[cfg(test)]
#[path = "python_worker_files_tests.rs"]
mod tests;
