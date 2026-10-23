//! Durable one-use Root result for an observed candidate builder exit. The
//! result is still a supervisor claim until anchored by a trusted host.

use crate::builder_candidate_source::same_file;
use gauntlet_contracts::canonicalize;
use rustix::fs::{fstat, fsync, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;

const RESULT: &str = "candidate-run.result.json";
const MAX_RESULT: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateReceiptError {
    InvalidResult,
    ExistingResult,
    WriteUncertain,
}

impl fmt::Display for CandidateReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidResult => "candidate result exceeds fixed canonical boundary",
            Self::ExistingResult => "candidate result already exists",
            Self::WriteUncertain => "candidate result write or readback uncertain",
        })
    }
}

pub(crate) fn write_root_canonical_job_file(
    job: &OwnedFd,
    name: &str,
    body: &Value,
) -> Result<String, CandidateReceiptError> {
    let bytes = canonicalize(body.to_string().as_bytes())
        .map_err(|_| CandidateReceiptError::InvalidResult)?;
    if bytes.is_empty() || bytes.len() > MAX_RESULT {
        return Err(CandidateReceiptError::InvalidResult);
    }
    let descriptor = openat(
        job,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| {
        if error == Errno::EXIST {
            CandidateReceiptError::ExistingResult
        } else {
            CandidateReceiptError::WriteUncertain
        }
    })?;
    let mut output = File::from(descriptor);
    output
        .write_all(&bytes)
        .map_err(|_| CandidateReceiptError::WriteUncertain)?;
    output
        .sync_all()
        .map_err(|_| CandidateReceiptError::WriteUncertain)?;
    fsync(job).map_err(|_| CandidateReceiptError::WriteUncertain)?;
    let descriptor = openat(
        job,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateReceiptError::WriteUncertain)?;
    let before = fstat(&descriptor).map_err(|_| CandidateReceiptError::WriteUncertain)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o777 != 0o600
        || before.st_size != bytes.len() as i64
    {
        return Err(CandidateReceiptError::WriteUncertain);
    }
    let mut file = File::from(descriptor);
    let mut readback = Vec::with_capacity(bytes.len());
    (&mut file)
        .take(MAX_RESULT as u64 + 1)
        .read_to_end(&mut readback)
        .map_err(|_| CandidateReceiptError::WriteUncertain)?;
    let after = fstat(&file).map_err(|_| CandidateReceiptError::WriteUncertain)?;
    let visible = statat(job, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateReceiptError::WriteUncertain)?;
    if readback != bytes || !same_file(&before, &after) || !same_file(&before, &visible) {
        return Err(CandidateReceiptError::WriteUncertain);
    }
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

pub(crate) fn write_candidate_receipt(
    job: &OwnedFd,
    body: &Value,
) -> Result<String, CandidateReceiptError> {
    write_root_canonical_job_file(job, RESULT, body)
}
