//! Fixed Root source-slot and unprivileged output-directory custody for one
//! local candidate run. No archive contents or wheel are admitted here.

use crate::{hex, open_root_owned_public_directory};
use rustix::fs::{fstat, fsync, mkdirat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

const BUILDS: &str = "/var/lib/hol-gauntlet/builds";
const SOURCE: &str = "source.tar.gz";
const EXPORT: &str = "export";
const MAX_SOURCE: u64 = 256 * 1024 * 1024;
const MAX_ARTIFACT: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateSourceError {
    InvalidPins,
    UnsafeSlot,
    SourceMismatch,
    ExistingExport,
    ExportUncertain,
}

impl fmt::Display for CandidateSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPins => "fixed candidate job and archive digest required",
            Self::UnsafeSlot => "Root-owned candidate build slot unavailable",
            Self::SourceMismatch => "captured source archive differs from outside digest",
            Self::ExistingExport => "one-use candidate export directory already exists",
            Self::ExportUncertain => "candidate export directory or file is uncertain",
        })
    }
}

pub(crate) fn same_file(a: &Stat, b: &Stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_mode == b.st_mode
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_nlink == b.st_nlink
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}

pub(crate) fn open_fixed_build_slot(job_id: &str) -> Result<OwnedFd, CandidateSourceError> {
    if !hex(job_id, 16) {
        return Err(CandidateSourceError::InvalidPins);
    }
    let builds = open_root_owned_public_directory(Path::new(BUILDS))
        .map_err(|_| CandidateSourceError::UnsafeSlot)?;
    let parent = fstat(&builds).map_err(|_| CandidateSourceError::UnsafeSlot)?;
    if FileType::from_raw_mode(parent.st_mode) != FileType::Directory
        || parent.st_uid != 0
        || parent.st_mode & 0o077 != 0
    {
        return Err(CandidateSourceError::UnsafeSlot);
    }
    let job = openat(
        &builds,
        job_id,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateSourceError::UnsafeSlot)?;
    let stat = fstat(&job).map_err(|_| CandidateSourceError::UnsafeSlot)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_mode & 0o077 != 0
    {
        return Err(CandidateSourceError::UnsafeSlot);
    }
    Ok(job)
}

pub(crate) fn verify_captured_source(
    job: &OwnedFd,
    expected_sha256: &str,
) -> Result<u64, CandidateSourceError> {
    if !hex(expected_sha256, 64) {
        return Err(CandidateSourceError::InvalidPins);
    }
    let descriptor = openat(
        job,
        SOURCE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateSourceError::SourceMismatch)?;
    let before = fstat(&descriptor).map_err(|_| CandidateSourceError::SourceMismatch)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_mode & 0o777 != 0o444
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as u64 > MAX_SOURCE
    {
        return Err(CandidateSourceError::SourceMismatch);
    }
    let mut file = File::from(descriptor);
    let mut hasher = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| CandidateSourceError::SourceMismatch)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > MAX_SOURCE {
            return Err(CandidateSourceError::SourceMismatch);
        }
        hasher.update(&buffer[..n]);
    }
    let after = fstat(&file).map_err(|_| CandidateSourceError::SourceMismatch)?;
    let visible = statat(job, SOURCE, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateSourceError::SourceMismatch)?;
    if count != before.st_size as u64
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
        || format!("{:x}", hasher.finalize()) != expected_sha256
    {
        return Err(CandidateSourceError::SourceMismatch);
    }
    Ok(count)
}

pub(crate) fn prepare_export(job: &OwnedFd) -> Result<(), CandidateSourceError> {
    match mkdirat(job, EXPORT, Mode::from_bits_truncate(0o700)) {
        Ok(()) => {}
        Err(Errno::EXIST) => return Err(CandidateSourceError::ExistingExport),
        Err(_) => return Err(CandidateSourceError::ExportUncertain),
    }
    fsync(job).map_err(|_| CandidateSourceError::ExportUncertain)?;
    let directory = openat(
        job,
        EXPORT,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateSourceError::ExportUncertain)?;
    // SAFETY: directory is the descriptor for the exclusively created export directory.
    if unsafe { libc::fchown(directory.as_raw_fd(), 65532, 65532) } != 0 {
        return Err(CandidateSourceError::ExportUncertain);
    }
    let stat = fstat(&directory).map_err(|_| CandidateSourceError::ExportUncertain)?;
    let visible = statat(job, EXPORT, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateSourceError::ExportUncertain)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 65532
        || stat.st_gid != 65532
        || stat.st_mode & 0o777 != 0o700
        || !same_file(&stat, &visible)
    {
        return Err(CandidateSourceError::ExportUncertain);
    }
    fsync(&directory).map_err(|_| CandidateSourceError::ExportUncertain)?;
    fsync(job).map_err(|_| CandidateSourceError::ExportUncertain)
}

pub(crate) fn unadmitted_export_identity(
    job: &OwnedFd,
) -> Result<Option<(u64, String)>, CandidateSourceError> {
    let directory = openat(
        job,
        EXPORT,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateSourceError::ExportUncertain)?;
    let parent = fstat(&directory).map_err(|_| CandidateSourceError::ExportUncertain)?;
    if FileType::from_raw_mode(parent.st_mode) != FileType::Directory
        || parent.st_uid != 65532
        || parent.st_gid != 65532
        || parent.st_mode & 0o777 != 0o700
    {
        return Err(CandidateSourceError::ExportUncertain);
    }
    let descriptor = match openat(
        &directory,
        "candidate.zip",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(_) => return Err(CandidateSourceError::ExportUncertain),
    };
    let stat = fstat(&descriptor).map_err(|_| CandidateSourceError::ExportUncertain)?;
    let visible = statat(&directory, "candidate.zip", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateSourceError::ExportUncertain)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != 65532
        || stat.st_nlink != 1
        || stat.st_size <= 0
        || stat.st_size as u64 > MAX_ARTIFACT
        || !same_file(&stat, &visible)
    {
        return Err(CandidateSourceError::ExportUncertain);
    }
    let mut file = File::from(descriptor);
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| CandidateSourceError::ExportUncertain)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .ok_or(CandidateSourceError::ExportUncertain)?;
        if count > MAX_ARTIFACT {
            return Err(CandidateSourceError::ExportUncertain);
        }
        digest.update(&buffer[..n]);
    }
    let after = fstat(&file).map_err(|_| CandidateSourceError::ExportUncertain)?;
    let visible = statat(&directory, "candidate.zip", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateSourceError::ExportUncertain)?;
    if count != stat.st_size as u64 || !same_file(&stat, &after) || !same_file(&stat, &visible) {
        return Err(CandidateSourceError::ExportUncertain);
    }
    Ok(Some((count, format!("{:x}", digest.finalize()))))
}
