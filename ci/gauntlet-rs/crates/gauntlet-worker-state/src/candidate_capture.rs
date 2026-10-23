//! One-use Root capture and inert inspection of a completed local builder
//! export. This diagnostic cannot admit the wheel or claim a worker receipt.

use crate::builder_candidate_process::container_absent;
use crate::builder_candidate_source::{open_fixed_build_slot, same_file, verify_captured_source};
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::builder_policy::profile_is_loaded;
use crate::candidate_archive::{inspect_candidate_archive, CandidateArchiveDeclaration};
use crate::candidate_wheel::{inspect_candidate_wheel, CandidateWheelProof};
use crate::RunReservationJournal;
use gauntlet_contracts::is_git_sha;
use gauntlet_evidence::valid_package_version;
use rustix::fs::{fchmod, fstat, fsync, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::OwnedFd;
use std::path::Path;
use zip::ZipArchive;

const MAX_ARCHIVE: u64 = 256 * 1024 * 1024;
const ARCHIVE: &str = "candidate.zip";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateCaptureError {
    RootRequired,
    InvalidPins,
    LeaseUnavailable,
    SourceMismatch,
    ContainerUncertain,
    ProfileLoaded,
    CgroupUncertain,
    ExportUnavailable,
    ExportMismatch,
    ExistingCapture,
    CaptureUncertain,
    ArchiveInvalid,
    WheelInvalid,
}

impl fmt::Display for CandidateCaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for candidate capture",
            Self::InvalidPins => "fixed candidate identity and archive digests required",
            Self::LeaseUnavailable => "Rust or Python worker lease unavailable",
            Self::SourceMismatch => "captured candidate source differs from outside digest",
            Self::ContainerUncertain => "candidate container absence is unproven",
            Self::ProfileLoaded => "candidate AppArmor profile is still loaded",
            Self::CgroupUncertain => "candidate client cgroup absence is unproven",
            Self::ExportUnavailable => "bounded one-use candidate export unavailable",
            Self::ExportMismatch => "candidate export differs from outside digest",
            Self::ExistingCapture => "Root candidate capture already exists",
            Self::CaptureUncertain => "Root candidate capture or source stability uncertain",
            Self::ArchiveInvalid => "captured candidate archive declaration or wheel is invalid",
            Self::WheelInvalid => "nested wheel entry, metadata or native bytes are invalid",
        })
    }
}

impl std::error::Error for CandidateCaptureError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateCaptureProof {
    job_id: String,
    source_sha: String,
    source_archive_sha256: String,
    archive_sha256: String,
    archive_bytes: u64,
    declaration: CandidateArchiveDeclaration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateWheelLiveProof {
    job_id: String,
    source_sha: String,
    archive_sha256: String,
    declaration: CandidateArchiveDeclaration,
    wheel: CandidateWheelProof,
}

impl CandidateWheelLiveProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-candidate-wheel-shadow.v1",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "archive_sha256":self.archive_sha256,
            "version":self.declaration.version,
            "wheel":self.declaration.wheel,
            "wheel_sha256":self.declaration.wheel_sha256,
            "entries":self.wheel.entries,
            "uncompressed_bytes":self.wheel.uncompressed_bytes,
            "entry_tree_sha256":self.wheel.entry_tree_sha256,
            "distribution":self.wheel.distribution,
            "native_bytes":self.wheel.native_bytes,
            "native_sha256":self.wheel.native_sha256,
            "wheel_completion_module_present":self.wheel.contained_completion_present,
            "missing_capabilities":if self.wheel.contained_completion_present { vec![] } else { vec!["contained-output-completion.v1"] },
            "native_bytes_verified":true,
            "all_wheel_entries_read":true,
            "artifact_admitted":false,
            "execution_eligible":false,
        })
    }
}

impl CandidateCaptureProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-candidate-capture-shadow.v1",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "source_archive_sha256":self.source_archive_sha256,
            "archive_sha256":self.archive_sha256,
            "archive_bytes":self.archive_bytes,
            "version":self.declaration.version,
            "wheel":self.declaration.wheel,
            "wheel_sha256":self.declaration.wheel_sha256,
            "wheel_bytes":self.declaration.wheel_bytes,
            "native_sha256_claim":self.declaration.native_sha256_claim,
            "native_bytes_verified":false,
            "container_absent":true,
            "candidate_cgroup_absent":true,
            "build_profile_absent":true,
            "artifact_admitted":false,
            "execution_eligible":false,
        })
    }
}

fn lower_hex(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
}

pub(crate) fn inactive(job_id: &str) -> Result<(), CandidateCaptureError> {
    if container_absent(job_id) != Ok(true) {
        return Err(CandidateCaptureError::ContainerUncertain);
    }
    let profile = format!("hol-gauntlet-build-{job_id}");
    if profile_is_loaded(&profile) != Ok(false) {
        return Err(CandidateCaptureError::ProfileLoaded);
    }
    let parent = Path::new("/sys/fs/cgroup/system.slice");
    if !parent.is_dir() || !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
        return Err(CandidateCaptureError::CgroupUncertain);
    }
    let group = parent.join(format!("hol-gauntlet-rust-candidate-{job_id}"));
    match std::fs::symlink_metadata(group) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(CandidateCaptureError::CgroupUncertain),
    }
}

fn export_file(job: &OwnedFd) -> Result<(OwnedFd, File, Stat), CandidateCaptureError> {
    let export = openat(
        job,
        "export",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateCaptureError::ExportUnavailable)?;
    let directory = fstat(&export).map_err(|_| CandidateCaptureError::ExportUnavailable)?;
    if FileType::from_raw_mode(directory.st_mode) != FileType::Directory
        || directory.st_uid != 65532
        || directory.st_gid != 65532
        || directory.st_mode & 0o777 != 0o700
    {
        return Err(CandidateCaptureError::ExportUnavailable);
    }
    let descriptor = openat(
        &export,
        ARCHIVE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateCaptureError::ExportUnavailable)?;
    let stat = fstat(&descriptor).map_err(|_| CandidateCaptureError::ExportUnavailable)?;
    let visible = statat(&export, ARCHIVE, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateCaptureError::ExportUnavailable)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != 65532
        || stat.st_gid != 65532
        || stat.st_nlink != 1
        || stat.st_mode & 0o022 != 0
        || stat.st_size <= 0
        || stat.st_size as u64 > MAX_ARCHIVE
        || !same_file(&stat, &visible)
    {
        return Err(CandidateCaptureError::ExportUnavailable);
    }
    Ok((export, File::from(descriptor), stat))
}

fn digest_file(file: &mut File, maximum: u64) -> Result<(String, u64), CandidateCaptureError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| CandidateCaptureError::CaptureUncertain)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .ok_or(CandidateCaptureError::CaptureUncertain)?;
        if count > maximum {
            return Err(CandidateCaptureError::CaptureUncertain);
        }
        digest.update(&buffer[..n]);
    }
    Ok((format!("{:x}", digest.finalize()), count))
}

pub(crate) fn verify_captured(
    job: &OwnedFd,
    expected_sha: &str,
    expected_bytes: u64,
    source_sha: &str,
    version: &str,
) -> Result<CandidateArchiveDeclaration, CandidateCaptureError> {
    let descriptor = openat(
        job,
        ARCHIVE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    let before = fstat(&descriptor).map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o777 != 0o444
        || before.st_size as u64 != expected_bytes
    {
        return Err(CandidateCaptureError::CaptureUncertain);
    }
    let mut file = File::from(descriptor);
    let declaration = inspect_candidate_archive(
        file.try_clone()
            .map_err(|_| CandidateCaptureError::CaptureUncertain)?,
        source_sha,
        version,
    )
    .map_err(|_| CandidateCaptureError::ArchiveInvalid)?;
    let (digest, bytes) = digest_file(&mut file, MAX_ARCHIVE)?;
    let after = fstat(&file).map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    let visible = statat(job, ARCHIVE, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    if digest != expected_sha
        || bytes != expected_bytes
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
    {
        return Err(CandidateCaptureError::CaptureUncertain);
    }
    Ok(declaration)
}

/// Copy one dormant unprivileged export into a Root-owned, mode-0444 file and
/// inspect its two ZIP entries. Outside digests are caller observations, not a
/// trusted build receipt; the proof remains execution-ineligible.
pub fn capture_local_candidate_archive_ineligible(
    job_id: &str,
    source_sha: &str,
    source_archive_sha256: &str,
    export_sha256: &str,
    version: &str,
) -> Result<CandidateCaptureProof, CandidateCaptureError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateCaptureError::RootRequired);
    }
    if !lower_hex(job_id, 16)
        || !is_git_sha(source_sha)
        || !lower_hex(source_archive_sha256, 64)
        || !lower_hex(export_sha256, 64)
        || !valid_package_version(version)
    {
        return Err(CandidateCaptureError::InvalidPins);
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| CandidateCaptureError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| CandidateCaptureError::LeaseUnavailable)?;
    let python_lock = python_worker_lock().map_err(|_| CandidateCaptureError::LeaseUnavailable)?;
    let still_owned = || {
        lease
            .verify(&journal.root)
            .map_err(|_| CandidateCaptureError::LeaseUnavailable)?;
        verify_python_lock(&python_lock).map_err(|_| CandidateCaptureError::LeaseUnavailable)
    };
    let job = open_fixed_build_slot(job_id).map_err(|_| CandidateCaptureError::SourceMismatch)?;
    verify_captured_source(&job, source_archive_sha256)
        .map_err(|_| CandidateCaptureError::SourceMismatch)?;
    inactive(job_id)?;
    let (export, mut input, before) = export_file(&job)?;
    let (pre_digest, pre_bytes) = digest_file(&mut input, MAX_ARCHIVE)?;
    let pre_stat = fstat(&input).map_err(|_| CandidateCaptureError::ExportMismatch)?;
    let pre_visible = statat(&export, ARCHIVE, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateCaptureError::ExportMismatch)?;
    if pre_digest != export_sha256
        || pre_bytes != before.st_size as u64
        || !same_file(&before, &pre_stat)
        || !same_file(&before, &pre_visible)
    {
        return Err(CandidateCaptureError::ExportMismatch);
    }
    let descriptor = openat(
        &job,
        ARCHIVE,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            CandidateCaptureError::ExistingCapture
        } else {
            CandidateCaptureError::CaptureUncertain
        }
    })?;
    let mut output = File::from(descriptor);
    input
        .seek(SeekFrom::Start(0))
        .map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    let copied = std::io::copy(&mut input.take(MAX_ARCHIVE + 1), &mut output)
        .map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    if copied != pre_bytes {
        return Err(CandidateCaptureError::CaptureUncertain);
    }
    output
        .sync_all()
        .map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    fchmod(&output, Mode::from_bits_truncate(0o444))
        .map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    output
        .sync_all()
        .map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    fsync(&job).map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    let mut input = export_file(&job)?.1;
    let (post_digest, post_bytes) = digest_file(&mut input, MAX_ARCHIVE)?;
    let post_stat = fstat(&input).map_err(|_| CandidateCaptureError::ExportMismatch)?;
    let post_visible = statat(&export, ARCHIVE, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateCaptureError::ExportMismatch)?;
    if post_digest != export_sha256
        || post_bytes != pre_bytes
        || !same_file(&before, &post_stat)
        || !same_file(&before, &post_visible)
    {
        return Err(CandidateCaptureError::ExportMismatch);
    }
    let declaration = verify_captured(&job, export_sha256, copied, source_sha, version)?;
    still_owned()?;
    inactive(job_id)?;
    verify_captured_source(&job, source_archive_sha256)
        .map_err(|_| CandidateCaptureError::SourceMismatch)?;
    Ok(CandidateCaptureProof {
        job_id: job_id.to_owned(),
        source_sha: source_sha.to_owned(),
        source_archive_sha256: source_archive_sha256.to_owned(),
        archive_sha256: export_sha256.to_owned(),
        archive_bytes: copied,
        declaration,
    })
}

/// Verify the already captured Root archive and every inert wheel entry.
/// This is a read-only diagnostic, not staging or a trusted terminal receipt.
pub fn verify_captured_candidate_wheel_ineligible(
    job_id: &str,
    source_sha: &str,
    source_archive_sha256: &str,
    archive_sha256: &str,
    version: &str,
) -> Result<CandidateWheelLiveProof, CandidateCaptureError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateCaptureError::RootRequired);
    }
    if !lower_hex(job_id, 16)
        || !is_git_sha(source_sha)
        || !lower_hex(source_archive_sha256, 64)
        || !lower_hex(archive_sha256, 64)
        || !valid_package_version(version)
    {
        return Err(CandidateCaptureError::InvalidPins);
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| CandidateCaptureError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| CandidateCaptureError::LeaseUnavailable)?;
    let python_lock = python_worker_lock().map_err(|_| CandidateCaptureError::LeaseUnavailable)?;
    let job = open_fixed_build_slot(job_id).map_err(|_| CandidateCaptureError::SourceMismatch)?;
    verify_captured_source(&job, source_archive_sha256)
        .map_err(|_| CandidateCaptureError::SourceMismatch)?;
    inactive(job_id)?;
    let descriptor = openat(
        &job,
        ARCHIVE,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    let before = fstat(&descriptor).map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    if before.st_size <= 0 || before.st_size as u64 > MAX_ARCHIVE {
        return Err(CandidateCaptureError::CaptureUncertain);
    }
    let declaration = verify_captured(
        &job,
        archive_sha256,
        before.st_size as u64,
        source_sha,
        version,
    )?;
    let mut outer = ZipArchive::new(File::from(descriptor))
        .map_err(|_| CandidateCaptureError::ArchiveInvalid)?;
    let mut wheel = Vec::with_capacity(declaration.wheel_bytes as usize);
    outer
        .by_name(&declaration.wheel)
        .map_err(|_| CandidateCaptureError::ArchiveInvalid)?
        .take(MAX_ARCHIVE + 1)
        .read_to_end(&mut wheel)
        .map_err(|_| CandidateCaptureError::ArchiveInvalid)?;
    if wheel.len() as u64 != declaration.wheel_bytes || wheel.len() as u64 > MAX_ARCHIVE {
        return Err(CandidateCaptureError::ArchiveInvalid);
    }
    let nested = inspect_candidate_wheel(&wheel, &declaration)
        .map_err(|_| CandidateCaptureError::WheelInvalid)?;
    let held_file = outer.into_inner();
    let held = fstat(&held_file).map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    let visible = statat(&job, ARCHIVE, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateCaptureError::CaptureUncertain)?;
    if !same_file(&before, &held) || !same_file(&before, &visible) {
        return Err(CandidateCaptureError::CaptureUncertain);
    }
    let after = verify_captured(
        &job,
        archive_sha256,
        before.st_size as u64,
        source_sha,
        version,
    )?;
    if after != declaration {
        return Err(CandidateCaptureError::CaptureUncertain);
    }
    lease
        .verify(&journal.root)
        .map_err(|_| CandidateCaptureError::LeaseUnavailable)?;
    verify_python_lock(&python_lock).map_err(|_| CandidateCaptureError::LeaseUnavailable)?;
    inactive(job_id)?;
    verify_captured_source(&job, source_archive_sha256)
        .map_err(|_| CandidateCaptureError::SourceMismatch)?;
    Ok(CandidateWheelLiveProof {
        job_id: job_id.to_owned(),
        source_sha: source_sha.to_owned(),
        archive_sha256: archive_sha256.to_owned(),
        declaration,
        wheel: nested,
    })
}
