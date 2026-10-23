//! Inert, one-use clone of a reviewed dependency prefix with candidate wheel
//! files overlaid as data. No interpreter, installer, hook or candidate import
//! runs here. This is not a conformance or deployment admission path.

use crate::builder_candidate_source::{open_fixed_build_slot, same_file, verify_captured_source};
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::candidate_capture::{inactive, verify_captured};
use crate::RunReservationJournal;
use gauntlet_contracts::is_git_sha;
use gauntlet_evidence::{inventory_tree, valid_package_version, TreeKind};
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, open, openat, readlinkat, statat, symlinkat, AtFlags, Dir,
    FileType, Mode, OFlags, Stat,
};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

const STAGE: &str = "inert-wheel";
const TARGET: &str = "inert-prefix";
const SITE: &str = "lib/python3.12/site-packages/";
const NATIVE: &str = "codex_plugin_scanner/_native/hol-guard-runtime";
const MAX_ENTRIES: usize = 100_000;
const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_DEPTH: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidatePrefixCloneError {
    RootRequired,
    InvalidPins,
    LeaseUnavailable,
    SourceMismatch,
    BuildActive,
    ArchiveInvalid,
    BaselineMismatch,
    StageMismatch,
    ExistingClone,
    CloneUncertain,
    ReadbackMismatch,
}

impl fmt::Display for CandidatePrefixCloneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for inert prefix clone",
            Self::InvalidPins => "exact baseline, source, archive and wheel-tree pins required",
            Self::LeaseUnavailable => "Rust or Python worker lease unavailable",
            Self::SourceMismatch => "captured source differs from outside digest",
            Self::BuildActive => "candidate build or cleanup remains active or uncertain",
            Self::ArchiveInvalid => "captured candidate archive differs from outside pins",
            Self::BaselineMismatch => "reviewed baseline prefix differs from outside tree pin",
            Self::StageMismatch => "one-use inert wheel stage differs from outside tree pin",
            Self::ExistingClone => "one-use inert prefix clone already exists",
            Self::CloneUncertain => "private prefix clone could not be written durably",
            Self::ReadbackMismatch => "cloned prefix bytes or tree metadata differ on readback",
        })
    }
}

impl std::error::Error for CandidatePrefixCloneError {}

#[derive(Debug, Clone, Copy)]
pub struct CandidatePrefixClonePins<'a> {
    pub job_id: &'a str,
    pub source_sha: &'a str,
    pub source_archive_sha256: &'a str,
    pub archive_sha256: &'a str,
    pub version: &'a str,
    pub baseline_path: &'a Path,
    pub baseline_tree_sha256: &'a str,
    pub stage_tree_sha256: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePrefixCloneProof {
    job_id: String,
    source_sha: String,
    archive_sha256: String,
    baseline_tree_sha256: String,
    stage_tree_sha256: String,
    prefix_tree_sha256: String,
    prefix_entries: usize,
    prefix_bytes: u64,
    wheel_files: usize,
}

impl CandidatePrefixCloneProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-candidate-prefix-clone-shadow.v1",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "archive_sha256":self.archive_sha256,
            "baseline_tree_sha256":self.baseline_tree_sha256,
            "stage_tree_sha256":self.stage_tree_sha256,
            "prefix_tree_sha256":self.prefix_tree_sha256,
            "prefix_entries":self.prefix_entries,
            "prefix_bytes":self.prefix_bytes,
            "wheel_files":self.wheel_files,
            "candidate_executed":false,
            "dependency_validation_completed":false,
            "conformance_completed":false,
            "artifact_admitted":false,
            "execution_eligible":false,
        })
    }
}

fn lower_hex(raw: &str, len: usize) -> bool {
    raw.len() == len
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_baseline(path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix("/opt/hol-gauntlet/candidates") else {
        return false;
    };
    let mut components = relative.components();
    matches!(
        (components.next(), components.next(), components.next()),
        (Some(Component::Normal(source)), Some(Component::Normal(prefix)), None)
            if source.to_str().is_some_and(is_git_sha) && prefix == "prefix"
    )
}

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
}

fn entries(directory: &OwnedFd) -> Result<Vec<String>, CandidatePrefixCloneError> {
    let iterator =
        Dir::read_from(directory).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let mut names = Vec::new();
    for item in iterator {
        let item = item.map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
        let name = item
            .file_name()
            .to_str()
            .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
        if name == "." || name == ".." {
            continue;
        }
        if !safe_name(name) || names.len() >= MAX_ENTRIES {
            return Err(CandidatePrefixCloneError::CloneUncertain);
        }
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

fn safe_source(stat: &Stat, kind: FileType) -> bool {
    stat.st_uid == 0
        && (kind == FileType::Symlink || stat.st_mode & 0o022 == 0)
        && stat.st_mode & 0o7000 == 0
        && matches!(
            kind,
            FileType::Directory | FileType::RegularFile | FileType::Symlink
        )
}

fn private_directory(directory: &OwnedFd) -> Result<(), CandidatePrefixCloneError> {
    let stat = fstat(directory).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o777 != 0o700
    {
        return Err(CandidatePrefixCloneError::CloneUncertain);
    }
    Ok(())
}

fn regular_copy(
    source: &OwnedFd,
    target: &OwnedFd,
    name: &str,
    mode: u32,
    total: &mut u64,
) -> Result<(), CandidatePrefixCloneError> {
    let before = statat(source, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || !safe_source(&before, FileType::RegularFile)
        || before.st_size < 0
        || before.st_size as u64 > MAX_BYTES
    {
        return Err(CandidatePrefixCloneError::CloneUncertain);
    }
    let input = openat(
        source,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let opened = fstat(&input).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    if !same_file(&before, &opened) {
        return Err(CandidatePrefixCloneError::CloneUncertain);
    }
    let output = openat(
        target,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let mut input = File::from(input);
    let mut output = File::from(output);
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let n = input
            .read(&mut buffer)
            .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .filter(|size| *size <= MAX_BYTES)
            .ok_or(CandidatePrefixCloneError::CloneUncertain)?;
        output
            .write_all(&buffer[..n])
            .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
        digest.update(&buffer[..n]);
    }
    *total = total
        .checked_add(count)
        .filter(|size| *size <= MAX_BYTES)
        .ok_or(CandidatePrefixCloneError::CloneUncertain)?;
    let after = fstat(&input).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let visible = statat(source, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    if count != before.st_size as u64
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
    {
        return Err(CandidatePrefixCloneError::CloneUncertain);
    }
    fchmod(&output, Mode::from_bits_truncate(mode))
        .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    output
        .sync_all()
        .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    fsync(target).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let readback = openat(
        target,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePrefixCloneError::ReadbackMismatch)?;
    let proof = fstat(&readback).map_err(|_| CandidatePrefixCloneError::ReadbackMismatch)?;
    if FileType::from_raw_mode(proof.st_mode) != FileType::RegularFile
        || proof.st_uid != 0
        || proof.st_nlink != 1
        || proof.st_mode & 0o777 != mode
        || proof.st_size != count as i64
    {
        return Err(CandidatePrefixCloneError::ReadbackMismatch);
    }
    let mut readback = File::from(readback);
    let mut observed = Sha256::new();
    let mut read_bytes = 0_u64;
    loop {
        let n = readback
            .read(&mut buffer)
            .map_err(|_| CandidatePrefixCloneError::ReadbackMismatch)?;
        if n == 0 {
            break;
        }
        read_bytes += n as u64;
        observed.update(&buffer[..n]);
    }
    let later = fstat(&readback).map_err(|_| CandidatePrefixCloneError::ReadbackMismatch)?;
    let visible = statat(target, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidatePrefixCloneError::ReadbackMismatch)?;
    if read_bytes != count
        || format!("{:x}", observed.finalize()) != format!("{:x}", digest.finalize())
        || !same_file(&proof, &later)
        || !same_file(&proof, &visible)
    {
        return Err(CandidatePrefixCloneError::ReadbackMismatch);
    }
    Ok(())
}

fn old_product(relative: &str) -> bool {
    let Some(after_site) = relative.strip_prefix(SITE) else {
        return false;
    };
    let head = after_site.split('/').next().unwrap_or("");
    head == "codex_plugin_scanner"
        || head
            .strip_prefix("hol_guard-")
            .and_then(|part| part.strip_suffix(".dist-info"))
            .is_some_and(|version| {
                !version.is_empty()
                    && version
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
            })
}

pub(crate) fn clone_baseline(
    source: &OwnedFd,
    target: &OwnedFd,
    prefix: &str,
    depth: usize,
    entries_seen: &mut usize,
    copied_bytes: &mut u64,
    skip_old_product: bool,
) -> Result<(), CandidatePrefixCloneError> {
    if depth > MAX_DEPTH {
        return Err(CandidatePrefixCloneError::CloneUncertain);
    }
    for name in entries(source)? {
        *entries_seen += 1;
        if *entries_seen > MAX_ENTRIES {
            return Err(CandidatePrefixCloneError::CloneUncertain);
        }
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if skip_old_product && old_product(&relative) {
            continue;
        }
        let before = statat(source, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
        let kind = FileType::from_raw_mode(before.st_mode);
        if !safe_source(&before, kind) {
            return Err(CandidatePrefixCloneError::CloneUncertain);
        }
        match kind {
            FileType::Directory => {
                let child_source = openat(
                    source,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                if !same_file(
                    &before,
                    &fstat(&child_source).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?,
                ) {
                    return Err(CandidatePrefixCloneError::CloneUncertain);
                }
                mkdirat(target, name.as_str(), Mode::from_bits_truncate(0o700))
                    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                let child_target = openat(
                    target,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                clone_baseline(
                    &child_source,
                    &child_target,
                    &relative,
                    depth + 1,
                    entries_seen,
                    copied_bytes,
                    skip_old_product,
                )?;
                fchmod(
                    &child_target,
                    Mode::from_bits_truncate(before.st_mode & 0o777),
                )
                .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                fsync(&child_target).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                fsync(target).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                let held =
                    fstat(&child_source).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                let visible = statat(source, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                if !same_file(&before, &held) || !same_file(&before, &visible) {
                    return Err(CandidatePrefixCloneError::CloneUncertain);
                }
            }
            FileType::RegularFile => {
                regular_copy(source, target, &name, before.st_mode & 0o777, copied_bytes)?
            }
            FileType::Symlink => {
                let link = readlinkat(source, name.as_str(), Vec::new())
                    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                let link = link
                    .to_str()
                    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                symlinkat(link, target, name.as_str())
                    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                fsync(target).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                let after = statat(source, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                let target_link = readlinkat(target, name.as_str(), Vec::new())
                    .map_err(|_| CandidatePrefixCloneError::ReadbackMismatch)?;
                if !same_file(&before, &after) || target_link.to_str() != Ok(link) {
                    return Err(CandidatePrefixCloneError::ReadbackMismatch);
                }
            }
            _ => return Err(CandidatePrefixCloneError::CloneUncertain),
        }
    }
    Ok(())
}

fn target_parent(
    root: &OwnedFd,
    relative: &str,
) -> Result<(OwnedFd, String), CandidatePrefixCloneError> {
    let full = format!("{SITE}{relative}");
    let mut directory = openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let mut parts = full.split('/').peekable();
    while let Some(part) = parts.next() {
        if !safe_name(part) {
            return Err(CandidatePrefixCloneError::StageMismatch);
        }
        if parts.peek().is_none() {
            return Ok((directory, part.to_owned()));
        }
        match mkdirat(&directory, part, Mode::from_bits_truncate(0o700)) {
            Ok(()) => {
                let created = openat(
                    &directory,
                    part,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                fchmod(&created, Mode::from_bits_truncate(0o755))
                    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                fsync(&directory).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                directory = created;
            }
            Err(Errno::EXIST) => {
                let existing = openat(
                    &directory,
                    part,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                let stat =
                    fstat(&existing).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
                if stat.st_uid != 0 || stat.st_mode & 0o022 != 0 {
                    return Err(CandidatePrefixCloneError::CloneUncertain);
                }
                directory = existing;
            }
            Err(_) => return Err(CandidatePrefixCloneError::CloneUncertain),
        }
    }
    Err(CandidatePrefixCloneError::StageMismatch)
}

fn overlay_wheel(
    source: &OwnedFd,
    target: &OwnedFd,
    prefix: &str,
    depth: usize,
    files: &mut usize,
    copied_bytes: &mut u64,
) -> Result<(), CandidatePrefixCloneError> {
    if depth > MAX_DEPTH {
        return Err(CandidatePrefixCloneError::StageMismatch);
    }
    for name in entries(source)? {
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let before = statat(source, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| CandidatePrefixCloneError::StageMismatch)?;
        let kind = FileType::from_raw_mode(before.st_mode);
        if !safe_source(&before, kind) {
            return Err(CandidatePrefixCloneError::StageMismatch);
        }
        match kind {
            FileType::Directory => {
                let child = openat(
                    source,
                    name.as_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| CandidatePrefixCloneError::StageMismatch)?;
                if !same_file(
                    &before,
                    &fstat(&child).map_err(|_| CandidatePrefixCloneError::StageMismatch)?,
                ) {
                    return Err(CandidatePrefixCloneError::StageMismatch);
                }
                overlay_wheel(&child, target, &relative, depth + 1, files, copied_bytes)?;
                let held = fstat(&child).map_err(|_| CandidatePrefixCloneError::StageMismatch)?;
                let visible = statat(source, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| CandidatePrefixCloneError::StageMismatch)?;
                if !same_file(&before, &held) || !same_file(&before, &visible) {
                    return Err(CandidatePrefixCloneError::StageMismatch);
                }
            }
            FileType::RegularFile => {
                if !(relative.starts_with("codex_plugin_scanner/")
                    || relative.starts_with("hol_guard-") && relative.contains(".dist-info/"))
                {
                    return Err(CandidatePrefixCloneError::StageMismatch);
                }
                *files += 1;
                if *files > MAX_ENTRIES {
                    return Err(CandidatePrefixCloneError::StageMismatch);
                }
                let (destination, basename) = target_parent(target, &relative)?;
                if basename != name {
                    return Err(CandidatePrefixCloneError::StageMismatch);
                }
                regular_copy(
                    source,
                    &destination,
                    name.as_str(),
                    if relative == NATIVE { 0o755 } else { 0o644 },
                    copied_bytes,
                )?;
            }
            _ => return Err(CandidatePrefixCloneError::StageMismatch),
        }
    }
    Ok(())
}

/// Clone a separately pinned baseline and overlay a one-use inert wheel tree.
/// A partial clone is retained on failure. No installer or candidate process
/// runs, and the result cannot be used as a deployment.
pub fn clone_captured_candidate_prefix_ineligible(
    pins: &CandidatePrefixClonePins<'_>,
) -> Result<CandidatePrefixCloneProof, CandidatePrefixCloneError> {
    let CandidatePrefixClonePins {
        job_id,
        source_sha,
        source_archive_sha256,
        archive_sha256,
        version,
        baseline_path,
        baseline_tree_sha256,
        stage_tree_sha256,
    } = *pins;
    if geteuid().as_raw() != 0 {
        return Err(CandidatePrefixCloneError::RootRequired);
    }
    if !lower_hex(job_id, 16)
        || !is_git_sha(source_sha)
        || !lower_hex(source_archive_sha256, 64)
        || !lower_hex(archive_sha256, 64)
        || !valid_package_version(version)
        || !valid_baseline(baseline_path)
        || !lower_hex(baseline_tree_sha256, 64)
        || !lower_hex(stage_tree_sha256, 64)
    {
        return Err(CandidatePrefixCloneError::InvalidPins);
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| CandidatePrefixCloneError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| CandidatePrefixCloneError::LeaseUnavailable)?;
    let python_lock =
        python_worker_lock().map_err(|_| CandidatePrefixCloneError::LeaseUnavailable)?;
    let job =
        open_fixed_build_slot(job_id).map_err(|_| CandidatePrefixCloneError::SourceMismatch)?;
    verify_captured_source(&job, source_archive_sha256)
        .map_err(|_| CandidatePrefixCloneError::SourceMismatch)?;
    inactive(job_id).map_err(|_| CandidatePrefixCloneError::BuildActive)?;
    let archive = openat(
        &job,
        "candidate.zip",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePrefixCloneError::ArchiveInvalid)?;
    let archive_stat = fstat(&archive).map_err(|_| CandidatePrefixCloneError::ArchiveInvalid)?;
    if archive_stat.st_size <= 0 {
        return Err(CandidatePrefixCloneError::ArchiveInvalid);
    }
    verify_captured(
        &job,
        archive_sha256,
        archive_stat.st_size as u64,
        source_sha,
        version,
    )
    .map_err(|_| CandidatePrefixCloneError::ArchiveInvalid)?;
    let stage_path = Path::new("/var/lib/hol-gauntlet/builds")
        .join(job_id)
        .join(STAGE);
    let baseline = inventory_tree(baseline_path, TreeKind::InstalledPrefix)
        .map_err(|_| CandidatePrefixCloneError::BaselineMismatch)?;
    let stage = inventory_tree(&stage_path, TreeKind::InstalledPrefix)
        .map_err(|_| CandidatePrefixCloneError::StageMismatch)?;
    if baseline.digest != baseline_tree_sha256 {
        return Err(CandidatePrefixCloneError::BaselineMismatch);
    }
    if stage.digest != stage_tree_sha256 {
        return Err(CandidatePrefixCloneError::StageMismatch);
    }
    let baseline_fd = open(
        baseline_path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePrefixCloneError::BaselineMismatch)?;
    let stage_fd = openat(
        &job,
        STAGE,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePrefixCloneError::StageMismatch)?;
    private_directory(&stage_fd).map_err(|_| CandidatePrefixCloneError::StageMismatch)?;
    match mkdirat(&job, TARGET, Mode::from_bits_truncate(0o700)) {
        Ok(()) => (),
        Err(Errno::EXIST) => return Err(CandidatePrefixCloneError::ExistingClone),
        Err(_) => return Err(CandidatePrefixCloneError::CloneUncertain),
    }
    fsync(&job).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let target = openat(
        &job,
        TARGET,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    private_directory(&target)?;
    let mut seen = 0_usize;
    let mut bytes = 0_u64;
    clone_baseline(&baseline_fd, &target, "", 0, &mut seen, &mut bytes, true)?;
    let mut wheel_files = 0_usize;
    overlay_wheel(&stage_fd, &target, "", 0, &mut wheel_files, &mut bytes)?;
    if wheel_files == 0 {
        return Err(CandidatePrefixCloneError::StageMismatch);
    }
    fchmod(&target, Mode::from_bits_truncate(0o755))
        .map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    fsync(&target).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    fsync(&job).map_err(|_| CandidatePrefixCloneError::CloneUncertain)?;
    let target_path = Path::new("/var/lib/hol-gauntlet/builds")
        .join(job_id)
        .join(TARGET);
    let cloned = inventory_tree(&target_path, TreeKind::InstalledPrefix)
        .map_err(|_| CandidatePrefixCloneError::ReadbackMismatch)?;
    if cloned.bytes != bytes {
        return Err(CandidatePrefixCloneError::ReadbackMismatch);
    }
    if inventory_tree(baseline_path, TreeKind::InstalledPrefix)
        .map_err(|_| CandidatePrefixCloneError::BaselineMismatch)?
        .digest
        != baseline_tree_sha256
        || inventory_tree(&stage_path, TreeKind::InstalledPrefix)
            .map_err(|_| CandidatePrefixCloneError::StageMismatch)?
            .digest
            != stage_tree_sha256
    {
        return Err(CandidatePrefixCloneError::ReadbackMismatch);
    }
    verify_captured(
        &job,
        archive_sha256,
        archive_stat.st_size as u64,
        source_sha,
        version,
    )
    .map_err(|_| CandidatePrefixCloneError::ArchiveInvalid)?;
    verify_captured_source(&job, source_archive_sha256)
        .map_err(|_| CandidatePrefixCloneError::SourceMismatch)?;
    inactive(job_id).map_err(|_| CandidatePrefixCloneError::BuildActive)?;
    lease
        .verify(&journal.root)
        .map_err(|_| CandidatePrefixCloneError::LeaseUnavailable)?;
    verify_python_lock(&python_lock).map_err(|_| CandidatePrefixCloneError::LeaseUnavailable)?;
    Ok(CandidatePrefixCloneProof {
        job_id: job_id.to_owned(),
        source_sha: source_sha.to_owned(),
        archive_sha256: archive_sha256.to_owned(),
        baseline_tree_sha256: baseline_tree_sha256.to_owned(),
        stage_tree_sha256: stage_tree_sha256.to_owned(),
        prefix_tree_sha256: cloned.digest,
        prefix_entries: cloned.entries,
        prefix_bytes: cloned.bytes,
        wheel_files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn unprivileged_clone_refuses_before_any_pins_or_files() {
        if geteuid().as_raw() == 0 {
            return;
        }
        let pins = CandidatePrefixClonePins {
            job_id: "",
            source_sha: "",
            source_archive_sha256: "",
            archive_sha256: "",
            version: "",
            baseline_path: Path::new(""),
            baseline_tree_sha256: "",
            stage_tree_sha256: "",
        };
        assert_eq!(
            clone_captured_candidate_prefix_ineligible(&pins),
            Err(CandidatePrefixCloneError::RootRequired)
        );
    }

    #[test]
    #[ignore = "Root-owned fixture; run explicitly on the dedicated ARM VM"]
    fn clone_keeps_reviewed_dependencies_and_replaces_only_product_files() {
        assert_eq!(geteuid().as_raw(), 0);
        let scratch = tempfile::tempdir().unwrap();
        let baseline = scratch.path().join("baseline");
        let stage = scratch.path().join("stage");
        let target = scratch.path().join("target");
        fs::create_dir(&baseline).unwrap();
        fs::create_dir(&stage).unwrap();
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(baseline.join("lib/python3.12/site-packages/dependency")).unwrap();
        fs::create_dir_all(baseline.join("lib/python3.12/site-packages/codex_plugin_scanner"))
            .unwrap();
        fs::create_dir_all(
            baseline.join("lib/python3.12/site-packages/hol_guard-3.49.0.dist-info"),
        )
        .unwrap();
        fs::write(
            baseline.join("lib/python3.12/site-packages/dependency/__init__.py"),
            b"reviewed dependency",
        )
        .unwrap();
        fs::write(
            baseline.join("lib/python3.12/site-packages/codex_plugin_scanner/old.py"),
            b"old product",
        )
        .unwrap();
        fs::write(
            baseline.join("lib/python3.12/site-packages/hol_guard-3.49.0.dist-info/METADATA"),
            b"old distribution",
        )
        .unwrap();
        fs::create_dir_all(stage.join("codex_plugin_scanner/_native")).unwrap();
        fs::create_dir_all(stage.join("hol_guard-3.48.0.dist-info")).unwrap();
        fs::write(
            stage.join("codex_plugin_scanner/_native/hol-guard-runtime"),
            b"inert new native",
        )
        .unwrap();
        fs::write(
            stage.join("hol_guard-3.48.0.dist-info/METADATA"),
            b"new distribution",
        )
        .unwrap();
        let baseline_fd = open(
            &baseline,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let stage_fd = open(
            &stage,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let target_fd = open(
            &target,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let mut entries_seen = 0;
        let mut bytes = 0;
        clone_baseline(
            &baseline_fd,
            &target_fd,
            "",
            0,
            &mut entries_seen,
            &mut bytes,
            true,
        )
        .unwrap();
        let mut wheel_files = 0;
        overlay_wheel(&stage_fd, &target_fd, "", 0, &mut wheel_files, &mut bytes).unwrap();
        fchmod(&target_fd, Mode::from_bits_truncate(0o755)).unwrap();
        let inventory = inventory_tree(&target, TreeKind::InstalledPrefix).unwrap();
        assert_eq!(inventory.bytes, bytes);
        assert_eq!(wheel_files, 2);
        let site = target.join(SITE);
        assert_eq!(
            fs::read(site.join("dependency/__init__.py")).unwrap(),
            b"reviewed dependency"
        );
        assert!(!site.join("codex_plugin_scanner/old.py").exists());
        assert!(!site.join("hol_guard-3.49.0.dist-info").exists());
        assert_eq!(
            fs::read(site.join("codex_plugin_scanner/_native/hol-guard-runtime")).unwrap(),
            b"inert new native"
        );
        assert_eq!(
            fs::metadata(site.join("codex_plugin_scanner/_native/hol-guard-runtime"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }
}
