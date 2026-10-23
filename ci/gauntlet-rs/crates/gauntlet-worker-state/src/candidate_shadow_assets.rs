//! One-use, inert copy of a captured candidate into an isolated /opt shadow
//! asset root. It never writes the active Python candidate path or a config.

use crate::builder_candidate_source::{open_fixed_build_slot, same_file, verify_captured_source};
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::candidate_capture::{inactive, verify_captured};
use crate::candidate_prefix_clone::clone_baseline;
use crate::candidate_wheel::inspect_candidate_wheel;
use crate::{open_root_owned_public_directory, RunReservationJournal};
use gauntlet_contracts::is_git_sha;
use gauntlet_evidence::{
    inventory_tree, valid_package_version, verify_installed_version_metadata, TreeKind,
};
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, openat, statat, statvfs, AtFlags, FileType, Mode, OFlags,
};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use zip::ZipArchive;

const BASE: &str = "/opt/hol-gauntlet";
const SHADOW: &str = "rust-shadow-candidates";
const PREFIX: &str = "inert-prefix";
const NATIVE_IN_WHEEL: &str = "codex_plugin_scanner/_native/hol-guard-runtime";
const MAX_ARCHIVE: u64 = 256 * 1024 * 1024;
const MAX_NATIVE: u64 = 128 * 1024 * 1024;
const MIN_REMAIN_FREE: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateShadowAssetsError {
    RootRequired,
    InvalidPins,
    LeaseUnavailable,
    SourceMismatch,
    BuildActive,
    ArchiveMismatch,
    PrefixMismatch,
    LowDisk,
    ExistingShadow,
    CopyUncertain,
    ReadbackMismatch,
}

impl fmt::Display for CandidateShadowAssetsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for inert shadow assets",
            Self::InvalidPins => "exact captured source, archive and prefix pins required",
            Self::LeaseUnavailable => "Rust or Python worker lease unavailable",
            Self::SourceMismatch => "captured source differs from outside digest",
            Self::BuildActive => "candidate build or cleanup remains active or uncertain",
            Self::ArchiveMismatch => "captured archive, wheel or native differs from outside pins",
            Self::PrefixMismatch => "inert prefix differs from outside tree digest",
            Self::LowDisk => "shadow copy would violate the VM free-disk floor",
            Self::ExistingShadow => "one-use shadow asset root already exists",
            Self::CopyUncertain => "shadow asset copy could not be completed durably",
            Self::ReadbackMismatch => "shadow asset bytes or prefix tree differ on readback",
        })
    }
}

impl std::error::Error for CandidateShadowAssetsError {}

#[derive(Debug, Clone, Copy)]
pub struct CandidateShadowAssetsPins<'a> {
    pub job_id: &'a str,
    pub source_sha: &'a str,
    pub source_archive_sha256: &'a str,
    pub archive_sha256: &'a str,
    pub version: &'a str,
    pub native_sha256: &'a str,
    pub prefix_tree_sha256: &'a str,
    pub wheel_sha256: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateShadowAssetsProof {
    job_id: String,
    source_sha: String,
    shadow_root: String,
    prefix_tree_sha256: String,
    prefix_entries: usize,
    prefix_bytes: u64,
    wheel_sha256: String,
    native_sha256: String,
    contained_completion_present: bool,
}

impl CandidateShadowAssetsProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-candidate-shadow-assets.v1",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "shadow_root":self.shadow_root,
            "prefix_tree_sha256":self.prefix_tree_sha256,
            "prefix_entries":self.prefix_entries,
            "prefix_bytes":self.prefix_bytes,
            "wheel_sha256":self.wheel_sha256,
            "native_sha256":self.native_sha256,
            "wheel_completion_module_present":self.contained_completion_present,
            "missing_capabilities":if self.contained_completion_present { vec![] } else { vec!["contained-output-completion.v1"] },
            "assets_copied":true,
            "assets_admitted":false,
            "config_written":false,
            "conformance_completed":false,
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

pub(crate) fn private_directory(directory: &OwnedFd) -> Result<(), CandidateShadowAssetsError> {
    let stat = fstat(directory).map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o777 != 0o700
    {
        return Err(CandidateShadowAssetsError::CopyUncertain);
    }
    Ok(())
}

pub(crate) fn write_data(
    directory: &OwnedFd,
    name: &str,
    data: &[u8],
    digest: &str,
    mode: u32,
) -> Result<(), CandidateShadowAssetsError> {
    if format!("{:x}", Sha256::digest(data)) != digest {
        return Err(CandidateShadowAssetsError::ArchiveMismatch);
    }
    let output = openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    let mut output = File::from(output);
    output
        .write_all(data)
        .map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    output
        .sync_all()
        .map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    fchmod(&output, Mode::from_bits_truncate(mode))
        .map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    output
        .sync_all()
        .map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    fsync(directory).map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    let readback = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateShadowAssetsError::ReadbackMismatch)?;
    let before = fstat(&readback).map_err(|_| CandidateShadowAssetsError::ReadbackMismatch)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o777 != mode
        || before.st_size != data.len() as i64
    {
        return Err(CandidateShadowAssetsError::ReadbackMismatch);
    }
    let mut readback = File::from(readback);
    let mut observed = Sha256::new();
    let mut count = 0_usize;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let n = readback
            .read(&mut buffer)
            .map_err(|_| CandidateShadowAssetsError::ReadbackMismatch)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n)
            .filter(|size| *size <= data.len())
            .ok_or(CandidateShadowAssetsError::ReadbackMismatch)?;
        observed.update(&buffer[..n]);
    }
    let after = fstat(&readback).map_err(|_| CandidateShadowAssetsError::ReadbackMismatch)?;
    let visible = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateShadowAssetsError::ReadbackMismatch)?;
    if count != data.len()
        || format!("{:x}", observed.finalize()) != digest
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
    {
        return Err(CandidateShadowAssetsError::ReadbackMismatch);
    }
    Ok(())
}

/// Copy only previously captured data into a one-use, non-admitted /opt tree.
/// A partial tree is retained on any error and cannot be retried under the
/// same job ID. No candidate process, installer, config or deployment runs.
pub fn assemble_candidate_shadow_assets_ineligible(
    pins: &CandidateShadowAssetsPins<'_>,
) -> Result<CandidateShadowAssetsProof, CandidateShadowAssetsError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateShadowAssetsError::RootRequired);
    }
    if !lower_hex(pins.job_id, 16)
        || !is_git_sha(pins.source_sha)
        || !lower_hex(pins.source_archive_sha256, 64)
        || !lower_hex(pins.archive_sha256, 64)
        || !valid_package_version(pins.version)
        || !lower_hex(pins.native_sha256, 64)
        || !lower_hex(pins.prefix_tree_sha256, 64)
        || !lower_hex(pins.wheel_sha256, 64)
    {
        return Err(CandidateShadowAssetsError::InvalidPins);
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| CandidateShadowAssetsError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| CandidateShadowAssetsError::LeaseUnavailable)?;
    let python_lock =
        python_worker_lock().map_err(|_| CandidateShadowAssetsError::LeaseUnavailable)?;
    let job = open_fixed_build_slot(pins.job_id)
        .map_err(|_| CandidateShadowAssetsError::SourceMismatch)?;
    verify_captured_source(&job, pins.source_archive_sha256)
        .map_err(|_| CandidateShadowAssetsError::SourceMismatch)?;
    inactive(pins.job_id).map_err(|_| CandidateShadowAssetsError::BuildActive)?;
    let archive = openat(
        &job,
        "candidate.zip",
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateShadowAssetsError::ArchiveMismatch)?;
    let archive_stat = fstat(&archive).map_err(|_| CandidateShadowAssetsError::ArchiveMismatch)?;
    if archive_stat.st_size <= 0 || archive_stat.st_size as u64 > MAX_ARCHIVE {
        return Err(CandidateShadowAssetsError::ArchiveMismatch);
    }
    let declaration = verify_captured(
        &job,
        pins.archive_sha256,
        archive_stat.st_size as u64,
        pins.source_sha,
        pins.version,
    )
    .map_err(|_| CandidateShadowAssetsError::ArchiveMismatch)?;
    if declaration.wheel_sha256 != pins.wheel_sha256
        || declaration.native_sha256_claim != pins.native_sha256
    {
        return Err(CandidateShadowAssetsError::ArchiveMismatch);
    }
    let mut outer = ZipArchive::new(File::from(archive))
        .map_err(|_| CandidateShadowAssetsError::ArchiveMismatch)?;
    let mut wheel = Vec::with_capacity(declaration.wheel_bytes as usize);
    outer
        .by_name(&declaration.wheel)
        .map_err(|_| CandidateShadowAssetsError::ArchiveMismatch)?
        .take(MAX_ARCHIVE + 1)
        .read_to_end(&mut wheel)
        .map_err(|_| CandidateShadowAssetsError::ArchiveMismatch)?;
    if wheel.len() as u64 != declaration.wheel_bytes {
        return Err(CandidateShadowAssetsError::ArchiveMismatch);
    }
    let checked_wheel = inspect_candidate_wheel(&wheel, &declaration)
        .map_err(|_| CandidateShadowAssetsError::ArchiveMismatch)?;
    let mut nested = ZipArchive::new(Cursor::new(&wheel))
        .map_err(|_| CandidateShadowAssetsError::ArchiveMismatch)?;
    let mut native = Vec::with_capacity(checked_wheel.native_bytes as usize);
    nested
        .by_name(NATIVE_IN_WHEEL)
        .map_err(|_| CandidateShadowAssetsError::ArchiveMismatch)?
        .take(MAX_NATIVE + 1)
        .read_to_end(&mut native)
        .map_err(|_| CandidateShadowAssetsError::ArchiveMismatch)?;
    if native.len() as u64 != checked_wheel.native_bytes
        || checked_wheel.native_sha256 != pins.native_sha256
        || format!("{:x}", Sha256::digest(&native)) != pins.native_sha256
    {
        return Err(CandidateShadowAssetsError::ArchiveMismatch);
    }
    let source_prefix = Path::new("/var/lib/hol-gauntlet/builds")
        .join(pins.job_id)
        .join(PREFIX);
    let source_inventory = inventory_tree(&source_prefix, TreeKind::InstalledPrefix)
        .map_err(|_| CandidateShadowAssetsError::PrefixMismatch)?;
    if source_inventory.digest != pins.prefix_tree_sha256 {
        return Err(CandidateShadowAssetsError::PrefixMismatch);
    }
    verify_installed_version_metadata(
        &source_prefix,
        pins.version,
        pins.source_sha,
        pins.native_sha256,
    )
    .map_err(|_| CandidateShadowAssetsError::PrefixMismatch)?;
    let free = statvfs(BASE).map_err(|_| CandidateShadowAssetsError::LowDisk)?;
    let available = u128::from(free.f_bavail) * u128::from(free.f_frsize);
    let required = u128::from(MIN_REMAIN_FREE)
        + u128::from(source_inventory.bytes)
        + wheel.len() as u128
        + native.len() as u128
        + 64 * 1024 * 1024;
    if available < required {
        return Err(CandidateShadowAssetsError::LowDisk);
    }
    let base = open_root_owned_public_directory(Path::new(BASE))
        .map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    match mkdirat(&base, SHADOW, Mode::from_bits_truncate(0o700)) {
        Ok(()) => fsync(&base).map_err(|_| CandidateShadowAssetsError::CopyUncertain)?,
        Err(Errno::EXIST) => (),
        Err(_) => return Err(CandidateShadowAssetsError::CopyUncertain),
    }
    let shadow_parent = openat(
        &base,
        SHADOW,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    private_directory(&shadow_parent)?;
    match mkdirat(&shadow_parent, pins.job_id, Mode::from_bits_truncate(0o700)) {
        Ok(()) => fsync(&shadow_parent).map_err(|_| CandidateShadowAssetsError::CopyUncertain)?,
        Err(Errno::EXIST) => return Err(CandidateShadowAssetsError::ExistingShadow),
        Err(_) => return Err(CandidateShadowAssetsError::CopyUncertain),
    }
    let shadow = openat(
        &shadow_parent,
        pins.job_id,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    private_directory(&shadow)?;
    let source = openat(
        &job,
        PREFIX,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateShadowAssetsError::PrefixMismatch)?;
    mkdirat(&shadow, "prefix", Mode::from_bits_truncate(0o700))
        .map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    let target = openat(
        &shadow,
        "prefix",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    let mut entries = 0;
    let mut bytes = 0;
    clone_baseline(&source, &target, "", 0, &mut entries, &mut bytes, false)
        .map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    fchmod(&target, Mode::from_bits_truncate(0o755))
        .map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    fsync(&target).map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    fsync(&shadow).map_err(|_| CandidateShadowAssetsError::CopyUncertain)?;
    if bytes != source_inventory.bytes || entries != source_inventory.entries {
        return Err(CandidateShadowAssetsError::ReadbackMismatch);
    }
    write_data(
        &shadow,
        &declaration.wheel,
        &wheel,
        pins.wheel_sha256,
        0o444,
    )?;
    write_data(
        &shadow,
        "hol-guard-runtime",
        &native,
        pins.native_sha256,
        0o555,
    )?;
    let shadow_path = Path::new(BASE).join(SHADOW).join(pins.job_id);
    let target_inventory = inventory_tree(&shadow_path.join("prefix"), TreeKind::InstalledPrefix)
        .map_err(|_| CandidateShadowAssetsError::ReadbackMismatch)?;
    if target_inventory.digest != pins.prefix_tree_sha256
        || target_inventory.bytes != source_inventory.bytes
        || target_inventory.entries != source_inventory.entries
        || inventory_tree(&source_prefix, TreeKind::InstalledPrefix)
            .map_err(|_| CandidateShadowAssetsError::PrefixMismatch)?
            .digest
            != pins.prefix_tree_sha256
    {
        return Err(CandidateShadowAssetsError::ReadbackMismatch);
    }
    verify_captured(
        &job,
        pins.archive_sha256,
        archive_stat.st_size as u64,
        pins.source_sha,
        pins.version,
    )
    .map_err(|_| CandidateShadowAssetsError::ArchiveMismatch)?;
    verify_captured_source(&job, pins.source_archive_sha256)
        .map_err(|_| CandidateShadowAssetsError::SourceMismatch)?;
    inactive(pins.job_id).map_err(|_| CandidateShadowAssetsError::BuildActive)?;
    lease
        .verify(&journal.root)
        .map_err(|_| CandidateShadowAssetsError::LeaseUnavailable)?;
    verify_python_lock(&python_lock).map_err(|_| CandidateShadowAssetsError::LeaseUnavailable)?;
    Ok(CandidateShadowAssetsProof {
        job_id: pins.job_id.to_owned(),
        source_sha: pins.source_sha.to_owned(),
        shadow_root: shadow_path.to_string_lossy().into_owned(),
        prefix_tree_sha256: target_inventory.digest,
        prefix_entries: target_inventory.entries,
        prefix_bytes: target_inventory.bytes,
        wheel_sha256: pins.wheel_sha256.to_owned(),
        native_sha256: pins.native_sha256.to_owned(),
        contained_completion_present: checked_wheel.contained_completion_present,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unprivileged_shadow_assembly_refuses_before_any_files() {
        if geteuid().as_raw() == 0 {
            return;
        }
        let pins = CandidateShadowAssetsPins {
            job_id: "",
            source_sha: "",
            source_archive_sha256: "",
            archive_sha256: "",
            version: "",
            native_sha256: "",
            prefix_tree_sha256: "",
            wheel_sha256: "",
        };
        assert!(matches!(
            assemble_candidate_shadow_assets_ineligible(&pins),
            Err(CandidateShadowAssetsError::RootRequired)
        ));
    }
}
