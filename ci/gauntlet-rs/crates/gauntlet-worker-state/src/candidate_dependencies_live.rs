//! Read-only, Root-held dependency verification for one inert prefix clone.
//! The interpreter version is an outside observation, not authenticated here.

use crate::builder_candidate_source::{open_fixed_build_slot, same_file, verify_captured_source};
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::candidate_capture::{inactive, verify_captured};
use crate::candidate_dependencies::{
    check_candidate_dependencies, metadata_headers, normalize_name, CandidateDependencyProof,
};
use crate::RunReservationJournal;
use gauntlet_contracts::is_git_sha;
use gauntlet_evidence::{
    inventory_tree, valid_package_version, verify_installed_version_metadata, TreeKind,
};
use pep508_rs::{MarkerEnvironment, MarkerEnvironmentBuilder};
use rustix::fs::{fstat, openat, openat2, Dir, FileType, Mode, OFlags, ResolveFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::OwnedFd;
use std::path::Path;

const PREFIX: &str = "inert-prefix";
const SITE: &str = "inert-prefix/lib/python3.12/site-packages";
const MAX_METADATA: u64 = 128 * 1024;
const MAX_DISTRIBUTIONS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateDependencyLiveError {
    RootRequired,
    InvalidPins,
    LeaseUnavailable,
    SourceMismatch,
    BuildActive,
    ArchiveInvalid,
    PrefixMismatch,
    MetadataUnsafe,
    DistributionAmbiguous,
    MarkerEnvironmentUnavailable,
    RequirementRefused,
}

impl fmt::Display for CandidateDependencyLiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for inert dependency check",
            Self::InvalidPins => "exact source, prefix and interpreter-version pins required",
            Self::LeaseUnavailable => "Rust or Python worker lease unavailable",
            Self::SourceMismatch => "captured source differs from outside digest",
            Self::BuildActive => "candidate build or cleanup remains active or uncertain",
            Self::ArchiveInvalid => "captured candidate archive differs from outside pins",
            Self::PrefixMismatch => "inert prefix differs from outside tree digest",
            Self::MetadataUnsafe => "Root-owned bounded distribution metadata required",
            Self::DistributionAmbiguous => "installed distribution metadata has duplicate identity",
            Self::MarkerEnvironmentUnavailable => "Linux ARM Python marker environment unavailable",
            Self::RequirementRefused => "candidate dependency is absent or incompatible",
        })
    }
}

impl std::error::Error for CandidateDependencyLiveError {}

#[derive(Debug, Clone, Copy)]
pub struct CandidateDependencyLivePins<'a> {
    pub job_id: &'a str,
    pub source_sha: &'a str,
    pub source_archive_sha256: &'a str,
    pub archive_sha256: &'a str,
    pub version: &'a str,
    pub native_sha256: &'a str,
    pub prefix_tree_sha256: &'a str,
    pub python_full_version: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateDependencyLiveProof {
    job_id: String,
    source_sha: String,
    archive_sha256: String,
    native_sha256: String,
    prefix_tree_sha256: String,
    python_full_version: String,
    installed_distributions: usize,
    dependencies: CandidateDependencyProof,
}

impl CandidateDependencyLiveProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-candidate-dependencies-shadow.v1",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "archive_sha256":self.archive_sha256,
            "native_sha256":self.native_sha256,
            "prefix_tree_sha256":self.prefix_tree_sha256,
            "python_full_version":self.python_full_version,
            "installed_distributions":self.installed_distributions,
            "requirements":self.dependencies.requirements,
            "active_requirements":self.dependencies.active,
            "inactive_requirements":self.dependencies.inactive,
            "active_names":self.dependencies.active_names,
            "all_active_requirements_satisfied":true,
            "candidate_executed":false,
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

fn root_directory(fd: &OwnedFd) -> Result<(), CandidateDependencyLiveError> {
    let stat = fstat(fd).map_err(|_| CandidateDependencyLiveError::MetadataUnsafe)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_mode & 0o022 != 0
    {
        return Err(CandidateDependencyLiveError::MetadataUnsafe);
    }
    Ok(())
}

fn read_metadata(directory: &OwnedFd, path: &str) -> Result<Vec<u8>, CandidateDependencyLiveError> {
    let fd = openat2(
        directory,
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| CandidateDependencyLiveError::MetadataUnsafe)?;
    let before = fstat(&fd).map_err(|_| CandidateDependencyLiveError::MetadataUnsafe)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_mode & 0o022 != 0
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as u64 > MAX_METADATA
    {
        return Err(CandidateDependencyLiveError::MetadataUnsafe);
    }
    let mut file = File::from(fd);
    let mut bytes = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take(MAX_METADATA + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| CandidateDependencyLiveError::MetadataUnsafe)?;
    let after = fstat(&file).map_err(|_| CandidateDependencyLiveError::MetadataUnsafe)?;
    let visible = openat2(
        directory,
        path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| CandidateDependencyLiveError::MetadataUnsafe)?;
    let visible = fstat(&visible).map_err(|_| CandidateDependencyLiveError::MetadataUnsafe)?;
    if bytes.len() as i64 != before.st_size
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
    {
        return Err(CandidateDependencyLiveError::MetadataUnsafe);
    }
    Ok(bytes)
}

fn distribution_identity(raw: &[u8]) -> Result<(String, String), CandidateDependencyLiveError> {
    let headers =
        metadata_headers(raw).map_err(|_| CandidateDependencyLiveError::MetadataUnsafe)?;
    let mut name = None;
    let mut version = None;
    for (key, value) in headers {
        if key.eq_ignore_ascii_case("Name") {
            if name.replace(value).is_some() {
                return Err(CandidateDependencyLiveError::MetadataUnsafe);
            }
        } else if key.eq_ignore_ascii_case("Version") && version.replace(value).is_some() {
            return Err(CandidateDependencyLiveError::MetadataUnsafe);
        }
    }
    let name = name.ok_or(CandidateDependencyLiveError::MetadataUnsafe)?;
    let version = version.ok_or(CandidateDependencyLiveError::MetadataUnsafe)?;
    if name.is_empty() || version.is_empty() {
        return Err(CandidateDependencyLiveError::MetadataUnsafe);
    }
    Ok((normalize_name(&name), version))
}

fn installed_distributions(
    site: &OwnedFd,
) -> Result<BTreeMap<String, String>, CandidateDependencyLiveError> {
    let mut versions = BTreeMap::new();
    let entries = Dir::read_from(site).map_err(|_| CandidateDependencyLiveError::MetadataUnsafe)?;
    for item in entries {
        let item = item.map_err(|_| CandidateDependencyLiveError::MetadataUnsafe)?;
        let name = item
            .file_name()
            .to_str()
            .map_err(|_| CandidateDependencyLiveError::MetadataUnsafe)?;
        if !name.ends_with(".dist-info") {
            continue;
        }
        if name.contains('/') || name.contains('\\') || name == "." || name == ".." {
            return Err(CandidateDependencyLiveError::MetadataUnsafe);
        }
        let directory = openat2(
            site,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| CandidateDependencyLiveError::MetadataUnsafe)?;
        root_directory(&directory)?;
        let raw = read_metadata(&directory, "METADATA")?;
        let (package, version) = distribution_identity(&raw)?;
        if versions.insert(package, version).is_some() {
            return Err(CandidateDependencyLiveError::DistributionAmbiguous);
        }
        if versions.len() > MAX_DISTRIBUTIONS {
            return Err(CandidateDependencyLiveError::MetadataUnsafe);
        }
    }
    Ok(versions)
}

fn uname_text(raw: &[libc::c_char]) -> Result<&str, CandidateDependencyLiveError> {
    // SAFETY: libc::uname NUL-terminates each fixed utsname field on success.
    unsafe { CStr::from_ptr(raw.as_ptr()) }
        .to_str()
        .map_err(|_| CandidateDependencyLiveError::MarkerEnvironmentUnavailable)
}

fn marker_environment(
    full_version: &str,
) -> Result<MarkerEnvironment, CandidateDependencyLiveError> {
    if !full_version.starts_with("3.12.")
        || !full_version[5..].bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(CandidateDependencyLiveError::InvalidPins);
    }
    let mut uts = MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: uts points to writable storage for one libc::utsname value.
    if unsafe { libc::uname(uts.as_mut_ptr()) } != 0 {
        return Err(CandidateDependencyLiveError::MarkerEnvironmentUnavailable);
    }
    // SAFETY: uname succeeded and initialized every utsname field.
    let uts = unsafe { uts.assume_init() };
    let machine = uname_text(&uts.machine)?;
    if machine != "aarch64" {
        return Err(CandidateDependencyLiveError::MarkerEnvironmentUnavailable);
    }
    MarkerEnvironment::try_from(MarkerEnvironmentBuilder {
        implementation_name: "cpython",
        implementation_version: full_version,
        os_name: "posix",
        platform_machine: machine,
        platform_python_implementation: "CPython",
        platform_release: uname_text(&uts.release)?,
        platform_system: "Linux",
        platform_version: uname_text(&uts.version)?,
        python_full_version: full_version,
        python_version: "3.12",
        sys_platform: "linux",
    })
    .map_err(|_| CandidateDependencyLiveError::MarkerEnvironmentUnavailable)
}

/// Read a complete Root-owned inert prefix and evaluate its candidate's PEP
/// 508 requirements against its installed PEP 440 versions. This diagnostic
/// cannot establish interpreter provenance or execution admission.
pub fn verify_cloned_candidate_dependencies_ineligible(
    pins: &CandidateDependencyLivePins<'_>,
) -> Result<CandidateDependencyLiveProof, CandidateDependencyLiveError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateDependencyLiveError::RootRequired);
    }
    if !lower_hex(pins.job_id, 16)
        || !is_git_sha(pins.source_sha)
        || !lower_hex(pins.source_archive_sha256, 64)
        || !lower_hex(pins.archive_sha256, 64)
        || !valid_package_version(pins.version)
        || !lower_hex(pins.native_sha256, 64)
        || !lower_hex(pins.prefix_tree_sha256, 64)
    {
        return Err(CandidateDependencyLiveError::InvalidPins);
    }
    let environment = marker_environment(pins.python_full_version)?;
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| CandidateDependencyLiveError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| CandidateDependencyLiveError::LeaseUnavailable)?;
    let python_lock =
        python_worker_lock().map_err(|_| CandidateDependencyLiveError::LeaseUnavailable)?;
    let job = open_fixed_build_slot(pins.job_id)
        .map_err(|_| CandidateDependencyLiveError::SourceMismatch)?;
    verify_captured_source(&job, pins.source_archive_sha256)
        .map_err(|_| CandidateDependencyLiveError::SourceMismatch)?;
    inactive(pins.job_id).map_err(|_| CandidateDependencyLiveError::BuildActive)?;
    let archive = openat(
        &job,
        "candidate.zip",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateDependencyLiveError::ArchiveInvalid)?;
    let archive_stat = fstat(&archive).map_err(|_| CandidateDependencyLiveError::ArchiveInvalid)?;
    if archive_stat.st_size <= 0 {
        return Err(CandidateDependencyLiveError::ArchiveInvalid);
    }
    verify_captured(
        &job,
        pins.archive_sha256,
        archive_stat.st_size as u64,
        pins.source_sha,
        pins.version,
    )
    .map_err(|_| CandidateDependencyLiveError::ArchiveInvalid)?;
    let prefix_path = Path::new("/var/lib/hol-gauntlet/builds")
        .join(pins.job_id)
        .join(PREFIX);
    let inventory = inventory_tree(&prefix_path, TreeKind::InstalledPrefix)
        .map_err(|_| CandidateDependencyLiveError::PrefixMismatch)?;
    if inventory.digest != pins.prefix_tree_sha256 {
        return Err(CandidateDependencyLiveError::PrefixMismatch);
    }
    verify_installed_version_metadata(
        &prefix_path,
        pins.version,
        pins.source_sha,
        pins.native_sha256,
    )
    .map_err(|_| CandidateDependencyLiveError::PrefixMismatch)?;
    let site = openat2(
        &job,
        SITE,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| CandidateDependencyLiveError::MetadataUnsafe)?;
    root_directory(&site)?;
    let versions = installed_distributions(&site)?;
    let product = format!("hol_guard-{}.dist-info/METADATA", pins.version);
    let metadata = read_metadata(&site, &product)?;
    let dependencies =
        check_candidate_dependencies(&metadata, pins.version, &versions, &environment)
            .map_err(|_| CandidateDependencyLiveError::RequirementRefused)?;
    if inventory_tree(&prefix_path, TreeKind::InstalledPrefix)
        .map_err(|_| CandidateDependencyLiveError::PrefixMismatch)?
        .digest
        != pins.prefix_tree_sha256
    {
        return Err(CandidateDependencyLiveError::PrefixMismatch);
    }
    verify_captured(
        &job,
        pins.archive_sha256,
        archive_stat.st_size as u64,
        pins.source_sha,
        pins.version,
    )
    .map_err(|_| CandidateDependencyLiveError::ArchiveInvalid)?;
    verify_captured_source(&job, pins.source_archive_sha256)
        .map_err(|_| CandidateDependencyLiveError::SourceMismatch)?;
    inactive(pins.job_id).map_err(|_| CandidateDependencyLiveError::BuildActive)?;
    lease
        .verify(&journal.root)
        .map_err(|_| CandidateDependencyLiveError::LeaseUnavailable)?;
    verify_python_lock(&python_lock).map_err(|_| CandidateDependencyLiveError::LeaseUnavailable)?;
    Ok(CandidateDependencyLiveProof {
        job_id: pins.job_id.to_owned(),
        source_sha: pins.source_sha.to_owned(),
        archive_sha256: pins.archive_sha256.to_owned(),
        native_sha256: pins.native_sha256.to_owned(),
        prefix_tree_sha256: pins.prefix_tree_sha256.to_owned(),
        python_full_version: pins.python_full_version.to_owned(),
        installed_distributions: versions.len(),
        dependencies,
    })
}
