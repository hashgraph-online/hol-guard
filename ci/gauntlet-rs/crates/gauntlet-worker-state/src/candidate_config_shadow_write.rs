//! One-use shadow-path provisional config, with inert Rust asset verification.
//! The output is Root-only data and cannot be a worker deployment.

use crate::builder_candidate_source::{open_fixed_build_slot, same_file, verify_captured_source};
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::candidate_capture::{inactive, verify_captured};
use crate::candidate_config_projection::{
    project_shadow_candidate_config_ineligible,
    project_shadow_candidate_config_with_private_cell_ineligible, CandidateConfigProjectionPins,
};
use crate::candidate_config_projection_live::{
    project_cloned_candidate_config_ineligible, project_installed_candidate_config_ineligible,
    CandidateConfigArtifactPins,
};
use crate::{open_root_owned_public_directory, RunReservationJournal};
use gauntlet_evidence::{
    inventory_tree, load_runner_config_from_paths, verify_private_cell_artifacts,
    verify_runner_assets_inert, TreeKind,
};
use rustix::fs::{fchmod, fstat, fsync, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;

const ASSET_ROOT: &str = "/opt";
const SHADOW_ROOT: &str = "/opt/hol-gauntlet/rust-shadow-candidates";
const CONFIG: &str = "provisional.json";
const MAX_WHEEL: u64 = 256 * 1024 * 1024;
const MAX_NATIVE: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateConfigShadowWriteError {
    RootRequired,
    ArtifactMismatch,
    LeaseUnavailable,
    SourceMismatch,
    BuildActive,
    ShadowMismatch,
    TemplateMismatch,
    PrivateCellMismatch,
    ExistingConfig,
    WriteUncertain,
    RunnerConfigMismatch(String),
    AssetMismatch(String),
}

impl fmt::Display for CandidateConfigShadowWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for shadow candidate config",
            Self::ArtifactMismatch => "captured candidate artifacts differ from outside pins",
            Self::LeaseUnavailable => "Rust or Python worker lease unavailable",
            Self::SourceMismatch => "captured source differs from outside digest",
            Self::BuildActive => "candidate build or cleanup remains active or uncertain",
            Self::ShadowMismatch => "one-use shadow assets differ from outside pins",
            Self::TemplateMismatch => "installed template or shadow projection refused",
            Self::PrivateCellMismatch => {
                "source-matched private-cell artifacts differ from outside pin"
            }
            Self::ExistingConfig => "one-use shadow provisional config already exists",
            Self::WriteUncertain => "shadow provisional config write or readback is uncertain",
            Self::RunnerConfigMismatch(_) => "inert runner config refused",
            Self::AssetMismatch(_) => "inert runner asset inventory refused",
        })?;
        match self {
            Self::RunnerConfigMismatch(reason) | Self::AssetMismatch(reason) => {
                write!(f, ": {reason}")
            }
            _ => Ok(()),
        }
    }
}

impl std::error::Error for CandidateConfigShadowWriteError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateConfigShadowWriteProof {
    job_id: String,
    source_sha: String,
    config_path: String,
    config_digest: String,
    config_file_sha256: String,
    config_bytes: usize,
    asset_roles: usize,
    private_cell_manifest_sha256: Option<String>,
    contained_completion_present: bool,
}

impl CandidateConfigShadowWriteProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-candidate-shadow-config.v1",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "config_path":self.config_path,
            "config_digest":self.config_digest,
            "config_file_sha256":self.config_file_sha256,
            "config_bytes":self.config_bytes,
            "asset_roles":self.asset_roles,
            "private_cell_manifest_sha256":self.private_cell_manifest_sha256,
            "wheel_completion_module_present":self.contained_completion_present,
            "missing_capabilities":if self.contained_completion_present { vec![] } else { vec!["contained-output-completion.v1"] },
            "config_written":true,
            "inert_assets_verified":true,
            "conformance_completed":false,
            "deployment_created":false,
            "execution_eligible":false,
        })
    }
}

fn shadow_directory(fd: &OwnedFd) -> Result<(), CandidateConfigShadowWriteError> {
    let stat = fstat(fd).map_err(|_| CandidateConfigShadowWriteError::ShadowMismatch)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o777 != 0o700
    {
        return Err(CandidateConfigShadowWriteError::ShadowMismatch);
    }
    Ok(())
}

fn hash_shadow_file(
    root: &OwnedFd,
    name: &str,
    expected: &str,
    maximum: u64,
    mode: u32,
) -> Result<(), CandidateConfigShadowWriteError> {
    let descriptor = openat(
        root,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateConfigShadowWriteError::ShadowMismatch)?;
    let before = fstat(&descriptor).map_err(|_| CandidateConfigShadowWriteError::ShadowMismatch)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o777 != mode
        || before.st_size <= 0
        || before.st_size as u64 > maximum
    {
        return Err(CandidateConfigShadowWriteError::ShadowMismatch);
    }
    let mut file = File::from(descriptor);
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|_| CandidateConfigShadowWriteError::ShadowMismatch)?;
        if n == 0 {
            break;
        }
        bytes = bytes
            .checked_add(n as u64)
            .filter(|size| *size <= maximum)
            .ok_or(CandidateConfigShadowWriteError::ShadowMismatch)?;
        digest.update(&buffer[..n]);
    }
    let after = fstat(&file).map_err(|_| CandidateConfigShadowWriteError::ShadowMismatch)?;
    let visible = statat(root, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| CandidateConfigShadowWriteError::ShadowMismatch)?;
    if bytes != before.st_size as u64
        || format!("{:x}", digest.finalize()) != expected
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
    {
        return Err(CandidateConfigShadowWriteError::ShadowMismatch);
    }
    Ok(())
}

fn verify_shadow_assets(
    root: &OwnedFd,
    path: &Path,
    pins: &CandidateConfigArtifactPins<'_>,
) -> Result<(), CandidateConfigShadowWriteError> {
    if inventory_tree(&path.join("prefix"), TreeKind::InstalledPrefix)
        .map_err(|_| CandidateConfigShadowWriteError::ShadowMismatch)?
        .digest
        != pins.prefix_tree_sha256
    {
        return Err(CandidateConfigShadowWriteError::ShadowMismatch);
    }
    let wheel = format!("hol_guard-{}-py3-none-linux_aarch64.whl", pins.version);
    hash_shadow_file(root, &wheel, pins.wheel_sha256, MAX_WHEEL, 0o444)?;
    hash_shadow_file(
        root,
        "hol-guard-runtime",
        pins.native_sha256,
        MAX_NATIVE,
        0o555,
    )?;
    Ok(())
}

/// Write only a Root-only provisional file under the one-use shadow asset
/// root. Full inert asset verification is required before returning; the file
/// is retained on any failure and never converted into a deployment here.
pub fn write_shadow_candidate_config_ineligible(
    pins: &CandidateConfigArtifactPins<'_>,
) -> Result<CandidateConfigShadowWriteProof, CandidateConfigShadowWriteError> {
    write_shadow_candidate_config_inner(pins, None)
}

/// A separate one-use filename binds the new source-matched private-cell
/// manifest. The prior failed provisional file remains retained unchanged.
pub fn write_shadow_candidate_config_with_private_cell_ineligible(
    pins: &CandidateConfigArtifactPins<'_>,
    manifest_sha256: &str,
) -> Result<CandidateConfigShadowWriteProof, CandidateConfigShadowWriteError> {
    write_shadow_candidate_config_inner(pins, Some(manifest_sha256))
}

fn write_shadow_candidate_config_inner(
    pins: &CandidateConfigArtifactPins<'_>,
    private_cell_manifest: Option<&str>,
) -> Result<CandidateConfigShadowWriteProof, CandidateConfigShadowWriteError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateConfigShadowWriteError::RootRequired);
    }
    let artifact_proof = project_cloned_candidate_config_ineligible(pins)
        .map_err(|_| CandidateConfigShadowWriteError::ArtifactMismatch)?;
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| CandidateConfigShadowWriteError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| CandidateConfigShadowWriteError::LeaseUnavailable)?;
    let python_lock =
        python_worker_lock().map_err(|_| CandidateConfigShadowWriteError::LeaseUnavailable)?;
    let job = open_fixed_build_slot(pins.job_id)
        .map_err(|_| CandidateConfigShadowWriteError::SourceMismatch)?;
    verify_captured_source(&job, pins.source_archive_sha256)
        .map_err(|_| CandidateConfigShadowWriteError::SourceMismatch)?;
    inactive(pins.job_id).map_err(|_| CandidateConfigShadowWriteError::BuildActive)?;
    let archive = openat(
        &job,
        "candidate.zip",
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateConfigShadowWriteError::ArtifactMismatch)?;
    let archive_stat =
        fstat(&archive).map_err(|_| CandidateConfigShadowWriteError::ArtifactMismatch)?;
    if archive_stat.st_size <= 0 {
        return Err(CandidateConfigShadowWriteError::ArtifactMismatch);
    }
    let declaration = verify_captured(
        &job,
        pins.archive_sha256,
        archive_stat.st_size as u64,
        pins.source_sha,
        pins.version,
    )
    .map_err(|_| CandidateConfigShadowWriteError::ArtifactMismatch)?;
    if declaration.wheel_sha256 != pins.wheel_sha256
        || declaration.native_sha256_claim != pins.native_sha256
    {
        return Err(CandidateConfigShadowWriteError::ArtifactMismatch);
    }
    let shadow_path = Path::new(SHADOW_ROOT).join(pins.job_id);
    let shadow = open_root_owned_public_directory(&shadow_path)
        .map_err(|_| CandidateConfigShadowWriteError::ShadowMismatch)?;
    shadow_directory(&shadow)?;
    verify_shadow_assets(&shadow, &shadow_path, pins)?;
    let projection_pins = CandidateConfigProjectionPins {
        source_sha: pins.source_sha,
        package_version: pins.version,
        native_sha256: pins.native_sha256,
        root_prefix_digest: pins.prefix_tree_sha256,
        runtime_tree_digest: pins.prefix_tree_sha256,
        wheel_sha256: pins.wheel_sha256,
    };
    let template = project_installed_candidate_config_ineligible(
        pins.template_path,
        pins.template_raw_sha256,
        pins.template_canonical_sha256,
        &projection_pins,
    )
    .map_err(|_| CandidateConfigShadowWriteError::TemplateMismatch)?;
    let projection = match private_cell_manifest {
        Some(manifest) => project_shadow_candidate_config_with_private_cell_ineligible(
            template.template_raw(),
            pins.template_canonical_sha256,
            &projection_pins,
            pins.job_id,
            manifest,
        ),
        None => project_shadow_candidate_config_ineligible(
            template.template_raw(),
            pins.template_canonical_sha256,
            &projection_pins,
            pins.job_id,
        ),
    }
    .map_err(|_| CandidateConfigShadowWriteError::TemplateMismatch)?;
    let config_name = if let Some(manifest) = private_cell_manifest {
        let value: Value = serde_json::from_slice(&projection.canonical_bytes)
            .map_err(|_| CandidateConfigShadowWriteError::TemplateMismatch)?;
        let initializer = value["runtime"]["private_cell"]["initializer_sha256"]
            .as_str()
            .ok_or(CandidateConfigShadowWriteError::TemplateMismatch)?;
        verify_private_cell_artifacts(&shadow_path.join("cell-artifacts"), manifest, initializer)
            .map_err(|_| CandidateConfigShadowWriteError::PrivateCellMismatch)?;
        format!("provisional-{}.json", &manifest[..16])
    } else {
        CONFIG.to_owned()
    };
    let descriptor = openat(
        &shadow,
        config_name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::EXIST {
            CandidateConfigShadowWriteError::ExistingConfig
        } else {
            CandidateConfigShadowWriteError::WriteUncertain
        }
    })?;
    let mut file = File::from(descriptor);
    file.write_all(&projection.file_bytes)
        .map_err(|_| CandidateConfigShadowWriteError::WriteUncertain)?;
    file.sync_all()
        .map_err(|_| CandidateConfigShadowWriteError::WriteUncertain)?;
    fchmod(&file, Mode::from_bits_truncate(0o444))
        .map_err(|_| CandidateConfigShadowWriteError::WriteUncertain)?;
    file.sync_all()
        .map_err(|_| CandidateConfigShadowWriteError::WriteUncertain)?;
    fsync(&shadow).map_err(|_| CandidateConfigShadowWriteError::WriteUncertain)?;
    let config_path = shadow_path.join(&config_name);
    let file_digest = format!("{:x}", Sha256::digest(&projection.file_bytes));
    hash_shadow_file(&shadow, &config_name, &file_digest, 16 * 1024 * 1024, 0o444)
        .map_err(|_| CandidateConfigShadowWriteError::WriteUncertain)?;
    let loaded =
        load_runner_config_from_paths(&config_path, &projection.digest, Path::new(ASSET_ROOT))
            .map_err(|error| {
                CandidateConfigShadowWriteError::RunnerConfigMismatch(error.to_string())
            })?;
    let assets = verify_runner_assets_inert(&loaded, Path::new(ASSET_ROOT))
        .map_err(|error| CandidateConfigShadowWriteError::AssetMismatch(error.to_string()))?;
    if let Some(manifest) = private_cell_manifest {
        let initializer = loaded.verified.config.value()["runtime"]["private_cell"]
            ["initializer_sha256"]
            .as_str()
            .ok_or(CandidateConfigShadowWriteError::PrivateCellMismatch)?;
        verify_private_cell_artifacts(&shadow_path.join("cell-artifacts"), manifest, initializer)
            .map_err(|_| CandidateConfigShadowWriteError::PrivateCellMismatch)?;
    }
    verify_shadow_assets(&shadow, &shadow_path, pins)?;
    verify_captured(
        &job,
        pins.archive_sha256,
        archive_stat.st_size as u64,
        pins.source_sha,
        pins.version,
    )
    .map_err(|_| CandidateConfigShadowWriteError::ArtifactMismatch)?;
    verify_captured_source(&job, pins.source_archive_sha256)
        .map_err(|_| CandidateConfigShadowWriteError::SourceMismatch)?;
    inactive(pins.job_id).map_err(|_| CandidateConfigShadowWriteError::BuildActive)?;
    lease
        .verify(&journal.root)
        .map_err(|_| CandidateConfigShadowWriteError::LeaseUnavailable)?;
    verify_python_lock(&python_lock)
        .map_err(|_| CandidateConfigShadowWriteError::LeaseUnavailable)?;
    Ok(CandidateConfigShadowWriteProof {
        job_id: pins.job_id.to_owned(),
        source_sha: pins.source_sha.to_owned(),
        config_path: config_path.to_string_lossy().into_owned(),
        config_digest: projection.digest,
        config_file_sha256: file_digest,
        config_bytes: projection.file_bytes.len(),
        asset_roles: assets.observed.len(),
        private_cell_manifest_sha256: private_cell_manifest.map(str::to_owned),
        contained_completion_present: artifact_proof.contained_completion_present(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unprivileged_shadow_config_refuses_before_any_files() {
        if geteuid().as_raw() == 0 {
            return;
        }
        let pins = CandidateConfigArtifactPins {
            job_id: "",
            source_sha: "",
            source_archive_sha256: "",
            archive_sha256: "",
            version: "",
            native_sha256: "",
            prefix_tree_sha256: "",
            wheel_sha256: "",
            template_path: "",
            template_raw_sha256: "",
            template_canonical_sha256: "",
        };
        assert!(matches!(
            write_shadow_candidate_config_ineligible(&pins),
            Err(CandidateConfigShadowWriteError::RootRequired)
        ));
    }
}
