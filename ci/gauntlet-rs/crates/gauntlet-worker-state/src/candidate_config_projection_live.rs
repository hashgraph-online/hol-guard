//! Read-only diagnostic for a Root-owned installed staging template.

use crate::builder_candidate_source::same_file;
use crate::builder_candidate_source::{open_fixed_build_slot, verify_captured_source};
use crate::builder_image_context::{python_worker_lock, verify_python_lock, RUST_STATE};
use crate::candidate_capture::{inactive, verify_captured};
use crate::candidate_config_projection::{
    project_candidate_config_ineligible, CandidateConfigProjectionPins,
};
use crate::candidate_wheel::inspect_candidate_wheel;
use crate::{open_root_owned_public_directory, RunReservationJournal};
use gauntlet_contracts::is_git_sha;
use gauntlet_evidence::{
    inventory_tree, valid_package_version, verify_installed_version_metadata, TreeKind,
};
use rustix::fs::{fstat, openat, openat2, FileType, Mode, OFlags, ResolveFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

const NAME: &str = "staging-template.json";
const MAX_TEMPLATE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateConfigLiveError {
    RootRequired,
    InvalidArtifactPins,
    LeaseUnavailable,
    SourceMismatch,
    BuildActive,
    ArchiveMismatch,
    NativeMismatch,
    PrefixMismatch,
    InvalidTemplatePath,
    InvalidTemplatePin,
    UnsafeTemplate,
    ProjectionRefused,
}

impl fmt::Display for CandidateConfigLiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for installed template check",
            Self::InvalidArtifactPins => "exact captured artifact and prefix pins required",
            Self::LeaseUnavailable => "Rust or Python worker lease unavailable",
            Self::SourceMismatch => "captured source differs from outside digest",
            Self::BuildActive => "candidate build or cleanup remains active or uncertain",
            Self::ArchiveMismatch => "captured archive or declared wheel differs from outside pins",
            Self::NativeMismatch => "installed native bytes differ from outside digest",
            Self::PrefixMismatch => {
                "inert prefix or installed Guard identity differs from outside pins"
            }
            Self::InvalidTemplatePath => "fixed controller staging-template path required",
            Self::InvalidTemplatePin => "outside raw template SHA-256 required",
            Self::UnsafeTemplate => "stable Root-owned staging template required",
            Self::ProjectionRefused => "candidate config projection refused",
        })
    }
}

impl std::error::Error for CandidateConfigLiveError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateConfigLiveProof {
    template_path: String,
    template_raw_sha256: String,
    template_canonical_sha256: String,
    config_digest: String,
    config_bytes: usize,
    file_bytes: usize,
    template_raw: Vec<u8>,
}

impl CandidateConfigLiveProof {
    pub(crate) fn template_raw(&self) -> &[u8] {
        &self.template_raw
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-candidate-config-shadow.v1",
            "template_path":self.template_path,
            "template_raw_sha256":self.template_raw_sha256,
            "template_canonical_sha256":self.template_canonical_sha256,
            "config_digest":self.config_digest,
            "config_bytes":self.config_bytes,
            "file_bytes":self.file_bytes,
            "candidate_config_written":false,
            "assets_verified":false,
            "conformance_completed":false,
            "deployment_created":false,
            "execution_eligible":false,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CandidateConfigArtifactPins<'a> {
    pub job_id: &'a str,
    pub source_sha: &'a str,
    pub source_archive_sha256: &'a str,
    pub archive_sha256: &'a str,
    pub version: &'a str,
    pub native_sha256: &'a str,
    pub prefix_tree_sha256: &'a str,
    pub wheel_sha256: &'a str,
    pub template_path: &'a str,
    pub template_raw_sha256: &'a str,
    pub template_canonical_sha256: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateConfigArtifactProof {
    job_id: String,
    source_sha: String,
    archive_sha256: String,
    prefix_tree_sha256: String,
    wheel_sha256: String,
    native_sha256: String,
    contained_completion_present: bool,
    config: CandidateConfigLiveProof,
}

impl CandidateConfigArtifactProof {
    pub(crate) fn contained_completion_present(&self) -> bool {
        self.contained_completion_present
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-candidate-config-artifacts-shadow.v1",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "archive_sha256":self.archive_sha256,
            "prefix_tree_sha256":self.prefix_tree_sha256,
            "wheel_sha256":self.wheel_sha256,
            "native_sha256":self.native_sha256,
            "wheel_completion_module_present":self.contained_completion_present,
            "missing_capabilities":if self.contained_completion_present { vec![] } else { vec!["contained-output-completion.v1"] },
            "template_raw_sha256":self.config.template_raw_sha256,
            "template_canonical_sha256":self.config.template_canonical_sha256,
            "config_digest":self.config.config_digest,
            "config_bytes":self.config.config_bytes,
            "candidate_config_written":false,
            "assets_verified":false,
            "conformance_completed":false,
            "deployment_created":false,
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

fn fixed_template_directory(path: &str) -> Result<&Path, CandidateConfigLiveError> {
    let generation = path
        .strip_prefix("/opt/hol-gauntlet/controller-")
        .and_then(|rest| rest.strip_suffix("/staging-template.json"))
        .ok_or(CandidateConfigLiveError::InvalidTemplatePath)?;
    if !lower_hex(generation, 16) {
        return Err(CandidateConfigLiveError::InvalidTemplatePath);
    }
    Path::new(path)
        .parent()
        .ok_or(CandidateConfigLiveError::InvalidTemplatePath)
}

/// Hash a trusted installed template through stable descriptors, then project
/// only inert JSON. Outside native, prefix and wheel pins are not authenticated
/// here, so this result cannot authorize a candidate run.
pub fn project_installed_candidate_config_ineligible(
    template_path: &str,
    template_raw_sha256: &str,
    template_canonical_sha256: &str,
    pins: &CandidateConfigProjectionPins<'_>,
) -> Result<CandidateConfigLiveProof, CandidateConfigLiveError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateConfigLiveError::RootRequired);
    }
    let parent = fixed_template_directory(template_path)?;
    if !lower_hex(template_raw_sha256, 64) {
        return Err(CandidateConfigLiveError::InvalidTemplatePin);
    }
    let directory = open_root_owned_public_directory(parent)
        .map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let directory_before =
        fstat(&directory).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let descriptor = openat(
        &directory,
        NAME,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let before = fstat(&descriptor).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 0
        || before.st_mode & 0o022 != 0
        || before.st_nlink != 1
        || before.st_size <= 0
        || before.st_size as u64 > MAX_TEMPLATE
    {
        return Err(CandidateConfigLiveError::UnsafeTemplate);
    }
    let mut file = File::from(descriptor);
    let mut raw = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take(MAX_TEMPLATE + 1)
        .read_to_end(&mut raw)
        .map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let after = fstat(&file).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let visible = openat(
        &directory,
        NAME,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let visible = fstat(&visible).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    if raw.len() as i64 != before.st_size
        || !same_file(&before, &after)
        || !same_file(&before, &visible)
        || format!("{:x}", Sha256::digest(&raw)) != template_raw_sha256
    {
        return Err(CandidateConfigLiveError::UnsafeTemplate);
    }
    let projection = project_candidate_config_ineligible(&raw, template_canonical_sha256, pins)
        .map_err(|_| CandidateConfigLiveError::ProjectionRefused)?;
    let directory_after =
        fstat(&directory).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let visible_directory = open_root_owned_public_directory(parent)
        .map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let visible_directory =
        fstat(&visible_directory).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let file_after = fstat(&file).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let visible_file = openat(
        &directory,
        NAME,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    let visible_file =
        fstat(&visible_file).map_err(|_| CandidateConfigLiveError::UnsafeTemplate)?;
    if !same_file(&directory_before, &directory_after)
        || !same_file(&directory_before, &visible_directory)
        || !same_file(&before, &file_after)
        || !same_file(&before, &visible_file)
    {
        return Err(CandidateConfigLiveError::UnsafeTemplate);
    }
    Ok(CandidateConfigLiveProof {
        template_path: template_path.to_owned(),
        template_raw_sha256: template_raw_sha256.to_owned(),
        template_canonical_sha256: template_canonical_sha256.to_owned(),
        config_digest: projection.digest,
        config_bytes: projection.canonical_bytes.len(),
        file_bytes: projection.file_bytes.len(),
        template_raw: raw,
    })
}

/// Compose the installed-template projection with the retained Root capture
/// and clone. This binds the config's outside values to observed inert assets,
/// but those assets are still in the private build slot, not a deployment.
pub fn project_cloned_candidate_config_ineligible(
    pins: &CandidateConfigArtifactPins<'_>,
) -> Result<CandidateConfigArtifactProof, CandidateConfigLiveError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateConfigLiveError::RootRequired);
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
        return Err(CandidateConfigLiveError::InvalidArtifactPins);
    }
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| CandidateConfigLiveError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| CandidateConfigLiveError::LeaseUnavailable)?;
    let python_lock =
        python_worker_lock().map_err(|_| CandidateConfigLiveError::LeaseUnavailable)?;
    let job =
        open_fixed_build_slot(pins.job_id).map_err(|_| CandidateConfigLiveError::SourceMismatch)?;
    verify_captured_source(&job, pins.source_archive_sha256)
        .map_err(|_| CandidateConfigLiveError::SourceMismatch)?;
    inactive(pins.job_id).map_err(|_| CandidateConfigLiveError::BuildActive)?;
    let archive = openat(
        &job,
        "candidate.zip",
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| CandidateConfigLiveError::ArchiveMismatch)?;
    let archive_stat = fstat(&archive).map_err(|_| CandidateConfigLiveError::ArchiveMismatch)?;
    if archive_stat.st_size <= 0 {
        return Err(CandidateConfigLiveError::ArchiveMismatch);
    }
    let declaration = verify_captured(
        &job,
        pins.archive_sha256,
        archive_stat.st_size as u64,
        pins.source_sha,
        pins.version,
    )
    .map_err(|_| CandidateConfigLiveError::ArchiveMismatch)?;
    if declaration.wheel_sha256 != pins.wheel_sha256
        || declaration.native_sha256_claim != pins.native_sha256
    {
        return Err(CandidateConfigLiveError::ArchiveMismatch);
    }
    let mut outer = ZipArchive::new(File::from(archive))
        .map_err(|_| CandidateConfigLiveError::ArchiveMismatch)?;
    let mut wheel = Vec::with_capacity(declaration.wheel_bytes as usize);
    outer
        .by_name(&declaration.wheel)
        .map_err(|_| CandidateConfigLiveError::ArchiveMismatch)?
        .take(256 * 1024 * 1024 + 1)
        .read_to_end(&mut wheel)
        .map_err(|_| CandidateConfigLiveError::ArchiveMismatch)?;
    if wheel.len() as u64 != declaration.wheel_bytes {
        return Err(CandidateConfigLiveError::ArchiveMismatch);
    }
    let checked_wheel = inspect_candidate_wheel(&wheel, &declaration)
        .map_err(|_| CandidateConfigLiveError::ArchiveMismatch)?;
    let archive = outer.into_inner();
    let archive_after = fstat(&archive).map_err(|_| CandidateConfigLiveError::ArchiveMismatch)?;
    if !same_file(&archive_stat, &archive_after) {
        return Err(CandidateConfigLiveError::ArchiveMismatch);
    }
    let prefix = Path::new("/var/lib/hol-gauntlet/builds")
        .join(pins.job_id)
        .join("inert-prefix");
    if inventory_tree(&prefix, TreeKind::InstalledPrefix)
        .map_err(|_| CandidateConfigLiveError::PrefixMismatch)?
        .digest
        != pins.prefix_tree_sha256
    {
        return Err(CandidateConfigLiveError::PrefixMismatch);
    }
    verify_installed_version_metadata(&prefix, pins.version, pins.source_sha, pins.native_sha256)
        .map_err(|_| CandidateConfigLiveError::PrefixMismatch)?;
    let native = openat2(
        &job,
        "inert-prefix/lib/python3.12/site-packages/codex_plugin_scanner/_native/hol-guard-runtime",
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| CandidateConfigLiveError::NativeMismatch)?;
    let native_before = fstat(&native).map_err(|_| CandidateConfigLiveError::NativeMismatch)?;
    if FileType::from_raw_mode(native_before.st_mode) != FileType::RegularFile
        || native_before.st_uid != 0
        || native_before.st_mode & 0o022 != 0
        || native_before.st_nlink != 1
        || native_before.st_size <= 0
        || native_before.st_size > 128 * 1024 * 1024
    {
        return Err(CandidateConfigLiveError::NativeMismatch);
    }
    let mut native = File::from(native);
    let mut native_bytes = Vec::with_capacity(native_before.st_size as usize);
    native
        .by_ref()
        .take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut native_bytes)
        .map_err(|_| CandidateConfigLiveError::NativeMismatch)?;
    let native_after = fstat(&native).map_err(|_| CandidateConfigLiveError::NativeMismatch)?;
    if native_bytes.len() as i64 != native_before.st_size
        || !same_file(&native_before, &native_after)
        || format!("{:x}", Sha256::digest(&native_bytes)) != pins.native_sha256
    {
        return Err(CandidateConfigLiveError::NativeMismatch);
    }
    let projection_pins = CandidateConfigProjectionPins {
        source_sha: pins.source_sha,
        package_version: pins.version,
        native_sha256: pins.native_sha256,
        root_prefix_digest: pins.prefix_tree_sha256,
        runtime_tree_digest: pins.prefix_tree_sha256,
        wheel_sha256: pins.wheel_sha256,
    };
    let config = project_installed_candidate_config_ineligible(
        pins.template_path,
        pins.template_raw_sha256,
        pins.template_canonical_sha256,
        &projection_pins,
    )?;
    if inventory_tree(&prefix, TreeKind::InstalledPrefix)
        .map_err(|_| CandidateConfigLiveError::PrefixMismatch)?
        .digest
        != pins.prefix_tree_sha256
    {
        return Err(CandidateConfigLiveError::PrefixMismatch);
    }
    verify_captured(
        &job,
        pins.archive_sha256,
        archive_stat.st_size as u64,
        pins.source_sha,
        pins.version,
    )
    .map_err(|_| CandidateConfigLiveError::ArchiveMismatch)?;
    verify_captured_source(&job, pins.source_archive_sha256)
        .map_err(|_| CandidateConfigLiveError::SourceMismatch)?;
    inactive(pins.job_id).map_err(|_| CandidateConfigLiveError::BuildActive)?;
    lease
        .verify(&journal.root)
        .map_err(|_| CandidateConfigLiveError::LeaseUnavailable)?;
    verify_python_lock(&python_lock).map_err(|_| CandidateConfigLiveError::LeaseUnavailable)?;
    Ok(CandidateConfigArtifactProof {
        job_id: pins.job_id.to_owned(),
        source_sha: pins.source_sha.to_owned(),
        archive_sha256: pins.archive_sha256.to_owned(),
        prefix_tree_sha256: pins.prefix_tree_sha256.to_owned(),
        wheel_sha256: pins.wheel_sha256.to_owned(),
        native_sha256: pins.native_sha256.to_owned(),
        contained_completion_present: checked_wheel.contained_completion_present,
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unprivileged_artifact_binding_refuses_before_any_files() {
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
            project_cloned_candidate_config_ineligible(&pins),
            Err(CandidateConfigLiveError::RootRequired)
        ));
    }
}
