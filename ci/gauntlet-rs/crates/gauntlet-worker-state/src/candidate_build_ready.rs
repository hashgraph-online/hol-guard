//! Read-only candidate readiness probe before the host spends its one-use
//! build pin. The actual runner repeats every check under both worker locks.

use crate::builder_candidate_preflight::{verify_candidate_runtime, CandidateRuntimePins};
use crate::builder_candidate_process::container_absent;
use crate::builder_candidate_source::{open_fixed_build_slot, verify_captured_source};
use crate::builder_context::inspect_fixed_builder_context;
use crate::builder_image::{fixed_builder_image_plan, inspect_fixed_builder_base_images};
use crate::builder_image_build::{free_bytes, inspect_result};
use crate::builder_image_context::{
    python_worker_lock, verify_existing_context, verify_python_lock, RUST_STATE,
};
use crate::builder_policy::{profile_is_loaded, read_policy};
use crate::{fixed_builder_run_plan, hex, RunReservationJournal};
use rustix::fs::{statat, AtFlags};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::fmt;
use std::path::Path;

const MIN_START_FREE: u64 = 12 * 1024 * 1024 * 1024;
const EMPTY_NAMES: [&str; 5] = [
    "candidate-run.stdout.log",
    "candidate-run.stderr.log",
    "candidate-run.host-anchor.json",
    "candidate-run.result.json",
    "export",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateBuildReadyError {
    RootRequired,
    InvalidPins,
    LeaseUnavailable,
    ControllerMismatch,
    BaseMismatch,
    ContextMismatch,
    ImageMismatch,
    PolicyMismatch,
    RuntimeMismatch,
    SourceMismatch,
    ExistingOutput,
    ContainerUnknown,
    LowDisk,
}

impl fmt::Display for CandidateBuildReadyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RootRequired => "Linux ARM Root required for candidate readiness probe",
            Self::InvalidPins => "complete fixed candidate readiness pins required",
            Self::LeaseUnavailable => "Rust or Python worker lease unavailable",
            Self::ControllerMismatch => "Root controller tree differs from outside pin",
            Self::BaseMismatch => "local ARM builder base IDs differ",
            Self::ContextMismatch => "one-use builder image context differs",
            Self::ImageMismatch => "built source-bound image differs from outside ID",
            Self::PolicyMismatch => "one-use job AppArmor policy missing or loaded",
            Self::RuntimeMismatch => "Podman, slirp, AppArmor or seccomp helper differs",
            Self::SourceMismatch => "captured candidate source differs from outside digest",
            Self::ExistingOutput => "candidate output or host anchor already exists",
            Self::ContainerUnknown => "candidate container absence unproven",
            Self::LowDisk => "candidate lacks 12 GiB starting disk reserve",
        })
    }
}

impl std::error::Error for CandidateBuildReadyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateBuildReadyProof {
    job_id: String,
    source_sha: String,
    source_archive_sha256: String,
    tag: String,
    image_id: String,
    policy_sha256: String,
    free_disk_bytes: u64,
}

impl CandidateBuildReadyProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-candidate-build-ready-shadow.v2",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "source_archive_sha256":self.source_archive_sha256,
            "tag":self.tag,
            "image_id":self.image_id,
            "policy_sha256":self.policy_sha256,
            "free_disk_bytes":self.free_disk_bytes,
            "ready_at_probe":true,
            "host_pin_recorded":false,
            "candidate_started":false,
            "artifact_admitted":false,
            "execution_eligible":false,
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn probe_fixed_candidate_build_ready_ineligible(
    controller_root: &Path,
    tree_digest: &str,
    job_id: &str,
    uv_id: &str,
    rust_id: &str,
    image_id: &str,
    source_sha: &str,
    archive_sha256: &str,
    version: &str,
    tag: &str,
    runtime: &CandidateRuntimePins,
    policy_sha256: &str,
) -> Result<CandidateBuildReadyProof, CandidateBuildReadyError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateBuildReadyError::RootRequired);
    }
    if !hex(tree_digest, 64)
        || !hex(job_id, 16)
        || !hex(uv_id, 64)
        || !hex(rust_id, 64)
        || !hex(source_sha, 40)
        || !hex(archive_sha256, 64)
        || !hex(policy_sha256, 64)
        || !(tag == format!("local-{source_sha}")
            || matches!(tag, "v3.48.0" | "v3.49.0") && &tag[1..] == version)
        || image_id
            .strip_prefix("sha256:")
            .is_none_or(|digest| !hex(digest, 64))
    {
        return Err(CandidateBuildReadyError::InvalidPins);
    }
    let request = json!({
        "image_id":image_id,
        "job_id":job_id,
        "source_sha":source_sha,
        "source_archive_sha256":archive_sha256,
        "tag":tag,
        "memory_gib":12,
        "local_version":if tag.starts_with("local-") { Some(version) } else { None },
        "retest_build_job_id":null,
    });
    fixed_builder_run_plan(&request).map_err(|_| CandidateBuildReadyError::InvalidPins)?;
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| CandidateBuildReadyError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| CandidateBuildReadyError::LeaseUnavailable)?;
    let python_lock =
        python_worker_lock().map_err(|_| CandidateBuildReadyError::LeaseUnavailable)?;
    let context = inspect_fixed_builder_context(controller_root, tree_digest, job_id)
        .map_err(|_| CandidateBuildReadyError::ControllerMismatch)?;
    if context.policy_sha256() != policy_sha256 {
        return Err(CandidateBuildReadyError::PolicyMismatch);
    }
    let image_plan = fixed_builder_image_plan(&context, job_id, uv_id, rust_id)
        .map_err(|_| CandidateBuildReadyError::ContextMismatch)?;
    inspect_fixed_builder_base_images(&image_plan)
        .map_err(|_| CandidateBuildReadyError::BaseMismatch)?;
    verify_existing_context(&image_plan).map_err(|_| CandidateBuildReadyError::ContextMismatch)?;
    if inspect_result(&image_plan).map_err(|_| CandidateBuildReadyError::ImageMismatch)? != image_id
    {
        return Err(CandidateBuildReadyError::ImageMismatch);
    }
    read_policy(job_id, policy_sha256).map_err(|_| CandidateBuildReadyError::PolicyMismatch)?;
    if profile_is_loaded(context.profile_name())
        .map_err(|_| CandidateBuildReadyError::PolicyMismatch)?
    {
        return Err(CandidateBuildReadyError::PolicyMismatch);
    }
    verify_candidate_runtime(runtime).map_err(|_| CandidateBuildReadyError::RuntimeMismatch)?;
    let job =
        open_fixed_build_slot(job_id).map_err(|_| CandidateBuildReadyError::SourceMismatch)?;
    verify_captured_source(&job, archive_sha256)
        .map_err(|_| CandidateBuildReadyError::SourceMismatch)?;
    for name in EMPTY_NAMES {
        match statat(&job, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => {}
            _ => return Err(CandidateBuildReadyError::ExistingOutput),
        }
    }
    if !container_absent(job_id).map_err(|_| CandidateBuildReadyError::ContainerUnknown)? {
        return Err(CandidateBuildReadyError::ContainerUnknown);
    }
    let free_disk_bytes = free_bytes().map_err(|_| CandidateBuildReadyError::LowDisk)?;
    if free_disk_bytes < MIN_START_FREE {
        return Err(CandidateBuildReadyError::LowDisk);
    }
    lease
        .verify(&journal.root)
        .map_err(|_| CandidateBuildReadyError::LeaseUnavailable)?;
    verify_python_lock(&python_lock).map_err(|_| CandidateBuildReadyError::LeaseUnavailable)?;
    Ok(CandidateBuildReadyProof {
        job_id: job_id.to_owned(),
        source_sha: source_sha.to_owned(),
        source_archive_sha256: archive_sha256.to_owned(),
        tag: tag.to_owned(),
        image_id: image_id.to_owned(),
        policy_sha256: policy_sha256.to_owned(),
        free_disk_bytes,
    })
}
