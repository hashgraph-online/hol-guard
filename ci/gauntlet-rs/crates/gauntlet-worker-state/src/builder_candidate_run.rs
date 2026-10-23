//! One-use Rust ownership of a local candidate Podman compile attempt. The
//! result is diagnostic until archive custody and product contracts are
//! independently verified; even exit zero cannot admit an artifact.

use crate::builder_candidate_preflight::{verify_candidate_runtime, CandidateRuntimePins};
use crate::builder_candidate_process::{
    container_absent, run_candidate_process, CandidateProcessError,
};
use crate::builder_candidate_receipt::write_candidate_receipt;
use crate::builder_candidate_source::{
    open_fixed_build_slot, prepare_export, unadmitted_export_identity, verify_captured_source,
};
use crate::builder_context::inspect_fixed_builder_context;
use crate::builder_image::{fixed_builder_image_plan, inspect_fixed_builder_base_images};
use crate::builder_image_build::{free_bytes, inspect_result};
use crate::builder_image_context::{
    python_worker_lock, verify_existing_context, verify_python_lock, RUST_STATE,
};
use crate::builder_policy::{profile_is_loaded, read_policy, run_parser};
use crate::candidate_host_anchor::{
    verify_running_binary, write_host_anchor, HostCandidateRunAnchor,
};
use crate::{fixed_builder_run_plan, hex, RunReservationJournal};
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::fmt;
use std::path::Path;

const MIN_START_FREE: u64 = 12 * 1024 * 1024 * 1024;
const BUILDS: &str = "/var/lib/hol-gauntlet/builds";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateRunError {
    RootRequired,
    InvalidPins,
    LeaseUnavailable,
    ContextMismatch,
    BaseMismatch,
    ImageMismatch,
    PolicyMismatch,
    ProfileAlreadyLoaded,
    RuntimeMismatch,
    SourceMismatch,
    ExportUnavailable,
    LowDisk,
    Process(CandidateProcessError),
    CleanupUncertain,
    ReceiptUncertain,
    HostAnchorMismatch,
    HostAnchorUncertain,
}

impl fmt::Display for CandidateRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootRequired => f.write_str("Linux ARM Root required for candidate run"),
            Self::InvalidPins => {
                f.write_str("fixed local candidate, image and helper pins required")
            }
            Self::LeaseUnavailable => f.write_str("Rust or Python worker lease unavailable"),
            Self::ContextMismatch => f.write_str("builder controller or one-use context differs"),
            Self::BaseMismatch => f.write_str("local builder base IDs changed"),
            Self::ImageMismatch => f.write_str("builder image differs from outside ID"),
            Self::PolicyMismatch => f.write_str("job AppArmor policy differs or failed to load"),
            Self::ProfileAlreadyLoaded => f.write_str("job AppArmor profile was already loaded"),
            Self::RuntimeMismatch => f.write_str("Podman/slirp/AppArmor/seccomp runtime differs"),
            Self::SourceMismatch => {
                f.write_str("captured source archive differs from outside digest")
            }
            Self::ExportUnavailable => f.write_str("one-use candidate export is unavailable"),
            Self::LowDisk => f.write_str("candidate run lacks the fixed disk reserve"),
            Self::Process(error) => write!(f, "candidate process: {error}"),
            Self::CleanupUncertain => {
                f.write_str("candidate container, cgroup or profile cleanup uncertain")
            }
            Self::ReceiptUncertain => {
                f.write_str("one-use candidate result write or custody uncertain")
            }
            Self::HostAnchorMismatch => f.write_str("host build pin or running binary differs"),
            Self::HostAnchorUncertain => f.write_str("one-use guest host-anchor write uncertain"),
        }
    }
}

impl std::error::Error for CandidateRunError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRunProof {
    job_id: String,
    source_sha: String,
    source_archive_sha256: String,
    source_bytes: u64,
    version: String,
    image_id: String,
    policy_sha256: String,
    runtime: CandidateRuntimePins,
    client_pid: u32,
    client_start_ticks: u64,
    exit_code: i32,
    stdout_sha256: String,
    stderr_sha256: String,
    unadmitted_export_bytes: Option<u64>,
    unadmitted_export_sha256: Option<String>,
    result_sha256: String,
    host_anchor: Option<(HostCandidateRunAnchor, String)>,
}

impl CandidateRunProof {
    fn result_body(&self) -> Value {
        let mut body = json!({
            "schema":"hol-gauntlet-candidate-build-result.v1",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "source_archive_sha256":self.source_archive_sha256,
            "source_bytes":self.source_bytes,
            "local_version":self.version,
            "image_id":self.image_id,
            "policy_sha256":self.policy_sha256,
            "runtime_pins":self.runtime.to_json(),
            "client_pid":self.client_pid,
            "client_start_ticks":self.client_start_ticks,
            "status":if self.exit_code == 0 {"exited-zero"} else {"build-failed"},
            "exit_code":self.exit_code,
            "stdout_sha256":self.stdout_sha256,
            "stderr_sha256":self.stderr_sha256,
            "unadmitted_export_bytes":self.unadmitted_export_bytes,
            "unadmitted_export_sha256":self.unadmitted_export_sha256,
            "container_absent":true,
            "candidate_cgroup_drained":true,
            "build_profile_removed":true,
            "artifact_admitted":false,
            "execution_eligible":false,
        });
        if let Some((anchor, anchor_file_sha256)) = &self.host_anchor {
            body["schema"] = json!(if anchor.tag.is_some() {
                "hol-gauntlet-candidate-build-result.v3"
            } else {
                "hol-gauntlet-candidate-build-result.v2"
            });
            if let Some(tag) = &anchor.tag {
                body["tag"] = json!(tag);
                if !tag.starts_with("local-") {
                    body["local_version"] = Value::Null;
                }
            }
            body["host_pin_sha256"] = json!(anchor.host_pin_sha256);
            body["host_nonce_hex"] = json!(anchor.host_nonce_hex);
            body["host_anchor_sha256"] = json!(anchor_file_sha256);
            body["runner_binary_sha256"] = json!(anchor.runner_binary_sha256);
            body["result_reader_binary_sha256"] = json!(anchor.result_reader_binary_sha256);
        }
        body
    }

    pub fn to_json(&self) -> Value {
        let mut body = self.result_body();
        body["result_sha256"] = json!(self.result_sha256);
        body
    }
}

/// Own one actual local candidate compile attempt. The exact container argv
/// comes from the Python-parity fixed plan; no caller may supply a command,
/// path, image tag, profile or resource selector. This diagnostic cannot
/// publish a benchmark pass or stage an artifact.
#[allow(clippy::too_many_arguments)]
pub fn run_fixed_local_candidate_ineligible(
    controller_root: &Path,
    tree_digest: &str,
    job_id: &str,
    uv_id: &str,
    rust_id: &str,
    image_id: &str,
    source_sha: &str,
    archive_sha256: &str,
    version: &str,
    runtime: CandidateRuntimePins,
) -> Result<CandidateRunProof, CandidateRunError> {
    run_fixed_local_candidate_inner(
        controller_root,
        tree_digest,
        job_id,
        uv_id,
        rust_id,
        image_id,
        source_sha,
        archive_sha256,
        version,
        &format!("local-{source_sha}"),
        runtime,
        None,
    )
}

/// The host-bound form requires its independently pinned executable to be the
/// actual running Root binary. It consumes a one-use guest anchor before the
/// candidate Podman run, then binds that anchor to a v2 terminal result.
#[allow(clippy::too_many_arguments)]
pub fn run_fixed_local_candidate_hostbound_ineligible(
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
    runtime: CandidateRuntimePins,
    anchor: HostCandidateRunAnchor,
) -> Result<CandidateRunProof, CandidateRunError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateRunError::RootRequired);
    }
    verify_running_binary(&anchor.runner_binary_sha256)
        .map_err(|_| CandidateRunError::HostAnchorMismatch)?;
    run_fixed_local_candidate_inner(
        controller_root,
        tree_digest,
        job_id,
        uv_id,
        rust_id,
        image_id,
        source_sha,
        archive_sha256,
        version,
        tag,
        runtime,
        Some(anchor),
    )
}

#[allow(clippy::too_many_arguments)]
fn run_fixed_local_candidate_inner(
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
    runtime: CandidateRuntimePins,
    host_anchor: Option<HostCandidateRunAnchor>,
) -> Result<CandidateRunProof, CandidateRunError> {
    if geteuid().as_raw() != 0 {
        return Err(CandidateRunError::RootRequired);
    }
    if !hex(tree_digest, 64)
        || !hex(job_id, 16)
        || !hex(uv_id, 64)
        || !hex(rust_id, 64)
        || !hex(source_sha, 40)
        || !hex(archive_sha256, 64)
        || !(tag == format!("local-{source_sha}")
            || matches!(tag, "v3.48.0" | "v3.49.0") && &tag[1..] == version)
        || image_id
            .strip_prefix("sha256:")
            .is_none_or(|digest| !hex(digest, 64))
    {
        return Err(CandidateRunError::InvalidPins);
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
    let plan = fixed_builder_run_plan(&request).map_err(|_| CandidateRunError::InvalidPins)?;
    let journal = RunReservationJournal::open_root_owned(Path::new(RUST_STATE))
        .map_err(|_| CandidateRunError::LeaseUnavailable)?;
    let lease = journal
        .acquire_active_lease()
        .map_err(|_| CandidateRunError::LeaseUnavailable)?;
    let python_lock = python_worker_lock().map_err(|_| CandidateRunError::LeaseUnavailable)?;
    let context = inspect_fixed_builder_context(controller_root, tree_digest, job_id)
        .map_err(|_| CandidateRunError::ContextMismatch)?;
    let image_plan = fixed_builder_image_plan(&context, job_id, uv_id, rust_id)
        .map_err(|_| CandidateRunError::ContextMismatch)?;
    inspect_fixed_builder_base_images(&image_plan).map_err(|_| CandidateRunError::BaseMismatch)?;
    verify_existing_context(&image_plan).map_err(|_| CandidateRunError::ContextMismatch)?;
    if inspect_result(&image_plan).map_err(|_| CandidateRunError::ImageMismatch)? != image_id {
        return Err(CandidateRunError::ImageMismatch);
    }
    read_policy(job_id, context.policy_sha256()).map_err(|_| CandidateRunError::PolicyMismatch)?;
    if host_anchor.as_ref().is_some_and(|anchor| {
        anchor.policy_sha256 != context.policy_sha256()
            || anchor.tag.as_deref().is_some_and(|pinned| pinned != tag)
    }) {
        return Err(CandidateRunError::HostAnchorMismatch);
    }
    if profile_is_loaded(context.profile_name()).map_err(|_| CandidateRunError::PolicyMismatch)? {
        return Err(CandidateRunError::ProfileAlreadyLoaded);
    }
    verify_candidate_runtime(&runtime).map_err(|_| CandidateRunError::RuntimeMismatch)?;
    let job = open_fixed_build_slot(job_id).map_err(|_| CandidateRunError::SourceMismatch)?;
    let source_bytes = verify_captured_source(&job, archive_sha256)
        .map_err(|_| CandidateRunError::SourceMismatch)?;
    if !container_absent(job_id).map_err(CandidateRunError::Process)? {
        return Err(CandidateRunError::Process(
            CandidateProcessError::ExistingContainer,
        ));
    }
    if free_bytes().map_err(|_| CandidateRunError::LowDisk)? < MIN_START_FREE {
        return Err(CandidateRunError::LowDisk);
    }
    let host_anchor = if let Some(anchor) = host_anchor {
        let body = anchor.body(
            job_id,
            source_sha,
            archive_sha256,
            version,
            tree_digest,
            image_id,
            &runtime,
        );
        let digest =
            write_host_anchor(&job, &body).map_err(|_| CandidateRunError::HostAnchorUncertain)?;
        Some((anchor, digest))
    } else {
        None
    };
    prepare_export(&job).map_err(|_| CandidateRunError::ExportUnavailable)?;
    let policy_path = format!("{BUILDS}/{job_id}/Builder.apparmor");
    let load = run_parser("--replace", &policy_path);
    if load.is_err() {
        if profile_is_loaded(context.profile_name()) == Ok(true) {
            let _ = run_parser("--remove", &policy_path);
        }
        if profile_is_loaded(context.profile_name()) != Ok(false) {
            return Err(CandidateRunError::CleanupUncertain);
        }
        return Err(CandidateRunError::PolicyMismatch);
    }
    if profile_is_loaded(context.profile_name()) != Ok(true) {
        let _ = run_parser("--remove", &policy_path);
        return Err(CandidateRunError::CleanupUncertain);
    }
    let still_owned = || {
        lease
            .verify(&journal.root)
            .map_err(|_| CandidateProcessError::LeaseUnavailable)?;
        verify_python_lock(&python_lock).map_err(|_| CandidateProcessError::LeaseUnavailable)
    };
    let process = run_candidate_process(&plan, &job, &still_owned);
    let absent = container_absent(job_id);
    if absent != Ok(true) {
        // Keep the exact profile for inspection if the container may survive.
        return Err(CandidateRunError::CleanupUncertain);
    }
    let removed = run_parser("--remove", &policy_path);
    if removed.is_err() || profile_is_loaded(context.profile_name()) != Ok(false) {
        return Err(CandidateRunError::CleanupUncertain);
    }
    let process = process.map_err(CandidateRunError::Process)?;
    still_owned().map_err(|_| CandidateRunError::LeaseUnavailable)?;
    verify_captured_source(&job, archive_sha256).map_err(|_| CandidateRunError::SourceMismatch)?;
    read_policy(job_id, context.policy_sha256()).map_err(|_| CandidateRunError::PolicyMismatch)?;
    inspect_fixed_builder_context(controller_root, tree_digest, job_id)
        .map_err(|_| CandidateRunError::ContextMismatch)?;
    inspect_fixed_builder_base_images(&image_plan).map_err(|_| CandidateRunError::BaseMismatch)?;
    verify_candidate_runtime(&runtime).map_err(|_| CandidateRunError::RuntimeMismatch)?;
    if inspect_result(&image_plan).map_err(|_| CandidateRunError::ImageMismatch)? != image_id {
        return Err(CandidateRunError::ImageMismatch);
    }
    let unadmitted_export =
        unadmitted_export_identity(&job).map_err(|_| CandidateRunError::ExportUnavailable)?;
    if free_bytes().map_err(|_| CandidateRunError::LowDisk)? < 8 * 1024 * 1024 * 1024 {
        return Err(CandidateRunError::LowDisk);
    }
    let mut proof = CandidateRunProof {
        job_id: job_id.to_owned(),
        source_sha: source_sha.to_owned(),
        source_archive_sha256: archive_sha256.to_owned(),
        source_bytes,
        version: version.to_owned(),
        image_id: image_id.to_owned(),
        policy_sha256: context.policy_sha256().to_owned(),
        runtime,
        client_pid: process.client_pid,
        client_start_ticks: process.client_start_ticks,
        exit_code: process.exit_code,
        stdout_sha256: process.stdout_sha256,
        stderr_sha256: process.stderr_sha256,
        unadmitted_export_bytes: unadmitted_export.as_ref().map(|(bytes, _)| *bytes),
        unadmitted_export_sha256: unadmitted_export.map(|(_, digest)| digest),
        result_sha256: String::new(),
        host_anchor,
    };
    still_owned().map_err(|_| CandidateRunError::LeaseUnavailable)?;
    proof.result_sha256 = write_candidate_receipt(&job, &proof.result_body())
        .map_err(|_| CandidateRunError::ReceiptUncertain)?;
    still_owned().map_err(|_| CandidateRunError::LeaseUnavailable)?;
    Ok(proof)
}
