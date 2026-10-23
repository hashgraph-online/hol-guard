//! Inert durable run reservation for a future, separately reviewed Linux worker.
//! A successful reservation consumes a job ID but never launches candidate code.

use gauntlet_contracts::{canonicalize, is_git_sha, WorkerAction, WorkerRequest};
use rustix::fs::{fstat, fsync, open, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

const MARKER_SCHEMA: &str = "hol-gauntlet-worker-started.v1";
const KEYED_MARKER_SCHEMA: &str = "hol-gauntlet-worker-started.v2";
const MAX_MARKER_BYTES: u64 = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedMarker {
    pub source_sha: String,
    pub job_id: String,
    pub deployment_digest: String,
    pub worker_generation: String,
    pub controller_public_key_hex: Option<String>,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReservationError {
    InvalidPins,
    RootRequired,
    UnsafeRoot,
    WrongRequest,
    AlreadyStarted,
    LeaseBusy,
    InvalidMarker,
    InvalidDeployment,
    CleanupUncertain,
    Io(String),
}

impl fmt::Display for ReservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPins => f.write_str("invalid outside worker/deployment pins"),
            Self::RootRequired => f.write_str("Linux Root required for Rust job slice observation"),
            Self::UnsafeRoot => f.write_str("Linux Root-owned private worker directory required"),
            Self::WrongRequest => {
                f.write_str("run request differs from outside source/deployment pins")
            }
            Self::AlreadyStarted => f.write_str("job ID was already reserved for execution"),
            Self::LeaseBusy => f.write_str("another worker holds the active lease"),
            Self::InvalidMarker => {
                f.write_str("started marker is malformed or differs from outside pins")
            }
            Self::InvalidDeployment => {
                f.write_str("deployment declaration differs from its outside pins")
            }
            Self::CleanupUncertain => {
                f.write_str("Rust job product-cell slice cleanup is not independently absent")
            }
            Self::Io(message) => write!(f, "worker reservation I/O error: {message}"),
        }
    }
}

impl std::error::Error for ReservationError {}

pub struct RunReservationJournal {
    pub(crate) root: OwnedFd,
    root_owned: bool,
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod builder_candidate_preflight;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod builder_candidate_process;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod builder_candidate_receipt;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod builder_candidate_run;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod builder_candidate_source;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod builder_cgroup;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod builder_context;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod builder_image;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod builder_image_build;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod builder_image_context;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod builder_policy;
mod builder_run_plan;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod builder_source_capture;
mod candidate_archive;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_build_ready;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_capture;
mod candidate_config_projection;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_config_projection_live;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_config_shadow_write;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_conformance_readiness;
mod candidate_dependencies;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_dependencies_live;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_host_anchor;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_prefix_clone;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_result_read;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_shadow_assets;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_staging_config_revision;
mod candidate_staging_plan;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_staging_reconcile;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_staging_run;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_staging_tap;
mod candidate_wheel;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod candidate_wheel_stage;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod contained_probe;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod controller_exec;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod controller_install;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod controller_key;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod controller_run;
#[cfg(target_os = "linux")]
mod deadline;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod private_cell_shadow_artifacts;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use contained_probe::{
    run_fixed_cgroup_probe, run_fixed_contained_interpreter_probe, run_fixed_job_cgroup_probe,
    CgroupProbeError, CgroupProbeProof, ContainedInterpreterProbeProof, JobCgroupProbeProof,
    OwnedJobCgroup, OwnedSdkTapCgroup,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use controller_exec::{
    exchange_prelaunch_pipe, read_run_request_pipe, run_fixed_root_controller_exec_probe,
    ControllerExecError, RootControllerProbeProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use controller_install::{
    install_fixed_controller, ControllerInstallError, ControllerInstallProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use controller_key::{
    observe_controller_key_pin_root_owned, ControllerKeyError, ControllerKeyObservation,
    ControllerKeyOutsidePins,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use controller_run::run_fixed_deterministic_controller_pipe_ineligible;
#[cfg(target_os = "linux")]
mod deployment;
#[cfg(target_os = "linux")]
mod interpreter_exec;
#[cfg(any(target_os = "linux", test))]
mod job_slice_guard;
mod launch_plan;
#[cfg(target_os = "linux")]
pub use interpreter_exec::{
    probe_verified_interpreter_exec, InterpreterExecError, InterpreterExecProof,
};
#[cfg(target_os = "linux")]
pub use job_slice_guard::{
    require_rust_job_slice_absent, stop_rust_job_slice, JobSliceStopObservation,
};
mod lease;
#[cfg(target_os = "linux")]
mod linux_cgroup;
#[cfg(any(target_os = "linux", test))]
mod linux_process;
#[cfg(target_os = "linux")]
mod prelaunch;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod process_reap;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod product_cell_units;
mod projection;
#[cfg(target_os = "linux")]
mod running;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod sdk_wire_child;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod sdk_wire_fd_handoff;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod sdk_wire_journal;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod sdk_wire_listener;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod sdk_wire_native;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod sdk_wire_peer;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod sdk_wire_pidns;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod sdk_wire_pipe;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod sdk_wire_spawn;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod sdk_wire_tap;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub mod staging_contained_effect;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub mod staging_effect_events;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub mod staging_effect_file;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub mod staging_effect_journal;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod staging_file_handle;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod staging_kernel_observer;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod staging_machine_observer;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub mod staging_product_effect;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod staging_product_mounts;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod staging_product_observer;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod staging_product_process;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod staging_writer_capture;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod staging_writer_process;
mod terminal;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use builder_candidate_preflight::{CandidatePreflightError, CandidateRuntimePins};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use builder_candidate_process::CandidateProcessError;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use builder_candidate_run::{
    run_fixed_local_candidate_hostbound_ineligible, run_fixed_local_candidate_ineligible,
    CandidateRunError, CandidateRunProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use builder_context::{
    inspect_fixed_builder_context, BuilderContextError, BuilderContextProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use builder_image::{
    fixed_builder_image_plan, inspect_fixed_builder_base_images, BuilderImageError,
    BuilderImagePlan,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use builder_image_build::{
    build_fixed_builder_image_ineligible, BuilderImageBuildError, BuilderImageBuildProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use builder_image_context::{
    materialize_fixed_builder_image_context, BuilderImageContextError, BuilderImageContextProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use builder_policy::{
    prove_fixed_builder_policy_ineligible, BuilderPolicyError, BuilderPolicyProof,
};
pub use builder_run_plan::{fixed_builder_run_plan, BuilderRunError, BuilderRunPlan};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use builder_source_capture::{
    capture_fixed_guest_source_archive, BuilderSourceCaptureError, BuilderSourceCaptureProof,
};
pub use candidate_archive::{
    inspect_candidate_archive, CandidateArchiveDeclaration, CandidateArchiveError,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_build_ready::{
    probe_fixed_candidate_build_ready_ineligible, CandidateBuildReadyError,
    CandidateBuildReadyProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_capture::{
    capture_local_candidate_archive_ineligible, verify_captured_candidate_wheel_ineligible,
    CandidateCaptureError, CandidateCaptureProof, CandidateWheelLiveProof,
};
pub use candidate_config_projection::{
    project_candidate_config_ineligible, project_shadow_candidate_config_ineligible,
    project_shadow_candidate_config_with_private_cell_ineligible, CandidateConfigProjection,
    CandidateConfigProjectionError, CandidateConfigProjectionPins,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_config_projection_live::{
    project_cloned_candidate_config_ineligible, project_installed_candidate_config_ineligible,
    CandidateConfigArtifactPins, CandidateConfigArtifactProof, CandidateConfigLiveError,
    CandidateConfigLiveProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_config_shadow_write::{
    write_shadow_candidate_config_ineligible,
    write_shadow_candidate_config_with_private_cell_ineligible, CandidateConfigShadowWriteError,
    CandidateConfigShadowWriteProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_conformance_readiness::{
    inspect_candidate_conformance_readiness_ineligible,
    inspect_candidate_staging_readiness_ineligible, CandidateConformanceReadinessError,
    CandidateConformanceReadinessPins, CandidateConformanceReadinessProof,
};
pub use candidate_dependencies::{
    check_candidate_dependencies, CandidateDependencyError, CandidateDependencyProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_dependencies_live::{
    verify_cloned_candidate_dependencies_ineligible, CandidateDependencyLiveError,
    CandidateDependencyLivePins, CandidateDependencyLiveProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_host_anchor::{
    verify_running_binary, CandidateBinaryError, HostCandidateRunAnchor,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_prefix_clone::{
    clone_captured_candidate_prefix_ineligible, CandidatePrefixCloneError,
    CandidatePrefixClonePins, CandidatePrefixCloneProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_result_read::{
    read_fixed_candidate_result_ineligible, read_fixed_hostbound_candidate_result_ineligible,
    CandidateResultReadError, CandidateResultReadProof, HostBoundCandidateResultPins,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_shadow_assets::{
    assemble_candidate_shadow_assets_ineligible, CandidateShadowAssetsError,
    CandidateShadowAssetsPins, CandidateShadowAssetsProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_staging_config_revision::{
    revise_staging_config_ineligible, StagingConfigRevisionPins,
};
pub use candidate_staging_plan::{
    fixed_staging_control_plan, fixed_staging_control_plan_sdk_tap_v2, FixedStagingControlPlan,
    StagingControlPins, StagingRole,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_staging_reconcile::{
    read_restarted_staging_tap_ineligible, StagingTapReadbackPins,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_staging_run::{
    run_fixed_candidate_staging_control_ineligible,
    run_fixed_candidate_staging_control_sdk_tap_pidns_ineligible,
    run_fixed_candidate_staging_control_sdk_tap_root_relay_ineligible,
    run_fixed_candidate_staging_control_sdk_tap_v2_ineligible, CandidateStagingRunPins,
    CandidateStagingRunProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_staging_tap::CandidateSdkTapPins;
pub use candidate_wheel::{inspect_candidate_wheel, CandidateWheelError, CandidateWheelProof};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use candidate_wheel_stage::{
    materialize_captured_candidate_wheel_ineligible, CandidateWheelStageError,
    CandidateWheelStageProof,
};
#[cfg(target_os = "linux")]
pub use deadline::{BoottimeDeadline, DeadlineError, MAX_ACTIVE_SECONDS};
#[cfg(target_os = "linux")]
pub use deployment::{
    read_fixed_deployment, read_fixed_interpreter, read_fixed_interpreter_held,
    read_fixed_interpreter_path_held, DeploymentDeclaration, HeldInterpreter,
    InterpreterDeclaration,
};
pub use launch_plan::{
    fixed_launch_plan, fixed_rust_job_launch_plan, FixedLaunchPlan, RunLaunchPins,
    RustJobLaunchPlan,
};
pub use lease::ActiveLease;
#[cfg(target_os = "linux")]
pub use linux_cgroup::{
    observe_cgroup_drain, observe_process_resources, CgroupDrainState, CgroupResources,
    ProcessResourceObservation,
};
#[cfg(target_os = "linux")]
pub use linux_process::{observe_process, ProcessObservation, ProcessObservationError};
#[cfg(target_os = "linux")]
pub use prelaunch::{
    prepare_fixed_prelaunch, verify_fixed_prelaunch, PrelaunchError, PrelaunchPins, PrelaunchProof,
    PreparedLaunch,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use private_cell_shadow_artifacts::{
    prepare_private_cell_shadow_artifacts_ineligible, PrivateCellShadowError,
    PrivateCellShadowPins, PrivateCellShadowProof,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use product_cell_units::{
    observe_product_cell_units, require_no_product_cell_units, ProductCellScanError,
};
#[cfg(target_os = "linux")]
pub use running::RunningMarker;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use sdk_wire_child::{
    connect_native_once_pidns_ineligible, run_sdk_tap_child_once_ineligible,
    run_sdk_tap_child_once_pidns_ineligible, SdkTapChildPins,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use sdk_wire_journal::{
    read_sdk_tap_journal_ineligible, retain_sdk_tap_journal_ineligible, SdkTapJournalReceipt,
    SdkTapRetainedSession, SdkTapWireOwner,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use sdk_wire_listener::{bind_sdk_tap_listeners_ineligible, SdkTapListeners};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use sdk_wire_native::{open_fixed_native_frontdoor_ineligible, HeldNativeFrontdoor};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use sdk_wire_peer::{
    authenticate_native_frontdoor_peer_ineligible, authenticate_sdk_relay_peer_ineligible,
    bind_sdk_relay_to_ancestor_ineligible, observe_sdk_relay_peer_in_cgroup_ineligible,
    HeldSdkWirePeer, SdkWireAncestryObservation, SdkWirePeerObservation, SdkWirePeerPin,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use sdk_wire_pidns::{
    probe_owned_tap_pid_namespace_ineligible, run_pinned_sdk_tap_child_in_pidns_ineligible,
    run_pinned_sdk_tap_root_relay_in_pidns_ineligible,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use sdk_wire_pipe::{read_sdk_tap_frame_pipe_ineligible, SdkTapFramePipeWriter};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use sdk_wire_spawn::{
    open_pinned_sdk_tap_executable_ineligible, run_pinned_sdk_tap_child_in_group_ineligible,
    run_pinned_sdk_tap_child_ineligible, HeldSdkTapExecutable,
};
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use sdk_wire_tap::{
    relay_bounded_sdk_mcp_pair_ineligible, relay_bounded_sdk_mcp_pair_with_frame_sink_ineligible,
    SdkWireEvent, SdkWireFrameObserver, SdkWireObservation,
};
pub use terminal::{ProcessIdentity, TerminalOutcome, TerminalReceipt};

pub(crate) fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn io(error: impl fmt::Display) -> ReservationError {
    ReservationError::Io(error.to_string())
}

pub(crate) fn marker_name(job_id: &str) -> Result<String, ReservationError> {
    if !hex(job_id, 16) {
        return Err(ReservationError::InvalidPins);
    }
    Ok(format!("{job_id}.started.json"))
}

pub(crate) fn read_bounded_regular(
    root: &OwnedFd,
    name: &str,
    limit: u64,
) -> Result<Option<Vec<u8>>, ReservationError> {
    let descriptor = match openat(
        root,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Ok(None),
        Err(error) => return Err(io(error)),
    };
    let mut file = File::from(descriptor);
    let before = file.metadata().map_err(io)?;
    if !before.is_file() || before.nlink() != 1 || before.len() > limit {
        return Err(ReservationError::InvalidMarker);
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > limit {
        return Err(ReservationError::InvalidMarker);
    }
    let after = file.metadata().map_err(io)?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.nlink() != after.nlink()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err(ReservationError::InvalidMarker);
    }
    Ok(Some(bytes))
}

fn trusted_directory(stat: &Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::Directory
        && stat.st_uid == 0
        && stat.st_mode & 0o022 == 0
}

fn open_canonical_directory(path: &Path, require_root: bool) -> Result<OwnedFd, ReservationError> {
    open_canonical_directory_with_mode(path, require_root, require_root)
}

#[cfg(target_os = "linux")]
fn open_root_owned_public_directory(path: &Path) -> Result<OwnedFd, ReservationError> {
    open_canonical_directory_with_mode(path, true, false)
}

fn open_canonical_directory_with_mode(
    path: &Path,
    require_root: bool,
    private_final: bool,
) -> Result<OwnedFd, ReservationError> {
    let literal = path.to_str().ok_or(ReservationError::InvalidPins)?;
    if !path.is_absolute()
        || literal != "/"
            && !literal.strip_prefix('/').is_some_and(|relative| {
                !relative.is_empty()
                    && relative
                        .split('/')
                        .all(|part| !part.is_empty() && part != "." && part != "..")
            })
    {
        return Err(ReservationError::InvalidPins);
    }
    let mut root = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io)?;
    if require_root {
        let stat = fstat(&root).map_err(io)?;
        if !trusted_directory(&stat) {
            return Err(ReservationError::UnsafeRoot);
        }
    }
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                root = openat(
                    &root,
                    name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(io)?;
                if require_root {
                    let stat = fstat(&root).map_err(io)?;
                    if !trusted_directory(&stat) {
                        return Err(ReservationError::UnsafeRoot);
                    }
                }
            }
            _ => return Err(ReservationError::InvalidPins),
        }
    }
    if private_final {
        let stat = fstat(&root).map_err(io)?;
        if path == Path::new("/") || stat.st_mode & 0o077 != 0 {
            return Err(ReservationError::UnsafeRoot);
        }
    }
    Ok(root)
}

impl RunReservationJournal {
    /// Inert tests may use an ordinary directory. A live Linux worker must use
    /// `open_root_owned` before any durable write.
    pub fn open(path: &Path) -> Result<Self, ReservationError> {
        Ok(Self {
            root: open_canonical_directory(path, false)?,
            root_owned: false,
        })
    }

    /// Open a private worker directory through no-symlink descriptors, checking
    /// that this process is Linux Root, every ancestor is Root-owned and not
    /// group/world writable, and the final journal directory has no
    /// group/world permissions.
    /// The exclusive active lease and process/cgroup checks remain separate.
    pub fn open_root_owned(path: &Path) -> Result<Self, ReservationError> {
        if !cfg!(target_os = "linux") || geteuid().as_raw() != 0 {
            return Err(ReservationError::UnsafeRoot);
        }
        Ok(Self {
            root: open_canonical_directory(path, true)?,
            root_owned: true,
        })
    }

    /// Inert test entrypoint. A Root-owned live journal must use
    /// `reserve_under_lease` so no job ID can be consumed without the lease.
    pub fn reserve(
        &self,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
    ) -> Result<StartedMarker, ReservationError> {
        if self.root_owned {
            return Err(ReservationError::UnsafeRoot);
        }
        self.reserve_internal(
            request,
            source_sha,
            deployment_digest,
            worker_generation,
            None,
        )
    }

    /// Persist an immutable, source/deployment/job-bound marker before any
    /// candidate launch. A failed or partial write still consumes the job ID.
    pub(crate) fn reserve_internal(
        &self,
        request: &WorkerRequest,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
        controller_public_key_hex: Option<&str>,
    ) -> Result<StartedMarker, ReservationError> {
        if !is_git_sha(source_sha) || !hex(worker_generation, 64) || !hex(deployment_digest, 64) {
            return Err(ReservationError::InvalidPins);
        }
        if controller_public_key_hex.is_some_and(|key| !hex(key, 64)) {
            return Err(ReservationError::InvalidPins);
        }
        if request.action() != WorkerAction::Run
            || !request.matches_deployment(source_sha, deployment_digest)
        {
            return Err(ReservationError::WrongRequest);
        }
        let name = marker_name(request.job_id())?;
        for suffix in ["running", "report", "terminal", "controller-key"] {
            let sidecar_name = format!("{}.{suffix}.json", request.job_id());
            match statat(&self.root, sidecar_name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => return Err(ReservationError::AlreadyStarted),
                Err(Errno::NOENT) => {}
                Err(error) => return Err(io(error)),
            }
        }
        let mut value = json!({
            "schema": if controller_public_key_hex.is_some() { KEYED_MARKER_SCHEMA } else { MARKER_SCHEMA },
            "source_sha": source_sha,
            "job_id": request.job_id(),
            "deployment_digest": deployment_digest,
            "worker_generation": worker_generation,
        });
        if let Some(key) = controller_public_key_hex {
            value["controller_public_key_hex"] = json!(key);
        }
        let bytes = canonicalize(value.to_string().as_bytes())
            .map_err(|_| ReservationError::InvalidMarker)?;
        if bytes.len() as u64 > MAX_MARKER_BYTES {
            return Err(ReservationError::InvalidMarker);
        }
        let descriptor = openat(
            &self.root,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|error| {
            if error == Errno::EXIST {
                ReservationError::AlreadyStarted
            } else {
                io(error)
            }
        })?;
        let mut file = File::from(descriptor);
        file.write_all(&bytes).map_err(io)?;
        file.sync_all().map_err(io)?;
        fsync(&self.root).map_err(io)?;
        Ok(StartedMarker {
            source_sha: source_sha.to_owned(),
            job_id: request.job_id().to_owned(),
            deployment_digest: deployment_digest.to_owned(),
            worker_generation: worker_generation.to_owned(),
            controller_public_key_hex: controller_public_key_hex.map(str::to_owned),
            sha256: format!("{:x}", Sha256::digest(bytes)),
        })
    }

    /// Read a marker against outside pins. An invalid marker is never treated
    /// as not-started; the host must surface it as unknown and block replay.
    pub fn started(
        &self,
        job_id: &str,
        source_sha: &str,
        deployment_digest: &str,
        worker_generation: &str,
    ) -> Result<Option<StartedMarker>, ReservationError> {
        if !is_git_sha(source_sha) || !hex(deployment_digest, 64) || !hex(worker_generation, 64) {
            return Err(ReservationError::InvalidPins);
        }
        let name = marker_name(job_id)?;
        let Some(bytes) = read_bounded_regular(&self.root, &name, MAX_MARKER_BYTES)? else {
            return Ok(None);
        };
        let canonical = canonicalize(&bytes).map_err(|_| ReservationError::InvalidMarker)?;
        if bytes != canonical {
            return Err(ReservationError::InvalidMarker);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| ReservationError::InvalidMarker)?;
        let fields = value.as_object().ok_or(ReservationError::InvalidMarker)?;
        let controller_public_key_hex = match value["schema"].as_str() {
            Some(MARKER_SCHEMA) if fields.len() == 5 => None,
            Some(KEYED_MARKER_SCHEMA) if fields.len() == 6 => {
                let key = value["controller_public_key_hex"]
                    .as_str()
                    .ok_or(ReservationError::InvalidMarker)?;
                if !hex(key, 64) {
                    return Err(ReservationError::InvalidMarker);
                }
                Some(key.to_owned())
            }
            _ => return Err(ReservationError::InvalidMarker),
        };
        if value["job_id"] != job_id
            || value["source_sha"] != source_sha
            || value["deployment_digest"] != deployment_digest
            || value["worker_generation"] != worker_generation
        {
            return Err(ReservationError::InvalidMarker);
        }
        Ok(Some(StartedMarker {
            source_sha: source_sha.to_owned(),
            job_id: job_id.to_owned(),
            deployment_digest: deployment_digest.to_owned(),
            worker_generation: worker_generation.to_owned(),
            controller_public_key_hex,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }))
    }
}
