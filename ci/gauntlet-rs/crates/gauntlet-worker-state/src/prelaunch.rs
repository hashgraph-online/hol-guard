//! Compose the fixed Linux ARM prelaunch readers against four outside pins.
//! This is a read-only point-in-time diagnostic, not a dispatch authority.

use crate::{
    fixed_rust_job_launch_plan, hex, read_fixed_deployment, read_fixed_interpreter_held,
    HeldInterpreter, ReservationError, RunLaunchPins, RustJobLaunchPlan,
};
use gauntlet_contracts::{is_git_sha, WorkerAction, WorkerRequest};
use gauntlet_evidence::{
    load_runner_config_from_paths, verify_controller_tree, verify_runner_assets_inert,
    EvidenceError,
};
use rustix::process::geteuid;
use serde_json::{json, Value};
use std::fmt;
use std::path::Path;

const ASSET_ROOT: &str = "/opt";

/// These hashes must be supplied by a trusted caller outside the candidate
/// deployment. This type cannot establish that the caller reviewed them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrelaunchPins {
    pub source_sha: String,
    pub deployment_digest: String,
    pub controller_tree_digest: String,
    pub interpreter_sha256: String,
}

#[derive(Debug)]
pub enum PrelaunchError {
    Platform,
    RootRequired,
    InvalidPins,
    WrongRequest,
    Deployment(ReservationError),
    Controller(EvidenceError),
    Interpreter(ReservationError),
    Config(EvidenceError),
    Assets(EvidenceError),
    Plan(ReservationError),
}

impl fmt::Display for PrelaunchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform => f.write_str("Linux ARM64 prelaunch diagnostic required"),
            Self::RootRequired => f.write_str("Linux Root required for prelaunch custody"),
            Self::InvalidPins => f.write_str("invalid outside prelaunch pins"),
            Self::WrongRequest => f.write_str("run request differs from outside pins"),
            Self::Deployment(error) => write!(f, "deployment: {error}"),
            Self::Controller(error) => write!(f, "controller tree: {error}"),
            Self::Interpreter(error) => write!(f, "interpreter: {error}"),
            Self::Config(error) => write!(f, "runner config: {error}"),
            Self::Assets(error) => write!(f, "runner assets: {error}"),
            Self::Plan(error) => write!(f, "fixed launch plan: {error}"),
        }
    }
}

impl std::error::Error for PrelaunchError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrelaunchProof {
    source_sha: String,
    deployment_digest: String,
    controller_tree_digest: String,
    interpreter_sha256: String,
    config_digest: String,
    controller_entries: usize,
    asset_roles: usize,
    plan: RustJobLaunchPlan,
}

/// Keep the verified interpreter inode open while a future dispatcher decides
/// whether it can safely launch. This is not a lease, cgroup or result.
pub struct PreparedLaunch {
    proof: PrelaunchProof,
    interpreter: HeldInterpreter,
}

impl PreparedLaunch {
    pub fn proof(&self) -> &PrelaunchProof {
        &self.proof
    }

    pub fn interpreter(&self) -> &HeldInterpreter {
        &self.interpreter
    }

    pub fn launch_plan(&self) -> &RustJobLaunchPlan {
        &self.proof.plan
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn config_digest(&self) -> &str {
        &self.proof.config_digest
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn matches_run_request(&self, request: &WorkerRequest) -> bool {
        request.action() == WorkerAction::Run
            && request.matches_deployment(&self.proof.source_sha, &self.proof.deployment_digest)
    }

    /// Re-hash the Root-owned controller and recheck the held interpreter
    /// immediately around a future descriptor-bound child launch. Other
    /// deployment assets still need their own post-run custody checks.
    pub fn recheck_controller_and_interpreter(&self) -> Result<(), PrelaunchError> {
        let controller = verify_controller_tree(
            Path::new(&self.proof.plan.fixed().cwd),
            &self.proof.controller_tree_digest,
        )
        .map_err(PrelaunchError::Controller)?;
        if controller.entries() != self.proof.controller_entries {
            return Err(PrelaunchError::InvalidPins);
        }
        self.interpreter
            .assert_unchanged()
            .map_err(PrelaunchError::Interpreter)
    }

    /// Refuse a completed controller observation if any pinned execution
    /// input changed while the child or its product cells were active. Call
    /// this only after both containment domains have been drained; it is a
    /// post-run custody check, not an independent control verdict.
    #[cfg(target_arch = "aarch64")]
    pub(crate) fn recheck_all_assets_after_cleanup(&self) -> Result<(), PrelaunchError> {
        self.recheck_controller_and_interpreter()?;
        let config_path = format!(
            "/opt/hol-gauntlet/candidates/{}/config.json",
            self.proof.source_sha
        );
        let loaded = load_runner_config_from_paths(
            Path::new(&config_path),
            &self.proof.config_digest,
            Path::new(ASSET_ROOT),
        )
        .map_err(PrelaunchError::Config)?;
        if loaded.verified.version != 7 {
            return Err(PrelaunchError::InvalidPins);
        }
        let assets = verify_runner_assets_inert(&loaded, Path::new(ASSET_ROOT))
            .map_err(PrelaunchError::Assets)?;
        if assets.observed.len() != self.proof.asset_roles {
            return Err(PrelaunchError::InvalidPins);
        }
        self.recheck_controller_and_interpreter()
    }

    pub fn into_parts(self) -> (PrelaunchProof, HeldInterpreter) {
        (self.proof, self.interpreter)
    }
}

impl PrelaunchProof {
    pub fn to_json(&self) -> Value {
        json!({
            "schema": "hol-gauntlet-prelaunch-shadow.v1",
            "source_sha": self.source_sha,
            "deployment_digest": self.deployment_digest,
            "controller_tree_digest": self.controller_tree_digest,
            "interpreter_sha256": self.interpreter_sha256,
            "config_digest": self.config_digest,
            "controller_entries": self.controller_entries,
            "verified_asset_roles": self.asset_roles,
            "fixed_launch_plan": self.plan.fixed().to_json(),
            "rust_job_slice": self.plan.job_slice(),
            "rust_job_cgroup": self.plan.job_cgroup(),
            "rust_controller_cgroup": self.plan.controller_cgroup(),
            "rust_job_environment": self.plan.environment(),
            "outside_pin_provenance_verified": false,
            "interpreter_execution_bound": false,
            "execution_eligible": false,
        })
    }
}

/// Re-read the fixed deployment, every controller file, the interpreter, v7
/// config and every declared inert asset before constructing the only allowed
/// deterministic launch plan. No journal, process, cgroup or provider is touched.
/// A future dispatcher must still authenticate the outside pin source, hold
/// the worker lease, bind the opened executable to its launch, contain/reap the
/// process and independently score its output.
pub fn prepare_fixed_prelaunch(
    request: &WorkerRequest,
    pins: &PrelaunchPins,
) -> Result<PreparedLaunch, PrelaunchError> {
    if !cfg!(target_arch = "aarch64") {
        return Err(PrelaunchError::Platform);
    }
    if geteuid().as_raw() != 0 {
        return Err(PrelaunchError::RootRequired);
    }
    if !is_git_sha(&pins.source_sha)
        || !hex(&pins.deployment_digest, 64)
        || !hex(&pins.controller_tree_digest, 64)
        || !hex(&pins.interpreter_sha256, 64)
    {
        return Err(PrelaunchError::InvalidPins);
    }
    if request.action() != WorkerAction::Run
        || !request.matches_deployment(&pins.source_sha, &pins.deployment_digest)
    {
        return Err(PrelaunchError::WrongRequest);
    }
    let deployment = read_fixed_deployment(&pins.source_sha, &pins.deployment_digest)
        .map_err(PrelaunchError::Deployment)?;
    let controller = verify_controller_tree(
        Path::new(&deployment.controller_path),
        &pins.controller_tree_digest,
    )
    .map_err(PrelaunchError::Controller)?;
    let interpreter = read_fixed_interpreter_held(&deployment, &pins.interpreter_sha256)
        .map_err(PrelaunchError::Interpreter)?;
    let config_path = format!(
        "/opt/hol-gauntlet/candidates/{}/config.json",
        pins.source_sha
    );
    let loaded = load_runner_config_from_paths(
        Path::new(&config_path),
        &deployment.config_digest,
        Path::new(ASSET_ROOT),
    )
    .map_err(PrelaunchError::Config)?;
    if loaded.verified.version != 7 {
        return Err(PrelaunchError::InvalidPins);
    }
    let assets = verify_runner_assets_inert(&loaded, Path::new(ASSET_ROOT))
        .map_err(PrelaunchError::Assets)?;
    interpreter
        .assert_unchanged()
        .map_err(PrelaunchError::Interpreter)?;
    let declaration = interpreter.declaration();
    let plan_pins = RunLaunchPins {
        source_sha: deployment.source_sha.clone(),
        deployment_digest: deployment.deployment_digest.clone(),
        config_digest: deployment.config_digest.clone(),
        controller_path: controller.root().to_string_lossy().into_owned(),
        python_path: declaration.python_path.clone(),
        interpreter_sha256: declaration.sha256.clone(),
    };
    let plan = fixed_rust_job_launch_plan(request, &plan_pins, &pins.interpreter_sha256)
        .map_err(PrelaunchError::Plan)?;
    Ok(PreparedLaunch {
        proof: PrelaunchProof {
            source_sha: deployment.source_sha,
            deployment_digest: deployment.deployment_digest,
            controller_tree_digest: controller.digest().to_owned(),
            interpreter_sha256: declaration.sha256.clone(),
            config_digest: deployment.config_digest,
            controller_entries: controller.entries(),
            asset_roles: assets.observed.len(),
            plan,
        },
        interpreter,
    })
}

/// Data-only compatibility wrapper for diagnostics that do not need to retain
/// the executable descriptor after prelaunch verification.
pub fn verify_fixed_prelaunch(
    request: &WorkerRequest,
    pins: &PrelaunchPins,
) -> Result<PrelaunchProof, PrelaunchError> {
    Ok(prepare_fixed_prelaunch(request, pins)?.proof)
}
