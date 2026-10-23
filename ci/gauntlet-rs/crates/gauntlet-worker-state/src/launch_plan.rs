//! Inert, exact Python-worker launch vector. Creating a plan does not prove
//! deployment custody, controller bytes, process isolation or job eligibility.

use crate::{hex, ReservationError};
use gauntlet_contracts::{is_git_sha, WorkerRequest};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const CODE: &str = "import sys;sys.path.insert(0,sys.argv.pop(1));from ci.gauntlet.benchmark.__main__ import main;raise SystemExit(main())";
const CONTROLLER_PREFIX: &str = "/opt/hol-gauntlet/controller-";
const PYTHON_PREFIX: &str = "/opt/hol-benchmark-controller-";
const PYTHON_SUFFIX: &str = "/.venv/bin/python";

pub(crate) fn rust_job_slice_name(job_id: &str) -> Result<String, ReservationError> {
    if !hex(job_id, 16) {
        return Err(ReservationError::InvalidPins);
    }
    Ok(format!("holgauntletrust{job_id}.slice"))
}

pub(crate) fn rust_controller_cgroup_path(job_id: &str) -> Result<String, ReservationError> {
    if !hex(job_id, 16) {
        return Err(ReservationError::InvalidPins);
    }
    Ok(format!("/system.slice/hol-gauntlet-rust-job-{job_id}"))
}

/// The caller must obtain these bytes from independently verified, Root-owned
/// deployment and interpreter readers. This data-only struct is not a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLaunchPins {
    pub source_sha: String,
    pub deployment_digest: String,
    pub config_digest: String,
    pub controller_path: String,
    pub python_path: String,
    pub interpreter_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedLaunchPlan {
    pub argv: Vec<String>,
    pub cwd: String,
    pub state_root: String,
    pub output_dir: String,
    pub log_path: String,
}

/// The Rust-owned variant of the frozen Python launch. The environment is
/// derived from the parsed job ID, never accepted from a caller's request.
/// It only arranges product-cell placement; dispatch and cleanup remain open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustJobLaunchPlan {
    fixed: FixedLaunchPlan,
    job_slice: String,
    controller_cgroup: String,
}

impl RustJobLaunchPlan {
    pub fn fixed(&self) -> &FixedLaunchPlan {
        &self.fixed
    }

    pub fn job_slice(&self) -> &str {
        &self.job_slice
    }

    /// The systemd-managed product-cell slice cgroup, distinct from the
    /// directly owned controller cgroup below.
    pub fn job_cgroup(&self) -> String {
        format!("/{}", self.job_slice)
    }

    /// Separate contained-controller cgroup; product cells use `job_slice`.
    pub fn controller_cgroup(&self) -> &str {
        &self.controller_cgroup
    }

    pub fn environment(&self) -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("PATH", "/usr/bin:/bin".to_owned()),
            ("LANG", "C.UTF-8".to_owned()),
            ("HOME", "/root".to_owned()),
            ("HOL_GAUNTLET_RUST_JOB_SLICE", self.job_slice.clone()),
        ])
    }
}

impl FixedLaunchPlan {
    pub fn to_json(&self) -> Value {
        json!({
            "argv": self.argv,
            "cwd": self.cwd,
            "env": {"PATH":"/usr/bin:/bin", "LANG":"C.UTF-8", "HOME":"/root"},
            "state_root": self.state_root,
            "output_dir": self.output_dir,
            "log_path": self.log_path,
            "execution_eligible": false,
        })
    }
}

fn fixed_controller_path(path: &str) -> bool {
    path.strip_prefix(CONTROLLER_PREFIX)
        .is_some_and(|generation| hex(generation, 16))
}

fn fixed_python_path(path: &str) -> bool {
    path.strip_prefix(PYTHON_PREFIX)
        .and_then(|rest| rest.strip_suffix(PYTHON_SUFFIX))
        .is_some_and(|generation| {
            generation.len() == 8 && generation.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// Reproduce the pinned Python VM worker's deterministic `ci check` argv,
/// cwd, environment and output paths. The fixed request has no command, path
/// or profile selector. A caller must still authenticate the deployed bytes,
/// hold the exclusive lease, isolate the child and independently score output.
pub fn fixed_launch_plan(
    request: &WorkerRequest,
    pins: &RunLaunchPins,
    expected_interpreter_sha256: &str,
) -> Result<FixedLaunchPlan, ReservationError> {
    if !is_git_sha(&pins.source_sha)
        || !hex(&pins.deployment_digest, 64)
        || !hex(&pins.config_digest, 64)
        || !hex(&pins.interpreter_sha256, 64)
        || !hex(expected_interpreter_sha256, 64)
        || pins.interpreter_sha256 != expected_interpreter_sha256
        || !fixed_controller_path(&pins.controller_path)
        || !fixed_python_path(&pins.python_path)
    {
        return Err(ReservationError::InvalidPins);
    }
    if !request.matches_deployment(&pins.source_sha, &pins.deployment_digest) {
        return Err(ReservationError::WrongRequest);
    }
    let job_id = request.job_id();
    let config = format!(
        "/opt/hol-gauntlet/candidates/{}/config.json",
        pins.source_sha
    );
    let state_root = format!("/home/hg-{job_id}");
    let output_dir = format!("/var/lib/hol-gauntlet/outputs/{job_id}");
    let log_path = format!("{output_dir}.log");
    let argv = vec![
        pins.python_path.clone(),
        "-I".to_owned(),
        "-B".to_owned(),
        "-c".to_owned(),
        CODE.to_owned(),
        pins.controller_path.clone(),
        "ci".to_owned(),
        "check".to_owned(),
        "--profile".to_owned(),
        "deterministic".to_owned(),
        "--config".to_owned(),
        config,
        "--expected-config-digest".to_owned(),
        pins.config_digest.clone(),
        "--expected-guard-source-sha".to_owned(),
        pins.source_sha.clone(),
        "--asset-root".to_owned(),
        "/opt".to_owned(),
        "--state-root".to_owned(),
        state_root.clone(),
        "--output-dir".to_owned(),
        output_dir.clone(),
    ];
    Ok(FixedLaunchPlan {
        argv,
        cwd: pins.controller_path.clone(),
        state_root,
        output_dir,
        log_path,
    })
}

/// Compose the same fixed command with the sole additional Rust-owned
/// product-cell slice setting. The caller must still create, own, stop and
/// verify that systemd slice before claiming whole-job cleanup.
pub fn fixed_rust_job_launch_plan(
    request: &WorkerRequest,
    pins: &RunLaunchPins,
    expected_interpreter_sha256: &str,
) -> Result<RustJobLaunchPlan, ReservationError> {
    let fixed = fixed_launch_plan(request, pins, expected_interpreter_sha256)?;
    Ok(RustJobLaunchPlan {
        fixed,
        job_slice: rust_job_slice_name(request.job_id())?,
        controller_cgroup: rust_controller_cgroup_path(request.job_id())?,
    })
}
