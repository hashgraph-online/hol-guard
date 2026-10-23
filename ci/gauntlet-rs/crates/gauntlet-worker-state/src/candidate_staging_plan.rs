//! Fixed one-role launch vector for candidate conformance staging. This is
//! data only: a caller must authenticate the inputs, reserve one-use state,
//! pin the signing key, contain the process, and score its retained record.

use crate::{hex, ReservationError};
use gauntlet_contracts::is_git_sha;
use gauntlet_evidence::valid_package_version;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const CODE: &str = "import sys;sys.path.insert(0,sys.argv.pop(1));from ci.gauntlet.benchmark.stage_control_adapter import main;raise SystemExit(main())";
const SHADOW: &str = "/opt/hol-gauntlet/rust-shadow-candidates";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagingRole {
    Success,
    InputBinding,
    Injection,
    Boundary,
    Timeout,
    Cancel,
}

impl StagingRole {
    pub const ALL: [Self; 6] = [
        Self::Success,
        Self::InputBinding,
        Self::Injection,
        Self::Boundary,
        Self::Timeout,
        Self::Cancel,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::InputBinding => "input-binding",
            Self::Injection => "injection",
            Self::Boundary => "boundary",
            Self::Timeout => "timeout",
            Self::Cancel => "cancel",
        }
    }
}

impl std::str::FromStr for StagingRole {
    type Err = ReservationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|role| role.as_str() == value)
            .ok_or(ReservationError::InvalidPins)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StagingControlPins<'a> {
    pub build_job_id: &'a str,
    pub run_id: &'a str,
    pub source_sha: &'a str,
    pub version: &'a str,
    pub config_digest: &'a str,
    pub private_manifest_sha256: &'a str,
    pub controller_path: &'a str,
    pub python_path: &'a str,
    pub interpreter_sha256: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedStagingControlPlan {
    argv: Vec<String>,
    cwd: String,
    config_path: String,
    state_root: String,
    record_path: String,
    job_slice: String,
    controller_cgroup: String,
}

impl FixedStagingControlPlan {
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    pub fn state_root(&self) -> &str {
        &self.state_root
    }

    pub fn record_path(&self) -> &str {
        &self.record_path
    }

    pub fn controller_cgroup(&self) -> &str {
        &self.controller_cgroup
    }

    pub fn job_slice(&self) -> &str {
        &self.job_slice
    }

    pub fn environment(&self) -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            ("HOL_GAUNTLET_RUST_JOB_SLICE", self.job_slice.clone()),
            ("HOME", "/root".to_owned()),
            ("LANG", "C.UTF-8".to_owned()),
            ("PATH", "/usr/bin:/bin".to_owned()),
        ])
    }

    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "schema":"hol-gauntlet-candidate-staging-plan.v1",
            "argv":self.argv,
            "cwd":self.cwd,
            "config_path":self.config_path,
            "state_root":self.state_root,
            "record_path":self.record_path,
            "controller_cgroup":self.controller_cgroup,
            "job_slice":self.job_slice,
            "environment":self.environment(),
            "control_started":false,
            "execution_eligible":false,
        });
        if self.argv.last().is_some_and(|arg| arg == "--sdk-tap-v2") {
            value["schema"] = json!("hol-gauntlet-candidate-staging-plan.v2");
            value["sdk_tap_v2_requested"] = json!(true);
        }
        value
    }
}

/// The v2 declaration changes only the final fixed adapter selector. It
/// cannot affect an existing v1 run unless a separate worker dispatch opts in.
pub fn fixed_staging_control_plan_sdk_tap_v2(
    pins: &StagingControlPins<'_>,
    role: StagingRole,
) -> Result<FixedStagingControlPlan, ReservationError> {
    let mut plan = fixed_staging_control_plan(pins, role)?;
    plan.argv.push("--sdk-tap-v2".to_owned());
    Ok(plan)
}

pub fn fixed_staging_control_plan(
    pins: &StagingControlPins<'_>,
    role: StagingRole,
) -> Result<FixedStagingControlPlan, ReservationError> {
    if !hex(pins.build_job_id, 16)
        || !hex(pins.run_id, 16)
        || !is_git_sha(pins.source_sha)
        || !valid_package_version(pins.version)
        || !hex(pins.config_digest, 64)
        || !hex(pins.private_manifest_sha256, 64)
        || !hex(pins.interpreter_sha256, 64)
        || !pins
            .controller_path
            .strip_prefix("/opt/hol-gauntlet/controller-")
            .is_some_and(|suffix| hex(suffix, 16))
        || !pins
            .python_path
            .strip_prefix("/opt/hol-benchmark-controller-")
            .and_then(|rest| rest.strip_suffix("/.venv/bin/python"))
            .is_some_and(|date| date.len() == 8 && date.bytes().all(|c| c.is_ascii_digit()))
    {
        return Err(ReservationError::InvalidPins);
    }
    let config_path = format!(
        "{SHADOW}/{}/provisional-{}-{}.json",
        pins.build_job_id,
        &pins.private_manifest_sha256[..16],
        &pins.config_digest[..16]
    );
    let state_root = format!("/home/hx-{}", pins.run_id);
    let record_path = format!("{state_root}/{}/control.json", role.as_str());
    let argv = vec![
        pins.python_path.to_owned(),
        "-I".to_owned(),
        "-B".to_owned(),
        "-c".to_owned(),
        CODE.to_owned(),
        pins.controller_path.to_owned(),
        pins.build_job_id.to_owned(),
        pins.run_id.to_owned(),
        pins.source_sha.to_owned(),
        pins.version.to_owned(),
        pins.config_digest.to_owned(),
        pins.private_manifest_sha256.to_owned(),
        role.as_str().to_owned(),
    ];
    Ok(FixedStagingControlPlan {
        argv,
        cwd: pins.controller_path.to_owned(),
        config_path,
        state_root,
        record_path,
        job_slice: format!("holgauntletrust{}.slice", pins.run_id),
        controller_cgroup: format!("/system.slice/hol-gauntlet-rust-job-{}", pins.run_id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins() -> StagingControlPins<'static> {
        StagingControlPins {
            build_job_id: "aabbccddeeff0011",
            run_id: "1122334455667788",
            source_sha: "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
            version: "3.50.0a1",
            config_digest: concat!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ),
            private_manifest_sha256: concat!(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            ),
            controller_path: "/opt/hol-gauntlet/controller-aabbccddeeff0011",
            python_path: "/opt/hol-benchmark-controller-20261013/.venv/bin/python",
            interpreter_sha256: concat!(
                "cccccccccccccccccccccccccccccccc",
                "cccccccccccccccccccccccccccccccc"
            ),
        }
    }

    #[test]
    fn fixed_roles_match_adapter_and_bind_one_candidate() {
        let pins = pins();
        for role in StagingRole::ALL {
            assert_eq!(role.as_str().parse::<StagingRole>().unwrap(), role);
            let plan = fixed_staging_control_plan(&pins, role).unwrap();
            assert_eq!(plan.argv().len(), 13);
            assert_eq!(plan.argv()[6], pins.build_job_id);
            assert_eq!(plan.argv()[12], role.as_str());
            assert_eq!(plan.cwd(), pins.controller_path);
            assert_eq!(
                plan.to_json()["config_path"],
                format!(
                    "{SHADOW}/{}/provisional-bbbbbbbbbbbbbbbb-aaaaaaaaaaaaaaaa.json",
                    pins.build_job_id
                )
            );
            assert_eq!(plan.to_json()["control_started"], false);
            assert_eq!(plan.to_json()["execution_eligible"], false);
        }
        assert!("all".parse::<StagingRole>().is_err());
    }

    #[test]
    fn selectors_and_noncanonical_pins_refuse() {
        let mut wrong = pins();
        wrong.build_job_id = "../aabbccddeeff0011";
        assert!(fixed_staging_control_plan(&wrong, StagingRole::Success).is_err());
        wrong = pins();
        wrong.controller_path = "/tmp/controller-aabbccddeeff0011";
        assert!(fixed_staging_control_plan(&wrong, StagingRole::Success).is_err());
        wrong = pins();
        wrong.python_path = "/tmp/python";
        assert!(fixed_staging_control_plan(&wrong, StagingRole::Success).is_err());
        wrong = pins();
        wrong.version = "3.50.0;sh";
        assert!(fixed_staging_control_plan(&wrong, StagingRole::Success).is_err());
    }

    #[test]
    fn opt_in_tap_plan_preserves_v1_and_adds_only_fixed_selector() {
        let ordinary = fixed_staging_control_plan(&pins(), StagingRole::Success).unwrap();
        let tap = fixed_staging_control_plan_sdk_tap_v2(&pins(), StagingRole::Success).unwrap();
        assert_eq!(ordinary.argv().len(), 13);
        assert_eq!(tap.argv().len(), 14);
        assert_eq!(&tap.argv()[..13], ordinary.argv());
        assert_eq!(tap.argv()[13], "--sdk-tap-v2");
        assert_eq!(
            tap.to_json()["schema"],
            "hol-gauntlet-candidate-staging-plan.v2"
        );
        assert_eq!(tap.to_json()["execution_eligible"], false);
        assert_eq!(
            ordinary.to_json()["schema"],
            "hol-gauntlet-candidate-staging-plan.v1"
        );
        assert!(ordinary.to_json().get("sdk_tap_v2_requested").is_none());
    }
}
