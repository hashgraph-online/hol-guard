//! Fixed, read-only Lima probe for a completed Rust candidate build. The
//! guest response is a local supervisor claim, never an authenticated result.

use crate::fixed_process::{run_fixed, FixedProcessError};
use crate::load_operations_bytes;
use gauntlet_contracts::{canonicalize, is_git_sha};
use gauntlet_evidence::valid_package_version;
use serde_json::{json, Value};
use std::fmt;
use std::time::Duration;

const MAX_RESPONSE_BYTES: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmCandidateResultError {
    InvalidConfig,
    InvalidPins,
    InvalidResponse,
    Unavailable,
    TimedOut,
    TooLarge,
}

impl fmt::Display for VmCandidateResultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid VM operations configuration",
            Self::InvalidPins => "invalid outside candidate, result or binary pins",
            Self::InvalidResponse => "VM candidate result differs from outside pins or schema",
            Self::Unavailable => "VM candidate result reader unavailable",
            Self::TimedOut => "VM candidate result reader timed out",
            Self::TooLarge => "VM candidate result response too large",
        })
    }
}

impl std::error::Error for VmCandidateResultError {}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmCandidateResultPlan {
    pub argv: Vec<String>,
    job_id: String,
    source_sha: String,
    result_sha256: String,
    archive_sha256: String,
    version: String,
    binary_sha256: String,
}

impl VmCandidateResultPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operations: &Value,
        job_id: &str,
        source_sha: &str,
        source_archive_sha256: &str,
        result_sha256: &str,
        archive_sha256: &str,
        version: &str,
        binary_sha256: &str,
    ) -> Result<Self, VmCandidateResultError> {
        if !lower_hex(job_id, 16)
            || !is_git_sha(source_sha)
            || !lower_hex(source_archive_sha256, 64)
            || !lower_hex(result_sha256, 64)
            || !lower_hex(archive_sha256, 64)
            || !valid_package_version(version)
            || !lower_hex(binary_sha256, 64)
        {
            return Err(VmCandidateResultError::InvalidPins);
        }
        let raw =
            serde_json::to_vec(operations).map_err(|_| VmCandidateResultError::InvalidConfig)?;
        let config =
            load_operations_bytes(&raw).map_err(|_| VmCandidateResultError::InvalidConfig)?;
        if config["release_build_backend"] != "local-vm" {
            return Err(VmCandidateResultError::InvalidConfig);
        }
        let limactl = config["limactl"]
            .as_str()
            .ok_or(VmCandidateResultError::InvalidConfig)?;
        let vm = config["vm"]
            .as_str()
            .ok_or(VmCandidateResultError::InvalidConfig)?;
        Ok(Self {
            argv: vec![
                limactl.to_owned(),
                "shell".to_owned(),
                vm.to_owned(),
                "--".to_owned(),
                "sudo".to_owned(),
                "-n".to_owned(),
                format!("/opt/hol-gauntlet/rust-candidate-result-read-shadow-{binary_sha256}"),
                job_id.to_owned(),
                source_sha.to_owned(),
                source_archive_sha256.to_owned(),
                result_sha256.to_owned(),
                archive_sha256.to_owned(),
                version.to_owned(),
            ],
            job_id: job_id.to_owned(),
            source_sha: source_sha.to_owned(),
            result_sha256: result_sha256.to_owned(),
            archive_sha256: archive_sha256.to_owned(),
            version: version.to_owned(),
            binary_sha256: binary_sha256.to_owned(),
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "argv":self.argv,
            "binary_sha256":self.binary_sha256,
            "binary_pin_verified":false,
            "timeout_seconds":30,
            "read_only":true,
            "execution_eligible":false,
        })
    }

    pub fn parse_response(&self, stdout: &[u8]) -> Result<Value, VmCandidateResultError> {
        if stdout.len() > MAX_RESPONSE_BYTES + 1 {
            return Err(VmCandidateResultError::TooLarge);
        }
        let frame = stdout
            .strip_suffix(b"\n")
            .filter(|frame| !frame.is_empty() && !frame.contains(&b'\n'))
            .ok_or(VmCandidateResultError::InvalidResponse)?;
        if canonicalize(frame).map_err(|_| VmCandidateResultError::InvalidResponse)? != frame {
            return Err(VmCandidateResultError::InvalidResponse);
        }
        let result: Value =
            serde_json::from_slice(frame).map_err(|_| VmCandidateResultError::InvalidResponse)?;
        let object = result
            .as_object()
            .ok_or(VmCandidateResultError::InvalidResponse)?;
        if object.len() != 14
            || result["schema"] != "hol-gauntlet-candidate-result-read-shadow.v1"
            || result["job_id"] != self.job_id
            || result["source_sha"] != self.source_sha
            || result["result_sha256"] != self.result_sha256
            || result["archive_sha256"] != self.archive_sha256
            || result["version"] != self.version
            || result["wheel_sha256"]
                .as_str()
                .is_none_or(|digest| !lower_hex(digest, 64))
            || result["client_pid"]
                .as_u64()
                .is_none_or(|pid| pid == 0 || pid > u32::MAX as u64)
            || result["client_start_ticks"]
                .as_u64()
                .is_none_or(|ticks| ticks == 0)
            || result["retained_files_match"] != true
            || result["cleanup_absent"] != true
            || result["host_anchor_present"] != false
            || result["artifact_admitted"] != false
            || result["execution_eligible"] != false
        {
            return Err(VmCandidateResultError::InvalidResponse);
        }
        Ok(json!({
            "schema":"hol-gauntlet-host-candidate-result-shadow.v1",
            "job_id":self.job_id,
            "source_sha":self.source_sha,
            "result_sha256":self.result_sha256,
            "archive_sha256":self.archive_sha256,
            "wheel_sha256":result["wheel_sha256"],
            "version":self.version,
            "client_pid":result["client_pid"],
            "client_start_ticks":result["client_start_ticks"],
            "retained_files_match":true,
            "cleanup_absent":true,
            "binary_pin_verified":false,
            "host_anchor_present":false,
            "artifact_admitted":false,
            "execution_eligible":false,
        }))
    }

    pub fn execute_read_only(&self) -> Result<Value, VmCandidateResultError> {
        let output = run_fixed(
            &self.argv,
            Duration::from_secs(30),
            MAX_RESPONSE_BYTES + 1,
            1500,
            &[],
        )
        .map_err(|error| match error {
            FixedProcessError::Unavailable | FixedProcessError::Failed => {
                VmCandidateResultError::Unavailable
            }
            FixedProcessError::TimedOut => VmCandidateResultError::TimedOut,
            FixedProcessError::TooLarge => VmCandidateResultError::TooLarge,
        })?;
        self.parse_response(&output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOB: &str = "c04e7f93a2b15d68";
    const SOURCE: &str = "76c31929833b5571d25a56d9783e24a0997d5422";
    const SOURCE_ARCHIVE: &str = "bedd98ab7da8ca728484799e1ef6b13c854f7fcbb31a17ebdcc469c4c772af43";
    const RESULT: &str = "8037a45d1e47ce0e82dc5786a30ab956e99b830a9818783d460ea514211fac8e";
    const ARCHIVE: &str = "d9a3258818344e48c84808692c598ace45ec19bb1cb782bb958505795ec5ac04";
    const BINARY: &str = "f977ae6a0da162392cd0c03360083d78a98b66cd6e6e12144f8f7756f1363c98";

    fn plan() -> VmCandidateResultPlan {
        let operations: Value =
            serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap();
        VmCandidateResultPlan::new(
            &operations,
            JOB,
            SOURCE,
            SOURCE_ARCHIVE,
            RESULT,
            ARCHIVE,
            "3.49.0",
            BINARY,
        )
        .unwrap()
    }

    fn response() -> Value {
        json!({
            "archive_sha256":ARCHIVE,
            "artifact_admitted":false,
            "cleanup_absent":true,
            "client_pid":1253463,
            "client_start_ticks":31070585,
            "execution_eligible":false,
            "host_anchor_present":false,
            "job_id":JOB,
            "result_sha256":RESULT,
            "retained_files_match":true,
            "schema":"hol-gauntlet-candidate-result-read-shadow.v1",
            "source_sha":SOURCE,
            "version":"3.49.0",
            "wheel_sha256":"f3acbcd0476e1ecc3d119f29e56c9c1bd22401e76c5d83c8cb8255d214eab496",
        })
    }

    fn parse(plan: &VmCandidateResultPlan, value: &Value) -> Result<Value, VmCandidateResultError> {
        let mut bytes = canonicalize(value.to_string().as_bytes()).unwrap();
        bytes.push(b'\n');
        plan.parse_response(&bytes)
    }

    #[test]
    fn fixed_lima_call_uses_only_outside_pins_and_compiled_vm() {
        let plan = plan();
        assert_eq!(plan.argv.len(), 13);
        assert_eq!(plan.argv[1], "shell");
        assert_eq!(plan.argv[3], "--");
        assert_eq!(plan.argv[4..6], ["sudo", "-n"]);
        assert_eq!(plan.argv[7], JOB);
        assert_eq!(plan.argv[8], SOURCE);
        assert_eq!(plan.argv[9], SOURCE_ARCHIVE);
        assert_eq!(plan.argv[10], RESULT);
        assert_eq!(plan.argv[11], ARCHIVE);
        assert_eq!(plan.argv[12], "3.49.0");
        assert!(plan.argv[6].ends_with(BINARY));
        let operations: Value =
            serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap();
        assert_eq!(
            VmCandidateResultPlan::new(
                &operations,
                JOB,
                SOURCE,
                SOURCE_ARCHIVE,
                RESULT,
                ARCHIVE,
                "3.49.0",
                "../arbitrary-program",
            ),
            Err(VmCandidateResultError::InvalidPins)
        );
    }

    #[test]
    fn host_refuses_wrong_guest_identity_or_eligibility() {
        let plan = plan();
        let valid = response();
        let accepted = parse(&plan, &valid).unwrap();
        assert_eq!(accepted["binary_pin_verified"], false);
        assert_eq!(accepted["execution_eligible"], false);
        for (field, replacement) in [
            ("result_sha256", json!("0".repeat(64))),
            ("archive_sha256", json!("0".repeat(64))),
            ("job_id", json!("0000000000000000")),
            ("source_sha", json!("0".repeat(40))),
            ("version", json!("3.50.0")),
            ("wheel_sha256", json!("broken")),
            ("client_pid", json!(0)),
            ("retained_files_match", json!(false)),
            ("cleanup_absent", json!(false)),
            ("host_anchor_present", json!(true)),
            ("artifact_admitted", json!(true)),
            ("execution_eligible", json!(true)),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = replacement;
            assert_eq!(
                parse(&plan, &invalid),
                Err(VmCandidateResultError::InvalidResponse),
                "{field}"
            );
        }
        let mut extra = valid.clone();
        extra["extra"] = json!(true);
        assert_eq!(
            parse(&plan, &extra),
            Err(VmCandidateResultError::InvalidResponse)
        );
        let noncanonical = format!(" {valid}\n");
        assert_eq!(
            plan.parse_response(noncanonical.as_bytes()),
            Err(VmCandidateResultError::InvalidResponse)
        );
        assert_eq!(
            plan.parse_response(b"{}\n{}\n"),
            Err(VmCandidateResultError::InvalidResponse)
        );
    }
}
