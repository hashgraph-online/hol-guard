//! Read-only Lima reconciliation of a v2 candidate result against the
//! prelaunch, one-use host pin journal. The guest result is still a local
//! supervisor claim; this plan never admits a wheel or a benchmark pass.

use crate::fixed_process::{run_fixed, FixedProcessError};
use crate::{load_operations_bytes, HostCandidateBuildPinJournal, HostCandidateBuildPinRecord};
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use std::fmt;
use std::time::Duration;

const MAX_RESPONSE_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmHostBoundCandidateResultError {
    InvalidConfig,
    InvalidPins,
    HostPinUnavailable,
    InvalidResponse,
    Unavailable,
    TimedOut,
    TooLarge,
}

impl fmt::Display for VmHostBoundCandidateResultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid fixed VM operations configuration",
            Self::InvalidPins => "invalid outside terminal result or archive digest",
            Self::HostPinUnavailable => "durable prelaunch host candidate pin unavailable",
            Self::InvalidResponse => "VM terminal result differs from prelaunch host pins",
            Self::Unavailable => "VM host-bound result reader unavailable",
            Self::TimedOut => "VM host-bound result reader timed out",
            Self::TooLarge => "VM host-bound result response too large",
        })
    }
}

impl std::error::Error for VmHostBoundCandidateResultError {}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmHostBoundCandidateResultPlan {
    argv: Vec<String>,
    record: HostCandidateBuildPinRecord,
    result_sha256: String,
    archive_sha256: String,
}

impl VmHostBoundCandidateResultPlan {
    pub fn new(
        operations: &Value,
        journal: &HostCandidateBuildPinJournal,
        job_id: &str,
        result_sha256: &str,
        archive_sha256: &str,
    ) -> Result<Self, VmHostBoundCandidateResultError> {
        if !lower_hex(job_id, 16) || !lower_hex(result_sha256, 64) || !lower_hex(archive_sha256, 64)
        {
            return Err(VmHostBoundCandidateResultError::InvalidPins);
        }
        let raw = serde_json::to_vec(operations)
            .map_err(|_| VmHostBoundCandidateResultError::InvalidConfig)?;
        let config = load_operations_bytes(&raw)
            .map_err(|_| VmHostBoundCandidateResultError::InvalidConfig)?;
        if config["release_build_backend"] != "local-vm" {
            return Err(VmHostBoundCandidateResultError::InvalidConfig);
        }
        let limactl = config["limactl"]
            .as_str()
            .ok_or(VmHostBoundCandidateResultError::InvalidConfig)?;
        let vm = config["vm"]
            .as_str()
            .ok_or(VmHostBoundCandidateResultError::InvalidConfig)?;
        let record = journal
            .read(job_id)
            .map_err(|_| VmHostBoundCandidateResultError::HostPinUnavailable)?;
        let pins = &record.pins;
        let tagged = record.schema == "hol-gauntlet-host-candidate-build-pin.v3";
        let mut argv = vec![
            limactl.to_owned(),
            "shell".to_owned(),
            vm.to_owned(),
            "--".to_owned(),
            "sudo".to_owned(),
            "-n".to_owned(),
            format!(
                "/opt/hol-gauntlet/rust-candidate-result-hostbound-shadow-{}",
                pins.result_reader_binary_sha256
            ),
            pins.job_id.clone(),
            pins.source_sha.clone(),
            pins.source_archive_sha256.clone(),
            result_sha256.to_owned(),
            archive_sha256.to_owned(),
            pins.version.clone(),
        ];
        if tagged {
            argv.push(pins.tag.clone());
        }
        argv.extend([
            pins.controller_tree_sha256.clone(),
            pins.builder_image_id.clone(),
            pins.policy_sha256.clone(),
            pins.podman_sha256.clone(),
            pins.slirp4netns_sha256.clone(),
            pins.apparmor_parser_sha256.clone(),
            pins.seccomp_sha256.clone(),
            pins.runner_binary_sha256.clone(),
            pins.result_reader_binary_sha256.clone(),
            record.raw_sha256.clone(),
            record.host_nonce_hex.clone(),
        ]);
        Ok(Self {
            argv,
            record,
            result_sha256: result_sha256.to_owned(),
            archive_sha256: archive_sha256.to_owned(),
        })
    }

    pub fn parse_response(&self, stdout: &[u8]) -> Result<Value, VmHostBoundCandidateResultError> {
        if stdout.len() > MAX_RESPONSE_BYTES + 1 {
            return Err(VmHostBoundCandidateResultError::TooLarge);
        }
        let frame = stdout
            .strip_suffix(b"\n")
            .filter(|frame| !frame.is_empty() && !frame.contains(&b'\n'))
            .ok_or(VmHostBoundCandidateResultError::InvalidResponse)?;
        if canonicalize(frame).map_err(|_| VmHostBoundCandidateResultError::InvalidResponse)?
            != frame
        {
            return Err(VmHostBoundCandidateResultError::InvalidResponse);
        }
        let value: Value = serde_json::from_slice(frame)
            .map_err(|_| VmHostBoundCandidateResultError::InvalidResponse)?;
        let object = value
            .as_object()
            .ok_or(VmHostBoundCandidateResultError::InvalidResponse)?;
        let pins = &self.record.pins;
        let tagged = self.record.schema == "hol-gauntlet-host-candidate-build-pin.v3";
        if object.len() != 20 + usize::from(tagged)
            || value["schema"]
                != if tagged {
                    "hol-gauntlet-candidate-result-read-shadow.v3"
                } else {
                    "hol-gauntlet-candidate-result-read-shadow.v2"
                }
            || tagged && value["tag"] != pins.tag
            || value["job_id"] != pins.job_id
            || value["source_sha"] != pins.source_sha
            || value["result_sha256"] != self.result_sha256
            || value["archive_sha256"] != self.archive_sha256
            || value["version"] != pins.version
            || value["host_pin_sha256"] != self.record.raw_sha256
            || value["runner_binary_sha256"] != pins.runner_binary_sha256
            || value["result_reader_binary_sha256"] != pins.result_reader_binary_sha256
            || value["image_id"] != pins.builder_image_id
            || value["policy_sha256"] != pins.policy_sha256
            || value["host_anchor_sha256"]
                .as_str()
                .is_none_or(|digest| !lower_hex(digest, 64))
            || value["wheel_sha256"]
                .as_str()
                .is_none_or(|digest| !lower_hex(digest, 64))
            || value["client_pid"]
                .as_u64()
                .is_none_or(|pid| pid == 0 || pid > u32::MAX as u64)
            || value["client_start_ticks"]
                .as_u64()
                .is_none_or(|ticks| ticks == 0)
            || value["retained_files_match"] != true
            || value["cleanup_absent"] != true
            || value["host_anchor_present"] != true
            || value["artifact_admitted"] != false
            || value["execution_eligible"] != false
        {
            return Err(VmHostBoundCandidateResultError::InvalidResponse);
        }
        let mut report = json!({
            "schema":if tagged {"hol-gauntlet-host-candidate-result-shadow.v3"} else {"hol-gauntlet-host-candidate-result-shadow.v2"},
            "job_id":pins.job_id,
            "source_sha":pins.source_sha,
            "result_sha256":self.result_sha256,
            "archive_sha256":self.archive_sha256,
            "wheel_sha256":value["wheel_sha256"],
            "version":pins.version,
            "client_pid":value["client_pid"],
            "client_start_ticks":value["client_start_ticks"],
            "host_pin_sha256":self.record.raw_sha256,
            "host_anchor_sha256":value["host_anchor_sha256"],
            "retained_files_match":true,
            "cleanup_absent":true,
            "host_pin_journal_match":true,
            "artifact_admitted":false,
            "execution_eligible":false,
        });
        if tagged {
            report["tag"] = json!(pins.tag);
        }
        Ok(report)
    }

    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    pub fn execute_read_only(&self) -> Result<Value, VmHostBoundCandidateResultError> {
        let output = run_fixed(
            &self.argv,
            Duration::from_secs(30),
            MAX_RESPONSE_BYTES + 1,
            1500,
            &[],
        )
        .map_err(|error| match error {
            FixedProcessError::Unavailable | FixedProcessError::Failed => {
                VmHostBoundCandidateResultError::Unavailable
            }
            FixedProcessError::TimedOut => VmHostBoundCandidateResultError::TimedOut,
            FixedProcessError::TooLarge => VmHostBoundCandidateResultError::TooLarge,
        })?;
        self.parse_response(&output)
    }
}
