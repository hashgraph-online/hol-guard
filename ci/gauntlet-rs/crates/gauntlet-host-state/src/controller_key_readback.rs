//! Host-keyed readback of one completed, explicitly ineligible Rust
//! deterministic run. The guest is still a producer; these relations are
//! custody checks, not independent Guard control verdicts.

use super::{hex, HostKeyPinError, HostKeyPinRecord};
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;

const MAX_READBACK_BYTES: usize = 16 * 1024;
const INVALID: HostKeyPinError = HostKeyPinError::InvalidTerminal;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDeterministicReadbackObservation {
    pub host_pin_record_sha256: String,
    pub terminal_sha256: String,
    pub diagnostic_report_sha256: String,
    pub deterministic_report_sha256: String,
    pub controller_exit_code: i32,
    pub producer_status_claim: String,
}

impl HostDeterministicReadbackObservation {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-host-deterministic-readback.v1",
            "host_pin_record_sha256":self.host_pin_record_sha256,
            "terminal_sha256":self.terminal_sha256,
            "diagnostic_report_sha256":self.diagnostic_report_sha256,
            "deterministic_report_sha256":self.deterministic_report_sha256,
            "controller_exit_code":self.controller_exit_code,
            "producer_status_claim":self.producer_status_claim,
            "keyed_terminal_status":"invalid-evidence",
            "independent_control_verdict":false,
            "execution_eligible":false,
        })
    }
}

impl HostKeyPinRecord {
    /// Bind a bounded guest readback to this prelaunch pin and the hashes
    /// claimed by the same guest process after its terminal write.
    pub fn observe_deterministic_readback(
        &self,
        raw: &[u8],
        expected_terminal_sha256: &str,
        expected_diagnostic_sha256: &str,
        expected_deterministic_sha256: &str,
    ) -> Result<HostDeterministicReadbackObservation, HostKeyPinError> {
        if raw.len() > MAX_READBACK_BYTES
            || ![
                expected_terminal_sha256,
                expected_diagnostic_sha256,
                expected_deterministic_sha256,
            ]
            .iter()
            .all(|hash| hex(hash, 64))
        {
            return Err(INVALID);
        }
        let line = raw.strip_suffix(b"\n").ok_or(INVALID)?;
        if line.is_empty()
            || line.contains(&b'\n')
            || canonicalize(line).map_err(|_| INVALID)? != line
        {
            return Err(INVALID);
        }
        let value: Value = serde_json::from_slice(line).map_err(|_| INVALID)?;
        let fields = value.as_object().ok_or(INVALID)?;
        let terminal = value["terminal"].as_object().ok_or(INVALID)?;
        let report = value["diagnostic_report"].as_object().ok_or(INVALID)?;
        if fields.len() != 9
            || value["schema"] != "hol-gauntlet-rust-deterministic-readback.v1"
            || value["job_id"] != self.pins.job_id
            || value["source_sha"] != self.pins.source_sha
            || value["execution_eligible"] != false
            || terminal.len() != 13
            || report["schema"] != "hol-gauntlet-rust-deterministic-run-diagnostic.v1"
            || report["job_id"] != self.pins.job_id
            || report["source_sha"] != self.pins.source_sha
            || report["deployment_digest"] != self.pins.deployment_digest
            || report["worker_generation"] != self.pins.worker_generation
            || report["started_marker_sha256"] != self.pins.started_marker_sha256
            || report["controller_key_pin_sha256"] != self.pins.controller_key_pin_sha256
            || report["controller_public_key_hex"] != self.pins.controller_public_key_hex
            || report["independent_control_verdict"] != false
            || report["execution_eligible"] != false
        {
            return Err(INVALID);
        }
        let terminal_raw =
            canonicalize(value["terminal"].to_string().as_bytes()).map_err(|_| INVALID)?;
        let report_raw =
            canonicalize(value["diagnostic_report"].to_string().as_bytes()).map_err(|_| INVALID)?;
        let terminal_sha256 = format!("{:x}", Sha256::digest(&terminal_raw));
        let diagnostic_sha256 = format!("{:x}", Sha256::digest(&report_raw));
        if terminal_sha256 != expected_terminal_sha256
            || diagnostic_sha256 != expected_diagnostic_sha256
            || value["terminal_sha256"] != terminal_sha256
            || value["diagnostic_report_sha256"] != diagnostic_sha256
            || value["deterministic_report_sha256"] != expected_deterministic_sha256
            || report["deterministic_report_sha256"] != expected_deterministic_sha256
        {
            return Err(INVALID);
        }
        let keyed = self.observe_keyed_terminal(&terminal_raw, &report_raw)?;
        if keyed.producer_status != "invalid-evidence"
            || report["exit_code"] != keyed.exit_code
            || report["process"]["pid"] != keyed.pid
            || report["process"]["start_ticks"] != keyed.process_start_ticks
        {
            return Err(INVALID);
        }
        let producer = report["producer_status_claim"]
            .as_str()
            .filter(|status| matches!(*status, "passed" | "failed" | "invalid-evidence"))
            .ok_or(INVALID)?;
        Ok(HostDeterministicReadbackObservation {
            host_pin_record_sha256: self.raw_sha256.clone(),
            terminal_sha256,
            diagnostic_report_sha256: diagnostic_sha256,
            deterministic_report_sha256: expected_deterministic_sha256.to_owned(),
            controller_exit_code: keyed.exit_code,
            producer_status_claim: producer.to_owned(),
        })
    }

    /// Call the fixed Root readback binary over Lima after the guest process
    /// exits. The binary hashes its own ELF and reopens the keyed terminal and
    /// deterministic report; this host still treats the VM as untrusted for
    /// eligibility until independent provenance and effect checks exist.
    #[allow(clippy::too_many_arguments)]
    pub fn observe_fixed_vm_deterministic_readback(
        &self,
        limactl: &str,
        vm: &str,
        reader_binary_sha256: &str,
        expected_terminal_sha256: &str,
        expected_diagnostic_sha256: &str,
        expected_deterministic_sha256: &str,
    ) -> Result<HostDeterministicReadbackObservation, HostKeyPinError> {
        use crate::fixed_process::{run_fixed, FixedProcessError};

        if !Path::new(limactl).is_absolute()
            || vm.is_empty()
            || !vm
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !hex(reader_binary_sha256, 64)
        {
            return Err(HostKeyPinError::InvalidPins);
        }
        let binary =
            format!("/opt/hol-gauntlet/rust-deterministic-readback-{reader_binary_sha256}");
        let argv = vec![
            limactl.to_owned(),
            "shell".to_owned(),
            vm.to_owned(),
            "--".to_owned(),
            "sudo".to_owned(),
            "-n".to_owned(),
            binary,
            self.pins.source_sha.clone(),
            self.pins.job_id.clone(),
            self.pins.deployment_digest.clone(),
            self.pins.worker_generation.clone(),
            reader_binary_sha256.to_owned(),
        ];
        let raw =
            run_fixed(&argv, Duration::from_secs(60), 16 * 1024, 1024, &[]).map_err(|error| {
                match error {
                    FixedProcessError::TimedOut => HostKeyPinError::TransportTimedOut,
                    FixedProcessError::TooLarge => HostKeyPinError::FrameTooLarge,
                    FixedProcessError::Unavailable | FixedProcessError::Failed => {
                        HostKeyPinError::TransportFailed
                    }
                }
            })?;
        self.observe_deterministic_readback(
            &raw,
            expected_terminal_sha256,
            expected_diagnostic_sha256,
            expected_deterministic_sha256,
        )
    }
}
