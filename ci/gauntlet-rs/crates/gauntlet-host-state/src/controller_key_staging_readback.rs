//! Fixed Mac/Lima readback of one completed Root-forwarded staging tap.
//! The VM remains a producer; this authenticates custody against the outside
//! prelaunch key and post-run tap pins without awarding a control verdict.

use super::{hex, HostKeyPinError, HostKeyPinRecord, HostSdkTapJournalPin};
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;

const INVALID: HostKeyPinError = HostKeyPinError::InvalidTapJournal;
const MAX_READBACK_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostStagingRestartReadbackObservation {
    pub run_id: String,
    pub role: String,
    pub host_key_record_sha256: String,
    pub host_tap_pin_sha256: String,
    pub terminal_sha256: String,
    pub report_sha256: String,
    pub tap_journal_sha256: String,
}

impl HostStagingRestartReadbackObservation {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-host-staging-restart-readback.v1",
            "run_id":self.run_id,
            "role":self.role,
            "host_key_record_sha256":self.host_key_record_sha256,
            "host_tap_pin_sha256":self.host_tap_pin_sha256,
            "terminal_sha256":self.terminal_sha256,
            "report_sha256":self.report_sha256,
            "tap_journal_sha256":self.tap_journal_sha256,
            "restart_state":"verified-ineligible-terminal",
            "independent_control_verdict":false,
            "execution_eligible":false,
        })
    }
}

impl HostKeyPinRecord {
    /// Match one canonical guest restart readback to both durable host pins.
    pub fn observe_staging_restart_readback(
        &self,
        raw: &[u8],
        tap: &HostSdkTapJournalPin,
    ) -> Result<HostStagingRestartReadbackObservation, HostKeyPinError> {
        if raw.len() > MAX_READBACK_BYTES
            || tap.run_id != self.pins.job_id
            || tap.host_key_record_sha256 != self.raw_sha256
            || !hex(&tap.raw_sha256, 64)
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
        let role = value["role"]
            .as_str()
            .filter(|role| {
                matches!(
                    *role,
                    "success" | "input-binding" | "injection" | "boundary" | "timeout" | "cancel"
                )
            })
            .ok_or(INVALID)?;
        if fields.len() != 17
            || value["schema"] != "hol-gauntlet-staging-tap-restart-readback.v1"
            || value["run_id"] != self.pins.job_id
            || value["source_sha"] != self.pins.source_sha
            || value["config_digest"] != self.pins.deployment_digest
            || value["worker_generation_sha256"] != self.pins.worker_generation
            || value["started_marker_sha256"] != self.pins.started_marker_sha256
            || value["controller_key_pin_sha256"] != self.pins.controller_key_pin_sha256
            || value["controller_public_key_hex"] != self.pins.controller_public_key_hex
            || value["terminal_sha256"] != tap.terminal_sha256
            || value["report_sha256"] != tap.report_sha256
            || value["tap_journal_sha256"] != tap.journal_sha256
            || value["state"] != "verified-ineligible-terminal"
            || value["one_use_tap_tombstone_empty"] != true
            || value["controller_tap_and_product_cgroups_absent"] != true
            || value["conformance_package_created"] != false
            || value["execution_eligible"] != false
        {
            return Err(INVALID);
        }
        Ok(HostStagingRestartReadbackObservation {
            run_id: self.pins.job_id.clone(),
            role: role.to_owned(),
            host_key_record_sha256: self.raw_sha256.clone(),
            host_tap_pin_sha256: tap.raw_sha256.clone(),
            terminal_sha256: tap.terminal_sha256.clone(),
            report_sha256: tap.report_sha256.clone(),
            tap_journal_sha256: tap.journal_sha256.clone(),
        })
    }

    /// Invoke only the SHA-named Root guest reader through the fixed Lima VM.
    pub fn observe_fixed_vm_staging_restart_readback(
        &self,
        limactl: &str,
        vm: &str,
        reader_binary_sha256: &str,
        tap: &HostSdkTapJournalPin,
    ) -> Result<HostStagingRestartReadbackObservation, HostKeyPinError> {
        use crate::fixed_process::{run_fixed, FixedProcessError};

        if !Path::new(limactl).is_absolute()
            || vm.is_empty()
            || !vm
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !hex(reader_binary_sha256, 64)
            || tap.run_id != self.pins.job_id
            || tap.host_key_record_sha256 != self.raw_sha256
        {
            return Err(HostKeyPinError::InvalidPins);
        }
        let binary =
            format!("/opt/hol-gauntlet/rust-staging-tap-restart-readback-{reader_binary_sha256}");
        let argv = vec![
            limactl.to_owned(),
            "shell".to_owned(),
            vm.to_owned(),
            "--".to_owned(),
            "sudo".to_owned(),
            "-n".to_owned(),
            binary,
            self.pins.job_id.clone(),
            self.pins.source_sha.clone(),
            self.pins.deployment_digest.clone(),
            self.pins.worker_generation.clone(),
            self.pins.started_marker_sha256.clone(),
            self.pins.controller_key_pin_sha256.clone(),
            tap.terminal_sha256.clone(),
            tap.report_sha256.clone(),
            tap.journal_sha256.clone(),
            reader_binary_sha256.to_owned(),
        ];
        let raw = run_fixed(
            &argv,
            Duration::from_secs(60),
            MAX_READBACK_BYTES,
            1024,
            &[],
        )
        .map_err(|error| match error {
            FixedProcessError::TimedOut => HostKeyPinError::TransportTimedOut,
            FixedProcessError::TooLarge => HostKeyPinError::FrameTooLarge,
            FixedProcessError::Unavailable | FixedProcessError::Failed => {
                HostKeyPinError::TransportFailed
            }
        })?;
        self.observe_staging_restart_readback(&raw, tap)
    }
}
