//! Data-only composition of a host-retained prelaunch key pin with one keyed
//! VM terminal and exact report bytes. Producer status remains unauthenticated.

use super::{hex, HostKeyPinError, HostKeyPinRecord};
use gauntlet_contracts::{canonicalize, MAX_RECORD_BYTES};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const TERMINAL_SCHEMA: &str = "hol-gauntlet-worker-terminal.v2";
const MAX_TERMINAL_BYTES: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyedTerminalObservation {
    pub host_pin_record_sha256: String,
    pub terminal_sha256: String,
    pub report_sha256: String,
    pub pid: u32,
    pub process_start_ticks: u64,
    pub exit_code: i32,
    pub producer_status: String,
}

impl HostKeyedTerminalObservation {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-host-keyed-terminal-observation.v1",
            "host_pin_record_sha256":self.host_pin_record_sha256,
            "terminal_sha256":self.terminal_sha256,
            "report_sha256":self.report_sha256,
            "pid":self.pid,
            "process_start_ticks":self.process_start_ticks,
            "exit_code":self.exit_code,
            "producer_status":self.producer_status,
            "execution_eligible":false,
        })
    }
}

impl HostKeyPinRecord {
    /// Bind canonical terminal and report bytes to the host's already durable
    /// key pin. Transport, worker provenance, signature verification, physical
    /// observations and verdict recomputation remain separate requirements.
    pub fn observe_keyed_terminal(
        &self,
        terminal_raw: &[u8],
        report_raw: &[u8],
    ) -> Result<HostKeyedTerminalObservation, HostKeyPinError> {
        if terminal_raw.is_empty()
            || terminal_raw.len() > MAX_TERMINAL_BYTES
            || report_raw.is_empty()
            || report_raw.len() > MAX_RECORD_BYTES
            || canonicalize(terminal_raw).map_err(|_| HostKeyPinError::InvalidTerminal)?
                != terminal_raw
            || canonicalize(report_raw).map_err(|_| HostKeyPinError::InvalidTerminal)? != report_raw
        {
            return Err(HostKeyPinError::InvalidTerminal);
        }
        let value: Value =
            serde_json::from_slice(terminal_raw).map_err(|_| HostKeyPinError::InvalidTerminal)?;
        let fields = value.as_object().ok_or(HostKeyPinError::InvalidTerminal)?;
        let report_sha256 = format!("{:x}", Sha256::digest(report_raw));
        let pid = value["pid"]
            .as_u64()
            .and_then(|number| u32::try_from(number).ok())
            .filter(|number| *number > 0)
            .ok_or(HostKeyPinError::InvalidTerminal)?;
        let start_ticks = value["process_start_ticks"]
            .as_u64()
            .filter(|number| *number > 0)
            .ok_or(HostKeyPinError::InvalidTerminal)?;
        let exit_code = value["exit_code"]
            .as_i64()
            .and_then(|number| i32::try_from(number).ok())
            .filter(|number| (-128..=255).contains(number))
            .ok_or(HostKeyPinError::InvalidTerminal)?;
        let status = value["status"]
            .as_str()
            .filter(|status| matches!(*status, "passed" | "failed" | "invalid-evidence"))
            .ok_or(HostKeyPinError::InvalidTerminal)?;
        if fields.len() != 13
            || value["schema"] != TERMINAL_SCHEMA
            || value["job_id"] != self.pins.job_id
            || value["source_sha"] != self.pins.source_sha
            || value["deployment_digest"] != self.pins.deployment_digest
            || value["worker_generation"] != self.pins.worker_generation
            || value["started_marker_sha256"] != self.pins.started_marker_sha256
            || value["controller_key_pin_sha256"] != self.pins.controller_key_pin_sha256
            || value["controller_public_key_hex"] != self.pins.controller_public_key_hex
            || value["report_sha256"] != report_sha256
            || !value["report_sha256"]
                .as_str()
                .is_some_and(|sha| hex(sha, 64))
            || status == "passed" && exit_code != 0
        {
            return Err(HostKeyPinError::InvalidTerminal);
        }
        Ok(HostKeyedTerminalObservation {
            host_pin_record_sha256: self.raw_sha256.clone(),
            terminal_sha256: format!("{:x}", Sha256::digest(terminal_raw)),
            report_sha256,
            pid,
            process_start_ticks: start_ticks,
            exit_code,
            producer_status: status.to_owned(),
        })
    }
}
