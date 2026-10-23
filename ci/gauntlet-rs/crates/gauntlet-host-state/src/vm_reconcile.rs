//! Fixed read-only query for one retained Python worker receipt. A response is
//! producer data, not an independently authenticated benchmark verdict.

use crate::fixed_process::{run_fixed_input, FixedProcessError};
use crate::load_operations_bytes;
use gauntlet_contracts::{canonicalize, is_git_sha};
use serde_json::{json, Value};
use std::fmt;
use std::time::Duration;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const UNKNOWN_ERROR: &str = "No terminal worker receipt; inspect VM before admitting more work";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmReconcileError {
    InvalidConfig,
    InvalidIdentity,
    InvalidResponse,
    TooLarge,
    Unavailable,
    TimedOut,
}

impl fmt::Display for VmReconcileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid reviewed VM worker configuration",
            Self::InvalidIdentity => "invalid retained source or job identity",
            Self::InvalidResponse => "VM reconcile response identity or structure differs",
            Self::TooLarge => "VM reconcile response exceeds byte limit",
            Self::Unavailable => "VM reconcile probe unavailable",
            Self::TimedOut => "VM reconcile probe timed out",
        })
    }
}

impl std::error::Error for VmReconcileError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmReconcilePlan {
    pub argv: Vec<String>,
    pub request: Value,
    source_sha: String,
    job_id: String,
    deployment_digest: Option<String>,
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl VmReconcilePlan {
    /// Freeze Python `Agent.worker(job, "reconcile")` without letting a caller
    /// select another worker action, VM command or output path.
    pub fn new(
        operations: &Value,
        source_sha: &str,
        job_id: &str,
        deployment_digest: Option<&str>,
    ) -> Result<Self, VmReconcileError> {
        let raw = serde_json::to_vec(operations).map_err(|_| VmReconcileError::InvalidConfig)?;
        let config = load_operations_bytes(&raw).map_err(|_| VmReconcileError::InvalidConfig)?;
        if !is_git_sha(source_sha)
            || !lower_hex(job_id, 16)
            || deployment_digest.is_some_and(|digest| !lower_hex(digest, 64))
        {
            return Err(VmReconcileError::InvalidIdentity);
        }
        let limactl = config["limactl"]
            .as_str()
            .ok_or(VmReconcileError::InvalidConfig)?;
        let vm = config["vm"]
            .as_str()
            .ok_or(VmReconcileError::InvalidConfig)?;
        let python = config["guest_python"]
            .as_str()
            .ok_or(VmReconcileError::InvalidConfig)?;
        let mut request = json!({
            "action":"reconcile",
            "source_sha":source_sha,
            "job_id":job_id,
        });
        if let Some(digest) = deployment_digest {
            request["deployment_digest"] = json!(digest);
        }
        Ok(Self {
            argv: vec![
                limactl.to_owned(),
                "shell".to_owned(),
                vm.to_owned(),
                "--".to_owned(),
                "sudo".to_owned(),
                "-n".to_owned(),
                python.to_owned(),
                "-I".to_owned(),
                "-B".to_owned(),
                "/opt/hol-gauntlet/worker.py".to_owned(),
            ],
            request,
            source_sha: source_sha.to_owned(),
            job_id: job_id.to_owned(),
            deployment_digest: deployment_digest.map(str::to_owned),
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "argv":self.argv,
            "request":self.request,
            "timeout_seconds":30,
            "read_only":true,
            "admission_eligible":false,
        })
    }

    /// Parse the exact missing-receipt marker or an identity-bound terminal
    /// receipt. An absent outside deployment pin cannot authenticate a receipt.
    pub fn parse_response(&self, stdout: &[u8]) -> Result<Value, VmReconcileError> {
        if stdout.len() > MAX_RESPONSE_BYTES {
            return Err(VmReconcileError::TooLarge);
        }
        let canonical = canonicalize(stdout).map_err(|_| VmReconcileError::InvalidResponse)?;
        let value: Value =
            serde_json::from_slice(&canonical).map_err(|_| VmReconcileError::InvalidResponse)?;
        if value == json!({"status":"unknown","error":UNKNOWN_ERROR}) {
            return Ok(value);
        }
        let object = value.as_object().ok_or(VmReconcileError::InvalidResponse)?;
        let expected_digest = self
            .deployment_digest
            .as_deref()
            .ok_or(VmReconcileError::InvalidResponse)?;
        let expected_path = format!("/var/lib/hol-gauntlet/outputs/{}/report", self.job_id);
        let valid_status = object
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| {
                !status.is_empty()
                    && status != "unknown"
                    && status.len() <= 64
                    && status
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            });
        if object.get("source_sha").and_then(Value::as_str) != Some(&self.source_sha)
            || object.get("job_id").and_then(Value::as_str) != Some(&self.job_id)
            || object.get("deployment_digest").and_then(Value::as_str) != Some(expected_digest)
            || object.get("report_path").and_then(Value::as_str) != Some(expected_path.as_str())
            || !valid_status
            || object
                .get("exit_code")
                .and_then(Value::as_i64)
                .filter(|code| (-128..=255).contains(code))
                .is_none()
            || object.get("model_tokens").and_then(Value::as_u64) != Some(0)
            || object.get("report_sha256").is_some_and(|digest| {
                !digest.is_null() && !digest.as_str().is_some_and(|text| lower_hex(text, 64))
            })
            || object
                .get("cells")
                .is_some_and(|cells| cells.as_array().is_none_or(|rows| rows.len() > 1024))
        {
            return Err(VmReconcileError::InvalidResponse);
        }
        Ok(value)
    }

    /// Query the fixed Python worker's read-only `reconcile` action. This does
    /// not acquire a host lease, call `Agent.finish`, or write a GitHub status.
    pub fn execute_read_only(&self) -> Result<Value, VmReconcileError> {
        let input =
            serde_json::to_vec(&self.request).map_err(|_| VmReconcileError::InvalidIdentity)?;
        let stdout = run_fixed_input(
            &self.argv,
            Some(&input),
            Duration::from_secs(30),
            MAX_RESPONSE_BYTES,
            1500,
            &[],
        )
        .map_err(|error| match error {
            FixedProcessError::Unavailable | FixedProcessError::Failed => {
                VmReconcileError::Unavailable
            }
            FixedProcessError::TimedOut => VmReconcileError::TimedOut,
            FixedProcessError::TooLarge => VmReconcileError::TooLarge,
        })?;
        self.parse_response(&stdout)
    }

    /// Reproduce Python `Agent.finish`'s terminal state mapping for a parsed
    /// response. The mapping is diagnostic until receipt bytes and report
    /// results are independently authenticated by a trusted VM worker.
    pub fn classify_terminal(&self, response: &Value) -> Result<Value, VmReconcileError> {
        let raw = serde_json::to_vec(response).map_err(|_| VmReconcileError::InvalidResponse)?;
        let parsed = self.parse_response(&raw)?;
        if parsed.get("status").and_then(Value::as_str) == Some("unknown") {
            return Err(VmReconcileError::InvalidResponse);
        }
        let code = parsed["exit_code"]
            .as_i64()
            .ok_or(VmReconcileError::InvalidResponse)?;
        let passed =
            code == 0 && parsed["status"] == "passed" && parsed["report_sha256"].as_str().is_some();
        let (state, posted_state) = if passed {
            ("passed", "success")
        } else if code == 1 {
            ("failed", "failure")
        } else {
            ("invalid-evidence", "error")
        };
        Ok(json!({
            "state":state,
            "post_state":posted_state,
            "description":format!("Gauntlet {state} (deterministic, zero inference)"),
            "producer_receipt_only":true,
            "admission_eligible":false,
        }))
    }
}
