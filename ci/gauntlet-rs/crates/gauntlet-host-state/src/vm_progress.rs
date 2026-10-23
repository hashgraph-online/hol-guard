//! Fixed read-only Python VM worker progress call. This is a shadow probe;
//! its response is untrusted telemetry and cannot prove worker termination.

use crate::fixed_process::{run_fixed_input, FixedProcessError};
use crate::load_operations_bytes;
use gauntlet_contracts::{canonicalize, is_git_sha};
use serde_json::{json, Value};
use std::fmt;
use std::time::Duration;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmProgressError {
    InvalidConfig,
    InvalidIdentity,
    InvalidResponse,
    TooLarge,
    Unavailable,
    TimedOut,
}

impl fmt::Display for VmProgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid reviewed VM worker configuration",
            Self::InvalidIdentity => "invalid source or job identity for VM progress",
            Self::InvalidResponse => "VM progress response identity or structure differs",
            Self::TooLarge => "VM progress response exceeds byte limit",
            Self::Unavailable => "VM progress probe unavailable",
            Self::TimedOut => "VM progress probe timed out",
        })
    }
}

impl std::error::Error for VmProgressError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmProgressPlan {
    pub argv: Vec<String>,
    pub request: Value,
    source_sha: String,
    job_id: String,
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl VmProgressPlan {
    /// Freeze only Python `Agent.worker(job, "progress", timeout=12)`'s
    /// fixed call. The caller must source the job from trusted state.
    pub fn new(
        operations: &Value,
        source_sha: &str,
        job_id: &str,
        deployment_digest: Option<&str>,
    ) -> Result<Self, VmProgressError> {
        let raw = serde_json::to_vec(operations).map_err(|_| VmProgressError::InvalidConfig)?;
        let config = load_operations_bytes(&raw).map_err(|_| VmProgressError::InvalidConfig)?;
        if !is_git_sha(source_sha)
            || !lower_hex(job_id, 16)
            || deployment_digest.is_some_and(|digest| !lower_hex(digest, 64))
        {
            return Err(VmProgressError::InvalidIdentity);
        }
        let limactl = config["limactl"]
            .as_str()
            .ok_or(VmProgressError::InvalidConfig)?;
        let vm = config["vm"]
            .as_str()
            .ok_or(VmProgressError::InvalidConfig)?;
        let python = config["guest_python"]
            .as_str()
            .ok_or(VmProgressError::InvalidConfig)?;
        let mut request = json!({
            "action":"progress",
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
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "argv":self.argv,
            "request":self.request,
            "timeout_seconds":12,
            "read_only":true,
            "admission_eligible":false,
        })
    }

    /// Validate the Python worker's bounded progress JSON and outside job
    /// identity. This does not authenticate that the worker observed a live
    /// process; `process_alive` remains a producer-reported field.
    pub fn parse_response(&self, stdout: &[u8]) -> Result<Value, VmProgressError> {
        if stdout.len() > MAX_RESPONSE_BYTES {
            return Err(VmProgressError::TooLarge);
        }
        let canonical = canonicalize(stdout).map_err(|_| VmProgressError::InvalidResponse)?;
        let value: Value =
            serde_json::from_slice(&canonical).map_err(|_| VmProgressError::InvalidResponse)?;
        let object = value.as_object().ok_or(VmProgressError::InvalidResponse)?;
        let phase = object
            .get("phase")
            .and_then(Value::as_str)
            .ok_or(VmProgressError::InvalidResponse)?;
        if object.get("source_sha").and_then(Value::as_str) != Some(&self.source_sha)
            || object.get("job_id").and_then(Value::as_str) != Some(&self.job_id)
            || phase.is_empty()
            || phase.len() > 64
            || !phase
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || object
                .get("checked_at")
                .and_then(Value::as_f64)
                .filter(|time| time.is_finite() && *time > 0.0)
                .is_none()
            || object
                .get("process_alive")
                .is_some_and(|value| !value.is_boolean())
        {
            return Err(VmProgressError::InvalidResponse);
        }
        Ok(value)
    }

    /// Execute the fixed progress request only. No run/reconcile/stage action
    /// can be selected through this plan.
    pub fn execute_read_only(&self) -> Result<Value, VmProgressError> {
        let input =
            serde_json::to_vec(&self.request).map_err(|_| VmProgressError::InvalidIdentity)?;
        let stdout = run_fixed_input(
            &self.argv,
            Some(&input),
            Duration::from_secs(12),
            MAX_RESPONSE_BYTES,
            1500,
            &[],
        )
        .map_err(|error| match error {
            FixedProcessError::Unavailable | FixedProcessError::Failed => {
                VmProgressError::Unavailable
            }
            FixedProcessError::TimedOut => VmProgressError::TimedOut,
            FixedProcessError::TooLarge => VmProgressError::TooLarge,
        })?;
        self.parse_response(&stdout)
    }
}
