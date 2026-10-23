//! Fixed read-only Lima probe for an isolated Rust VM worker shadow binary.
//! The binary path is derived from an outside hash but is not attested here.

use crate::fixed_process::{run_fixed_input, FixedProcessError};
use crate::load_operations_bytes;
use gauntlet_contracts::{canonicalize, WorkerRequest, WorkerResponse};
use serde_json::{json, Value};
use std::fmt;
use std::time::Duration;

const MAX_RESPONSE_BYTES: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmRustShadowError {
    InvalidConfig,
    InvalidPins,
    InvalidResponse,
    Unavailable,
    TimedOut,
    TooLarge,
}

impl fmt::Display for VmRustShadowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid VM operations configuration",
            Self::InvalidPins => "invalid outside Rust worker shadow pins",
            Self::InvalidResponse => "Rust VM worker shadow response refused",
            Self::Unavailable => "Rust VM worker shadow unavailable",
            Self::TimedOut => "Rust VM worker shadow timed out",
            Self::TooLarge => "Rust VM worker shadow response too large",
        })
    }
}

impl std::error::Error for VmRustShadowError {}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmRustShadowPlan {
    pub argv: Vec<String>,
    pub request: Value,
    expected: WorkerRequest,
    deployment_digest: String,
    worker_generation: String,
    binary_sha256: String,
}

impl VmRustShadowPlan {
    /// Plan only a read-only `progress` call. The guest path has one fixed
    /// directory and basename derived from the complete caller-supplied hash;
    /// no `run`, shell, path or command selector is accepted from a job.
    pub fn new(
        operations: &Value,
        source_sha: &str,
        job_id: &str,
        deployment_digest: &str,
        worker_generation: &str,
        binary_sha256: &str,
    ) -> Result<Self, VmRustShadowError> {
        let config = load_operations_bytes(
            &serde_json::to_vec(operations).map_err(|_| VmRustShadowError::InvalidConfig)?,
        )
        .map_err(|_| VmRustShadowError::InvalidConfig)?;
        if !lower_hex(deployment_digest, 64)
            || !lower_hex(worker_generation, 64)
            || !lower_hex(binary_sha256, 64)
        {
            return Err(VmRustShadowError::InvalidPins);
        }
        let request = json!({
            "schema":"hol-gauntlet-worker-request.v1",
            "action":"progress",
            "source_sha":source_sha,
            "job_id":job_id,
        });
        let raw = canonicalize(request.to_string().as_bytes())
            .map_err(|_| VmRustShadowError::InvalidPins)?;
        let expected = WorkerRequest::parse(&raw).map_err(|_| VmRustShadowError::InvalidPins)?;
        let limactl = config["limactl"]
            .as_str()
            .ok_or(VmRustShadowError::InvalidConfig)?;
        let vm = config["vm"]
            .as_str()
            .ok_or(VmRustShadowError::InvalidConfig)?;
        Ok(Self {
            argv: vec![
                limactl.to_owned(),
                "shell".to_owned(),
                vm.to_owned(),
                "--".to_owned(),
                "sudo".to_owned(),
                "-n".to_owned(),
                format!("/opt/hol-gauntlet/rust-worker-shadow-{binary_sha256}"),
                source_sha.to_owned(),
                deployment_digest.to_owned(),
                worker_generation.to_owned(),
            ],
            request,
            expected,
            deployment_digest: deployment_digest.to_owned(),
            worker_generation: worker_generation.to_owned(),
            binary_sha256: binary_sha256.to_owned(),
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "argv":self.argv,
            "request":self.request,
            "binary_sha256":self.binary_sha256,
            "binary_pin_verified":false,
            "timeout_seconds":12,
            "read_only":true,
            "execution_eligible":false,
        })
    }

    pub fn parse_response(&self, stdout: &[u8]) -> Result<WorkerResponse, VmRustShadowError> {
        if stdout.len() > MAX_RESPONSE_BYTES + 1 {
            return Err(VmRustShadowError::TooLarge);
        }
        let frame = stdout
            .strip_suffix(b"\n")
            .filter(|frame| !frame.is_empty() && !frame.contains(&b'\n'))
            .ok_or(VmRustShadowError::InvalidResponse)?;
        if canonicalize(frame).map_err(|_| VmRustShadowError::InvalidResponse)? != frame {
            return Err(VmRustShadowError::InvalidResponse);
        }
        let response =
            WorkerResponse::parse(frame).map_err(|_| VmRustShadowError::InvalidResponse)?;
        response
            .bind_request(
                &self.expected,
                &self.worker_generation,
                Some(&self.deployment_digest),
            )
            .map_err(|_| VmRustShadowError::InvalidResponse)?;
        Ok(response)
    }

    pub fn execute_read_only(&self) -> Result<WorkerResponse, VmRustShadowError> {
        let mut input = canonicalize(self.request.to_string().as_bytes())
            .map_err(|_| VmRustShadowError::InvalidPins)?;
        input.push(b'\n');
        let stdout = run_fixed_input(
            &self.argv,
            Some(&input),
            Duration::from_secs(12),
            MAX_RESPONSE_BYTES + 1,
            1500,
            &[],
        )
        .map_err(|error| match error {
            FixedProcessError::Unavailable | FixedProcessError::Failed => {
                VmRustShadowError::Unavailable
            }
            FixedProcessError::TimedOut => VmRustShadowError::TimedOut,
            FixedProcessError::TooLarge => VmRustShadowError::TooLarge,
        })?;
        self.parse_response(&stdout)
    }
}
