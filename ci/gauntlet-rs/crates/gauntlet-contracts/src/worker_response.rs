//! Bounded, data-only responses for the proposed Linux VM worker.
//!
//! These records are untrusted until a caller authenticates the worker channel,
//! verifies Root-owned receipts and independently pins the worker/deployment.

use crate::{canonicalize, is_git_sha, WorkerAction, WorkerRequest};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fmt;

const SCHEMA: &str = "hol-gauntlet-worker-response.v1";
const MAX_RESPONSE_BYTES: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    Unavailable,
    NotStarted,
    Staged,
    Running,
    Unknown,
    Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerResponse {
    action: WorkerAction,
    source_sha: String,
    job_id: String,
    worker_generation: String,
    state: WorkerState,
    deployment_digest: Option<String>,
    started_marker_sha256: Option<String>,
    report_sha256: Option<String>,
    pid: Option<u32>,
    process_start_ticks: Option<u64>,
    exit_code: Option<i32>,
    status: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerResponseError {
    InvalidJson,
    UnsupportedSchema,
    InvalidFields,
    InvalidIdentity,
    InvalidState,
    ExternalPinMismatch,
}

impl fmt::Display for WorkerResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidJson => "invalid bounded worker response JSON",
            Self::UnsupportedSchema => "unsupported worker response schema or action",
            Self::InvalidFields => "worker response contains unknown or misplaced fields",
            Self::InvalidIdentity => "invalid worker, source or job identity",
            Self::InvalidState => "invalid worker state, process identity or terminal outcome",
            Self::ExternalPinMismatch => "worker response differs from independent request or pin",
        })
    }
}

impl std::error::Error for WorkerResponseError {}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl WorkerResponse {
    pub fn state(&self) -> WorkerState {
        self.state
    }

    pub fn deployment_digest(&self) -> Option<&str> {
        self.deployment_digest.as_deref()
    }

    pub fn report_sha256(&self) -> Option<&str> {
        self.report_sha256.as_deref()
    }

    pub fn started_marker_sha256(&self) -> Option<&str> {
        self.started_marker_sha256.as_deref()
    }

    pub fn process_identity(&self) -> Option<(u32, u64)> {
        self.pid.zip(self.process_start_ticks)
    }

    pub fn terminal_outcome(&self) -> Option<(i32, &str)> {
        self.exit_code.zip(self.status.as_deref())
    }

    pub fn parse(raw: &[u8]) -> Result<Self, WorkerResponseError> {
        if raw.len() > MAX_RESPONSE_BYTES {
            return Err(WorkerResponseError::InvalidJson);
        }
        let canonical = canonicalize(raw).map_err(|_| WorkerResponseError::InvalidJson)?;
        let value: Value =
            serde_json::from_slice(&canonical).map_err(|_| WorkerResponseError::InvalidJson)?;
        if value["schema"] != SCHEMA {
            return Err(WorkerResponseError::UnsupportedSchema);
        }
        let action = match value["action"].as_str() {
            Some("inspect") => WorkerAction::Inspect,
            Some("progress") => WorkerAction::Progress,
            Some("reconcile") => WorkerAction::Reconcile,
            Some("run") => WorkerAction::Run,
            _ => return Err(WorkerResponseError::UnsupportedSchema),
        };
        let state = match value["state"].as_str() {
            Some("unavailable") => WorkerState::Unavailable,
            Some("not-started") => WorkerState::NotStarted,
            Some("staged") => WorkerState::Staged,
            Some("running") => WorkerState::Running,
            Some("unknown") => WorkerState::Unknown,
            Some("terminal") => WorkerState::Terminal,
            _ => return Err(WorkerResponseError::InvalidState),
        };
        if !matches!(
            (action, state),
            (
                WorkerAction::Inspect,
                WorkerState::Unavailable | WorkerState::Staged
            ) | (
                WorkerAction::Progress,
                WorkerState::Unavailable
                    | WorkerState::NotStarted
                    | WorkerState::Running
                    | WorkerState::Unknown
                    | WorkerState::Terminal
            ) | (
                WorkerAction::Reconcile,
                WorkerState::Unavailable | WorkerState::Unknown | WorkerState::Terminal
            ) | (
                WorkerAction::Run,
                WorkerState::Unavailable
                    | WorkerState::Running
                    | WorkerState::Unknown
                    | WorkerState::Terminal
            )
        ) {
            return Err(WorkerResponseError::InvalidState);
        }
        let fields: BTreeSet<&str> = value
            .as_object()
            .ok_or(WorkerResponseError::InvalidFields)?
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected: BTreeSet<&str> = [
            "schema",
            "action",
            "source_sha",
            "job_id",
            "worker_generation",
            "state",
        ]
        .into_iter()
        .collect();
        if matches!(
            state,
            WorkerState::Staged | WorkerState::Running | WorkerState::Terminal
        ) {
            expected.insert("deployment_digest");
        }
        if matches!(state, WorkerState::Running | WorkerState::Terminal) {
            expected.insert("started_marker_sha256");
        }
        if state == WorkerState::Running {
            expected.extend(["pid", "process_start_ticks"]);
        }
        if state == WorkerState::Terminal {
            expected.extend(["report_sha256", "exit_code", "status"]);
        }
        if fields != expected {
            return Err(WorkerResponseError::InvalidFields);
        }
        let source_sha = value["source_sha"]
            .as_str()
            .filter(|sha| is_git_sha(sha))
            .ok_or(WorkerResponseError::InvalidIdentity)?;
        let job_id = value["job_id"]
            .as_str()
            .filter(|job| lowercase_hex(job, 16))
            .ok_or(WorkerResponseError::InvalidIdentity)?;
        let worker_generation = value["worker_generation"]
            .as_str()
            .filter(|generation| lowercase_hex(generation, 64))
            .ok_or(WorkerResponseError::InvalidIdentity)?;
        let digest = |name| {
            value[name]
                .as_str()
                .filter(|digest| lowercase_hex(digest, 64))
                .map(str::to_owned)
                .ok_or(WorkerResponseError::InvalidIdentity)
        };
        let deployment_digest = matches!(
            state,
            WorkerState::Staged | WorkerState::Running | WorkerState::Terminal
        )
        .then(|| digest("deployment_digest"))
        .transpose()?;
        let started_marker_sha256 = matches!(state, WorkerState::Running | WorkerState::Terminal)
            .then(|| digest("started_marker_sha256"))
            .transpose()?;
        let report_sha256 = (state == WorkerState::Terminal)
            .then(|| digest("report_sha256"))
            .transpose()?;
        let (pid, process_start_ticks) = if state == WorkerState::Running {
            let pid = value["pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok());
            let ticks = value["process_start_ticks"].as_u64();
            match (pid, ticks) {
                (Some(pid), Some(ticks)) if pid > 0 && ticks > 0 => (Some(pid), Some(ticks)),
                _ => return Err(WorkerResponseError::InvalidState),
            }
        } else {
            (None, None)
        };
        let (exit_code, status) = if state == WorkerState::Terminal {
            let exit = value["exit_code"]
                .as_i64()
                .and_then(|exit| i32::try_from(exit).ok())
                .filter(|exit| (-128..=255).contains(exit))
                .ok_or(WorkerResponseError::InvalidState)?;
            let status = value["status"]
                .as_str()
                .filter(|status| matches!(*status, "passed" | "failed" | "invalid-evidence"))
                .ok_or(WorkerResponseError::InvalidState)?;
            if status == "passed" && exit != 0 {
                return Err(WorkerResponseError::InvalidState);
            }
            (Some(exit), Some(status.to_owned()))
        } else {
            (None, None)
        };
        Ok(Self {
            action,
            source_sha: source_sha.to_owned(),
            job_id: job_id.to_owned(),
            worker_generation: worker_generation.to_owned(),
            state,
            deployment_digest,
            started_marker_sha256,
            report_sha256,
            pid,
            process_start_ticks,
            exit_code,
            status,
        })
    }

    /// A successful comparison does not authenticate a response or verify a
    /// terminal report. The caller must also establish trusted transport and
    /// independently read the Root-owned started/terminal receipts.
    pub fn bind_request(
        &self,
        request: &WorkerRequest,
        expected_generation: &str,
        expected_deployment: Option<&str>,
    ) -> Result<(), WorkerResponseError> {
        if !lowercase_hex(expected_generation, 64)
            || expected_deployment.is_some_and(|pin| !lowercase_hex(pin, 64))
            || self.action != request.action()
            || self.source_sha != request.source_sha()
            || self.job_id != request.job_id()
            || self.worker_generation != expected_generation
            || self
                .deployment_digest
                .as_deref()
                .is_some_and(|digest| Some(digest) != expected_deployment)
            || request
                .deployment_digest()
                .is_some_and(|digest| Some(digest) != expected_deployment)
        {
            return Err(WorkerResponseError::ExternalPinMismatch);
        }
        Ok(())
    }
}
