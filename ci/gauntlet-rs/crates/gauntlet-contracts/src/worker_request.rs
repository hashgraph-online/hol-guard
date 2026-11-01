//! Fixed, data-only request boundary for the future Linux VM worker.
//!
//! Parsing never starts a job or confers deployment authority. The reviewed
//! worker must still bind an external deployment, lease and one-time job ID.

use crate::{canonicalize, is_git_sha};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fmt;

const SCHEMA: &str = "hol-gauntlet-worker-request.v1";
const MAX_REQUEST_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerAction {
    Inspect,
    Progress,
    Reconcile,
    Run,
}

impl WorkerAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Progress => "progress",
            Self::Reconcile => "reconcile",
            Self::Run => "run",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerRequest {
    action: WorkerAction,
    source_sha: String,
    job_id: String,
    deployment_digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerRequestError {
    InvalidJson,
    UnsupportedSchema,
    UnsafeFields,
    InvalidIdentity,
    MissingRunPin,
}

impl fmt::Display for WorkerRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidJson => "invalid bounded worker request JSON",
            Self::UnsupportedSchema => "unsupported worker request schema or action",
            Self::UnsafeFields => "worker request contains unknown or misplaced fields",
            Self::InvalidIdentity => "invalid source SHA or one-time job identity",
            Self::MissingRunPin => "run requires an exact external deployment digest",
        };
        f.write_str(message)
    }
}

impl std::error::Error for WorkerRequestError {}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl WorkerRequest {
    pub fn action(&self) -> WorkerAction {
        self.action
    }

    pub fn source_sha(&self) -> &str {
        &self.source_sha
    }

    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    pub fn deployment_digest(&self) -> Option<&str> {
        self.deployment_digest.as_deref()
    }

    pub fn parse(raw: &[u8]) -> Result<Self, WorkerRequestError> {
        if raw.len() > MAX_REQUEST_BYTES {
            return Err(WorkerRequestError::InvalidJson);
        }
        let canonical = canonicalize(raw).map_err(|_| WorkerRequestError::InvalidJson)?;
        let value: Value =
            serde_json::from_slice(&canonical).map_err(|_| WorkerRequestError::InvalidJson)?;
        if value["schema"] != SCHEMA {
            return Err(WorkerRequestError::UnsupportedSchema);
        }
        let action = match value["action"].as_str() {
            Some("inspect") => WorkerAction::Inspect,
            Some("progress") => WorkerAction::Progress,
            Some("reconcile") => WorkerAction::Reconcile,
            Some("run") => WorkerAction::Run,
            _ => return Err(WorkerRequestError::UnsupportedSchema),
        };
        let fields: BTreeSet<&str> = value
            .as_object()
            .ok_or(WorkerRequestError::UnsafeFields)?
            .keys()
            .map(String::as_str)
            .collect();
        let mut expected: BTreeSet<&str> = ["schema", "action", "source_sha", "job_id"]
            .into_iter()
            .collect();
        if action == WorkerAction::Run {
            expected.insert("deployment_digest");
        }
        if fields != expected {
            return Err(WorkerRequestError::UnsafeFields);
        }
        let sha = value["source_sha"]
            .as_str()
            .ok_or(WorkerRequestError::InvalidIdentity)?;
        let job = value["job_id"]
            .as_str()
            .ok_or(WorkerRequestError::InvalidIdentity)?;
        if !is_git_sha(sha) || !lowercase_hex(job, 16) {
            return Err(WorkerRequestError::InvalidIdentity);
        }
        let deployment_digest = if action == WorkerAction::Run {
            let pin = value["deployment_digest"]
                .as_str()
                .filter(|pin| lowercase_hex(pin, 64))
                .ok_or(WorkerRequestError::MissingRunPin)?;
            Some(pin.to_owned())
        } else {
            None
        };
        Ok(Self {
            action,
            source_sha: sha.to_owned(),
            job_id: job.to_owned(),
            deployment_digest,
        })
    }

    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "schema": SCHEMA,
            "action": self.action.as_str(),
            "source_sha": self.source_sha,
            "job_id": self.job_id,
        });
        if let Some(pin) = &self.deployment_digest {
            value["deployment_digest"] = json!(pin);
        }
        value
    }

    /// The parser cannot establish whether a job already ran. The worker
    /// must check its Root-owned lease and started/terminal receipts too.
    pub fn matches_deployment(&self, source_sha: &str, deployment_digest: &str) -> bool {
        self.action == WorkerAction::Run
            && self.source_sha == source_sha
            && self.deployment_digest.as_deref() == Some(deployment_digest)
    }
}
