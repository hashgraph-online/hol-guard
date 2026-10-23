//! Passive host readers and queue decisions matching the pinned Python release
//! observer. This crate neither owns the Python lease nor writes live jobs.

use serde_json::{json, Value};
use std::collections::HashSet;
use std::fmt;

mod operations;
pub use operations::{load_operations_bytes, OperationsError};
mod fixed_process;
mod git_controller_source;
pub use git_controller_source::{
    verify_git_controller_source, GitControllerSourceError, GitControllerSourceProof,
};
mod host_telemetry;
pub use host_telemetry::{sample_host, HostTelemetryError};
mod live_provider_preflight;
pub use live_provider_preflight::{evaluate_live_provider_preflight, LiveProviderPreflightError};
mod live_provider_observe;
pub use live_provider_observe::observe_live_provider_preflight_shadow;
mod live_provider_start;
pub use live_provider_start::{
    fixed_live_provider_start_plan, LiveProviderStartError, LiveProviderStartPlan,
};
mod live_provider_manifest;
pub use live_provider_manifest::{
    verify_live_provider_manifest_claim, LiveProviderManifestExpectation,
};
mod controller_key_pins;
pub use controller_key_pins::{
    HostControllerKeyPinJournal, HostControllerKeyPins, HostDeterministicReadbackObservation,
    HostEffectEventsPin, HostKeyPinError, HostKeyPinRecord, HostKeyedTerminalObservation,
    HostPrelaunchIdentity, HostPreparedProcess, HostProcessFailure, HostSdkTapJournalPin,
    HostStagingRestartReadbackObservation,
};
mod candidate_build_pins;
pub use candidate_build_pins::{
    HostCandidateBuildPinError, HostCandidateBuildPinJournal, HostCandidateBuildPinRecord,
    HostCandidateBuildPins,
};
mod private_jobs;
pub use private_jobs::{
    read_private_jobs, read_private_jobs_if_idle, read_private_operations, PrivateJobError,
};
mod public_jobs;
pub use public_jobs::{project_public_jobs, PublicJobsError, PublicJobsProjection};
mod release_source;
pub use release_source::{ReleaseSourceError, TagLookupPlan};
mod source_archive;
pub use source_archive::{
    verify_retained_source_archive, SourceArchiveError, SourceArchiveInventory,
};
mod source_archive_commit;
pub use source_archive_commit::{
    verify_retained_source_archive_commit, SourceArchiveCommitError, SourceArchiveCommitProof,
};
mod stream_process;
mod telemetry;
pub use telemetry::{resource_admission_reasons, TelemetryError, VmProbePlan};
mod vm_progress;
pub use vm_progress::{VmProgressError, VmProgressPlan};
mod vm_candidate_result;
pub use vm_candidate_result::{VmCandidateResultError, VmCandidateResultPlan};
mod vm_candidate_result_hostbound;
pub use vm_candidate_result_hostbound::{
    VmHostBoundCandidateResultError, VmHostBoundCandidateResultPlan,
};
mod vm_candidate_build;
pub use vm_candidate_build::{
    VmCandidateBuildError, VmCandidateBuildInvocation, VmCandidateBuildLaunchError,
    VmCandidateBuildPlan, VmCandidateBuildPreflightError, VmCandidateBuildPreflightPlan,
};
mod vm_source_archive;
pub use vm_source_archive::{VmSourceArchiveError, VmSourceArchiveProbePlan};
mod vm_source_transfer;
pub use vm_source_transfer::{
    transfer_source_archive_one_use, VmSourceTransferError, VmSourceTransferProof,
};
mod vm_reconcile;
pub use vm_reconcile::{VmReconcileError, VmReconcilePlan};
mod vm_rust_shadow;
pub use vm_rust_shadow::{VmRustShadowError, VmRustShadowPlan};

const ARCHIVE_REASON: &str = "Removed from active queue by release-only configuration";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMode {
    ReleaseTags,
    PullRequests,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueConfig {
    pub mode: DiscoveryMode,
    pub release_tags: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    InvalidConfig,
    InvalidJob,
    InvalidTime,
}

impl fmt::Display for QueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("invalid release queue configuration"),
            Self::InvalidJob => f.write_str("invalid release queue job"),
            Self::InvalidTime => f.write_str("invalid archive timestamp"),
        }
    }
}

impl std::error::Error for QueueError {}

fn stable_tag(tag: &str) -> bool {
    let Some(version) = tag.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<_> = version.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

impl QueueConfig {
    /// Parse only the queue fields of an already trusted operations document.
    /// The full Python config loader and its private-file custody are separate.
    pub fn from_operations(value: &Value) -> Result<Self, QueueError> {
        let mode = match value.get("discovery_mode").and_then(Value::as_str) {
            Some("release-tags") => DiscoveryMode::ReleaseTags,
            Some("pull-requests") => DiscoveryMode::PullRequests,
            _ => return Err(QueueError::InvalidConfig),
        };
        let tags = value
            .get("release_tags")
            .and_then(Value::as_array)
            .ok_or(QueueError::InvalidConfig)?;
        if !(1..=20).contains(&tags.len()) {
            return Err(QueueError::InvalidConfig);
        }
        let mut seen = HashSet::new();
        let mut release_tags = Vec::with_capacity(tags.len());
        for tag in tags {
            let tag = tag.as_str().ok_or(QueueError::InvalidConfig)?;
            if !stable_tag(tag) || !seen.insert(tag) {
                return Err(QueueError::InvalidConfig);
            }
            release_tags.push(tag.to_owned());
        }
        Ok(Self { mode, release_tags })
    }
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|number| number != 0.0),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(value)) => !value.is_empty(),
        Some(Value::Object(value)) => !value.is_empty(),
        Some(Value::Bool(true)) => true,
    }
}

fn job_object(job: &Value) -> Result<&serde_json::Map<String, Value>, QueueError> {
    job.as_object().ok_or(QueueError::InvalidJob)
}

/// The exact Python `admitted(config, job)` decision for JSON job records.
pub fn admitted(config: &QueueConfig, job: &Value) -> Result<bool, QueueError> {
    let job = job_object(job)?;
    if truthy(job.get("archived_at")) {
        return Ok(false);
    }
    if job.get("kind").and_then(Value::as_str) == Some("local-candidate") {
        let operator_queued = job.get("operator_queued") == Some(&Value::Bool(true));
        let sha = job.get("sha").and_then(Value::as_str).unwrap_or("");
        return Ok(operator_queued && git_sha(sha));
    }
    Ok(match config.mode {
        DiscoveryMode::ReleaseTags => {
            job.get("kind").and_then(Value::as_str) == Some("release")
                && job
                    .get("tag")
                    .and_then(Value::as_str)
                    .is_some_and(|tag| config.release_tags.iter().any(|allowed| allowed == tag))
        }
        DiscoveryMode::PullRequests => job.get("kind").and_then(Value::as_str) != Some("release"),
    })
}

fn git_sha(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn state(job: &Value) -> Result<&str, QueueError> {
    job.get("state")
        .and_then(Value::as_str)
        .ok_or(QueueError::InvalidJob)
}

/// Apply the Python archival decisions to an in-memory copy. `now` is supplied
/// by the caller; this pure reducer never persists a record or grants admission.
/// It validates the entire batch first, so malformed input cannot partly mutate it.
pub fn archive_unwatched(
    config: &QueueConfig,
    jobs: &mut [Value],
    now: f64,
) -> Result<Vec<String>, QueueError> {
    if !now.is_finite() || now <= 0.0 {
        return Err(QueueError::InvalidTime);
    }
    for job in jobs.iter() {
        job_object(job)?;
        state(job)?;
        job.get("id")
            .and_then(Value::as_str)
            .ok_or(QueueError::InvalidJob)?;
    }
    let mut saved = Vec::new();
    for job in jobs {
        let id = job["id"].as_str().ok_or(QueueError::InvalidJob)?.to_owned();
        let current_state = state(job)?.to_owned();
        let superseded_local = job.get("kind").and_then(Value::as_str) == Some("local-candidate")
            && current_state == "superseded"
            && !truthy(job.get("archived_at"));
        if superseded_local {
            job["archived_at"] = json!(now);
            saved.push(id);
            continue;
        }
        if admitted(config, job)? || truthy(job.get("archived_at")) {
            continue;
        }
        if matches!(current_state.as_str(), "running" | "preparing" | "unknown") {
            continue;
        }
        job["archived_at"] = json!(now);
        if matches!(
            current_state.as_str(),
            "queued" | "waiting" | "waiting-candidate"
        ) {
            job["state"] = json!("archived");
            job["reason"] = json!(ARCHIVE_REASON);
            job["finished_at"] = json!(now);
        }
        saved.push(id);
    }
    Ok(saved)
}

/// Match the Python observer's first-ready selection over a caller-supplied
/// ordered job list. Any unknown job blocks all admission, even if archived.
/// Lease ownership, resource checks and source revalidation remain external.
pub fn next_queued_job<'a>(
    config: &QueueConfig,
    jobs: &'a [Value],
    held: bool,
    active: bool,
    admission_reasons: bool,
) -> Result<Option<&'a str>, QueueError> {
    for job in jobs {
        job_object(job)?;
        state(job)?;
    }
    if held || active || admission_reasons || jobs.iter().any(|job| state(job) == Ok("unknown")) {
        return Ok(None);
    }
    for job in jobs {
        if admitted(config, job)?
            && !truthy(job.get("status_error"))
            && !truthy(job.get("source_error"))
            && matches!(state(job)?, "queued" | "waiting" | "waiting-candidate")
        {
            return job
                .get("id")
                .and_then(Value::as_str)
                .ok_or(QueueError::InvalidJob)
                .map(Some);
        }
    }
    Ok(None)
}
