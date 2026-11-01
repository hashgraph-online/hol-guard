//! Bounded progress/idempotency metadata, never SDK readiness or scope grants.
//! Only a live native coordinator and sealed selection can authorize effects.
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};
pub(crate) const MAX_JOBS: usize = 32;
#[cfg(test)]
#[path = "context_assistance_switch_job_tests.rs"]
mod tests;
const MAX_BYTES: u64 = 16 * 1024;
#[path = "context_assistance_initial_recovery_progress.rs"]
mod recovery_progress;
pub(super) use recovery_progress::begin as begin_initial_recovery;
pub(super) use recovery_progress::begin as begin_disabled_recovery;
pub(crate) use recovery_progress::RecoveryAttempt;
#[path = "context_assistance_switch_job_cancellation.rs"]
mod cancellation;
pub(crate) use cancellation::{cancelled, mark_cancel};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SwitchRequest {
    pub job_id: String,
    pub target_runtime_id: String,
    pub expected_generation: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub rollback: bool,
}
fn is_false(value: &bool) -> bool {
    !*value
}
impl SwitchRequest {
    pub(crate) fn operation(&self) -> &'static str {
        if self.rollback {
            "rollback"
        } else {
            "switch"
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JobPhase {
    Queued,
    Verifying,
    PreparingData,
    Ready,
    Quiescing,
    Committing,
    Completed,
    Cancelled,
    Failed,
    RecoveryRequired,
    Cancelling,
    Restoring,
    CleanupPending,
    PreparingRecovery,
}
impl JobPhase {
    pub(crate) fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Cancelled | Self::Failed | Self::RecoveryRequired
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SwitchJob {
    pub schema: String,
    pub request: SwitchRequest,
    pub request_sha256: String,
    pub source_runtime_id: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub source_disabled: bool,
    pub phase: JobPhase,
    pub code: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub deadline_at_ms: u64,
    pub prepared_data_generation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryAttempt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restoration_deadline_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restoration_failure_code: Option<String>,
}
pub(crate) fn validate_request(r: &SwitchRequest) -> Result<(), String> {
    if !valid_id(&r.job_id) || !valid_id(&r.target_runtime_id) || r.expected_generation == 0 {
        return Err(error("switch_request_invalid"));
    }
    Ok(())
}
fn request_hash(r: &SwitchRequest, source: &str) -> Result<String, String> {
    serde_json::to_vec(&("guard-cigar-switch-job-request.v1", r, source))
        .map(|b| format!("{:x}", Sha256::digest(b)))
        .map_err(|_| error("switch_request_invalid"))
}
impl SwitchJob {
    pub(crate) fn new(request: SwitchRequest, source_runtime_id: String) -> Result<Self, String> {
        Self::create(request, source_runtime_id, false)
    }
    fn create(
        request: SwitchRequest,
        source_runtime_id: String,
        source_disabled: bool,
    ) -> Result<Self, String> {
        validate_request(&request)?;
        let now = now()?;
        let request_sha256 = request_hash(&request, &source_runtime_id)?;
        let mut result = Self {
            schema: "guard-cigar-switch-job.v1".into(),
            request,
            request_sha256,
            source_runtime_id,
            source_disabled,
            phase: JobPhase::Queued,
            code: "queued".into(),
            created_at_ms: now,
            updated_at_ms: now,
            deadline_at_ms: now
                .checked_add(120_000)
                .ok_or_else(|| error("clock_invalid"))?,
            prepared_data_generation: None,
            recovery: None,
            restoration_deadline_at_ms: None,
            failure_code: None,
            restoration_failure_code: None,
        };
        result.request_sha256 = result.bound_hash()?;
        result.validate()?;
        Ok(result)
    }
    pub(crate) fn new_disabled(request: SwitchRequest, source: String) -> Result<Self, String> {
        if !valid_id(&source) {
            return Err(error("switch_request_invalid"));
        }
        Self::create(request, source, true)
    }
    pub(crate) fn new_initial(request: SwitchRequest) -> Result<Self, String> {
        Self::create(request, String::new(), true)
    }
    pub(crate) fn is_initial(&self) -> bool {
        self.source_disabled && self.source_runtime_id.is_empty()
    }
    pub(crate) fn operation(&self) -> &'static str {
        if self.recovery.is_some() {
            "recover"
        } else if self.is_initial() {
            "select"
        } else {
            self.request.operation()
        }
    }
    fn bound_hash(&self) -> Result<String, String> {
        let original = request_hash(&self.request, &self.source_runtime_id)?;
        if self.source_disabled {
            let bytes = serde_json::to_vec(&(
                if self.is_initial() {
                    "guard-cigar-initial-selection-job.v1"
                } else {
                    "guard-cigar-disabled-switch-job.v1"
                },
                original,
            ))
            .map_err(|_| error("switch_request_invalid"))?;
            Ok(format!("{:x}", Sha256::digest(bytes)))
        } else {
            Ok(original)
        }
    }
    fn validate(&self) -> Result<(), String> {
        validate_request(&self.request)?;
        if let Some(attempt) = &self.recovery {
            attempt.validate(self)?;
        }
        if self.schema != "guard-cigar-switch-job.v1"
            || (!valid_id(&self.source_runtime_id) && !self.is_initial())
            || (self.is_initial()
                && (self.request.rollback || self.prepared_data_generation.is_some()))
            || self.source_runtime_id == self.request.target_runtime_id
            || self.request_sha256 != self.bound_hash()?
            || self.created_at_ms == 0
            || self.updated_at_ms < self.created_at_ms
            || self.deadline_at_ms
                != self
                    .created_at_ms
                    .checked_add(120_000)
                    .ok_or_else(|| error("clock_invalid"))?
            || self.restoration_deadline_at_ms.is_some_and(|d| {
                d < self.created_at_ms || d > self.deadline_at_ms.saturating_add(30_000)
            })
            || [&self.failure_code, &self.restoration_failure_code]
                .iter()
                .any(|c| {
                    c.as_ref().is_some_and(|c| {
                        c.is_empty()
                            || c.len() > 128
                            || !c
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    })
                })
            || self.code.is_empty()
            || self.code.len() > 128
            || !self
                .code
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            || self
                .prepared_data_generation
                .as_deref()
                .is_some_and(|s| !is_lower_hex(s, 64))
        {
            return Err(error("switch_job_invalid"));
        }
        Ok(())
    }
}
pub(crate) fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|t| u64::try_from(t.as_millis()).ok())
        .filter(|t| *t > 0)
        .ok_or_else(|| error("clock_invalid"))
}
fn directory(home: &Path, create: bool) -> Result<PathBuf, String> {
    preparation::lifecycle_directory(home, "switch-jobs", create)
}
pub(crate) fn get(home: &Path, id: &str) -> Result<Option<SwitchJob>, String> {
    if !valid_id(id) {
        return Err(error("switch_request_invalid"));
    }
    if !exists_directory(home)? {
        return Ok(None);
    }
    let path = directory(home, false)?.join(record_name(id));
    let job: Option<SwitchJob> = preparation::lifecycle_read(home, &path, MAX_BYTES)?;
    if let Some(job) = &job {
        job.validate()?;
        if job.request.job_id != id {
            return Err(error("switch_job_invalid"));
        }
    }
    Ok(job)
}
fn exists_directory(home: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(home.join("context-assistance/switch-jobs")) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(error("switch_storage_unavailable")),
    }
}
pub(crate) fn list(home: &Path) -> Result<Vec<SwitchJob>, String> {
    if !exists_directory(home)? {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    for (index, entry) in fs::read_dir(directory(home, false)?)
        .map_err(|_| error("switch_storage_unavailable"))?
        .take(MAX_JOBS * 4 + 1)
        .enumerate()
    {
        if index >= MAX_JOBS * 4 {
            return Err(error("switch_job_limit"));
        }
        let entry = entry.map_err(|_| error("switch_storage_unavailable"))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| error("switch_job_invalid"))?;
        if preparation::lifecycle_temporary_name(name) {
            continue;
        }
        if name
            .strip_suffix(".cancel.json")
            .is_some_and(|s| is_lower_hex(s, 64))
        {
            continue;
        }
        let stem = name
            .strip_suffix(".json")
            .filter(|s| is_lower_hex(s, 64))
            .ok_or_else(|| error("switch_job_invalid"))?;
        let job: SwitchJob = preparation::lifecycle_read(home, &entry.path(), MAX_BYTES)?
            .ok_or_else(|| error("switch_job_invalid"))?;
        job.validate()?;
        if record_name(&job.request.job_id) != format!("{stem}.json") {
            return Err(error("switch_job_invalid"));
        }
        values.push(job);
        if values.len() > MAX_JOBS {
            return Err(error("switch_job_limit"));
        }
    }
    values.sort_by(|a, b| {
        b.created_at_ms
            .cmp(&a.created_at_ms)
            .then(a.request.job_id.cmp(&b.request.job_id))
    });
    Ok(values)
}
/// Caller owns the shared profile lifecycle lease. Stored progress is not a
/// resumable engine or proof that a worker still exists.
pub(crate) fn save(
    home: &Path,
    job: &mut SwitchJob,
    phase: JobPhase,
    code: &str,
) -> Result<(), String> {
    if let Some(previous) = get(home, &job.request.job_id)? {
        if previous.request != job.request
            || previous.request_sha256 != job.request_sha256
            || previous.source_runtime_id != job.source_runtime_id
            || previous.source_disabled != job.source_disabled
            || previous.recovery != job.recovery
            || previous.created_at_ms != job.created_at_ms
            || previous.deadline_at_ms != job.deadline_at_ms
            || previous
                .prepared_data_generation
                .as_ref()
                .is_some_and(|g| job.prepared_data_generation.as_ref() != Some(g))
            || previous
                .restoration_deadline_at_ms
                .is_some_and(|d| job.restoration_deadline_at_ms != Some(d))
            || (previous.phase.terminal() && previous.phase != phase)
        {
            return Err(error("switch_idempotency_conflict"));
        }
    } else {
        if preparation::native_job_id_exists(home, &job.request.job_id)? {
            return Err(error("switch_idempotency_conflict"));
        }
        if preparation::total_job_count(home)? >= MAX_JOBS {
            return Err(error("switch_job_limit"));
        }
    }
    write(home, job, phase, code)
}
fn write(home: &Path, job: &mut SwitchJob, phase: JobPhase, code: &str) -> Result<(), String> {
    job.phase = phase;
    job.code = code.into();
    job.updated_at_ms = now()?.max(job.created_at_ms);
    job.validate()?;
    let path = directory(home, true)?.join(record_name(&job.request.job_id));
    let bytes = serde_json::to_vec(job).map_err(|_| error("switch_job_invalid"))?;
    persist_private_bytes(&path, &bytes, MAX_BYTES, "cigar_switch_job", home)
        .map_err(|_| error("switch_job_write_failed"))
}
/// Only the parent selection owner calls this after authenticating an exact
/// Completed transaction. It repairs history and creates no runtime authority.
pub(super) fn complete_reconciled(home: &Path, id: &str) -> Result<(), String> {
    let mut job = get(home, id)?.ok_or_else(|| error("switch_job_missing"))?;
    if job.phase == JobPhase::Completed {
        return Ok(());
    }
    if matches!(job.phase, JobPhase::Cancelled | JobPhase::Failed) {
        return Err(error("switch_selection_conflict"));
    }
    write(home, &mut job, JobPhase::Completed, "completed")
}
pub(super) fn cancel_initial_reconciled(home: &Path, id: &str) -> Result<(), String> {
    let mut job = get(home, id)?.ok_or_else(|| error("switch_job_missing"))?;
    if !job.is_initial() || job.phase == JobPhase::Completed {
        return Err(error("switch_selection_conflict"));
    }
    if job.phase == JobPhase::Cancelled {
        return Ok(());
    }
    write(
        home,
        &mut job,
        JobPhase::Cancelled,
        "cancelled_initial_selection",
    )
}
