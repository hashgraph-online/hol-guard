//! Explicit recovery attempts renew only a bounded verification budget. They
//! are progress/cancellation identities, never target eligibility or consent.
use super::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryAttempt {
    pub(crate) id: String,
    pub(crate) expected_generation: u64,
    pub(crate) started_at_ms: u64,
    pub(crate) deadline_at_ms: u64,
}
impl RecoveryAttempt {
    pub(crate) fn describe(&self) -> Value {
        json!({"id":self.id,"expected_generation":self.expected_generation.to_string(),
            "started_at_ms":self.started_at_ms,"deadline_at_ms":self.deadline_at_ms})
    }
    pub(super) fn validate(&self, job: &SwitchJob) -> Result<(), String> {
        if !is_lower_hex(&self.id, 32)
            || self.expected_generation == 0
            || self.started_at_ms < job.created_at_ms
            || self.deadline_at_ms
                != self
                    .started_at_ms
                    .checked_add(120_000)
                    .ok_or_else(|| error("clock_invalid"))?
            || job.updated_at_ms < self.started_at_ms
        {
            return Err(error("switch_job_invalid"));
        }
        Ok(())
    }
}
/// Only an authenticated selection owner calls this after checking the sealed
/// target, unchanged disabled preferences and its corresponding data proof.
pub(in super::super) fn begin(
    home: &Path,
    expected: &SwitchJob,
    generation: u64,
) -> Result<SwitchJob, String> {
    let mut job =
        get(home, &expected.request.job_id)?.ok_or_else(|| error("switch_job_missing"))?;
    if &job != expected
        || generation == 0
        || matches!(
            job.phase,
            JobPhase::Completed | JobPhase::Cancelled | JobPhase::Failed
        )
    {
        return Err(error("initial_selection_conflict"));
    }
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| error("switch_worker_unavailable"))?;
    let started_at_ms = now()?.max(job.updated_at_ms);
    job.recovery = Some(RecoveryAttempt {
        id: hex::encode(nonce),
        expected_generation: generation,
        started_at_ms,
        deadline_at_ms: started_at_ms
            .checked_add(120_000)
            .ok_or_else(|| error("clock_invalid"))?,
    });
    let code = if job.is_initial() {
        "verifying_initial_recovery"
    } else {
        "verifying_disabled_recovery"
    };
    write(home, &mut job, JobPhase::PreparingRecovery, code)?;
    Ok(job)
}

#[cfg(all(test, unix))]
#[path = "context_assistance_initial_recovery_progress_tests.rs"]
mod tests;
