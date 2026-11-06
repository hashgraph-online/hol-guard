//! A sealed completed transaction can repair progress metadata. A job record
//! cannot authorize SDK work, a selection change, or a restored source grant.
use super::*;

impl Owner {
    fn preparation_available(&self) -> Result<(), String> {
        self.check_initial_clear()?;
        DataRemoval::check_clear(&self.home).map_err(|e| error(e.code()))?;
        if self
            .record
            .as_ref()
            .and_then(|r| r.transaction.as_ref())
            .is_some_and(|t| !t.phase.terminal())
        {
            return Err(error("switch_recovery_required"));
        }
        Ok(())
    }
    pub(crate) fn rollback_target(
        &self,
    ) -> Result<guard_cigar_release::SelectionInstallation, String> {
        self.preparation_available()?;
        self.record
            .as_ref()
            .and_then(|r| r.last_good.as_ref())
            .map(|p| p.runtime.clone())
            .ok_or_else(|| error("rollback_unavailable"))
    }
    pub(crate) fn prepare_for(&self, request: &jobs::SwitchRequest) -> Result<(), String> {
        self.preparation_available()?;
        if request.rollback && self.rollback_target()?.installation_id != request.target_runtime_id
        {
            return Err(error("rollback_target_changed"));
        }
        Ok(())
    }
    pub(crate) fn check_rollback_target(
        &self,
        request: &jobs::SwitchRequest,
        target: &guard_cigar_release::SelectionInstallation,
    ) -> Result<(), String> {
        if request.rollback && self.rollback_target()? != *target {
            return Err(error("rollback_target_changed"));
        }
        Ok(())
    }
    pub(crate) fn job_phase(&self, job: &jobs::SwitchJob) -> Result<SelectionPhase, String> {
        let t = self
            .record
            .as_ref()
            .and_then(|r| r.transaction.as_ref())
            .ok_or_else(|| error("switch_transaction_missing"))?;
        if t.request_id != job.request.job_id
            || t.expected_service_generation != job.request.expected_generation
            || t.from.runtime.installation_id != job.source_runtime_id
            || t.to.runtime.installation_id != job.request.target_runtime_id
            || t.to.data.generation_id() != job.prepared_data_generation.as_deref()
        {
            return Err(error("switch_selection_conflict"));
        }
        Ok(t.phase)
    }
    pub(crate) fn reconcile_job(&self, job: &jobs::SwitchJob) -> Result<(), String> {
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        self.check(&lock)?;
        if self.job_phase(job)? != SelectionPhase::Completed {
            return Err(error("switch_recovery_required"));
        }
        jobs::complete_reconciled(&self.home, &job.request.job_id)
    }
}
