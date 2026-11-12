//! Reconcile a published actor's missing completion acknowledgement. No disk
//! record is accepted as permission to start an SDK or reconstruct a grant.
use super::*;
use guard_cigar_release::SelectionPhase;

impl Service {
    pub(crate) fn reconcile_switch(
        &self,
        home: &Path,
        id: &str,
        generation: u64,
    ) -> Result<Value, String> {
        let job = jobs::get(home, id)?.ok_or_else(|| error("switch_job_missing"))?;
        if matches!(
            job.phase,
            JobPhase::Completed | JobPhase::Cancelled | JobPhase::Failed
        ) {
            return self.switch_job(home, id);
        }
        if (job.is_initial() || job.recovery.is_some())
            && initial::running(self, home, &job, generation)?
        {
            return self.switch_job(home, id);
        }
        let mut owner = switching::Owner::acquire(home)?;
        if job.is_initial() {
            return initial::reconcile(self, home, &job, generation, owner);
        }
        let phase = owner.job_phase(&job)?;
        if phase == SelectionPhase::Completed {
            owner.reconcile_job(&job)?;
            return self.switch_job(home, id);
        }
        let current = crate::guard_config_load::context_assistance_config(home)
            .map_err(|_| error("configuration_unavailable"))?;
        if job.source_disabled || (!current.requested.enabled && !current.effective.enabled) {
            return cold::reconcile(self, home, &job, generation, owner);
        }
        if phase != SelectionPhase::Healthy {
            return Err(error("switch_recovery_required"));
        }
        let home = std::fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
        let (actor, settings) = {
            let state = lock(&self.state)?;
            if state.closed
                || state.stopping
                || state.upgrade.is_some()
                || state.cutover.is_some()
                || state.pending.is_some()
                || state.generation != generation
                || !state.settings.requested.enabled
                || !state.settings.effective.enabled
                || !state.settings.verification_permitted
                || state.settings.diagnostic.is_some()
                || state.settings.effective.runtime_id != job.request.target_runtime_id
            {
                return Err(error("switch_selection_conflict"));
            }
            (
                state
                    .runtime
                    .as_ref()
                    .filter(|a| a.is_active())
                    .cloned()
                    .ok_or_else(|| error("switch_recovery_required"))?,
                state.settings.clone(),
            )
        };
        let installation = registry::load(&home, &job.request.target_runtime_id)?;
        let root = home.clone();
        let measured = actor
            .call(move |runtime, engine| {
                runtime.recheck_artifacts()?;
                runtime.check_transport()?;
                let data = engine.upgrade_selection_data(&root)?;
                installation
                    .measured_selection(&root, runtime, data)
                    .map(|(pointer, _)| pointer)
                    .map_err(|_| guard_context_assistance::RuntimeError::ApprovalMismatch)
            })
            .map_err(|e| error(e.code()))?;
        if owner.record().is_none_or(|r| r.current != measured) {
            return Err(error("switch_selection_conflict"));
        }
        let current = crate::guard_config_load::context_assistance_config(&home)
            .map_err(|_| error("configuration_unavailable"))?;
        self.configure_at(current, generation)?;
        {
            let state = lock(&self.state)?;
            if state.closed
                || state.stopping
                || state.generation != generation
                || state.settings != settings
                || state
                    .runtime
                    .as_ref()
                    .is_none_or(|a| !Arc::ptr_eq(a, &actor))
                || !actor.is_active()
            {
                return Err(error("switch_selection_conflict"));
            }
        }
        owner.complete_publication(&job.request.job_id)?;
        owner.reconcile_job(&job)?;
        self.switch_job(&home, id)
    }
}
