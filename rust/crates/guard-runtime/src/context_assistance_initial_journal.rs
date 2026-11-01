//! Initial publication shares the short writer lane. Its marker precedes the
//! config/selection writes and blocks startup until completion is observed.
use super::*;
use guard_cigar_release::InitialRecovery;

fn matches_settings(owner: &Owner, plan: &InitialSelection, settings: &SwitchSettings) -> bool {
    let data = if settings.target().storage.mode == guard_context_assistance::StorageMode::Memory {
        guard_cigar_release::SelectionData::Memory
    } else {
        guard_cigar_release::SelectionData::LegacySaved
    };
    settings.home() == owner.home
        && settings.source().runtime_id.is_empty()
        && !settings.source().enabled
        && !settings.target().enabled
        && !settings.source_settings().requested.enabled
        && !settings.target_settings().requested.enabled
        && settings.target().runtime_id == plan.target.runtime.installation_id
        && plan.target.data == data
        && settings.before_sha256() == plan.before_settings_sha256
        && settings.after_sha256() == plan.after_settings_sha256
}
impl Owner {
    fn publish_initial_locked(
        &mut self,
        lock: &WriteLock,
        plan: InitialSelection,
    ) -> Result<(), String> {
        self.check(lock)?;
        plan.validate().map_err(state_error)?;
        let payload =
            serde_json::to_string(&plan).map_err(|_| error("initial_selection_invalid"))?;
        if payload.len() > PAYLOAD_BYTES {
            return Err(error("initial_selection_invalid"));
        }
        let key = self
            .key
            .as_deref()
            .ok_or_else(|| error("switch_key_missing"))?;
        let mac = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, key),
            &message(&self.home, &payload)?,
        );
        let raw = serde_json::to_vec(&Envelope {
            schema: "guard-cigar-sealed-initial-selection.v1".into(),
            payload,
            mac: hex::encode(mac.as_ref()),
        })
        .map_err(|_| error("initial_selection_invalid"))?;
        lock.publish_lifecycle(
            LifecycleFile::InitialSelection,
            self.initial.raw.as_deref(),
            &raw,
        )
        .map_err(storage_error)?;
        self.initial.raw = Some(raw);
        self.initial.record = Some(plan);
        Ok(())
    }
    fn initial_for(&self, id: &str) -> Result<&InitialSelection, String> {
        self.initial_record()
            .filter(|p| p.request_id == id)
            .ok_or_else(|| error("initial_selection_conflict"))
    }
    fn initial_target_record(&self, plan: &InitialSelection) -> Result<(), String> {
        if self.record.as_ref().is_none_or(|r| {
            r.current != plan.target
                || r.revision != 1
                || r.last_good.is_some()
                || r.transaction.is_some()
        }) {
            return Err(error("initial_selection_conflict"));
        }
        Ok(())
    }
    fn publish_initial_target(
        &mut self,
        lock: &WriteLock,
        plan: &InitialSelection,
    ) -> Result<(), String> {
        if self.record.is_some() {
            return self.initial_target_record(plan);
        }
        self.publish_locked(
            lock,
            SelectionRecord {
                schema: "guard-cigar-selection.v2".into(),
                revision: 1,
                current: plan.target.clone(),
                last_good: None,
                transaction: None,
            },
        )
    }
    pub(crate) fn begin_initial(
        &mut self,
        plan: InitialSelection,
        settings: &SwitchSettings,
        proof: &empty::EmptyDataProof,
    ) -> Result<(), String> {
        plan.validate().map_err(state_error)?;
        if self.record.is_some()
            || plan.phase != InitialPhase::Prepared
            || plan.revision != 1
            || self
                .initial_record()
                .is_some_and(|p| p.phase != InitialPhase::Cancelled)
            || !matches_settings(self, &plan, settings)
            || plan.empty_data_sha256 != proof.sha256()
        {
            return Err(error("initial_selection_conflict"));
        }
        settings.check_current()?;
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        proof.check(self, &lock)?;
        settings.check_current()?;
        self.provision(&lock)?;
        self.publish_initial_locked(&lock, plan)
    }
    /// The caller has closed its verified private target and owns no serving
    /// actor. No SDK work, project read or enable change occurs in this lane.
    pub(crate) fn commit_initial(
        &mut self,
        id: &str,
        settings: &SwitchSettings,
        proof: &empty::EmptyDataProof,
    ) -> Result<(), String> {
        let plan = self.initial_for(id)?.clone();
        if plan.phase != InitialPhase::Prepared
            || self.record.is_some()
            || !matches_settings(self, &plan, settings)
            || plan.empty_data_sha256 != proof.sha256()
        {
            return Err(error("initial_selection_conflict"));
        }
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        proof.check(self, &lock)?;
        settings.check_current()?;
        self.publish_initial_locked(
            &lock,
            plan.advance(InitialPhase::CommitIntent)
                .map_err(state_error)?,
        )?;
        settings.publish(&lock)?;
        self.publish_initial_target(&lock, &plan)?;
        let committed = self
            .initial_for(id)?
            .advance(InitialPhase::Committed)
            .map_err(state_error)?;
        self.publish_initial_locked(&lock, committed)
    }
    /// Reconcile an uncertain config/record acknowledgement after independently
    /// remeasuring the same exact target. Never replay its SDK initialization.
    pub(crate) fn reconcile_initial_committed(
        &mut self,
        id: &str,
        settings: &SwitchSettings,
        proof: &empty::EmptyDataProof,
        verified: &SelectionPointer,
    ) -> Result<(), String> {
        self.reload()?;
        let plan = self.initial_for(id)?.clone();
        if !matches_settings(self, &plan, settings)
            || &plan.target != verified
            || plan.empty_data_sha256 != proof.sha256()
        {
            return Err(error("initial_selection_conflict"));
        }
        settings.check_target_exact()?;
        let raw =
            crate::guard_config_update::read_home_config(&self.home).map_err(storage_error)?;
        let recovery = plan
            .recovery(
                &settings.target().runtime_id,
                &settings_hash(raw.as_deref()),
                false,
                self.record.as_ref().map(|r| &r.current),
                true,
            )
            .map_err(state_error)?;
        if recovery != InitialRecovery::VerifyTarget {
            return Err(error("initial_selection_recovery_required"));
        }
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        proof.check(self, &lock)?;
        settings.check_target_exact()?;
        self.publish_initial_target(&lock, &plan)?;
        let reconciled = plan
            .reconcile(
                &settings.target().runtime_id,
                &settings_hash(raw.as_deref()),
                false,
                self.record.as_ref().map(|r| &r.current),
                true,
            )
            .map_err(state_error)?;
        self.publish_initial_locked(&lock, reconciled)
    }
    pub(crate) fn cancel_initial(&mut self, id: &str) -> Result<(), String> {
        self.reload()?;
        let Some(plan) = self.initial_record().cloned() else {
            return Ok(());
        };
        if plan.request_id != id {
            return Err(error("initial_selection_conflict"));
        }
        if plan.phase == InitialPhase::Cancelled {
            return Ok(());
        }
        if !matches!(
            plan.phase,
            InitialPhase::Prepared | InitialPhase::CommitIntent
        ) || self.record.is_some()
        {
            return Err(error("initial_selection_recovery_required"));
        }
        let current = crate::guard_config_load::context_assistance_config(&self.home)
            .map_err(|_| error("configuration_unavailable"))?;
        if current.requested.enabled
            || current.effective.enabled
            || !current.requested.runtime_id.is_empty()
            || !current.effective.runtime_id.is_empty()
        {
            return Err(error("initial_selection_recovery_required"));
        }
        let proof = empty::EmptyDataProof::capture(self)?;
        if proof.sha256() != plan.empty_data_sha256 {
            return Err(error("initial_selection_data_changed"));
        }
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        proof.check(self, &lock)?;
        self.publish_initial_locked(
            &lock,
            plan.advance(InitialPhase::Cancelled).map_err(state_error)?,
        )
    }
    fn advance_initial_health(
        &mut self,
        id: &str,
        from: InitialPhase,
        to: InitialPhase,
    ) -> Result<(), String> {
        let plan = self.initial_for(id)?.clone();
        self.initial_target_record(&plan)?;
        if plan.phase == to {
            return Ok(());
        }
        if plan.phase != from {
            return Err(error("initial_selection_conflict"));
        }
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        self.publish_initial_locked(&lock, plan.advance(to).map_err(state_error)?)
    }
    pub(crate) fn mark_initial_healthy(&mut self, id: &str) -> Result<(), String> {
        self.advance_initial_health(id, InitialPhase::Committed, InitialPhase::Healthy)
    }
    pub(crate) fn complete_initial(&mut self, id: &str) -> Result<(), String> {
        self.advance_initial_health(id, InitialPhase::Healthy, InitialPhase::Completed)
    }
}

#[cfg(test)]
#[path = "context_assistance_initial_journal_tests.rs"]
mod tests;

impl Owner {
    /// Recovery admission observes an already selected, still-disabled target.
    /// It renews only verification progress; no config or data is published.
    pub(crate) fn begin_initial_recovery(
        &mut self,
        job: &jobs::SwitchJob,
        generation: u64,
    ) -> Result<(InitialTarget, empty::EmptyDataProof, jobs::SwitchJob), String> {
        self.initial_matches_job(job)?;
        let target = InitialTarget::capture(self, &job.request.job_id)?;
        let proof = empty::EmptyDataProof::capture_for_initial(self, &job.request.job_id)?;
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        self.check(&lock)?;
        target.check_owner(self)?;
        proof.check(self, &lock)?;
        let job = jobs::begin_initial_recovery(&self.home, job, generation)?;
        Ok((target, proof, job))
    }
    /// The worker independently verified the exact target and closed it before
    /// this lane. Reconcile records only; never rewrite preferences or replay SDK.
    pub(crate) fn recover_initial_target(
        &mut self,
        id: &str,
        target: &InitialTarget,
        proof: &empty::EmptyDataProof,
        measured: &SelectionPointer,
    ) -> Result<(), String> {
        self.reload()?;
        target.check_owner(self)?;
        let plan = self.initial_for(id)?.clone();
        if &plan.target != measured || plan.empty_data_sha256 != proof.sha256() {
            return Err(error("initial_selection_conflict"));
        }
        let recovery = plan
            .recovery(
                &target.settings().requested.runtime_id,
                &plan.after_settings_sha256,
                false,
                self.record.as_ref().map(|r| &r.current),
                true,
            )
            .map_err(state_error)?;
        if recovery != InitialRecovery::VerifyTarget {
            return Err(error("initial_selection_recovery_required"));
        }
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        self.check(&lock)?;
        target.check_owner(self)?;
        proof.check(self, &lock)?;
        self.publish_initial_target(&lock, &plan)?;
        let reconciled = plan
            .reconcile(
                &target.settings().requested.runtime_id,
                &plan.after_settings_sha256,
                false,
                self.record.as_ref().map(|r| &r.current),
                true,
            )
            .map_err(state_error)?;
        if reconciled != plan {
            self.publish_initial_locked(&lock, reconciled)?;
        }
        Ok(())
    }

    fn initial_matches_job(&self, job: &jobs::SwitchJob) -> Result<(), String> {
        if !job.is_initial() || job.prepared_data_generation.is_some() {
            return Err(error("initial_selection_conflict"));
        }
        if let Some(plan) = self.initial_record() {
            if plan.request_id != job.request.job_id
                || plan.expected_service_generation != job.request.expected_generation
                || plan.target.runtime.installation_id != job.request.target_runtime_id
            {
                return Err(error("initial_selection_conflict"));
            }
        }
        Ok(())
    }
    pub(crate) fn reconcile_initial_job(&self, job: &jobs::SwitchJob) -> Result<(), String> {
        self.initial_matches_job(job)?;
        if self
            .initial_record()
            .is_none_or(|p| p.phase != InitialPhase::Completed)
            || self.record.is_none()
        {
            return Err(error("initial_selection_recovery_required"));
        }
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        self.check(&lock)?;
        jobs::complete_reconciled(&self.home, &job.request.job_id)
    }
    pub(crate) fn cancel_initial_job(&mut self, job: &jobs::SwitchJob) -> Result<(), String> {
        self.initial_matches_job(job)?;
        if self.initial_record().is_none() {
            let current = crate::guard_config_load::context_assistance_config(&self.home)
                .map_err(|_| error("configuration_unavailable"))?;
            if current.requested.enabled
                || current.effective.enabled
                || !current.requested.runtime_id.is_empty()
                || !current.effective.runtime_id.is_empty()
            {
                return Err(error("initial_selection_recovery_required"));
            }
            empty::EmptyDataProof::capture(self)?;
        } else {
            self.cancel_initial(&job.request.job_id)?;
        }
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        self.check(&lock)?;
        jobs::cancel_initial_reconciled(&self.home, &job.request.job_id)
    }
}
