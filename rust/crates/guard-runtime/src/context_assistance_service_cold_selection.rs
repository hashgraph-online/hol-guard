//! Explicit disabled-profile selection. Temporary SDKs never become a Service
//! actor, and neither progress nor a recovered journal grants app authority.
use super::*;
use guard_cigar_release::{SelectionData, SelectionPhase};
use guard_context_assistance::{
    EvidenceCache, EvidenceGenerationStore, EvidenceUpgradeInventory, PreparedEvidenceGeneration,
};

#[path = "context_assistance_service_cold_commit.rs"]
mod commit;
#[path = "context_assistance_service_cold_prepare.rs"]
mod prepare;
#[path = "context_assistance_service_cold_worker.rs"]
pub(super) mod worker;

pub(super) struct Source {
    pub(super) settings: AssistanceSettings,
    pub(super) generation: u64,
}
impl Source {
    pub(super) fn capture(shared: &Mutex<State>, request: &SwitchRequest) -> Result<Self, String> {
        let state = lock(shared)?;
        if state.closed {
            return Err(error("shutdown"));
        }
        if state.stopping
            || state.pending.is_some()
            || state.upgrade.is_some()
            || state.cutover.is_some()
            || state.runtime.is_some()
            || state
                .retiring
                .as_ref()
                .is_some_and(|a| !a.cleanup_finished())
        {
            return Err(error("switch_busy"));
        }
        if state.generation != request.expected_generation {
            return Err(error("switch_selection_conflict"));
        }
        if state.settings.requested.enabled
            || state.settings.effective.enabled
            || !state.settings.verification_permitted
            || state.settings.diagnostic.is_some()
        {
            return Err(error("disabled"));
        }
        if state.settings.effective.runtime_id == request.target_runtime_id {
            return Err(error("switch_request_invalid"));
        }
        Ok(Self {
            settings: state.settings.clone(),
            generation: state.generation,
        })
    }
    pub(super) fn matches(&self, state: &State) -> bool {
        state.generation == self.generation
            && state.settings == self.settings
            && !state.settings.requested.enabled
            && !state.settings.effective.enabled
            && state.runtime.is_none()
    }
}
pub(super) fn check(
    shared: &Weak<Mutex<State>>,
    source: &Source,
    signal: &Arc<Signal>,
) -> Result<(), String> {
    if signal.cancel.load(Ordering::Acquire) {
        return Err(error("switch_cancelled"));
    }
    let shared = shared.upgrade().ok_or_else(|| error("shutdown"))?;
    let state = lock(&shared)?;
    if state.closed
        || state.stopping
        || state.pending.is_some()
        || !source.matches(&state)
        || state
            .upgrade
            .as_ref()
            .is_none_or(|s| !Arc::ptr_eq(s, signal))
        || !(signal.source_disabled || signal.recovery.is_some())
    {
        return Err(error("switch_source_changed"));
    }
    Ok(())
}

/// Only repair a completed disabled publication's metadata. Health was already
/// measured; this creates no SDK process and future activation rechecks bytes.
pub(super) fn reconcile(
    service: &Service,
    home: &Path,
    job: &SwitchJob,
    generation: u64,
    mut owner: switching::Owner,
) -> Result<Value, String> {
    let phase = owner.job_phase(job)?;
    let changed_after_health = if phase == SelectionPhase::Healthy {
        let t = owner
            .record()
            .and_then(|r| r.transaction.as_ref())
            .ok_or_else(|| error("switch_transaction_missing"))?;
        let raw = crate::guard_config_update::read_home_config(home)
            .map_err(|_| error("configuration_unavailable"))?;
        !job.source_disabled || switching::settings_hash(raw.as_deref()) != t.after_settings_sha256
    } else {
        false
    };
    // Health was measured under earlier preferences. A later edit must pass
    // the same explicit bounded verifier; no old settings are written back.
    if matches!(
        phase,
        SelectionPhase::CommitIntent | SelectionPhase::Committed
    ) || changed_after_health
    {
        let current = crate::guard_config_load::context_assistance_config(home)
            .map_err(|_| error("configuration_unavailable"))?;
        service.configure_at(current, generation)?;
        return initial::verify_disabled(service, home, job.clone(), generation, owner);
    }
    let record = owner
        .record()
        .ok_or_else(|| error("switch_selection_missing"))?;
    let t = record
        .transaction
        .as_ref()
        .ok_or_else(|| error("switch_transaction_missing"))?;
    if owner.job_phase(job)? != SelectionPhase::Healthy
        || t.was_enabled
        || t.activate_target
        || record.current != t.to
    {
        return Err(error("switch_recovery_required"));
    }
    let current = crate::guard_config_load::context_assistance_config(home)
        .map_err(|_| error("configuration_unavailable"))?;
    let raw = crate::guard_config_update::read_home_config(home)
        .map_err(|_| error("configuration_unavailable"))?;
    if current.requested.enabled
        || current.effective.enabled
        || current.diagnostic.is_some()
        || current.requested.runtime_id != job.request.target_runtime_id
        || switching::settings_hash(raw.as_deref()) != t.after_settings_sha256
    {
        return Err(error("switch_settings_conflict"));
    }
    if let Some(id) = record.current.data.generation_id() {
        let summary = EvidenceGenerationStore::existing(home)
            .map_err(|e| error(e.code()))?
            .ok_or_else(|| error("switch_data_generation_missing"))?
            .load(id)
            .map_err(|e| error(e.code()))?
            .describe()
            .map_err(|e| error(e.code()))?;
        if summary["phase"] != "ready"
            || summary["target_producer_sha256"] != record.current.runtime.producer_sha256
        {
            return Err(error("switch_data_generation_mismatch"));
        }
    }
    service.configure_at(current.clone(), generation)?;
    {
        let state = lock(&service.state)?;
        if state.closed
            || state.stopping
            || state.generation != generation
            || state.settings != current
            || state.runtime.is_some()
            || state.pending.is_some()
            || state.upgrade.is_some()
            || state.cutover.is_some()
        {
            return Err(error("switch_selection_conflict"));
        }
        owner.complete_publication(&job.request.job_id)?;
        owner.reconcile_job(job)?;
    }
    drop(owner);
    service.switch_job(home, &job.request.job_id)
}

pub(super) fn run(
    shared: Weak<Mutex<State>>,
    home: PathBuf,
    source: Source,
    owner: switching::Owner,
    job: SwitchJob,
    signal: Arc<Signal>,
    receive: std::sync::mpsc::Receiver<Decision>,
) {
    worker::run(shared, home, source, owner, job, signal, receive);
}
