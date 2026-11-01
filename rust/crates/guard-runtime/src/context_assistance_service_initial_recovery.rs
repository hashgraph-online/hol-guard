//! Initial recovery repairs Healthy metadata or explicitly schedules bounded
//! SDK verification of an already selected, still-disabled committed target.
use super::*;
#[path = "context_assistance_service_initial_verify.rs"]
mod verify;

pub(in crate::context_assistance_service::upgrade) fn running(
    service: &Service,
    home: &Path,
    job: &SwitchJob,
    generation: u64,
) -> Result<bool, String> {
    let canonical = std::fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    let pool = service
        .switches
        .pool
        .lock()
        .map_err(|_| error("switch_worker_unavailable"))?;
    let Some(live) = pool.live.as_ref().filter(|l| {
        l.home == canonical
            && l.signal.request.job_id == job.request.job_id
            && !l.thread.is_finished()
    }) else {
        return Ok(false);
    };
    if live
        .signal
        .recovery
        .as_ref()
        .is_none_or(|a| a.expected_generation != generation)
        || !live.signal.matches_job(job)
        || lock(&service.state)?.generation != generation
    {
        return Err(error("switch_selection_conflict"));
    }
    Ok(true)
}

pub(in crate::context_assistance_service::upgrade) fn verify_disabled(
    service: &Service,
    home: &Path,
    job: SwitchJob,
    generation: u64,
    owner: switching::Owner,
) -> Result<Value, String> {
    if job.is_initial() {
        return Err(error("switch_selection_conflict"));
    }
    verify::start(service, home, job, generation, owner)
}

pub(in crate::context_assistance_service::upgrade) fn reconcile(
    service: &Service,
    home: &Path,
    job: &SwitchJob,
    generation: u64,
    mut owner: switching::Owner,
) -> Result<Value, String> {
    let plan = owner.initial_record().cloned();
    if let Some(p) = &plan {
        if p.request_id != job.request.job_id
            || p.expected_service_generation != job.request.expected_generation
            || p.target.runtime.installation_id != job.request.target_runtime_id
        {
            return Err(error("initial_selection_conflict"));
        }
        if p.phase == InitialPhase::Completed {
            owner.reconcile_initial_job(job)?;
            drop(owner);
            return service.switch_job(home, &job.request.job_id);
        }
    }
    let current = crate::guard_config_load::context_assistance_config(home)
        .map_err(|_| error("configuration_unavailable"))?;
    service.configure_at(current.clone(), generation)?;
    if plan.as_ref().is_some_and(|p| {
        matches!(
            p.phase,
            InitialPhase::CommitIntent | InitialPhase::Committed | InitialPhase::RecoveryRequired
        ) && current.requested.runtime_id == p.target.runtime.installation_id
    }) {
        return verify::start(service, home, job.clone(), generation, owner);
    }
    {
        let state = lock(&service.state)?;
        if state.closed
            || state.stopping
            || state.generation != generation
            || state.settings != current
            || current.requested.enabled
            || current.effective.enabled
            || state.runtime.is_some()
            || state.pending.is_some()
            || state.upgrade.is_some()
            || state.cutover.is_some()
        {
            return Err(error("switch_selection_conflict"));
        }
        match plan.as_ref().map(|p| p.phase) {
            Some(InitialPhase::Healthy) => {
                let p = plan.as_ref().unwrap();
                let raw = crate::guard_config_update::read_home_config(home)
                    .map_err(|_| error("configuration_unavailable"))?;
                if current.requested.runtime_id != p.target.runtime.installation_id
                    || switching::settings_hash(raw.as_deref()) != p.after_settings_sha256
                {
                    return Err(error("switch_settings_conflict"));
                }
                owner.complete_initial(&job.request.job_id)?;
                owner.reconcile_initial_job(job)?;
            }
            None
            | Some(InitialPhase::Prepared | InitialPhase::CommitIntent | InitialPhase::Cancelled) =>
            {
                if !current.requested.runtime_id.is_empty()
                    || !current.effective.runtime_id.is_empty()
                {
                    return Err(error("initial_selection_recovery_required"));
                }
                owner.cancel_initial_job(job)?;
            }
            _ => return Err(error("initial_selection_recovery_required")),
        }
    }
    drop(owner);
    service.switch_job(home, &job.request.job_id)
}
