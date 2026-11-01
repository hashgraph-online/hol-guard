//! Commit an SDK/data pair while still off. All SDK work precedes the short
//! native settings/state lane, and later activation requires a separate opt-in.
use super::*;

pub(super) fn run(
    shared: &Weak<Mutex<State>>,
    source: &Source,
    owner: &mut switching::Owner,
    job: &mut SwitchJob,
    signal: &Arc<Signal>,
    prepared: &mut prepare::Prepared,
    deadline: &deadline::Deadline,
) -> Result<(), String> {
    check(shared, source, signal)?;
    prepared.settings.check_current()?;
    prepared.settings.preflight_publish()?;
    prepared.check_data()?;
    prepared
        .target
        .runtime
        .recheck_artifacts()
        .map_err(|e| error(e.code()))?;
    prepared
        .target
        .runtime
        .check_transport()
        .map_err(|e| error(e.code()))?;
    let data = job
        .prepared_data_generation
        .clone()
        .map_or(SelectionData::Memory, |generation_id| {
            SelectionData::Generation { generation_id }
        });
    let (measured, _) = prepared.target_install.measured_selection(
        prepared.settings.home(),
        &prepared.target.runtime,
        data,
    )?;
    if owner
        .record()
        .and_then(|r| r.transaction.as_ref())
        .is_none_or(|t| {
            t.to != measured
                || t.was_enabled
                || t.activate_target
                || t.expected_service_generation != source.generation
        })
    {
        return Err(error("switch_selection_conflict"));
    }
    // Only this private runtime's token closes. The job remains cancellable.
    prepared.target.runtime.close();
    check(shared, source, signal)?;
    owner.advance(SelectionPhase::StopIntent)?;
    let shared = shared.upgrade().ok_or_else(|| error("shutdown"))?;
    let mut state = lock(&shared)?;
    if state.closed
        || state.stopping
        || !source.matches(&state)
        || state.pending.is_some()
        || signal.cancel.load(Ordering::Acquire)
        || state
            .upgrade
            .as_ref()
            .is_none_or(|s| !Arc::ptr_eq(s, signal))
    {
        return Err(error("switch_source_changed"));
    }
    let next = state
        .generation
        .checked_add(1)
        .ok_or_else(|| error("generation_exhausted"))?;
    super::super::worker::step(
        prepared.settings.home(),
        job,
        signal,
        JobPhase::Committing,
        "committing_disabled",
    )?;
    if let Err(code) = owner.commit(&prepared.settings) {
        if !code.ends_with("switch_commit_outcome_unknown") {
            return Err(code);
        }
        owner.reconcile_committed(&job.request.job_id, &prepared.settings)?;
    }
    signal.published.store(true, Ordering::Release);
    prepared.settings.check_target_exact()?;
    #[cfg(test)]
    if let Some(hook) = signal.committed_hook.lock().unwrap().take() {
        hook();
    }
    owner.mark_healthy(&job.request.job_id)?;
    if !signal.complete() {
        return Err(error("switch_cancelled"));
    }
    deadline.finish();
    state.settings = prepared.settings.target_settings().clone();
    state.generation = next;
    state.last_check = None;
    state.retiring = None;
    state.error = None;
    drop(state);
    #[cfg(test)]
    if let Some(hook) = signal.completion_hook.lock().unwrap().take() {
        hook();
    }
    owner.complete_publication(&job.request.job_id)
}
