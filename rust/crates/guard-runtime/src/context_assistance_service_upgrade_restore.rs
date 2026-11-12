//! Bounded best-effort restoration for an unpublished cutover. Native intent
//! survives only in this live owner; SDK contexts, sessions and epochs do not.
use super::*;
use crate::context_assistance_engine::UpgradeBoundary;

pub(super) struct Snapshot {
    pub(super) boundary: UpgradeBoundary,
    pub(super) settings: switching::SwitchSettings,
}
pub(super) struct Prepared {
    pub(super) snapshot: Snapshot,
    pub(super) runtime: VerifiedRuntime,
}
fn check_state(state: &State, source: &Source, signal: &Arc<Signal>) -> Result<(), String> {
    if signal.authority_revoked.load(Ordering::Acquire)
        || signal.restore_cancel.load(Ordering::Acquire)
        || state.closed
        || state.stopping
        || source.generation.checked_add(1) != Some(state.generation)
        || state.settings != source.settings
        || state.runtime.is_some()
        || state
            .upgrade
            .as_ref()
            .is_none_or(|s| !Arc::ptr_eq(s, signal))
        || state
            .cutover
            .as_ref()
            .is_none_or(|c| c.id != signal.request.job_id)
        || !source.actor.cleanup_finished()
    {
        return Err(error("switch_restore_revoked"));
    }
    Ok(())
}
pub(super) fn run(
    shared: &Weak<Mutex<State>>,
    home: &Path,
    source: &Source,
    owner: &mut switching::Owner,
    job: &mut SwitchJob,
    signal: &Arc<Signal>,
    prepared: Prepared,
) -> Result<(), String> {
    let Prepared {
        snapshot,
        mut runtime,
    } = prepared;
    #[cfg(test)]
    let started = Instant::now();
    #[cfg(test)]
    trace("begin", started);
    let limit = jobs::now()?
        .saturating_add(30_000)
        .min(job.deadline_at_ms.saturating_add(30_000));
    job.restoration_deadline_at_ms = Some(limit);
    worker::step(
        home,
        job,
        signal,
        JobPhase::Restoring,
        "restoring_previous_runtime",
    )?;
    let deadline = deadline::Deadline::restore(Arc::clone(signal), shared.clone(), limit)?;
    let shared = shared.upgrade().ok_or_else(|| error("shutdown"))?;
    {
        // Serialize the small config effect with native Stop/config revocation.
        // All verification, source I/O and SDK reconstruction remain outside.
        let state = lock(&shared)?;
        check_state(&state, source, signal)?;
        owner.restore_source(&job.request.job_id, &snapshot.settings)?;
    }
    #[cfg(test)]
    if let Some(hook) = signal.restore_hook.lock().unwrap().take() {
        hook();
    }
    check_state(&*lock(&shared)?, source, signal)?;
    let installation = registry::load(home, &source.settings.effective.runtime_id)?;
    #[cfg(test)]
    trace("installation_loaded", started);
    // This fresh process was fully verified alongside the serving source.
    // Repeat physical/transport checks before data admission; never reuse the
    // stopped source's clients, contexts, session or cancellation token.
    runtime.recheck_artifacts().map_err(|e| error(e.code()))?;
    runtime.check_transport().map_err(|e| error(e.code()))?;
    #[cfg(test)]
    trace("runtime_verified", started);
    let selection = owner.verify_restore_source(
        &job.request.job_id,
        &installation,
        &runtime,
        snapshot.settings.source(),
    )?;
    let (_, producer) = installation.measured_selection(
        home,
        &runtime,
        source_data(owner, &job.request.job_id)?,
    )?;
    #[cfg(test)]
    trace("selection_verified", started);
    check_state(&*lock(&shared)?, source, signal)?;
    snapshot.settings.check_current()?;
    let config = snapshot.settings.source().clone();
    let notifications =
        (config.sources.native_policy_facts || config.sources.sanitized_receipt_facts).then(|| {
            Arc::new(Notifications::with_sources(
                config.sources.native_policy_facts,
                config.sources.sanitized_receipt_facts,
            ))
        });
    let built = snapshot
        .boundary
        .restore(
            home.to_path_buf(),
            config,
            producer,
            selection,
            runtime,
            notifications.clone(),
        )
        .map_err(|e| error(e.code()))?;
    #[cfg(test)]
    trace("engine_built", started);
    #[cfg(target_os = "macos")]
    let execution_ready = built.engine.upgrade_execution_ready();
    let actor = Arc::new(
        RuntimeActor::start_with_maintenance(built.runtime, built.engine, Engine::maintenance)
            .map_err(|e| error(e.code()))?,
    );
    #[cfg(test)]
    if let Some(hook) = signal.restore_ready_hook.lock().unwrap().take() {
        hook(&actor);
    }
    let result = (|| {
        actor
            .call(|runtime, _| {
                runtime.recheck_artifacts()?;
                runtime.check_transport()
            })
            .map_err(|e| error(e.code()))?;
        #[cfg(test)]
        trace("actor_healthy", started);
        let mut state = lock(&shared)?;
        check_state(&state, source, signal)?;
        snapshot.settings.check_current()?;
        owner.finish_restore(&job.request.job_id, &snapshot.settings)?;
        let generation = state
            .generation
            .checked_add(1)
            .ok_or_else(|| error("generation_exhausted"))?;
        lifecycle::start_watcher(Arc::downgrade(&shared), generation, home.to_path_buf())
            .map_err(|_| error("settings_watcher_unavailable"))?;
        if notifications.as_ref().is_some_and(|n| {
            !crate::context_assistance_notifications::register(home.to_path_buf(), n)
        }) {
            return Err(error("notifications_unavailable"));
        }
        if signal.restore_cancel.load(Ordering::Acquire)
            || jobs::now()? >= limit
            || !actor.is_active()
        {
            return Err(error("switch_restore_deadline_exceeded"));
        }
        deadline.finish();
        if signal.restore_cancel.load(Ordering::Acquire) || !actor.is_active() {
            return Err(error("switch_restore_revoked"));
        }
        // Every app must acquire fresh SDK context/session authority. The native
        // epoch was already invalidated at source shutdown and is advanced again.
        state.epoch.invalidate();
        state.generation = generation;
        state.settings = snapshot.settings.source_settings().clone();
        let mut checked = actor.status();
        checked.active = false;
        state.last_check = Some(checked);
        state.runtime = Some(Arc::clone(&actor));
        state.retiring = None;
        state.notifications = notifications;
        state.observations = Default::default();
        #[cfg(target_os = "macos")]
        {
            state.execution_ready = execution_ready;
        }
        state.last_used = Instant::now();
        state.error = None;
        state.cutover = None;
        Ok(())
    })();
    if result.is_err() {
        signal.restore_cancel.store(true, Ordering::Release);
        cleanup::close(signal, cleanup::Role::Restoration, actor);
        if signal.pending_cleanup.active() {
            return Err(error("switch_cleanup_pending"));
        }
    }
    result
}
fn source_data(
    owner: &switching::Owner,
    id: &str,
) -> Result<guard_cigar_release::SelectionData, String> {
    owner
        .record()
        .and_then(|r| r.transaction.as_ref())
        .filter(|t| t.request_id == id)
        .map(|t| t.from.data.clone())
        .ok_or_else(|| error("switch_recovery_required"))
}

#[cfg(test)]
fn trace(stage: &str, started: Instant) {
    eprintln!(
        "CIGAR_RESTORATION_TIMING={}",
        json!({"stage":stage,"elapsed_ms":started.elapsed().as_millis()})
    );
}
