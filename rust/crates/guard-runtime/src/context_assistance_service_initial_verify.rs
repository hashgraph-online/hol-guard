//! Shared disabled committed-target verification stays on the bounded worker.
//! No SDK is attached to Service and no source/app authority is reconstructed.
use super::*;
#[path = "context_assistance_service_disabled_recovery_target.rs"]
mod target;
use target::RecoveryTarget;

struct Recovery {
    home: PathBuf,
    source: cold::Source,
    owner: switching::Owner,
    job: SwitchJob,
    target: RecoveryTarget,
    signal: Arc<Signal>,
}

pub(super) fn start(
    service: &Service,
    home: &Path,
    job: SwitchJob,
    generation: u64,
    mut owner: switching::Owner,
) -> Result<Value, String> {
    let mut pool = service
        .switches
        .pool
        .lock()
        .map_err(|_| error("switch_worker_unavailable"))?;
    if pool.closed {
        return Err(error("shutdown"));
    }
    if pool.live.as_ref().is_some_and(|l| !l.thread.is_finished()) {
        return Err(error("switch_busy"));
    }
    if let Some(old) = pool.live.take() {
        let _ = old.thread.join();
    }
    let home = std::fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
    let source = {
        let state = lock(&service.state)?;
        if state.closed
            || state.stopping
            || state.generation != generation
            || state.settings.requested.enabled
            || state.settings.effective.enabled
            || state.runtime.is_some()
            || state.pending.is_some()
            || state.upgrade.is_some()
            || state.cutover.is_some()
            || state
                .retiring
                .as_ref()
                .is_some_and(|a| !a.cleanup_finished())
        {
            return Err(error("switch_selection_conflict"));
        }
        cold::Source {
            settings: state.settings.clone(),
            generation,
        }
    };
    let (target, mut job) = RecoveryTarget::admit(&mut owner, &job, generation)?;
    if target.settings() != &source.settings {
        return Err(error("switch_settings_conflict"));
    }
    let signal = Arc::new(Signal::for_job(&job));
    signal.set_phase(JobPhase::PreparingRecovery);
    {
        let mut state = lock(&service.state)?;
        if state.closed
            || state.stopping
            || !source.matches(&state)
            || state.pending.is_some()
            || state.upgrade.is_some()
            || state.cutover.is_some()
        {
            let code = if job.is_initial() {
                "initial_recovery_source_changed"
            } else {
                "disabled_recovery_source_changed"
            };
            jobs::save(&home, &mut job, JobPhase::RecoveryRequired, code)?;
            return Err(error("switch_selection_conflict"));
        }
        state.upgrade = Some(Arc::clone(&signal));
    }
    let (decision, _receive) = mpsc::sync_channel(1);
    let (begin, start) = mpsc::sync_channel(1);
    let shared = Arc::downgrade(&service.state);
    let thread_signal = Arc::clone(&signal);
    let thread_home = home.clone();
    let thread = std::thread::Builder::new()
        .name("guard-cigar-switch".into())
        .spawn(move || {
            if start.recv().is_err() {
                thread_signal.cancel.store(true, Ordering::Release);
            }
            run(
                shared,
                Recovery {
                    home: thread_home,
                    source,
                    owner,
                    job,
                    target,
                    signal: thread_signal,
                },
            );
        })
        .map_err(|_| {
            signal.cancel.store(true, Ordering::Release);
            if let Ok(mut state) = lock(&service.state) {
                if state
                    .upgrade
                    .as_ref()
                    .is_some_and(|s| Arc::ptr_eq(s, &signal))
                {
                    state.upgrade = None;
                }
            }
            error("switch_worker_unavailable")
        })?;
    let id = signal.request.job_id.clone();
    pool.live = Some(Live {
        home: home.clone(),
        signal,
        decision,
        thread,
    });
    begin
        .send(())
        .map_err(|_| error("switch_worker_unavailable"))?;
    drop(pool);
    service.switch_job(&home, &id)
}

fn run(shared: Weak<Mutex<State>>, recovery: Recovery) {
    let Recovery {
        home,
        source,
        mut owner,
        mut job,
        target,
        signal,
    } = recovery;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let deadline = deadline::Deadline::start(
            home.clone(),
            job.clone(),
            Arc::clone(&signal),
            shared.clone(),
        )?;
        cold::check(&shared, &source, &signal)?;
        target.check()?;
        let installation = registry::load(&home, &job.request.target_runtime_id)?;
        crate::guard_config_load::cigar_updates::check_installation(
            &home,
            target.rules(),
            &installation,
        )?;
        let mut sdk =
            PrivateRuntime::start(&installation, &home, &target.settings().effective, &signal)?;
        #[cfg(test)]
        if let Some(hook) = signal.before_commit_hook.lock().unwrap().take() {
            hook();
        }
        cold::check(&shared, &source, &signal)?;
        target.check()?;
        sdk.runtime
            .recheck_artifacts()
            .map_err(|e| error(e.code()))?;
        sdk.runtime.check_transport().map_err(|e| error(e.code()))?;
        let (measured, _) =
            installation.measured_selection(&home, &sdk.runtime, target.pointer().data.clone())?;
        if &measured != target.pointer() {
            return Err(error(target.conflict_code()));
        }
        sdk.runtime.close();
        drop(sdk);
        cold::check(&shared, &source, &signal)?;
        target.check()?;
        let current = shared.upgrade().ok_or_else(|| error("shutdown"))?;
        let state = lock(&current)?;
        if state.closed
            || state.stopping
            || !source.matches(&state)
            || state.pending.is_some()
            || signal.cancel.load(Ordering::Acquire)
            || state
                .upgrade
                .as_ref()
                .is_none_or(|s| !Arc::ptr_eq(s, &signal))
            || !signal.matches_job(
                &jobs::get(&home, &job.request.job_id)?
                    .ok_or_else(|| error("switch_job_missing"))?,
            )
        {
            return Err(error("switch_source_changed"));
        }
        worker::step(
            &home,
            &mut job,
            &signal,
            JobPhase::Committing,
            target.commit_code(),
        )?;
        target.recover(&mut owner, &job, &measured)?;
        target.check()?;
        if signal.cancel.load(Ordering::Acquire) {
            return Err(error("switch_cancelled"));
        }
        target.healthy(&mut owner, &job.request.job_id)?;
        if !signal.complete() {
            return Err(error("switch_cancelled"));
        }
        deadline.finish();
        drop(state);
        target.complete(&mut owner, &job.request.job_id)?;
        target.reconcile_job(&owner, &job)
    }))
    .unwrap_or_else(|_| Err(error("switch_worker_failed")));
    if let Err(code) = result {
        job.failure_code = Some(worker::diagnostic(&code));
        let _ = worker::step(
            &home,
            &mut job,
            &signal,
            JobPhase::RecoveryRequired,
            target.failure_code(),
        );
    }
    drop(owner);
    signal.cleaned.store(true, Ordering::Release);
    if let Some(shared) = shared.upgrade() {
        if let Ok(mut state) = lock(&shared) {
            if state
                .upgrade
                .as_ref()
                .is_some_and(|s| Arc::ptr_eq(s, &signal))
            {
                state.upgrade = None;
            }
        }
    }
}
