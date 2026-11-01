//! Explicit first selection stays off and has no previous SDK/data pointer.
use super::*;
use guard_cigar_release::{InitialPhase, InitialSelection, SelectionData, SelectionPointer};
use private::PrivateRuntime;
use std::sync::mpsc::Receiver;
#[path = "context_assistance_service_initial_recovery.rs"]
mod recovery;
pub(super) use recovery::{reconcile, running, verify_disabled};

struct Prepared {
    settings: switching::SwitchSettings,
    target: PrivateRuntime,
    installation: registry::Installation,
    proof: switching::EmptyDataProof,
    pointer: SelectionPointer,
}
fn prepare(
    shared: &Weak<Mutex<State>>,
    home: &Path,
    source: &cold::Source,
    owner: &mut switching::Owner,
    job: &mut SwitchJob,
    signal: &Arc<Signal>,
) -> Result<Prepared, String> {
    cold::check(shared, source, signal)?;
    if !job.is_initial() || !signal.is_initial() || !source.settings.effective.runtime_id.is_empty()
    {
        return Err(error("initial_selection_conflict"));
    }
    let settings = switching::SwitchSettings::capture(
        home,
        &source.settings.effective,
        &job.request.target_runtime_id,
    )?;
    if settings.source_settings() != &source.settings {
        return Err(error("switch_settings_conflict"));
    }
    let proof = switching::EmptyDataProof::capture(owner)?;
    let installation = registry::load(home, &job.request.target_runtime_id)?;
    crate::guard_config_load::cigar_updates::check_installation(
        home,
        settings.update_preferences(),
        &installation,
    )?;
    worker::step(
        home,
        job,
        signal,
        JobPhase::Verifying,
        "verifying_initial_target",
    )?;
    let target = PrivateRuntime::start(&installation, home, settings.target(), signal)?;
    cold::check(shared, source, signal)?;
    let data = if settings.target().storage.mode == StorageMode::Memory {
        SelectionData::Memory
    } else {
        SelectionData::LegacySaved
    };
    let (pointer, _) = installation.measured_selection(home, &target.runtime, data)?;
    worker::step(
        home,
        job,
        signal,
        JobPhase::PreparingData,
        "checking_empty_data",
    )?;
    owner.begin_initial(
        InitialSelection {
            schema: "guard-cigar-initial-selection.v1".into(),
            revision: 1,
            request_id: job.request.job_id.clone(),
            expected_service_generation: source.generation,
            before_settings_sha256: settings.before_sha256(),
            after_settings_sha256: settings.after_sha256(),
            empty_data_sha256: proof.sha256().into(),
            target: pointer.clone(),
            phase: InitialPhase::Prepared,
        },
        &settings,
        &proof,
    )?;
    settings.check_current()?;
    cold::check(shared, source, signal)?;
    Ok(Prepared {
        settings,
        target,
        installation,
        proof,
        pointer,
    })
}
fn commit(
    shared: &Weak<Mutex<State>>,
    source: &cold::Source,
    owner: &mut switching::Owner,
    job: &mut SwitchJob,
    signal: &Arc<Signal>,
    prepared: &mut Prepared,
    deadline: &deadline::Deadline,
) -> Result<(), String> {
    cold::check(shared, source, signal)?;
    prepared.settings.check_current()?;
    prepared.settings.preflight_publish()?;
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
    let (measured, _) = prepared.installation.measured_selection(
        prepared.settings.home(),
        &prepared.target.runtime,
        prepared.pointer.data.clone(),
    )?;
    if measured != prepared.pointer
        || owner.initial_record().is_none_or(|p| {
            p.target != measured
                || p.request_id != job.request.job_id
                || p.expected_service_generation != source.generation
        })
    {
        return Err(error("initial_selection_conflict"));
    }
    prepared.target.runtime.close();
    cold::check(shared, source, signal)?;
    #[cfg(test)]
    if let Some(hook) = signal.before_commit_hook.lock().unwrap().take() {
        hook();
    }
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
    worker::step(
        prepared.settings.home(),
        job,
        signal,
        JobPhase::Committing,
        "committing_initial_selection",
    )?;
    if let Err(code) =
        owner.commit_initial(&job.request.job_id, &prepared.settings, &prepared.proof)
    {
        if !code.ends_with("switch_commit_outcome_unknown") {
            return Err(code);
        }
        owner.reload()?;
        let proof = switching::EmptyDataProof::capture_for_initial(owner, &job.request.job_id)?;
        owner.reconcile_initial_committed(
            &job.request.job_id,
            &prepared.settings,
            &proof,
            &measured,
        )?;
    }
    signal.published.store(true, Ordering::Release);
    prepared.settings.check_target_exact()?;
    #[cfg(test)]
    if let Some(hook) = signal.committed_hook.lock().unwrap().take() {
        hook();
    }
    owner.mark_initial_healthy(&job.request.job_id)?;
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
    owner.complete_initial(&job.request.job_id)
}
fn cancel_owned(owner: &mut switching::Owner, id: &str) -> Result<(), String> {
    owner.reload()?;
    match owner.initial_record() {
        Some(p) if p.request_id == id => owner.cancel_initial(id),
        Some(p) if !p.phase.terminal() => Err(error("initial_selection_recovery_required")),
        _ => Ok(()),
    }
}
pub(super) fn run(
    shared: Weak<Mutex<State>>,
    home: PathBuf,
    source: cold::Source,
    mut owner: switching::Owner,
    mut job: SwitchJob,
    signal: Arc<Signal>,
    receive: Receiver<Decision>,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let deadline = deadline::Deadline::start(
            home.clone(),
            job.clone(),
            Arc::clone(&signal),
            shared.clone(),
        )?;
        let mut prepared = prepare(&shared, &home, &source, &mut owner, &mut job, &signal)?;
        worker::step(
            &home,
            &mut job,
            &signal,
            JobPhase::Ready,
            "ready_initial_selection",
        )?;
        loop {
            cold::check(&shared, &source, &signal)?;
            prepared.settings.check_current()?;
            if jobs::now()? >= job.deadline_at_ms {
                return Err(error("switch_deadline_exceeded"));
            }
            match receive.recv_timeout(Duration::from_millis(25)) {
                Ok(Decision::Commit) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(error("switch_cancelled")),
            }
        }
        commit(
            &shared,
            &source,
            &mut owner,
            &mut job,
            &signal,
            &mut prepared,
            &deadline,
        )
    }))
    .unwrap_or_else(|_| Err(error("switch_worker_failed")));
    let (phase, code) = match result {
        Ok(()) => (
            JobPhase::Completed,
            "completed_initial_selection".to_owned(),
        ),
        Err(_) if signal.published.load(Ordering::Acquire) => (
            JobPhase::RecoveryRequired,
            "initial_selection_completion_pending".into(),
        ),
        Err(code) => {
            job.failure_code = Some(worker::diagnostic(&code));
            signal.cancel.store(true, Ordering::Release);
            if cancel_owned(&mut owner, &job.request.job_id).is_err() {
                (
                    JobPhase::RecoveryRequired,
                    "initial_selection_recovery_required".into(),
                )
            } else if code.ends_with("switch_cancelled") {
                (JobPhase::Cancelled, "cancelled_initial_selection".into())
            } else {
                (JobPhase::Failed, worker::diagnostic(&code))
            }
        }
    };
    let _ = worker::step(&home, &mut job, &signal, phase, &code);
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
