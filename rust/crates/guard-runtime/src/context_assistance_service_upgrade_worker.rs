//! Actual verification/data work runs beside the serving source actor.
use super::*;
use guard_cigar_release::{SelectionData, SelectionPhase, SelectionTransaction};
use guard_context_assistance::EvidenceUpgradeProducer;
use std::sync::mpsc::Receiver;

pub(super) struct Candidate {
    pub(super) actor: Arc<RuntimeActor<Engine>>,
    pub(super) semantic: String,
    pub(super) producer: EvidenceUpgradeProducer,
    pub(super) notifications: Option<Arc<Notifications>>,
    #[cfg(target_os = "macos")]
    pub(super) execution_ready: Arc<AtomicBool>,
}
pub(super) fn step(
    home: &Path,
    job: &mut SwitchJob,
    signal: &Signal,
    phase: JobPhase,
    code: &str,
) -> Result<(), String> {
    // Ready history must never precede live commit readiness. Status also
    // requires both observations, so an unacknowledged progress write cannot
    // advertise a commit or authorize an SDK effect.
    if phase == JobPhase::Ready {
        *signal
            .ready_data
            .lock()
            .map_err(|_| error("switch_worker_unavailable"))? =
            Some(job.prepared_data_generation.clone());
        signal.set_phase(phase);
    }
    jobs::save(home, job, phase, code)?;
    signal.set_phase(phase);
    Ok(())
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
        || state.generation != source.generation
        || state.settings != source.settings
        || state
            .upgrade
            .as_ref()
            .is_none_or(|s| !Arc::ptr_eq(s, signal))
        || state
            .runtime
            .as_ref()
            .is_none_or(|a| !Arc::ptr_eq(a, &source.actor))
        || !source.actor.is_active()
    {
        return Err(error("switch_source_changed"));
    }
    Ok(())
}
fn prepare(
    shared: &Weak<Mutex<State>>,
    home: &Path,
    source: &Source,
    owner: &mut switching::Owner,
    job: &mut SwitchJob,
    signal: &Arc<Signal>,
) -> Result<(Candidate, switching::SwitchSettings), String> {
    check(shared, source, signal)?;
    let settings = switching::SwitchSettings::capture(
        home,
        &source.settings.effective,
        &job.request.target_runtime_id,
    )?;
    if settings.source_settings() != &source.settings {
        return Err(error("switch_settings_conflict"));
    }
    let from_install = registry::load(home, &source.settings.effective.runtime_id)?;
    let to_install = registry::load(home, &job.request.target_runtime_id)?;
    crate::guard_config_load::cigar_updates::check_installation(
        home,
        settings.update_preferences(),
        &to_install,
    )?;
    let source_home = home.to_path_buf();
    let (from, producer) = source
        .actor
        .call(move |runtime, engine| {
            let data = engine.upgrade_selection_data(&source_home)?;
            from_install
                .measured_selection(&source_home, runtime, data)
                .map_err(|_| guard_context_assistance::RuntimeError::ApprovalMismatch)
        })
        .map_err(|e| error(e.code()))?;
    owner.initialize(from.clone())?;
    step(home, job, signal, JobPhase::Verifying, "verifying")?;
    let runtime = verification::runtime(
        &to_install,
        home,
        settings.target(),
        Arc::clone(&signal.cancel),
    )?;
    let (target_stamp, target_producer) =
        to_install.measured_selection(home, &runtime, SelectionData::Memory)?;
    owner.check_rollback_target(&job.request, &target_stamp.runtime)?;
    check(shared, source, signal)?;
    step(home, job, signal, JobPhase::PreparingData, "preparing_data")?;
    let old = settings.source().clone();
    let target = settings.target().clone();
    let old_producer = producer.clone();
    let request = job.request.job_id.clone();
    let capture = source
        .actor
        .call(move |runtime, engine| {
            engine.prepare_upgrade_capture(
                runtime,
                old,
                target,
                old_producer,
                target_producer,
                &request,
            )
        })
        .map_err(|e| error(e.code()))?;
    let notifications = (settings.target().sources.native_policy_facts
        || settings.target().sources.sanitized_receipt_facts)
        .then(|| {
            Arc::new(Notifications::with_sources(
                settings.target().sources.native_policy_facts,
                settings.target().sources.sanitized_receipt_facts,
            ))
        });
    let built = capture
        .build(runtime, notifications.clone())
        .map_err(|e| error(e.code()))?;
    check(shared, source, signal)?;
    let data = built
        .data_generation
        .as_ref()
        .map_or(SelectionData::Memory, |id| SelectionData::Generation {
            generation_id: id.clone(),
        });
    let (to, _) = to_install.measured_selection(home, &built.runtime, data)?;
    job.prepared_data_generation = built.data_generation;
    owner.begin(SelectionTransaction {
        request_id: job.request.job_id.clone(),
        expected_service_generation: source.generation,
        before_settings_sha256: settings.before_sha256(),
        after_settings_sha256: settings.after_sha256(),
        source_semantic_sha256: built.source_semantic_sha256.clone(),
        from,
        to,
        was_enabled: settings.source().enabled,
        activate_target: true,
        reconnect_acknowledged: false,
        cancel_requested: false,
        phase: SelectionPhase::Prepared,
    })?;
    #[cfg(target_os = "macos")]
    let execution_ready = built.engine.upgrade_execution_ready();
    let actor = Arc::new(
        RuntimeActor::start_with_maintenance(built.runtime, built.engine, Engine::maintenance)
            .map_err(|e| error(e.code()))?,
    );
    #[cfg(test)]
    {
        *signal.prepared_actor.lock().unwrap() = Arc::downgrade(&actor);
    }
    let candidate = Candidate {
        actor,
        semantic: built.source_semantic_sha256,
        producer,
        notifications,
        #[cfg(target_os = "macos")]
        execution_ready,
    };
    Ok((candidate, settings))
}
pub(super) fn diagnostic(code: &str) -> String {
    let code = code
        .strip_prefix("native_context_assistance_")
        .unwrap_or(code);
    if !code.is_empty()
        && code.len() <= 128
        && code
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        code.to_owned()
    } else {
        "switch_worker_failed".into()
    }
}
pub(super) fn run(
    shared: Weak<Mutex<State>>,
    home: PathBuf,
    source: Source,
    mut owner: switching::Owner,
    mut job: SwitchJob,
    signal: Arc<Signal>,
    receive: Receiver<Decision>,
) {
    let mut candidate = None;
    let mut restoration = None;
    let mut recovery_runtime = None;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let deadline = deadline::Deadline::start(
            home.clone(),
            job.clone(),
            Arc::clone(&signal),
            shared.clone(),
        )?;
        let (prepared, settings) = prepare(&shared, &home, &source, &mut owner, &mut job, &signal)?;
        // Register ownership before any further fallible progress or SDK work.
        candidate = Some(prepared);
        step(
            &home,
            &mut job,
            &signal,
            JobPhase::PreparingRecovery,
            "preparing_recovery",
        )?;
        recovery_runtime = Some(warm::prepare(
            &home,
            &source,
            &owner,
            &job.request.job_id,
            &settings,
            &signal,
        )?);
        check(&shared, &source, &signal)?;
        step(&home, &mut job, &signal, JobPhase::Ready, "ready")?;
        loop {
            check(&shared, &source, &signal)?;
            if jobs::now()? >= job.deadline_at_ms {
                return Err(error("switch_deadline_exceeded"));
            }
            match receive.recv_timeout(Duration::from_millis(25)) {
                Ok(Decision::Commit) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Err(error("switch_cancelled")),
            }
        }
        commit::Cutover {
            shared: &shared,
            home: &home,
            source: &source,
            owner: &mut owner,
            job: &mut job,
            signal: &signal,
            candidate: candidate
                .as_ref()
                .ok_or_else(|| error("switch_candidate_missing"))?,
            settings: &settings,
            deadline: &deadline,
            restoration: &mut restoration,
        }
        .run()
    }))
    .unwrap_or_else(|_| Err(error("switch_worker_failed")));
    let (phase, code) = match result {
        Ok(()) => (JobPhase::Completed, "completed".to_owned()),
        Err(_) if signal.published.load(Ordering::Acquire) => (
            JobPhase::RecoveryRequired,
            "switch_publication_acknowledgement_pending".to_owned(),
        ),
        Err(code) => {
            job.failure_code = Some(diagnostic(&code));
            signal.cancel.store(true, Ordering::Release);
            if let Some(prepared) = candidate.take() {
                cleanup::close(&signal, cleanup::Role::Candidate, prepared.actor);
            }
            if signal.source_revoked.load(Ordering::Acquire) {
                cleanup::close(&signal, cleanup::Role::Source, Arc::clone(&source.actor));
            }
            let actor_clean = cleanup::drain(&home, &mut job, &signal).is_ok();
            if signal.source_revoked.load(Ordering::Acquire) {
                let restored = actor_clean
                    && source.actor.cleanup_finished()
                    && !signal.authority_revoked.load(Ordering::Acquire)
                    && restoration.take().zip(recovery_runtime.take()).is_some_and(
                        |(snapshot, runtime)| {
                            let prepared = restore::Prepared { snapshot, runtime };
                            let outcome =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    restore::run(
                                        &shared, &home, &source, &mut owner, &mut job, &signal,
                                        prepared,
                                    )
                                }))
                                .unwrap_or_else(|_| Err(error("switch_restore_failed")));
                            match outcome {
                                Ok(()) => true,
                                Err(code) => {
                                    job.restoration_failure_code = Some(diagnostic(&code));
                                    false
                                }
                            }
                        },
                    );
                if !restored {
                    signal.restore_cancel.store(true, Ordering::Release);
                    // A fresh source attempt may itself own private state
                    // after a failed close acknowledgement. Keep the same
                    // lease and generation until that state is really gone.
                    let _ = cleanup::drain(&home, &mut job, &signal);
                }
                if restored && owner.discard_job_data(&job.request.job_id).is_err() {
                    (
                        JobPhase::RecoveryRequired,
                        "switch_previous_runtime_restored_cleanup_pending".into(),
                    )
                } else if restored {
                    if code.ends_with("switch_cancelled") {
                        (
                            JobPhase::Cancelled,
                            "cancelled_previous_runtime_restored".into(),
                        )
                    } else {
                        (
                            JobPhase::Failed,
                            "switch_failed_previous_runtime_restored".into(),
                        )
                    }
                } else {
                    (
                        JobPhase::RecoveryRequired,
                        "switch_recovery_required".into(),
                    )
                }
            } else {
                let cleaned = if actor_clean {
                    owner
                        .cancel_precommit(&job.request.job_id)
                        .and_then(|_| owner.discard_job_data(&job.request.job_id))
                } else {
                    Err(error("switch_recovery_required"))
                };
                if !actor_clean || cleaned.is_err() {
                    (
                        JobPhase::RecoveryRequired,
                        "switch_recovery_required".into(),
                    )
                } else if code.ends_with("switch_cancelled") {
                    (JobPhase::Cancelled, "cancelled".into())
                } else {
                    (
                        JobPhase::Failed,
                        code.strip_prefix("native_context_assistance_")
                            .unwrap_or("switch_failed")
                            .into(),
                    )
                }
            }
        }
    };
    let _ = step(&home, &mut job, &signal, phase, &code);
    // State owns a published actor even if completion metadata failed. This
    // extra Arc cannot cancel it; only unpublished failures were closed above.
    drop(candidate);
    drop(recovery_runtime);
    drop(owner);
    signal.cleaned.store(true, Ordering::Release);
    if let Some(shared) = shared.upgrade() {
        if let Ok(mut state) = lock(&shared) {
            if state
                .runtime
                .as_ref()
                .is_some_and(|a| Arc::ptr_eq(a, &source.actor) && !a.is_active())
            {
                revoke_runtime(&mut state);
                state.error = Some("runtime_closed".into());
            }
            if state
                .upgrade
                .as_ref()
                .is_some_and(|s| Arc::ptr_eq(s, &signal))
            {
                state.upgrade = None;
            }
            if state
                .cutover
                .as_ref()
                .is_some_and(|f| f.id == signal.request.job_id)
            {
                state.cutover = None;
                if phase != JobPhase::Completed {
                    state.error = Some("switch_recovery_required".into());
                }
            }
        }
    }
}
