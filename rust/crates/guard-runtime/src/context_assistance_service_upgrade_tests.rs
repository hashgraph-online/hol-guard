use super::*;

fn signal() -> Arc<Signal> {
    Arc::new(Signal::new(SwitchRequest {
        job_id: "switch-race".into(),
        target_runtime_id: "target".into(),
        expected_generation: 7,
        rollback: false,
    }))
}
#[test]
fn cancellation_and_publication_have_one_winner_and_never_cancel_a_published_actor() {
    for _ in 0..128 {
        let signal = signal();
        signal.set_phase(JobPhase::Committing);
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let s = Arc::clone(&signal);
        let b = Arc::clone(&barrier);
        let complete = std::thread::spawn(move || {
            b.wait();
            s.complete()
        });
        let s = Arc::clone(&signal);
        let b = Arc::clone(&barrier);
        let cancel = std::thread::spawn(move || {
            b.wait();
            s.request_cancel()
        });
        barrier.wait();
        let completed = complete.join().unwrap();
        let cancelled = cancel.join().unwrap();
        assert_ne!(completed, cancelled);
        assert_eq!(signal.cancel.load(Ordering::Acquire), cancelled);
        assert_eq!(
            signal.phase(),
            if completed {
                JobPhase::Completed
            } else {
                JobPhase::Cancelling
            }
        );
        if completed {
            assert!(!signal.request_cancel());
            assert!(!signal.cancel.load(Ordering::Acquire));
        }
    }
}
#[test]
fn progress_cannot_reverse_a_cancellation_or_a_completed_publication() {
    let signal = signal();
    assert!(signal.request_cancel());
    for phase in [JobPhase::Verifying, JobPhase::Ready, JobPhase::Committing] {
        signal.set_phase(phase);
        assert_eq!(signal.phase(), JobPhase::Cancelling);
    }
    assert!(!signal.complete());
    signal.set_phase(JobPhase::Cancelled);
    assert!(!signal.request_cancel());
    let signal = super::tests::signal();
    signal.set_phase(JobPhase::Committing);
    assert!(signal.complete());
    signal.set_phase(JobPhase::Failed);
    assert_eq!(signal.phase(), JobPhase::Completed);
}
#[test]
fn the_cutover_fence_defers_only_its_own_settings_and_never_defers_stop() {
    let service = Service::default();
    let mut source = AssistanceSettings::default();
    source.requested.enabled = true;
    source.effective.enabled = true;
    source.requested.runtime_id = "source".into();
    source.effective.runtime_id = "source".into();
    let mut target = source.clone();
    target.requested.runtime_id = "target".into();
    target.effective.runtime_id = "target".into();
    service.configure(source.clone()).unwrap();
    let generation = service.configuration_generation().unwrap();
    let signal = signal();
    {
        let mut state = lock(&service.state).unwrap();
        state.upgrade = Some(Arc::clone(&signal));
        state.cutover = Some(Cutover {
            id: "switch-race".into(),
            source: source.clone(),
            target: target.clone(),
        });
    }
    service.configure_at(target.clone(), generation).unwrap();
    assert!(lock(&service.state).unwrap().settings == source);
    assert_eq!(service.configuration_generation().unwrap(), generation);
    assert!(!signal.cancel.load(Ordering::Acquire));
    let mut narrowed = target;
    narrowed.requested.enabled = false;
    narrowed.effective.enabled = false;
    service.configure_at(narrowed.clone(), generation).unwrap();
    assert!(lock(&service.state).unwrap().settings == narrowed);
    assert!(signal.cancel.load(Ordering::Acquire));
    assert!(lock(&service.state).unwrap().cutover.is_none());
}

#[test]
fn cancelling_an_upgrade_allows_rebuilding_the_previous_selection_but_stop_revokes_both_tokens() {
    let signal = signal();
    signal.set_phase(JobPhase::Committing);
    assert!(signal.request_cancel());
    assert!(signal.cancel.load(Ordering::Acquire));
    assert!(!signal.restore_cancel.load(Ordering::Acquire));
    signal.set_phase(JobPhase::Restoring);
    assert_eq!(signal.phase(), JobPhase::Restoring);
    signal.revoke();
    assert!(signal.authority_revoked.load(Ordering::Acquire));
    assert!(signal.restore_cancel.load(Ordering::Acquire));
}

#[test]
fn background_recovery_preparation_propagates_cancel_but_a_finished_bridge_cannot_kill_recovery() {
    let pending = signal();
    let bridge = deadline::Deadline::preparing_recovery(Arc::clone(&pending)).unwrap();
    assert!(pending.request_cancel());
    let start = Instant::now();
    while !pending.restore_cancel.load(Ordering::Acquire) {
        assert!(start.elapsed() < Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(5));
    }
    bridge.finish();
    let prepared = signal();
    let bridge = deadline::Deadline::preparing_recovery(Arc::clone(&prepared)).unwrap();
    bridge.finish();
    assert!(prepared.request_cancel());
    std::thread::sleep(Duration::from_millis(60));
    assert!(!prepared.restore_cancel.load(Ordering::Acquire));
    prepared.revoke();
    assert!(prepared.restore_cancel.load(Ordering::Acquire));
}

#[test]
fn disabled_source_capture_has_no_actor_and_stop_invalidates_its_generation() {
    let service = Service::default();
    let mut settings = AssistanceSettings::default();
    settings.requested.runtime_id = "source".into();
    settings.effective.runtime_id = "source".into();
    service.configure(settings).unwrap();
    let request = SwitchRequest {
        job_id: "cold-capture".into(),
        target_runtime_id: "target".into(),
        expected_generation: service.configuration_generation().unwrap(),
        rollback: false,
    };
    let captured = input::capture(&service.state, &request).unwrap();
    assert!(captured.matches(&lock(&service.state).unwrap()));
    let job = captured.job(request).unwrap();
    assert!(job.source_disabled);
    let signal = Arc::new(Signal::for_job(&job));
    assert_eq!(signal.describe()["reconnect_required"], false);
    lock(&service.state).unwrap().upgrade = Some(Arc::clone(&signal));
    assert!(service.status().unwrap()["runtime"].is_null());
    assert_eq!(service.status().unwrap()["availability"], "off");
    service.stop().unwrap();
    assert!(signal.cancel.load(Ordering::Acquire));
    assert!(!captured.matches(&lock(&service.state).unwrap()));
    assert_eq!(service.status().unwrap()["requested_enabled"], false);
}

#[test]
fn closing_one_private_sdk_cannot_cancel_the_job_or_another_private_sdk() {
    let signal = signal();
    let source = Arc::new(AtomicBool::new(false));
    let target = Arc::new(AtomicBool::new(false));
    let source_relay =
        deadline::Deadline::forward_cancel(Arc::clone(&signal), Arc::clone(&source)).unwrap();
    let target_relay =
        deadline::Deadline::forward_cancel(Arc::clone(&signal), Arc::clone(&target)).unwrap();
    source.store(true, Ordering::Release);
    source_relay.finish();
    assert!(!signal.cancel.load(Ordering::Acquire));
    assert!(!target.load(Ordering::Acquire));
    assert!(signal.request_cancel());
    let started = Instant::now();
    while !target.load(Ordering::Acquire) {
        assert!(started.elapsed() < Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(5));
    }
    target_relay.finish();
}

#[test]
fn live_commit_identity_includes_request_source_mode_and_the_native_ready_data_id() {
    let request = SwitchRequest {
        job_id: "bound-live".into(),
        target_runtime_id: "target".into(),
        expected_generation: 7,
        rollback: false,
    };
    let mut job = SwitchJob::new_disabled(request, "source".into()).unwrap();
    job.prepared_data_generation = Some("7".repeat(64));
    let signal = Signal::for_job(&job);
    *signal.ready_data.lock().unwrap() = Some(job.prepared_data_generation.clone());
    signal.set_phase(JobPhase::Ready);
    assert!(signal.matches_job(&job));
    let mut other = job.clone();
    other.request.target_runtime_id = "other-target".into();
    assert!(!signal.matches_job(&other));
    let mut other = job.clone();
    other.request.expected_generation += 1;
    assert!(!signal.matches_job(&other));
    let mut other = job.clone();
    other.source_runtime_id = "different-source".into();
    assert!(!signal.matches_job(&other));
    let mut other = job.clone();
    other.source_disabled = false;
    assert!(!signal.matches_job(&other));
    let mut other = job;
    other.prepared_data_generation = Some("8".repeat(64));
    assert!(!signal.matches_job(&other));
}

#[test]
fn stale_recovery_cancellation_does_not_cancel_a_new_native_attempt() {
    let mut job = SwitchJob::new_initial(SwitchRequest {
        job_id: "initial-recovery".into(),
        target_runtime_id: "target".into(),
        expected_generation: 1,
        rollback: false,
    })
    .unwrap();
    let now = jobs::now().unwrap();
    job.recovery = Some(jobs::RecoveryAttempt {
        id: "a".repeat(32),
        expected_generation: 2,
        started_at_ms: now,
        deadline_at_ms: now + 120_000,
    });
    let signal = Signal::for_job(&job);
    signal.set_phase(JobPhase::PreparingRecovery);
    let mut stale = job.clone();
    stale.recovery.as_mut().unwrap().id = "b".repeat(32);
    assert!(signal.request_cancel_for(&stale).is_err());
    assert!(!signal.cancel.load(Ordering::Acquire));
    assert_eq!(signal.phase(), JobPhase::PreparingRecovery);
    assert!(signal.request_cancel_for(&job).unwrap());
    assert!(signal.cancel.load(Ordering::Acquire));
}

#[test]
fn recovery_of_a_stopped_live_switch_has_no_reconnect_or_commit_authority() {
    let mut job = SwitchJob::new(
        SwitchRequest {
            job_id: "stopped-live-recovery".into(),
            target_runtime_id: "target".into(),
            expected_generation: 1,
            rollback: false,
        },
        "source".into(),
    )
    .unwrap();
    let now = jobs::now().unwrap();
    job.recovery = Some(jobs::RecoveryAttempt {
        id: "a".repeat(32),
        expected_generation: 2,
        started_at_ms: now,
        deadline_at_ms: now + 120_000,
    });
    let signal = Signal::for_job(&job);
    signal.set_phase(JobPhase::PreparingRecovery);
    assert!(signal.matches_job(&job));
    assert!(
        !signal.source_disabled,
        "original request mode is immutable"
    );
    assert_eq!(signal.describe()["operation"], "recover");
    assert_eq!(signal.describe()["reconnect_required"], false);
    assert!(
        !signal.complete(),
        "verification progress is not a commit handle"
    );
}
