//! Actual SDK private-state destruction gates prove the profile owner outlives
//! cancellation and bounded control responses, rather than inferring cleanup.
use super::*;
use crate::context_assistance_engine::upgrade_reviewed_summary;

fn hold_private_drop(
    actor: &Arc<RuntimeActor<Engine>>,
) -> (mpsc::Receiver<()>, mpsc::SyncSender<()>) {
    let (entered, observed) = mpsc::sync_channel(1);
    let (release, held) = mpsc::sync_channel(1);
    actor
        .call(move |_, engine| {
            engine.cleanup_test.0 = Some(Box::new(move || {
                let _ = entered.try_send(());
                let _ = held.recv_timeout(Duration::from_secs(10));
            }));
            Ok(())
        })
        .unwrap();
    (observed, release)
}
fn wait_pending(service: &Service, home: &Path, id: &str) -> Value {
    let start = Instant::now();
    loop {
        let job = service.switch_job(home, id).unwrap();
        if job["phase"] == "cleanup_pending"
            && job["cleanup_pending"] == true
            && job["worker_live"] == true
        {
            return job;
        }
        assert!(start.elapsed() < Duration::from_secs(5), "{job}");
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn note_summary(service: &Service, scope: &str) -> Value {
    let id = scope.to_owned();
    old_actor(service)
        .call(move |r, e| upgrade_reviewed_summary(e, r, &id))
        .unwrap()
}
#[test]
#[ignore = "requires explicit final0.14.1 SDK/dependency wheels and CPython3.14.7/3.14.10 task-private inputs"]
fn actual_profile_lease_waits_for_private_cleanup_and_stop_never_rebuilds_a_revoked_source() {
    let (f, store, service, scope) = restoration::activate(false);
    let notes = note_summary(&service, &scope);
    let original = std::fs::read(f.home.join("config.toml")).unwrap();
    for (id, stop) in [("cleanup-restores", false), ("cleanup-stops", true)] {
        let old = old_actor(&service);
        let fence = lock(&service.state).unwrap().epoch.fence();
        let (observed, release) = hold_private_drop(&old);
        let generation = service.configuration_generation().unwrap();
        service
            .prepare_switch(
                &f.home,
                SwitchRequest {
                    job_id: id.into(),
                    target_runtime_id: f.target.runtime_id.clone(),
                    expected_generation: generation,
                    rollback: false,
                },
            )
            .unwrap();
        let ready = wait_job(&service, &f.home, id, "ready");
        let data = ready["prepared_data_generation"]
            .as_str()
            .unwrap()
            .to_owned();
        service
            .commit_switch(&f.home, id, generation, true)
            .unwrap();
        observed.recv_timeout(Duration::from_secs(5)).unwrap();
        let pending = wait_pending(&service, &f.home, id);
        assert!(!old.is_active());
        assert!(!old.cleanup_finished());
        assert!(!fence.is_current());
        assert_eq!(service.configuration_generation().unwrap(), generation + 1);
        assert!(lock(&service.state).unwrap().runtime.is_none());
        assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), original);
        assert!(switching::Owner::acquire(&f.home)
            .err()
            .unwrap()
            .ends_with("busy"));
        assert!(matches!(
            switching::DataRemoval::acquire(&f.home),
            Err(guard_context_assistance::RuntimeError::Busy)
        ));
        let other = Service::default();
        assert!(other
            .prepare_switch(
                &f.home,
                SwitchRequest {
                    job_id: format!("other-{id}"),
                    target_runtime_id: f.target.runtime_id.clone(),
                    expected_generation: generation,
                    rollback: false
                }
            )
            .unwrap_err()
            .ends_with("busy"));
        assert!(
            guard_context_assistance::EvidenceGenerationStore::existing(&f.home)
                .unwrap()
                .unwrap()
                .list()
                .unwrap()
                .iter()
                .any(|g| g["generation_id"] == data)
        );
        assert_eq!(pending["can_commit"], false);
        if stop {
            let started = Instant::now();
            service.stop().unwrap();
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "Stop joined a private destructor"
            );
            crate::guard_config_update::disable_context_assistance(&f.home).unwrap();
            assert!(!old.cleanup_finished());
            assert!(switching::Owner::acquire(&f.home).is_err());
        }
        release.send(()).unwrap();
        let done = wait_job(
            &service,
            &f.home,
            id,
            if stop { "recovery_required" } else { "failed" },
        );
        assert_eq!(done["cleanup_pending"], false);
        assert!(old.cleanup_finished());
        let owner = switching::Owner::acquire(&f.home).unwrap();
        drop(owner);
        if stop {
            assert!(lock(&service.state).unwrap().runtime.is_none());
            assert!(
                !crate::guard_config_load::context_assistance_config(&f.home)
                    .unwrap()
                    .requested
                    .enabled
            );
        } else {
            assert_eq!(done["code"], "switch_failed_previous_runtime_restored");
            assert_eq!(done["failure_code"], "switch_cleanup_pending");
            assert_eq!(service.configuration_generation().unwrap(), generation + 2);
            assert_eq!(note_summary(&service, &scope), notes);
            assert!(workspace(
                &service,
                &f,
                &store,
                json!({"action":"compile","scope_id":scope,"query":"reviewed source"})
            )
            .to_string()
            .contains("Reviewed source survives"));
            assert!(
                !guard_context_assistance::EvidenceGenerationStore::existing(&f.home)
                    .unwrap()
                    .unwrap()
                    .list()
                    .unwrap()
                    .iter()
                    .any(|g| g["generation_id"] == data)
            );
        }
    }
    service.shutdown();
    println!(
        "CIGAR_CLEANUP_OWNER_PROOF={}",
        json!({"schema":"guard-cigar-cleanup-owner-proof.v1","scope":"local-macos-arm64-final0141-enrolled-source-test-qualified-target-not-b47380-not-newer-sdk","private_destructor_deliberately_held":true,"inactive_actor_not_assumed_clean":true,"same_profile_lease_retained":true,"other_service_excluded":true,"saved_data_removal_refused":true,"pending_generation_retained":true,"status_responded_while_pending":true,"source_restored_after_ack":true,"reviewed_vector_preserved":true,"generation_removed_after_ack":true,"stop_during_pending_returned_before_private_cleanup":true,"stop_did_not_reactivate_source":true,"lease_released_after_ack":true})
    );
}

#[test]
#[ignore = "requires explicit final0.14.1 SDK/dependency wheels and CPython3.14.7/3.14.10 task-private inputs"]
fn actual_candidate_and_failed_restoration_keep_the_lease_until_their_private_state_is_gone() {
    let (f, store, service, scope) = restoration::activate(false);
    let source = old_actor(&service);
    let fence = lock(&service.state).unwrap().epoch.fence();
    let notes = note_summary(&service, &scope);
    let original = std::fs::read(f.home.join("config.toml")).unwrap();
    let generation = service.configuration_generation().unwrap();
    service
        .prepare_switch(
            &f.home,
            SwitchRequest {
                job_id: "candidate-private-cleanup".into(),
                target_runtime_id: f.target.runtime_id.clone(),
                expected_generation: generation,
                rollback: false,
            },
        )
        .unwrap();
    let ready = wait_job(&service, &f.home, "candidate-private-cleanup", "ready");
    let data = ready["prepared_data_generation"]
        .as_str()
        .unwrap()
        .to_owned();
    let signal = lock(&service.state).unwrap().upgrade.clone().unwrap();
    let candidate = signal.prepared_actor.lock().unwrap().upgrade().unwrap();
    let (observed, release) = hold_private_drop(&candidate);
    service
        .cancel_switch(&f.home, "candidate-private-cleanup")
        .unwrap();
    observed.recv_timeout(Duration::from_secs(5)).unwrap();
    wait_pending(&service, &f.home, "candidate-private-cleanup");
    assert!(!candidate.cleanup_finished());
    assert!(source.is_active());
    assert!(fence.is_current());
    assert_eq!(service.configuration_generation().unwrap(), generation);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), original);
    assert!(switching::Owner::acquire(&f.home).is_err());
    assert!(matches!(
        switching::DataRemoval::acquire(&f.home),
        Err(guard_context_assistance::RuntimeError::Busy)
    ));
    assert!(
        guard_context_assistance::EvidenceGenerationStore::existing(&f.home)
            .unwrap()
            .unwrap()
            .list()
            .unwrap()
            .iter()
            .any(|g| g["generation_id"] == data)
    );
    assert!(workspace(
        &service,
        &f,
        &store,
        json!({"action":"compile","scope_id":scope,"query":"reviewed source"})
    )
    .to_string()
    .contains("Reviewed source survives"));
    assert_eq!(note_summary(&service, &scope), notes);
    release.send(()).unwrap();
    wait_job(&service, &f.home, "candidate-private-cleanup", "cancelled");
    assert!(candidate.cleanup_finished());
    assert!(source.is_active());
    assert!(Arc::ptr_eq(&source, &old_actor(&service)));
    assert!(
        !guard_context_assistance::EvidenceGenerationStore::existing(&f.home)
            .unwrap()
            .unwrap()
            .list()
            .unwrap()
            .iter()
            .any(|g| g["generation_id"] == data)
    );
    drop(switching::Owner::acquire(&f.home).unwrap());
    // A fresh source SDK has been constructed but never attached. Stop makes
    // its health/publication fail; its private destructor still owns the lease.
    service
        .prepare_switch(
            &f.home,
            SwitchRequest {
                job_id: "restored-private-cleanup".into(),
                target_runtime_id: f.target.runtime_id.clone(),
                expected_generation: generation,
                rollback: false,
            },
        )
        .unwrap();
    wait_job(&service, &f.home, "restored-private-cleanup", "ready");
    let signal = lock(&service.state).unwrap().upgrade.clone().unwrap();
    let weak = Arc::downgrade(&signal);
    *signal.committed_hook.lock().unwrap() = Some(Box::new(move || {
        weak.upgrade().unwrap().request_cancel();
    }));
    let (observed_tx, observed) = mpsc::sync_channel(1);
    let (release, held) = mpsc::sync_channel(1);
    let (created_tx, created) = mpsc::sync_channel(1);
    let stopped = Arc::downgrade(&service);
    let home = f.home.clone();
    *signal.restore_ready_hook.lock().unwrap() = Some(Box::new(move |actor| {
        let _ = created_tx.try_send(Arc::clone(actor));
        actor
            .call(move |_, engine| {
                engine.cleanup_test.0 = Some(Box::new(move || {
                    let _ = observed_tx.try_send(());
                    let _ = held.recv_timeout(Duration::from_secs(10));
                }));
                Ok(())
            })
            .unwrap();
        stopped.upgrade().unwrap().stop().unwrap();
        crate::guard_config_update::disable_context_assistance(&home).unwrap();
    }));
    service
        .commit_switch(&f.home, "restored-private-cleanup", generation, true)
        .unwrap();
    let unpublished = created.recv_timeout(Duration::from_secs(45)).unwrap();
    observed.recv_timeout(Duration::from_secs(5)).unwrap();
    wait_pending(&service, &f.home, "restored-private-cleanup");
    assert!(!unpublished.is_active());
    assert!(!unpublished.cleanup_finished());
    assert!(source.cleanup_finished());
    assert!(!fence.is_current());
    assert!(lock(&service.state).unwrap().runtime.is_none());
    assert!(signal.authority_revoked.load(Ordering::Acquire));
    assert!(switching::Owner::acquire(&f.home).is_err());
    assert!(matches!(
        switching::DataRemoval::acquire(&f.home),
        Err(guard_context_assistance::RuntimeError::Busy)
    ));
    assert!(
        !crate::guard_config_load::context_assistance_config(&f.home)
            .unwrap()
            .requested
            .enabled
    );
    release.send(()).unwrap();
    let done = wait_job(
        &service,
        &f.home,
        "restored-private-cleanup",
        "recovery_required",
    );
    assert!(!done["restoration_failure_code"].is_null());
    assert!(unpublished.cleanup_finished());
    assert_eq!(done["cleanup_pending"], false);
    assert!(lock(&service.state).unwrap().runtime.is_none());
    drop(switching::Owner::acquire(&f.home).unwrap());
    service.shutdown();
    println!(
        "CIGAR_CLEANUP_OWNER_PROOF={}",
        json!({"schema":"guard-cigar-cleanup-owner-proof.v1","scope":"local-macos-arm64-final0141-enrolled-source-test-qualified-target-not-b47380-not-newer-sdk","roles":["candidate","restoration"],"candidate_private_destructor_deliberately_held":true,"source_kept_serving_during_candidate_cleanup":true,"source_epoch_and_generation_preserved_during_candidate_cancel":true,"candidate_generation_retained_until_ack":true,"candidate_generation_pruned_after_ack":true,"restored_source_constructed_but_never_attached":true,"restoration_private_destructor_deliberately_held":true,"stop_kept_source_disabled":true,"same_profile_lease_retained_until_each_ack":true,"saved_data_removal_refused_while_pending":true,"lease_released_after_each_ack":true})
    );
}
