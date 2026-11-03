//! Real SDK recovery after acknowledged shutdown, with temporary fixture-only
//! filesystem faults. The source and target are final 0.14.1 on two interpreters.
use super::*;
use crate::context_assistance_engine::upgrade_reviewed_summary;
use std::os::unix::fs::PermissionsExt;

#[test]
#[ignore = "requires explicit final0.14.1 SDK/dependency wheels and CPython3.14.7/3.14.10 task-private inputs"]
fn actual_sqlite_failed_cutovers_restore_fresh_source_and_stop_cancels_reconstruction() {
    run(false);
}
#[test]
#[ignore = "requires explicit final0.14.1 SDK/dependency wheels and CPython3.14.7/3.14.10 task-private inputs"]
fn actual_memory_failed_cutovers_restore_fresh_source_and_stop_cancels_reconstruction() {
    run(true);
}
fn summary(service: &Service, scope: &str) -> Value {
    let id = scope.to_owned();
    old_actor(service)
        .call(move |r, e| upgrade_reviewed_summary(e, r, &id))
        .unwrap()
}
pub(super) fn activate(
    memory_only: bool,
) -> (
    UpgradeFixture,
    crate::policy_store::PolicySnapshotStore,
    Arc<Service>,
    String,
) {
    activate_with_limit(
        memory_only,
        guard_context_assistance::ContextAssistanceConfig::default()
            .limits
            .max_active_workspaces,
    )
}
pub(super) fn activate_with_limit(
    memory_only: bool,
    max_workspaces: u32,
) -> (
    UpgradeFixture,
    crate::policy_store::PolicySnapshotStore,
    Arc<Service>,
    String,
) {
    let mut f = UpgradeFixture::new();
    f.source.limits.max_active_workspaces = max_workspaces;
    f.target.limits.max_active_workspaces = max_workspaces;
    if memory_only {
        f.source.storage.mode = StorageMode::Memory;
        f.target.storage.mode = StorageMode::Memory;
    }
    let mut key =
        crate::resident_state::private_file(&f.home.join("policy-verifier.key"), true, &f.home)
            .unwrap();
    key.write_all(&[73_u8; 32]).unwrap();
    drop(key);
    let store = crate::policy_store::PolicySnapshotStore::new(
        &f.home,
        &crate::resident_state::runtime_digest().unwrap(),
    )
    .unwrap();
    f.write_settings(&f.source);
    let (runtime, _) = f.start(false);
    f.enroll_source(&runtime);
    drop(runtime);
    let (_, runtime, _) = f.installed_target();
    drop(runtime);
    let service = Arc::new(Service::default());
    service
        .configure(crate::guard_config_load::context_assistance_config(&f.home).unwrap())
        .unwrap();
    service.schedule(Check::Activate, f.home.clone()).unwrap();
    let started = Instant::now();
    while service.status().unwrap()["availability"] != "ready" {
        assert!(started.elapsed() < Duration::from_secs(90));
        std::thread::sleep(Duration::from_millis(25));
    }
    let scope=workspace(&service,&f,&store,json!({"action":"grant","workspace":f.workspace,"app":"codex","sources":["README.md"],"shared_notes":{"read":true,"propose":true}}))["scope_id"].as_str().unwrap().to_owned();
    let id = scope.clone();
    old_actor(&service)
        .call(move |r, e| {
            upgrade_admit(
                e,
                r,
                &id,
                "recovery-reviewed",
                "Reviewed source survives failed cutover.",
            )
        })
        .unwrap();
    (f, store, service, scope)
}
fn run(memory_only: bool) {
    let (f, store, service, scope) = activate(memory_only);
    let original = std::fs::read(f.home.join("config.toml")).unwrap();
    let notes = summary(&service, &scope);
    let mut recovery_times = Vec::new();
    for (id, post_commit) in [("restore-readonly", false), ("restore-target-cancel", true)] {
        let previous = old_actor(&service);
        let fence = lock(&service.state).unwrap().epoch.fence();
        let session = previous
            .call(|runtime, engine| {
                engine.agent(
                    runtime,
                    crate::context_assistance_agents::Input::Begin {},
                    None,
                )
            })
            .unwrap();
        let session_id = session["result"]["session_id"].as_str().unwrap().to_owned();
        workspace(
            &service,
            &f,
            &store,
            json!({"action":"authorize_agent","scope_id":scope,"session_id":session_id}),
        );
        assert_eq!(
            workspace(&service, &f, &store, json!({"action":"list_agents"}))["agent_sessions"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let compiled = workspace(
            &service,
            &f,
            &store,
            json!({"action":"compile","scope_id":scope,"query":"reviewed source"}),
        );
        let snapshot = compiled["brief"]["snapshot_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let latest = workspace(
            &service,
            &f,
            &store,
            json!({"action":"history","scope_id":scope}),
        )["entries"]
            .as_array()
            .unwrap()
            .clone();
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
        wait_job(&service, &f.home, id, "ready");
        let signal = lock(&service.state).unwrap().upgrade.clone().unwrap();
        if post_commit {
            let weak = Arc::downgrade(&signal);
            *signal.committed_hook.lock().unwrap() = Some(Box::new(move || {
                assert!(weak.upgrade().unwrap().request_cancel());
            }));
        } else {
            let path = f.home.join("config.toml");
            *signal.source_closed_hook.lock().unwrap() = Some(Box::new(move || {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
            }));
        }
        let commit_started = Instant::now();
        service
            .commit_switch(&f.home, id, generation, true)
            .unwrap();
        let done = wait_job(
            &service,
            &f.home,
            id,
            if post_commit { "cancelled" } else { "failed" },
        );
        assert!(
            done["code"]
                .as_str()
                .unwrap()
                .ends_with("previous_runtime_restored"),
            "{done}"
        );
        assert!(
            done["restoration_deadline_at_ms"].as_u64().unwrap()
                <= done["deadline_at_ms"].as_u64().unwrap() + 30_000
        );
        recovery_times.push(json!({"case":id,"commit_to_finished_recovery_ms":commit_started.elapsed().as_millis()}));
        assert!(done["restoration_failure_code"].is_null(), "{done}");
        assert_eq!(
            done["failure_code"],
            if post_commit {
                "switch_cancelled"
            } else {
                "switch_storage_unavailable_or_changed"
            }
        );
        assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), original);
        std::fs::set_permissions(
            f.home.join("config.toml"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(!previous.is_active());
        assert!(previous.cleanup_finished());
        assert!(!fence.is_current());
        assert!(!Arc::ptr_eq(&previous, &old_actor(&service)));
        assert_eq!(service.configuration_generation().unwrap(), generation + 2);
        assert_eq!(service.status().unwrap()["availability"], "ready");
        assert_eq!(summary(&service, &scope), notes);
        assert_history_entries(
            &workspace(
                &service,
                &f,
                &store,
                json!({"action":"history","scope_id":scope}),
            ),
            &latest,
        );
        assert!(service
            .workspace(
                &f.home,
                &store,
                json!({"action":"explain","scope_id":scope,"snapshot_id":snapshot}),
                true,
                true
            )
            .is_err());
        assert_eq!(
            workspace(&service, &f, &store, json!({"action":"list_agents"}))["agent_sessions"],
            json!([])
        );
        assert!(workspace(
            &service,
            &f,
            &store,
            json!({"action":"compile","scope_id":scope,"query":"reviewed source"})
        )
        .to_string()
        .contains("Reviewed source survives"));
        service.cancel_switch(&f.home, id).unwrap();
        assert!(old_actor(&service).is_active());
        let selected = switching::Owner::acquire(&f.home).unwrap();
        assert_eq!(
            selected.record().unwrap().current.runtime.installation_id,
            f.source.runtime_id
        );
        assert!(selected.record().unwrap().last_good.is_none());
        assert_eq!(
            selected
                .record()
                .unwrap()
                .transaction
                .as_ref()
                .unwrap()
                .phase,
            guard_cigar_release::SelectionPhase::RolledBack
        );
        drop(selected);
        if memory_only {
            memory::no_saved_evidence(&f);
        }
    }
    // A native Stop after source selection restoration, before SDK rebuilding,
    // must prevent both config re-enablement and process/scope publication.
    let generation = service.configuration_generation().unwrap();
    service
        .prepare_switch(
            &f.home,
            SwitchRequest {
                job_id: "restore-stop".into(),
                target_runtime_id: f.target.runtime_id.clone(),
                expected_generation: generation,
                rollback: false,
            },
        )
        .unwrap();
    wait_job(&service, &f.home, "restore-stop", "ready");
    let signal = lock(&service.state).unwrap().upgrade.clone().unwrap();
    let weak = Arc::downgrade(&signal);
    *signal.committed_hook.lock().unwrap() = Some(Box::new(move || {
        weak.upgrade().unwrap().request_cancel();
    }));
    let stopped = Arc::downgrade(&service);
    let home = f.home.clone();
    *signal.restore_hook.lock().unwrap() = Some(Box::new(move || {
        stopped.upgrade().unwrap().stop().unwrap();
        crate::guard_config_update::disable_context_assistance(&home).unwrap();
    }));
    service
        .commit_switch(&f.home, "restore-stop", generation, true)
        .unwrap();
    wait_job(&service, &f.home, "restore-stop", "recovery_required");
    assert!(signal.authority_revoked.load(Ordering::Acquire));
    assert!(signal.restore_cancel.load(Ordering::Acquire));
    assert!(lock(&service.state).unwrap().runtime.is_none());
    assert!(
        !crate::guard_config_load::context_assistance_config(&f.home)
            .unwrap()
            .requested
            .enabled
    );
    service.shutdown();
    println!(
        "CIGAR_SOURCE_RESTORE_PROOF={}",
        json!({"schema":"guard-cigar-source-restore-proof.v1","storage":if memory_only {"memory"}else{"sqlite"},"scope":"local-macos-arm64-final0141-enrolled-source-test-qualified-target-not-b47380-not-newer-sdk","readonly_commit_failure_restored":true,"post_commit_cancel_restored":true,"exact_source_config_preserved":true,"complete_reviewed_data_and_original_expiry_preserved":true,"latest_readonly_history_preserved":true,"old_actor_cleanup_acknowledged":true,"old_epoch_revoked":true,"fresh_actor_published":true,"old_contexts_restored":false,"old_sessions_restored":false,"old_agent_verified_live_before_cutover":true,"stop_during_restore_remains_disabled":true,"preparation_budget_ms":120000,"restoration_budget_ms":30000,"recovery_timings":recovery_times,"timing_scope":"commit_request_until_worker_finished_not_pure_sdk_outage"})
    );
}
