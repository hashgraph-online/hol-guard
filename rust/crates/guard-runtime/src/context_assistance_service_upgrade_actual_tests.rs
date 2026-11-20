//! Live Service orchestration using actual final SDK artifacts. The catalog
//! qualification is test-only and does not claim b47380 or a newer SDK release.
use super::*;
#[path = "context_assistance_service_versions_actual.rs"]
mod operator;
use crate::context_assistance_engine::{upgrade_admit, UpgradeFixture};
use guard_context_assistance::ContextFence;
use std::io::Write;
#[path = "context_assistance_service_upgrade_cleanup_actual.rs"]
mod cleanup_owner;
#[path = "context_assistance_service_upgrade_erasure_actual.rs"]
mod full_erasure;
#[path = "context_assistance_service_upgrade_generation_actual.rs"]
mod generation_restoration;
#[path = "context_assistance_service_upgrade_memory_actual.rs"]
mod memory;
#[path = "context_assistance_service_upgrade_publication_actual.rs"]
mod publication;
#[path = "context_assistance_service_upgrade_restore_actual.rs"]
mod restoration;
#[path = "context_assistance_service_upgrade_rollback_actual.rs"]
mod rollback;
#[path = "context_assistance_service_upgrade_scope_actual.rs"]
mod scope_erasure;

fn wait_job(service: &Service, home: &Path, id: &str, phase: &str) -> Value {
    let started = Instant::now();
    loop {
        let job = service.switch_job(home, id).unwrap();
        if job["phase"] == phase
            && (if phase == "ready" {
                job["can_commit"] == true
            } else {
                job["worker_live"] == false
            })
        {
            return job;
        }
        assert!(
            job["phase"] == phase
                || !["failed", "cancelled", "recovery_required"]
                    .iter()
                    .any(|p| job["phase"] == *p),
            "unexpected switch outcome: {job}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(125),
            "bounded job did not finish: {job}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}
#[track_caller]
fn workspace(
    service: &Service,
    f: &UpgradeFixture,
    store: &crate::policy_store::PolicySnapshotStore,
    value: Value,
) -> Value {
    let action = value["action"].as_str().unwrap().to_owned();
    let started = Instant::now();
    let result = service.workspace(&f.home, store, value, true, true);
    eprintln!(
        "CIGAR_WORKSPACE_TIMING={}",
        json!({"action":action,"elapsed_ms":started.elapsed().as_millis(),
            "error":result.as_ref().err()})
    );
    result.unwrap_or_else(|error| panic!("workspace {action} failed: {error}"))["result"].clone()
}
fn assert_history_entries(history: &Value, latest: &[Value]) {
    for entry in latest {
        assert!(history["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["history_id"] == entry["history_id"]
                && v["prepared_at_ms"] == entry["prepared_at_ms"]));
    }
}
fn old_actor(service: &Service) -> Arc<RuntimeActor<Engine>> {
    lock(&service.state)
        .unwrap()
        .runtime
        .as_ref()
        .unwrap()
        .clone()
}

#[test]
#[ignore = "requires explicit final0.14.1 SDK/dependency wheels and CPython3.14.7/3.14.10 task-private inputs"]
fn actual_service_cancels_a_ready_copy_then_switches_at_the_native_boundary() {
    actual_service_roundtrip(false);
}
#[test]
#[ignore = "requires explicit final0.14.1 SDK/dependency wheels and CPython3.14.7/3.14.10 task-private inputs"]
fn actual_service_switches_memory_notes_without_persisting_them_or_crossing_app_scopes() {
    actual_service_roundtrip(true);
}
fn actual_service_roundtrip(memory_only: bool) {
    let mut f = UpgradeFixture::new();
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
    let (source_runtime, source_producer) = f.start(false);
    f.enroll_source(&source_runtime);
    drop(source_runtime);
    let (_, target_runtime, target_producer) = f.installed_target();
    drop(target_runtime);
    let service = Service::default();
    service
        .configure(crate::guard_config_load::context_assistance_config(&f.home).unwrap())
        .unwrap();
    service.schedule(Check::Activate, f.home.clone()).unwrap();
    let started = Instant::now();
    while service.status().unwrap()["availability"] != "ready" {
        assert!(
            started.elapsed() < Duration::from_secs(90),
            "source activation: {}",
            service.status().unwrap()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let scope = workspace(
        &service,
        &f,
        &store,
        json!({"action":"grant","workspace":f.workspace,
        "app":"codex","sources":["README.md"],"shared_notes":{"read":true,"propose":true}}),
    )["scope_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let old = old_actor(&service);
    let id = scope.clone();
    old.call(move |runtime, engine| {
        upgrade_admit(
            engine,
            runtime,
            &id,
            "service-reviewed",
            "A reviewed note survives live Service switching.",
        )
    })
    .unwrap();
    let secondary = memory_only.then(|| memory::second_app(&service, &f, &store));
    let session = old
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
    let initial = workspace(
        &service,
        &f,
        &store,
        json!({"action":"compile","scope_id":scope,"query":"release evidence reviewed note"}),
    );
    assert!(initial.to_string().contains("A reviewed note survives"));
    let generation = service.configuration_generation().unwrap();
    let before = std::fs::read(f.home.join("config.toml")).unwrap();
    let fence: ContextFence = lock(&service.state).unwrap().epoch.fence();
    let request = SwitchRequest {
        job_id: "live-cancel".into(),
        target_runtime_id: f.target.runtime_id.clone(),
        expected_generation: generation,
        rollback: false,
    };
    service.prepare_switch(&f.home, request.clone()).unwrap();
    assert_eq!(
        service.prepare_switch(&f.home, request).unwrap()["job_id"],
        "live-cancel"
    );
    wait_job(&service, &f.home, "live-cancel", "ready");
    let cancelled_data = jobs::get(&f.home, "live-cancel")
        .unwrap()
        .unwrap()
        .prepared_data_generation;
    assert!(old.is_active());
    assert_eq!(service.configuration_generation().unwrap(), generation);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    assert!(service
        .commit_switch(&f.home, "live-cancel", generation, false)
        .unwrap_err()
        .ends_with("acknowledgement_required"));
    assert!(service
        .commit_switch(&f.home, "live-cancel", generation + 1, true)
        .unwrap_err()
        .ends_with("selection_conflict"));
    service.cancel_switch(&f.home, "live-cancel").unwrap();
    wait_job(&service, &f.home, "live-cancel", "cancelled");
    assert!(old.is_active());
    assert!(fence.is_current());
    if let Some(cancelled_data) = cancelled_data {
        assert!(!memory_only);
        let generations = guard_context_assistance::EvidenceGenerationStore::existing(&f.home)
            .unwrap()
            .unwrap()
            .list()
            .unwrap();
        assert!(generations
            .iter()
            .all(|g| g["generation_id"] != cancelled_data));
    } else {
        assert!(memory_only);
        memory::no_saved_evidence(&f);
    }
    if memory_only {
        memory::invalidate_ready(&service, &f, &scope, generation);
        assert!(old.is_active());
        assert!(fence.is_current());
    }
    service
        .prepare_switch(
            &f.home,
            SwitchRequest {
                job_id: "live-commit".into(),
                target_runtime_id: f.target.runtime_id.clone(),
                expected_generation: generation,
                rollback: false,
            },
        )
        .unwrap();
    let memory_before = secondary
        .as_ref()
        .map(|id| memory::summaries(&service, &scope, id));
    let mut served = 0;
    let preparing = Instant::now();
    loop {
        let value = workspace(
            &service,
            &f,
            &store,
            json!({"action":"compile","scope_id":scope,"query":"release evidence reviewed note"}),
        );
        assert!(value.to_string().contains("A reviewed note survives"));
        served += 1;
        let job = service.switch_job(&f.home, "live-commit").unwrap();
        if job["phase"] == "ready" {
            break;
        }
        assert!(
            !["failed", "cancelled", "recovery_required"]
                .iter()
                .any(|p| job["phase"] == *p),
            "{job}"
        );
        assert!(
            preparing.elapsed() < Duration::from_secs(125),
            "job did not reach readiness: {job}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    // This readonly observation occurs after the early preparation capture.
    let late = workspace(
        &service,
        &f,
        &store,
        json!({"action":"compile","scope_id":scope,"query":"late boundary history"}),
    );
    let snapshot = late["brief"]["snapshot_id"].as_str().unwrap().to_owned();
    workspace(
        &service,
        &f,
        &store,
        json!({"action":"explain","scope_id":scope,"snapshot_id":snapshot}),
    );
    let latest = workspace(
        &service,
        &f,
        &store,
        json!({"action":"history","scope_id":scope}),
    )["entries"]
        .as_array()
        .unwrap()
        .clone();
    if !memory_only {
        publication::fail_completion(&service, &f);
    }
    service
        .commit_switch(&f.home, "live-commit", generation, true)
        .unwrap();
    let done = if memory_only {
        wait_job(&service, &f.home, "live-commit", "completed")
    } else {
        publication::reconcile(&service, &f, &store, &scope, generation + 1, &latest)
    };
    assert!(!old.is_active());
    assert!(old.cleanup_finished());
    assert!(!fence.is_current());
    assert_eq!(service.configuration_generation().unwrap(), generation + 1);
    assert_eq!(service.status().unwrap()["availability"], "ready");
    assert_eq!(
        crate::guard_config_load::context_assistance_config(&f.home)
            .unwrap()
            .requested,
        f.target
    );
    let history = workspace(
        &service,
        &f,
        &store,
        json!({"action":"history","scope_id":scope}),
    );
    if memory_only {
        assert_history_entries(&history, &latest);
    }
    assert!(history
        .to_string()
        .contains(source_producer.identity_sha256()));
    assert!(service
        .workspace(
            &f.home,
            &store,
            json!({"action":"explain","scope_id":scope,"snapshot_id":snapshot}),
            true,
            true
        )
        .is_err());
    let fresh = workspace(
        &service,
        &f,
        &store,
        json!({"action":"compile","scope_id":scope,"query":"release evidence reviewed note"}),
    );
    assert!(fresh.to_string().contains("A reviewed note survives"));
    assert_eq!(
        workspace(&service, &f, &store, json!({"action":"list_agents"}))["agent_sessions"],
        json!([])
    );
    let selected = switching::Owner::acquire(&f.home).unwrap();
    assert_eq!(
        selected.record().unwrap().current.runtime.installation_id,
        f.target.runtime_id
    );
    assert_eq!(
        selected
            .record()
            .unwrap()
            .last_good
            .as_ref()
            .unwrap()
            .runtime
            .installation_id,
        f.source.runtime_id
    );
    drop(selected);
    if let Some(secondary) = &secondary {
        memory::verify_target(
            &service,
            &f,
            &store,
            &scope,
            secondary,
            memory_before.as_ref().unwrap(),
        );
    }
    service.cancel_switch(&f.home, "live-commit").unwrap();
    assert_eq!(service.status().unwrap()["availability"], "ready");
    let reverse = rollback::round_trip(&service, &f, &store, &scope, secondary.as_deref());
    service.stop().unwrap();
    service.shutdown();
    println!(
        "CIGAR_LIVE_SERVICE_SWITCH_PROOF={}",
        json!({"schema":"guard-cigar-live-service-switch-proof.v1",
        "scope":"local-macos-arm64-final0141-enrolled-source-test-qualified-target-not-b47380-not-newer-sdk",
        "source_calls_during_preparation":served,"cancelled_ready_data_removed":!memory_only,"source_served_after_cancel":true,
        "storage":if memory_only {"memory"}else{"sqlite"},"cancelled_memory_candidate_closed":memory_only,
        "app_scopes_checked":if memory_only {2}else{1},"saved_evidence_absent":memory_only,"original_memory_expiry_preserved":memory_only,"complete_memory_note_digests_preserved":memory_only,
        "late_reviewed_edit_check":if memory_only {"passed"}else{"not_exercised"},
        "reconnect_ack_required":true,"stale_generation_refused":true,"old_actor_cleanup_acknowledged":true,
        "old_native_epoch_revoked":true,"latest_readonly_history_preserved":true,"reviewed_notes_preserved":true,
        "old_context_verified_live_before_cutover":true,"old_contexts_restored":false,"old_agent_sessions_restored":false,"late_cancel_keeps_target_serving":true,
        "source_producer":source_producer.identity_sha256(),"target_producer":target_producer.identity_sha256(),
        "selected_data_generation":done["prepared_data_generation"],"config_commit_was_native":true,"published_target_survives_completion_failure":!memory_only,
        "completion_reconciled_without_restart":!memory_only,"explicit_rollback":reverse})
    );
}
