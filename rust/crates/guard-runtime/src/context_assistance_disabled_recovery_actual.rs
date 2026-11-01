//! Actual SDK acceptance after a fresh Service, not an OS process-loss claim.
use super::*;
use std::os::unix::fs::PermissionsExt;
fn off(service: &Service) {
    let status = service.status().unwrap();
    assert_eq!(status["requested_enabled"], false, "{status}");
    assert_eq!(status["effective_enabled"], false);
    assert!(status["runtime"].is_null());
}
fn generation(service: &Service) -> String {
    service.status().unwrap()["generation"]
        .as_str()
        .unwrap()
        .to_owned()
}
#[test]
#[ignore = "requires exact published final0141 wheels and external CPython3.14.7/3.14.10"]
fn actual_committed_disabled_selection_recovers_after_fresh_service_cancel_and_retry_with_data_intact(
) {
    recover(false);
}
#[test]
#[ignore = "requires exact published final0141 wheels and external CPython3.14.7/3.14.10"]
fn actual_committed_live_selection_after_later_stop_recovers_without_restoring_activation() {
    recover(true);
}
fn recover(was_live: bool) {
    let f = UpgradeFixture::new();
    let mut key =
        crate::resident_state::private_file(&f.home.join("policy-verifier.key"), true, &f.home)
            .unwrap();
    key.write_all(&[91u8; 32]).unwrap();
    drop(key);
    let digest = crate::resident_state::runtime_digest().unwrap();
    let store = crate::policy_store::PolicySnapshotStore::new(&f.home, &digest).unwrap();
    f.write_settings(&f.source);
    let (runtime, _) = f.start(false);
    f.enroll_source(&runtime);
    drop(runtime);
    let (_, runtime, _) = f.installed_target();
    drop(runtime);
    let service = store.context_assistance();
    assert_eq!(ask(&store, &f.home, "activate", json!({}))["status"], "ok");
    let started = Instant::now();
    while service.status().unwrap()["availability"] != "ready" {
        assert!(started.elapsed() < Duration::from_secs(90));
        std::thread::sleep(Duration::from_millis(25));
    }
    let old_scope = grant(service, &f, &store, "dashboard", true);
    let scope = old_scope.clone();
    old_actor(service)
        .call(move |r, e| {
            upgrade_admit(
                e,
                r,
                &scope,
                "dashboard",
                "Reviewed note survives committed disabled recovery.",
            )
        })
        .unwrap();
    let original = summary(service, &old_scope);
    catalog_fixture::install(&store, &f.home);
    if !was_live {
        assert_eq!(ask(&store, &f.home, "stop", json!({}))["status"], "ok");
        off(service);
    }
    let source_generation = generation(service);
    versions(
        &store,
        &f.home,
        json!({"action":"prepare_switch","job_id":"interrupted-disabled",
        "target_runtime_id":f.target.runtime_id,"expected_generation":source_generation}),
    );
    wait_job(service, &f.home, "interrupted-disabled", "ready");
    let path = f.home.join("cigar-lifecycle.json");
    let signal = lock(&service.state).unwrap().upgrade.clone().unwrap();
    *signal.committed_hook.lock().unwrap() = Some(Box::new(move || {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
    }));
    versions(
        &store,
        &f.home,
        json!({"action":"commit","job_id":"interrupted-disabled",
        "expected_generation":source_generation,"reconnect":was_live}),
    );
    wait_job(
        service,
        &f.home,
        "interrupted-disabled",
        "recovery_required",
    );
    if was_live {
        assert_eq!(ask(&store, &f.home, "stop", json!({}))["status"], "ok");
    }
    off(service);
    let committed_settings = std::fs::read(f.home.join("config.toml")).unwrap();
    let owner = switching::Owner::acquire(&f.home).unwrap();
    let record = owner.record().unwrap();
    assert_eq!(
        record.transaction.as_ref().unwrap().phase,
        SelectionPhase::Committed
    );
    assert_eq!(record.current.runtime.installation_id, f.target.runtime_id);
    assert!(record.last_good.is_none());
    let data_id = record.current.data.generation_id().unwrap().to_owned();
    drop(owner);
    let data = EvidenceGenerationStore::existing(&f.home)
        .unwrap()
        .unwrap()
        .load(&data_id)
        .unwrap();
    let semantic = data.semantic_sha256().unwrap();
    service.shutdown();
    drop(store);
    std::fs::set_permissions(
        f.home.join("cigar-lifecycle.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let fresh = crate::policy_store::PolicySnapshotStore::new(&f.home, &digest).unwrap();
    assert_eq!(ask(&fresh, &f.home, "status", json!({}))["status"], "ok");
    let service = fresh.context_assistance();
    off(service);
    // A later Stop and a narrower settings save win over the old transaction.
    assert_eq!(ask(&fresh, &f.home, "stop", json!({}))["status"], "ok");
    let mut settings = crate::guard_config_load::context_assistance_config(&f.home)
        .unwrap()
        .requested;
    settings.sources.native_policy_facts = false;
    settings.limits.max_active_workspaces = 1;
    let update = json!({"schema":"guard-config-update.v1","guard_home":f.home,
        "kind":"settings","value_text":json!({"context_assistance":settings}).to_string()});
    let result: Value = serde_json::from_slice(
        &crate::guard_config_update::run_command(update.to_string().as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(ask(&fresh, &f.home, "status", json!({}))["status"], "ok");
    off(service);
    let before = std::fs::read(f.home.join("config.toml")).unwrap();
    assert_ne!(before, committed_settings);
    let current = crate::guard_config_load::context_assistance_config(&f.home).unwrap();
    assert!(!current.requested.sources.native_policy_facts);
    assert_eq!(current.requested.limits.max_active_workspaces, 1);
    let current_generation = generation(service);
    let request = || json!({"action":"recover","job_id":"interrupted-disabled","expected_generation":current_generation});
    let first = versions(&fresh, &f.home, request());
    assert_eq!(first["operation"], "recover");
    assert_eq!(first["initial_selection"], false);
    assert_eq!(first["keeps_disabled"], true);
    assert_eq!(first["can_commit"], false);
    let attempt = first["recovery_attempt"]["id"].as_str().unwrap().to_owned();
    let signal = lock(&service.state).unwrap().upgrade.clone().unwrap();
    let (entered, seen) = std::sync::mpsc::sync_channel(1);
    let (release, pending) = std::sync::mpsc::sync_channel(1);
    *signal.before_commit_hook.lock().unwrap() = Some(Box::new(move || {
        entered.send(()).unwrap();
        pending.recv_timeout(Duration::from_secs(10)).unwrap();
    }));
    seen.recv_timeout(Duration::from_secs(90)).unwrap();
    assert_eq!(
        versions(&fresh, &f.home, request())["recovery_attempt"]["id"],
        attempt
    );
    off(service);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    versions(
        &fresh,
        &f.home,
        json!({"action":"cancel","job_id":"interrupted-disabled"}),
    );
    release.send(()).unwrap();
    wait_job(
        service,
        &f.home,
        "interrupted-disabled",
        "recovery_required",
    );
    off(service);
    assert_eq!(generation(service), current_generation);
    assert_eq!(data.semantic_sha256().unwrap(), semantic);
    let second = versions(&fresh, &f.home, request());
    assert_ne!(second["recovery_attempt"]["id"], attempt);
    assert_eq!(second["cancel_requested"], false);
    wait_job(service, &f.home, "interrupted-disabled", "completed");
    off(service);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    assert_eq!(generation(service), current_generation);
    assert_eq!(data.semantic_sha256().unwrap(), semantic);
    let owner = switching::Owner::acquire(&f.home).unwrap();
    let record = owner.record().unwrap();
    assert_eq!(
        record.transaction.as_ref().unwrap().phase,
        SelectionPhase::Completed
    );
    assert_eq!(record.current.runtime.installation_id, f.target.runtime_id);
    assert_eq!(
        record.last_good.as_ref().unwrap().runtime.installation_id,
        f.source.runtime_id
    );
    drop(owner);
    enable(&fresh, &f);
    let id = old_scope.clone();
    assert!(old_actor(service)
        .call(move |r, e| upgrade_reviewed_summary(e, r, &id))
        .is_err());
    let scope = grant(service, &f, &fresh, "dashboard", true);
    assert_ne!(scope, old_scope);
    same_notes(&summary(service, &scope), &original);
    assert_eq!(ask(&fresh, &f.home, "stop", json!({}))["status"], "ok");
    off(service);
    service.shutdown();
    println!(
        "CIGAR_DISABLED_RECOVERY_PROOF={}",
        json!({
        "schema":"guard-cigar-disabled-recovery-proof.v1",
        "scope":"local-macos-arm64-final0141-external3147-31410-test-qualified-fresh-service-not-os-process-loss-not-b47380-not-newer-sdk",
        "committed_disabled_target_reverified_with_bounded_worker":true,
        "original_transaction_was_live":was_live,
        "original_job_mode_and_request_hash_preserved":true,
        "live_retry_reused_attempt_and_cancel_preserved_data_preferences_and_generation":true,
        "later_explicit_attempt_ignored_old_cancel_marker":true,
        "recovery_changed_only_selection_health_completion_and_job_metadata":true,
        "last_good_promoted_only_after_verified_completion":true,
        "later_stop_and_narrower_settings_preserved_without_restoring_transaction_preferences":true,
        "separate_enable_and_fresh_grant_required_and_reviewed_notes_expiry_preserved":true})
    );
}
