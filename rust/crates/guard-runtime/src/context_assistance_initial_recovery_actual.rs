//! Actual SDK verification after a fresh Service, not an OS process-loss claim.
use super::*;
use guard_cigar_release::InitialPhase;
use std::os::unix::fs::PermissionsExt;
fn disabled(service: &Service) {
    let status = service.status().unwrap();
    assert_eq!(status["requested_enabled"], false, "{status}");
    assert_eq!(status["effective_enabled"], false);
    assert!(status["runtime"].is_null());
}
#[test]
#[ignore = "requires exact published final0141 wheels and external CPython3.14.10"]
fn actual_committed_initial_recovery_survives_fresh_service_cancel_and_retry_without_enabling() {
    let f = UpgradeFixture::new();
    let mut key =
        crate::resident_state::private_file(&f.home.join("policy-verifier.key"), true, &f.home)
            .unwrap();
    key.write_all(&[91u8; 32]).unwrap();
    drop(key);
    let mut initial = f.target.clone();
    initial.enabled = false;
    initial.runtime_id.clear();
    f.write_settings(&initial);
    let (_, runtime, _) = f.installed_target();
    drop(runtime);
    let digest = crate::resident_state::runtime_digest().unwrap();
    let store = crate::policy_store::PolicySnapshotStore::new(&f.home, &digest).unwrap();
    catalog_fixture::install(&store, &f.home);
    assert_eq!(ask(&store, &f.home, "status", json!({}))["status"], "ok");
    let service = store.context_assistance();
    let generation = service.status().unwrap()["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    versions(
        &store,
        &f.home,
        json!({"action":"prepare_switch","job_id":"interrupted-initial",
        "target_runtime_id":f.target.runtime_id,"expected_generation":generation}),
    );
    wait_job(service, &f.home, "interrupted-initial", "ready");
    let marker = f.home.join("cigar-initial-selection.json");
    let signal = lock(&service.state).unwrap().upgrade.clone().unwrap();
    *signal.committed_hook.lock().unwrap() = Some(Box::new(move || {
        std::fs::set_permissions(marker, std::fs::Permissions::from_mode(0o400)).unwrap();
    }));
    versions(
        &store,
        &f.home,
        json!({"action":"commit","job_id":"interrupted-initial",
        "expected_generation":generation,"reconnect":false}),
    );
    wait_job(service, &f.home, "interrupted-initial", "recovery_required");
    let before = std::fs::read(f.home.join("config.toml")).unwrap();
    let owner = switching::Owner::acquire(&f.home).unwrap();
    assert_eq!(
        owner.initial_record().unwrap().phase,
        InitialPhase::Committed
    );
    assert!(owner.check_initial_clear().is_err());
    drop(owner);
    service.shutdown();
    drop(store);
    std::fs::set_permissions(
        f.home.join("cigar-initial-selection.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let fresh = crate::policy_store::PolicySnapshotStore::new(&f.home, &digest).unwrap();
    assert_eq!(ask(&fresh, &f.home, "status", json!({}))["status"], "ok");
    let service = fresh.context_assistance();
    disabled(service);
    let generation = service.status().unwrap()["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    let request = || json!({"action":"recover","job_id":"interrupted-initial","expected_generation":generation});
    let first = versions(&fresh, &f.home, request());
    assert_eq!(first["operation"], "recover");
    let first_attempt = first["recovery_attempt"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        first["recovery_attempt"]["deadline_at_ms"]
            .as_u64()
            .unwrap()
            - first["recovery_attempt"]["started_at_ms"].as_u64().unwrap(),
        120_000
    );
    let signal = lock(&service.state).unwrap().upgrade.clone().unwrap();
    let (entered, seen) = std::sync::mpsc::sync_channel(1);
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    *signal.before_commit_hook.lock().unwrap() = Some(Box::new(move || {
        entered.send(()).unwrap();
        wait.recv_timeout(Duration::from_secs(10)).unwrap();
    }));
    seen.recv_timeout(Duration::from_secs(90)).unwrap();
    let retry = versions(&fresh, &f.home, request());
    assert_eq!(
        retry["recovery_attempt"]["id"], first_attempt,
        "lost reply must reuse live worker"
    );
    disabled(service);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    versions(
        &fresh,
        &f.home,
        json!({"action":"cancel","job_id":"interrupted-initial"}),
    );
    release.send(()).unwrap();
    wait_job(service, &f.home, "interrupted-initial", "recovery_required");
    disabled(service);
    assert_eq!(service.status().unwrap()["generation"], generation);
    let owner = switching::Owner::acquire(&f.home).unwrap();
    assert_eq!(
        owner.initial_record().unwrap().phase,
        InitialPhase::Committed
    );
    drop(owner);
    let second = versions(&fresh, &f.home, request());
    assert_ne!(second["recovery_attempt"]["id"], first_attempt);
    assert_eq!(
        second["cancel_requested"], false,
        "old attempt cancellation must not veto explicit retry"
    );
    wait_job(service, &f.home, "interrupted-initial", "completed");
    disabled(service);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    assert_eq!(service.status().unwrap()["generation"], generation);
    let owner = switching::Owner::acquire(&f.home).unwrap();
    assert_eq!(
        owner.initial_record().unwrap().phase,
        InitialPhase::Completed
    );
    owner.check_initial_clear().unwrap();
    assert_eq!(
        owner.record().unwrap().current.runtime.installation_id,
        f.target.runtime_id
    );
    assert!(owner.record().unwrap().last_good.is_none());
    assert!(owner.record().unwrap().transaction.is_none());
    drop(owner);
    assert!(!f.home.join("cigar-scopes.json").exists());
    service.shutdown();
    println!(
        "CIGAR_INITIAL_RECOVERY_PROOF={}",
        json!({
        "schema":"guard-cigar-initial-recovery-proof.v1",
        "scope":"local-macos-arm64-final0141-external31410-test-qualified-fresh-service-not-os-process-loss-not-newer-sdk",
        "committed_marker_blocked_activation_until_recovery":true,
        "fresh_service_reverified_exact_target_with_bounded_budget":true,
        "lost_reply_reused_one_live_attempt":true,
        "cancel_preserved_pending_target_preferences_and_off_state":true,
        "new_explicit_attempt_was_not_cancelled_by_old_marker":true,
        "completed_recovery_changed_no_preferences_generation_or_app_grants":true})
    );
}
