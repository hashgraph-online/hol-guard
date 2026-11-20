//! Published target SDK, empty initial profile, no previous runtime claim.
use super::*;
use guard_cigar_release::InitialPhase;
use std::os::unix::fs::PermissionsExt;

fn off(service: &Service, home: &Path) {
    let status = service.status().unwrap();
    assert_eq!(status["requested_enabled"], false, "{status}");
    assert_eq!(status["effective_enabled"], false);
    assert!(status["runtime"].is_null());
    assert!(
        !crate::guard_config_load::context_assistance_config(home)
            .unwrap()
            .requested
            .enabled
    );
}
#[test]
#[ignore = "requires published final0141 wheels and external CPython3.14.10 target"]
fn actual_empty_initial_profile_cancels_selects_recovers_and_enables_only_with_fresh_grants() {
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
    let (_, target, _) = f.installed_target();
    drop(target);
    let store = crate::policy_store::PolicySnapshotStore::new(
        &f.home,
        &crate::resident_state::runtime_digest().unwrap(),
    )
    .unwrap();
    catalog_fixture::install(&store, &f.home);
    assert_eq!(ask(&store, &f.home, "status", json!({}))["status"], "ok");
    let service = store.context_assistance();
    off(service, &f.home);
    let before = std::fs::read(f.home.join("config.toml")).unwrap();
    let generation = service.status().unwrap()["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    let request = |id: &str| json!({"action":"prepare_switch","job_id":id,"target_runtime_id":f.target.runtime_id,"expected_generation":generation});
    versions(&store, &f.home, request("initial-cancel"));
    let ready = wait_job(service, &f.home, "initial-cancel", "ready");
    assert_eq!(ready["operation"], "select");
    assert_eq!(ready["initial_selection"], true);
    assert!(ready["source_runtime_id"].is_null());
    assert_eq!(ready["reconnect_required"], false);
    off(service, &f.home);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    assert!(!f.home.join("cigar-lifecycle.json").exists());
    assert!(!f.home.join("cigar-scopes.json").exists());
    versions(
        &store,
        &f.home,
        json!({"action":"cancel","job_id":"initial-cancel"}),
    );
    wait_job(service, &f.home, "initial-cancel", "cancelled");
    assert_eq!(service.status().unwrap()["generation"], generation);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    let owner = switching::Owner::acquire(&f.home).unwrap();
    assert!(owner.record().is_none());
    assert_eq!(
        owner.initial_record().unwrap().phase,
        InitialPhase::Cancelled
    );
    drop(owner);
    versions(&store, &f.home, request("initial-forward"));
    wait_job(service, &f.home, "initial-forward", "ready");
    let signal = lock(&service.state).unwrap().upgrade.clone().unwrap();
    *signal.before_commit_hook.lock().unwrap() = Some(Box::new(|| {
        crate::guard_config_update::io::fail_next_config_write_after_rename();
    }));
    let marker = f.home.join("cigar-initial-selection.json");
    *signal.completion_hook.lock().unwrap() = Some(Box::new(move || {
        std::fs::set_permissions(marker, std::fs::Permissions::from_mode(0o400)).unwrap();
    }));
    versions(
        &store,
        &f.home,
        json!({"action":"commit","job_id":"initial-forward","expected_generation":generation,"reconnect":false}),
    );
    wait_job(service, &f.home, "initial-forward", "recovery_required");
    off(service, &f.home);
    let selected = std::fs::read(f.home.join("config.toml")).unwrap();
    let owner = switching::Owner::acquire(&f.home).unwrap();
    assert_eq!(owner.initial_record().unwrap().phase, InitialPhase::Healthy);
    assert_eq!(
        owner.record().unwrap().current.runtime.installation_id,
        f.target.runtime_id
    );
    assert!(owner.record().unwrap().last_good.is_none());
    assert!(owner.record().unwrap().transaction.is_none());
    assert!(owner.check_initial_clear().is_err());
    drop(owner);
    assert!(!f.home.join("cigar-scopes.json").exists());
    let current_generation = service.status().unwrap()["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    std::fs::set_permissions(
        f.home.join("cigar-initial-selection.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let recovered = versions(
        &store,
        &f.home,
        json!({"action":"recover","job_id":"initial-forward","expected_generation":current_generation}),
    );
    assert_eq!(recovered["phase"], "completed");
    off(service, &f.home);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), selected);
    assert_eq!(service.status().unwrap()["generation"], current_generation);
    let rollback = ask(
        &store,
        &f.home,
        "versions",
        json!({"action":"prepare_rollback","job_id":"no-previous","expected_generation":current_generation}),
    );
    assert_ne!(rollback["status"], "ok");
    assert!(rollback["code"]
        .as_str()
        .unwrap()
        .ends_with("rollback_unavailable"));
    let request = json!({"schema":"guard-config-update.v1","guard_home":f.home,"kind":"settings","value_text":json!({"context_assistance":f.target}).to_string()});
    let enabled: Value = serde_json::from_slice(
        &crate::guard_config_update::run_command(request.to_string().as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(enabled["ok"], true, "{enabled}");
    assert!(service.status().unwrap()["runtime"].is_null());
    assert_eq!(ask(&store, &f.home, "activate", json!({}))["status"], "ok");
    let started = Instant::now();
    while service.status().unwrap()["availability"] != "ready" {
        assert!(
            started.elapsed() < Duration::from_secs(90),
            "{}",
            service.status().unwrap()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let scope=workspace(service,&f,&store,json!({"action":"grant","workspace":f.workspace,"app":"codex","sources":["README.md"],"shared_notes":{"read":true,"propose":true}}))["scope_id"].as_str().unwrap().to_owned();
    let id = scope.clone();
    old_actor(service)
        .call(move |r, e| {
            upgrade_admit(
                e,
                r,
                &id,
                "first-reviewed",
                "Initial selection creates reviewed data only after a fresh explicit grant.",
            )
        })
        .unwrap();
    assert_eq!(summary(service, &scope)["notes"], 1);
    let compiled = workspace(
        service,
        &f,
        &store,
        json!({"action":"compile","scope_id":scope,"query":"Initial selection reviewed data fresh explicit grant"}),
    );
    assert!(compiled
        .to_string()
        .contains("Initial selection creates reviewed data only after a fresh explicit grant."));
    assert_eq!(ask(&store, &f.home, "stop", json!({}))["status"], "ok");
    off(service, &f.home);
    service.shutdown();
    println!(
        "CIGAR_INITIAL_SELECTION_PROOF={}",
        json!({"schema":"guard-cigar-initial-selection-proof.v1",
        "scope":"local-macos-arm64-final0141-external31410-test-qualified-resident-empty-initial-not-prior-candidate-not-newer-sdk",
        "cancel_preserved_no_selection_preferences_generation_and_off_state":true,
        "no_previous_runtime_data_pointer_or_last_good_was_invented":true,
        "uncertain_config_commit_was_observed_without_sdk_replay":true,
        "healthy_completion_recovery_started_no_sdk_and_changed_no_preferences":true,
        "initial_selection_remained_disabled_and_created_no_native_app_scope":true,
        "explicit_enable_activation_and_fresh_grant_preceded_reviewed_data":true})
    );
}
