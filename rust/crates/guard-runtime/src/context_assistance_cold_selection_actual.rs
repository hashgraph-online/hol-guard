//! Published-SDK disabled selection through resident operator envelopes.
use super::*;
use std::os::unix::fs::PermissionsExt;

fn off(service: &Service, home: &Path) {
    let status = service.status().unwrap();
    assert_eq!(status["requested_enabled"], false, "{status}");
    assert_eq!(status["effective_enabled"], false, "{status}");
    assert!(status["runtime"].is_null(), "{status}");
    assert!(
        !crate::guard_config_load::context_assistance_config(home)
            .unwrap()
            .requested
            .enabled
    );
}
fn generation(service: &Service) -> String {
    service.status().unwrap()["generation"]
        .as_str()
        .unwrap()
        .to_owned()
}
#[test]
#[ignore = "requires published final0141 wheels and external CPython3.14.7/3.14.10"]
fn actual_operator_cancels_selects_recovers_and_rolls_back_while_disabled_then_freshly_admits_notes(
) {
    let f = UpgradeFixture::new();
    let mut key =
        crate::resident_state::private_file(&f.home.join("policy-verifier.key"), true, &f.home)
            .unwrap();
    key.write_all(&[91u8; 32]).unwrap();
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
    let (_, target, _) = f.installed_target();
    drop(target);
    let service = store.context_assistance();
    assert_eq!(ask(&store, &f.home, "activate", json!({}))["status"], "ok");
    let started = Instant::now();
    while service.status().unwrap()["availability"] != "ready" {
        assert!(started.elapsed() < Duration::from_secs(90));
        std::thread::sleep(Duration::from_millis(25));
    }
    let mut original = Vec::new();
    for (app, text) in [
        ("codex", "Codex cold operator note."),
        ("dashboard", "Dashboard cold operator note."),
    ] {
        let scope = grant(service, &f, &store, app, true);
        let id = scope.clone();
        old_actor(service)
            .call(move |r, e| upgrade_admit(e, r, &id, app, text))
            .unwrap();
        original.push((app, summary(service, &scope)));
    }
    catalog_fixture::install(&store, &f.home);
    assert_eq!(ask(&store, &f.home, "stop", json!({}))["status"], "ok");
    off(service, &f.home);
    let before = std::fs::read(f.home.join("config.toml")).unwrap();
    let initial_generation = generation(service);
    let request = |id: &str| {
        json!({"action":"prepare_switch","job_id":id,
        "target_runtime_id":f.target.runtime_id,"expected_generation":initial_generation})
    };
    versions(&store, &f.home, request("cold-cancel"));
    let ready = wait_job(service, &f.home, "cold-cancel", "ready");
    assert_eq!(ready["keeps_disabled"], true);
    assert_eq!(ready["reconnect_required"], false);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    off(service, &f.home);
    assert!(switching::Owner::acquire(&f.home).is_err());
    versions(
        &store,
        &f.home,
        json!({"action":"cancel","job_id":"cold-cancel"}),
    );
    wait_job(service, &f.home, "cold-cancel", "cancelled");
    assert_eq!(generation(service), initial_generation);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    off(service, &f.home);

    versions(&store, &f.home, request("cold-forward"));
    wait_job(service, &f.home, "cold-forward", "ready");
    // Fail only final metadata acknowledgement, after the off selection is published.
    let record = f.home.join("cigar-lifecycle.json");
    *lock(&service.state)
        .unwrap()
        .upgrade
        .as_ref()
        .unwrap()
        .completion_hook
        .lock()
        .unwrap() = Some(Box::new(move || {
        std::fs::set_permissions(record, std::fs::Permissions::from_mode(0o400)).unwrap();
    }));
    versions(
        &store,
        &f.home,
        json!({"action":"commit","job_id":"cold-forward",
        "expected_generation":initial_generation,"reconnect":false}),
    );
    wait_job(service, &f.home, "cold-forward", "recovery_required");
    off(service, &f.home);
    let selected = std::fs::read(f.home.join("config.toml")).unwrap();
    assert_eq!(
        crate::guard_config_load::context_assistance_config(&f.home)
            .unwrap()
            .requested
            .runtime_id,
        f.target.runtime_id
    );
    let current_generation = generation(service);
    std::fs::set_permissions(
        f.home.join("cigar-lifecycle.json"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let recovered = versions(
        &store,
        &f.home,
        json!({"action":"recover","job_id":"cold-forward","expected_generation":current_generation}),
    );
    assert_eq!(recovered["phase"], "completed");
    assert_eq!(generation(service), current_generation);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), selected);
    off(service, &f.home);
    assert_eq!(
        versions(
            &store,
            &f.home,
            json!({"action":"commit","job_id":"cold-forward",
        "expected_generation":initial_generation,"reconnect":false})
        )["phase"],
        "completed"
    );

    versions(
        &store,
        &f.home,
        json!({"action":"prepare_switch","job_id":"cold-missing-target",
        "target_runtime_id":"missing-installation","expected_generation":current_generation}),
    );
    wait_job(service, &f.home, "cold-missing-target", "failed");
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), selected);
    off(service, &f.home);

    versions(
        &store,
        &f.home,
        json!({"action":"prepare_rollback","job_id":"cold-rollback","expected_generation":current_generation}),
    );
    let ready = wait_job(service, &f.home, "cold-rollback", "ready");
    assert_eq!(ready["operation"], "rollback");
    assert_eq!(ready["reconnect_required"], false);
    off(service, &f.home);
    versions(
        &store,
        &f.home,
        json!({"action":"commit","job_id":"cold-rollback",
        "expected_generation":current_generation,"reconnect":false}),
    );
    wait_job(service, &f.home, "cold-rollback", "completed");
    assert_eq!(
        crate::guard_config_load::context_assistance_config(&f.home)
            .unwrap()
            .requested
            .runtime_id,
        f.source.runtime_id
    );
    off(service, &f.home);
    enable(&store, &f);
    for (app, before) in original {
        let scope = grant(service, &f, &store, app, true);
        same_notes(&summary(service, &scope), &before);
    }
    assert_eq!(ask(&store, &f.home, "stop", json!({}))["status"], "ok");
    off(service, &f.home);
    service.shutdown();
    println!(
        "CIGAR_COLD_SELECTION_PROOF={}",
        json!({
            "schema":"guard-cigar-cold-selection-proof.v1",
            "scope":"local-macos-arm64-final0141-external3147-31410-test-qualified-resident-operator-not-initial-not-unavailable-source-not-b47380-not-newer-sdk",
            "ready_cancel_preserved_disabled_source_and_preferences":true,
            "existing_job_owner_and_shared_lifecycle_lease":true,
            "commit_without_reconnect_kept_serving_actor_absent":true,
            "missing_completion_acknowledgement_reconciled_without_sdk_activation_or_replay":true,
            "last_good_rollback_carried_deferred_notes_while_remaining_off":true,
            "explicit_enable_and_fresh_grants_restored_two_app_notes_and_expiry":true
        })
    );
}
