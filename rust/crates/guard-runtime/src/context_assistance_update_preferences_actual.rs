//! Exact build pins and Ready invalidation against the real final0141 SDK.
use super::*;
fn preferences(
    store: &crate::policy_store::PolicySnapshotStore,
    home: &Path,
    pin: Option<&str>,
) -> Value {
    let current = versions(store, home, json!({"action":"preferences"}));
    versions(
        store,
        home,
        json!({"action":"set_preferences","expected_revision":current["revision"],
        "preferences":{"mode":"notify","allow_preview":false,"retain_last_good":true,"pinned_build":pin}}),
    )
}
#[test]
#[ignore = "requires exact final0141 SDK wheels and task-private external Python3.14.7/3.14.10"]
fn actual_update_preferences_preserve_live_context_and_fence_ready_selection() {
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
    let (_, runtime, _) = f.installed_target();
    drop(runtime);
    let service = store.context_assistance();
    assert_eq!(ask(&store, &f.home, "activate", json!({}))["status"], "ok");
    let until = Instant::now();
    while service.status().unwrap()["availability"] != "ready" {
        assert!(until.elapsed() < Duration::from_secs(90));
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
                "pin-original",
                "Current reviewed data survives preference edits.",
            )
        })
        .unwrap();
    let original = summary(service, &scope);
    let actor = old_actor(service);
    let fence = lock(&service.state).unwrap().epoch.fence();
    let generation = service.status().unwrap()["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    let compiled = workspace(
        service,
        &f,
        &store,
        json!({"action":"compile","scope_id":scope,"query":"Current reviewed data"}),
    );
    let snapshot = compiled["brief"]["snapshot_id"].clone();
    catalog_fixture::install(&store, &f.home);
    let installation =
        crate::policy_store::context_assistance_registry::load(&f.home, &f.target.runtime_id)
            .unwrap();
    let build = installation
        .approval
        .release
        .as_ref()
        .unwrap()
        .identity
        .build_id
        .clone();
    let saved = preferences(&store, &f.home, Some("different-exact-build"));
    assert_eq!(saved["effective"]["pinned_build"], "different-exact-build");
    assert!(Arc::ptr_eq(&actor, &old_actor(service)));
    assert!(fence.is_current());
    assert_eq!(service.status().unwrap()["generation"], generation);
    same_notes(&summary(service, &scope), &original);
    workspace(
        service,
        &f,
        &store,
        json!({"action":"explain","scope_id":scope,"snapshot_id":snapshot}),
    );
    versions(
        &store,
        &f.home,
        json!({"action":"prepare_switch","job_id":"pin-refused","target_runtime_id":f.target.runtime_id,"expected_generation":generation}),
    );
    let blocked = wait(&store, &f.home, "pin-refused", "failed");
    assert!(
        blocked["failure_code"]
            .as_str()
            .unwrap()
            .ends_with("update_pin_conflict"),
        "{blocked}"
    );
    let before = std::fs::read(f.home.join("config.toml")).unwrap();
    let request = json!({"schema":"guard-config-update.v1","guard_home":f.home,"kind":"settings","value_text":json!({"context_assistance":f.target}).to_string()});
    let reply: Value = serde_json::from_slice(
        &crate::guard_config_update::run_command(request.to_string().as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        reply["error"], "native_context_assistance_update_pin_conflict",
        "{reply}"
    );
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    preferences(&store, &f.home, Some(&build));
    versions(
        &store,
        &f.home,
        json!({"action":"prepare_switch","job_id":"pin-stale-ready","target_runtime_id":f.target.runtime_id,"expected_generation":generation}),
    );
    wait(&store, &f.home, "pin-stale-ready", "ready");
    preferences(&store, &f.home, Some("different-exact-build"));
    versions(
        &store,
        &f.home,
        json!({"action":"commit","job_id":"pin-stale-ready","expected_generation":generation,"reconnect":true}),
    );
    let refused = wait(&store, &f.home, "pin-stale-ready", "failed");
    assert!(
        refused["failure_code"]
            .as_str()
            .unwrap()
            .ends_with("switch_settings_conflict"),
        "{refused}"
    );
    assert!(Arc::ptr_eq(&actor, &old_actor(service)));
    assert!(actor.is_active());
    assert!(fence.is_current());
    assert_eq!(service.status().unwrap()["generation"], generation);
    same_notes(&summary(service, &scope), &original);
    preferences(&store, &f.home, Some(&build));
    versions(
        &store,
        &f.home,
        json!({"action":"prepare_switch","job_id":"pin-forward","target_runtime_id":f.target.runtime_id,"expected_generation":generation}),
    );
    wait(&store, &f.home, "pin-forward", "ready");
    versions(
        &store,
        &f.home,
        json!({"action":"commit","job_id":"pin-forward","expected_generation":generation,"reconnect":true}),
    );
    wait(&store, &f.home, "pin-forward", "completed");
    same_notes(&summary(service, &scope), &original);
    assert!(!fence.is_current());
    assert_eq!(
        service.status().unwrap()["preferences"]["runtime_id"],
        f.target.runtime_id
    );
    let selected = crate::guard_config_load::cigar_updates::read(&f.home).unwrap();
    assert_eq!(selected["effective"]["pinned_build"], build);
    assert_eq!(ask(&store, &f.home, "stop", json!({}))["status"], "ok");
    let off = versions(&store, &f.home, json!({"action":"preferences"}));
    assert_eq!(off["requested"]["pinned_build"], build);
    assert!(service.status().unwrap()["runtime"].is_null());
    service.shutdown();
    println!(
        "CIGAR_UPDATE_PREFERENCES_PROOF={}",
        json!({"schema":"guard-cigar-update-preferences-proof.v1","scope":"local-macos-arm64-final0141-external3147-31410-test-qualified-cached-catalog-not-newer-sdk","preferences_preserved_serving_actor_generation_epoch_notes_and_snapshot":true,"exact_build_pin_refused_switch_preparation":true,"ordinary_settings_selection_honored_pin":true,"ready_pin_edit_refused_cutover_without_source_interruption":true,"matching_pin_explicit_switch_preserved_notes":true,"stop_and_passive_preferences_preserved_opt_out":true})
    );
}
