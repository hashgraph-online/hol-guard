//! Ordinary preference writes cannot bypass native SDK/data preparation.
use super::*;

fn settings(
    f: &UpgradeFixture,
    config: &guard_context_assistance::ContextAssistanceConfig,
) -> Value {
    let request = json!({"schema":"guard-config-update.v1","guard_home":f.home,"kind":"settings",
        "value_text":json!({"context_assistance":config}).to_string()});
    serde_json::from_slice(
        &crate::guard_config_update::run_command(request.to_string().as_bytes()).unwrap(),
    )
    .unwrap()
}
#[test]
#[ignore = "requires published final0141 wheels and external CPython3.14.7/3.14.10"]
fn actual_ordinary_settings_replacement_is_refused_while_live_or_off_without_restarting_source() {
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
    catalog_fixture::install(&store, &f.home);
    let service = store.context_assistance();
    assert_eq!(ask(&store, &f.home, "activate", json!({}))["status"], "ok");
    let started = Instant::now();
    while service.status().unwrap()["availability"] != "ready" {
        assert!(started.elapsed() < Duration::from_secs(90));
        std::thread::sleep(Duration::from_millis(25));
    }
    let scope = workspace(
        service,
        &f,
        &store,
        json!({"action":"grant","workspace":f.workspace,"app":"codex",
        "sources":["README.md"],"shared_notes":{"read":true,"propose":true}}),
    )["scope_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let id = scope.clone();
    old_actor(service)
        .call(move |r, e| {
            upgrade_admit(
                e,
                r,
                &id,
                "settings-guard",
                "Reviewed notes remain available on the same actor.",
            )
        })
        .unwrap();
    let before_notes = summary(service, &scope);
    let actor = old_actor(service);
    let fence = lock(&service.state).unwrap().epoch.fence();
    let generation = service.configuration_generation().unwrap();
    let before = std::fs::read(f.home.join("config.toml")).unwrap();
    let refused = settings(&f, &f.target);
    assert_eq!(refused["ok"], false, "{refused}");
    assert_eq!(
        refused["error"],
        "native_context_assistance_switch_required"
    );
    assert!(refused["invalid"]
        .as_str()
        .unwrap()
        .contains("Prepare and commit a CIGAR switch"));
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    assert_eq!(service.configuration_generation().unwrap(), generation);
    assert!(fence.is_current());
    assert!(Arc::ptr_eq(&actor, &old_actor(service)));
    same_notes(&summary(service, &scope), &before_notes);
    let compiled = workspace(
        service,
        &f,
        &store,
        json!({"action":"compile","scope_id":scope,
        "query":"Reviewed notes remain available"}),
    );
    assert!(compiled
        .to_string()
        .contains("Reviewed notes remain available on the same actor."));
    assert_eq!(ask(&store, &f.home, "stop", json!({}))["status"], "ok");
    let before = std::fs::read(f.home.join("config.toml")).unwrap();
    let mut off_target = f.target.clone();
    off_target.enabled = false;
    let refused = settings(&f, &off_target);
    assert_eq!(refused["ok"], false, "{refused}");
    assert_eq!(
        refused["error"],
        "native_context_assistance_switch_required"
    );
    assert!(refused["invalid"]
        .as_str()
        .unwrap()
        .contains("Prepare and commit a CIGAR switch"));
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    assert!(service.status().unwrap()["runtime"].is_null());
    assert_eq!(service.status().unwrap()["requested_enabled"], false);
    let enabled = settings(&f, &f.source);
    assert_eq!(enabled["ok"], true, "{enabled}");
    let status = ask(&store, &f.home, "status", json!({}));
    assert_eq!(status["status"], "ok", "{status}");
    assert!(service.status().unwrap()["runtime"].is_null());
    assert_eq!(service.status().unwrap()["requested_enabled"], true);
    assert_eq!(ask(&store, &f.home, "stop", json!({}))["status"], "ok");
    service.shutdown();
    println!(
        "CIGAR_SETTINGS_SELECTION_PROOF={}",
        json!({
            "schema":"guard-cigar-settings-selection-proof.v1",
            "scope":"local-macos-arm64-final0141-external3147-31410-test-qualified-resident-and-native-writer-not-initial-reset-not-newer-sdk",
            "verified_target_could_not_bypass_sdk_data_owner_while_live_or_off":true,
            "live_actor_generation_epoch_preferences_and_reviewed_context_preserved":true,
            "disabled_replacement_left_preferences_and_actor_absence_unchanged":true,
            "same_selected_id_enable_stored_intent_without_activating_sdk":true,
            "refusal_included_actionable_settings_validation_message":true
        })
    );
}
