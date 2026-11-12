//! Actual SDK scope erasure after a real Service switch, including restart.
use super::*;
use crate::context_assistance_engine::upgrade_reviewed_summary;
use guard_context_assistance::EvidenceCache;

#[track_caller]
fn summary(service: &Service, scope: &str) -> Value {
    let id = scope.to_owned();
    old_actor(service)
        .call(move |runtime, engine| upgrade_reviewed_summary(engine, runtime, &id))
        .unwrap()
}
fn grant(
    service: &Service,
    f: &UpgradeFixture,
    store: &crate::policy_store::PolicySnapshotStore,
    workspace_path: &Path,
    app: &str,
) -> Value {
    workspace(
        service,
        f,
        store,
        json!({"action":"grant","workspace":workspace_path,
        "app":app,"sources":["README.md"],"shared_notes":{"read":true,"propose":true}}),
    )
}
fn admit(service: &Service, scope: &str, key: &str, text: &str) {
    let (scope, key, text) = (scope.to_owned(), key.to_owned(), text.to_owned());
    old_actor(service)
        .call(move |runtime, engine| upgrade_admit(engine, runtime, &scope, &key, &text))
        .unwrap();
}
fn same_notes(now: &Value, original: &Value) {
    for key in ["scope_sha256", "notes", "documents_sha256", "expires_at_ms"] {
        assert_eq!(now[key], original[key], "{key}");
    }
}
fn ready(service: &Service) {
    let started = Instant::now();
    while service.status().unwrap()["availability"] != "ready" {
        assert!(
            started.elapsed() < Duration::from_secs(90),
            "activation: {}",
            service.status().unwrap()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}
#[test]
#[ignore = "requires explicit final0.14.1 SDK/dependency wheels and CPython3.14.7/3.14.10 task-private inputs"]
fn actual_saved_scope_erasure_preserves_other_apps_and_workspaces_and_resumes_while_off() {
    run(false);
}
#[test]
#[ignore = "requires explicit final0.14.1 SDK/dependency wheels and CPython3.14.7/3.14.10 task-private inputs"]
fn actual_memory_scope_erasure_preserves_other_scopes_and_creates_no_saved_evidence() {
    run(true);
}
fn run(memory_only: bool) {
    let (f, store, service, primary) = restoration::activate_with_limit(memory_only, 3);
    let other_root = tempfile::tempdir().unwrap();
    let other_path = other_root.path().canonicalize().unwrap();
    std::fs::write(
        other_path.join("README.md"),
        "Release evidence in an independent workspace.\n",
    )
    .unwrap();
    let app = grant(&service, &f, &store, &f.workspace, "dashboard")["scope_id"]
        .as_str()
        .unwrap()
        .to_owned();
    admit(
        &service,
        &app,
        "scoped-dashboard",
        "Other app reviewed evidence must remain unchanged.",
    );
    let third_grant = grant(&service, &f, &store, &other_path, "codex");
    let third = third_grant["scope_id"].as_str().unwrap().to_owned();
    let third_source = third_grant["sources"][0]["source_id"]
        .as_str()
        .unwrap()
        .to_owned();
    admit(
        &service,
        &third,
        "scoped-workspace",
        "Other workspace reviewed evidence must remain scoped.",
    );
    let legacy_key = EvidenceCache::key(
        "codex",
        &f.workspace,
        &old_actor(&service).status().worker_fingerprint,
    )
    .unwrap();
    let generation = service.configuration_generation().unwrap();
    service
        .prepare_switch(
            &f.home,
            SwitchRequest {
                job_id: "scope-forward".into(),
                target_runtime_id: f.target.runtime_id.clone(),
                expected_generation: generation,
                rollback: false,
            },
        )
        .unwrap();
    wait_job(&service, &f.home, "scope-forward", "ready");
    service
        .commit_switch(&f.home, "scope-forward", generation, true)
        .unwrap();
    let switched = wait_job(&service, &f.home, "scope-forward", "completed");
    let selected = switched["prepared_data_generation"]
        .as_str()
        .map(str::to_owned);
    let before_primary = summary(&service, &primary);
    let before_app = summary(&service, &app);
    let before_third = summary(&service, &third);
    assert_eq!(before_primary["notes"], 1);
    let prefs = std::fs::read(f.home.join("config.toml")).unwrap();
    let selection = std::fs::read(f.home.join("cigar-lifecycle.json")).unwrap();
    let sdk = old_actor(&service);
    let compiled = workspace(
        &service,
        &f,
        &store,
        json!({"action":"compile","scope_id":primary,"query":"reviewed source"}),
    );
    let old_snapshot = compiled["brief"]["snapshot_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let other_snapshot = workspace(
        &service,
        &f,
        &store,
        json!({"action":"compile","scope_id":app,"query":"other app reviewed evidence"}),
    )["brief"]["snapshot_id"]
        .as_str()
        .unwrap()
        .to_owned();
    if !memory_only {
        assert!(f
            .home
            .join("context-assistance/saved-evidence")
            .join(&legacy_key)
            .exists());
        // Inject an owned empty old-format namespace. It is not SDK-qualified
        // evidence, and its unknown ownership must refuse before SDK mutation.
        let unknown = EvidenceCache::key("unattributed", &f.workspace, &"f".repeat(64)).unwrap();
        let cache = EvidenceCache::existing(&f.home).unwrap().unwrap();
        drop(
            cache
                .open_slot(&unknown, 1, crate::context_assistance_data::now_ms())
                .unwrap(),
        );
        drop(cache);
        let error = service
            .workspace(
                &f.home,
                &store,
                json!({"action":"clear_notes","scope_id":primary}),
                true,
                true,
            )
            .unwrap_err();
        assert!(error.ends_with("storage_repair_required"), "{error}");
        assert!(!f.home.join("cigar-erasure.json").exists());
        assert!(Arc::ptr_eq(&sdk, &old_actor(&service)));
        same_notes(&summary(&service, &primary), &before_primary);
        workspace(
            &service,
            &f,
            &store,
            json!({"action":"explain","scope_id":primary,"snapshot_id":old_snapshot}),
        );
        let cache = EvidenceCache::existing(&f.home).unwrap().unwrap();
        cache.forget(&unknown).unwrap();
    }
    let cleared = workspace(
        &service,
        &f,
        &store,
        json!({"action":"clear_notes","scope_id":primary}),
    );
    assert_eq!(cleared["cleared_notes"], true);
    assert_eq!(
        cleared["scope"]["saved_copy_erasure"]["removed_slots"],
        if memory_only { 0 } else { 1 }
    );
    assert_eq!(summary(&service, &primary)["notes"], 0);
    assert!(service
        .workspace(
            &f.home,
            &store,
            json!({"action":"explain","scope_id":primary,"snapshot_id":old_snapshot}),
            true,
            true
        )
        .is_err());
    workspace(
        &service,
        &f,
        &store,
        json!({"action":"explain","scope_id":app,"snapshot_id":other_snapshot}),
    );
    same_notes(&summary(&service, &app), &before_app);
    same_notes(&summary(&service, &third), &before_third);
    assert!(Arc::ptr_eq(&sdk, &old_actor(&service)));
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), prefs);
    assert_eq!(
        std::fs::read(f.home.join("cigar-lifecycle.json")).unwrap(),
        selection
    );
    if memory_only {
        memory::no_saved_evidence(&f);
    } else {
        assert!(!f
            .home
            .join("context-assistance/saved-evidence")
            .join(&legacy_key)
            .exists());
        assert!(selected.is_some());
    }
    let withdrawn = workspace(
        &service,
        &f,
        &store,
        json!({"action":"withdraw","scope_id":third,"source_id":third_source}),
    );
    assert!(withdrawn["sources"].as_array().unwrap().is_empty());
    assert_eq!(summary(&service, &third)["notes"], 0);
    same_notes(&summary(&service, &app), &before_app);
    assert!(Arc::ptr_eq(&sdk, &old_actor(&service)));
    admit(
        &service,
        &primary,
        "after-scope-clear",
        "New review after clearing must also be erasable.",
    );
    assert_eq!(summary(&service, &primary)["notes"], 1);
    old_actor(&service)
        .call(|_, _| {
            switching::ScopeRemoval::fail_next_after_purge();
            Ok(())
        })
        .unwrap();
    let error = service
        .workspace(
            &f.home,
            &store,
            json!({"action":"clear_notes","scope_id":primary}),
            true,
            true,
        )
        .unwrap_err();
    assert!(error.ends_with("storage_outcome_unknown"), "{error}");
    let marker = std::fs::read(f.home.join("cigar-erasure.json")).unwrap();
    assert_eq!(
        crate::context_assistance_data::inspect(&f.home)["status"],
        "repair_required"
    );
    assert!(service
        .workspace(
            &f.home,
            &store,
            json!({"action":"compile","scope_id":primary,"query":"new review"}),
            true,
            true
        )
        .is_err());
    service.stop().unwrap();
    crate::guard_config_update::disable_context_assistance(&f.home).unwrap();
    service
        .configure(crate::guard_config_load::context_assistance_config(&f.home).unwrap())
        .unwrap();
    let disabled = std::fs::read(f.home.join("config.toml")).unwrap();
    assert!(service
        .workspace(
            &f.home,
            &store,
            json!({"action":"resume_erasure"}),
            false,
            false
        )
        .is_err());
    assert_eq!(
        std::fs::read(f.home.join("cigar-erasure.json")).unwrap(),
        marker
    );
    let resumed = workspace(&service, &f, &store, json!({"action":"resume_erasure"}));
    assert_eq!(resumed["resumed_erasure"], true);
    assert!(!f.home.join("cigar-erasure.json").exists());
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), disabled);
    assert_eq!(
        std::fs::read(f.home.join("cigar-lifecycle.json")).unwrap(),
        selection
    );
    assert!(lock(&service.state).unwrap().runtime.is_none());
    assert!(!service.status().unwrap()["effective_enabled"]
        .as_bool()
        .unwrap());
    if memory_only {
        memory::no_saved_evidence(&f);
    }
    // Only this explicit enable/activation and fresh native grants may reopen
    // scopes. Disk ownership metadata supplies none of them.
    f.write_settings(&f.target);
    service
        .configure(crate::guard_config_load::context_assistance_config(&f.home).unwrap())
        .unwrap();
    service.schedule(Check::Activate, f.home.clone()).unwrap();
    ready(&service);
    assert!(
        workspace(&service, &f, &store, json!({"action":"list"}))["scopes"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let fresh = grant(&service, &f, &store, &f.workspace, "codex")["scope_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(fresh, primary);
    assert_eq!(summary(&service, &fresh)["notes"], 0);
    if !memory_only {
        let restored_app = grant(&service, &f, &store, &f.workspace, "dashboard")["scope_id"]
            .as_str()
            .unwrap()
            .to_owned();
        same_notes(&summary(&service, &restored_app), &before_app);
    } else {
        memory::no_saved_evidence(&f);
    }
    service.stop().unwrap();
    workspace(&service, &f, &store, json!({"action":"forget_saved"}));
    assert!(!f.home.join("cigar-scopes.json").exists());
    service.shutdown();
    println!(
        "CIGAR_SCOPED_ERASURE_PROOF={}",
        json!({
            "schema":"guard-cigar-scoped-erasure-proof.v1",
            "scope":"local-macos-arm64-final0141-external-py3147-31410-test-qualified-target-not-b47380-not-newer-sdk",
            "storage":if memory_only {"memory"}else{"sqlite"},
            "other_app_preserved_during_scoped_erase":true,"other_workspace_preserved_during_primary_erase":true,
            "old_primary_context_revoked":true,"other_app_context_remained_usable":true,
            "successful_scoped_erase_kept_the_serving_sdk":true,"withdrawal_erased_its_scope_notes":true,
            "interrupted_second_clear_fenced_admission":true,"off_state_authenticated_resume":true,
            "disabled_preferences_preserved":true,"selection_and_last_good_preserved":true,
            "resume_did_not_start_sdk":true,"restart_restored_no_grants":true,"erased_notes_not_readmitted":true,
            "unknown_legacy_refused_before_sdk_mutation":!memory_only,"legacy_original_copy_erased":!memory_only,
            "memory_saved_stores_created":if memory_only {json!(false)}else{Value::Null}
        })
    );
}
