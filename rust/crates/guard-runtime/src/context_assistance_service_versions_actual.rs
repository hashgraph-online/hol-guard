//! Actual SDK administration through authenticated resident request envelopes.
//! Final0.14.1 on two external Python builds; no newer-SDK/platform claim.
use super::*;
use crate::context_assistance_engine::upgrade_reviewed_summary;
#[path = "context_assistance_catalog_actual_fixture.rs"]
mod catalog_fixture;
#[path = "context_assistance_cold_data_actual.rs"]
mod cold_data;
#[path = "context_assistance_initial_recovery_actual.rs"]
mod initial_recovery;
#[path = "context_assistance_initial_selection_actual.rs"]
mod initial_selection;
#[path = "context_assistance_settings_opt_in_actual.rs"]
mod settings_opt_in;
#[path = "context_assistance_settings_selection_actual.rs"]
mod settings_selection;
#[path = "context_assistance_update_preferences_actual.rs"]
mod update_preferences;

fn ask(
    store: &crate::policy_store::PolicySnapshotStore,
    home: &Path,
    kind: &str,
    input: Value,
) -> Value {
    let request: crate::context_assistance_op::Request = serde_json::from_value(json!({
        "schema":"guard-context-assistance-request.v1", "request_id":"actual-version-controls",
        "query":{"kind":kind,"guard_home":home,"input":input}}))
    .unwrap();
    serde_json::from_slice(&crate::context_assistance_op::evaluate(&request, store).unwrap())
        .unwrap()
}
#[track_caller]
fn versions(store: &crate::policy_store::PolicySnapshotStore, home: &Path, input: Value) -> Value {
    let answer = ask(store, home, "versions", input);
    assert_eq!(answer["status"], "ok", "{answer}");
    assert_eq!(
        answer["payload"]["data"]["schema"],
        "guard-cigar-versions-result.v1"
    );
    answer["payload"]["data"]["result"].clone()
}
fn wait(
    store: &crate::policy_store::PolicySnapshotStore,
    home: &Path,
    id: &str,
    phase: &str,
) -> Value {
    let started = Instant::now();
    loop {
        let reply = ask(store, home, "versions", json!({"action":"job","job_id":id}));
        if reply["code"] == "native_context_assistance_context_stale" {
            assert!(started.elapsed() < Duration::from_secs(125), "{reply}");
            println!("CIGAR_CATALOG_READ_POLL_STALE={id}");
            std::thread::sleep(Duration::from_millis(25));
            continue;
        }
        assert_eq!(reply["status"], "ok", "{reply}");
        let job = reply["payload"]["data"]["result"].clone();
        if job["phase"] == phase {
            return job;
        }
        assert!(
            !["failed", "cancelled", "recovery_required"]
                .iter()
                .any(|v| job["phase"] == *v),
            "{job}"
        );
        assert!(started.elapsed() < Duration::from_secs(125), "{job}");
        std::thread::sleep(Duration::from_millis(25));
    }
}
fn summary(service: &Service, scope: &str) -> Value {
    let id = scope.to_owned();
    old_actor(service)
        .call(move |r, e| upgrade_reviewed_summary(e, r, &id))
        .unwrap()
}
fn same_notes(now: &Value, before: &Value) {
    for field in ["scope_sha256", "notes", "expires_at_ms", "documents_sha256"] {
        assert_eq!(now[field], before[field], "{field}");
    }
}
#[test]
#[ignore = "requires explicit final0.14.1 SDK/dependency wheels and CPython3.14.7/3.14.10 task-private inputs"]
fn actual_resident_operator_cancels_switches_and_rolls_back_latest_saved_data() {
    run(false);
}
#[test]
#[ignore = "requires explicit final0.14.1 SDK/dependency wheels and CPython3.14.7/3.14.10 task-private inputs"]
fn actual_cached_catalog_preserves_live_context_then_switches_and_rolls_back_latest_data() {
    run(true);
}
fn run(use_cached_catalog: bool) {
    let f = UpgradeFixture::new();
    let mut key =
        crate::resident_state::private_file(&f.home.join("policy-verifier.key"), true, &f.home)
            .unwrap();
    key.write_all(&[91_u8; 32]).unwrap();
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
    let started = Instant::now();
    while service.status().unwrap()["availability"] != "ready" {
        assert!(started.elapsed() < Duration::from_secs(90));
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
                "operator-original",
                "Original review before the operator switch.",
            )
        })
        .unwrap();
    let original = summary(service, &scope);
    let source = old_actor(service);
    let generation = service.status().unwrap()["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    let before = std::fs::read(f.home.join("config.toml")).unwrap();
    let signed_catalog = if use_cached_catalog {
        let compiled = workspace(
            service,
            &f,
            &store,
            json!({"action":"compile","scope_id":scope,"query":"Original review"}),
        );
        let snapshot = compiled["brief"]["snapshot_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let fence = lock(&service.state).unwrap().epoch.fence();
        let raw = catalog_fixture::install(&store, &f.home);
        assert!(Arc::ptr_eq(&source, &old_actor(service)));
        assert!(fence.is_current());
        assert_eq!(service.status().unwrap()["generation"], generation);
        assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
        same_notes(&summary(service, &scope), &original);
        workspace(
            service,
            &f,
            &store,
            json!({"action":"explain","scope_id":scope,"snapshot_id":snapshot}),
        );
        catalog_fixture::refresh(&store, &f, &raw, &scope, &snapshot);
        same_notes(&summary(service, &scope), &original);
        catalog_fixture::reverify(&store, &f);
        assert_eq!(service.status().unwrap()["generation"], generation);
        same_notes(&summary(service, &scope), &original);
        Some(raw)
    } else {
        None
    };
    versions(
        &store,
        &f.home,
        json!({"action":"prepare_switch","job_id":"operator-cancel","target_runtime_id":f.target.runtime_id,"expected_generation":generation}),
    );
    wait(&store, &f.home, "operator-cancel", "ready");
    if let Some(raw) = &signed_catalog {
        let previous = std::fs::read(f.home.join("cigar-catalog-state/catalog.json")).unwrap();
        let reply = ask(
            &store,
            &f.home,
            "versions",
            json!({"action":"import_catalog","signed_catalog":raw}),
        );
        assert_eq!(reply["code"], "native_context_assistance_install_busy");
        assert_eq!(
            std::fs::read(f.home.join("cigar-catalog-state/catalog.json")).unwrap(),
            previous
        );
        assert_eq!(
            versions(&store, &f.home, json!({"action":"catalog"}))["source"],
            "cached"
        );
    }
    assert!(Arc::ptr_eq(&source, &old_actor(service)));
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    let listed = versions(&store, &f.home, json!({"action":"jobs"}));
    assert!(listed["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|j| j["job_id"] == "operator-cancel" && j["can_commit"] == true));
    versions(
        &store,
        &f.home,
        json!({"action":"cancel","job_id":"operator-cancel"}),
    );
    wait(&store, &f.home, "operator-cancel", "cancelled");
    assert!(source.is_active());
    same_notes(&summary(service, &scope), &original);
    versions(
        &store,
        &f.home,
        json!({"action":"prepare_switch","job_id":"operator-forward","target_runtime_id":f.target.runtime_id,"expected_generation":generation}),
    );
    wait(&store, &f.home, "operator-forward", "ready");
    for (expected, reconnect, code) in [
        (
            generation.clone(),
            false,
            "native_context_assistance_switch_reconnect_acknowledgement_required",
        ),
        (
            (generation.parse::<u64>().unwrap() + 1).to_string(),
            true,
            "native_context_assistance_switch_selection_conflict",
        ),
    ] {
        let refused = ask(
            &store,
            &f.home,
            "versions",
            json!({"action":"commit","job_id":"operator-forward","expected_generation":expected,"reconnect":reconnect}),
        );
        assert_eq!(refused["code"], code, "{refused}");
        assert!(source.is_active());
    }
    versions(
        &store,
        &f.home,
        json!({"action":"commit","job_id":"operator-forward","expected_generation":generation,"reconnect":true}),
    );
    wait(&store, &f.home, "operator-forward", "completed");
    same_notes(&summary(service, &scope), &original);
    assert!(source.cleanup_finished());
    workspace(
        service,
        &f,
        &store,
        json!({"action":"clear_notes","scope_id":scope}),
    );
    let id = scope.clone();
    old_actor(service)
        .call(move |r, e| {
            upgrade_admit(
                e,
                r,
                &id,
                "operator-latest",
                "Latest review survives rollback; original review stays removed.",
            )
        })
        .unwrap();
    let latest = summary(service, &scope);
    assert_ne!(latest["documents_sha256"], original["documents_sha256"]);
    let generation = service.status().unwrap()["generation"]
        .as_str()
        .unwrap()
        .to_owned();
    let request = json!({"action":"prepare_rollback","job_id":"operator-back","expected_generation":generation});
    let rollback = versions(&store, &f.home, request.clone());
    assert_eq!(rollback["target_runtime_id"], f.source.runtime_id);
    wait(&store, &f.home, "operator-back", "ready");
    versions(
        &store,
        &f.home,
        json!({"action":"commit","job_id":"operator-back","expected_generation":generation,"reconnect":true}),
    );
    wait(&store, &f.home, "operator-back", "completed");
    same_notes(&summary(service, &scope), &latest);
    assert_eq!(versions(&store, &f.home, request)["phase"], "completed");
    versions(
        &store,
        &f.home,
        json!({"action":"recover","job_id":"operator-back","expected_generation":service.status().unwrap()["generation"]}),
    );
    assert_eq!(
        crate::guard_config_load::context_assistance_config(&f.home)
            .unwrap()
            .requested,
        f.source
    );
    assert_eq!(ask(&store, &f.home, "stop", json!({}))["status"], "ok");
    assert_eq!(service.status().unwrap()["requested_enabled"], false);
    assert!(
        versions(&store, &f.home, json!({"action":"jobs"}))["jobs"]
            .as_array()
            .unwrap()
            .len()
            >= 3
    );
    service.shutdown();
    println!(
        "CIGAR_VERSION_CONTROLS_PROOF={}",
        json!({"schema":"guard-cigar-version-controls-proof.v1",
        "scope":"local-macos-arm64-final0141-external-py3147-31410-test-qualified-target-not-b47380-not-newer-sdk",
        "resident_operator_envelopes":true,"authenticated_cached_catalog":use_cached_catalog,"normal_reverification_used_imported_catalog_without_interrupting_source":use_cached_catalog,"synthetic_feed_refresh_preserved_live_context_and_preferences":use_cached_catalog,"catalog_import_preserved_actor_context_preferences_and_generation":use_cached_catalog,"ready_switch_excluded_catalog_publication":use_cached_catalog,"cancelled_ready_source_preserved":true,"unified_job_listing":true,
        "stale_generation_refused":true,"explicit_reconnect_acknowledgement":true,"forward_notes_and_expiry_preserved":true,
        "rollback_uses_latest_reviewed_data":true,"removed_notes_not_resurrected":true,"lost_reply_retry_did_not_switch_again":true,
        "stop_kept_disabled":true,"off_state_job_inspection_did_not_start_sdk":true})
    );
}
