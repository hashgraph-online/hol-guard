//! Core cold SDK/data selection through the existing native transaction owner.
//! The bounded operator cold-selection job/CLI/HTTP action is still separate.
use super::*;
use guard_cigar_release::{SelectionData, SelectionPhase, SelectionTransaction};
use guard_context_assistance::{EvidenceCache, EvidenceGenerationStore, EvidencePreparation};
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}
fn enable(store: &crate::policy_store::PolicySnapshotStore, f: &UpgradeFixture) {
    let mut selected = crate::guard_config_load::context_assistance_config(&f.home)
        .unwrap()
        .requested;
    selected.enabled = true;
    let request = json!({"schema":"guard-config-update.v1","guard_home":f.home,"kind":"settings","value_text":json!({"context_assistance":selected}).to_string()});
    let value: Value = serde_json::from_slice(
        &crate::guard_config_update::run_command(request.to_string().as_bytes()).unwrap(),
    )
    .unwrap();
    assert_eq!(value["ok"], true, "{value}");
    assert_eq!(ask(store, &f.home, "activate", json!({}))["status"], "ok");
    let started = Instant::now();
    while store.context_assistance().status().unwrap()["availability"] != "ready" {
        assert!(
            started.elapsed() < Duration::from_secs(90),
            "{}",
            store.context_assistance().status().unwrap()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}
fn grant(
    service: &Service,
    f: &UpgradeFixture,
    store: &crate::policy_store::PolicySnapshotStore,
    app: &str,
    read: bool,
) -> String {
    workspace(service,f,store,json!({"action":"grant","workspace":f.workspace,"app":app,"sources":["README.md"],"shared_notes":{"read":read,"propose":read}}))["scope_id"].as_str().unwrap().to_owned()
}
#[test]
#[ignore = "requires exact final0141 wheels and private external CPython3.14.7/3.14.10"]
fn actual_cold_sdk_data_pair_stays_off_then_readmits_only_under_fresh_grants() {
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
    let (_, target, to) = f.installed_target();
    let service = store.context_assistance();
    assert_eq!(ask(&store, &f.home, "activate", json!({}))["status"], "ok");
    let started = Instant::now();
    while service.status().unwrap()["availability"] != "ready" {
        assert!(started.elapsed() < Duration::from_secs(90));
        std::thread::sleep(Duration::from_millis(25));
    }
    let codex = grant(service, &f, &store, "codex", true);
    let claude = grant(service, &f, &store, "dashboard", true);
    for (id, name, text) in [
        (
            &codex,
            "cold-codex",
            "Codex reviewed data survives a disabled selection.",
        ),
        (
            &claude,
            "cold-claude",
            "Claude reviewed data retains its own scope and expiry.",
        ),
    ] {
        let id = id.clone();
        old_actor(service)
            .call(move |r, e| upgrade_admit(e, r, &id, name, text))
            .unwrap();
    }
    let codex_notes = summary(service, &codex);
    let claude_notes = summary(service, &claude);
    catalog_fixture::install(&store, &f.home);
    let old = old_actor(service);
    let fence = lock(&service.state).unwrap().epoch.fence();
    assert_eq!(ask(&store, &f.home, "stop", json!({}))["status"], "ok");
    let until = Instant::now();
    while !old.cleanup_finished() {
        assert!(until.elapsed() < Duration::from_secs(15));
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(!fence.is_current());
    assert!(service.status().unwrap()["runtime"].is_null());
    let before = std::fs::read(f.home.join("config.toml")).unwrap();
    let off = crate::guard_config_load::context_assistance_config(&f.home).unwrap();
    assert!(!off.requested.enabled);
    use crate::policy_store::context_assistance_registry::{self as registry, switching};
    let source_install = registry::load(&f.home, &f.source.runtime_id).unwrap();
    let target_install = registry::load(&f.home, &f.target.runtime_id).unwrap();
    let mut source = crate::context_assistance_service::verification::runtime(
        &source_install,
        &f.home,
        &f.source,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    let (source_pointer, from) = source_install
        .measured_selection(&f.home, &source, SelectionData::LegacySaved)
        .unwrap();
    let mut owner = switching::Owner::acquire(&f.home).unwrap();
    let owners = switching::scope_index::owners(&owner).unwrap();
    let cache = EvidenceCache::existing(&f.home).unwrap().unwrap();
    let transfers = cache
        .export_cold_notes(&f.home, &owners, &from, &mut source, &off.effective, now())
        .unwrap();
    assert_eq!(transfers.len(), 2);
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    assert!(service.status().unwrap()["runtime"].is_null());
    assert_eq!(service.status().unwrap()["requested_enabled"], false);
    let snapshot = cache.upgrade_inventory(now()).unwrap();
    let generation = EvidenceGenerationStore::open(&f.home)
        .unwrap()
        .prepare_cold(
            EvidencePreparation {
                request_id: "native-cold-pair",
                source: &cache,
                snapshot: &snapshot,
                from: &from,
                to: &to,
                notes: &transfers,
            },
            now(),
        )
        .unwrap();
    assert_eq!(generation.describe().unwrap()["phase"], "ready");
    assert_eq!(generation.describe().unwrap()["deferred_scopes"], 2);
    let settings =
        switching::SwitchSettings::capture(&f.home, &off.effective, &f.target.runtime_id).unwrap();
    assert!(!settings.target().enabled);
    crate::guard_config_load::cigar_updates::check_installation(
        &f.home,
        settings.update_preferences(),
        &target_install,
    )
    .unwrap();
    let (target_pointer, measured_to) = target_install
        .measured_selection(
            &f.home,
            &target,
            SelectionData::Generation {
                generation_id: generation.id().into(),
            },
        )
        .unwrap();
    assert_eq!(measured_to.identity_sha256(), to.identity_sha256());
    owner.initialize(source_pointer.clone()).unwrap();
    owner
        .begin(SelectionTransaction {
            request_id: "native-cold-pair".into(),
            expected_service_generation: service.status().unwrap()["generation"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            before_settings_sha256: settings.before_sha256(),
            after_settings_sha256: settings.after_sha256(),
            source_semantic_sha256: snapshot.snapshot_sha256().into(),
            from: source_pointer,
            to: target_pointer,
            was_enabled: false,
            activate_target: false,
            reconnect_acknowledged: false,
            cancel_requested: false,
            phase: SelectionPhase::Prepared,
        })
        .unwrap();
    owner.advance(SelectionPhase::StopIntent).unwrap();
    owner.commit(&settings).unwrap();
    owner.mark_healthy("native-cold-pair").unwrap();
    owner.complete_publication("native-cold-pair").unwrap();
    assert_eq!(
        owner.record().unwrap().current.runtime.installation_id,
        f.target.runtime_id
    );
    assert_eq!(
        owner.record().unwrap().current.data.generation_id(),
        Some(generation.id())
    );
    drop(owner);
    drop(cache);
    drop(source);
    drop(target);
    let status = ask(&store, &f.home, "status", json!({}));
    assert_eq!(status["status"], "ok", "{status}");
    assert_eq!(status["payload"]["state"]["requested_enabled"], false);
    assert!(status["payload"]["state"]["runtime"].is_null());
    let prefs = crate::guard_config_load::context_assistance_config(&f.home).unwrap();
    assert_eq!(prefs.requested.runtime_id, f.target.runtime_id);
    assert!(!prefs.requested.enabled);
    assert_eq!(prefs.requested.storage, off.requested.storage);
    enable(&store, &f);
    let readless = grant(service, &f, &store, "codex", false);
    assert_eq!(summary(service, &readless)["notes"], 0);
    assert_eq!(generation.describe().unwrap()["deferred_scopes"], 2);
    assert_eq!(ask(&store, &f.home, "stop", json!({}))["status"], "ok");
    enable(&store, &f);
    let fresh_codex = grant(service, &f, &store, "codex", true);
    assert_ne!(fresh_codex, codex);
    same_notes(&summary(service, &fresh_codex), &codex_notes);
    assert_eq!(generation.describe().unwrap()["deferred_scopes"], 1);
    let fresh_claude = grant(service, &f, &store, "dashboard", true);
    assert_ne!(fresh_claude, claude);
    same_notes(&summary(service, &fresh_claude), &claude_notes);
    assert_eq!(generation.describe().unwrap()["deferred_scopes"], 0);
    let actor = old_actor(service);
    workspace(
        service,
        &f,
        &store,
        json!({"action":"clear_notes","scope_id":fresh_codex}),
    );
    assert!(Arc::ptr_eq(&actor, &old_actor(service)));
    same_notes(&summary(service, &fresh_claude), &claude_notes);
    assert_eq!(summary(service, &fresh_codex)["notes"], 0);
    assert_eq!(ask(&store, &f.home, "stop", json!({}))["status"], "ok");
    enable(&store, &f);
    let again = grant(service, &f, &store, "codex", true);
    assert_eq!(summary(service, &again)["notes"], 0);
    let other = grant(service, &f, &store, "dashboard", true);
    same_notes(&summary(service, &other), &claude_notes);
    assert_eq!(ask(&store, &f.home, "stop", json!({}))["status"], "ok");
    service.shutdown();
    println!(
        "CIGAR_COLD_DATA_PROOF={}",
        json!({"schema":"guard-cigar-cold-data-proof.v1","scope":"local-macos-arm64-final0141-external3147-31410-test-qualified-target-native-transaction-primitives-not-operator-cold-job-not-b47380-not-newer-sdk","authenticated_native_scope_attribution":true,"temporary_sdk_export_preserved_persisted_opt_out_and_no_serving_actor":true,"committed_sdk_data_pair_stayed_disabled":true,"deferred_data_did_not_grant_note_read_access":true,"fresh_grants_preserved_both_apps_notes_and_expiry":true,"empty_restored_target_readmitted_only_after_fresh_note_permission":true,"scoped_deletion_removed_legacy_and_deferred_copies_without_other_app_loss":true,"explicit_restart_did_not_resurrect_deleted_notes":true})
    );
}

#[path = "context_assistance_cold_selection_actual.rs"]
mod operator_job;
#[path = "context_assistance_disabled_recovery_actual.rs"]
mod recovery;
