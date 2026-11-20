//! Full erase after a real generation switch must cover the original legacy
//! root and every generation, survive interruption, and never opt in/regrant.
use super::*;
use guard_context_assistance::{EvidenceCache, EvidenceGenerationStore};
use std::os::unix::fs::OpenOptionsExt;

#[test]
#[ignore = "requires explicit final0.14.1 SDK/dependency wheels and CPython3.14.7/3.14.10 task-private inputs"]
fn actual_full_clear_after_upgrade_durably_blocks_readmission_and_erases_legacy_and_generations() {
    let (f, store, service, scope) = restoration::activate(false);
    let generation = service.configuration_generation().unwrap();
    service
        .prepare_switch(
            &f.home,
            SwitchRequest {
                job_id: "erase-forward".into(),
                target_runtime_id: f.target.runtime_id.clone(),
                expected_generation: generation,
                rollback: false,
            },
        )
        .unwrap();
    wait_job(&service, &f.home, "erase-forward", "ready");
    service
        .commit_switch(&f.home, "erase-forward", generation, true)
        .unwrap();
    let done = wait_job(&service, &f.home, "erase-forward", "completed");
    let selected = done["prepared_data_generation"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(workspace(
        &service,
        &f,
        &store,
        json!({"action":"compile","scope_id":scope,"query":"reviewed source"})
    )
    .to_string()
    .contains("Reviewed source survives"));
    assert!(
        EvidenceCache::existing(&f.home)
            .unwrap()
            .unwrap()
            .summary()
            .unwrap()
            .slots
            > 0
    );
    assert!(EvidenceGenerationStore::existing(&f.home)
        .unwrap()
        .unwrap()
        .list()
        .unwrap()
        .iter()
        .any(|g| g["generation_id"] == selected));
    let prefs = std::fs::read(f.home.join("config.toml")).unwrap();
    let actor = old_actor(&service);
    actor
        .call(|_, _| {
            switching::DataRemoval::fail_next_after_legacy();
            Ok(())
        })
        .unwrap();
    let failed = service
        .workspace(&f.home, &store, json!({"action":"clear"}), true, true)
        .unwrap_err();
    assert!(failed.ends_with("storage_outcome_unknown"), "{failed}");
    assert!(f.home.join("cigar-erasure.json").exists());
    assert_eq!(
        EvidenceCache::existing(&f.home)
            .unwrap()
            .unwrap()
            .summary()
            .unwrap()
            .slots,
        0
    );
    assert!(EvidenceGenerationStore::existing(&f.home)
        .unwrap()
        .unwrap()
        .list()
        .unwrap()
        .iter()
        .any(|g| g["generation_id"] == selected));
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), prefs);
    assert_eq!(
        crate::context_assistance_data::inspect(&f.home)["status"],
        "repair_required"
    );
    assert!(service
        .workspace(
            &f.home,
            &store,
            json!({"action":"compile","scope_id":scope,"query":"reviewed source"}),
            true,
            true
        )
        .is_err());
    assert!(service
        .schedule(Check::Activate, f.home.clone())
        .unwrap_err()
        .ends_with("storage_repair_required"));
    let cleared = workspace(&service, &f, &store, json!({"action":"forget_saved"}));
    assert_eq!(cleared["cleared_saved"], true);
    assert_eq!(cleared["saved_evidence"]["status"], "empty");
    assert!(!f.home.join("cigar-erasure.json").exists());
    assert!(!f.home.join("cigar-lifecycle.json").exists());
    assert!(!f.home.join("cigar-lifecycle.key").exists());
    assert_eq!(
        EvidenceCache::existing(&f.home)
            .unwrap()
            .unwrap()
            .summary()
            .unwrap()
            .slots,
        0
    );
    assert!(EvidenceGenerationStore::existing(&f.home)
        .unwrap()
        .is_none());
    assert!(lock(&service.state).unwrap().runtime.is_none());
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), prefs);
    // Corrupt intent can be repaired by the same explicit erase while off.
    // It never supplies enablement or a recoverable SDK scope.
    service.stop().unwrap();
    crate::guard_config_update::disable_context_assistance(&f.home).unwrap();
    let disabled = std::fs::read(f.home.join("config.toml")).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(f.home.join("cigar-erasure.json"))
        .unwrap()
        .write_all(b"{corrupt erase intent}")
        .unwrap();
    let repaired = workspace(&service, &f, &store, json!({"action":"forget_saved"}));
    assert_eq!(repaired["saved_evidence"]["status"], "empty");
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), disabled);
    assert!(
        !crate::guard_config_load::context_assistance_config(&f.home)
            .unwrap()
            .requested
            .enabled
    );
    assert!(lock(&service.state).unwrap().runtime.is_none());
    service.shutdown();
    println!(
        "CIGAR_FULL_ERASURE_PROOF={}",
        json!({"schema":"guard-cigar-full-erasure-proof.v1","scope":"local-macos-arm64-final0141-enrolled-source-test-qualified-target-not-b47380-not-newer-sdk","upgraded_to_selected_generation":true,"legacy_saved_copy_present_before_clear":true,"interrupted_after_legacy_clear":true,"pending_intent_persisted":true,"data_admission_and_activation_refused_while_pending":true,"selected_generation_removed_on_explicit_retry":true,"legacy_cache_empty":true,"selection_references_and_key_removed":true,"intent_removed_last":true,"requested_preferences_preserved":true,"corrupt_intent_repaired_while_disabled":true,"disabled_user_remained_disabled":true,"sdk_not_restarted":true,"old_scope_not_recreated":true})
    );
}
