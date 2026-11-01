//! Restore the selected, edited ready generation after a failed reverse switch;
//! never substitute retained legacy data or the last-good installation's cache.
use super::*;
use crate::context_assistance_engine::upgrade_reviewed_summary;
use guard_cigar_release::{SelectionData, SelectionPhase};
use std::os::unix::fs::PermissionsExt;

fn summary(service: &Service, scope: &str) -> Value {
    let id = scope.to_owned();
    old_actor(service)
        .call(move |r, e| upgrade_reviewed_summary(e, r, &id))
        .unwrap()
}
fn data(service: &Service, home: &Path) -> SelectionData {
    let home = home.to_path_buf();
    old_actor(service)
        .call(move |_, e| e.upgrade_selection_data(&home))
        .unwrap()
}
#[test]
#[ignore = "requires explicit final0.14.1 SDK/dependency wheels and CPython3.14.7/3.14.10 task-private inputs"]
fn actual_failed_rollback_restores_the_current_edited_generation_and_preserves_last_good() {
    let (f, store, service, scope) = restoration::activate(false);
    let initial = service.configuration_generation().unwrap();
    let original = old_actor(&service);
    service
        .prepare_switch(
            &f.home,
            SwitchRequest {
                job_id: "generation-forward".into(),
                target_runtime_id: f.target.runtime_id.clone(),
                expected_generation: initial,
                rollback: false,
            },
        )
        .unwrap();
    wait_job(&service, &f.home, "generation-forward", "ready");
    service
        .commit_switch(&f.home, "generation-forward", initial, true)
        .unwrap();
    let forward = wait_job(&service, &f.home, "generation-forward", "completed");
    assert!(original.cleanup_finished());
    let selected_generation = forward["prepared_data_generation"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        data(&service, &f.home),
        SelectionData::Generation {
            generation_id: selected_generation.clone()
        }
    );
    workspace(
        &service,
        &f,
        &store,
        json!({"action":"clear_notes","scope_id":scope}),
    );
    let id = scope.clone();
    old_actor(&service)
        .call(move |r, e| {
            upgrade_admit(
                e,
                r,
                &id,
                "generation-current-only",
                "Only the latest reviewed generation may return after failed rollback.",
            )
        })
        .unwrap();
    let notes = summary(&service, &scope);
    let compiled = workspace(
        &service,
        &f,
        &store,
        json!({"action":"compile","scope_id":scope,"query":"latest reviewed generation"}),
    );
    assert!(compiled
        .to_string()
        .contains("Only the latest reviewed generation"));
    assert!(!compiled
        .to_string()
        .contains("Reviewed source survives failed cutover"));
    let source = old_actor(&service);
    let fence = lock(&service.state).unwrap().epoch.fence();
    let generation = service.configuration_generation().unwrap();
    let bytes = std::fs::read(f.home.join("config.toml")).unwrap();
    let owner = switching::Owner::acquire(&f.home).unwrap();
    let current = owner.record().unwrap().current.clone();
    let last_good = owner.record().unwrap().last_good.clone();
    assert_eq!(current.runtime.installation_id, f.target.runtime_id);
    assert_eq!(
        last_good.as_ref().unwrap().runtime.installation_id,
        f.source.runtime_id
    );
    drop(owner);
    service
        .prepare_rollback(&f.home, "generation-failed-rollback", generation)
        .unwrap();
    let started = Instant::now();
    let mut recovery_source_calls = 0;
    let ready = loop {
        let job = service
            .switch_job(&f.home, "generation-failed-rollback")
            .unwrap();
        if job["phase"] == "ready" && job["can_commit"] == true {
            break job;
        }
        assert!(
            !["failed", "cancelled", "recovery_required"]
                .iter()
                .any(|p| job["phase"] == *p),
            "{job}"
        );
        assert!(started.elapsed() < Duration::from_secs(125), "{job}");
        if job["phase"] == "preparing_recovery" {
            let value = workspace(
                &service,
                &f,
                &store,
                json!({"action":"compile","scope_id":scope,"query":"latest reviewed generation"}),
            );
            assert!(value
                .to_string()
                .contains("Only the latest reviewed generation"));
            recovery_source_calls += 1;
            assert!(source.is_active());
            assert!(fence.is_current());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(recovery_source_calls > 0);
    let compiled = workspace(
        &service,
        &f,
        &store,
        json!({"action":"compile","scope_id":scope,"query":"latest reviewed generation"}),
    );
    let snapshot = compiled["brief"]["snapshot_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let history = workspace(
        &service,
        &f,
        &store,
        json!({"action":"history","scope_id":scope}),
    )["entries"]
        .as_array()
        .unwrap()
        .clone();

    assert_eq!(ready["operation"], "rollback");
    let prepared = ready["prepared_data_generation"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(prepared, selected_generation);
    assert!(source.is_active());
    assert!(fence.is_current());
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), bytes);
    let signal = lock(&service.state).unwrap().upgrade.clone().unwrap();
    let path = f.home.join("config.toml");
    *signal.source_closed_hook.lock().unwrap() = Some(Box::new(move || {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400)).unwrap();
    }));
    service
        .commit_switch(&f.home, "generation-failed-rollback", generation, true)
        .unwrap();
    let done = wait_job(&service, &f.home, "generation-failed-rollback", "failed");
    assert_eq!(
        done["code"], "switch_failed_previous_runtime_restored",
        "{done}"
    );
    assert!(done["restoration_failure_code"].is_null(), "{done}");
    assert!(source.cleanup_finished());
    assert!(!source.is_active());
    assert!(!fence.is_current());
    assert_eq!(service.configuration_generation().unwrap(), generation + 2);
    assert_eq!(service.status().unwrap()["availability"], "ready");
    assert!(!Arc::ptr_eq(&source, &old_actor(&service)));
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), bytes);
    std::fs::set_permissions(
        f.home.join("config.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_eq!(data(&service, &f.home), current.data);
    assert_eq!(summary(&service, &scope), notes);
    assert_history_entries(
        &workspace(
            &service,
            &f,
            &store,
            json!({"action":"history","scope_id":scope}),
        ),
        &history,
    );
    assert!(service
        .workspace(
            &f.home,
            &store,
            json!({"action":"explain","scope_id":scope,"snapshot_id":snapshot}),
            true,
            true
        )
        .is_err());
    let fresh = workspace(
        &service,
        &f,
        &store,
        json!({"action":"compile","scope_id":scope,"query":"latest reviewed generation"}),
    );
    assert!(fresh
        .to_string()
        .contains("Only the latest reviewed generation"));
    assert!(!fresh
        .to_string()
        .contains("Reviewed source survives failed cutover"));
    let owner = switching::Owner::acquire(&f.home).unwrap();
    assert_eq!(owner.record().unwrap().current, current);
    assert_eq!(owner.record().unwrap().last_good, last_good);
    assert_eq!(
        owner.record().unwrap().transaction.as_ref().unwrap().phase,
        SelectionPhase::RolledBack
    );
    drop(owner);
    let list = guard_context_assistance::EvidenceGenerationStore::existing(&f.home)
        .unwrap()
        .unwrap()
        .list()
        .unwrap();
    assert!(list
        .iter()
        .any(|g| g["generation_id"] == selected_generation));
    assert!(!list.iter().any(|g| g["generation_id"] == prepared));
    let restored = old_actor(&service);
    let retry = service
        .prepare_rollback(&f.home, "generation-failed-rollback", generation)
        .unwrap();
    assert_eq!(retry["phase"], "failed");
    assert!(Arc::ptr_eq(&restored, &old_actor(&service)));
    service
        .cancel_switch(&f.home, "generation-failed-rollback")
        .unwrap();
    assert!(restored.is_active());
    service.stop().unwrap();
    service.shutdown();
    println!(
        "CIGAR_GENERATION_RESTORE_PROOF={}",
        json!({"schema":"guard-cigar-generation-source-restore-proof.v1","scope":"local-macos-arm64-final0141-enrolled-source-test-qualified-target-not-b47380-not-newer-sdk","selected_generation":selected_generation,"failed_prepared_generation":prepared,"upgraded_before_failure":true,"source_calls_during_recovery_preparation":recovery_source_calls,"current_review_edited_after_upgrade":true,"exact_selected_generation_restored":true,"complete_reviewed_digest_and_original_expiry_preserved":true,"removed_legacy_note_returned":false,"original_last_good_preserved":true,"failed_rollback_target_not_published":true,"failed_prepared_generation_removed":true,"latest_history_preserved":true,"old_context_and_epoch_revoked":true,"fresh_actor":true,"exact_config_preserved":true,"retry_did_not_switch_again":true})
    );
}
