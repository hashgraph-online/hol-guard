//! Reverse preparation must follow current reviewed state, including removal.
//! Reusing the old last-good cache would resurrect the deliberately removed note.
use super::*;

pub(super) fn round_trip(
    service: &Service,
    f: &UpgradeFixture,
    store: &crate::policy_store::PolicySnapshotStore,
    scope: &str,
    secondary: Option<&str>,
) -> Value {
    let original = old_actor(service);
    let fence = lock(&service.state).unwrap().epoch.fence();
    let generation = service.configuration_generation().unwrap();
    workspace(
        service,
        f,
        store,
        json!({"action":"clear_notes","scope_id":scope}),
    );
    let id = scope.to_owned();
    original
        .call(move |runtime, engine| {
            upgrade_admit(
                engine,
                runtime,
                &id,
                "after-upgrade-latest-only",
                "Latest only after upgrade; rollback must retain this review.",
            )
        })
        .unwrap();
    let latest = original
        .call({
            let id = scope.to_owned();
            move |runtime, engine| {
                crate::context_assistance_engine::upgrade_reviewed_summary(engine, runtime, &id)
            }
        })
        .unwrap();
    let memory = f.source.storage.mode == StorageMode::Memory;
    let secondary_before = secondary.map(|id| memory::summary(service, id));
    if memory {
        memory::no_saved_evidence(f);
    }
    let before = std::fs::read(f.home.join("config.toml")).unwrap();
    let prepared = service
        .prepare_rollback(&f.home, "live-rollback", generation)
        .unwrap();
    assert_eq!(prepared["operation"], "rollback");
    assert_eq!(prepared["target_runtime_id"], f.source.runtime_id);
    assert_eq!(
        service
            .prepare_rollback(&f.home, "live-rollback", generation)
            .unwrap()["job_id"],
        "live-rollback"
    );
    let started = Instant::now();
    let mut served = 0;
    loop {
        let value = workspace(
            service,
            f,
            store,
            json!({"action":"compile","scope_id":scope,"query":"Latest only after upgrade"}),
        );
        assert!(value.to_string().contains("Latest only after upgrade"));
        assert!(!value.to_string().contains("A reviewed note survives"));
        served += 1;
        let job = service.switch_job(&f.home, "live-rollback").unwrap();
        if job["phase"] == "ready" {
            break;
        }
        assert!(
            !["failed", "cancelled", "recovery_required"]
                .iter()
                .any(|p| job["phase"] == *p),
            "{job}"
        );
        assert!(started.elapsed() < Duration::from_secs(125), "{job}");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(fence.is_current());
    assert!(original.is_active());
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), before);
    service
        .commit_switch(&f.home, "live-rollback", generation, true)
        .unwrap();
    let done = wait_job(service, &f.home, "live-rollback", "completed");
    assert_eq!(done["operation"], "rollback");
    assert!(!fence.is_current());
    assert!(original.cleanup_finished());
    let returned = old_actor(service);
    let current = returned
        .call({
            let id = scope.to_owned();
            move |runtime, engine| {
                crate::context_assistance_engine::upgrade_reviewed_summary(engine, runtime, &id)
            }
        })
        .unwrap();
    let expiry = if memory {
        "valid_until_ms"
    } else {
        "expires_at_ms"
    };
    for field in ["scope_sha256", "notes", expiry, "documents_sha256"] {
        assert_eq!(current[field], latest[field], "{field}");
    }
    if memory {
        assert_eq!(current["observed_at_ms"], latest["observed_at_ms"]);
        memory::no_saved_evidence(f);
    }
    if let Some(secondary) = secondary {
        let after = memory::summary(service, secondary);
        let before = secondary_before.unwrap();
        for field in [
            "scope_sha256",
            "notes",
            "valid_until_ms",
            "observed_at_ms",
            "documents_sha256",
        ] {
            assert_eq!(after[field], before[field], "secondary {field}");
        }
    }
    let output = workspace(
        service,
        f,
        store,
        json!({"action":"compile","scope_id":scope,"query":"Latest only after upgrade"}),
    )
    .to_string();
    assert!(output.contains("Latest only after upgrade"));
    assert!(!output.contains("A reviewed note survives"));
    assert_eq!(
        crate::guard_config_load::context_assistance_config(&f.home)
            .unwrap()
            .requested,
        f.source
    );
    let owner = switching::Owner::acquire(&f.home).unwrap();
    assert_eq!(
        owner.record().unwrap().current.runtime.installation_id,
        f.source.runtime_id
    );
    assert_eq!(
        owner
            .record()
            .unwrap()
            .last_good
            .as_ref()
            .unwrap()
            .runtime
            .installation_id,
        f.target.runtime_id
    );
    assert_eq!(
        owner.record().unwrap().current.data.generation_id(),
        done["prepared_data_generation"].as_str()
    );
    drop(owner);
    // Lost-reply retry returns the original reverse job even though last-good
    // now refers to the other runtime; it must not start a second switch.
    assert_eq!(
        service
            .prepare_rollback(&f.home, "live-rollback", generation)
            .unwrap()["phase"],
        "completed"
    );
    assert_eq!(service.configuration_generation().unwrap(), generation + 1);
    json!({"performed":true,"source_calls_during_rollback_preparation":served,"latest_review_preserved":true,
        "removed_note_returned":false,"complete_note_digest_preserved":true,"original_expiry_preserved":true,
        "old_epoch_revoked":true,"old_actor_cleanup_acknowledged":true,"fresh_data_generation":done["prepared_data_generation"],
        "retry_did_not_switch_again":true,"storage":if memory {"memory"}else{"sqlite"},
        "secondary_app_preserved":secondary.is_some(),"saved_evidence_absent":memory})
}
