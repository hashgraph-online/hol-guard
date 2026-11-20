//! Real final SDK, native journal/config publication and fresh resident
//! recovery. The live Service cutover controller remains a separate milestone.
use super::*;
use crate::policy_store::context_assistance_registry::switching::{Owner, SwitchSettings};
use guard_cigar_release::{SelectionData, SelectionPhase, SelectionTransaction};
use guard_context_assistance::RuntimeActor;
use std::io::Write;
use std::time::{Duration, Instant};

use super::actual_tests::fixture::{admit, ask, Fixture};

#[test]
#[ignore = "requires exact final0.14.1 SDK/dependency wheels and explicit CPython3.14.7/3.14.10 task-private inputs"]
fn actual_journal_recovers_lost_config_reply_and_reopens_reviewed_notes_in_a_fresh_service() {
    let f = Fixture::new();
    let mut fixture_key =
        crate::resident_state::private_file(&f.home.join("policy-verifier.key"), true, &f.home)
            .unwrap();
    fixture_key.write_all(&[73_u8; 32]).unwrap();
    drop(fixture_key);
    let store = crate::policy_store::PolicySnapshotStore::new(
        &f.home,
        &crate::resident_state::runtime_digest().unwrap(),
    )
    .unwrap();
    f.write_settings(&f.source);
    let config_before = std::fs::read(f.home.join("config.toml")).unwrap();
    let (mut runtime, from_producer) = f.start(false);
    let source_installation = f.enroll_source(&runtime);
    let mut engine = Engine::new(f.home.clone(), &f.source, None);
    let scope = ask(
        &mut engine,
        &mut runtime,
        json!({"action":"grant","workspace":f.workspace,
        "app":"dashboard","sources":["README.md"],"shared_notes":{"read":true,"propose":true}}),
    )
    .unwrap()["scope_id"]
        .as_str()
        .unwrap()
        .to_owned();
    admit(
        &mut engine,
        &mut runtime,
        &scope,
        "switch-review",
        "Human reviewed release note survives native selection recovery.",
    )
    .unwrap();
    let actor = Arc::new(
        RuntimeActor::start_with_maintenance(runtime, engine, Engine::maintenance).unwrap(),
    );
    let (target_installation, target_runtime, target_producer) = std::thread::scope(|threads| {
        let target = threads.spawn(|| f.installed_target());
        for _ in 0..4 {
            let scope = scope.clone();
            actor
                .call(move |runtime, engine| {
                    ask(
                        engine,
                        runtime,
                        json!({"action":"compile", "scope_id":scope,"query":"release evidence"}),
                    )
                })
                .unwrap();
        }
        target.join().unwrap()
    });
    assert_eq!(
        std::fs::read(f.home.join("config.toml")).unwrap(),
        config_before
    );
    let settings = SwitchSettings::capture(&f.home, &f.source, &f.target.runtime_id).unwrap();
    let mut owner = Owner::acquire(&f.home).unwrap();
    let home = f.home.clone();
    let installation = source_installation.clone();
    let (from, measured_producer) = actor
        .call(move |runtime, _| {
            installation
                .measured_selection(&home, runtime, SelectionData::LegacySaved)
                .map_err(|_| RuntimeError::ApprovalMismatch)
        })
        .unwrap();
    assert_eq!(
        measured_producer.identity_sha256(),
        from_producer.identity_sha256()
    );
    owner.initialize(from.clone()).unwrap();
    let source = settings.source().clone();
    let target = settings.target().clone();
    let source_producer = from_producer.clone();
    let to_producer = target_producer.clone();
    let capture = actor
        .call(move |runtime, engine| {
            engine.prepare_upgrade_capture(
                runtime,
                source,
                target,
                source_producer,
                to_producer,
                "actual-native-switch",
            )
        })
        .unwrap();
    let candidate = capture.build(target_runtime, None).unwrap();
    let generation = candidate.data_generation.clone().unwrap();
    let (to, _) = target_installation
        .measured_selection(
            &f.home,
            &candidate.runtime,
            SelectionData::Generation {
                generation_id: generation.clone(),
            },
        )
        .unwrap();
    owner
        .begin(SelectionTransaction {
            request_id: "actual-native-switch".into(),
            expected_service_generation: 7,
            before_settings_sha256: settings.before_sha256(),
            after_settings_sha256: settings.after_sha256(),
            source_semantic_sha256: candidate.source_semantic_sha256.clone(),
            from: from.clone(),
            to: to.clone(),
            was_enabled: true,
            activate_target: true,
            reconnect_acknowledged: true,
            cancel_requested: false,
            phase: SelectionPhase::Prepared,
        })
        .unwrap();
    let config = f.source.clone();
    let producer = from_producer.clone();
    let (boundary, stamp) = actor
        .pause_at_boundary(move |runtime, engine| {
            engine.upgrade_semantic_sha256(runtime, &config, &producer)
        })
        .unwrap();
    assert_eq!(stamp, candidate.source_semantic_sha256);
    owner.advance(SelectionPhase::StopIntent).unwrap();
    assert!(boundary.close_and_wait(Duration::from_millis(500)));
    assert!(!actor.is_active());
    crate::guard_config_update::io::fail_next_config_write_after_rename();
    assert_eq!(
        owner.commit(&settings).unwrap_err(),
        "native_context_assistance_switch_commit_outcome_unknown"
    );
    assert_eq!(
        owner.record().unwrap().transaction.as_ref().unwrap().phase,
        SelectionPhase::CommitIntent
    );
    let current = crate::guard_config_load::context_assistance_config(&f.home).unwrap();
    assert!(current.requested.enabled);
    assert_eq!(current.requested, f.target);
    let target_actor = RuntimeActor::start_with_maintenance(
        candidate.runtime,
        candidate.engine,
        Engine::maintenance,
    )
    .unwrap();
    let same_scope = scope.clone();
    let prepared = target_actor
        .call(move |runtime, engine| {
            ask(
                engine,
                runtime,
                json!({"action":"compile","scope_id":same_scope,"query":"release note"}),
            )
        })
        .unwrap();
    assert!(prepared.to_string().contains("Human reviewed release note"));
    assert!(target_actor.close_and_wait(Duration::from_millis(500)));
    drop(target_actor);
    drop(owner);
    drop(actor);
    // A new resident repeats installed byte/SDK/feature checks, reconciles the
    // actual config/intent, and binds the ready data generation. It restores
    // no logical scope, app grant, SDK context or agent session from the journal.
    let service = crate::context_assistance_service::Service::default();
    service.configure(current).unwrap();
    service
        .schedule(
            crate::context_assistance_service::Check::Activate,
            f.home.clone(),
        )
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let status = service.status().unwrap();
        if status["effective_enabled"] == true {
            break;
        }
        assert!(Instant::now() < deadline, "{status}");
        std::thread::sleep(Duration::from_millis(25));
    }
    let owner = Owner::acquire(&f.home).unwrap();
    let record = owner.record().unwrap();
    assert_eq!(record.current, to);
    assert_eq!(record.last_good.as_ref(), Some(&from));
    assert_eq!(
        record.transaction.as_ref().unwrap().phase,
        SelectionPhase::Completed
    );
    drop(owner);
    let list = service
        .workspace(&f.home, &store, json!({"action":"list"}), false, false)
        .unwrap();
    assert_eq!(list["result"]["scopes"], json!([]));
    let agents = service
        .workspace(
            &f.home,
            &store,
            json!({"action":"list_agents"}),
            false,
            false,
        )
        .unwrap();
    assert_eq!(agents["result"]["agent_sessions"], json!([]));
    let grant = service
        .workspace(
            &f.home,
            &store,
            json!({"action":"grant","workspace":f.workspace,
        "app":"dashboard","sources":["README.md"],"shared_notes":{"read":true,"propose":true}}),
            false,
            true,
        )
        .unwrap();
    let fresh_scope = grant["result"]["scope_id"].as_str().unwrap().to_owned();
    assert_ne!(fresh_scope, scope);
    let restored = service
        .workspace(
            &f.home,
            &store,
            json!({"action":"compile","scope_id":fresh_scope,
        "query":"reviewed release note"}),
            false,
            false,
        )
        .unwrap();
    assert!(restored.to_string().contains("Human reviewed release note"));
    assert!(service
        .workspace(
            &f.home,
            &store,
            json!({"action":"compile","scope_id":scope,
        "query":"old authority"}),
            false,
            false
        )
        .is_err());
    service.stop().unwrap();
    crate::guard_config_update::disable_context_assistance(&f.home).unwrap();
    service
        .configure(crate::guard_config_load::context_assistance_config(&f.home).unwrap())
        .unwrap();
    let stopped = std::fs::read(f.home.join("config.toml")).unwrap();
    // Corrupt metadata must not prevent an explicitly authorized full erasure.
    std::fs::write(f.home.join("cigar-lifecycle.json"), b"{invalid journal}").unwrap();
    let removed = service
        .workspace(
            &f.home,
            &store,
            json!({"action":"forget_saved"}),
            true,
            false,
        )
        .unwrap();
    assert_eq!(removed["result"]["cleared_saved"], true);
    assert!(!f.home.join("cigar-lifecycle.json").exists());
    assert!(!f.home.join("cigar-lifecycle.key").exists());
    assert!(
        guard_context_assistance::EvidenceGenerationStore::existing(&f.home)
            .unwrap()
            .is_none()
    );
    assert_eq!(std::fs::read(f.home.join("config.toml")).unwrap(), stopped);
    assert_eq!(service.status().unwrap()["effective_enabled"], false);
    service.shutdown();
    println!(
        "GUARD_CIGAR_NATIVE_SELECTION_RECOVERY_VERIFIED {}",
        json!({
        "source_producer_sha256":from.runtime.producer_sha256,"target_producer_sha256":to.runtime.producer_sha256,
        "generation_id":generation,"guard_binary_sha256":crate::resident_state::runtime_digest().unwrap(),
        "native_installation_stamps":true,"native_config_journal_exercised":true,
        "lost_config_reply_reconciled_by_fresh_service":true,"last_good_after_fresh_verification":true,
        "reviewed_notes_after_fresh_grant":true,"old_actor_closed_before_commit":true,
        "scope_or_agent_authority_restored":false,"live_service_cutover_controller_exercised":false,
        "process_kill_injected":false,"full_forget_repairs_corrupt_selection":true,
        "stop_and_all_other_preferences_preserved":true,"raw_sqlite_copied":false,
        "actual_newer_sdk_qualified":false})
    );
}
