//! Real native actor/engine preparation. This does not qualify a selection journal.
use super::*;
use guard_context_assistance::{EvidenceCache, RuntimeActor};
use std::time::{Duration, Instant};

#[path = "context_assistance_upgrade_test_fixture.rs"]
pub(crate) mod fixture;
use fixture::{admit, ask, Fixture};

#[test]
#[ignore = "requires exact final0.14.1 SDK and CPython3.14.7/3.14.10 in GUARD_CIGAR_NOTE_TRANSFER_TEST_INPUT"]
fn actual_actor_prepares_fresh_scopes_notes_and_history_while_old_runtime_keeps_serving() {
    let test = Fixture::new();
    test.write_settings(&test.source);
    let preferences = std::fs::read(test.home.join("config.toml")).unwrap();
    let (old_vm, from) = test.start(false);
    let worker = old_vm.status().worker_fingerprint.clone();
    let old = Arc::new(
        RuntimeActor::start_with_maintenance(
            old_vm,
            Engine::new(test.home.clone(), &test.source, None),
            Engine::maintenance,
        )
        .unwrap(),
    );
    let mut scopes = Vec::new();
    for (app, marker) in [
        ("dashboard", "Scoped marker alpha"),
        ("codex", "Scoped marker beta"),
    ] {
        let workspace = test.workspace.clone();
        let marker = marker.to_owned();
        let row = old.call(move |runtime,engine| {
            let grant = ask(engine,runtime,json!({"action":"grant","workspace":workspace,"app":app,
                "sources":["README.md"],"shared_notes":{"read":true,"propose":true}}))?;
            let id = grant["scope_id"].as_str().ok_or(RuntimeError::TransportFailed)?.to_owned();
            admit(engine,runtime,&id,"initial-review",&marker)?;
            let observation = ask(engine,runtime,json!({"action":"compile","scope_id":id,"query":"release evidence scoped marker"}))?;
            Ok((id, observation["brief"]["snapshot_id"].as_str().unwrap().to_owned(), marker))
        }).unwrap();
        scopes.push(row);
    }
    let (target_vm, to) = test.start(true);
    let source = test.source.clone();
    let target = test.target.clone();
    let source_producer = from.clone();
    let target_producer = to.clone();
    let first = old
        .call(move |runtime, engine| {
            engine.prepare_upgrade_capture(
                runtime,
                source,
                target,
                source_producer,
                target_producer,
                "actor-capture-initial",
            )
        })
        .unwrap();
    let first_summary = first.describe();
    let first_semantic = first_summary["source_semantic_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let first_generation = first_summary["prepared_data_generation"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(first_summary["scopes"], 2);
    for private in [
        test.home.to_str().unwrap(),
        test.workspace.to_str().unwrap(),
        "Scoped marker",
    ] {
        assert!(!first_summary.to_string().contains(private));
    }
    let id = scopes[0].0.clone();
    old.call(move |runtime, engine| {
        admit(
            engine,
            runtime,
            &id,
            "late-reviewed-edit",
            "Latest reviewed edit survives replacement preparation.",
        )
    })
    .unwrap();
    let source = test.source.clone();
    let source_producer = from.clone();
    let changed = old
        .call(move |runtime, engine| {
            engine.upgrade_semantic_sha256(runtime, &source, &source_producer)
        })
        .unwrap();
    assert_ne!(
        changed, first_semantic,
        "a real reviewed edit invalidates the earlier preparation"
    );
    drop(first);
    EvidenceGenerationStore::existing(&test.home)
        .unwrap()
        .unwrap()
        .discard_prepared(&first_generation)
        .unwrap();
    let source = test.source.clone();
    let target = test.target.clone();
    let source_producer = from.clone();
    let target_producer = to.clone();
    let capture = old
        .call(move |runtime, engine| {
            engine.prepare_upgrade_capture(
                runtime,
                source,
                target,
                source_producer,
                target_producer,
                "actor-capture-current",
            )
        })
        .unwrap();
    let expected = capture.describe()["source_semantic_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    let manifest = test
        .home
        .join("context-assistance/saved-evidence")
        .join(EvidenceCache::key("dashboard", &test.workspace, &worker).unwrap())
        .join("state.json");
    let before_read_stamps = std::fs::read(&manifest).unwrap();
    let building = std::thread::spawn(move || capture.build(target_vm, None));
    let mut samples = 0;
    let mut max_old_call_us = 0;
    while !building.is_finished() && samples < 4 {
        let id = scopes[0].0.clone();
        let started = Instant::now();
        let result = old.call(move |runtime,engine|ask(engine,runtime,json!({"action":"compile","scope_id":id,"query":"release evidence scoped marker latest"}))).unwrap();
        assert!(result["brief"]["rendered"]
            .as_str()
            .unwrap()
            .contains("Scoped marker alpha"));
        max_old_call_us = max_old_call_us.max(started.elapsed().as_micros());
        samples += 1;
    }
    let replacement = building.join().unwrap().unwrap();
    assert!(samples > 0);
    assert!(
        before_read_stamps == std::fs::read(&manifest).unwrap(),
        "read-only serving and preparation preserve the source evidence manifest"
    );
    let source = test.source.clone();
    let source_producer = from.clone();
    let after_reads = old
        .call(move |runtime, engine| {
            engine.upgrade_semantic_sha256(runtime, &source, &source_producer)
        })
        .unwrap();
    assert_eq!(
        expected, after_reads,
        "read timestamps and history are not reviewed-data edits"
    );
    assert_eq!(replacement.source_semantic_sha256, expected);
    assert!(replacement.data_generation.is_some());
    assert_eq!(
        std::fs::read(test.home.join("config.toml")).unwrap(),
        preferences
    );
    std::fs::write(
        test.workspace.join("README.md"),
        "Changed source must prevent stale cutover.\n",
    )
    .unwrap();
    let source = test.source.clone();
    let source_producer = from.clone();
    assert!(matches!(
        old.call(move |runtime, engine| engine.upgrade_semantic_sha256(
            runtime,
            &source,
            &source_producer
        )),
        Err(RuntimeError::ContextStale)
    ));
    std::fs::write(test.workspace.join("README.md"), fixture::SOURCE_TEXT).unwrap();
    let source = test.source.clone();
    let source_producer = from.clone();
    assert_eq!(
        old.call(move |runtime, engine| engine.upgrade_semantic_sha256(
            runtime,
            &source,
            &source_producer
        ))
        .unwrap(),
        expected
    );
    // A queued caller admitted before the pause must be rejected at dispatch.
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let actor = Arc::clone(&old);
    let blocker = std::thread::spawn(move || {
        actor.call(move |_, _| {
            entered_tx.send(()).map_err(|_| RuntimeError::Cancelled)?;
            release_rx
                .recv_timeout(Duration::from_secs(4))
                .map_err(|_| RuntimeError::Cancelled)?;
            Ok(())
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let mutated = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mutation = Arc::clone(&mutated);
    let actor = Arc::clone(&old);
    let queued = std::thread::spawn(move || {
        actor.call(move |_, _| {
            mutation.store(true, std::sync::atomic::Ordering::Release);
            Ok(())
        })
    });
    let wait = Instant::now();
    while old.pending_calls() == 0 && wait.elapsed() < Duration::from_secs(2) {
        std::thread::yield_now();
    }
    assert!(old.pending_calls() > 0);
    let actor = Arc::clone(&old);
    let (paused_tx, paused_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let pausing = std::thread::spawn(move || {
        let (pause, ()) = actor.pause_at_boundary(|_, _| Ok(())).unwrap();
        paused_tx.send(()).unwrap();
        resume_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(pause);
    });
    let wait = Instant::now();
    while !old.is_quiescent() && wait.elapsed() < Duration::from_secs(2) {
        std::thread::yield_now();
    }
    assert!(old.is_quiescent());
    release_tx.send(()).unwrap();
    blocker.join().unwrap().unwrap();
    assert!(matches!(queued.join().unwrap(), Err(RuntimeError::Busy)));
    paused_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(!mutated.load(std::sync::atomic::Ordering::Acquire));
    assert!(matches!(old.call(|_, _| Ok(())), Err(RuntimeError::Busy)));
    resume_tx.send(()).unwrap();
    pausing.join().unwrap();
    let source = test.source.clone();
    let source_producer = from.clone();
    let (pause, final_semantic) = old
        .pause_at_boundary(move |runtime, engine| {
            engine.upgrade_semantic_sha256(runtime, &source, &source_producer)
        })
        .unwrap();
    assert_eq!(final_semantic, expected);
    assert!(old.is_quiescent());
    assert!(matches!(old.call(|_, _| Ok(())), Err(RuntimeError::Busy)));
    drop(pause);
    assert!(!old.is_quiescent());
    old.call(|runtime, _| runtime.check_transport()).unwrap();
    let (pause, ()) = old.pause_at_boundary(|_, _| Ok(())).unwrap();
    assert!(pause.close_and_wait(Duration::from_millis(500)));
    assert!(!old.is_active());
    drop(old);
    // Fixture-only policy transition to exercise the reconstructed engine.
    // There is no selection-journal qualification or live-profile write here.
    test.write_settings(&test.target);
    let target = RuntimeActor::start_with_maintenance(
        replacement.runtime,
        replacement.engine,
        Engine::maintenance,
    )
    .unwrap();
    for (index, (id, old_snapshot, marker)) in scopes.into_iter().enumerate() {
        let old_origin = from.identity_sha256().to_owned();
        let new_origin = to.identity_sha256().to_owned();
        target.call(move |runtime,engine| {
            assert!(matches!(ask(engine,runtime,json!({"action":"explain","scope_id":id,"snapshot_id":old_snapshot})),Err(RuntimeError::ContextStale)));
            let historical = ask(engine,runtime,json!({"action":"history","scope_id":id}))?;
            assert!(historical["entries"].as_array().unwrap().iter().any(|v|v["producer"]["producer_sha256"]==old_origin));
            let result = ask(engine,runtime,json!({"action":"compile","scope_id":id,"query":"release evidence scoped marker latest"}))?;
            let text = result["brief"]["rendered"].as_str().unwrap();
            assert!(text.contains(&marker));
            assert!(!text.contains(if index==0 {"Scoped marker beta"} else {"Scoped marker alpha"}));
            assert_eq!(text.contains("Latest reviewed edit"),index==0);
            let history = ask(engine,runtime,json!({"action":"history","scope_id":id}))?;
            assert!(history["entries"].as_array().unwrap().iter().any(|v|v["producer"]["producer_sha256"]==new_origin));
            assert_eq!(ask(engine,runtime,json!({"action":"list_agents"}))?["agent_sessions"],json!([]));
            Ok(())
        }).unwrap();
    }
    assert!(target.close_and_wait(Duration::from_millis(500)));
    drop(target);
    let legacy = EvidenceCache::existing(&test.home).unwrap().unwrap();
    legacy.forget_all().unwrap();
    drop(legacy);
    assert_eq!(
        EvidenceGenerationStore::forget_existing(&test.home).unwrap(),
        1
    );
    println!(
        "CIGAR_NATIVE_ENGINE_UPGRADE_PROOF={}",
        json!({"schema":"guard-cigar-native-engine-upgrade-proof.v1",
        "scope":"local-macos-arm64-final0141-v1-enrolled-source-test-qualified-target-not-b47380",
        "logical_scopes_preserved":2,"cross_app_notes_combined":false,"source_actor_served_during_build":true,"bounded_quiescence_blocks_new_calls":true,"queued_preboundary_mutation_refused":true,"aborted_boundary_resumed_source":true,"shutdown_never_resumed_source":true,
        "source_calls_during_build":samples,"max_old_call_us":max_old_call_us,
        "normal_reads_preserve_semantic_snapshot":true,"source_manifest_unchanged_by_preparation_and_reads":true,"reviewed_edit_invalidated_earlier_capture":true,
        "cancelled_preimport_copy_removed":true,"latest_reviewed_edit_preserved":true,"changed_source_cutover_refused":true,
        "original_preferences_unchanged_during_preparation":true,"historical_origin_preserved":true,
        "new_history_uses_target_origin":true,"old_contexts_restored":false,"old_agent_sessions_restored":false,
        "source_producer":from.identity_sha256(),"target_producer":to.identity_sha256(),
        "selection_journal_exercised":false,"raw_sdk_checkpoint_copied":false,"authority_restored":false})
    );
}
