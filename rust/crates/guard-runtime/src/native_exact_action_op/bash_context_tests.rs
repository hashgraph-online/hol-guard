//! Actual native owning executor + approved SDK, with disposable trusted
//! consent setup. This does not establish installed or external app delivery.
use super::*;
use crate::context_assistance_service::Check;
use crate::policy_store::context_assistance_registry;
use guard_context_assistance::ContextAssistanceConfig;
use sha2::Digest;
use std::time::{Duration, Instant};

fn fixture() -> (tempfile::TempDir, NativeBashCaptureV1) {
    let (root, request) = tests::fixture();
    std::fs::write(
        Path::new(&request.workspace).join("maintenance.sh"),
        ": > \"$HOME/maintenance-report.tsv\"\nprintf 'cigar-native-owner\\n' >> \"$HOME/maintenance-report.tsv\"\n",
    )
    .unwrap();
    (root, request)
}

fn activate(request: &NativeBashCaptureV1, store: &PolicySnapshotStore) {
    let selection: Value = serde_json::from_slice(
        &std::fs::read(std::env::var_os("GUARD_CIGAR_TEST_SELECTION").expect("explicit selection"))
            .unwrap(),
    )
    .unwrap();
    let approval: Value = serde_json::from_slice(
        &std::fs::read(std::env::var_os("GUARD_CIGAR_TEST_APPROVAL").expect("explicit approval"))
            .unwrap(),
    )
    .unwrap();
    let enrolled: Value = serde_json::from_slice(
        &context_assistance_registry::run_enroll_command(
            json!({"schema":"guard-cigar-enroll-local.v1","guard_home":request.guard_home,
            "runtime_id":"execution-candidate","local_candidate_approved":true,
            "source_revision":"b47380e5a5cbeaaad5a61cab3372e9e67368732f",
            "selection":selection,"approval":approval})
            .to_string()
            .as_bytes(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(enrolled["ok"], true);
    let mut config = ContextAssistanceConfig {
        enabled: true,
        runtime_id: "execution-candidate".into(),
        ..Default::default()
    };
    config.features.execution_context = true;
    let saved: Value = serde_json::from_slice(
        &crate::guard_config_update::run_command(
            json!({"schema":"guard-config-update.v1","guard_home":request.guard_home,
            "kind":"settings","value_text":json!({"context_assistance":config}).to_string()})
            .to_string()
            .as_bytes(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(saved["ok"], true);
    let home = Path::new(&request.guard_home);
    let service = store.context_assistance();
    service
        .configure(crate::guard_config_load::context_assistance_config(home).unwrap())
        .unwrap();
    service.schedule(Check::Activate, home.to_owned()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let status = service.status().unwrap();
        if status["job"].is_null() {
            assert_eq!(status["effective_enabled"], true, "{status}");
            assert_eq!(
                status["runtime"]["execution_handoff_verified"], true,
                "{status}"
            );
            assert_eq!(status["execution_ready"], true, "{status}");
            assert_eq!(status["runtime"]["interpreter"]["version"][1], 14);
            assert_eq!(
                status["runtime"]["worker_fingerprint"],
                approval["worker_sha256"]
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "execution activation did not finish"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        service
            .agent(
                home,
                store,
                crate::context_assistance_agents::Input::Discover {}
            )
            .unwrap()["result"]["available"],
        false
    );
}

fn grant(request: &NativeBashCaptureV1, store: &PolicySnapshotStore) -> String {
    let unsupported = store
        .context_assistance()
        .workspace(
            Path::new(&request.guard_home),
            store,
            json!({"action":"grant","workspace":request.workspace,"app":"codex","sources":[]}),
            true,
            true,
        )
        .unwrap_err();
    assert_eq!(
        unsupported, "native_context_assistance_context_scope_denied",
        "execution consent cannot enable an unqualified app or MCP access"
    );
    let result = store.context_assistance().workspace(Path::new(&request.guard_home), store,
        json!({"action":"grant","workspace":request.workspace,"app":request.harness,"sources":[]}), true, true).unwrap();
    result["result"]["scope_id"].as_str().unwrap().into()
}
fn observations(store: &PolicySnapshotStore) -> Vec<Value> {
    store.context_assistance().status().unwrap()["execution_observations"]
        .as_array()
        .unwrap()
        .clone()
}
fn assert_applied(store: &PolicySnapshotStore) -> Value {
    let values = observations(store);
    let observed = values.first().expect("actual executor observation").clone();
    assert_eq!(observed["phase"], "completed", "{observed}");
    assert_eq!(observed["association_applied"], true, "{observed}");
    assert_eq!(observed["native_dispatch_acknowledged"], true);
    assert_eq!(observed["approval_grant"], false);
    assert_eq!(observed["send_boundary_atomicity"], false);
    assert_eq!(
        observed["source_qualification"],
        "captured_native_facts_only"
    );
    assert!(observed["native_barrier_checked_at_ms"].is_u64());
    for forbidden in [
        "ticket",
        "submission_id",
        "intent_digest",
        "command",
        "environment",
        "workspace",
    ] {
        assert!(observed.get(forbidden).is_none());
    }
    observed
}

#[test]
#[ignore = "requires explicitly approved actual CPython 3.14/CIGAR 0.14.1"]
fn actual_cigar_native_executor_preserves_once_replay_and_scope_revocation() {
    let (_root, request) = fixture();
    let (store, envelope) = policy_store(&request);
    let before = bash_grant::binding(
        &capture_for_launch(&request, &store.current_admitted_snapshot().unwrap())
            .unwrap()
            .subject,
        &store.current_admitted_snapshot().unwrap(),
    )
    .unwrap();
    activate(&request, &store);
    let scope = grant(&request, &store);
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    assert_eq!(
        claim.decisions[0]["artifact_hash"], before,
        "context preference cannot change approval identity"
    );
    let operation = "cigar-once-native-operation-0001";
    let output = run_operation(&request, &store, &envelope, &claim, operation).unwrap();
    assert_eq!(output.exit_code, Some(0));
    assert_eq!(
        std::fs::read_to_string(Path::new(&request.home_dir).join("maintenance-report.tsv"))
            .unwrap(),
        "cigar-native-owner\n"
    );
    let first = assert_applied(&store);
    assert_eq!(first["scope_id"], scope);
    let reference = format!(
        "{:x}",
        sha2::Sha256::digest(serde_json::to_vec(&json!([operation, before])).unwrap())
    );
    assert_eq!(first["execution_reference"], reference);
    assert!(run_operation(&request, &store, &envelope, &claim, operation).is_err());
    let repeated = observations(&store);
    assert_eq!(repeated[0]["phase"], "not_dispatched");
    assert_eq!(repeated[0]["association_applied"], false);
    assert_eq!(repeated[0]["reason"], "native_operation_already_recorded");
    let connection = Connection::open(&claim.store_path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "select count(*) from guard_events where event_name='approval.local_once_applied'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    store
        .context_assistance()
        .workspace(
            Path::new(&request.guard_home),
            &store,
            json!({"action":"revoke","scope_id":scope}),
            true,
            false,
        )
        .unwrap();
    assert!(observations(&store).is_empty());
    store.context_assistance().stop().unwrap();
    assert!(observations(&store).is_empty());
    println!("GUARD_CIGAR_NATIVE_EXECUTOR_ONCE={{\"status\":\"passed\",\"real_native_launch\":true,\"actual_SDK\":true,\"installed\":false,\"external_harness\":false}}");
}

#[test]
#[ignore = "requires explicitly approved actual CPython 3.14/CIGAR 0.14.1"]
fn actual_cigar_native_executor_preserves_always_and_native_fallback_after_stop() {
    let (_root, request) = fixture();
    let (store, envelope) = policy_store(&request);
    activate(&request, &store);
    let claim = persistent(&request, &store);
    assert_eq!(
        run_operation(
            &request,
            &store,
            &envelope,
            &claim,
            "cigar-always-native-without-grant"
        )
        .unwrap()
        .exit_code,
        Some(0)
    );
    assert!(observations(&store).is_empty());
    let scope = grant(&request, &store);
    for id in [
        "cigar-always-native-operation-0001",
        "cigar-always-native-operation-0002",
    ] {
        assert_eq!(
            run_operation(&request, &store, &envelope, &claim, id)
                .unwrap()
                .exit_code,
            Some(0)
        );
        assert_applied(&store);
    }
    let entry = Path::new(&request.workspace).join("maintenance.sh");
    let original = std::fs::read(&entry).unwrap();
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    let previous_output = std::fs::read(&report).unwrap();
    std::fs::write(&entry, ": > \"$HOME/maintenance-report.tsv\"\nprintf changed >> \"$HOME/maintenance-report.tsv\"\n").unwrap();
    assert!(run_operation(
        &request,
        &store,
        &envelope,
        &claim,
        "cigar-always-native-changed-source"
    )
    .is_err());
    let refused = observations(&store);
    assert_eq!(refused[0]["phase"], "not_dispatched");
    assert_eq!(
        refused[0]["association_applied"], false,
        "even an actual SDK precondition cannot replace native approval"
    );
    assert_eq!(std::fs::read(&report).unwrap(), previous_output);
    std::fs::write(entry, original).unwrap();
    store
        .context_assistance()
        .workspace(
            Path::new(&request.guard_home),
            &store,
            json!({"action":"revoke","scope_id":scope}),
            true,
            false,
        )
        .unwrap();
    assert_eq!(
        run_operation(
            &request,
            &store,
            &envelope,
            &claim,
            "cigar-always-native-after-revoke"
        )
        .unwrap()
        .exit_code,
        Some(0)
    );
    assert!(observations(&store).is_empty());
    store.context_assistance().stop().unwrap();
    assert_eq!(
        run_operation(
            &request,
            &store,
            &envelope,
            &claim,
            "cigar-always-native-operation-0003"
        )
        .unwrap()
        .exit_code,
        Some(0)
    );
    assert!(observations(&store).is_empty());
    let connection = Connection::open(&claim.store_path).unwrap();
    assert_eq!(
        connection
            .query_row("select count(*) from policy_decisions", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(connection.query_row("select count(*) from guard_events where event_name='approval.policy_reuse_applied'", [], |r| r.get::<_, i64>(0)).unwrap(), 5);
    println!("GUARD_CIGAR_NATIVE_EXECUTOR_ALWAYS={{\"status\":\"passed\",\"saved_reuse\":5,\"native_fallback_without_scope_after_revoke_and_Stop\":true,\"installed\":false,\"external_harness\":false}}");
}

#[test]
#[ignore = "requires explicitly approved actual CPython 3.14/CIGAR 0.14.1"]
fn actual_cigar_native_executor_sdk_failure_after_take_does_not_veto_once() {
    use std::sync::atomic::Ordering;
    let (_root, request) = fixture();
    let (store, envelope) = policy_store(&request);
    activate(&request, &store);
    grant(&request, &store);
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    let interrupted = std::sync::Arc::new(AtomicBool::new(false));
    let marker = std::sync::Arc::clone(&interrupted);
    store
        .context_assistance()
        .set_execution_test_hook(Box::new(move |store| {
            // This point is reached only after the actual successful SDK take,
            // before the executor reacquires its policy fence or spends consent.
            marker.store(true, Ordering::Release);
            store
                .context_assistance()
                .interrupt_execution_runtime_for_test();
        }));
    let output = run_operation(
        &request,
        &store,
        &envelope,
        &claim,
        "cigar-native-sdk-fault-after-take",
    )
    .unwrap();
    assert!(
        interrupted.load(Ordering::Acquire),
        "actual SDK handoff was not reached"
    );
    assert_eq!(output.exit_code, Some(0));
    assert_eq!(
        std::fs::read_to_string(Path::new(&request.home_dir).join("maintenance-report.tsv"))
            .unwrap(),
        "cigar-native-owner\n"
    );
    let status = store.context_assistance().status().unwrap();
    assert_eq!(status["effective_enabled"], false);
    assert!(observations(&store)
        .iter()
        .all(|event| event["association_applied"] == false));
    let connection = Connection::open(&claim.store_path).unwrap();
    assert_eq!(
        connection
            .query_row(
                "select count(*) from guard_events where event_name='approval.local_once_applied'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    store.context_assistance().stop().unwrap();
    println!("GUARD_CIGAR_NATIVE_EXECUTOR_FAULT={{\"status\":\"passed\",\"SDK_interrupted_after_actual_take\":true,\"native_once_launch_completed\":true,\"installed\":false}}");
}

#[test]
#[ignore = "requires explicitly approved actual CPython 3.14/CIGAR 0.14.1"]
fn actual_cigar_native_executor_scope_revoked_after_take_does_not_veto_once() {
    use std::sync::atomic::Ordering;
    let (_root, request) = fixture();
    let (store, envelope) = policy_store(&request);
    activate(&request, &store);
    let scope = grant(&request, &store);
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    let revoked = std::sync::Arc::new(AtomicBool::new(false));
    let marker = std::sync::Arc::clone(&revoked);
    let home = PathBuf::from(&request.guard_home);
    store
        .context_assistance()
        .set_execution_test_hook(Box::new(move |store| {
            store
                .context_assistance()
                .workspace(
                    &home,
                    store,
                    json!({"action":"revoke","scope_id":scope}),
                    true,
                    false,
                )
                .unwrap();
            marker.store(true, Ordering::Release);
        }));
    assert_eq!(
        run_operation(
            &request,
            &store,
            &envelope,
            &claim,
            "cigar-native-scope-revoked-after-take"
        )
        .unwrap()
        .exit_code,
        Some(0)
    );
    assert!(
        revoked.load(Ordering::Acquire),
        "revocation must follow an actual successful SDK take"
    );
    assert!(
        observations(&store).is_empty(),
        "revoked observations cannot reappear on completion"
    );
    assert_eq!(
        store.context_assistance().status().unwrap()["effective_enabled"],
        true
    );
    store.context_assistance().stop().unwrap();
    println!("GUARD_CIGAR_NATIVE_EXECUTOR_REVOKE={{\"status\":\"passed\",\"scope_revoked_after_actual_take\":true,\"native_once_launch_completed\":true,\"installed\":false}}");
}
