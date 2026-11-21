//! Policy-allowed launches use no consent row, key or billing authority.
use super::*;
use guard_contracts::{NativeBashAuthorizationKindV1 as Kind, NativeBashAuthorizationV1};
#[path = "bash_invocation_tests.rs"]
mod invocation_tests;

fn quiet(
    request: &NativeBashCaptureV1,
    envelope: &GuardHookEnvelopeV2,
) -> NativeBashExecuteRequestV1 {
    let store_path = Path::new(&request.guard_home).join("guard.db");
    let connection = Connection::open(&store_path).unwrap();
    let initialized: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='policy_decisions')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    if !initialized {
        crate::policy_decision_lookup_op::tests::seed_store(&store_path);
    }
    NativeBashExecuteRequestV1 {
        tool_call_id: None,
        schema: NATIVE_BASH_EXECUTE_REQUEST_SCHEMA.into(),
        request_id: "quiet-request-0001".into(),
        operation_id: "quiet-operation-0001".into(),
        capture: request.clone(),
        envelope: envelope.clone(),
        timeout_ms: 5000,
        authorization: NativeBashAuthorizationV1::CurrentPolicy {
            store_path: store_path.to_str().unwrap().into(),
        },
    }
}

fn execution_floor(store: &PolicySnapshotStore, envelope: &mut GuardHookEnvelopeV2, action: &str) {
    let mut snapshot = store.current_snapshot().unwrap();
    snapshot.generation += 1;
    snapshot
        .effective_policy
        .risk_actions
        .insert("execution".into(), action.into());
    snapshot.config_digest =
        guard_policy_snapshot::config_digest(&snapshot.effective_policy).unwrap();
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, &[37u8; 32]).unwrap();
    store
        .push(&json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":snapshot}))
        .unwrap();
    envelope.policy_generation = snapshot.generation;
    envelope.policy_snapshot = serde_json::to_value(snapshot).unwrap();
}

#[test]
fn bash_realistic_dry_report_runs_ten_times_across_resident_restarts_without_consent() {
    let (_root, request) = tests::fixture();
    let (mut store, envelope) = policy_store(&request);
    let mut execution = quiet(&request, &envelope);
    for iteration in 0..10 {
        execution.operation_id = format!("quiet-operation-{iteration:04}");
        let result = execute(&execution, &store);
        assert_eq!(result.status, "ok", "{}", result.code);
        assert!(!result.grant_claimed && result.dispatch_acknowledged && !result.replayed);
        assert_eq!(result.operation.unwrap().authorization, Kind::CurrentPolicy);
        assert_eq!(result.payload.unwrap().exit_code, Some(0));
        drop(store);
        store = PolicySnapshotStore::new(Path::new(&request.guard_home), &"a".repeat(64)).unwrap();
    }
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    assert!(std::fs::read_to_string(&report)
        .unwrap()
        .contains("beta\tlocal metadata"));
    let connection = Connection::open(execution.authorization.store_path()).unwrap();
    let consent_rows: i64 = connection.query_row(
        "SELECT (SELECT count(*) FROM guard_local_once_approvals) + (SELECT count(*) FROM policy_decisions)",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(
        consent_rows, 0,
        "quiet launches must not create or need consent rows"
    );
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM guard_bash_operations", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        10
    );
    // Recover the first actual operation after ten independent executions.
    execution.operation_id = "quiet-operation-0000".into();
    execution.request_id = "quiet-reissued-request".into();
    std::fs::write(&report, "preserve recovered report").unwrap();
    let replay = execute(&execution, &store);
    assert_eq!(replay.status, "recorded");
    assert!(replay.replayed && !replay.grant_claimed && replay.dispatch_acknowledged);
    assert!(replay.payload.is_none());
    assert_eq!(
        std::fs::read_to_string(report).unwrap(),
        "preserve recovered report"
    );
}

#[test]
fn bash_explicit_ask_still_needs_consent_and_saved_once_authorizes_the_real_launch() {
    let (_root, request) = tests::fixture();
    let (store, mut envelope) = policy_store(&request);
    execution_floor(&store, &mut envelope, "review");
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    let unapproved = quiet(&request, &envelope);
    let result = execute(&unapproved, &store);
    assert_eq!(result.code, "native_bash_consent_required");
    assert!(!result.grant_claimed && !result.dispatch_acknowledged && result.operation.is_none());
    assert!(!Path::new(&request.home_dir)
        .join("maintenance-report.tsv")
        .exists());
    let lineage = result.review_lineage.unwrap();
    assert_eq!(lineage.operation_id, unapproved.operation_id);
    let mut approved = execution(request, envelope, claim);
    approved.operation_id = unapproved.operation_id;
    let result = execute(&approved, &store);
    assert!(result.grant_claimed && result.dispatch_acknowledged);
    assert_eq!(result.operation.unwrap().authorization, Kind::SavedGrant);
    assert_eq!(result.payload.unwrap().exit_code, Some(0));
}

#[test]
fn bash_current_deny_stops_the_quiet_route_before_any_report_effect() {
    let (_root, request) = tests::fixture();
    let (store, mut envelope) = policy_store(&request);
    execution_floor(&store, &mut envelope, "block");
    let execution = quiet(&request, &envelope);
    let result = execute(&execution, &store);
    assert_ne!(result.status, "ok");
    assert!(!result.grant_claimed && !result.dispatch_acknowledged);
    assert!(!Path::new(&request.home_dir)
        .join("maintenance-report.tsv")
        .exists());
}

#[test]
fn bash_execution_authorization_is_explicit_and_does_not_default_from_legacy_or_unknown_fields() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let execution = quiet(&request, &envelope);
    let mut wire = serde_json::to_value(&execution).unwrap();
    wire.as_object_mut().unwrap().remove("authorization");
    wire["claim"] = json!({"decisions":[]});
    assert_eq!(
        dispatch("native_bash_execute", wire, Some(&store)).unwrap_err(),
        "native_request_schema_unsupported"
    );
    for authorization in [
        json!({"kind":"auto"}),
        json!({"kind":"current_policy", "store_path":execution.authorization.store_path(),"claim":{}}),
    ] {
        let mut wire = serde_json::to_value(&execution).unwrap();
        wire["authorization"] = authorization;
        assert_eq!(
            dispatch("native_bash_execute", wire, Some(&store)).unwrap_err(),
            "native_request_schema_unsupported"
        );
    }
    assert!(!Path::new(&request.home_dir)
        .join("maintenance-report.tsv")
        .exists());
}
