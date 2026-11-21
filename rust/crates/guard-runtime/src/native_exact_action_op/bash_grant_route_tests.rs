//! Resident dispatch proof, separate from the authenticated socket/host lanes.
use super::*;
#[path = "bash_grant_cancel_tests.rs"]
mod cancel_tests;
#[path = "bash_quiet_tests.rs"]
mod quiet_tests;
#[path = "bash_transport_tests.rs"]
mod transport_tests;
use guard_contracts::{
    NativeBashExecuteRequestV1, NativeBashExecuteResultV1, NativeBashPrepareRequestV1,
    NativeBashPrepareResultV1, NATIVE_BASH_EXECUTE_REQUEST_SCHEMA,
    NATIVE_BASH_PREPARE_REQUEST_SCHEMA,
};

fn dispatch(
    operation: &str,
    request: Value,
    store: Option<&PolicySnapshotStore>,
) -> std::result::Result<Vec<u8>, String> {
    crate::resident_protocol::evaluate_resident_bytes(
        &serde_json::to_vec(&json!({"operation":operation,"request":request})).unwrap(),
        store,
    )
}

fn prepare(
    request: &NativeBashCaptureV1,
    envelope: &GuardHookEnvelopeV2,
) -> NativeBashPrepareRequestV1 {
    NativeBashPrepareRequestV1 {
        schema: NATIVE_BASH_PREPARE_REQUEST_SCHEMA.into(),
        request_id: "prepare-bash-test".into(),
        capture: request.clone(),
        envelope: envelope.clone(),
        budget_ms: 5000,
    }
}

fn execution(
    request: NativeBashCaptureV1,
    envelope: GuardHookEnvelopeV2,
    claim: ClaimApprovalReuseDecisionsRequestV1,
) -> NativeBashExecuteRequestV1 {
    NativeBashExecuteRequestV1 {
        tool_call_id: None,
        schema: NATIVE_BASH_EXECUTE_REQUEST_SCHEMA.into(),
        request_id: "execute-bash-test".into(),
        operation_id: "execute-bash-operation-test".into(),
        capture: request,
        envelope,
        authorization: guard_contracts::NativeBashAuthorizationV1::SavedGrant {
            claim: Box::new(claim),
        },
        timeout_ms: 5000,
    }
}

fn saved_claim(
    request: &mut NativeBashExecuteRequestV1,
) -> &mut ClaimApprovalReuseDecisionsRequestV1 {
    match &mut request.authorization {
        guard_contracts::NativeBashAuthorizationV1::SavedGrant { claim } => claim,
        _ => panic!("expected saved authorization"),
    }
}

fn execute(
    request: &NativeBashExecuteRequestV1,
    store: &PolicySnapshotStore,
) -> NativeBashExecuteResultV1 {
    if let guard_contracts::NativeBashAuthorizationV1::SavedGrant { claim } = &request.authorization
    {
        seed_once_review(&request.capture, store, claim, &request.operation_id);
    }
    serde_json::from_slice(
        &dispatch(
            "native_bash_execute",
            serde_json::to_value(request).unwrap(),
            Some(store),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn bash_resident_prepare_does_not_claim_and_execute_acknowledges_one_real_launch() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let preparation = prepare(&request, &envelope);
    let prepared: NativeBashPrepareResultV1 = serde_json::from_slice(
        &dispatch(
            "native_bash_prepare",
            serde_json::to_value(&preparation).unwrap(),
            Some(&store),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(prepared.status, "ok");
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    assert!(!report.exists());
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    let prepared = prepared.payload.unwrap();
    assert_eq!(prepared.artifact_hash, claim.decisions[0]["artifact_hash"]);
    assert_eq!(prepared.artifact_id, claim.decisions[0]["artifact_id"]);
    assert!(!prepared.assessment.is_empty());
    let execution = execution(request, envelope, claim);
    let first = execute(&execution, &store);
    assert_eq!(first.status, "ok");
    assert!(first.grant_claimed && first.dispatch_acknowledged);
    let output = first.payload.unwrap();
    assert_eq!(output.exit_code, Some(0));
    assert!(!output.timed_out && !output.cancelled && !output.output_limited);
    let reviewed = std::fs::read(&report).unwrap();
    let second = execute(&execution, &store);
    assert_eq!(second.status, "recorded");
    assert!(second.grant_claimed && second.dispatch_acknowledged && second.replayed);
    assert!(second.operation.unwrap().completion.is_some());
    assert!(second.payload.is_none());
    assert_eq!(std::fs::read(report).unwrap(), reviewed);
}

#[test]
fn bash_resident_routes_require_current_store_scope_and_known_schemas() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let mut prepare = prepare(&request, &envelope);
    let wire = serde_json::to_value(&prepare).unwrap();
    assert_eq!(
        dispatch("native_bash_prepare", wire.clone(), None).unwrap_err(),
        "native_policy_snapshot_unavailable"
    );
    prepare.capture.guard_home = request.home_dir.clone();
    assert_eq!(
        dispatch(
            "native_bash_prepare",
            serde_json::to_value(&prepare).unwrap(),
            Some(&store)
        )
        .unwrap_err(),
        "native_guard_home_mismatch"
    );
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    let mut execution = execution(request.clone(), envelope.clone(), claim);
    let mut missing_operation = serde_json::to_value(&execution).unwrap();
    missing_operation
        .as_object_mut()
        .unwrap()
        .remove("operation_id");
    assert_eq!(
        dispatch("native_bash_execute", missing_operation, Some(&store)).unwrap_err(),
        "native_request_schema_unsupported"
    );
    let operation_id = execution.operation_id.clone();
    for invalid in ["", "too-short", "operation with spaces-0001"] {
        execution.operation_id = invalid.into();
        let refused = execute(&execution, &store);
        assert!(!refused.grant_claimed && refused.operation.is_none());
    }
    execution.operation_id = operation_id;
    let mut unknown = serde_json::to_value(&execution).unwrap();
    unknown["caller_subject"] = json!({"permission":"allow"});
    assert_eq!(
        dispatch("native_bash_execute", unknown, Some(&store)).unwrap_err(),
        "native_request_schema_unsupported"
    );
    execution.schema = "guard-native-bash-execute-request.v99".into();
    assert!(!execute(&execution, &store).grant_claimed);
    execution.schema = NATIVE_BASH_EXECUTE_REQUEST_SCHEMA.into();
    execution.envelope.schema = "guard-hook-envelope.v99".into();
    assert!(!execute(&execution, &store).grant_claimed);
    execution.envelope = envelope;
    let original = saved_claim(&mut execution).store_path.clone();
    saved_claim(&mut execution).store_path = Path::new(&request.home_dir)
        .join("guard.db")
        .to_str()
        .unwrap()
        .into();
    assert_eq!(
        dispatch(
            "native_bash_execute",
            serde_json::to_value(&execution).unwrap(),
            Some(&store)
        )
        .unwrap_err(),
        "native_guard_home_mismatch"
    );
    saved_claim(&mut execution).store_path = original;
    assert_eq!(
        execute(&execution, &store).payload.unwrap().exit_code,
        Some(0)
    );
}

#[test]
fn bash_resident_reply_distinguishes_dispatch_from_program_success() {
    let (_root, request) = tests::fixture();
    std::fs::write(
        Path::new(&request.cwd).join("maintenance.sh"),
        "printf reviewed; false\n",
    )
    .unwrap();
    let (store, envelope) = policy_store(&request);
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    let result = execute(&execution(request, envelope, claim), &store);
    assert_eq!(result.status, "ok", "the owner delivered a result");
    assert!(result.grant_claimed && result.dispatch_acknowledged);
    let output = result.payload.unwrap();
    assert_eq!(
        output.exit_code,
        Some(1),
        "dispatch is not execution success"
    );
    assert_eq!(output.stdout, "reviewed");
}
