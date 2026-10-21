use super::*;
use serde_json::json;

fn prepared_reply() -> Value {
    json!({"artifact_id":NATIVE_BASH_ARTIFACT_ID,
        "artifact_hash":"guard-approval-context:v1:fixture", "assessment":[],
        "consent_required":true,"review":{"decision":{},"receipt":{}},
        "subject":{"schema":"guard.bash-subject.v1",
            "execution_assurance":"macos-readonly-root-framed-outputs-v1",
            "context":{"host":"omp-input-rewrite-v1"},"package_bindings":[{"state":"declared"}]}})
}

fn completed_reply() -> (Value, Value) {
    let completion = json!({"exit_code":7,"stdout":"result\n","stderr":"warning\n",
        "output_limited":false,"timed_out":false,"cancelled":false});
    let mut summary = completion.clone();
    summary.as_object_mut().unwrap().remove("stdout");
    summary.as_object_mut().unwrap().remove("stderr");
    summary["stdout_sha256"] = json!("a".repeat(64));
    summary["stderr_sha256"] = json!("b".repeat(64));
    (
        json!({"schema":"guard-native-bash-execute-result.v1","request_id":"fixture",
        "request_sha256":"sha256:fixture","status":"ok","code":"ok",
        "grant_claimed":false,"dispatch_acknowledged":true,"replayed":false,
        "payload":completion,"review_lineage":null,"operation":{
            "operation_id":"stable-operation-1","artifact_hash":"guard-approval-context:v1:fixture",
            "authorization":"current_policy","state":"completed",
            "dispatch_acknowledged":true,"completion":summary}}),
        json!({"operation_id":"stable-operation-1","authorization":{"kind":"current_policy"}}),
    )
}

#[test]
fn native_bash_reply_prepared_requires_native_consent_and_assurance() {
    let good = prepared_reply();
    assert!(prepared(&good));
    for (pointer, invalid) in [
        ("/consent_required", json!(0)),
        ("/artifact_id", json!("package-request")),
        ("/subject/execution_assurance", json!("hash-only")),
        ("/review/receipt", json!([])),
        ("/assessment", json!({})),
    ] {
        let mut changed = good.clone();
        *changed.pointer_mut(pointer).unwrap() = invalid;
        assert!(!prepared(&changed), "{pointer}");
    }
    let mut extra = good;
    extra["can_run_once"] = json!(true);
    assert!(!prepared(&extra));
}

#[test]
fn native_bash_reply_dependency_assessment_cannot_replace_consent() {
    let mut good = prepared_reply();
    good["dependency_artifact"] = json!({"artifact_id":format!("omp:project:package-request:{}","a".repeat(64)),
        "artifact_type":"package_request","harness":"omp",
        "metadata":{"assessment_only":true,"captured_subject_sha256":"a".repeat(64)}});
    assert!(prepared(&good));
    for (pointer, invalid) in [
        ("/dependency_artifact", Value::Null),
        ("/dependency_artifact/metadata/assessment_only", json!(1)),
        ("/dependency_artifact/harness", json!("pi")),
        (
            "/dependency_artifact/metadata/captured_subject_sha256",
            json!("b".repeat(64)),
        ),
        ("/subject/package_bindings", json!([])),
    ] {
        let mut changed = good.clone();
        *changed.pointer_mut(pointer).unwrap() = invalid;
        assert!(!prepared(&changed), "{pointer}");
    }
}

#[test]
fn native_bash_reply_nonzero_completion_is_execution_but_not_success() {
    let (good, request) = completed_reply();
    assert!(executed(&good, &request));
    for (pointer, invalid) in [
        ("/payload/exit_code", json!(true)),
        ("/payload/timed_out", json!(0)),
        ("/operation/completion/stdout_sha256", json!("not-a-digest")),
        ("/operation/operation_id", json!("different-operation")),
        ("/operation/authorization", json!("saved_grant")),
        ("/operation/state", json!("dispatched")),
        ("/dispatch_acknowledged", json!(false)),
        ("/replayed", json!(true)),
    ] {
        let mut changed = good.clone();
        *changed.pointer_mut(pointer).unwrap() = invalid;
        assert!(!executed(&changed, &request), "{pointer}");
    }
}

#[test]
fn native_bash_reply_replay_requires_authenticated_summary_without_output() {
    let (mut reply, request) = completed_reply();
    reply["status"] = json!("recorded");
    reply["code"] = json!("native_bash_already_completed_output_not_retained");
    reply["replayed"] = json!(true);
    reply["payload"] = Value::Null;
    assert!(executed(&reply, &request));
    reply["grant_claimed"] = json!(true);
    assert!(!executed(&reply, &request));
    reply["grant_claimed"] = json!(false);
    reply["payload"] = completed_reply().0["payload"].clone();
    assert!(!executed(&reply, &request));
}

#[test]
fn native_bash_reply_pending_lineage_never_acknowledges_or_spends_consent() {
    let review = json!({"schema":"guard-native-bash-review-lineage.v1","lineage_id":"c".repeat(64),
        "operation_id":"stable-operation-1","artifact_hash":"guard-approval-context:v1:fixture",
        "created_at_ms":100,"expires_at_ms":86_400_100});
    assert!(lineage(&review));
    let (mut reply, request) = completed_reply();
    reply["status"] = json!("error");
    reply["code"] = json!("native_bash_consent_required");
    reply["payload"] = Value::Null;
    reply["operation"] = Value::Null;
    reply["dispatch_acknowledged"] = json!(false);
    reply["review_lineage"] = review;
    assert!(executed(&reply, &request));
    for key in ["grant_claimed", "dispatch_acknowledged", "replayed"] {
        let mut changed = reply.clone();
        changed[key] = json!(true);
        assert!(!executed(&changed, &request), "{key}");
    }
    reply["review_lineage"]["expires_at_ms"] = json!(86_400_101);
    assert!(!executed(&reply, &request));
}

#[test]
fn native_bash_reply_tool_invocation_id_is_distinct_from_operation_permission() {
    let (mut reply, mut request) = completed_reply();
    request["tool_call_id"] = json!("sdk-call");
    assert!(!executed(&reply, &request));
    reply["operation"]["operation_id"] = json!(format!("bash-invocation:{}", "a".repeat(64)));
    assert!(executed(&reply, &request));
    assert!(!validate("allow", &reply, &request));
}

#[test]
fn native_bash_reply_context_transport_keeps_negative_answers_and_checks_ownership() {
    use guard_contracts::{
        ContextDigestKindV1, ContextDigestRequestV1, ContextDigestResultV1,
        CONTEXT_DIGEST_REQUEST_SCHEMA,
    };
    for (material, expected) in [(prepared_reply(), true), (Value::Null, false)] {
        let request = ContextDigestRequestV1 {
            schema: CONTEXT_DIGEST_REQUEST_SCHEMA.into(),
            request_id: "reply-validation".into(),
            kind: ContextDigestKindV1::NativeBashReplyValidation {
                reply_kind: "prepared".into(),
                material,
                request: Value::Null,
            },
        };
        let bytes = crate::context_digest::evaluate_context_digest_request(&request).unwrap();
        let result: ContextDigestResultV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result.status, "ok");
        assert_eq!(result.native_bash_reply_valid, Some(expected));
        let mut payload: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(crate::context_digest_result_check::check_result(
            "native_bash_reply_validation",
            &payload
        )
        .is_ok());
        assert!(
            crate::context_digest_result_check::check_result("canonical_sha256", &payload).is_err()
        );
        payload["native_bash_reply_valid"] = json!(1);
        assert!(crate::context_digest_result_check::check_result(
            "native_bash_reply_validation",
            &payload
        )
        .is_err());
    }
}

#[test]
fn native_bash_reply_owned_client_binds_large_completion_without_an_extra_rpc() {
    let (mut reply, mut request) = completed_reply();
    request["request_id"] = json!("fixture");
    reply["request_sha256"] = json!(crate::package_authority_op::request_digest_with_limit(
        &request,
        guard_contracts::NATIVE_BASH_LAUNCH_MAX_REQUEST_BYTES,
    )
    .unwrap());
    // The owning client validates locally; it does not copy output into the
    // smaller context-digest request frame to interpret completion semantics.
    reply["payload"]["stdout"] = json!("x".repeat(2 * 1024 * 1024));
    assert!(bound_execution(&reply, &request));
    for (pointer, invalid) in [
        ("/request_sha256", json!("sha256:foreign")),
        ("/request_id", json!("different-request")),
        ("/schema", json!("guard-native-bash-prepare-result.v1")),
        ("/status", json!("allowed")),
        ("/code", json!("recorded")),
    ] {
        let mut changed = reply.clone();
        *changed.pointer_mut(pointer).unwrap() = invalid;
        assert!(!bound_execution(&changed, &request), "{pointer}");
    }
}
