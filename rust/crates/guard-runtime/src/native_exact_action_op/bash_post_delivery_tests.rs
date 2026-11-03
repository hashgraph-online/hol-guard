//! Real owner dispatch and authenticated journal, with synthetic post payloads.
//! End-to-end host result delivery is qualified separately by the SDK/Gauntlet.
use super::*;
use crate::bash_post_delivery::{verify, VerifiedBashDelivery};
use crate::policy_enforcement::{apply_post_tool_policy_with_delivery, AdmittedPolicySnapshot};
use guard_contracts::{GuardHookPayloadKindV2, HookReviewResponseV1, NativeHookRequestV1};

fn post(execution: &NativeBashExecuteRequestV1, exit: i32) -> NativeHookRequestV1 {
    let capture = &execution.capture;
    let args = vec![
        "/fixture/guard-cli".into(),
        "execute-bound-bash".into(),
        "--harness".into(),
        capture.harness.clone(),
        "--operation-id".into(),
        execution.operation_id.clone(),
        "--host-owner-pid".into(),
        std::process::id().to_string(),
        "--tool-call-id".into(),
        execution.tool_call_id.clone().unwrap(),
        "--guard-home".into(),
        capture.guard_home.clone(),
        "--workspace".into(),
        capture.workspace.clone(),
        "--request-file".into(),
        "/fixture/hol-guard-contained-test-post/request.json".into(),
        "--request-sha256".into(),
        "b".repeat(64),
        "--timeout-seconds".into(),
        "120".into(),
        "--home".into(),
        capture.home_dir.clone(),
    ];
    let command = args
        .iter()
        .map(|arg: &String| format!("'{}'", arg.replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ");
    NativeHookRequestV1 {
        protocol_version: guard_contracts::NATIVE_PROTOCOL_VERSION,
        request_id: Some("native-bash-post-test".into()),
        harness: capture.harness.clone(),
        event_name: "PostToolUse".into(),
        cwd: Some(capture.cwd.clone()),
        home_dir: capture.home_dir.clone(),
        guard_home: capture.guard_home.clone(),
        source_ref_external_allowed: false,
        observe_mode: false,
        deadline_budget_ms: Some(750),
        payload: json!({
            "tool_name":"bash", "tool_call_id":execution.tool_call_id,
            "tool_input":{"command":command}, "tool_response":"completed",
            "guard_bash_owner_delivery":{
                "schema":"guard-native-bash-post-observation.v1",
                "operation_id":execution.operation_id, "tool_call_id":execution.tool_call_id,
                "exit_code":exit,
            }
        }),
    }
}

fn joined(
    store: &PolicySnapshotStore,
    request: &NativeHookRequestV1,
    response: HookReviewResponseV1,
    proof: Option<&VerifiedBashDelivery>,
) -> HookReviewResponseV1 {
    apply_post_tool_policy_with_delivery(
        &store.current_admitted_snapshot().unwrap(),
        request,
        GuardHookPayloadKindV2::Inline,
        response,
        proof,
        false,
    )
    .unwrap()
}

#[test]
fn bash_post_delivery_requires_signed_matching_call_and_never_acknowledges_it() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let mut execution = invocation(&request, &envelope);
    let post = post(&execution, 0);
    assert!(verify(&post, &store).is_none());
    assert_eq!(execute(&execution, &store).status, "ok");
    assert!(verify(&post, &store).unwrap().clean_completion());
    let physical = std::fs::canonicalize(&request.workspace).unwrap();
    let physical = physical.to_str().unwrap();
    let alias = physical.strip_prefix("/private").unwrap_or(physical);
    assert_ne!(alias, physical, "fixture must exercise a macOS path alias");
    let mut aliased = post.clone();
    aliased.cwd = Some(alias.into());
    aliased.payload["tool_input"]["command"] = json!(post.payload["tool_input"]["command"]
        .as_str()
        .unwrap()
        .replace(&format!("'{}'", request.workspace), &format!("'{alias}'")));
    assert!(verify(&aliased, &store).unwrap().clean_completion());
    for variant in [
        "call",
        "unknown-call",
        "harness",
        "project",
        "exit",
        "unknown",
        "compound",
        "substitution",
        "home",
        "scope",
    ] {
        let mut invalid = post.clone();
        match variant {
            "call" => invalid.payload["tool_call_id"] = json!("foreign-call"),
            "unknown-call" => {
                invalid.payload["tool_call_id"] = json!("foreign-call");
                invalid.payload["guard_bash_owner_delivery"]["tool_call_id"] =
                    json!("foreign-call");
                let command = invalid.payload["tool_input"]["command"].as_str().unwrap();
                invalid.payload["tool_input"]["command"] =
                    json!(command.replace("'sdk-call-0'", "'foreign-call'"));
            }
            "harness" => {
                invalid.harness = "pi".into();
                let command = invalid.payload["tool_input"]["command"].as_str().unwrap();
                invalid.payload["tool_input"]["command"] = json!(command.replace("'omp'", "'pi'"));
            }
            "project" => {
                invalid.cwd = Some(request.home_dir.clone());
                let command = invalid.payload["tool_input"]["command"].as_str().unwrap();
                invalid.payload["tool_input"]["command"] = json!(command.replace(
                    &format!("'{}'", request.workspace),
                    &format!("'{}'", request.home_dir)
                ));
            }
            "exit" => invalid.payload["guard_bash_owner_delivery"]["exit_code"] = json!(7),
            "unknown" => invalid.payload["guard_bash_owner_delivery"]["trusted"] = json!(true),
            "home" => invalid.home_dir.push_str("/foreign"),
            "scope" => invalid.guard_home.push_str("/foreign"),
            "compound" | "substitution" => {
                let original = invalid.payload["tool_input"]["command"].as_str().unwrap();
                invalid.payload["tool_input"]["command"] = json!(format!(
                    "{original} {}",
                    if variant == "compound" {
                        "; printf unrelated"
                    } else {
                        "$(printf unrelated)"
                    }
                ));
            }
            _ => unreachable!(),
        }
        assert!(verify(&invalid, &store).is_none(), "{variant}");
    }
    // Read-only post observation cannot spend the delivery acknowledgement.
    execution.tool_call_id = Some("sdk-before-final-context".into());
    assert!(execute(&execution, &store).replayed);
    assert!(ack(&execution, &store, 0).acknowledged);
    execution.tool_call_id = Some("sdk-after-final-context".into());
    assert_eq!(execute(&execution, &store).status, "ok");
    let old = verify(&post, &store).unwrap();
    assert!(
        !old.clean_completion(),
        "an old call cannot acknowledge the new generation"
    );
    let connection = Connection::open(execution.authorization.store_path()).unwrap();
    connection
        .execute("UPDATE guard_bash_invocations SET integrity='{}'", [])
        .unwrap();
    assert!(verify(&post, &store).is_none());
}

#[test]
fn bash_post_delivery_rejects_missing_or_corrupt_signed_operation() {
    for missing in [false, true] {
        let (_root, request) = tests::fixture();
        let (store, envelope) = policy_store(&request);
        let execution = invocation(&request, &envelope);
        assert_eq!(execute(&execution, &store).status, "ok");
        let post = post(&execution, 0);
        assert!(verify(&post, &store).is_some());
        let connection = Connection::open(execution.authorization.store_path()).unwrap();
        connection
            .execute(
                if missing {
                    "DELETE FROM guard_bash_operations"
                } else {
                    "UPDATE guard_bash_operations SET integrity='{}'"
                },
                [],
            )
            .unwrap();
        assert!(verify(&post, &store).is_none());
        assert!(!ack(&execution, &store, 0).acknowledged);
    }
}

#[test]
fn bash_post_delivery_reuses_execution_review_but_keeps_current_hard_and_output_floors() {
    let (_root, request) = tests::fixture();
    let (store, mut envelope) = policy_store(&request);
    let execution = invocation(&request, &envelope);
    assert_eq!(execute(&execution, &store).status, "ok");
    let post = post(&execution, 0);
    let proof = verify(&post, &store).unwrap();
    execution_floor(&store, &mut envelope, "require-reapproval");
    let native = guard_hook_core::review_post_tool(&post);
    assert_eq!(native.reason_code, "output_scan_allow");
    let allowed = joined(&store, &post, native.clone(), Some(&proof));
    assert_eq!(allowed.decision, "allow");
    assert_eq!(allowed.reason_code, "native_bash_owner_result_allow");
    assert_eq!(joined(&store, &post, native.clone(), None).decision, "deny");
    let mut no_digest = native.clone();
    no_digest.reviewed_output_sha256 = None;
    assert_eq!(
        joined(&store, &post, no_digest, Some(&proof)).decision,
        "deny"
    );
    let denied = HookReviewResponseV1::deny("source_secret_match", "sensitive output");
    assert_eq!(joined(&store, &post, denied, Some(&proof)).decision, "deny");
    let output_review = HookReviewResponseV1::allow("native_output_subprocess_review");
    assert_eq!(
        joined(&store, &post, output_review, Some(&proof)).decision,
        "deny"
    );
    for hard in ["block", "sandbox-required"] {
        execution_floor(&store, &mut envelope, hard);
        assert_eq!(
            joined(&store, &post, native.clone(), Some(&proof)).decision,
            "deny"
        );
    }
    // Exercise simultaneous floors, including a non-execution risk: filtering
    // only the winning floor could accidentally drop an independent review.
    let mut snapshot = store.current_snapshot().unwrap();
    snapshot.effective_policy = crate::policy_enforcement::tests::policy("review");
    snapshot.effective_policy.subprocess_action = "require-reapproval".into();
    snapshot
        .effective_policy
        .harness_actions
        .insert("omp".into(), "review".into());
    let admitted = AdmittedPolicySnapshot::new(snapshot.clone()).unwrap();
    let result = apply_post_tool_policy_with_delivery(
        &admitted,
        &post,
        GuardHookPayloadKindV2::Inline,
        native.clone(),
        Some(&proof),
        false,
    )
    .unwrap();
    assert_eq!(result.reason_code, "native_bash_owner_result_allow");
    snapshot
        .effective_policy
        .risk_actions
        .insert("local_secret_read".into(), "review".into());
    let mut sensitive = post.clone();
    sensitive.payload["sensitive_target"] = json!(true);
    let result = apply_post_tool_policy_with_delivery(
        &AdmittedPolicySnapshot::new(snapshot).unwrap(),
        &sensitive,
        GuardHookPayloadKindV2::Inline,
        guard_hook_core::review_post_tool(&sensitive),
        Some(&proof),
        false,
    )
    .unwrap();
    assert_eq!(result.decision, "deny");
}

#[test]
fn bash_post_delivery_pending_review_is_control_only_and_missing_journal_never_proves_completion() {
    let (_root, request) = tests::fixture();
    let (store, mut envelope) = policy_store(&request);
    execution_floor(&store, &mut envelope, "require-reapproval");
    let execution = invocation(&request, &envelope);
    assert!(execute(&execution, &store).review_lineage.is_some());
    let post = post(&execution, 125);
    let proof = verify(&post, &store).unwrap();
    assert!(!proof.clean_completion());
    let result = joined(
        &store,
        &post,
        guard_hook_core::review_post_tool(&post),
        Some(&proof),
    );
    assert_eq!(result.decision, "allow");
    assert_ne!(result.reason_code, "native_bash_owner_result_allow");
    assert!(!ack(&execution, &store, 125).acknowledged);
    let connection = Connection::open(execution.authorization.store_path()).unwrap();
    connection
        .execute("DELETE FROM guard_bash_invocations", [])
        .unwrap();
    assert!(verify(&post, &store).is_none());
}

#[test]
fn bash_post_delivery_busy_call_is_signed_control_and_never_a_completion_or_ack() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let execution = invocation(&request, &envelope);
    let registration = store
        .bash_launches()
        .register(&execution.operation_id)
        .unwrap();
    let mut busy = execution.clone();
    busy.tool_call_id = Some("concurrent-rejected-sdk-call".into());
    assert!(verify(&post(&busy, 125), &store).is_none());
    let rejected = execute(&busy, &store);
    assert_eq!(rejected.code, "native_bash_operation_active");
    assert!(rejected.operation.is_none() && rejected.payload.is_none());
    drop(registration);
    assert!(!verify(&post(&busy, 125), &store)
        .unwrap()
        .clean_completion());
    assert_eq!(execute(&execution, &store).status, "ok");
    // The real owner may finish and acknowledge before the rejected call's
    // result hook arrives. Its control witness must remain valid afterwards.
    assert!(ack(&execution, &store, 0).acknowledged);
    let proof = verify(&post(&busy, 125), &store).unwrap();
    assert!(!proof.clean_completion());
    assert!(verify(&post(&busy, 0), &store).is_none());
    assert!(!ack(&busy, &store, 125).acknowledged);
    assert!(!ack(&busy, &store, 0).acknowledged);
    let connection = Connection::open(execution.authorization.store_path()).unwrap();
    let count: i64 = connection
        .query_row("SELECT count(*) FROM guard_bash_operations", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        count, 1,
        "busy delivery must not allocate another execution"
    );
    connection
        .execute("DELETE FROM guard_bash_invocations", [])
        .unwrap();
    assert!(verify(&post(&busy, 125), &store).is_none());
}

#[test]
fn bash_post_delivery_nonzero_completion_preserves_exact_status_and_can_acknowledge() {
    let (_root, request) = tests::fixture();
    let script = Path::new(&request.cwd).join("maintenance.sh");
    std::fs::write(
        &script,
        std::fs::read_to_string(&script).unwrap() + "\nexit 7\n",
    )
    .unwrap();
    let (store, envelope) = policy_store(&request);
    let execution = invocation(&request, &envelope);
    let result = execute(&execution, &store);
    assert_eq!(result.status, "ok");
    assert_eq!(result.payload.unwrap().exit_code, Some(7));
    assert!(verify(&post(&execution, 0), &store).is_none());
    let proof = verify(&post(&execution, 7), &store).unwrap();
    assert!(proof.clean_completion());
    assert!(!ack(&execution, &store, 0).acknowledged);
    assert!(ack(&execution, &store, 7).acknowledged);
}

#[test]
fn bash_post_delivery_empty_output_requires_a_complete_digest_and_signed_completion() {
    let (_root, request) = tests::fixture();
    let (store, mut envelope) = policy_store(&request);
    let execution = invocation(&request, &envelope);
    assert_eq!(execute(&execution, &store).status, "ok");
    execution_floor(&store, &mut envelope, "require-reapproval");
    let mut empty = post(&execution, 0);
    empty.payload["tool_response"] = json!("");
    let native = guard_hook_core::review_post_tool(&empty);
    assert_eq!(native.reason_code, "output_empty_allow");
    assert_eq!(
        native.reviewed_output_sha256.as_deref(),
        Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    let proof = verify(&empty, &store).unwrap();
    let allowed = joined(&store, &empty, native.clone(), Some(&proof));
    assert_eq!(allowed.decision, "allow");
    assert_eq!(allowed.reason_code, "native_bash_owner_result_allow");
    assert_eq!(joined(&store, &empty, native, None).decision, "deny");

    for output in [
        json!([]),
        json!([{"type":"text", "text":""}]),
        json!([{"type":"text", "text":"completed"}]),
    ] {
        let mut text = empty.clone();
        text.payload["tool_response"] = output;
        let result = joined(
            &store,
            &text,
            guard_hook_core::review_post_tool(&text),
            Some(&proof),
        );
        assert_eq!(result.decision, "allow");
        assert_eq!(result.reason_code, "native_bash_owner_result_allow");
    }

    let mut missing = empty.clone();
    missing
        .payload
        .as_object_mut()
        .unwrap()
        .remove("tool_response");
    let mut truncated = empty.clone();
    truncated.payload["tool_response_summary"] = json!({"excerpt_truncated":true});
    for incomplete in [missing, truncated] {
        assert!(guard_hook_core::canonical_observed_output_sha256(&incomplete.payload).is_none());
        let result = joined(
            &store,
            &incomplete,
            guard_hook_core::review_post_tool(&incomplete),
            Some(&proof),
        );
        assert_eq!(result.decision, "deny");
        assert_ne!(result.reason_code, "native_bash_owner_result_allow");
    }
    // A digest of the extracted text alone is not a proof for opaque content.
    for output in [
        json!([{"type":"image", "data":"fixture-image"}]),
        json!([{"type":"text", "text":"ordinary"}, {"type":"image", "data":"fixture-image"}]),
        json!([{"type":"text", "text":"", "extra":"unreviewed"}]),
        json!({"opaque":"unreviewed"}),
        json!(null),
    ] {
        let mut opaque = empty.clone();
        opaque.payload["tool_response"] = output;
        let result = joined(
            &store,
            &opaque,
            guard_hook_core::review_post_tool(&opaque),
            Some(&proof),
        );
        assert_eq!(result.decision, "deny");
        assert_ne!(result.reason_code, "native_bash_owner_result_allow");
    }
}
