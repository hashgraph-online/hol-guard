use serde_json::{json, Map, Value};

use super::contract::rfc3339;
use super::{exact_result, result_payload, run_command, JOB_ID_MISSING, LEASE_ID_MISSING};

const NOW: &str = "2026-11-20T12:00:00+00:00";

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => panic!("expected an object"),
    }
}

fn generic_job() -> Map<String, Value> {
    object(json!({"id": "job-1", "leaseId": "lease-1", "operation": "status"}))
}

fn exact_job() -> Map<String, Value> {
    object(json!({
        "id": "job-1",
        "leaseId": "lease-1",
        "_guardCommandTransport": "cloud_review",
        "serverResolvedBinding": {"localRequestId": "req-1"},
        "payload": {"remoteApproval": {"localRequestId": "req-1", "receiptId": "rcpt-1"}},
    }))
}

fn native_job() -> Map<String, Value> {
    let mut job = exact_job();
    job.insert(
        "payload".to_owned(),
        json!({"localRequestId": "req-1", "receiptId": "rcpt-1", "envelope": {"v": 1}}),
    );
    job
}

fn applied_execution() -> Map<String, Value> {
    object(json!({
        "data": {
            "applicationStatus": "applied",
            "applicationUpdatedAt": "2026-11-20T11:00:00Z",
            "continuationStatus": "resumed",
            "continuationUpdatedAt": "2026-11-20T11:00:01.25+00:00",
            "localRequestId": "req-1",
            "receiptId": "rcpt-1",
        },
        "generatedAt": "2026-11-20T11:00:02Z",
    }))
}

fn payload(job: &Map<String, Value>, execution: &Map<String, Value>) -> Value {
    Value::Object(result_payload(job, execution, NOW).expect("payload"))
}

#[test]
fn generic_success_posts_the_execution() {
    let execution = object(json!({"ok": true, "items": [1]}));
    assert_eq!(
        payload(&generic_job(), &execution),
        json!({
            "leaseId": "lease-1",
            "idempotencyKey": "job-1:lease-1:succeeded",
            "status": "succeeded",
            "result": {"ok": true, "items": [1]},
        })
    );
}

#[test]
fn waiting_local_confirm_drops_the_marker() {
    let execution = object(json!({"waitingLocalConfirm": true, "pendingId": "p-1"}));
    assert_eq!(
        payload(&exact_job(), &execution),
        json!({
            "protocolVersion": 2,
            "leaseId": "lease-1",
            "idempotencyKey": "job-1:lease-1:waiting_local_confirm",
            "status": "waiting_local_confirm",
            "result": {"pendingId": "p-1"},
        })
    );
    // Only a literal true waits.
    let truthy = object(json!({"waitingLocalConfirm": 1}));
    assert_eq!(payload(&generic_job(), &truthy)["status"], "succeeded");
}

#[test]
fn failure_code_posts_a_failure() {
    let execution = object(json!({"failureCode": "denied", "failureMessage": "No."}));
    assert_eq!(
        payload(&generic_job(), &execution),
        json!({
            "leaseId": "lease-1",
            "idempotencyKey": "job-1:lease-1:failed",
            "status": "failed",
            "failureCode": "denied",
            "failureMessage": "No.",
        })
    );
    let bare = object(json!({"failureCode": "denied", "failureMessage": ""}));
    assert_eq!(payload(&generic_job(), &bare)["failureMessage"], "denied");
    let empty = object(json!({"failureCode": "", "x": 1}));
    assert_eq!(payload(&generic_job(), &empty)["status"], "succeeded");
}

#[test]
fn missing_lease_is_refused_before_missing_id() {
    let execution = Map::new();
    let no_lease = object(json!({"id": "job-1"}));
    assert_eq!(
        result_payload(&no_lease, &execution, NOW),
        Err(LEASE_ID_MISSING)
    );
    let neither = object(json!({"leaseId": ""}));
    assert_eq!(
        result_payload(&neither, &execution, NOW),
        Err(LEASE_ID_MISSING)
    );
    let no_id = object(json!({"leaseId": "lease-1", "id": 7}));
    assert_eq!(result_payload(&no_id, &execution, NOW), Err(JOB_ID_MISSING));
}

#[test]
fn exact_success_builds_the_contract_result() {
    assert_eq!(
        payload(&exact_job(), &applied_execution()),
        json!({
            "protocolVersion": 2,
            "leaseId": "lease-1",
            "idempotencyKey": "job-1:lease-1:succeeded",
            "status": "succeeded",
            "result": {
                "applicationReason": null,
                "applicationStatus": "applied",
                "applicationUpdatedAt": "2026-11-20T11:00:00Z",
                "continuationReason": null,
                "continuationStatus": "resumed",
                "continuationUpdatedAt": "2026-11-20T11:00:01.25+00:00",
                "contractVersion": "guard-cloud-review-command-result-v2",
                "correlationId": "job-1",
                "localRequestId": "req-1",
                "protocolVersion": 2,
                "receiptId": "rcpt-1",
            },
        })
    );
}

#[test]
fn native_workspace_payload_supplies_the_ids() {
    let result = exact_result(&native_job(), &applied_execution(), NOW).expect("result");
    assert_eq!(result["receiptId"], "rcpt-1");
    let mut partial = native_job();
    partial.insert("payload".to_owned(), json!({"localRequestId": "req-1"}));
    assert_eq!(
        exact_result(&partial, &applied_execution(), NOW),
        Err("remote_native_workspace_review_invalid")
    );
    for bad in [
        json!({"localRequestId": " req-1", "receiptId": "rcpt-1", "envelope": {"v": 1}}),
        json!({"localRequestId": "req/1", "receiptId": "rcpt-1", "envelope": {"v": 1}}),
        json!({"localRequestId": "req-1", "receiptId": "rcpt-1", "envelope": {}}),
        json!({"localRequestId": "req-1", "receiptId": "x".repeat(129), "envelope": {"v": 1}}),
    ] {
        let mut job = native_job();
        job.insert("payload".to_owned(), bad);
        assert_eq!(
            exact_result(&job, &applied_execution(), NOW),
            Err("remote_native_workspace_review_invalid")
        );
    }
}

#[test]
fn empty_data_reports_an_invalid_result_at_the_generated_time() {
    let execution = object(json!({"data": {}}));
    let result = exact_result(&exact_job(), &execution, NOW).expect("result");
    assert_eq!(result["applicationStatus"], "failed_terminal");
    assert_eq!(result["applicationReason"], "exact_result_invalid");
    assert_eq!(result["continuationStatus"], "failed");
    assert_eq!(result["applicationUpdatedAt"], NOW);
    let stamped = object(json!({"generatedAt": " 2026-01-02T03:04:05Z ", "data": null}));
    let result = exact_result(&exact_job(), &stamped, NOW).expect("result");
    assert_eq!(result["continuationUpdatedAt"], "2026-01-02T03:04:05Z");
}

#[test]
fn binding_mismatches_are_refused() {
    let mut job = exact_job();
    job.insert(
        "serverResolvedBinding".to_owned(),
        json!({"localRequestId": "req-2"}),
    );
    assert_eq!(
        exact_result(&job, &applied_execution(), NOW),
        Err("exact_result_local_request_binding_mismatch")
    );
    let mut execution = applied_execution();
    execution["data"]["receiptId"] = json!("rcpt-2");
    assert_eq!(
        exact_result(&exact_job(), &execution, NOW),
        Err("exact_result_execution_binding_mismatch")
    );
    let mut unbound = exact_job();
    unbound.remove("serverResolvedBinding");
    assert_eq!(
        exact_result(&unbound, &applied_execution(), NOW),
        Err("exact_result_local_request_binding_missing")
    );
}

#[test]
fn contract_violations_post_a_contract_failure() {
    let cases: [(&str, Value); 6] = [
        ("applicationStatus", json!("done")),
        ("continuationStatus", json!("later")),
        ("applicationReason", json!("not allowed on applied")),
        ("applicationUpdatedAt", json!("2026-02-30T00:00:00Z")),
        ("continuationUpdatedAt", json!("2026-11-20 11:00:00Z")),
        ("continuationReason", json!("r".repeat(129))),
    ];
    for (field, value) in cases {
        let mut execution = applied_execution();
        execution["data"][field] = value;
        let posted = payload(&exact_job(), &execution);
        assert_eq!(posted["status"], "failed", "{field}");
        assert_eq!(
            posted["failureCode"], "exact_result_contract_invalid",
            "{field}"
        );
        assert_eq!(posted["idempotencyKey"], "job-1:lease-1:failed");
    }
}

#[test]
fn rejected_status_needs_a_reason() {
    let mut execution = applied_execution();
    execution["data"]["applicationStatus"] = json!("rejected_stale");
    assert_eq!(payload(&exact_job(), &execution)["status"], "failed");
    execution["data"]["applicationReason"] = json!(" stale ");
    let posted = payload(&exact_job(), &execution);
    assert_eq!(posted["status"], "succeeded");
    assert_eq!(posted["result"]["applicationReason"], "stale");
}

#[test]
fn opaque_ids_follow_the_contract_pattern() {
    let mut job = exact_job();
    job.insert("id".to_owned(), json!("-job"));
    assert_eq!(
        payload(&job, &applied_execution())["failureCode"],
        "exact_result_contract_invalid"
    );
    job.insert("id".to_owned(), json!("j".repeat(257)));
    assert_eq!(
        payload(&job, &applied_execution())["failureCode"],
        "exact_result_contract_invalid"
    );
}

#[test]
fn rfc3339_matches_the_python_check() {
    for good in [
        "2026-11-20T11:00:00Z",
        "2024-02-29T23:59:59.123456-05:30",
        "2026-11-20T11:00:00+23:59",
    ] {
        assert!(rfc3339(good), "{good}");
    }
    for bad in [
        "2026-11-20T11:00:00",
        "2026-11-20T24:00:00Z",
        "2026-11-20T11:00:60Z",
        "2025-02-29T00:00:00Z",
        "0000-01-01T00:00:00Z",
        "2026-11-20T11:00:00.Z",
        "2026-11-20T11:00:00+24:00",
        "2026-11-20T11:00:00+05:60",
        "2026-11-20t11:00:00Z",
        "2026-13-01T00:00:00Z",
    ] {
        assert!(!rfc3339(bad), "{bad}");
    }
}

#[test]
fn stdin_envelope_answers_and_refuses() {
    let request = json!({
        "schema": "command-result.v1",
        "job": generic_job(),
        "execution": {"ok": true},
        "now": NOW,
    });
    let output = run_command(request.to_string().as_bytes()).expect("output");
    let response: Value = serde_json::from_slice(&output).expect("json");
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["status"], "succeeded");

    let refused = json!({"schema": "command-result.v1", "job": {}, "execution": {}, "now": NOW});
    let output = run_command(refused.to_string().as_bytes()).expect("output");
    let response: Value = serde_json::from_slice(&output).expect("json");
    assert_eq!(response, json!({"ok": false, "error": LEASE_ID_MISSING}));

    for bad in [
        json!({"schema": "other", "job": {}, "execution": {}, "now": NOW}),
        json!({"schema": "command-result.v1", "job": [], "execution": {}, "now": NOW}),
        json!({"schema": "command-result.v1", "job": {}, "execution": {}, "now": NOW, "x": 1}),
    ] {
        let output = run_command(bad.to_string().as_bytes()).expect("output");
        let response: Value = serde_json::from_slice(&output).expect("json");
        assert_eq!(response["error"], "command_result_request_invalid");
    }
}

#[test]
fn large_results_up_to_the_cloud_body_limit_are_built() {
    let big = "x".repeat(6 * 1024 * 1024);
    let request = json!({
        "schema": "command-result.v1",
        "job": generic_job(),
        "execution": {"packages": big},
        "now": NOW,
    });
    let output = run_command(request.to_string().as_bytes()).expect("output");
    let response: Value = serde_json::from_slice(&output).expect("json");
    assert_eq!(response["result"]["status"], "succeeded");
    assert_eq!(
        response["result"]["result"]["packages"]
            .as_str()
            .map(str::len),
        Some(6 * 1024 * 1024)
    );

    let oversized = vec![b' '; 16 * 1024 * 1024 + 1];
    assert_eq!(
        run_command(oversized.as_slice()),
        Err("command_result_request_too_large".to_owned())
    );
}
