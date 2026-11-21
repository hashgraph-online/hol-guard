use serde_json::{json, Value};

use super::{plan, report, Planned, ReportCall};
use crate::cloud_bundle_fetch::SyncError;

fn call(value: Value) -> ReportCall {
    serde_json::from_value(value).expect("call")
}

fn planned(value: Value) -> Planned {
    plan(&call(value)).expect("planned")
}

fn refused(value: Value) -> String {
    match plan(&call(value)) {
        Err(SyncError::Failed(reason)) => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_exact_ack_goes_to_the_review_route_with_its_protocol() {
    let planned =
        planned(json!({"jobId": "job-1", "exact": true, "kind": "ack", "leaseId": "lease-1"}));
    assert_eq!(planned.path, "/api/guard/review/v2/commands/job-1/ack");
    let body: Value = serde_json::from_str(planned.body.as_deref().expect("body")).expect("json");
    assert_eq!(body, json!({"leaseId": "lease-1", "protocolVersion": 2}));
    assert_eq!(planned.body_file, None);
}

#[test]
fn a_generic_ack_is_the_queue_heartbeat_without_a_protocol() {
    let planned =
        planned(json!({"jobId": "job-2", "exact": false, "kind": "ack", "leaseId": "lease-2"}));
    assert_eq!(planned.path, "/api/guard/commands/job-2/heartbeat");
    let body: Value = serde_json::from_str(planned.body.as_deref().expect("body")).expect("json");
    assert_eq!(body, json!({"leaseId": "lease-2"}));
}

#[test]
fn a_result_is_sent_byte_for_byte_on_the_route_it_was_leased_on() {
    let text = "{\"leaseId\":\"lease-3\",\"status\":\"succeeded\"}";
    let exact = planned(json!({"jobId": "job-3", "exact": true, "kind": "result", "body": text}));
    assert_eq!(exact.path, "/api/guard/review/v2/commands/job-3/result");
    assert_eq!(exact.body.as_deref(), Some(text));
    let generic = planned(
        json!({"jobId": "job-3", "exact": false, "kind": "result", "bodyFile": "/private/body.json"}),
    );
    assert_eq!(generic.path, "/api/guard/commands/job-3/result");
    assert_eq!(generic.body, None);
    assert_eq!(generic.body_file.as_deref(), Some("/private/body.json"));
}

#[test]
fn a_job_id_that_leaves_its_path_segment_is_refused() {
    for job in [
        "", ".", "..", "a/b", "a?b", "a#b", "a%2Fb", "a b", "a\\b", "jöb",
    ] {
        let reason =
            refused(json!({"jobId": job, "exact": false, "kind": "ack", "leaseId": "lease"}));
        assert_eq!(
            reason, "The Guard command job id cannot name a report path.",
            "{job:?}"
        );
    }
}

#[test]
fn an_ack_needs_its_lease_and_no_body() {
    assert_eq!(
        refused(json!({"jobId": "job", "exact": true, "kind": "ack"})),
        "A Guard command ack needs the job's lease id."
    );
    assert_eq!(
        refused(json!({"jobId": "job", "exact": true, "kind": "ack", "leaseId": ""})),
        "A Guard command ack needs the job's lease id."
    );
    assert_eq!(
        refused(
            json!({"jobId": "job", "exact": false, "kind": "ack", "leaseId": "lease", "body": "{}"})
        ),
        "A Guard command ack carries no result body."
    );
}

#[test]
fn a_result_carries_exactly_one_body_and_no_lease_field() {
    assert_eq!(
        refused(json!({"jobId": "job", "exact": false, "kind": "result"})),
        "A Guard command result carries one body."
    );
    assert_eq!(
        refused(
            json!({"jobId": "job", "exact": false, "kind": "result", "body": "{}", "bodyFile": "/private/b"})
        ),
        "A Guard command result carries one body."
    );
    assert_eq!(
        refused(
            json!({"jobId": "job", "exact": false, "kind": "result", "leaseId": "lease", "body": "{}"})
        ),
        "A Guard command result carries its lease in its body."
    );
}

#[test]
fn an_unknown_field_or_kind_is_not_a_call() {
    assert!(serde_json::from_value::<ReportCall>(
        json!({"jobId": "job", "exact": false, "kind": "ack", "leaseId": "l", "url": "https://elsewhere"})
    )
    .is_err());
    assert!(serde_json::from_value::<ReportCall>(
        json!({"jobId": "job", "exact": false, "kind": "cancel"})
    )
    .is_err());
}

#[test]
fn a_report_without_a_sign_in_is_not_configured() {
    let call = call(json!({"jobId": "job", "exact": false, "kind": "ack", "leaseId": "lease"}));
    assert!(matches!(
        report(None, &call),
        Err(SyncError::NotConfigured(_))
    ));
}
