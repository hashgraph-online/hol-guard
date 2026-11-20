use std::collections::VecDeque;

use serde_json::{json, Value};

use super::{lease, lease_with, origin, reply, LeaseCall, Reply, EXACT_OPERATION};
use crate::cloud_bundle_fetch::SyncError;

const GENERIC: &str = "inventory.read";

fn call(operations: &[&str], max_jobs: i64, collect_extras: bool) -> LeaseCall {
    serde_json::from_value(json!({
        "operations": operations,
        "waitMs": 25_000,
        "maxJobs": max_jobs,
        "collectExtras": collect_extras,
        "workspaceId": "workspace-1",
        "deviceId": "device-1",
        "daemonVersion": "1.2.3",
        "schemaVersions": {GENERIC: 1, EXACT_OPERATION: 9},
    }))
    .expect("call")
}

/// Answers each lease in turn and records which route and body it was sent.
fn run(call: &LeaseCall, replies: Vec<Reply>) -> (Value, Vec<(String, Value)>) {
    let mut replies: VecDeque<Reply> = replies.into();
    let mut sent = Vec::new();
    let answer = lease_with(call, |route, body| {
        sent.push((route.to_owned(), body.clone()));
        Ok(replies.pop_front().expect("a reply for every lease"))
    })
    .expect("answer");
    (answer, sent)
}

fn response(value: Value) -> Reply {
    Reply::Response(value.as_object().cloned().expect("object"))
}

fn refusal(status: i64) -> Reply {
    Reply::Refusal(json!({"status": status, "headers": {}, "body": ""}))
}

fn exact_job(lease: &str) -> Value {
    json!({"id": format!("job-{lease}"), "leaseId": lease, "protocolVersion": 2})
}

#[test]
fn an_exact_job_is_leased_first_with_the_batch_the_caller_settles() {
    let lease = call(&[EXACT_OPERATION, GENERIC], 3, true);
    let (answer, sent) = run(
        &lease,
        vec![response(json!({
            "protocolVersion": 2,
            "maxJobs": 4,
            "item": exact_job("a"),
            "items": [exact_job("a"), exact_job("b"), exact_job("b"), {"leaseId": "c", "protocolVersion": 1}, exact_job("")],
        }))],
    );
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, "/api/guard/review/v2/commands");
    assert_eq!(
        sent[0].1,
        json!({
            "workspaceId": "workspace-1",
            "deviceId": "device-1",
            "daemonVersion": "1.2.3",
            "capabilities": {"operations": [EXACT_OPERATION]},
            "maxJobs": 3,
            "waitMs": 0,
            "protocolVersion": 2,
        })
    );
    let leased = &answer["lease"];
    assert_eq!(leased["item"]["leaseId"], json!("a"));
    assert_eq!(leased["exact"], json!(true));
    assert_eq!(leased["extras"], json!([exact_job("b")]));
    assert_eq!(leased["exactRoute"], json!("ok"));
    assert_eq!(leased["batchLimit"], json!(4));
    assert_eq!(leased["responses"].as_array().map(Vec::len), Some(1));
    assert_eq!(answer["failure"], Value::Null);
}

#[test]
fn an_exact_only_lease_waits_and_a_caller_without_a_batch_gets_no_extras() {
    let lease = call(&[EXACT_OPERATION], 1, false);
    let (answer, sent) = run(
        &lease,
        vec![response(json!({
            "protocolVersion": 2.0,
            "item": exact_job("a"),
            "items": [exact_job("b")],
        }))],
    );
    assert_eq!(sent[0].1["waitMs"], json!(25_000));
    assert_eq!(answer["lease"]["extras"], json!([]));
    assert_eq!(answer["lease"]["batchLimit"], json!(1));
}

#[test]
fn an_empty_exact_lease_falls_through_to_the_generic_queue() {
    let lease = call(&[EXACT_OPERATION, GENERIC], 1, false);
    let (answer, sent) = run(
        &lease,
        vec![
            response(json!({"protocolVersion": 2, "item": {}})),
            response(json!({"item": {"id": "job-g", "leaseId": "g"}, "policyRevision": "r1"})),
        ],
    );
    assert_eq!(sent[1].0, "/api/guard/commands");
    assert_eq!(
        sent[1].1,
        json!({
            "workspaceId": "workspace-1",
            "deviceId": "device-1",
            "daemonVersion": "1.2.3",
            "capabilities": {"operations": [GENERIC], "schemaVersions": {GENERIC: 1}},
            "maxJobs": 1,
            "waitMs": 25_000,
        })
    );
    assert_eq!(answer["lease"]["item"]["id"], json!("job-g"));
    assert_eq!(answer["lease"]["exact"], json!(false));
    assert_eq!(
        answer["lease"]["responses"].as_array().map(Vec::len),
        Some(2)
    );
}

#[test]
fn a_refused_exact_route_is_recorded_and_the_generic_queue_still_leases() {
    let lease = call(&[EXACT_OPERATION, GENERIC], 3, true);
    let (answer, sent) = run(&lease, vec![refusal(400), response(json!({"item": null}))]);
    assert_eq!(sent.len(), 2);
    let leased = &answer["lease"];
    assert_eq!(leased["exactRoute"], json!("failed"));
    assert_eq!(leased["exactRefusal"]["status"], json!(400));
    assert_eq!(leased["batchLimit"], json!(1));
    assert_eq!(leased["item"], Value::Null);
    assert_eq!(answer["failure"], Value::Null);
}

#[test]
fn an_expired_sign_in_or_a_lone_exact_route_refusal_is_the_failure() {
    let both = call(&[EXACT_OPERATION, GENERIC], 1, false);
    let (answer, sent) = run(&both, vec![refusal(401)]);
    assert_eq!(sent.len(), 1);
    assert_eq!(answer["failure"]["refusal"]["status"], json!(401));
    assert_eq!(
        answer["failure"]["route"],
        json!("/api/guard/review/v2/commands")
    );
    assert_eq!(answer["lease"]["exactRoute"], Value::Null);
    let exact = call(&[EXACT_OPERATION], 2, true);
    let (answer, _) = run(&exact, vec![refusal(400)]);
    assert_eq!(answer["failure"]["refusal"]["status"], json!(400));
    assert_eq!(answer["lease"]["batchLimit"], json!(1));
}

#[test]
fn an_exact_answer_on_another_protocol_asks_for_an_upgrade() {
    let lease = call(&[EXACT_OPERATION, GENERIC], 1, false);
    for answer in [
        json!({"protocolVersion": 1, "item": exact_job("a")}),
        json!({"protocolVersion": true}),
        json!({"protocolVersion": 2, "item": {"leaseId": "a", "protocolVersion": "2"}}),
    ] {
        let (answer, sent) = run(&lease, vec![response(answer)]);
        assert_eq!(sent.len(), 1);
        assert_eq!(
            answer["failure"],
            json!({"protocol": "cloud_review_protocol_upgrade_required"})
        );
    }
}

#[test]
fn a_transport_failure_ends_the_lease() {
    let lease = call(&[GENERIC], 1, false);
    let (answer, _) = run(
        &lease,
        vec![Reply::Transport(json!({"reason": "timeout: read"}))],
    );
    assert_eq!(
        answer["failure"]["transport"]["reason"],
        json!("timeout: read")
    );
    assert_eq!(answer["failure"]["route"], json!("/api/guard/commands"));
    let exact = call(&[EXACT_OPERATION, GENERIC], 1, false);
    let (answer, sent) = run(&exact, vec![Reply::Transport(json!({"reason": "down"}))]);
    assert_eq!(sent.len(), 1);
    assert_eq!(answer["failure"]["transport"]["reason"], json!("down"));
}

#[test]
fn nothing_to_lease_sends_nothing() {
    let (answer, sent) = run(&call(&[], 1, false), Vec::new());
    assert!(sent.is_empty());
    assert_eq!(answer["lease"]["item"], Value::Null);
}

#[test]
fn a_lease_without_a_sign_in_is_not_configured() {
    let answer = lease(None, &call(&[GENERIC], 1, false));
    assert!(
        matches!(answer, Err(SyncError::NotConfigured(_))),
        "{answer:?}"
    );
}

#[test]
fn an_untrusted_sync_url_is_refused_before_any_lease() {
    let auth = serde_json::Map::from_iter([(
        "sync_url".to_owned(),
        json!("https://cloud.example.invalid/api/guard/receipts/sync"),
    )]);
    let answer = lease(Some(&auth), &call(&[GENERIC], 1, false));
    assert!(
        matches!(answer, Err(SyncError::EndpointUntrusted(_))),
        "{answer:?}"
    );
}

#[test]
fn the_request_answers_map_to_replies() {
    assert!(matches!(
        reply(json!({"response": {"item": null}})),
        Ok(Reply::Response(_))
    ));
    assert!(matches!(
        reply(json!({"refusal": {"status": 500}})),
        Ok(Reply::Refusal(_))
    ));
    assert!(matches!(
        reply(json!({"transport": {"reason": "x"}})),
        Ok(Reply::Transport(_))
    ));
    assert!(reply(json!({"response": []})).is_err());
    assert!(reply(json!([])).is_err());
}

#[test]
fn the_origin_keeps_the_scheme_and_authority() {
    assert_eq!(
        origin("https://hol.org/api/guard/receipts/sync"),
        Some("https://hol.org".to_owned())
    );
    assert_eq!(origin("not a url"), None);
}

#[test]
fn an_unknown_call_field_is_refused() {
    let mut fields = json!({
        "operations": [GENERIC], "waitMs": 0, "maxJobs": 1, "collectExtras": false,
        "workspaceId": "w", "deviceId": "d", "daemonVersion": "v",
    });
    assert!(serde_json::from_value::<LeaseCall>(fields.clone()).is_ok());
    fields["token"] = json!("x");
    assert!(serde_json::from_value::<LeaseCall>(fields).is_err());
}
