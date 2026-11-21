//! Each step writes the marker the Python replay loop and delivery wrote.

use serde_json::json;

use super::super::tests::{args, binding, put, store, NOW};
use super::super::{marker_key, read_payload};
use super::*;

const DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn authority() -> Value {
    json!({"authority_generation": 3, "authority_record_digest": DIGEST})
}

fn step(connection: &Connection, extra: Value) -> StoreResult<Value> {
    let args = args(extra);
    method(connection, &Args(&args))
}

fn marker(connection: &Connection) -> Option<Value> {
    read_payload(connection, &marker_key("default", "request-1")).unwrap()
}

#[test]
fn probe_without_authority_backs_off_and_keeps_history() {
    let connection = store();
    put(
        &connection,
        &json!({
            "binding": {"workspace_id": "other"}, "attempts": 2, "accepted": true,
            "requeued": 1, "request_snapshot": {"id": "request-1"}
        }),
    );
    let result = step(&connection, json!({"step": "probed", "authority": null})).unwrap();
    assert_eq!(result["action"], json!("failed"));
    let stored = marker(&connection).unwrap();
    assert_eq!(stored["attempts"], json!(3));
    assert_eq!(stored["next_probe_at"], json!("2026-09-27T12:08:00+00:00"));
    assert_eq!(stored["requeued"], json!(1));
    assert_eq!(stored["request_snapshot"], json!({"id": "request-1"}));
    assert!(stored.get("accepted").is_none());
    assert_eq!(stored["binding"], binding());
}

#[test]
fn invalid_authority_counts_as_failed_probe() {
    let connection = store();
    for authority in [
        json!({"authority_generation": 0, "authority_record_digest": DIGEST}),
        json!({"authority_generation": true, "authority_record_digest": DIGEST}),
        json!({"authority_generation": 3, "authority_record_digest": DIGEST.to_uppercase()}),
    ] {
        let result = step(
            &connection,
            json!({"step": "probed", "authority": authority}),
        )
        .unwrap();
        assert_eq!(result["action"], json!("failed"));
    }
    assert_eq!(marker(&connection).unwrap()["attempts"], json!(3));
}

#[test]
fn accepted_authority_is_probed_again_later() {
    let connection = store();
    put(
        &connection,
        &json!({
            "binding": binding(), "accepted": true, "authority_generation": 3,
            "authority_record_digest": DIGEST, "attempts": 0
        }),
    );
    let result = step(
        &connection,
        json!({"step": "probed", "authority": authority()}),
    )
    .unwrap();
    assert_eq!(result["action"], json!("accepted"));
    let stored = marker(&connection).unwrap();
    assert_eq!(stored["next_probe_at"], json!("2026-09-27T12:05:00+00:00"));
    assert_eq!(stored["accepted"], json!(true));
}

#[test]
fn new_authority_returns_seed_without_writing() {
    let connection = store();
    let result = step(
        &connection,
        json!({"step": "probed", "authority": authority()}),
    )
    .unwrap();
    assert_eq!(result["action"], json!("requeue"));
    assert_eq!(result["seed"]["attempts"], json!(1));
    assert_eq!(result["seed"]["replay_attempts"], json!(1));
    assert_eq!(result["seed"]["native_replay"], json!(true));
    assert_eq!(
        result["seed"]["next_probe_at"],
        json!("2026-09-27T12:05:00+00:00")
    );
    assert!(marker(&connection).is_none());
}

#[test]
fn replayed_authority_waits_longer_each_time() {
    let connection = store();
    put(
        &connection,
        &json!({
            "binding": binding(), "authority_generation": 3,
            "authority_record_digest": DIGEST, "requeued": 1, "replay_attempts": 2, "attempts": 0
        }),
    );
    let result = step(
        &connection,
        json!({"step": "probed", "authority": authority()}),
    )
    .unwrap();
    assert_eq!(result["seed"]["replay_attempts"], json!(3));
    assert_eq!(
        result["seed"]["next_probe_at"],
        json!("2026-09-27T13:00:00+00:00")
    );
}

#[test]
fn requeued_records_count_and_resets_attempts() {
    let connection = store();
    let seed = step(
        &connection,
        json!({"step": "probed", "authority": authority()}),
    )
    .unwrap()["seed"]
        .clone();
    step(
        &connection,
        json!({"step": "requeued", "seed": seed, "count": 2}),
    )
    .unwrap();
    let stored = marker(&connection).unwrap();
    assert_eq!(stored["requeued"], json!(2));
    assert_eq!(stored["attempts"], json!(0));
    step(
        &connection,
        json!({"step": "requeued", "seed": seed, "count": 0}),
    )
    .unwrap();
    assert_eq!(marker(&connection).unwrap()["attempts"], json!(1));
}

#[test]
fn requeued_refuses_another_requests_seed() {
    let connection = store();
    let seed = json!({"request_id": "request-2", "binding": binding(), "attempts": 1});
    assert!(step(
        &connection,
        json!({"step": "requeued", "seed": seed, "count": 1})
    )
    .is_err());
    assert!(marker(&connection).is_none());
}

#[test]
fn accepted_marks_replayed_authority_once() {
    let connection = store();
    put(
        &connection,
        &json!({
            "binding": binding(), "authority_generation": 3,
            "authority_record_digest": DIGEST, "requeued": 1, "attempts": 2
        }),
    );
    let result = step(
        &connection,
        json!({"step": "accepted", "authority": authority()}),
    )
    .unwrap();
    assert_eq!(result["result"], json!("accepted"));
    let stored = marker(&connection).unwrap();
    assert_eq!(stored["accepted"], json!(true));
    assert_eq!(stored["accepted_at"], json!(NOW));
    assert_eq!(stored["attempts"], json!(0));
    let again = step(
        &connection,
        json!({"step": "accepted", "authority": authority()}),
    )
    .unwrap();
    assert_eq!(again["result"], json!("already"));
}

#[test]
fn accepted_uses_fallback_when_stored_binding_differs() {
    let connection = store();
    put(&connection, &json!({"binding": {"workspace_id": "other"}}));
    let unmatched = step(
        &connection,
        json!({"step": "accepted", "authority": authority()}),
    )
    .unwrap();
    assert_eq!(unmatched["result"], json!("unmatched"));
    let fallback = json!({
        "binding": binding(), "authority_generation": 3,
        "authority_record_digest": DIGEST, "requeued": 1, "replay_attempts": 1
    });
    let result = step(
        &connection,
        json!({"step": "accepted", "authority": authority(), "fallback": fallback}),
    )
    .unwrap();
    assert_eq!(result["result"], json!("accepted"));
    assert_eq!(marker(&connection).unwrap()["binding"], binding());
}

#[test]
fn unknown_step_is_refused() {
    let connection = store();
    assert!(step(&connection, json!({"step": "other"})).is_err());
}
