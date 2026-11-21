use serde_json::{json, Map, Value};

use super::dispatch;
use crate::guard_store_outbox_decode::{EVENT_SCHEMA_NAME, SNAPSHOT_COLUMNS};
use crate::guard_store_outbox_identity::payload_digest_text;

const SOURCE: &str = "default";
const BINDING: [&str; 4] = ["subject", "workspace", "machine", "installation"];

fn snapshot() -> Map<String, Value> {
    let mut snapshot = Map::new();
    for column in SNAPSHOT_COLUMNS {
        snapshot.insert(column.to_owned(), Value::from("x"));
    }
    snapshot.insert("request_id".into(), Value::from("req-1"));
    snapshot.insert("oauth_source".into(), Value::from(SOURCE));
    snapshot.insert("changed_fields_json".into(), Value::from("[\"command\"]"));
    snapshot.insert("risk_signals_json".into(), Value::from("{\"ratio\":0.1}"));
    snapshot.insert("scanner_evidence_json".into(), Value::from("[]"));
    snapshot.remove("continuation_snapshot_json");
    for field in [
        "action_envelope_json",
        "browser_intent_json",
        "decision_v2_json",
    ] {
        snapshot.insert(field.into(), Value::Null);
    }
    snapshot
}

fn payload(event_type: &str) -> Map<String, Value> {
    json!({
        "schema": EVENT_SCHEMA_NAME,
        "localRequestId": "req-1",
        "eventType": event_type,
        "oauthSource": SOURCE,
        "requestSnapshot": snapshot(),
    })
    .as_object()
    .expect("payload object")
    .clone()
}

fn row(event_type: &str, payload: &Map<String, Value>) -> Value {
    let payload_json = Value::Object(payload.clone()).to_string();
    let digest = payload_digest_text(
        &payload_json,
        [SOURCE, BINDING[0], BINDING[1], BINDING[2], BINDING[3]],
    );
    json!({
        "event_schema_version": 1,
        "payload_json": payload_json,
        "payload_hash": digest,
        "oauth_source": SOURCE,
        "oauth_subject_hash": BINDING[0],
        "workspace_id": BINDING[1],
        "machine_id": BINDING[2],
        "machine_installation_id": BINDING[3],
        "event_type": event_type,
        "local_request_id": "req-1",
        "stream_sequence": 7,
        "request_sequence": 2,
        "event_id": "evt-1",
    })
}

fn decode(row: Value) -> Value {
    dispatch(&json!({ "row": row })).expect("object request")
}

fn reason(row: Value) -> Value {
    decode(row)["reason"].clone()
}

#[test]
fn an_authenticated_request_event_answers_its_parsed_snapshot() {
    let answer = decode(row(
        "review.request.created",
        &payload("review.request.created"),
    ));
    let event = &answer["event"];
    assert_eq!(event["event_id"], "evt-1");
    assert_eq!(event["event_type"], "review.request.created");
    assert_eq!(event["wire_event_type"], "request_created");
    assert_eq!(event["stream_sequence"], 7);
    assert_eq!(event["request_sequence"], 2);
    assert_eq!(event["native_replay"], Value::Null);
    assert_eq!(event["continuation_result"], Value::Null);
    let snapshot = &event["snapshot"];
    assert_eq!(snapshot["changed_fields_json"], json!(["command"]));
    assert_eq!(snapshot["risk_signals_json"], json!({ "ratio": 0.1 }));
    assert_eq!(snapshot["continuation_snapshot_json"], Value::Null);
    assert_eq!(snapshot["artifact_name"], "x");
}

#[test]
fn continuation_and_replay_events_carry_their_evidence() {
    let mut resumed = payload("review.continuation.manual_retry_required");
    resumed.insert(
        "continuationResult".into(),
        json!({
            "action": "block",
            "capability": "codex",
            "completedAt": "2026-11-03T00:00:00Z",
            "correlationId": "c",
            "evidenceId": "e",
            "reason": "r",
            "status": "manual_retry_required",
        }),
    );
    let event = decode(row("review.continuation.manual_retry_required", &resumed));
    assert_eq!(
        event["event"]["wire_event_type"],
        "continuation_manual_retry_required"
    );
    assert_eq!(event["event"]["continuation_result"]["action"], "block");

    let mut requeued = payload("review.request.snapshot_requeued");
    requeued.insert("nativeReplay".into(), Value::Bool(true));
    let event = decode(row("review.request.snapshot_requeued", &requeued));
    assert_eq!(event["event"]["native_replay"], true);
    assert_eq!(event["event"]["wire_event_type"], "request_created");
    let resolved = decode(row(
        "review.request.resolved",
        &payload("review.request.resolved"),
    ));
    assert_eq!(resolved["event"]["wire_event_type"], "request_resolved");
}

#[test]
fn envelope_failures_name_their_quarantine_reason() {
    let event_type = "review.request.created";
    let good = payload(event_type);
    let mut stale = row(event_type, &good);
    stale["event_schema_version"] = json!(999);
    let answer = decode(stale);
    assert_eq!(answer["reason"], "unsupported_event_schema");
    assert_eq!(
        answer["message"],
        "Unsupported Review event schema version: 999."
    );
    let mut tampered = row(event_type, &good);
    tampered["payload_hash"] = json!("00");
    assert_eq!(reason(tampered), "payload_hash_mismatch");
    let answer = decode(row(
        "review.continuation.paused",
        &payload("review.continuation.paused"),
    ));
    assert_eq!(answer["reason"], "unsupported_event_type");
    assert_eq!(
        answer["message"],
        "Unsupported Review event type: 'review.continuation.paused'."
    );
    let mut other_request = good.clone();
    other_request.insert("localRequestId".into(), json!("req-2"));
    assert_eq!(
        reason(row(event_type, &other_request)),
        "payload_metadata_mismatch"
    );
    let mut other_source = good.clone();
    other_source.insert("oauthSource".into(), json!("other"));
    assert_eq!(
        reason(row(event_type, &other_source)),
        "payload_source_binding_mismatch"
    );
    let mut replay = good.clone();
    replay.insert("nativeReplay".into(), json!(true));
    assert_eq!(
        reason(row(event_type, &replay)),
        "payload_native_replay_invalid"
    );
    let mut unsequenced = row(event_type, &good);
    unsequenced["request_sequence"] = json!("2");
    assert_eq!(reason(unsequenced), "payload_metadata_mismatch");
}

#[test]
fn snapshot_failures_name_their_quarantine_reason() {
    let event_type = "review.request.created";
    let with_snapshot = |edit: &dyn Fn(&mut Map<String, Value>)| {
        let mut payload = payload(event_type);
        let snapshot = payload["requestSnapshot"]
            .as_object_mut()
            .expect("snapshot object");
        edit(snapshot);
        decode(row(event_type, &payload))
    };
    let mut missing = payload(event_type);
    missing.remove("requestSnapshot");
    assert_eq!(
        reason(row(event_type, &missing)),
        "payload_snapshot_missing"
    );
    let answer = with_snapshot(&|snapshot| {
        snapshot.remove("harness");
        snapshot.remove("artifact_id");
    });
    assert_eq!(answer["reason"], "payload_snapshot_incomplete");
    assert_eq!(
        answer["message"],
        "Stored Review event snapshot is missing canonical fields: artifact_id, harness."
    );
    let answer = with_snapshot(&|snapshot| {
        snapshot.insert("zz_extra".into(), json!(1));
        snapshot.insert("aa_extra".into(), json!(1));
    });
    assert_eq!(answer["reason"], "payload_snapshot_unexpected_fields");
    assert_eq!(
        answer["message"],
        "Stored Review event snapshot has unexpected fields: aa_extra, zz_extra."
    );
    let answer = with_snapshot(&|snapshot| {
        snapshot.insert("status".into(), json!("  "));
        snapshot.insert("harness".into(), json!(3));
    });
    assert_eq!(
        answer["message"],
        "Stored Review event snapshot has invalid canonical fields: harness, status."
    );
    let answer = with_snapshot(&|snapshot| {
        snapshot.insert("browser_intent_json".into(), json!("{"));
    });
    assert_eq!(answer["reason"], "payload_snapshot_invalid");
    let answer = with_snapshot(&|snapshot| {
        snapshot.insert("request_id".into(), json!("req-2"));
    });
    assert_eq!(answer["reason"], "payload_snapshot_request_mismatch");
    let answer = with_snapshot(&|snapshot| {
        snapshot.insert("oauth_source".into(), json!("other"));
    });
    assert_eq!(answer["reason"], "payload_snapshot_source_mismatch");
}

#[test]
fn continuation_evidence_must_match_its_event() {
    let event_type = "review.continuation.resumed";
    let result = json!({
        "action": "allow_once",
        "capability": "codex",
        "completedAt": "t",
        "correlationId": "c",
        "evidenceId": "e",
        "reason": "r",
        "status": "resumed",
    });
    let with_result = |result: Value| {
        let mut payload = payload(event_type);
        payload.insert("continuationResult".into(), result);
        decode(row(event_type, &payload))
    };
    assert!(with_result(result.clone())["event"].is_object());
    assert_eq!(
        with_result(Value::Null)["reason"],
        "payload_continuation_missing"
    );
    for (field, value) in [
        ("status", json!("failed")),
        ("action", json!("allow")),
        ("evidenceId", json!(" ")),
        ("extra", json!("x")),
    ] {
        let mut edited = result.clone();
        edited[field] = value;
        assert_eq!(
            with_result(edited)["reason"],
            "payload_continuation_invalid",
            "{field}"
        );
    }
    let mut request = payload("review.request.created");
    request.insert("continuationResult".into(), result);
    assert_eq!(
        reason(row("review.request.created", &request)),
        "payload_continuation_unexpected"
    );
}

#[test]
fn a_request_without_a_row_object_is_invalid() {
    assert!(dispatch(&json!({ "row": [] })).is_err());
    assert!(dispatch(&json!([])).is_err());
}
