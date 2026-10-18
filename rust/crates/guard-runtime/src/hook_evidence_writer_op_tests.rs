//! The op drives a real writer against a real store: the schema and seed come
//! from the recorded command-activity vectors, so a row that lands here is a
//! row the Python store would have accepted.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde_json::{json, Value};

use super::{
    evaluate_hook_evidence_writer_request, HookEvidenceWriterRequestV1,
    HOOK_EVIDENCE_WRITER_REQUEST_SCHEMA,
};
use crate::guard_store_cmd_vectors_tests::{build_database, dump, temp_home};

const VECTORS: &str = include_str!("../testdata/guard_store/command_activity_vectors.json");

/// A Guard home holding the recorded schema and the named scenario's seed.
fn store_home(tag: &str, scenario: &str) -> PathBuf {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let scenario = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == json!(scenario))
        .expect("scenario")
        .clone();
    let home = temp_home(tag);
    build_database(&home.join("guard.db"), &vectors, &scenario);
    home
}

fn call(home: &Path, action: Value) -> Value {
    let Value::Object(mut wire) = json!({
        "schema": HOOK_EVIDENCE_WRITER_REQUEST_SCHEMA,
        "request_id": "writer-op",
        "guard_home": home.to_string_lossy(),
        "source": "guard",
    }) else {
        unreachable!("object literal");
    };
    let Value::Object(action) = action else {
        unreachable!("object literal");
    };
    wire.extend(action);
    let request: HookEvidenceWriterRequestV1 = serde_json::from_value(Value::Object(wire)).unwrap();
    let bytes = evaluate_hook_evidence_writer_request(&request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn activity_rows(home: &Path) -> Value {
    let connection = Connection::open(home.join("guard.db")).unwrap();
    dump(&connection, "command_activity", "activity_id")
}

#[test]
fn a_submitted_activity_lands_in_the_store_this_home_owns() {
    let home = store_home("writer-op-activity", "record_basic");
    let queued = call(
        &home,
        json!({
            "action": "submit_command_activity",
            "harness": "claude-code",
            "event": "PostToolUse",
            "payload": {
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /tmp/scratch"},
            },
            "succeeded": true,
        }),
    );
    assert_eq!(queued["status"], json!("ok"));
    assert_eq!(queued["payload"]["queued"], json!(true));

    let stopped = call(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
    assert_eq!(stopped["payload"]["drained"], json!(true));

    // A post event that pairs with no pre-hook decision is written as an
    // explicitly unpaired observation; it never invents a verdict.
    let recorded = activity_rows(&home);
    let recorded = recorded.as_array().expect("rows");
    assert_eq!(recorded.len(), 1, "one activity row");
    assert_eq!(recorded[0]["harness"], json!("claude-code"));
    assert_eq!(recorded[0]["execution_status"], json!("unpaired_post"));
    assert_eq!(recorded[0]["policy_action"], Value::Null);

    // The stop dropped the writer, so the home reads as idle again rather
    // than reporting the counters of a thread that has already exited.
    let after = call(&home, json!({"action": "stats"}));
    assert_eq!(after["payload"]["running"], json!(false));
    assert_eq!(after["payload"]["accepted"], json!(0));
}

#[test]
fn a_pre_event_without_a_guard_action_is_not_queued() {
    let home = store_home("writer-op-pre", "record_basic");
    let answer = call(
        &home,
        json!({
            "action": "submit_command_activity",
            "harness": "claude-code",
            "event": "PreToolUse",
            "payload": {
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /tmp/scratch"},
            },
            "succeeded": true,
        }),
    );
    assert_eq!(answer["payload"]["queued"], json!(false));
    call(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
    assert_eq!(activity_rows(&home).as_array().unwrap().len(), 0);
}

#[test]
fn a_receipt_the_validator_refuses_is_not_queued() {
    let home = store_home("writer-op-receipt", "record_basic");
    let answer = call(
        &home,
        json!({
            "action": "submit_native_decision_receipt",
            "receipt": {"not": "a receipt"},
        }),
    );
    assert_eq!(answer["payload"]["queued"], json!(false));
    let stats = call(&home, json!({"action": "stats"}))["payload"].clone();
    assert_eq!(
        stats["receipt_dropped"],
        json!(1),
        "a refused receipt is a dropped receipt"
    );
    assert_eq!(stats["dropped"], json!(1));
    assert_eq!(stats["degraded"], json!(true));
    call(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn a_drain_budget_too_large_for_a_duration_is_clamped() {
    let home = store_home("writer-op-drain-budget", "record_basic");
    let started = call(
        &home,
        json!({
            "action": "submit_command_activity",
            "harness": "claude-code",
            "event": "PostToolUse",
            "payload": {"tool_name": "Bash", "tool_input": {"command": "pwd"}},
            "succeeded": true,
        }),
    );
    assert_eq!(started["payload"]["queued"], json!(true));
    // The budget arrives as an unvalidated JSON number. A value no `Duration`
    // can hold is clamped rather than carried into the drain deadline.
    let stopped = call(&home, json!({"action": "stop", "timeout_seconds": 1e300}));
    assert_eq!(stopped["status"], json!("ok"));
    assert_eq!(stopped["payload"]["drained"], json!(true));
}

#[test]
fn reading_counters_never_starts_a_writer() {
    let home = temp_home("writer-op-idle");
    for _ in 0..2 {
        let stats = call(&home, json!({"action": "stats"}));
        assert_eq!(stats["status"], json!("ok"));
        assert_eq!(stats["payload"]["running"], json!(false));
        assert_eq!(stats["payload"]["policy_mutations"], json!(0));
    }
    // Stopping a home no writer ever ran for is not an error either.
    let stopped = call(&home, json!({"action": "stop"}));
    assert_eq!(stopped["payload"]["drained"], json!(true));
}

#[test]
fn an_unsuccessful_discovery_is_refused_before_a_writer_exists() {
    let home = temp_home("writer-op-discovery");
    let answer = call(
        &home,
        json!({
            "action": "submit_composio_discovery",
            "harness": "claude-code",
            "payload": {"tool_name": "mcp__composio__composio_search_tools"},
            "succeeded": false,
        }),
    );
    assert_eq!(answer["payload"]["queued"], json!(false));
    let nameless = call(
        &home,
        json!({
            "action": "submit_composio_discovery",
            "harness": "claude-code",
            "payload": {},
            "succeeded": true,
        }),
    );
    assert_eq!(nameless["payload"]["queued"], json!(false));
    assert_eq!(
        call(&home, json!({"action": "stats"}))["payload"]["running"],
        json!(false),
        "a refused discovery starts no writer"
    );
}

#[test]
fn a_request_of_another_schema_is_refused() {
    let home = temp_home("writer-op-schema");
    let request: HookEvidenceWriterRequestV1 = serde_json::from_value(json!({
        "schema": "guard-hook-evidence-writer-request.v0",
        "request_id": "writer-op",
        "guard_home": home.to_string_lossy(),
        "source": "guard",
        "action": "stats",
    }))
    .unwrap();
    let bytes = evaluate_hook_evidence_writer_request(&request).unwrap();
    let answer: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(answer["status"], json!("error"));
    assert_eq!(answer["code"], json!("invalid_schema"));
}

#[test]
fn a_request_without_a_guard_home_is_refused() {
    let request: HookEvidenceWriterRequestV1 = serde_json::from_value(json!({
        "schema": HOOK_EVIDENCE_WRITER_REQUEST_SCHEMA,
        "request_id": "writer-op",
        "guard_home": "",
        "source": "guard",
        "action": "stats",
    }))
    .unwrap();
    let bytes = evaluate_hook_evidence_writer_request(&request).unwrap();
    let answer: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(answer["status"], json!("error"));
    assert_eq!(answer["code"], json!("invalid_guard_home"));
}

/// The whole request as the Python client puts it on the wire: every field
/// the op knows is present, so the digest the resident takes over the request
/// it decoded is the digest the client took over the JSON it sent.
fn full_activity_wire(home: &Path) -> Value {
    json!({
        "schema": HOOK_EVIDENCE_WRITER_REQUEST_SCHEMA,
        "request_id": "writer-op-digest",
        "guard_home": home.to_string_lossy(),
        "source": "guard",
        "store_fatal_ack": Value::Null,
        "action": "submit_command_activity",
        "harness": "claude-code",
        "event": "PostToolUse",
        "payload": {"tool_name": "Bash", "tool_input": {"command": "ls /tmp"}},
        "succeeded": true,
        "policy_action": Value::Null,
        "receipt_id": Value::Null,
        "prompted": false,
        "approval_reuse_status": "not-applicable",
    })
}

/// The client refuses a reply that is not bound to the request it sent, so a
/// reply without the digest is a reply it reads as an unavailable resident.
#[test]
fn a_reply_carries_the_digest_of_the_request_that_arrived() {
    let home = store_home("writer-op-digest", "record_basic");
    let wire = full_activity_wire(&home);
    let request: HookEvidenceWriterRequestV1 = serde_json::from_value(wire.clone()).unwrap();
    let bytes = evaluate_hook_evidence_writer_request(&request).unwrap();
    let reply: Value = serde_json::from_slice(&bytes).unwrap();

    let mut canonical = Vec::new();
    crate::context_digest_json::write_canonical_json(&wire, &mut canonical).unwrap();
    let expected = format!("sha256:{}", guard_policy_snapshot::digest_bytes(&canonical));
    assert_eq!(reply["request_sha256"], json!(expected));

    let stopped = call(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
    assert_eq!(stopped["payload"]["drained"], json!(true));
}

/// A refused request is still bound to what was sent: the client has to be
/// able to read the code rather than discard the reply as unbound.
#[test]
fn a_refused_request_is_bound_to_what_was_sent() {
    let refused = call(
        Path::new(""),
        json!({"action": "submit_native_decision_receipt", "receipt": {}}),
    );
    assert_eq!(refused["status"], json!("error"));
    assert_eq!(refused["code"], json!("invalid_guard_home"));
    assert!(refused["request_sha256"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:")));
}

/// The writer drains on its own thread, so a failure it meets there has to
/// ride back on the call a daemon always makes rather than wait for a counter
/// read the daemon may never make.
#[test]
fn a_submission_reply_carries_the_signals_a_counter_read_would() {
    let home = store_home("writer-op-signals", "record_basic");
    let queued = call(
        &home,
        json!({
            "action": "submit_command_activity",
            "harness": "claude-code",
            "event": "PostToolUse",
            "payload": {"tool_name": "Bash", "tool_input": {"command": "ls /tmp"}},
            "succeeded": true,
        }),
    );
    assert_eq!(queued["payload"]["queued"], json!(true));
    assert_eq!(queued["payload"]["policy_mutations"], json!(0));
    assert_eq!(queued["payload"]["store_fatal"], Value::Null);

    // A discovery the op refuses before it reaches the writer answers with the
    // same shape, so the client reads one reply shape for every submission.
    let refused = call(
        &home,
        json!({
            "action": "submit_composio_discovery",
            "harness": "claude-code",
            "payload": {},
            "succeeded": true,
        }),
    );
    assert_eq!(refused["payload"]["queued"], json!(false));
    assert_eq!(refused["payload"]["store_fatal"], Value::Null);

    let stopped = call(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
    assert_eq!(stopped["payload"]["drained"], json!(true));
}

/// Building the writer replays its journal. The daemon paid that at startup
/// when it owned the object; `start` is where it pays for it now, so the
/// first hook to record a decision does not wait for the replay.
#[test]
fn a_start_builds_the_writer_before_any_submission() {
    let home = store_home("writer-op-start", "record_basic");
    let started = call(&home, json!({"action": "start"}));
    assert_eq!(started["status"], json!("ok"));
    assert_eq!(started["payload"]["running"], json!(true));
    assert_eq!(started["payload"]["accepted"], json!(0));

    // The writer the start built is the writer a counter read finds, not a
    // second one: `stats` never starts one of its own.
    let stats = call(&home, json!({"action": "stats"}));
    assert_eq!(stats["payload"]["running"], json!(true));
    assert_eq!(stats["payload"]["started"], json!(true));

    let stopped = call(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
    assert_eq!(stopped["payload"]["drained"], json!(true));
}

/// A home no writer was ever built for is idle, not faulty. A reader that
/// treats a stopped writer as something to repair needs the two apart.
#[test]
fn a_home_without_a_writer_reports_that_none_was_started() {
    let home = temp_home("writer-op-unstarted");
    let stats = call(&home, json!({"action": "stats"}));
    assert_eq!(stats["payload"]["running"], json!(false));
    assert_eq!(stats["payload"]["started"], json!(false));
}

/// A writer whose thread has exited is replaced on the next submission. It
/// may still hold the mutations a caller has to wake its publishers for and
/// the store failure a caller has to recover from — the two things the signal
/// path exists to deliver. Dropping that writer silently would drop both, so
/// its replacement carries them.
#[test]
fn a_replaced_writer_hands_its_pending_signals_to_the_next_one() {
    let home = store_home("writer-op-carry", "record_basic");
    let started = call(&home, json!({"action": "start"}));
    assert_eq!(started["payload"]["running"], json!(true));

    {
        let slot = super::slot(&std::fs::canonicalize(&home).unwrap());
        let held = slot.writer.lock().unwrap();
        let resident = held.as_ref().expect("the start built a writer");
        resident
            .mutations
            .fetch_add(3, std::sync::atomic::Ordering::SeqCst);
        resident.fatal.record("native_guard_store_sqlite_corrupt");
        // Stopping the writer leaves it in the slot with its thread gone,
        // which is the state a writer that died on its own reaches.
        assert!(resident.writer.stop(10.0));
    }

    let queued = call(
        &home,
        json!({
            "action": "submit_command_activity",
            "harness": "claude-code",
            "event": "PostToolUse",
            "payload": {"tool_name": "Bash", "tool_input": {"command": "ls /tmp"}},
            "succeeded": true,
        }),
    );
    assert_eq!(queued["payload"]["queued"], json!(true));
    assert_eq!(queued["payload"]["policy_mutations"], json!(3));
    assert_eq!(
        queued["payload"]["store_fatal"]["code"],
        json!("native_guard_store_sqlite_corrupt")
    );

    // The mutation count is cleared by the read that reported it; the failure
    // waits for the acknowledgement that names it.
    let identifier = queued["payload"]["store_fatal"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let stats = call(
        &home,
        json!({"action": "stats", "store_fatal_ack": identifier}),
    );
    assert_eq!(stats["payload"]["policy_mutations"], json!(0));
    assert_eq!(stats["payload"]["store_fatal"], Value::Null);

    let stopped = call(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
    assert_eq!(stopped["payload"]["drained"], json!(true));
}
