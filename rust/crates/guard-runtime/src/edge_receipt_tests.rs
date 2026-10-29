//! The edge records its receipt only for a resident request that asked, and
//! only into the writer already running for that Guard home.

use std::path::Path;

use serde_json::{json, Value};

use super::*;
use crate::guard_store_cmd_vectors_tests::{build_database, temp_home};
use crate::hook_evidence_writer_op::{
    evaluate_hook_evidence_writer_request, HookEvidenceWriterRequestV1,
    HOOK_EVIDENCE_WRITER_REQUEST_SCHEMA,
};

const VECTORS: &str = include_str!("../testdata/guard_store/command_activity_vectors.json");

/// A Guard home holding the recorded command-activity schema and seed.
fn store_home(tag: &str) -> std::path::PathBuf {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let scenario = vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == json!("record_basic"))
        .expect("scenario")
        .clone();
    let home = temp_home(tag);
    build_database(&home.join("guard.db"), &vectors, &scenario);
    home
}

fn writer(home: &Path, action: Value) -> Value {
    let Value::Object(mut wire) = json!({
        "schema": HOOK_EVIDENCE_WRITER_REQUEST_SCHEMA,
        "request_id": "edge-receipt",
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
    serde_json::from_slice(&evaluate_hook_evidence_writer_request(&request).unwrap()).unwrap()
}

/// Start the home's writer the way the daemon does: with a submission.
fn start_writer(home: &Path) {
    let started = writer(
        home,
        json!({
            "action": "submit_command_activity",
            "harness": "claude-code",
            "event": "PostToolUse",
            "payload": {"tool_name": "Bash", "tool_input": {"command": "pwd"}},
            "succeeded": true,
        }),
    );
    assert_eq!(started["payload"]["queued"], json!(true));
}

fn receipts_accepted(home: &Path) -> Value {
    writer(home, json!({"action": "stats"}))["payload"]["receipt_accepted"].clone()
}

/// An allowed `PreToolUse` answer and the envelope it answers, which now
/// names `home` and asks for the receipt when `record` is set.
fn answered(home: &Path, record: bool) -> (GuardHookEnvelopeV2, GuardHookEdgeResultV2) {
    let mut envelope = crate::edge::tests::envelope(
        "PreToolUse",
        json!({"tool_name": "Bash", "tool_input": {"command": "pwd"}}),
    );
    let bytes = crate::edge::tests::evaluate_isolated(envelope.clone()).unwrap();
    let edge: GuardHookEdgeResultV2 = serde_json::from_slice(&bytes).unwrap();
    assert!(!edge.receipt_recorded);
    envelope.source.guard_home = home.to_string_lossy().into_owned();
    envelope.record_receipt = record;
    (envelope, edge)
}

fn encoded(envelope: &GuardHookEnvelopeV2, resident: bool, edge: GuardHookEdgeResultV2) -> Value {
    serde_json::from_slice(&encode(envelope, resident, edge, Instant::now()).unwrap()).unwrap()
}

#[test]
fn a_resident_request_that_asks_queues_its_receipt_with_the_running_writer() {
    let home = store_home("edge-receipt-recorded");
    start_writer(&home);
    let (envelope, edge) = answered(&home, true);
    let answer = encoded(&envelope, true, edge);
    assert_eq!(answer["receipt_recorded"], json!(true));
    assert_eq!(receipts_accepted(&home), json!(1));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn a_request_that_does_not_ask_or_is_not_resident_leaves_the_receipt_to_the_daemon() {
    let home = store_home("edge-receipt-unasked");
    start_writer(&home);
    for (resident, record) in [(true, false), (false, true), (false, false)] {
        let (envelope, edge) = answered(&home, record);
        let answer = encoded(&envelope, resident, edge);
        // The flag is left off the wire entirely, so an older daemon that
        // refuses unknown fields still reads the answer.
        assert!(
            answer.get("receipt_recorded").is_none(),
            "{resident} {record}"
        );
    }
    assert_eq!(receipts_accepted(&home), json!(0));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn the_edge_never_starts_a_writer_to_record_its_receipt() {
    let home = store_home("edge-receipt-idle");
    let (envelope, edge) = answered(&home, true);
    let answer = encoded(&envelope, true, edge);
    assert!(answer.get("receipt_recorded").is_none());
    assert_eq!(
        writer(&home, json!({"action": "stats"}))["payload"]["running"],
        json!(false),
        "starting a writer replays the journal, which the edge must not do"
    );
}

#[test]
fn a_stopped_writer_takes_no_receipt() {
    let home = store_home("edge-receipt-stopped");
    start_writer(&home);
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
    let (envelope, edge) = answered(&home, true);
    let answer = encoded(&envelope, true, edge);
    assert!(answer.get("receipt_recorded").is_none());
}

#[test]
fn a_writer_slot_busy_starting_or_draining_leaves_the_receipt_to_the_daemon() {
    let home = store_home("edge-receipt-busy");
    start_writer(&home);
    let (envelope, edge) = answered(&home, true);
    // The answer comes back at once instead of waiting on the slot.
    let answer =
        crate::hook_evidence_writer_op::while_slot_busy(&home, || encoded(&envelope, true, edge));
    assert!(answer.get("receipt_recorded").is_none());
    assert_eq!(receipts_accepted(&home), json!(0));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn the_resident_advertises_that_its_edge_records_receipts() {
    assert!(
        crate::resident_op_features::RESIDENT_OP_FEATURES.contains(&EDGE_RECEIPT_RECORD_FEATURE)
    );
}

/// The evidence record a direct answer queues, carrying `edge`'s receipt.
fn direct_evidence(edge: &GuardHookEdgeResultV2) -> Value {
    json!({
        "harness": "claude-code",
        "event": "PreToolUse",
        "receipt": serde_json::to_value(&edge.receipt).unwrap(),
    })
}

fn queued(queue: &DirectEvidenceQueue) -> Vec<Value> {
    let request = crate::hook_direct_evidence::HookDirectEvidenceDrainRequestV1 {
        guard_home: String::new(),
        max_records: None,
        ack_through: None,
        ack_epoch: None,
    };
    let page: Value =
        serde_json::from_slice(&crate::hook_direct_evidence::drain(&request, queue).unwrap())
            .unwrap();
    page["records"].as_array().unwrap().clone()
}

#[test]
fn a_direct_answer_queues_its_receipt_with_the_running_writer_and_says_so() {
    let home = store_home("direct-receipt-recorded");
    start_writer(&home);
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    assert!(offer_direct(&queue, &home, direct_evidence(&edge)));
    let records = queued(&queue);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0][DIRECT_RECEIPT_RECORDED], json!(true));
    assert_eq!(receipts_accepted(&home), json!(1));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn a_direct_answer_without_a_running_writer_leaves_the_receipt_to_the_drain() {
    let home = store_home("direct-receipt-idle");
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    assert!(offer_direct(&queue, &home, direct_evidence(&edge)));
    let records = queued(&queue);
    assert_eq!(records.len(), 1);
    assert!(records[0].get(DIRECT_RECEIPT_RECORDED).is_none());
    assert_eq!(
        writer(&home, json!({"action": "stats"}))["payload"]["running"],
        json!(false),
        "starting a writer replays the journal, which the hook must not do"
    );
}

#[test]
fn a_direct_answer_with_the_writer_slot_busy_leaves_the_receipt_to_the_drain() {
    let home = store_home("direct-receipt-busy");
    start_writer(&home);
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    let offered = crate::hook_evidence_writer_op::while_slot_busy(&home, || {
        offer_direct(&queue, &home, direct_evidence(&edge))
    });
    assert!(offered);
    let records = queued(&queue);
    assert_eq!(records.len(), 1);
    assert!(records[0].get(DIRECT_RECEIPT_RECORDED).is_none());
    assert_eq!(receipts_accepted(&home), json!(0));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn a_direct_answer_the_queue_refuses_records_no_receipt() {
    let home = store_home("direct-receipt-full");
    start_writer(&home);
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    let mut evidence = direct_evidence(&edge);
    evidence["padding"] = json!("x".repeat(crate::hook_direct_evidence::MAX_RECORD_BYTES));
    assert!(!offer_direct(&queue, &home, evidence));
    assert!(queued(&queue).is_empty());
    assert_eq!(receipts_accepted(&home), json!(0));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn direct_evidence_without_a_receipt_is_queued_as_is() {
    let home = store_home("direct-receipt-none");
    let queue = DirectEvidenceQueue::default();
    assert!(offer_direct(
        &queue,
        &home,
        json!({"harness": "claude-code"})
    ));
    assert_eq!(queued(&queue), vec![json!({"harness": "claude-code"})]);
}

#[test]
fn a_direct_answer_whose_marker_would_not_fit_queues_unmarked() {
    let home = store_home("direct-receipt-near-limit");
    start_writer(&home);
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    let mut evidence = direct_evidence(&edge);
    evidence["padding"] = json!("");
    let room = crate::hook_direct_evidence::MAX_RECORD_BYTES
        - serde_json::to_vec(&evidence).unwrap().len();
    evidence["padding"] = json!("x".repeat(room));
    assert!(offer_direct(&queue, &home, evidence));
    let records = queued(&queue);
    assert_eq!(records.len(), 1);
    assert!(records[0].get(DIRECT_RECEIPT_RECORDED).is_none());
    assert_eq!(receipts_accepted(&home), json!(0));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn a_receipt_the_writer_refuses_leaves_the_record_unmarked() {
    let queue = DirectEvidenceQueue::default();
    let record = json!({"harness": "claude-code", "receipt": {}});
    assert!(queue
        .try_offer_recorded(record.clone(), DIRECT_RECEIPT_RECORDED, || false)
        .is_ok());
    // The page still says the drain must not cite the receipt.
    let mut expected = record;
    expected["receipt_valid"] = json!(false);
    assert_eq!(queued(&queue), [expected]);
}

#[test]
fn a_receipt_is_not_recorded_for_a_record_the_queue_refuses() {
    let queue = DirectEvidenceQueue::default();
    let mut record = json!({"receipt": {}});
    record["padding"] = json!("x".repeat(crate::hook_direct_evidence::MAX_RECORD_BYTES));
    let recorded = std::cell::Cell::new(false);
    assert!(queue
        .try_offer_recorded(record, DIRECT_RECEIPT_RECORDED, || {
            recorded.set(true);
            true
        })
        .is_err());
    assert!(!recorded.get());
}
