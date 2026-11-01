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
pub(super) fn store_home(tag: &str) -> std::path::PathBuf {
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

pub(super) fn writer(home: &Path, action: Value) -> Value {
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
pub(super) fn start_writer(home: &Path) {
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

pub(super) fn receipts_accepted(home: &Path) -> Value {
    writer(home, json!({"action": "stats"}))["payload"]["receipt_accepted"].clone()
}

/// The writer counts a receipt in `accepted` as well, so the activities are
/// what is left once its receipts are taken out.
pub(super) fn activities_accepted(home: &Path) -> Value {
    let stats = writer(home, json!({"action": "stats"}));
    let payload = &stats["payload"];
    json!(payload["accepted"].as_u64().unwrap() - payload["receipt_accepted"].as_u64().unwrap())
}

/// An allowed `PreToolUse` answer and the envelope it answers, which now
/// names `home` and asks for the receipt when `record` is set.
pub(super) fn answered(home: &Path, record: bool) -> (GuardHookEnvelopeV2, GuardHookEdgeResultV2) {
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

pub(super) fn encoded(
    envelope: &GuardHookEnvelopeV2,
    resident: bool,
    edge: GuardHookEdgeResultV2,
) -> Value {
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

/// An allowed `PostToolUse` answer and the envelope it answers, which names
/// `home`, asks for the receipt and, with `activity`, for the activity.
fn post_tool_answered(home: &Path, activity: bool) -> (GuardHookEnvelopeV2, GuardHookEdgeResultV2) {
    let mut envelope = crate::edge::tests::envelope(
        "PostToolUse",
        json!({"tool_name": "Bash", "tool_input": {"command": "pwd"}, "exit_code": 0}),
    );
    let bytes = crate::edge::tests::evaluate_isolated(envelope.clone()).unwrap();
    let edge: GuardHookEdgeResultV2 = serde_json::from_slice(&bytes).unwrap();
    assert!(!edge.activity_recorded);
    envelope.source.guard_home = home.to_string_lossy().into_owned();
    envelope.record_receipt = true;
    envelope.record_activity = activity;
    (envelope, edge)
}

#[test]
fn a_post_tool_edge_that_asks_queues_its_activity_behind_the_receipt() {
    let home = store_home("edge-activity-recorded");
    start_writer(&home);
    let (envelope, edge) = post_tool_answered(&home, true);
    let answer = encoded(&envelope, true, edge);
    assert_eq!(answer["receipt_recorded"], json!(true));
    assert_eq!(answer["activity_recorded"], json!(true));
    assert_eq!(receipts_accepted(&home), json!(1));
    // The writer was started with one activity; the edge queued the second.
    assert_eq!(activities_accepted(&home), json!(2));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn a_post_tool_activity_the_writer_refuses_is_left_to_the_daemon() {
    let home = store_home("edge-activity-refused");
    start_writer(&home);
    let (mut envelope, edge) = post_tool_answered(&home, true);
    // A request id that is not an exact string fails correlation, so the
    // writer takes the receipt and refuses the activity.
    let payload = envelope.raw_payload.as_object_mut().unwrap();
    for field in ["tool_use_id", "tool_call_id", "toolUseId", "generation_id"] {
        payload.insert(field.to_owned(), json!(17));
    }
    let answer = encoded(&envelope, true, edge);
    assert_eq!(answer["receipt_recorded"], json!(true));
    assert!(answer.get("activity_recorded").is_none());
    assert_eq!(receipts_accepted(&home), json!(1));
    assert_eq!(activities_accepted(&home), json!(1));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn the_edge_leaves_the_activity_to_the_daemon_unless_it_can_record_it() {
    let home = store_home("edge-activity-unasked");
    start_writer(&home);
    let (envelope, edge) = post_tool_answered(&home, false);
    let answer = encoded(&envelope, true, edge);
    assert_eq!(answer["receipt_recorded"], json!(true));
    assert!(answer.get("activity_recorded").is_none());
    // `record_activity` asks only for a `PostToolUse` activity, which is all
    // an older daemon skips, so a `PreToolUse` one stays with the daemon.
    let (mut envelope, edge) = answered(&home, true);
    envelope.record_activity = true;
    assert!(encoded(&envelope, true, edge)
        .get("activity_recorded")
        .is_none());
    assert_eq!(activities_accepted(&home), json!(1));
    // Without a running writer neither is recorded, and the answer says so.
    let (envelope, edge) = post_tool_answered(&home, true);
    let answer =
        crate::hook_evidence_writer_op::while_slot_busy(&home, || encoded(&envelope, true, edge));
    assert!(answer.get("receipt_recorded").is_none());
    assert!(answer.get("activity_recorded").is_none());
    assert_eq!(activities_accepted(&home), json!(1));
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
    assert!(offer_direct(&queue, &home, direct_evidence(&edge), true));
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
    assert!(offer_direct(&queue, &home, direct_evidence(&edge), true));
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
        offer_direct(&queue, &home, direct_evidence(&edge), true)
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
    assert!(!offer_direct(&queue, &home, evidence, true));
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
        json!({"harness": "claude-code"}),
        true
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
    assert!(offer_direct(&queue, &home, evidence, true));
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
        .try_offer_recorded(record.clone(), &[DIRECT_RECEIPT_RECORDED], |_| 0)
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
        .try_offer_recorded(record, &[DIRECT_RECEIPT_RECORDED], |_| {
            recorded.set(true);
            1
        })
        .is_err());
    assert!(!recorded.get());
}

/// The evidence of a direct `PreToolUse` answer carrying what its command
/// activity records, with `response` as the harness answer.
fn pre_tool_evidence(edge: &GuardHookEdgeResultV2, response: Value) -> Value {
    let mut evidence = direct_evidence(edge);
    evidence["payload"] = json!({"tool_name": "Bash", "tool_input": {"command": "pwd"}});
    evidence["harness_response"] = response;
    evidence
}

#[test]
fn a_direct_pre_tool_answer_queues_its_activity_behind_the_receipt() {
    let home = store_home("direct-activity-recorded");
    start_writer(&home);
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    let evidence = pre_tool_evidence(&edge, json!({"policy_action": "allow"}));
    assert!(offer_direct(&queue, &home, evidence, true));
    let records = queued(&queue);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0][DIRECT_RECEIPT_RECORDED], json!(true));
    assert_eq!(records[0][DIRECT_ACTIVITY_RECORDED], json!(true));
    assert_eq!(receipts_accepted(&home), json!(1));
    // The writer was started with one activity; this answer queued another.
    assert_eq!(activities_accepted(&home), json!(2));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn an_activity_the_resident_cannot_record_stays_with_the_drain() {
    let home = store_home("direct-activity-left");
    start_writer(&home);
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    for evidence in [
        // Not a guard action, which the writer refuses.
        pre_tool_evidence(&edge, json!({"policy_action": "pass"})),
        // A field the activity cannot carry, which the drain reports.
        pre_tool_evidence(
            &edge,
            json!({"policy_action": "allow", "approval_reuse_status": 1}),
        ),
        // A post-tool answer without the payload its activity records.
        {
            let mut evidence = pre_tool_evidence(&edge, json!({}));
            evidence["event"] = json!("PostToolUse");
            evidence["payload"] = Value::Null;
            evidence
        },
    ] {
        assert!(offer_direct(&queue, &home, evidence, true));
    }
    // A daemon whose drain does not skip it gets every activity.
    let evidence = pre_tool_evidence(&edge, json!({"policy_action": "allow"}));
    assert!(offer_direct(&queue, &home, evidence, false));
    let records = queued(&queue);
    assert_eq!(records.len(), 4);
    for record in &records {
        assert_eq!(record[DIRECT_RECEIPT_RECORDED], json!(true));
        assert!(record.get(DIRECT_ACTIVITY_RECORDED).is_none());
    }
    assert_eq!(activities_accepted(&home), json!(1));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn a_direct_post_tool_answer_queues_its_activity_behind_the_receipt() {
    let home = store_home("direct-post-activity-recorded");
    start_writer(&home);
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    let mut evidence = pre_tool_evidence(&edge, json!({}));
    evidence["event"] = json!("PostToolUse");
    evidence["payload"]["exit_code"] = json!(1);
    assert!(offer_direct(&queue, &home, evidence, true));
    let records = queued(&queue);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0][DIRECT_RECEIPT_RECORDED], json!(true));
    assert_eq!(records[0][DIRECT_ACTIVITY_RECORDED], json!(true));
    // A Bash call is no Composio tool, so only the activity was queued.
    assert_eq!(activities_accepted(&home), json!(2));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn a_post_tool_call_fails_only_on_the_signals_the_drain_reads() {
    for (payload, succeeded) in [
        (json!({}), true),
        (json!({"exit_code": 0}), true),
        (json!({"exit_code": 2}), false),
        (json!({"exitCode": -1}), false),
        // Python reads `exit_code` when present, even when it is null.
        (json!({"exit_code": null, "exitCode": 1}), true),
        (json!({"exit_code": 1.0}), true),
        (json!({"exit_code": true}), true),
        (json!({"is_error": true}), false),
        (json!({"isError": "true"}), true),
        (json!({"failed": true}), false),
        (json!({"success": false}), false),
        (json!({"success": 0}), true),
        (json!({"hook_event_name": "post_tool_use-failure"}), false),
        (json!({"hookEventName": "PostToolUseFailure"}), false),
        (json!({"hook_event_name": "PostToolUse"}), true),
    ] {
        let Value::Object(payload) = payload else {
            unreachable!("object literal");
        };
        assert_eq!(post_succeeded(&payload), succeeded, "{payload:?}");
    }
}

#[path = "edge_receipt_pre_tool_tests.rs"]
mod pre_tool;
