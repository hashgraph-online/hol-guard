//! The drain records what a direct answer left to the daemon, starting the
//! writer with the bound daemon's store source.

use std::path::Path;

use serde_json::{json, Value};

use super::tests::{activities_accepted, answered, receipts_accepted, store_home, writer};
use super::*;
use crate::hook_direct_evidence::HookDirectEvidenceDrainRequestV1;

/// Drain `queue` for `home` as the daemon does, without acknowledging.
fn drained(queue: &DirectEvidenceQueue, home: &Path, source: Option<&str>) -> Value {
    let request = HookDirectEvidenceDrainRequestV1 {
        guard_home: home.to_string_lossy().into_owned(),
        max_records: None,
        ack_through: None,
        ack_epoch: None,
    };
    serde_json::from_slice(&crate::hook_direct_evidence::drain(&request, queue, source).unwrap())
        .unwrap()
}

/// A direct `PreToolUse` allow whose activity the daemon would record.
fn allowed(edge: &GuardHookEdgeResultV2) -> Value {
    json!({
        "harness": "claude-code",
        "event": "PreToolUse",
        "receipt": serde_json::to_value(&edge.receipt).unwrap(),
        "payload": {"tool_name": "Bash", "tool_input": {"command": "pwd"}},
        "harness_response": {"policy_action": "allow"},
    })
}

#[test]
fn the_drain_records_what_a_direct_answer_left_and_marks_it_once() {
    let home = store_home("drain-records-leftovers");
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    assert!(offer_direct(&queue, &home, allowed(&edge), true));
    let page = drained(&queue, &home, Some("guard"));
    let records = page["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0][DIRECT_RECEIPT_RECORDED], json!(true));
    assert_eq!(records[0][DIRECT_ACTIVITY_RECORDED], json!(true));
    assert!(page.get("store_fatal").is_none());
    // A page sent again carries the marks and records nothing twice.
    let again = drained(&queue, &home, Some("guard"));
    assert_eq!(again["records"], page["records"]);
    assert_eq!(receipts_accepted(&home), json!(1));
    assert_eq!(activities_accepted(&home), json!(1));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn the_drain_records_only_the_receipt_when_the_binding_kept_the_activity() {
    let home = store_home("drain-records-receipt-only");
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    assert!(offer_direct(&queue, &home, allowed(&edge), false));
    let records = drained(&queue, &home, Some("guard"))["records"].clone();
    assert_eq!(records[0][DIRECT_RECEIPT_RECORDED], json!(true));
    assert!(records[0].get(DIRECT_ACTIVITY_RECORDED).is_none());
    assert_eq!(receipts_accepted(&home), json!(1));
    assert_eq!(activities_accepted(&home), json!(0));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn a_drain_without_a_bound_source_leaves_everything_to_the_daemon() {
    let home = store_home("drain-records-unbound");
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    assert!(offer_direct(&queue, &home, allowed(&edge), true));
    let records = drained(&queue, &home, None)["records"].clone();
    assert!(records[0].get(DIRECT_RECEIPT_RECORDED).is_none());
    assert_eq!(
        writer(&home, json!({"action": "stats"}))["payload"]["running"],
        json!(false)
    );
}

#[test]
fn the_drain_finishes_an_activity_the_answer_left_behind_its_receipt() {
    let home = store_home("drain-records-activity-left");
    super::tests::start_writer(&home);
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    // The writer took the receipt as the hook answered and left the activity.
    let record = allowed(&edge);
    assert!(queue
        .try_offer_recorded(
            record,
            &[DIRECT_RECEIPT_RECORDED, DIRECT_ACTIVITY_RECORDED],
            true,
            |record| {
                let receipt = record["receipt"].as_object().unwrap();
                crate::hook_evidence_writer_op::record_direct(&home, |writer| {
                    usize::from(writer.submit_native_decision_receipt(receipt))
                })
                .unwrap()
            },
        )
        .is_ok());
    let records = drained(&queue, &home, Some("guard"))["records"].clone();
    assert_eq!(records[0][DIRECT_RECEIPT_RECORDED], json!(true));
    assert_eq!(records[0][DIRECT_ACTIVITY_RECORDED], json!(true));
    assert_eq!(receipts_accepted(&home), json!(1));
    // The writer was started with one activity; the drain queued this one.
    assert_eq!(activities_accepted(&home), json!(2));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}
