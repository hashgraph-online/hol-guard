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

/// The page leaves out a record it left the daemon nothing to record for,
/// while its cursor still covers it.
fn assert_settled(page: &Value) {
    assert_eq!(page["records"], json!([]), "{page}");
    assert!(page["through"].as_u64().is_some(), "{page}");
    assert_eq!(page["remaining"], json!(0), "{page}");
}

#[test]
fn the_drain_records_what_a_direct_answer_left_once_and_leaves_it_off_the_page() {
    let home = store_home("drain-records-leftovers");
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    assert!(offer_direct(&queue, &home, allowed(&edge), true));
    let page = drained(&queue, &home, Some("guard"));
    assert_settled(&page);
    assert!(page.get("store_fatal").is_none());
    // A page sent again records nothing twice and still leaves it out.
    assert_settled(&drained(&queue, &home, Some("guard")));
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
    assert_settled(&drained(&queue, &home, Some("guard")));
    assert_eq!(receipts_accepted(&home), json!(1));
    // The writer was started with one activity; the drain queued this one.
    assert_eq!(activities_accepted(&home), json!(2));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn the_drain_records_a_fence_wait_once_as_the_daemon_window_would() {
    let home = store_home("drain-records-fence-wait");
    let store = rusqlite::Connection::open(home.join("guard.db")).unwrap();
    store
        .execute_batch(
            "create table guard_events (event_id integer primary key autoincrement, \
             event_name text not null, payload_json text not null, occurred_at text not null)",
        )
        .unwrap();
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    let mut record = allowed(&edge);
    record["fence_wait_ms"] = json!(300);
    assert!(offer_direct(&queue, &home, record, true));
    assert_settled(&drained(&queue, &home, Some("guard")));
    // A page sent again records no second window.
    assert_settled(&drained(&queue, &home, Some("guard")));
    assert_eq!(receipts_accepted(&home), json!(1));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
    let rows: Vec<(String, String, String)> = store
        .prepare("select event_name, payload_json, occurred_at from guard_events")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let [(name, payload, occurred_at)] = rows.as_slice() else {
        panic!("one window event, got {rows:?}");
    };
    assert_eq!(name, "policy_source_fence_window");
    let payload: Value = serde_json::from_str(payload).unwrap();
    assert_eq!(payload["ended_at"], json!(occurred_at));
    assert_eq!(payload["absorbed_calls"], json!(1));
    assert_eq!(payload["exhausted_calls"], json!(0));
    assert!(payload["started_at"].as_str().unwrap() < occurred_at.as_str());
}

#[cfg(unix)]
#[test]
fn the_drain_seals_a_codex_receipt_once_while_the_capture_is_on() {
    use std::os::unix::fs::PermissionsExt;

    let home = store_home("drain-records-capture");
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
    let now = crate::binding_capture_op::now_seconds();
    assert!(crate::binding_capture_fs::initialize_marker(
        &home,
        "run-1",
        now as i64 + 600,
        None,
        None,
        now
    )
    .is_some());
    let payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "pwd"},
        "tool_use_id": "call-1",
    });
    let mut envelope = crate::edge::tests::envelope("PreToolUse", payload.clone());
    envelope.harness = "codex".to_owned();
    let edge: GuardHookEdgeResultV2 =
        serde_json::from_slice(&crate::edge::tests::evaluate_isolated(envelope).unwrap()).unwrap();
    let mut record = allowed(&edge);
    record["harness"] = json!("codex");
    record["payload"] = payload;
    let queue = DirectEvidenceQueue::default();
    assert!(offer_direct(&queue, &home, record, true));
    assert_settled(&drained(&queue, &home, Some("guard")));
    // A page sent again seals nothing twice.
    assert_settled(&drained(&queue, &home, Some("guard")));
    let rows = std::fs::read_to_string(home.join("diagnostics/codex-binding-capture.run-1.jsonl"))
        .unwrap();
    assert_eq!(rows.lines().count(), 1, "{rows}");
    assert!(rows.contains("\"route\":\"native_worker\""), "{rows}");
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn the_drain_leaves_a_codex_receipt_uncaptured_while_the_capture_is_off() {
    let home = store_home("drain-records-capture-off");
    let (_, edge) = answered(&home, true);
    let mut record = allowed(&edge);
    record["harness"] = json!("codex");
    let queue = DirectEvidenceQueue::default();
    assert!(offer_direct(&queue, &home, record, true));
    // The daemon's capture would seal nothing without the marker either.
    assert_settled(&drained(&queue, &home, Some("guard")));
    assert!(!home.join("diagnostics").exists());
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn the_drain_raises_a_connector_setup_notice_once() {
    let home = store_home("drain-raises-connector-notice");
    let (_, edge) = answered(&home, true);
    let mut record = allowed(&edge);
    // A stored row the store does not hold raises nothing, so no notice shows.
    record["connector_setup_notice"] =
        json!({"request_id": "req-missing", "connector_name": "Example CLI"});
    let queue = DirectEvidenceQueue::default();
    // The binding keeps the activity, so the record stays on the page.
    assert!(offer_direct(&queue, &home, record, false));
    let records = drained(&queue, &home, Some("guard"))["records"].clone();
    assert_eq!(records[0]["connector_notice_raised"], json!(true));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn the_drain_marks_no_notice_a_record_does_not_name() {
    let home = store_home("drain-no-connector-notice");
    let (_, edge) = answered(&home, true);
    let queue = DirectEvidenceQueue::default();
    assert!(offer_direct(&queue, &home, allowed(&edge), false));
    let records = drained(&queue, &home, Some("guard"))["records"].clone();
    assert!(records[0].get("connector_notice_raised").is_none());
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}
