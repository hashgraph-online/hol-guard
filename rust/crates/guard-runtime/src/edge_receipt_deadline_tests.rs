//! An edge past the daemon's budget leaves every record to the daemon.

use serde_json::json;

use super::tests::{
    activities_accepted, answered, encoded, receipts_accepted, start_writer, store_home, writer,
};

#[test]
fn an_answer_past_the_daemon_budget_records_nothing() {
    let home = store_home("edge-receipt-budget-spent");
    start_writer(&home);
    let (mut envelope, edge) = answered(&home, true);
    // A daemon that stopped waiting records the hook as unavailable itself,
    // so evidence the edge queued now would be a second record of one hook.
    envelope.deadline_budget_ms = Some(0);
    let answer = encoded(&envelope, true, edge);
    assert!(answer.get("receipt_recorded").is_none());
    assert!(answer.get("activity_recorded").is_none());
    assert_eq!(receipts_accepted(&home), json!(0));
    assert_eq!(
        activities_accepted(&home),
        json!(1),
        "only the writer's start"
    );
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}

#[test]
fn an_answer_inside_the_daemon_budget_still_records_its_receipt() {
    let home = store_home("edge-receipt-budget-left");
    start_writer(&home);
    let (mut envelope, edge) = answered(&home, true);
    envelope.deadline_budget_ms = Some(60_000);
    let answer = encoded(&envelope, true, edge);
    assert_eq!(answer["receipt_recorded"], json!(true));
    assert_eq!(receipts_accepted(&home), json!(1));
    writer(&home, json!({"action": "stop", "timeout_seconds": 10.0}));
}
