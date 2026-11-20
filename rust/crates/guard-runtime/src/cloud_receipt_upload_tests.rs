use std::cell::RefCell;

use serde_json::{json, Value};

use super::*;
use crate::cloud_receipt_upload_rows::{
    batches, cursor_rowid, rows_for_upload, sized_batches, with_detail_backfill,
    DETAIL_BACKFILL_FLAG,
};

/// One batch, written without a one-range `vec!`.
fn one(range: std::ops::Range<usize>) -> Vec<std::ops::Range<usize>> {
    std::iter::once(range).collect()
}

fn receipt(rowid: i64) -> Value {
    json!({"receipt_id": format!("r-{rowid}"), "receipt_rowid": rowid})
}

/// A store that answers each method from a fixed table and records calls.
struct FakeStore {
    answers: Vec<(&'static str, Value)>,
    calls: RefCell<Vec<(String, Value)>>,
}

impl FakeStore {
    fn new(answers: Vec<(&'static str, Value)>) -> Self {
        Self {
            answers,
            calls: RefCell::new(Vec::new()),
        }
    }

    fn call(&self, method: &str, args: Value) -> Result<Value, SyncError> {
        self.calls.borrow_mut().push((method.to_owned(), args));
        Ok(self
            .answers
            .iter()
            .find(|(name, _)| *name == method)
            .map_or(Value::Null, |(_, answer)| answer.clone()))
    }
}

#[test]
fn a_first_sync_reads_the_window_from_the_oldest_newest_receipt() {
    let store = FakeStore::new(vec![
        ("list_receipts", json!([receipt(9), receipt(7)])),
        (
            "list_receipts_since_rowid",
            json!([receipt(7), receipt(8), receipt(9)]),
        ),
    ]);
    let rows = rows_for_upload(&|method, args| store.call(method, args), None).unwrap();
    assert_eq!(rows.len(), 3);
    let calls = store.calls.borrow();
    assert_eq!(calls[1].0, "list_receipts_since_rowid");
    assert_eq!(calls[1].1["after_rowid"], json!(6));
}

#[test]
fn a_cursor_past_the_store_resends_the_newest_window() {
    let store = FakeStore::new(vec![
        ("latest_receipt_rowid", json!(250)),
        ("list_receipts_since_rowid", json!([])),
    ]);
    rows_for_upload(&|method, args| store.call(method, args), Some(900)).unwrap();
    assert_eq!(store.calls.borrow()[1].1["after_rowid"], json!(50));
}

#[test]
fn an_empty_store_uploads_nothing_past_the_cursor() {
    let store = FakeStore::new(vec![("latest_receipt_rowid", Value::Null)]);
    let rows = rows_for_upload(&|method, args| store.call(method, args), Some(3)).unwrap();
    assert!(rows.is_empty());
    assert_eq!(store.calls.borrow().len(), 1);
}

#[test]
fn a_saved_cursor_reads_numbers_and_digit_strings() {
    assert_eq!(cursor_rowid(Some(&json!({"last_rowid": 12}))), Some(12));
    assert_eq!(cursor_rowid(Some(&json!({"last_rowid": " 40 "}))), Some(40));
    assert_eq!(cursor_rowid(Some(&json!({"last_rowid": "-4"}))), None);
    assert_eq!(cursor_rowid(Some(&json!([]))), None);
    assert_eq!(cursor_rowid(None), None);
}

#[test]
fn a_full_redaction_level_never_backfills() {
    let store = FakeStore::new(vec![]);
    let (rows, marker) = with_detail_backfill(
        &|method, args| store.call(method, args),
        None,
        vec![receipt(1)],
        "full",
        "2026-11-19T00:00:00Z",
    )
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(marker.is_none());
    assert!(store.calls.borrow().is_empty());
}

#[test]
fn a_backfill_appends_unseen_receipts_and_moves_its_marker_down() {
    let store = FakeStore::new(vec![(
        "list_receipts_for_command_detail_backfill",
        json!([receipt(5), receipt(3), receipt(2)]),
    )]);
    let saved = json!({"level": "partial", "before_rowid": 6, "complete": false});
    let (rows, marker) = with_detail_backfill(
        &|method, args| store.call(method, args),
        Some(&saved),
        vec![receipt(5), receipt(10)],
        "partial",
        "2026-11-19T00:00:00Z",
    )
    .unwrap();
    assert_eq!(store.calls.borrow()[0].1["before_rowid"], json!(6));
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[2][DETAIL_BACKFILL_FLAG], json!(true));
    assert!(rows[0].get(DETAIL_BACKFILL_FLAG).is_none());
    let marker = marker.unwrap();
    assert_eq!(marker["receipts"], json!(2));
    assert_eq!(marker["queried"], json!(3));
    assert_eq!(marker["before_rowid"], json!(2));
    assert_eq!(marker["complete"], json!(false));
}

#[test]
fn a_completed_backfill_at_the_same_level_stays_done() {
    let store = FakeStore::new(vec![]);
    let saved = json!({"level": "none", "before_rowid": 4, "complete": true});
    let (_, marker) = with_detail_backfill(
        &|method, args| store.call(method, args),
        Some(&saved),
        vec![],
        "none",
        "2026-11-19T00:00:00Z",
    )
    .unwrap();
    assert!(marker.is_none());
    assert!(store.calls.borrow().is_empty());
}

#[test]
fn an_empty_backfill_page_completes_the_walk() {
    let store = FakeStore::new(vec![(
        "list_receipts_for_command_detail_backfill",
        json!([]),
    )]);
    let saved = json!({"level": "partial", "before_rowid": "8"});
    let (_, marker) = with_detail_backfill(
        &|method, args| store.call(method, args),
        Some(&saved),
        vec![],
        "partial",
        "2026-11-19T00:00:00Z",
    )
    .unwrap();
    let marker = marker.unwrap();
    assert_eq!(marker["complete"], json!(true));
    assert_eq!(marker["before_rowid"], json!(8));
}

#[test]
fn batches_hold_fifty_and_an_empty_upload_still_sends_one() {
    assert_eq!(batches(0), one(0..0));
    assert_eq!(batches(120), vec![0..50, 50..100, 100..120]);
}

#[test]
fn only_backfilled_rows_advance_the_marker() {
    let marker = json!({"level": "partial", "before_rowid": 40});
    let mut flagged = receipt(12);
    flagged[DETAIL_BACKFILL_FLAG] = json!(true);
    let batch = [receipt(3), flagged];
    let updated = advance_marker(&marker, &batch, "2026-11-19T01:00:00Z").unwrap();
    assert_eq!(updated["before_rowid"], json!(12));
    assert_eq!(updated["updated_at"], json!("2026-11-19T01:00:00Z"));
    assert!(advance_marker(&marker, &[receipt(3)], "now").is_none());
}

#[test]
fn the_backfill_flag_reports_a_sync_with_nothing_past_its_cursor() {
    let mut plan = Plan {
        rows: vec![receipt(3), receipt(4)],
        prior_cursor: Some(10),
        ..Plan::default()
    };
    assert!(cursor_backfill(&plan));
    plan.rows.push(receipt(11));
    assert!(!cursor_backfill(&plan));
    plan.prior_cursor = None;
    assert!(!cursor_backfill(&plan));
}

fn http(status: u16, answer: Value) -> Refusal {
    Refusal::Http {
        status,
        answer: Some(answer),
        retry_after: None,
    }
}

#[test]
fn refusals_map_to_the_errors_python_raised() {
    assert_eq!(
        refusal_error(http(401, json!({"edge_block": null}))),
        SyncError::AuthExpired(REAUTHORIZE.to_owned())
    );
    assert_eq!(
        refusal_error(http(401, json!({"edge_block": "Blocked at the edge."}))),
        SyncError::Failed("Blocked at the edge.".to_owned())
    );
    assert_eq!(
        refusal_error(http(
            403,
            json!({"plan_restricted": true, "plan_message": "Upgrade the plan."})
        )),
        SyncError::NotAvailable {
            message: "Upgrade the plan.".to_owned(),
            retryable: false,
        }
    );
    assert_eq!(
        refusal_error(http(
            403,
            json!({"plan_restricted": false, "plan_message": "No."})
        )),
        SyncError::Failed("No.".to_owned())
    );
    assert_eq!(
        refusal_error(http(500, json!({"sync_message": "Cloud failed."}))),
        SyncError::Failed("Cloud failed.".to_owned())
    );
    assert_eq!(
        refusal_error(Refusal::Transport("connection refused".to_owned())),
        SyncError::Failed("Guard sync failed: connection refused".to_owned())
    );
}

fn request(posture: bool, workspace: Option<Value>) -> UploadRequest {
    UploadRequest {
        redaction_level: "full".to_owned(),
        device_id: "device-1".to_owned(),
        device_name: "Device".to_owned(),
        now: "2026-11-19T00:00:00Z".to_owned(),
        sync_context: serde_json::Map::from_iter([("deviceId".to_owned(), json!("device-1"))]),
        fleet_posture: posture.then(|| FleetPosture {
            payload: json!({"mode": "delta"}),
            next_state: json!({}),
            advanced_inventory: false,
        }),
        workspace_assessments: workspace,
        allow_auth_refresh: true,
        context_only: false,
    }
}

#[test]
fn the_posture_rides_on_the_first_request_only() {
    let request = request(true, None);
    let state = UploadState::default();
    let (first, _) = batch_body(&request, &[], 0, &state);
    let (second, _) = batch_body(&request, &[], 1, &state);
    assert_eq!(
        first["syncContext"]["fleetPosture"],
        json!({"mode": "delta"})
    );
    assert!(second["syncContext"].get("fleetPosture").is_none());
    assert_eq!(first["receipts"], json!([]));
}

#[test]
fn a_summary_that_does_not_fit_waits_for_a_later_request() {
    let summary = json!({
        "payload": {"generatedAt": "2026-11-19T00:00:00Z"},
        "digest": "d",
    });
    let request = request(false, Some(summary.clone()));
    let state = UploadState {
        workspace_pending: Some(summary),
        ..UploadState::default()
    };
    let (body, sent) = batch_body(&request, &[], 0, &state);
    assert!(sent.is_none());
    assert!(body["syncContext"].get("workspaceAssessments").is_none());
}

#[test]
fn answers_accumulate_across_batches() {
    let mut tally = Tally::default();
    tally.accumulate(&json!({
        "receiptsStored": 2,
        "advisories": [{"id": "a"}, "skip"],
        "policyBundle": {"bundleVersion": "1"},
        "policyBundleDelivery": {"mode": "v2"},
        "alertPreferences": {"email": true},
        "reviewVerificationKeys": [{"kid": "k"}],
    }));
    tally.accumulate(&json!({
        "receiptsStored": 3,
        "policyBundle": {},
        "alertPreferences": {},
        "syncedAt": "2026-11-19T02:00:00Z",
    }));
    assert_eq!(tally.receipts_stored, 5);
    assert_eq!(tally.advisories, vec![json!({"id": "a"})]);
    assert_eq!(tally.bundle, Some(json!({"bundleVersion": "1"})));
    assert!(tally.delivery_provided);
    assert_eq!(tally.alert_preferences, Some(json!({"email": true})));
    assert_eq!(tally.review_keys, json!([{"kid": "k"}]));
    assert_eq!(
        tally.last_payload.get("syncedAt"),
        Some(&json!("2026-11-19T02:00:00Z"))
    );
    tally.accumulate(&json!({"policyBundle": "not an object"}));
    assert!(tally.bundle_malformed);
}

#[test]
fn batches_split_before_a_body_goes_over_the_limit() {
    // Overhead 10, limit 40: 12 + 13 (with comma) fits, the third does not.
    let sizes = [Some(12), Some(12), Some(12)];
    assert_eq!(sized_batches(&sizes, 10, 10, 40), vec![0..2, 2..3]);
    assert_eq!(sized_batches(&[], 10, 10, 40), one(0..0));
}

#[test]
fn a_receipt_left_unsent_still_rides_in_its_batch() {
    let sizes = [Some(12), None, Some(12)];
    assert_eq!(sized_batches(&sizes, 10, 10, 40), one(0..3));
    let sizes = [None, None];
    assert_eq!(sized_batches(&sizes, 10, 10, 40), one(0..2));
}

#[test]
fn sized_batches_still_hold_fifty_rows_at_most() {
    let sizes = vec![Some(1); 120];
    assert_eq!(
        sized_batches(&sizes, 10, 10, usize::MAX / 2),
        vec![0..50, 50..100, 100..120]
    );
}

#[test]
fn a_receipt_too_large_for_any_request_is_planned_unsent() {
    let mut request = request(true, None);
    request.redaction_level = "full".to_owned();
    let big = "x".repeat(crate::cloud_event_sync::EVENTS_BODY_LIMIT);
    let rows = vec![
        json!({"receipt_id": "small", "receipt_rowid": 1, "timestamp": "2026-11-19T00:00:00Z",
               "harness": "codex", "artifact_id": "a", "artifact_hash": "h", "policy_decision": "allow"}),
        json!({"receipt_id": "big", "receipt_rowid": 2, "timestamp": "2026-11-19T00:00:00Z",
               "harness": "codex", "artifact_id": big, "artifact_hash": "h", "policy_decision": "allow"}),
    ];
    let plan = fit_to_broker(
        &request,
        Plan {
            rows,
            ..Plan::default()
        },
    )
    .unwrap();
    assert_eq!(plan.batches, one(0..2));
    assert!(plan.projected[0].is_some());
    assert!(plan.projected[1].is_none());
    let state = UploadState::default();
    let (body, _) = batch_body(&request, &plan.projected, 0, &state);
    assert_eq!(body["receipts"].as_array().map(Vec::len), Some(1));
}

#[test]
fn a_receipt_that_does_not_fit_beside_the_posture_waits_for_the_next_request() {
    // The posture takes 20 of the first request's 40 bytes; the receipt fits
    // only in a request without it.
    let sizes = [Some(25), Some(4)];
    assert_eq!(sized_batches(&sizes, 30, 10, 40), vec![0..0, 0..2]);
}

#[test]
fn a_context_only_request_is_one_body_without_receipts() {
    let mut request = request(true, None);
    request.context_only = true;
    let plan = fit_to_broker(&request, Plan::default()).unwrap();
    assert_eq!(plan.batches, one(0..0));
    let (body, _) = batch_body(&request, &plan.projected[0..0], 0, &UploadState::default());
    assert_eq!(body["receipts"], json!([]));
    assert_eq!(
        body["syncContext"]["fleetPosture"],
        json!({"mode": "delta"})
    );
}
