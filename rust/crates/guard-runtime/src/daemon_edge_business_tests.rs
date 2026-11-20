use serde_json::json;

use super::*;

fn summary() -> Value {
    json!({
        "schema": SUMMARY_SCHEMA,
        "version": 1,
        "request_id": "business-test",
        "request_snapshot_digest": "a".repeat(64),
        "prepared_input_binding": "b".repeat(64),
        "service": "google_gmail",
        "operation": "mail_send",
        "audience_kind": "named",
        "audience_expansion_state": "known",
        "recipient_count": 3,
        "record_count": 1,
        "byte_count": 24,
        "attachment_count": 0,
        "inspection_state": "known",
        "sensitivity_labels": ["confidential"],
        "snapshot_fact_completeness": "known",
        "account_currentness": "not_asserted",
        "execution_state": "not_checked",
    })
}

fn with(field: &str, value: Value) -> Value {
    let mut summary = summary();
    summary[field] = value;
    summary
}

#[test]
fn a_well_formed_summary_is_kept_whole() {
    let kept = valid_summary(&summary(), "business-test").unwrap();
    assert_eq!(Value::Object(kept), summary());
}

#[test]
fn a_summary_off_the_wire_shape_is_refused() {
    for bad in [
        with("request_id", json!("other")),
        with("version", json!(1.0)),
        with("version", json!(true)),
        with("operation", json!("drive_read")),
        with("service", json!("slack")),
        with("request_snapshot_digest", json!("A".repeat(64))),
        with("recipient_count", json!(-1)),
        with("byte_count", json!(1u64 << 53)),
        with("attachment_count", json!(false)),
        with("sensitivity_labels", json!(["secret", "secret"])),
        with("sensitivity_labels", json!(["internal"])),
        with("audience_kind", json!("everyone")),
        with("inspection_state", json!("partial")),
        with("account_currentness", json!("asserted")),
        with("execution_state", json!("checked")),
    ] {
        assert_eq!(valid_summary(&bad, "business-test"), None, "{bad}");
    }
    let mut extra = summary();
    extra["note"] = json!("x");
    assert_eq!(valid_summary(&extra, "business-test"), None);
    let mut missing = summary();
    missing.as_object_mut().unwrap().remove("byte_count");
    assert_eq!(valid_summary(&missing, "business-test"), None);
}

#[test]
fn only_the_resident_absence_errors_mean_no_saved_request() {
    assert!(absent(&json!({"error": UNAVAILABLE})));
    assert!(absent(
        &json!({"error": "native_policy_snapshot_missing", "retryable": false})
    ));
    assert!(!absent(&json!({"error": UNAVAILABLE, "retryable": "no"})));
    assert!(!absent(&json!({"error": "native_resident_busy"})));
    assert!(!absent(&json!({"error": UNAVAILABLE, "detail": "x"})));
}

#[test]
fn request_ids_follow_the_snapshot_id_alphabet() {
    assert!(valid_request_id("business-test:1.a_b"));
    assert!(!valid_request_id(""));
    assert!(!valid_request_id("a/b"));
    assert!(!valid_request_id(&"a".repeat(129)));
    assert!(valid_request_id(&"a".repeat(128)));
}

#[test]
fn a_summary_becomes_its_queue_row() {
    let Value::Object(summary) = summary() else {
        unreachable!()
    };
    let row = queue_row(summary).unwrap().unwrap();
    assert_eq!(row["request_id"], "business-test");
    assert_eq!(row["harness"], "native-business");
}

#[test]
fn queue_links_name_the_address_the_caller_reached() {
    let v6: SocketAddr = "[::1]:9".parse().unwrap();
    assert_eq!(local_url(v6, "/#/inbox"), "http://[::1]:9/#/inbox");
}

fn queue(items: Vec<Value>) -> Value {
    json!({"schema": QUEUE_SCHEMA, "version": 1, "items": items})
}

fn named(request_id: &str) -> Value {
    with("request_id", json!(request_id))
}

#[test]
fn the_queue_answer_is_read_as_the_daemon_reader_read_it() {
    assert_eq!(queue_summaries(&queue(vec![])).unwrap().len(), 0);
    for missing in [
        json!({"error": "native_policy_snapshot_missing"}),
        json!({"error": "native_policy_snapshot_unavailable", "retryable": true}),
    ] {
        assert!(queue_summaries(&missing).unwrap().is_empty(), "{missing}");
    }
    let rows = queue_summaries(&queue(vec![named("a"), named("b")])).unwrap();
    assert_eq!(rows.len(), 2);
    for failed in [
        queue(vec![named("b"), named("a")]),
        queue(vec![named("a"), named("a")]),
        queue(vec![json!({"request_id": "a"})]),
        queue(vec![named("a/b")]),
        json!({"schema": QUEUE_SCHEMA, "version": true, "items": []}),
        json!({"schema": QUEUE_SCHEMA, "version": 2, "items": []}),
        json!({"schema": "other", "version": 1, "items": []}),
        json!({"schema": QUEUE_SCHEMA, "version": 1, "items": [], "extra": 1}),
        json!({"error": "native_policy_snapshot_missing", "retryable": "yes"}),
        json!({"error": "native_store_failed"}),
        json!([]),
    ] {
        assert!(queue_summaries(&failed).is_err(), "{failed}");
    }
    let many: Vec<Value> = (0..=MAX_QUEUE_ITEMS)
        .map(|n| named(&format!("r{n:04}")))
        .collect();
    assert!(queue_summaries(&queue(many)).is_err());
}

#[test]
fn pages_follow_the_runtime_page_and_its_cursor_errors() {
    assert_eq!(
        page(&[], json!({"room": 3})).unwrap(),
        json!({"count": 0, "items": [], "next_cursor": null})
            .as_object()
            .unwrap()
            .clone()
    );
    assert_eq!(
        page(&[], json!({"cursor": "native-business-v1:x:0"})),
        Err(PageError::Cursor)
    );
    let rows: Vec<Map<String, Value>> = ["a", "b", "c"]
        .iter()
        .map(|id| named(id).as_object().unwrap().clone())
        .collect();
    let first = page(&rows, json!({"room": 2})).unwrap();
    assert_eq!(first["count"], 3);
    assert_eq!(first["items"].as_array().unwrap().len(), 2);
    let cursor = first["next_cursor"].as_str().unwrap().to_owned();
    assert!(cursor.starts_with(CURSOR_PREFIX));
    let rest = page(&rows, json!({"cursor": cursor, "limit": 5})).unwrap();
    assert_eq!(rest["items"].as_array().unwrap().len(), 1);
    assert_eq!(rest["next_cursor"], Value::Null);
    assert_eq!(
        page(&rows[..1], json!({"cursor": cursor, "limit": 5})),
        Err(PageError::Cursor)
    );
}
