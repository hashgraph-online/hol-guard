use super::*;

fn auth(url: &str) -> Map<String, Value> {
    Map::from_iter([("sync_url".to_owned(), json!(url))])
}

#[test]
fn an_untrusted_sync_host_is_refused_before_any_upload() {
    let error = trusted_base(&auth("https://evil.example/api/guard/receipts/sync")).unwrap_err();
    let SyncError::EndpointUntrusted(message) = error else {
        panic!("an untrusted host must read as an untrusted endpoint");
    };
    assert!(message.contains("not trusted"));
    assert!(message.contains("hol-guard connect"));
}

#[test]
fn a_loopback_sync_host_is_trusted() {
    let base = trusted_base(&auth("http://127.0.0.1:9/api/guard/receipts/sync")).unwrap();
    assert_eq!(
        route_url("guard_events", &base).unwrap(),
        "http://127.0.0.1:9/api/v1/guard/events"
    );
}

#[test]
fn retry_after_reads_whole_seconds_with_a_one_minute_default() {
    assert_eq!(retry_after_seconds(None), 60);
    assert_eq!(retry_after_seconds(Some("30")), 30);
    assert_eq!(retry_after_seconds(Some("0")), 1);
    assert_eq!(retry_after_seconds(Some("soon")), 60);
}

#[test]
fn cloud_synced_at_is_kept_only_when_it_is_a_timestamp() {
    let stamp = "2026-11-19T10:00:00+00:00";
    assert_eq!(synced_at(&json!({"syncedAt": stamp})), stamp);
    assert_ne!(synced_at(&json!({"syncedAt": "yesterday"})), "yesterday");
}

#[test]
fn an_unavailable_endpoint_is_skipped_for_five_minutes() {
    let recent = json!({"sync_reason": ENDPOINT_UNAVAILABLE, "synced_at": utc_now_iso()});
    assert!(endpoint_unavailable_recently(&recent));
    let old =
        json!({"sync_reason": ENDPOINT_UNAVAILABLE, "synced_at": "2020-01-01T00:00:00+00:00"});
    assert!(!endpoint_unavailable_recently(&old));
    let undated = json!({"sync_reason": RATE_LIMITED});
    assert!(endpoint_unavailable_recently(&undated));
    let synced = json!({"synced_at": utc_now_iso()});
    assert!(!endpoint_unavailable_recently(&synced));
}

#[test]
fn an_upload_batch_stops_before_the_broker_body_limit() {
    let large = "x".repeat(200 * 1024);
    let pending: Vec<Value> = (0..4)
        .map(|index| json!({"event_id": index, "payload": {"body": large}}))
        .collect();
    assert_eq!(batch_within_body_limit(&pending).len(), 2);
    let huge = vec![json!({"payload": {"body": "x".repeat(600 * 1024)}})];
    assert_eq!(batch_within_body_limit(&huge).len(), 1);
    assert_eq!(batch_within_body_limit(&[]).len(), 0);
}

#[test]
fn only_a_lone_event_above_the_broker_body_limit_is_too_large() {
    let huge = vec![json!({"eventId": "evt-huge", "body": "x".repeat(600 * 1024)})];
    assert_eq!(too_large_alone(&huge).as_deref(), Some("evt-huge"));
    let small = vec![json!({"eventId": "evt-small", "body": "x"})];
    assert_eq!(too_large_alone(&small), None);
    let pair = vec![small[0].clone(), small[0].clone()];
    assert_eq!(too_large_alone(&pair), None);
}

#[test]
fn a_refusal_message_that_echoes_a_credential_is_redacted() {
    let credential = "q7".repeat(9);
    let answer = json!({"plan_message": format!("denied access_token={credential}")});
    let text = answer_text(Some(&answer), "plan_message", 403);
    assert!(!text.contains(&credential), "{text}");
    assert!(text.starts_with("denied"), "{text}");
    assert_eq!(
        answer_text(None, "plan_message", 403),
        "Guard sync failed with HTTP 403."
    );
}
